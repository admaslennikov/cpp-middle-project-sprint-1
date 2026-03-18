#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <ios>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace CryptoGuard
{
enum class CRYPTO_OPERATION
{
    Encrypt,
    Decrypt,
    Checksum
};

std::string_view ToString(CRYPTO_OPERATION operation)
{
    switch (operation)
    {
    case CRYPTO_OPERATION::Encrypt:
        return "Encrypt";
    case CRYPTO_OPERATION::Decrypt:
        return "Decrypt";
    case CRYPTO_OPERATION::Checksum:
        return "Checksum";
    }
    return "Unknown";
}
}  // namespace CryptoGuard

namespace
{
std::string GetStreamStateInfo(const std::ios &stream)
{
    std::ostringstream oss;
    oss << "[state:";
    if (stream.bad())
        oss << " bad";
    if (stream.fail())
        oss << " fail";
    if (stream.eof())
        oss << " eof";
    oss << " ]";
    return oss.str();
}

std::string GetOpenSSLErrorInfo()
{
    std::ostringstream oss;

    bool hasErrors = false;
    unsigned long errorCode = 0;
    while ((errorCode = ERR_get_error()) != 0)
    {
        hasErrors = true;

        char errorBuffer[256]{};
        ERR_error_string_n(errorCode, errorBuffer, sizeof(errorBuffer));

        if (oss.tellp() > 0)
            oss << "; ";

        oss << errorBuffer;
    }

    if (!hasErrors)
        return "OpenSSL error queue is empty";

    return oss.str();
}

std::string MakeContextErrorMessage(CryptoGuard::CRYPTO_OPERATION operation, const std::string &details)
{
    std::ostringstream oss;
    oss << ToString(operation) << " failed: " << details;
    return oss.str();
}

std::string
MakeInputStreamErrorMessage(CryptoGuard::CRYPTO_OPERATION operation, const std::string &details, const std::ios &stream)
{
    std::ostringstream oss;
    oss << ToString(operation) << " failed: input stream error: " << details << ' ' << GetStreamStateInfo(stream);
    return oss.str();
}

std::string MakeOutputStreamErrorMessage(CryptoGuard::CRYPTO_OPERATION operation,
                                         const std::string &details,
                                         const std::ios &stream,
                                         std::streamsize bytesCount)
{
    std::ostringstream oss;
    oss << ToString(operation) << " failed: output stream error: " << details << ", bytes to write: " << bytesCount
        << ' ' << GetStreamStateInfo(stream);
    return oss.str();
}

std::string MakeCryptoErrorMessage(CryptoGuard::CRYPTO_OPERATION operation, const std::string &stage)
{
    std::ostringstream oss;
    oss << ToString(operation) << " failed: OpenSSL error during " << stage << ": " << GetOpenSSLErrorInfo();
    return oss.str();
}

std::string MakeSizedCryptoErrorMessage(CryptoGuard::CRYPTO_OPERATION operation,
                                        const std::string &stage,
                                        std::streamsize bytesCount)
{
    std::ostringstream oss;
    oss << ToString(operation) << " failed: OpenSSL error during " << stage << ", input bytes: " << bytesCount << ": "
        << GetOpenSSLErrorInfo();
    return oss.str();
}
}  // namespace

namespace CryptoGuard
{
struct AesCipherParams
{
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::PImpl
{
public:
    PImpl();
    ~PImpl();

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::iostream &inStream) const;

private:
    void DoCryptoOperation(std::iostream &inStream,
                           std::iostream &outStream,
                           std::string_view password,
                           CRYPTO_OPERATION operation) const;

private:
    const std::size_t m_inputBufferSize = 1024;
};

// CryptoGuardCtx::PImpl
CryptoGuardCtx::PImpl::PImpl() { OpenSSL_add_all_algorithms(); }
CryptoGuardCtx::PImpl::~PImpl() { EVP_cleanup(); }

AesCipherParams CryptoGuardCtx::PImpl::CreateChiperParamsFromPassword(std::string_view password) const
{
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher,
                                EVP_sha256(),
                                salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()),
                                password.size(),
                                1,
                                params.key.data(),
                                params.iv.data());

    if (result == 0)
        throw std::runtime_error{"Failed to create a key from password"};

    return params;
}

void CryptoGuardCtx::PImpl::DoCryptoOperation(std::iostream &inStream,
                                              std::iostream &outStream,
                                              std::string_view password,
                                              CRYPTO_OPERATION operation) const
{
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = (operation == CRYPTO_OPERATION::Encrypt) ? 1 : 0;

    using EvpCipherCtxPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    ERR_clear_error();
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());

    if (!ctx)
    {
        throw std::runtime_error(
            MakeContextErrorMessage(operation, "unable to create OpenSSL cipher context: " + GetOpenSSLErrorInfo()));
    }

    ERR_clear_error();

    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt))
    {
        throw std::runtime_error(MakeCryptoErrorMessage(operation, "EVP_CipherInit_ex"));
    }

    std::vector<unsigned char> inBuf(m_inputBufferSize);
    std::vector<unsigned char> outBuf(m_inputBufferSize + EVP_MAX_BLOCK_LENGTH);

    while (true)
    {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        const std::streamsize bytesRead = inStream.gcount();

        if (inStream.bad())
        {
            throw std::runtime_error(
                MakeInputStreamErrorMessage(operation, "stream became invalid during read", inStream));
        }

        if (inStream.fail() && !inStream.eof())
        {
            throw std::runtime_error(
                MakeInputStreamErrorMessage(operation, "read failed before reaching EOF", inStream));
        }

        if (bytesRead > 0)
        {
            int outLen = 0;

            ERR_clear_error();
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)))
            {
                throw std::runtime_error(MakeSizedCryptoErrorMessage(operation, "EVP_CipherUpdate", bytesRead));
            }

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

            if (outStream.bad() || outStream.fail())
            {
                throw std::runtime_error(
                    MakeOutputStreamErrorMessage(operation, "failed while writing encrypted chunk", outStream, outLen));
            }
        }

        if (inStream.eof())
            break;
    }

    int finalLen = 0;

    ERR_clear_error();
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &finalLen))
    {
        throw std::runtime_error(MakeCryptoErrorMessage(operation, "EVP_CipherFinal_ex"));
    }

    if (finalLen > 0)
    {
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), finalLen);

        if (outStream.bad() || outStream.fail())
        {
            throw std::runtime_error(MakeOutputStreamErrorMessage(
                operation, "failed while writing final encrypted block", outStream, finalLen));
        }
    }
}

void CryptoGuardCtx::PImpl::EncryptFile(std::iostream &inStream,
                                        std::iostream &outStream,
                                        std::string_view password) const
{
    DoCryptoOperation(inStream, outStream, password, CRYPTO_OPERATION::Encrypt);
    std::print("File encoded successfully\n");
}

void CryptoGuardCtx::PImpl::DecryptFile(std::iostream &inStream,
                                        std::iostream &outStream,
                                        std::string_view password) const
{
    DoCryptoOperation(inStream, outStream, password, CRYPTO_OPERATION::Decrypt);
    std::print("File decoded successfully\n");
}

std::string CryptoGuardCtx::PImpl::CalculateChecksum(std::iostream &inStream) const
{
    auto operation = CRYPTO_OPERATION::Checksum;

    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    ERR_clear_error();
    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());

    if (!mdCtx)
    {
        throw std::runtime_error(
            MakeContextErrorMessage(operation, "unable to create OpenSSL digest context: " + GetOpenSSLErrorInfo()));
    }

    ERR_clear_error();
    if (!EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr))
    {
        throw std::runtime_error(MakeCryptoErrorMessage(operation, "EVP_DigestInit_ex"));
    }

    std::vector<unsigned char> inBuf(m_inputBufferSize);

    while (true)
    {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        const std::streamsize bytesRead = inStream.gcount();

        if (inStream.bad())
        {
            throw std::runtime_error(
                MakeInputStreamErrorMessage(operation, "stream became invalid during read", inStream));
        }

        if (inStream.fail() && !inStream.eof())
        {
            throw std::runtime_error(
                MakeInputStreamErrorMessage(operation, "read failed before reaching EOF", inStream));
        }

        if (bytesRead > 0)
        {
            ERR_clear_error();
            if (!EVP_DigestUpdate(mdCtx.get(), inBuf.data(), static_cast<std::size_t>(bytesRead)))
            {
                throw std::runtime_error(MakeSizedCryptoErrorMessage(operation, "EVP_DigestUpdate", bytesRead));
            }
        }

        if (inStream.eof())
            break;
    }

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLen = 0;

    ERR_clear_error();
    if (!EVP_DigestFinal_ex(mdCtx.get(), digest.data(), &digestLen))
    {
        throw std::runtime_error(MakeCryptoErrorMessage(operation, "EVP_DigestFinal_ex"));
    }

    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < digestLen; ++i)
        hexStream << std::setw(2) << static_cast<int>(digest[i]);

    return hexStream.str();
}

// CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx() : d_ptr(std::make_unique<CryptoGuardCtx::PImpl>()) {};
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const
{
    d_ptr->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const
{
    d_ptr->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const
{
    return d_ptr->CalculateChecksum(inStream);
}
}  // namespace CryptoGuard