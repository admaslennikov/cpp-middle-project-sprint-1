#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>

using namespace CryptoGuard;

namespace
{
std::string EncryptString(const CryptoGuardCtx &crypto, const std::string &input, std::string_view password)
{
    std::stringstream in;
    std::stringstream out;

    in.str(input);
    crypto.EncryptFile(in, out, password);

    return out.str();
}

std::string DecryptString(const CryptoGuardCtx &crypto, const std::string &input, std::string_view password)
{
    std::stringstream in;
    std::stringstream out;

    in.str(input);
    crypto.DecryptFile(in, out, password);

    return out.str();
}

std::string CalculateChecksumForString(const CryptoGuardCtx &crypto, const std::string &input)
{
    std::stringstream in;

    in.str(input);

    return crypto.CalculateChecksum(in);
}
}  // namespace

// Encrypt tests
TEST(EncryptFileTests, EmptyString)
{
    CryptoGuardCtx crypto;

    const std::string plainText;
    const std::string encrypted = EncryptString(crypto, plainText, "password_1");

    EXPECT_FALSE(encrypted.empty());
}

TEST(EncryptFileTests, NonEmptyString)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";

    std::stringstream in;
    std::stringstream out;

    in.str(plainText);

    EXPECT_NO_THROW(crypto.EncryptFile(in, out, "password_1"));

    const std::string encrypted = out.str();

    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, plainText);
}

TEST(EncryptFileTests, SameInputAndPassword)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string encrypted1 = EncryptString(crypto, plainText, "password_1");
    const std::string encrypted2 = EncryptString(crypto, plainText, "password_1");

    EXPECT_EQ(encrypted1, encrypted2);
}

TEST(EncryptFileTests, DifferentPasswords)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string encrypted1 = EncryptString(crypto, plainText, "password_1");
    const std::string encrypted2 = EncryptString(crypto, plainText, "password_2");

    EXPECT_NE(encrypted1, encrypted2);
}

TEST(EncryptFileTests, InputStreamIsBad)
{
    CryptoGuardCtx crypto;

    std::stringstream in;
    std::stringstream out;

    in.str("some text");
    in.setstate(std::ios::badbit);

    ASSERT_THROW(crypto.EncryptFile(in, out, "password_1"), std::runtime_error);
}

TEST(EncryptFileTests, OutputStreamIsBad)
{
    CryptoGuardCtx crypto;

    std::stringstream in;
    std::stringstream out;

    in.str("Some text to test encryption/decryption/checksum");
    out.setstate(std::ios::badbit);

    ASSERT_THROW(crypto.EncryptFile(in, out, "password_1"), std::runtime_error);
}

// Decrypt tests
TEST(DecryptFileTests, DecryptRestoresOriginalText)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string password = "password_1";

    std::stringstream in;
    std::stringstream out;

    in.str(EncryptString(crypto, plainText, password));
    EXPECT_NO_THROW(crypto.DecryptFile(in, out, password));

    const std::string decrypted = out.str();

    EXPECT_EQ(decrypted, plainText);
}

TEST(DecryptFileTests, DecryptRestoresOriginalLongText)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum "
                                  "Longer text to check decryption for multiple chunks"
                                  "lkjflksvdfjgvlskdjdhgkljdhgvklsjhfgnvslkjfghvnslkjfghvskljfhnskljfghskljfh";
    const std::string password = "password_1";
    const std::string encrypted = EncryptString(crypto, plainText, password);
    const std::string decrypted = DecryptString(crypto, encrypted, password);

    EXPECT_EQ(decrypted, plainText);
}

TEST(DecryptFileTests, DecryptWithWrongPassword)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string encrypted = EncryptString(crypto, plainText, "password_1");

    std::stringstream in;
    std::stringstream out;

    in.str(encrypted);

    ASSERT_THROW(crypto.DecryptFile(in, out, "password_2"), std::runtime_error);
}

TEST(DecryptFileTests, InputStreamIsBad)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string password = "password_1";
    const std::string encrypted = EncryptString(crypto, plainText, password);

    std::stringstream in;
    std::stringstream out;

    in.str(encrypted);
    in.setstate(std::ios::badbit);

    ASSERT_THROW(crypto.DecryptFile(in, out, password), std::runtime_error);
}

TEST(DecryptFileTests, OutputStreamIsBad)
{
    CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string password = "password_1";
    const std::string encrypted = EncryptString(crypto, plainText, password);

    std::stringstream in;
    std::stringstream out;

    in.str(encrypted);
    out.setstate(std::ios::badbit);

    ASSERT_THROW(crypto.DecryptFile(in, out, password), std::runtime_error);
}

// Checksum tests
TEST(CalculateChecksumTests, EmptyString)
{
    const CryptoGuardCtx crypto;

    const std::string plainText;
    const std::string checksum = CalculateChecksumForString(crypto, plainText);

    EXPECT_EQ(checksum,
              "e3b0c44298fc1c149afbf4c8996fb924"
              "27ae41e4649b934ca495991b7852b855");
}

TEST(CalculateChecksumTests, ExpectedString)
{
    const CryptoGuardCtx crypto;
    const std::string plainText = "abc";

    std::stringstream in;
    in.str(plainText);

    std::string checksum;

    EXPECT_NO_THROW(checksum = crypto.CalculateChecksum(in));

    EXPECT_EQ(checksum,
              "ba7816bf8f01cfea414140de5dae2223"
              "b00361a396177a9cb410ff61f20015ad");
}

TEST(CalculateChecksumTests, SameChecksum)
{
    const CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string checksum1 = CalculateChecksumForString(crypto, plainText);
    const std::string checksum2 = CalculateChecksumForString(crypto, plainText);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(CalculateChecksumTests, InputStreamIsBad)
{
    const CryptoGuardCtx crypto;

    std::stringstream in;
    in.str("Some text to test encryption/decryption/checksum");
    in.setstate(std::ios::badbit);

    ASSERT_THROW(crypto.CalculateChecksum(in), std::runtime_error);
}

TEST(CalculateChecksumTests, EncryptDecryptSameChecksum)
{
    const CryptoGuardCtx crypto;

    const std::string plainText = "Some text to test encryption/decryption/checksum";
    const std::string password = "password_1";
    const std::string checksum1 = CalculateChecksumForString(crypto, plainText);
    const std::string encrypted = EncryptString(crypto, plainText, password);
    const std::string decrypted = DecryptString(crypto, encrypted, password);
    const std::string checksum2 = CalculateChecksumForString(crypto, decrypted);

    EXPECT_EQ(checksum1, checksum2);
}