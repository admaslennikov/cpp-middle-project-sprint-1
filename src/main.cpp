#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[])
{
    try
    {
        CryptoGuard::ProgramOptions options;

        options.Parse(argc, argv);

        if (options.IsHelpRequested())
            return 0;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        switch (options.GetCommand())
        {
        case COMMAND_TYPE::ENCRYPT:
        {
            std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::fstream out(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);

            if (!in.is_open())
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            if (!out.is_open())
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());

            cryptoCtx.EncryptFile(in, out, options.GetPassword());
        }
        break;

        case COMMAND_TYPE::DECRYPT:
        {
            std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::fstream out(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);

            if (!in.is_open())
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            if (!out.is_open())
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());

            cryptoCtx.DecryptFile(in, out, options.GetPassword());
        }
        break;

        case COMMAND_TYPE::CHECKSUM:
        {
            std::fstream in(options.GetInputFile(), std::ios::in | std::ios::binary);

            if (!in.is_open())
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());

            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
        }
        break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    }
    catch (const std::exception &e)
    {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}