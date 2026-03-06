#include "cmd_options.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace CryptoGuard;

namespace
{
std::vector<char *> MakeArgv(std::vector<std::string> &args)
{
    std::vector<char *> argv;
    argv.reserve(args.size());

    for (auto &arg : args)
        argv.push_back(arg.data());

    return argv;
}
}  // namespace

TEST(ProgramOptionsTests, EncryptCommand)
{
    ProgramOptions options;

    std::vector<std::string> args = {
        "app", "-c", "encrypt", "--input", "input.txt", "--output", "output.txt", "-p", "password_1"};
    auto argv = MakeArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "password_1");
}

TEST(ProgramOptionsTests, DecryptCommand)
{
    ProgramOptions options;

    std::vector<std::string> args = {
        "app", "--command", "decrypt", "-i", "input.txt", "--output", "output.txt", "-p", "password_1"};
    auto argv = MakeArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "password_1");
}

TEST(ProgramOptionsTests, ChecksumCommand)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "-c", "checksum", "--input", "input.txt"};
    auto argv = MakeArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptionsTests, UnsupportedCommand)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "--command", "checksummm", "--input", "input.txt"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, EncryptOutputIsMissing)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "--command", "encrypt", "--input", "input.txt", "--password", "password_1"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, EncryptPasswordIsMissing)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "--command", "encrypt", "--input", "input.txt", "-o", "output.txt"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, ChecksumReceivesOutput)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "--command", "checksum", "-i", "input.txt", "--output", "output.txt"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, ChecksumReceivesPassword)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "-c", "checksum", "--input", "input.txt", "--password", "password_1"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, InputIsMissing)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "-c", "checksum"};
    auto argv = MakeArgv(args);

    EXPECT_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, HelpRequested)
{
    ProgramOptions options;

    std::vector<std::string> args = {"app", "--help"};
    auto argv = MakeArgv(args);

    options.Parse(argv.size(), argv.data());

    EXPECT_TRUE(options.IsHelpRequested());
}