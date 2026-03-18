#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard
{
class ProgramOptions
{
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE
    {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return m_command; }
    std::string GetInputFile() const { return m_inputFile; }
    std::string GetOutputFile() const { return m_outputFile; }
    std::string GetPassword() const { return m_password; }

    bool IsHelpRequested() const { return m_helpRequested; }

private:
    COMMAND_TYPE m_command = COMMAND_TYPE::CHECKSUM;

    const std::unordered_map<std::string_view, COMMAND_TYPE> m_commandMapping = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string m_inputFile;
    std::string m_outputFile;
    std::string m_password;

    boost::program_options::options_description m_desc;

    bool m_helpRequested;
};
}  // namespace CryptoGuard
