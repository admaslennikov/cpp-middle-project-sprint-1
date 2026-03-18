#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard
{
namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : m_desc("Allowed options")
{
    auto options = m_desc.add_options();
    options("help,h", "Show help message");
    options("command,c", po::value<std::string>()->required(), "Command to execute [encrypt, decrypt, checksum]");
    options("input,i", po::value<std::string>(), "Input file path");
    options("output,o", po::value<std::string>(), "Output file path");
    options("password,p", po::value<std::string>(), "Password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[])
{
    m_helpRequested = false;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, m_desc), vm);

    if (vm.count("help"))
    {
        std::cout << m_desc << std::endl;
        m_helpRequested = true;
    }
    else
    {
        po::notify(vm);

        auto cmd = vm["command"].as<std::string>();
        auto it = m_commandMapping.find(cmd);

        if (it == m_commandMapping.end())
            throw std::runtime_error("Unsupported command: " + cmd);

        m_command = it->second;

        if (!vm.count("input"))
            throw std::runtime_error("the option '--input' is required but missing");

        m_inputFile = vm["input"].as<std::string>();

        if (m_inputFile.empty())
            throw std::runtime_error("Input file path cannot be empty");

        if (m_command != COMMAND_TYPE::CHECKSUM)
        {
            if (!vm.count("output"))
                throw std::runtime_error("the option '--output' is required but missing");

            if (!vm.count("password"))
                throw std::runtime_error("the option '--password' is required but missing");

            m_outputFile = vm["output"].as<std::string>();
            m_password = vm["password"].as<std::string>();

            if (m_outputFile.empty())
                throw std::runtime_error("Output file path cannot be empty");

            if (m_password.empty())
                throw std::runtime_error("Password cannot be empty");
        }
        else
        {
            if (vm.count("output"))
                throw std::runtime_error("the option '--output' is not applicable for checksum command");

            if (vm.count("password"))
                throw std::runtime_error("the option '--password' is not applicable for checksum command");

            m_outputFile.clear();
            m_password.clear();
        }
    }
}

}  // namespace CryptoGuard
