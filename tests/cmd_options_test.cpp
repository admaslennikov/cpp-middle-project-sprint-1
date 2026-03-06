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