#pragma once

#include "program/program.hpp"
#include "plugins/plugin.hpp"

void RunPostScript(std::string buf, std::string src = "<unknown>") {

    Program program;
    program.loadLibrary(std::make_shared<Plugins::Base>());
    program.loadLibrary(std::make_shared<Plugins::IO>());
    program.loadLibrary(std::make_shared<Plugins::FileIO>());
    program.loadLibrary(std::make_shared<Plugins::Math>());
    program.loadLibrary(std::make_shared<Plugins::MKAR>());

    program.ExecuteCode(buf, src);
}