#pragma once

#include "ast/program.hpp"
#include "env/common.hpp"
#include "parser/parser.hpp"
#include "vm/vm.hpp"
#include "plugins/plugin.hpp"

class Program {
public:
    std::shared_ptr<Environment> _outer;
    Program();
    ~Program();
public:
    void loadLibrary(std::shared_ptr<Plugin> _plg);
    int Execute(std::shared_ptr<ProgramNode> _program);
    int ExecuteCode(std::string src, std::string from = "[stdin]");
	int ExecuteOuter(std::shared_ptr<ProgramNode> _program);
};