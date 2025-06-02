#include "program/program.hpp"

#include <fstream>

void Program::loadLibrary(std::shared_ptr<Plugin> _plg) {
    _plg->attach(_outer);
}

int Program::Execute(std::shared_ptr<ProgramNode> _program) {
	return gVM->Execute(_program, gVM->inner);
}

int Program::ExecuteCode(std::string src, std::string from) {
    Parser parser(src, from);
    auto prog = parser.parse_program();
    return gVM->Execute(std::dynamic_pointer_cast<ProgramNode>(prog), gVM->inner);
}

int Program::ExecuteOuter(std::shared_ptr<ProgramNode> _program) {
	return gVM->Execute(_program, gVM->outer);
}

Program::Program() {
    std::ios::sync_with_stdio(false);
    _outer = std::make_shared<CommonEnvironment>();
    gVM = new VirtualMachine(_outer);
}

Program::~Program() {
    delete gVM;
}