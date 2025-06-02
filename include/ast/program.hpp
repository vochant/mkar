#pragma once

#include "ast/scope.hpp"
#include "ast/error.hpp"
#include "util.hpp"

class ProgramNode : public Node {
public:
    std::shared_ptr<Node> mainScope;
    ProgramNode(std::shared_ptr<Node> mainScope);
};