#pragma once

#include "ast/base/node.hpp"

class InfixNode : public Node {
public:
    std::string _op;
    std::shared_ptr<Node> left, right;
    InfixNode(std::string _op);
};