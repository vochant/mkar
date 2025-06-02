#pragma once

#include "ast/base/node.hpp"

class AssignNode : public Node {
public:
    std::string _op;
    std::shared_ptr<Node> left, right;
    AssignNode(std::string _op);
};