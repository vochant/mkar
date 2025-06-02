#pragma once

#include "ast/base/node.hpp"

class ExprNode : public Node {
public:
    std::shared_ptr<Node> inner;
    ExprNode(std::shared_ptr<Node> inner);
};