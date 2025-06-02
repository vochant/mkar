#pragma once

#include "ast/base/node.hpp"

class TernaryNode : public Node{
public:
    std::shared_ptr<Node> _cond, _if, _else;
    TernaryNode(std::shared_ptr<Node> _cond);
};