#pragma once

#include "ast/identifier.hpp"

class WhileNode : public Node {
public:
    std::shared_ptr<Node> _cond, _body;
    bool isDoWhile;
    WhileNode(bool isDoWhile);
};