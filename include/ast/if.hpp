#pragma once

#include "ast/base/node.hpp"

// if (condition) something
// else something

class IfNode : public Node {
public:
    std::shared_ptr<Node> _cond, _then, _else;
    IfNode();
};