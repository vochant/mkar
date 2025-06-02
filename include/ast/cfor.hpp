#pragma once

#include "ast/identifier.hpp"

// for varname(range-as-list) something

class CForNode : public Node {
public:
    std::shared_ptr<Node> _init, _cond, _next;
    std::shared_ptr<Node> _body;
    CForNode();
};