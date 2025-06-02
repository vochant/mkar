#pragma once

#include "ast/identifier.hpp"

// for varname(range-as-list) something

class ForNode : public Node {
public:
    std::string _var;
    std::shared_ptr<Node> _elem, _body;
    ForNode();
};