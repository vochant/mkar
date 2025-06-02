#pragma once

#include "ast/base/node.hpp"

class PrefixNode : public Node {
public:
    std::string _op;
    std::shared_ptr<Node> right;
    PrefixNode(std::string _op);
};