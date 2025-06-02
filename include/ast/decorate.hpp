#pragma once

#include "ast/base/node.hpp"

class DecorateNode : public Node {
public:
    std::shared_ptr<Node> decorator, inner;
public:
    DecorateNode();
};