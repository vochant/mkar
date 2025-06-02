#pragma once

#include "ast/base/node.hpp"

class GroupNode : public Node {
public:
    std::shared_ptr<Node> v;
    GroupNode(std::shared_ptr<Node> v);
};