#pragma once

#include "ast/base/node.hpp"

class IndexNode : public Node {
public:
    std::shared_ptr<Node> left, index;
    IndexNode(std::shared_ptr<Node> left, std::shared_ptr<Node> index);
};