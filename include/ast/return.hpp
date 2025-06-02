#pragma once

#include "ast/base/node.hpp"

class ReturnNode : public Node {
public:
    std::shared_ptr<Node> obj;
    bool isReference;
    ReturnNode(std::shared_ptr<Node> obj);
};