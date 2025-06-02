#pragma once

#include "ast/base/node.hpp"
 
class InDecrementNode : public Node {
public:
    bool isDecrement, isAfter;
    std::shared_ptr<Node> body;
    InDecrementNode(std::shared_ptr<Node> body, bool isDecrement, bool isAfter);
};