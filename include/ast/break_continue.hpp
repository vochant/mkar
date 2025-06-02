#pragma once

#include "ast/base/node.hpp"

class BreakContinueNode : public Node {
public:
    bool isContinue;
public:
    BreakContinueNode(bool isContinue);
};