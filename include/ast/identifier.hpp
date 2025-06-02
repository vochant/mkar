#pragma once

#include "ast/base/node.hpp"

class IdentifierNode : public Node {
public:
    std::string id;
    IdentifierNode(std::string id);
};