#pragma once

#include "ast/base/node.hpp"
#include "ast/identifier.hpp"


// <creation> name1, name2=value

class RemoveNode : public Node {
public:
    std::string toRemove;
    RemoveNode(std::string toRemove);
};