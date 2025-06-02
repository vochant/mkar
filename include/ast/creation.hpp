#pragma once

#include "ast/base/node.hpp"
#include "ast/identifier.hpp"

#include <utility>
#include <sstream>
#include <vector>

// <creation> name1, name2=value

class CreationNode : public Node {
public:
    std::vector<std::pair<std::string, std::shared_ptr<Node>>> creations;
    bool isGlobal, allowOverwrite, isConst;
    CreationNode(bool isGlobal, bool allowOverwrite, bool isConst);
};