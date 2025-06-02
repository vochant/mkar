#pragma once

#include "ast/base/node.hpp"
#include "object/object.hpp"

#include <vector>
#include <sstream>
#include <map>

class FunctionNode : public Node {
public:
    std::shared_ptr<Node> inner;
    std::vector<std::string> args;
    std::map<size_t, std::string> typechecks;
    std::string moreName;
    FunctionNode();
public:
    bool hasMore() const {
        return moreName != "__null__";
    }
};