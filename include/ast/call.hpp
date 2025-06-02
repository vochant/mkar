#pragma once

#include <vector>
#include <sstream>

#include "ast/base/node.hpp"

// function-or-class(arg1, arg2, ...)

class CallNode : public Node {
public:
    std::shared_ptr<Node> to_run;
    std::vector<std::shared_ptr<Node>> args;
	std::vector<int> expands;
    CallNode(std::shared_ptr<Node> to_run);
};