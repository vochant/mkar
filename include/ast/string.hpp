#pragma once

#include "ast/base/node.hpp"

class StringNode : public Node {
public:
	std::string value;
	StringNode(std::string value);
};