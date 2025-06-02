#pragma once

#include "ast/base/node.hpp"

class IntegerNode : public Node {
public:
	long long value;
	IntegerNode(long long value);
};