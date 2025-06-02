#pragma once

#include "ast/base/node.hpp"

class FloatNode : public Node {
public:
	double value;
	FloatNode(double value);
};