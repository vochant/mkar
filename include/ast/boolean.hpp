#pragma once

#include "ast/base/node.hpp"

class BooleanNode : public Node {
public:
	bool value;
	BooleanNode(bool value);
};