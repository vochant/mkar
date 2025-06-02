#pragma once

#include <string>
#include <iostream>
#include <memory>
#include <vector>

#include "util.hpp"

class Node {
public:
    enum class Type {
        Creation, Call, If, For, While,
        Infix, Prefix, Scope, Function,
        Identifier, Remove, CFor,
        Program, Import, Assign, Statement,
        Enumerate, Error, Index, TypeName,
        InDecrement, Expr, Array, Object,
        Return, Ternary, Group, Integer, Float,
		Boolean, String, Null, FunctionDef,
        Decorate, BreakContinue
    } type;
    Node(Type type);
    virtual ~Node();
};