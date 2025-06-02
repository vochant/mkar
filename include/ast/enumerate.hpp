#pragma once

#include "ast/identifier.hpp"

#include <vector>
#include <sstream>

class EnumerateNode : public Node{
public:
    std::vector<std::string> items;
    std::string _name;
    EnumerateNode();
};