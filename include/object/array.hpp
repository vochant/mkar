#pragma once

#include "object/object.hpp"

#include <vector>

class Array : public Object {
public:
    std::vector<std::shared_ptr<Object>> value;
public:
    Array();
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};