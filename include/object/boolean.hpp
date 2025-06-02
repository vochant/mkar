#pragma once

#include "object/object.hpp"

class Boolean : public Object {
public:
    bool value;
public:
    Boolean(bool value);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};