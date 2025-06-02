#pragma once

#include "object/object.hpp"

class Integer : public Object {
public:
    long long value;
public:
    Integer(long long value);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};