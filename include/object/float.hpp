#pragma once

#include "object/object.hpp"

class Float : public Object {
public:
    double value;
public:
    Float(double value);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};