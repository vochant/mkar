#pragma once

#include "object/object.hpp"

class Byte : public Object {
public:
    unsigned char value;
public:
    Byte(unsigned char value);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};