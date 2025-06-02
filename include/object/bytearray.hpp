#pragma once

#include "object/object.hpp"

#include <vector>

class ByteArray : public Object {
public:
    std::vector<unsigned char> value;
public:
    ByteArray();
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};