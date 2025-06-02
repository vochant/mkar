#pragma once

#include "object/object.hpp"

class Null : public Object {
public:
    Null();
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};