#pragma once

#include "object/object.hpp"

class Mark : public Object {
public:
    std::string value;
public:
    Mark(std::string value);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};