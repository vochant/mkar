#pragma once

#include "object/object.hpp"

class Reference : public Object {
public:
    std::shared_ptr<Object>* ptr;
public:
    Reference(std::shared_ptr<Object>* ptr);
    std::string toString() override;
    std::shared_ptr<Object> make_copy() override;
};