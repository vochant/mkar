#pragma once

#include "object/object.hpp"
#include "object/array.hpp"

class Iterator : public Object {
public:
    std::shared_ptr<Array> toArray();
    virtual bool hasNext() = 0;
    virtual std::shared_ptr<Object> next() = 0;
    virtual void go() = 0;
    std::string toString() override;
public:
    Iterator();
};