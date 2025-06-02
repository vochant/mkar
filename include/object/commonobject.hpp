#pragma once

#include "object/object.hpp"

class CommonObject : public Object {
public:
    enum ObjectType {
        COMMON, NATIVE
    } objtype;
public:
    CommonObject(ObjectType otype);
    virtual void set(std::string name, std::shared_ptr<Object> obj) = 0;
    virtual std::shared_ptr<Object> get(std::string name) = 0;
};