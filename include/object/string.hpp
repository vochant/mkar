#pragma once

#include "object/object.hpp"
#include "util.hpp"

class String : public Object {
public:
    std::string value;
    StringHash hash;
public:
    String(char ch);
    String(std::string value);
    String(std::string value, StringHash hash);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};