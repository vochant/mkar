#pragma once

#include "object/commonobject.hpp"

#include <map>

class NativeObject : public CommonObject {
private:
    std::map<std::string, std::shared_ptr<Object>> entries;
public:
    NativeObject();
    void set(std::string name, std::shared_ptr<Object> obj) override;
    std::shared_ptr<Object> get(std::string name) override;
    std::string toString() override;
    std::shared_ptr<Object> make_copy() override;
};