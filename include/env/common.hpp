#pragma once

#include <string>
#include "object/object.hpp"
#include <map>

struct CommonEntry {
    bool isConst;
    std::shared_ptr<Object> value;
};

class CommonEnvironment {
public:
    std::shared_ptr<CommonEnvironment> parent;
    std::map<std::string, CommonEntry> entries;
public:
    std::shared_ptr<Object> get(std::string name);
    std::shared_ptr<Object> getUnder(std::string name, long long ident);
    void set(std::string name, std::shared_ptr<Object> obj);
    void makeConst(std::string name);
    bool has(std::string name);
    void remove(std::string name);
    CommonEnvironment(std::shared_ptr<CommonEnvironment> parent = nullptr);
};

using Environment = CommonEnvironment;