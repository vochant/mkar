#pragma once

// GCT (Global Class Table)

#include <string>
#include <map>
#include <memory>
#include <set>

class MpcEnum {
public:
    std::map<std::string, long long> entries;
    MpcEnum();
};

extern std::map<std::string, std::shared_ptr<MpcEnum>> GENT;