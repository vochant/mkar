#pragma once

#include "object/executable.hpp"

#include <functional>

extern Environment* NF_Environment;

typedef std::vector<std::shared_ptr<Object>> Args;
typedef std::function<std::shared_ptr<Object>(Args)> NFunc;

class NativeFunction : public Executable {
private:
    NFunc func;
public:
    NativeFunction(NFunc func);
    std::shared_ptr<Object> call(std::vector<std::shared_ptr<Object>> args) override;
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
};