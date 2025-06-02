#pragma once

#include "object/object.hpp"
#include <fstream>

class File : public Object {
public:
    bool isClosed;
    std::shared_ptr<std::fstream> fs;
public:
    File(std::string name, std::string mode);
    File(std::shared_ptr<std::fstream> fs);
    std::shared_ptr<Object> make_copy() override;
    std::string toString() override;
    void close();
};