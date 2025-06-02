#pragma once

#include <exception>
#include <string>

class VMError : public std::exception {
private:
    std::string pos, desc;
public:
    VMError(std::string pos, std::string desc) noexcept;
    const char* what() const noexcept;
};