#pragma once

#include <exception>
#include <string>

class CompilerError : public std::exception {
private:
    std::string desc;
public:
    const char* what() const noexcept override;
    CompilerError(std::string desc) noexcept;
};