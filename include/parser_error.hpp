#pragma once

#include <exception>
#include <string>

#include "lexer/lexer.hpp"

class ParserError : public std::exception {
private:
    std::string desc;
public:
    const char* what() const noexcept override;
    ParserError(std::string desc, Lexer* lexer = nullptr) noexcept;
};