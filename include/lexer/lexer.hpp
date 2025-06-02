#pragma once

#include <fstream>
#include <string>
#include <algorithm>
#include <memory>
#include <set>

#include "util.hpp"
#include "lexer/token.hpp"

void reserved_err(std::string _res);

class Lexer {
private:
    std::string _input, _describe;
    size_t _at, _line, _column;
private:
    void break_whitespace();
    std::string read_identifier();
    static Token::Type lookup(std::string str);
    std::pair<std::string, Token::Type> read_number();
    std::string read_string();
public:
    Lexer(std::string _input, std::string _describe = "[stdin]");
    std::shared_ptr<Token> parseNext();
    static std::set<std::string> reserved;
    std::string get_desc() const;
};
