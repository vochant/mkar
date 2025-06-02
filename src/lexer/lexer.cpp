#pragma once

#include "lexer/lexer.hpp"
#include "util.hpp"

#include "parser_error.hpp"

#include <functional>

void reserved_err(std::string _res) {
    throw ParserError("Cannot use reserved identifier '" + _res + "'");
}

void Lexer::break_whitespace() {
    while (_at < _input.length() && isspace(_input.at(_at))) {
        if (_input.at(_at) == '\n') {
            _line++;
            _column = 0;
        }
        else {
            _column++;
        }
        _at++;

    }
}

Lexer::Lexer(std::string _input, std::string _describe) : _input(_input + " "), _describe(_describe), _at(0), _line(1), _column(0) {}

std::string Lexer::get_desc() const {
    return "at (" + std::to_string(_line - 1) + ", " + std::to_string(_column + 1) + ") of " + _describe;
} 

Token::Type Lexer::lookup(std::string str) {
    Token::Type result = Token::Type::Identifier;
    for (auto it = Token::typeNames.begin(); it != Token::typeNames.end(); it++) {
        if (it->second == str) {
            result = it->first;
        }
    }
    return result;
}

bool is_unicode(unsigned char ch) {
    return ch > 127;
}

std::string Lexer::read_identifier() {
    std::string res = "";
    while (isalnum(_input.at(_at)) || _input.at(_at) == '_' || _input.at(_at) == '#' || is_unicode(_input.at(_at))) {
        int w = getweight(&_input[_at]);
        _column += w;
        while (w--) {
            res += _input.at(_at);
            _at++;
        }
    }
    return res;
}

std::pair<std::string, Token::Type> Lexer::read_number() {
    std::function<bool(char)> isValid = [](char ch)->bool {
        return isdigit(ch) || ch == '.';
    };
    std::string res;
    if (_input.at(_at) == '0') {
        if (_input.at(_at + 1) == 'x') {
            isValid = [](char ch)->bool {
                return isdigit(ch) || ('a' <= ch && ch <= 'f') || ('A' <= ch && ch <= 'F');
            };
            _column += 2;
            _at += 2;
            res = "0x";
        }
        else if (_input.at(_at + 1) == 'b') {
            isValid = [](char ch)->bool {
                return ch == '0' || ch == '1';
            };
            _column += 2;
            _at += 2;
            res = "0b";
        }
        else if (isdigit(_input.at(_at + 1))) {
            isValid = [](char ch)->bool {
                return '0' <= ch && ch <= '7';
            };
            _column++;
            _at++;
            res = "0";
        }
        else if (_input.at(_at + 1) != '.') {
            _column++;
            _at++;
            return std::make_pair("0", Token::Type::Integer);
        }
    }
    while (isValid(_input.at(_at))) {
        if (_input.at(_at) == '.' && (_input.length() <= (_at + 1) || !isdigit(_input.at(_at + 1)))) {
            break;
        }
        res += _input.at(_at);
        _column++;
        _at++;
    }
    return std::make_pair(res, (res.find('.') != res.npos) ? Token::Type::Float : Token::Type::Integer);
}

std::string Lexer::read_string() {
    char ch = _input.at(_at);
    std::string res = "";
    res += ch;
    _column++;
    _at++;
    while (_input.at(_at) != ch) {
        if (_input.at(_at) == '\n') {
            throw ParserError("Strings cannot contain LF", this);
        }
        if (_input.at(_at) == '\\') {
            if (_at == _input.length() - 1) throw ParserError("String without ending", this);
            if (_input.at(_at + 1) == ch) {
                res += '\\';
                res += ch;
                _column += 2;
                _at += 2;
                continue;
            }
        }
        int w = getweight(&_input[_at]);
        while (w--) {
            res += _input.at(_at);
            _column++;
            _at++;
            if (_at == _input.length()) {
                throw ParserError("String without ending", this);
            }
        }
    }
    _column++;
    _at++;
    return res + ch;
}

std::shared_ptr<Token> Lexer::parseNext() {
    // Break whitespace
    break_whitespace();
    // Return "End" when end.
    if (_input.length() == _at) {
        return std::make_shared<Token>("", Token::Type::End);
    }
    // Ignore comments.
    if (_input.length() > _at + 1 && _input.at(_at) == '#' && _input.at(_at + 1) == '!') {
        while (_input.length() > _at && _input.at(_at) != '\n') {
            _at++;
        }
        _at++;
        _line++;
        _column = 0;
    } // UNIX <#!/path/to/mpcc>
    if (_input.length() > _at + 1 && _input.at(_at) == '/') {
        if (_input.at(_at + 1) == '/') {
            while (_input.length() > _at && _input.at(_at) != '\n') {
                _at++;
            }
            _at++;
            _line++;
            _column = 0;
        } // In-line comment
        else if (_input.at(_at + 1) == '*') {
            _at += 2;
            _column += 2;
            while (_input.length() > _at) {
                if (_input.at(_at) == '*' && _input.length() > (_at + 1)) {
                    if (_input.at(_at + 1) == '/') {
                        _at += 2;
                        break;
                    }
                }
                if (_input.at(_at) == '\n') {
                    _line++;
                    _column = 0;
                }
                else {
                    _column++;
                }
                _at++;
            }
        } // Out-line comment
    }
    // Try non-identifier tokens.
    switch (_input.at(_at)) {
    case '@':
        _column++;
        _at++;
        return std::make_shared<Token>("@", Token::Type::Decorate);
    case '~':
        _column++;
        _at++;
        return std::make_shared<Token>("~", Token::Type::BitwiseNot);
    case '!':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
            if (_input.length() > _at + 2 && _input.at(_at + 2) == '=') {
                _column += 3;
                _at += 3;
                return std::make_shared<Token>("!==", Token::Type::NotFullEqual);
            }
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("!=", Token::Type::NotEqual);
        }
        _column++;
        _at++;
        return std::make_shared<Token>("!", Token::Type::LogicalNot);
    case '$':
        _column++;
        _at++;
        return std::make_shared<Token>("$", Token::Type::Lambda);
    case '%':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("%=", Token::Type::ModulusAssign);
        }
        _column++;
        _at++;
        return std::make_shared<Token>("%", Token::Type::Modulus);
    case '^':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("^=", Token::Type::BitwiseXorAssign);
        }
        _column++;
        _at++;
        return std::make_shared<Token>("^", Token::Type::BitwiseXor);
    case '&':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '&') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("&&", Token::Type::LogicalAnd);
            }
            if (_input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("&=", Token::Type::BitwiseAndAssign);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("&", Token::Type::BitwiseAnd);
    case '*':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("*=", Token::Type::AsteriskAssign);
        }
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '*') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("**", Token::Type::Pow);
        }
        _column++;
        _at++;
        return std::make_shared<Token>("*", Token::Type::Asterisk);
    case '(':
        _column++;
        _at++;
        return std::make_shared<Token>("(", Token::Type::LParan);
    case ')':
        _column++;
        _at++;
        return std::make_shared<Token>(")", Token::Type::RParan);
    case '-':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("-=", Token::Type::MinusAssign);
            }
            if (_input.at(_at + 1) == '-') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("--", Token::Type::Decrement);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("-", Token::Type::Minus);
    case '=':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '=') {
                if (_input.length() > _at + 2 && _input.at(_at + 2) == '=') {
                    _column += 3;
                    _at += 3;
                    return std::make_shared<Token>("===", Token::Type::FullEqual);
                }
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("==", Token::Type::Equal);
            }
            if (_input.at(_at + 1) == '>') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("=>", Token::Type::Arrow);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("=", Token::Type::Assign);
    case '+':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("+=", Token::Type::PlusAssign);
            }
            if (_input.at(_at + 1) == '+') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("++", Token::Type::Increment);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("+", Token::Type::Plus);
    case '{':
        _column++;
        _at++;
        return std::make_shared<Token>("{", Token::Type::LBrace);
    case '}':
        _column++;
        _at++;
        return std::make_shared<Token>("}", Token::Type::RBrace);
    case '[':
        _column++;
        _at++;
        return std::make_shared<Token>("[", Token::Type::LBracket);
    case ']':
        _column++;
        _at++;
        return std::make_shared<Token>("]", Token::Type::RBracket);
    case '|':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("|=", Token::Type::BitwiseOrAssign);
            }
            if (_input.at(_at + 1) == '|') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("||", Token::Type::LogicalOr);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("|", Token::Type::BitwiseOr);
    case ',':
        _column++;
        _at++;
        return std::make_shared<Token>(",", Token::Type::Comma);
    case '.':
        if (_input.length() > _at + 2 && _input.at(_at + 1) == '.' && _input.at(_at + 2) == '.') {
            _column += 3;
            _at += 3;
            return std::make_shared<Token>("...", Token::Type::More);
        }
        _column++;
        _at++;
        return std::make_shared<Token>(".", Token::Type::Extand);
    case ';':
        _column++;
        _at++;
        return std::make_shared<Token>(";", Token::Type::Semicolon);
    case '/':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("/=", Token::Type::SlashAssign);
        }
        _column++;
        _at++;
        return std::make_shared<Token>("/", Token::Type::Slash);
    case '<':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '<') {
                if (_input.length() > _at + 2 && _input.at(_at + 2) == '=') {
                    _column += 3;
                    _at += 3;
                    return std::make_shared<Token>("<<=", Token::Type::BitwiseLeftAssign);
                }
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("<<", Token::Type::BitwiseLeft);
            }
            if (_input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>("<=", Token::Type::LessEqual);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>("<", Token::Type::Less);
    case '>':
        if (_input.length() > _at + 1) {
            if (_input.at(_at + 1) == '>') {
                if (_input.length() > _at + 2 && _input.at(_at + 2) == '=') {
                    _column += 3;
                    _at += 3;
                    return std::make_shared<Token>(">>=", Token::Type::BitwiseRightAssign);
                }
                _column += 2;
                _at += 2;
                return std::make_shared<Token>(">>", Token::Type::BitwiseRight);
            }
            if (_input.length() > _at + 1 && _input.at(_at + 1) == '=') {
                _column += 2;
                _at += 2;
                return std::make_shared<Token>(">=", Token::Type::GreaterEqual);
            }
        }
        _column++;
        _at++;
        return std::make_shared<Token>(">", Token::Type::Greater);
    case ':':
        if (_input.length() > _at + 1 && _input.at(_at + 1) == ':') {
            _column += 2;
            _at += 2;
            return std::make_shared<Token>("::", Token::Type::ForceExtand);
        }
        _column++;
        _at++;
        return std::make_shared<Token>(":", Token::Type::As);
    case '?':
        _column++;
        _at++;
        return std::make_shared<Token>("?", Token::Type::Ternary);
    }
    if (isdigit(_input.at(_at))) {
        auto _result = read_number();
        return std::make_shared<Token>(_result.first, _result.second);
    }
    if (_input.at(_at) == '"' || _input.at(_at) == '\'') {
        return std::make_shared<Token>(read_string(), Token::Type::String);
    }
    std::string id = read_identifier();
    if (reserved.count(id) > 0) {
        throw ParserError("Cannot use reserved identifier '" + id + "'", this);
    }
    return std::make_shared<Token>(id, lookup(id));
}

std::set<std::string> Lexer::reserved = {
    "__index__",
    "__builtin__",
    "__null__",
	"__reserved__",
	"__system__",
	"__external__",
	"__test__",
    "__seteflags__",
    "__eflags__",
    "__mpcc__",
    "__mpc__",
    "__kernel__",
    "__undefined__"
};