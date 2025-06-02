#include <utility>

#include "util.hpp"

#include "parser_error.hpp"
#include "compiler_error.hpp"
#include "vm_error.hpp"

unsigned long long _cert;

bool hasError;

std::set<std::string> implist; // Imported files

std::filesystem::path respath;

const unsigned long long NumA = 99991, NumB = 100003;

unsigned long long _FastPow(unsigned long long base, size_t sup) {
    unsigned long long res = 1;
    while (sup) {
        if (sup & 1) res *= base;
        base *= base;
        sup >>= 1;
    }
    return res;
}

unsigned long long GetHash(const std::string str, const unsigned long long num) {
    unsigned long long res = 0;
    for (size_t i = 0; i < str.length(); i++) {
        res = (res * num) + str[i];
    }
    return res;
}

unsigned long long ConcatHash(const unsigned long long a, const unsigned long long b, const unsigned long long num, const size_t lenA) {
    return _FastPow(num, lenA) * a + b;
}

StringHash genHash(const std::string str) {
    return {GetHash(str, NumA), GetHash(str, NumB)};
}

StringHash concatHash(const StringHash a, const StringHash b, const size_t lenL) {
    return {ConcatHash(a.first, b.first, NumA, lenL), ConcatHash(a.second, b.second, NumB, lenL)};
}

ParserError::ParserError(std::string descr, Lexer* lexer) noexcept {
    if (lexer != nullptr) {
        desc = lexer->get_desc() + " " + descr;
    }
    else {
        desc = "[unknown] " + descr;
    }
}

CompilerError::CompilerError(std::string desc) noexcept : desc(desc) {}

VMError::VMError(std::string pos, std::string desc) noexcept : pos(pos), desc(desc) {}

const char* ParserError::what() const noexcept {
    return ("ParserError: " + desc).c_str();
}

const char* CompilerError::what() const noexcept {
    return ("CompilerError: " + desc).c_str();
}

const char* VMError::what() const noexcept {
    return ("VMError: [" + pos + "] " + desc).c_str();
}

#include <iostream>

class UtilError : std::exception {
private:
    std::string desc;
public:
    const char* what() const noexcept override {
        return ("UtilError: " + desc).c_str();
    }
    UtilError(std::string desc) noexcept : desc(desc) {}
};

namespace BinaryOut {
    void write_byte(std::ostream& os, const char b) {
        os.write(&b, sizeof(char));
    }

    void write_string(std::ostream& os, const std::string str) {
        write_data(os, str.length());
        for (size_t i = 0; i < str.length(); i++) {
            write_byte(os, str.at(i));
        }
    }
}

int getweight(const char* const str) {
	unsigned int ch0 = str[0];
	if (ch0 < 0x80) {
		return 1;
	}
	unsigned int ch1 = str[1];
	if ((ch0 & 0xE0) == 0xC0) {
		return 2;
	}
	unsigned int ch2 = str[2];
	if ((ch0 & 0xF0) == 0xE0) {
		return 3;
	}
	unsigned int ch3 = str[3];
	if ((ch0 & 0xF8) == 0xF0) {
		return 4;
	}
	return 1;
}

namespace BinaryIn {
    char read_byte(std::istream& is) {
        char _res;
        is.read(&_res, sizeof(char));
        return _res;
    }

    std::string read_string(std::istream& is) {
        size_t _len = read_data<size_t>(is);
        std::string _str;
        while (_len--) {
            _str += read_byte(is);
        }
        return _str;
    }
}

unsigned char read_hex(char in) {
    if ('0' <= in && in <= '9') return (in - '0');
    if ('a' <= in && in <= 'f') return (in - 'a' + 10);
    if ('A' <= in && in <= 'F') return (in - 'A' + 10);
    return 255;
}

std::string unescape(std::string in) {
    std::string res = "";
    size_t p = 1;
    while (p < in.length() - 1) {
        if (in[p] == '\\') {
            if (p == in.length() - 2) {
                throw UtilError("Too short after rslash when unescaping a string");
            }
            switch (in[p + 1]) {
            case 'n':
                res += '\n';
                break;
            case 'r':
                res += '\r';
                break;
            case 'b':
                res += '\b';
                break;
            case 't':
                res += '\t';
                break;
            case 'a':
                res += '\a';
                break;
            case '"':
                res += '"';
                break;
            case '\'':
                res += '\'';
                break;
            case '\\':
                res += '\\';
                break;
            case 'x':
                if (p >= in.length() - 4) {
                    throw UtilError("Too short after rslash when unescaping a string");
                }
                res += (char)(read_hex(in[p + 2]) << 4 | read_hex(in[p + 3]));
                break;
            default:
                res += '\\';
                res += in[p + 1];
            }
            if (in[p + 1] == 'x') p += 4;
            else p += 2;
            continue;
        }
        if (in[p] == '\t' || in[p] == '\n' || in[p] == '\a' || in[p] == '\r') {
            throw UtilError("Not allowed to contain '\n', '\t', '\a' or '\r' in a string");
        }
        int w = getweight(&in[p]);
        while (w--) {
            res += in[p];
            p++;
        }
    }
    return res;
}

char ctohex(char v) {
    if (v < 10) return v + '0';
    return v - 10 + 'a';
}

std::string escape(std::string in) {
    std::string res = "\"";
    for (size_t i = 0; i < in.length(); i++) {
        if (32 <= in[i] && in[i] <= 126) {
            if (in[i] == '\\') res += "\\\\";
            else if (in[i] == '"') res += "\\\"";
            else res += in[i];
        }
        else {
            if (in[i] == '\n') res += "\\n";
            else if (in[i] == '\r') res += "\\r";
            else if (in[i] == '\a') res += "\\a";
            else if (in[i] == '\b') res += "\\b";
            else if (in[i] == '\t') res += "\\t";
            else {
                int w = getweight(&in[i]);
                if (i + w > in.length()) {
                    for (int j = i; j < in.length(); j++) {
                        res += "\\x";
                        res += ctohex(((unsigned char)(in[j])) >> 4);
                        res += ctohex(in[j] & 15);
                    }
                    break;
                }
                if (w == 1) {
                    res += "\\x";
                    res += ctohex(((unsigned char)(in[i])) >> 4);
                    res += ctohex(in[i] & 15);
                }
                else {
                    while (w--) {
                        res += in[i];
                        i++;
                    }
                    i--;
                }
            }
        }
    }
    res += '"';
    return res;
}