#pragma once

#define VERSION_NUMBER 0
#define IS_DEBUG true
#define CONSOLE_BUILD

#include <random>
#include <iostream>
#include <set>
#include <filesystem>
#include <string>

typedef std::pair<unsigned long long, unsigned long long> StringHash;

extern unsigned long long _cert;

extern bool hasError;

extern std::set<std::string> implist; // Imported files

extern std::filesystem::path respath;

unsigned long long _FastPow(unsigned long long base, size_t sup);
std::string unescape(std::string in);
std::string escape(std::string in);
int getweight(const char* const str);

namespace BinaryOut {
    void write_byte(std::ostream& os, const char b);
    
    template<typename _Tp>
    void write_data(std::ostream& os, const _Tp d) {
        os.write(reinterpret_cast<const char*>(&d), sizeof(_Tp));
    }

    void write_string(std::ostream& os, const std::string str);
}

namespace BinaryIn {
    char read_byte(std::istream& is);
    
    template<typename _Tp>
    _Tp read_data(std::istream& is) {
        _Tp _res;
        is.read(reinterpret_cast<char*>(&_res), sizeof(_Tp));
        return _res;
    }
    
    std::string read_string(std::istream& is);
}

StringHash genHash(const std::string str);
StringHash concatHash(const StringHash x, const StringHash y, const size_t lenL);