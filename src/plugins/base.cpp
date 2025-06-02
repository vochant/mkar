#include "plugins/plugin.hpp"
#include "vm_error.hpp"
#include <sstream>
#include "object/string.hpp"
#include "object/executable.hpp"
#include "object/array.hpp"
#include "object/integer.hpp"
#include "vm/vm.hpp"
#include <cstdlib>
#include "util.hpp"
#include "vm/gct.hpp"
#include "object/nativeobject.hpp"
#include "object/reference.hpp"
#include "object/float.hpp"
#include "object/rbit.hpp"
#include "object/bytearray.hpp"
#include "object/byte.hpp"
#include <algorithm>
#include <random>

Plugins::Base::Base() {}

std::shared_ptr<Object> Array_Join(Args args) {
    plain(args);
    if (args.size() == 1) {
        args.push_back(std::make_shared<String>(""));
    }
    if (args.size() != 2 || args[1]->type != Object::Type::String) {
        throw VMError("(Base)Array_Join", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Join", "Incorrect Format");
    }
    std::string str = std::dynamic_pointer_cast<String>(args[1])->value;
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    std::stringstream ss;
    bool isFirst = true;
    for (auto& e : arr->value) {
        if (isFirst) isFirst = false;
        else ss << str;
        ss << e->toString();
    }
    return std::make_shared<String>(ss.str());
}

std::shared_ptr<Object> Array_Map(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Map", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Map", "Incorrect Format");
    }
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    auto res = std::make_shared<Array>();
    res->value.reserve(arr->value.size());
    for (auto& e : arr->value) {
        res->value.push_back(exec->call({e}));
    }
    return res;
}

std::shared_ptr<Object> Array_Filter(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Filter", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Filter", "Incorrect Format");
    }
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    auto res = std::make_shared<Array>();
    for (auto& e : arr->value) {
        if (gVM->isTrue(exec->call({e}))) {
            res->value.push_back(e);
        }
    }
    return res;
}

std::shared_ptr<Object> Array_FlatMap(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Map", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Map", "Incorrect Format");
    }
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    auto res = std::make_shared<Array>();
    res->value.reserve(arr->value.size());
    for (auto& e : arr->value) {
        auto v = exec->call({e});
        if (v->type == Object::Type::Iterator) {
            v = std::dynamic_pointer_cast<Iterator>(v)->toArray();
        }
        if (v->type == Object::Type::Array) {
            auto cas = std::dynamic_pointer_cast<Array>(v);
            for (auto& i : cas->value) {
                res->value.push_back(i);
            }
        }
        else res->value.push_back(v);
    }
    return res;
}

std::shared_ptr<Object> Array_Foreach(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Foreach", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Foreach", "Incorrect Format");
    }
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    for (auto& e : arr->value) {
        exec->call({e});
    }
    return gVM->VNull;
}

std::shared_ptr<Object> Array_Find(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Find", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Find", "Incorrect Format");
    }
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    long long counter = 0;
    for (auto& e : arr->value) {
        if (gVM->isTrue(exec->call({e, std::make_shared<Integer>(counter)}))) return e;
        counter++;
    }
    return gVM->VNull;
}

std::shared_ptr<Object> Array_FindAt(Args args) {
    plain(args);
    if (args.size() != 2 || args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_FindAt", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_FindAt", "Incorrect Format");
    }
    auto arr = std::dynamic_pointer_cast<Array>(args[0]);
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    long long counter = 0;
    for (auto& e : arr->value) {
        if (gVM->isTrue(exec->call({e, std::make_shared<Integer>(counter)}))) return std::make_shared<Integer>(counter);
        counter++;
    }
    return gVM->VNull;
}

std::shared_ptr<Object> ArrStr_Reverse(Args args) {
    plain(args);
    if (args.size() != 1) {
        throw VMError("(Base)ArrStr_Reverse", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type == Object::Type::Array) {
        auto arr = std::dynamic_pointer_cast<Array>(args[0]);
        auto res = std::make_shared<Array>();
        res->value.reserve(arr->value.size());
        for (auto it = arr->value.rbegin(); it != arr->value.rend(); it++) {
            res->value.push_back(*it);
        }
        return res;
    }
    else if (args[0]->type == Object::Type::String) {
        auto str = std::dynamic_pointer_cast<String>(args[0])->value;
        std::stringstream ss;
        for (size_t i = str.length() - 1; i >= 0; i--) ss << str.at(i);
        return std::make_shared<String>(ss.str());
    }
    else if (args[0]->type == Object::Type::ByteArray) {
        auto arr = std::dynamic_pointer_cast<ByteArray>(args[0]);
        auto res = std::make_shared<ByteArray>();
        res->value.reserve(arr->value.size());
        for (auto it = arr->value.rbegin(); it != arr->value.rend(); it++) {
            res->value.push_back(*it);
        }
        return res;
    }
    throw VMError("(Base)ArrStr_Reverse", "Incorrect Format");
}

std::shared_ptr<Object> String_Split(Args args) {
    plain(args);
    if (args.size() < 1 || args.size() > 2 || args[0]->type != Object::Type::String) {
        throw VMError("(Base)String_Split", "Incorrect Format");
    }
    if (args.size() == 2) {
        if (args[1]->type != Object::Type::String) {
            throw VMError("(Base)String_Split", "Incorrect Format");
        }
        if (std::dynamic_pointer_cast<String>(args[1])->value == "") args.pop_back();
    }
    auto& str = std::dynamic_pointer_cast<String>(args[0])->value;
    if (args.size() == 1) {
        // 分隔符是空字符串，每个字符一项
        auto res = std::make_shared<Array>();
        res->value.reserve(str.length());
        for (size_t i = 0; i < str.length(); i++) {
            res->value.push_back(std::make_shared<String>(str.at(i)));
        }
        return res;
    }
    else {
        // 使用 KMP 算法进行 split 操作
        auto& mode = std::dynamic_pointer_cast<String>(args[1])->value;
        auto res = std::make_shared<Array>();
        std::vector<size_t> fail;
        fail.reserve(mode.length());
        fail.push_back(0);
        size_t mode_length = mode.length();
        for (size_t i = 1; i < mode_length; i++) {
            size_t p = fail[i - 1];
            while (p && mode[p] != mode[i]) p = fail[p - 1];
            fail.push_back(p + (mode[i] == mode[p]));
        }
        size_t e = 0, begin = 0;
        for (size_t i = 0; i < str.length(); i++) {
            while (e && mode[e] != str[i]) e = fail[e - 1];
            if (mode[e] == str[i]) e++;
            if (e == mode_length) {
                if (i + 1 - mode_length - begin == 0) res->value.push_back(std::make_shared<String>(""));
                else res->value.push_back(std::make_shared<String>(str.substr(begin, i + 1 - mode_length - begin)));
                begin = i + 1;
                e = 0;
            }
        }
        if (begin == str.length()) res->value.push_back(std::make_shared<String>(""));
        else res->value.push_back(std::make_shared<String>(str.substr(begin)));
        return res;
    }
}

std::shared_ptr<Object> String_Replace(Args args) {
    plain(args);
    if (args.size() != 3 || args[0]->type != Object::Type::String || args[1]->type != Object::Type::String || args[2]->type != Object::Type::String) {
        throw VMError("(Base)String_Replace", "Incorrect Format");
    }
    auto& str = std::dynamic_pointer_cast<String>(args[0])->value;
    auto& mode = std::dynamic_pointer_cast<String>(args[1])->value;
    auto& to = std::dynamic_pointer_cast<String>(args[2])->value;
    std::stringstream ss;
    std::vector<size_t> fail;
    fail.reserve(mode.length());
    fail.push_back(0);
    size_t mode_length = mode.length();
    for (size_t i = 1; i < mode_length; i++) {
        size_t p = fail[i - 1];
        while (p && mode[p] != mode[i]) p = fail[p - 1];
        fail.push_back(p + (mode[i] == mode[p]));
    }
    size_t e = 0, begin = 0;
    for (size_t i = 0; i < str.length(); i++) {
        while (e && mode[e] != str[i]) e = fail[e - 1];
        if (mode[e] == str[i]) e++;
        if (e == mode_length) {
            if (i + 1 - mode_length - begin != 0) {
                ss << str.substr(begin, i + 1 - mode_length - begin);
            }
            ss << to;
            begin = i + 1;
            e = 0;
        }
    }
    if (begin != str.length()) {
        ss << str.substr(begin);
    }
    return std::make_shared<String>(ss.str());
}

std::shared_ptr<Object> String_Escape(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::String) {
        throw VMError("(Base)String_Escape", "Incorrect Format");
    }
    std::string common_esc = escape(args[0]->toString());
    return std::make_shared<String>(common_esc.substr(1, common_esc.length() - 2));
}

std::shared_ptr<Object> String_Unescape(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::String) {
        throw VMError("(Base)String_Unscape", "Incorrect Format");
    }
    std::string common_unesc = escape("'" + args[0]->toString() + "'");
    return std::make_shared<String>(common_unesc);
}

std::shared_ptr<Object> Typestr(Args args) {
    if (args.size() != 1) {
        throw VMError("(Base)Typestr", "Incorrect Format");
    }
    return std::make_shared<String>(gVM->getTypeString(args[0]));
}

std::shared_ptr<Object> Assert(Args args) {
    if (args.size() != 1) {
        throw VMError("(Base)Assert", "Incorrect Format");
    }
    bool a = gVM->isTrue(args[0]);
    if (!a) {
        throw VMError("(Base)Assert", "Assertion Failed");
    }
    return gVM->VNull;
}

std::shared_ptr<Object> Max(Args args) {
    if (!args.size()) {
        return gVM->VNull;
    }
    if (args.size() == 1) return args[1];
    auto v = gVM->isTrue(gVM->CalculateInfix(">", args[1], args[0], gVM->inner)) ? args[1] : args[0];
    for (size_t i = 2; i < args.size(); i++) {
        if (gVM->isTrue(gVM->CalculateInfix(">", args[i], v, gVM->inner))) {
            v = args[i];
        }
    }
    return v;
}

std::shared_ptr<Object> Min(Args args) {
    if (!args.size()) {
        return gVM->VNull;
    }
    if (args.size() == 1) return args[1];
    auto v = gVM->isTrue(gVM->CalculateInfix("<", args[1], args[0], gVM->inner)) ? args[1] : args[0];
    for (size_t i = 2; i < args.size(); i++) {
        if (gVM->isTrue(gVM->CalculateInfix("<", args[i], v, gVM->inner))) {
            v = args[i];
        }
    }
    return v;
}

std::mt19937_64 _gRND(std::random_device{}());

std::shared_ptr<Object> Random_Integer(Args args) {
    plain(args);
    if (args.size() != 2 || args[0]->type != Object::Type::Integer || args[1]->type != Object::Type::Integer) {
        throw VMError("(Base)Random_Integer", "Incorrect Format");
    }
    long long s = std::dynamic_pointer_cast<Integer>(args[0])->value, e = std::dynamic_pointer_cast<Integer>(args[1])->value;
    if (s > e) {
        throw VMError("(Base)Random_Integer", "Incorrect Format");
    }
    return std::make_shared<Integer>(s + _gRND() % (e - s + 1));
}

std::shared_ptr<Object> String_Digit(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::String) {
        throw VMError("(Base)String_Digit", "Incorrect Format");
    }
    auto str = std::dynamic_pointer_cast<String>(args[0])->value;
    if (str.length() == 1) {
        return std::make_shared<Integer>((unsigned char) str[0]);
    }
    else {
        auto res = std::make_shared<Array>();
        res->value.reserve(str.length());
        for (size_t i = 0; i < str.length(); i++) {
            res->value.push_back(std::make_shared<Integer>((unsigned char) str[i]));
        }
        return res;
    }
}

std::shared_ptr<Object> String_Char(Args args) {
    plain(args);
    if (args.size() != 1) {
        throw VMError("(Base)String_Char", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) {
        return std::make_shared<String>((char)(std::dynamic_pointer_cast<Integer>(args[0])->value));
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)String_Char", "Incorrect Format");
    }
    auto& arr = std::dynamic_pointer_cast<Array>(args[0])->value;
    std::stringstream ss;
    for (auto& e : arr) {
        if (e->type != Object::Type::Integer) {
            throw VMError("(Base)String_Char", "Incorrect Format");
        }
        ss << (char)(std::dynamic_pointer_cast<Integer>(e)->value);
    }
    return std::make_shared<String>(ss.str());
}

std::shared_ptr<Object> To_String(Args args) {
    if (args.size() != 1) {
        throw VMError("(Base)To_String", "Incorrect Format");
    }
    return std::make_shared<String>(args[0]->toString());
}

std::shared_ptr<Object> ArrStr_Length(Args args) {
    if (args.size() != 1) {
        throw VMError("(Base)ArrStr_Length", "Incorrect Format");
    }
    plain(args);
    if (args[0]->type == Object::Type::String) {
        return std::make_shared<Integer>(std::dynamic_pointer_cast<String>(args[0])->value.length());
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type == Object::Type::Array) {
        return std::make_shared<Integer>(std::dynamic_pointer_cast<Array>(args[0])->value.size());
    }
    if (args[0]->type == Object::Type::ByteArray) {
        return std::make_shared<Integer>(std::dynamic_pointer_cast<ByteArray>(args[0])->value.size());
    }
    throw VMError("(Base)ArrStr_Length", "Incorrect Format");
}

std::shared_ptr<Object> Array_Push(Args args) {
    if (args.size() < 2 || args[0]->type != Object::Type::Reference) {
        throw VMError("(Base)Array_Push", "Incorrect Format");
    }
    args[0] = *(std::dynamic_pointer_cast<Reference>(args[0])->ptr);
    plain(args);
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Push", "Incorrect Format");
    }
    auto& arr = std::dynamic_pointer_cast<Array>(args[0])->value;
    for (size_t i = 1; i < args.size(); i++) {
        arr.push_back(args[i]);
    }
    return gVM->VNull;
}

std::shared_ptr<Object> Array_Pop(Args args) {
    if (args.size() == 1) {
        args.push_back(std::make_shared<Integer>(1));
    }
    if (args.size() != 2 || args[0]->type != Object::Type::Reference) {
        throw VMError("(Base)Array_Pop", "Incorrect Format");
    }
    args[0] = *(std::dynamic_pointer_cast<Reference>(args[0])->ptr);
    plain(args);
    if (args[0]->type != Object::Type::Array || args[1]->type != Object::Type::Integer) {
        throw VMError("(Base)Array_Pop", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<Integer>(args[1])->value < 0) {
        throw VMError("(Base)Array_Pop", "Incorrect Format");
    }
    auto p_count = std::min<size_t>(std::dynamic_pointer_cast<Integer>(args[1])->value, std::dynamic_pointer_cast<Array>(args[0])->value.size());
    auto& arr = std::dynamic_pointer_cast<Array>(args[0])->value;
    while (p_count--) arr.pop_back();
    return gVM->VNull;
}

std::shared_ptr<Object> Deduplicate(Args args) {
    plain(args);
    if (args.size() != 1) {
        throw VMError("(Base)Deduplicate", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Deduplicate", "Incorrect Format");
    }
    auto& arr = std::dynamic_pointer_cast<Array>(args[0])->value;
    auto res = std::make_shared<Array>();
    std::set<long long> is;
    std::set<double> fs;
    std::set<std::string> ss;
    for (auto& e : arr) {
        if (e->type == Object::Type::Integer) {
            long long v = std::dynamic_pointer_cast<Integer>(e)->value;
            if (!is.count(v)) {
                is.insert(v);
                res->value.push_back(e);
            }
        }
        else if (e->type == Object::Type::Float) {
            double v = std::dynamic_pointer_cast<Float>(e)->value;
            if (!fs.count(v)) {
                fs.insert(v);
                res->value.push_back(e);
            }
        }
        else if (e->type == Object::Type::String) {
            std::string v = std::dynamic_pointer_cast<String>(e)->value;
            if (!ss.count(v)) {
                ss.insert(v);
                res->value.push_back(e);
            }
        }
        else {
            throw VMError("(Base)Deduplicate", "Unsupported Object Type");
        }
    }
    return res;
}

std::shared_ptr<Object> Make_Exception(Args args) {
    if (args.size() == 0) {
        throw VMError("(Base)Make_Exception", "null");
    }
    if (args.size() == 1) {
        throw VMError("(Base)Make_Exception", args[0]->toString());
    }
    throw VMError("(Base)Make_Exception", "<Multi Arguments Detected>");
}

std::shared_ptr<Object> Make_Range(Args args) {
    plain(args);
    if (args.size() < 2 || args.size() > 3 || args[0]->type != Object::Type::Integer || args[1]->type != Object::Type::Integer) {
        throw VMError("(Base)Make_Range", "Incorrect Format");
    }
    auto b = std::dynamic_pointer_cast<Integer>(args[0])->value, e = std::dynamic_pointer_cast<Integer>(args[1])->value;
    if (args.size() == 2) {
        args.push_back(std::make_shared<Integer>(b <= e ? 1 : -1));
    }
    else if (args[2]->type != Object::Type::Integer) {
        throw VMError("(Base)Make_Range", "Incorrect Format");
    }
    auto s = std::dynamic_pointer_cast<Integer>(args[2])->value;
    return std::make_shared<RangeBasedIterator>(b, e, s);
}

std::shared_ptr<Object> Comparator_Greater(Args args) {
    if (args.size() != 2) {
        throw VMError("(Base)Comparator_Greater", "Incorrect Format");
    }
    return gVM->CalculateInfix("<", args[0], args[1], gVM->inner);
}

std::shared_ptr<Object> Comparator_Less(Args args) {
    if (args.size() != 2) {
        throw VMError("(Base)Comparator_Less", "Incorrect Format");
    }
    return gVM->CalculateInfix(">", args[0], args[1], gVM->inner);
}

std::shared_ptr<Object> Array_Sort(Args args) {
    if (args.size() < 1 || args.size() > 2) {
        throw VMError("(Base)Array_Sort", "Incorrect Format");
    }
    args[0] = args[0]->make_copy();
    plain(args);
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    if (args[0]->type != Object::Type::Array) {
        throw VMError("(Base)Array_Sort", "Incorrect Format");
    }
    if (args.size() == 1) {
        args.push_back(std::make_shared<NativeFunction>(Comparator_Greater));
    }
    else if (args[1]->type != Object::Type::Executable) {
        throw VMError("(Base)Array_Sort", "Incorrect Format");
    }
    auto exec = std::dynamic_pointer_cast<Executable>(args[1]);
    auto& arr = std::dynamic_pointer_cast<Array>(args[0])->value;
    std::sort(arr.begin(), arr.end(), [&exec](std::shared_ptr<Object> a, std::shared_ptr<Object> b)->bool {
        return gVM->isTrue(exec->call({a, b}));
    });
    return args[0];
}

std::shared_ptr<Object> ArrStr_Slice(Args args) {
    plain(args);
    if (args.size() < 2 || args.size() > 3 || args[1]->type != Object::Type::Integer) {
        throw VMError("(Base)ArrStr_Slice", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Iterator) {
        args[0] = std::dynamic_pointer_cast<Iterator>(args[0])->toArray();
    }
    size_t length;
    if (args[0]->type == Object::Type::String) {
        length = std::dynamic_pointer_cast<String>(args[0])->value.length();
    }
    else if (args[0]->type == Object::Type::Array) {
        length = std::dynamic_pointer_cast<Array>(args[0])->value.size();
    }
    else if (args[0]->type == Object::Type::ByteArray) {
        length = std::dynamic_pointer_cast<ByteArray>(args[0])->value.size();
    }
    else {
        throw VMError("(Base)ArrStr_Slice", "Incorrect Format");
    }
    if (args.size() == 2) {
        args.push_back(std::make_shared<Integer>(length));
    }
    if (args[2]->type != Object::Type::Integer) {
        throw VMError("(Base)ArrStr_Slice", "Incorrect Format");
    }
    long long s = std::dynamic_pointer_cast<Integer>(args[1])->value, e = std::dynamic_pointer_cast<Integer>(args[2])->value;
    if (args[0]->type == Object::Type::String) {
        std::stringstream ss;
        std::string& str = std::dynamic_pointer_cast<String>(args[0])->value;
        for (long long i = s; i < e; i++) {
            ss << str[(i % length + length) % length];
        }
        return std::make_shared<String>(ss.str());
    }
    if (args[0]->type == Object::Type::Array) {
        auto res = std::make_shared<Array>();
        auto& vec = std::dynamic_pointer_cast<Array>(args[0])->value;
        for (long long i = s; i < e; i++) {
            res->value.push_back(vec[(i % length + length) % length]);
        }
        return res;
    }
    if (args[0]->type == Object::Type::ByteArray) {
        auto res = std::make_shared<ByteArray>();
        auto& vec = std::dynamic_pointer_cast<ByteArray>(args[0])->value;
        for (long long i = s; i < e; i++) {
            res->value.push_back(vec[(i % length + length) % length]);
        }
        return res;
    }
    throw VMError("(Base)ArrStr_Slice", "Unhandled Error");
}

std::shared_ptr<Object> System_Exec(Args args) {
    if (!args.size()) {
        throw VMError("(Base)System_Exec", "Too few arguments");
    }
    std::stringstream ss;
    bool isFirst = true;
    for (auto& e : args) {
        if (isFirst) isFirst = false;
        else ss << ' ';
        ss << e->toString();
    }
    int retval = system(ss.str().c_str());
    return std::make_shared<Integer>(retval);
}

void Plugins::Base::enable() {
    regist("join", Array_Join);
    regist("map", Array_Map);
    regist("flatMap", Array_FlatMap);
    regist("foreach", Array_Foreach);
    regist("find", Array_Find);
    regist("findAt", Array_FindAt);
    regist("push", Array_Push);
    regist("pop", Array_Pop);
    regist("filter", Array_Filter);
    regist("reverse", ArrStr_Reverse);
    regist("len", ArrStr_Length);
    regist("split", String_Split);
    regist("escape", String_Escape);
    regist("unescape", String_Unescape);
    regist("digit", String_Digit);
    regist("char", String_Char);
    regist("system", System_Exec);
    regist("typestr", Typestr);
    regist("assert", Assert);
    regist("max", Max);
    regist("min", Min);
    regist("toString", To_String);
    regist("dedupicate", Deduplicate);
    regist("exception", Make_Exception);
    regist("range", Make_Range);
    regist("sort", Array_Sort);
    regist("slice", ArrStr_Slice);
    regist("greater", Comparator_Greater);
    regist("less", Comparator_Less);
    regist("randomInt", Random_Integer);
    regist("replace", String_Replace);

    auto _MPCC = std::make_shared<NativeObject>();
    _MPCC->set("version", std::make_shared<String>("2.3-MKAR"));
    _MPCC->set("arch", std::make_shared<String>("Arkscene"));
    _MPCC->set("update_name", std::make_shared<String>("Aivot-MKAR"));
    _MPCC->set("major_version", std::make_shared<Integer>(2));
    _MPCC->set("update_version", std::make_shared<Integer>(3));
    regist("MPCC", _MPCC);
}