#include "object/array.hpp"
#include "object/boolean.hpp"
#include "object/byte.hpp"
#include "object/bytearray.hpp"
#include "object/nativeobject.hpp"
#include "object/float.hpp"
#include "object/function.hpp"
#include "object/integer.hpp"
#include "object/nativefunction.hpp"
#include "object/null.hpp"
#include "object/string.hpp"
#include "object/reference.hpp"
#include "object/abit.hpp"
#include "object/file.hpp"
#include "object/mark.hpp"
#include "object/rbit.hpp"

#include "util.hpp"

#include <sstream>

Object::Object(Type type) : type(type) {}
Array::Array() : Object(Type::Array) {}
Boolean::Boolean(bool value) : Object(Type::Boolean), value(value) {}
Byte::Byte(unsigned char value) : Object(Type::Byte), value(value) {}
Executable::Executable(ExecType etype) : Object(Type::Executable), etype(etype) {}
Float::Float(double value) : Object(Type::Float), value(value) {}
Function::Function(std::shared_ptr<Node> inner, std::shared_ptr<Environment> env) : Executable(ExecType::Function), indexer(-1), inner(inner), env(env) {}
Integer::Integer(long long value) : Object(Type::Integer), value(value) {}
NativeFunction::NativeFunction(NFunc func) : Executable(ExecType::NativeFunction), func(func) {}
Null::Null() : Object(Type::Null) {}
String::String(std::string value) : Object(Type::String), value(value), hash(genHash(value)) {}
String::String(std::string value, StringHash hash) : Object(Type::String), value(value), hash(hash) {}
Reference::Reference(std::shared_ptr<Object>* ptr) : Object(Type::Reference), ptr(ptr) {}

std::shared_ptr<Object> Array::make_copy() {
    auto arr = std::make_shared<Array>();
    for (auto i : value) {
        arr->value.push_back(i->make_copy());
    }
    return arr;
}

std::shared_ptr<Object> Boolean::make_copy() {
    return std::make_shared<Boolean>(value);
}

std::shared_ptr<Object> Byte::make_copy() {
    return std::make_shared<Byte>(value);
}

std::shared_ptr<Object> Float::make_copy() {
    return std::make_shared<Float>(value);
}

std::shared_ptr<Object> Function::make_copy() {
    auto res = std::make_shared<Function>(inner, env);
    res->earg = earg;
    for (auto& v : args) {
        res->args.push_back(v);
    }
    for (auto& tc : checks) {
        res->checks.insert(tc);
    }
    return res;
}

std::shared_ptr<Object> Integer::make_copy() {
    return std::make_shared<Integer>(value);
}

std::shared_ptr<Object> NativeFunction::make_copy() {
    return std::make_shared<NativeFunction>(func);
}

std::shared_ptr<Object> String::make_copy() {
    return std::make_shared<String>(value, hash);
}

std::shared_ptr<Object> Reference::make_copy() {
    return (*ptr)->make_copy();
}

std::string Array::toString() {
    std::stringstream ss;
    ss << '[';
    bool isFirst = true;
    for (auto i : value) {
        if (isFirst) {
            isFirst = false;
        }
        else {
            ss << ", ";
        }
        if (i->type != Type::String) ss << i->toString();
        else ss << escape(i->toString());
    }
    ss << ']';
    return ss.str();
}

std::string Boolean::toString() {
    return value ? "true" : "false";
}

std::string Byte::toString() {
    auto toHex = [](unsigned char ch) {
        return (ch < 10) ? (ch + '0') : (ch - 10 + 'A');
    };
    char str[3];
    str[0] = toHex(value >> 4);
    str[1] = toHex(value & 15);
    str[2] = 0;
    return str;
}

std::string Float::toString() {
    return std::to_string(value);
}
std::string Function::toString() {
    return "[func ast]";
}

std::string Integer::toString() {
    return std::to_string(value);
}

std::string NativeFunction::toString() {
    return "[func native]";
}

std::string Null::toString() {
    return "null";
}

std::string String::toString() {
    return value;
}

std::string Reference::toString() {
    return (*ptr)->toString();
}

#include "vm_error.hpp"

#include "vm/vm.hpp"

std::shared_ptr<Array> Iterator::toArray() {
    auto res = std::make_shared<Array>();
    auto copy = std::dynamic_pointer_cast<Iterator>(make_copy());
    while (copy->hasNext()) {
        res->value.push_back(copy->next());
        copy->go();
    }
    return res;
}

std::string Iterator::toString() {
    return "[iterator]";
}

Iterator::Iterator() : Object(Object::Type::Iterator) {}

bool ArrayBasedIterator::hasNext() {
    return ptr != baseArr->value.size();
}

std::shared_ptr<Object> ArrayBasedIterator::next() {
    if (hasNext()) return baseArr->value[ptr];
    return gVM->VNull;
}

void ArrayBasedIterator::go() {
    if (hasNext()) ptr++;
}

ArrayBasedIterator::ArrayBasedIterator(std::shared_ptr<Array> baseArr) : Iterator(), baseArr(baseArr), ptr(0) {}

std::string ByteArray::toString() {
    auto single = [](unsigned char value)->std::string {
        auto toHex = [](unsigned char ch) {
            return (ch < 10) ? (ch + '0') : (ch - 10 + 'A');
        };
        char str[3];
        str[0] = toHex(value >> 4);
        str[1] = toHex(value & 15);
        str[2] = 0;
        return str;
    };
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < value.size(); i++) {
        if (i != 0) ss << ", ";
        ss << single(value[i]);
    }
    ss << "]";
    return ss.str();
}

std::shared_ptr<Object> ByteArray::make_copy() {
    auto cop = std::make_shared<ByteArray>();
    cop->value.insert(cop->value.end(), value.begin(), value.end());
    return cop;
}

ByteArray::ByteArray() : Object(Type::ByteArray) {}

CommonObject::CommonObject(ObjectType otype) : Object(Type::CommonObject), objtype(otype) {}

std::shared_ptr<Object> File::make_copy() {
    return std::make_shared<File>(fs);
}

std::string File::toString() {
    return "[file]";
}

void File::close() {
    fs->close();
    isClosed = true;
}

File::File(std::string name, std::string mode) : Object(Type::File), isClosed(false) {
    std::ios_base::openmode om = (std::ios_base::openmode)0;
    for (size_t i = 0; i < mode.length(); i++) {
        if (mode[i] == 'r') {
            om |= std::ios::in;
        }
        else if (mode[i] == 'w') {
            om |= std::ios::out;
        }
        else if (mode[i] == 'a') {
            om |= std::ios::app;
        }
        else if (mode[i] == 'A') {
            om |= std::ios::ate;
        }
        else if (mode[i] == 'b') {
            om |= std::ios::binary;
        }
        else if (mode[i] == 't') {
            om |= std::ios::trunc;
        }
        else {
            throw VMError("File:construct", "Unknown open mode: " + mode[i]);
        }
    }
    fs = std::make_shared<std::fstream>(name.c_str(), om);
}

File::File(std::shared_ptr<std::fstream> fs) : Object(Type::File), fs(fs), isClosed(false) {}

#include "env/common.hpp"
#include "vm/vm.hpp"

std::shared_ptr<Object> Function::call(std::vector<std::shared_ptr<Object>> cargs) {
    for (auto& i : cargs) {
        if (i->type == Object::Type::Reference) {
            i = i->make_copy();
        }
    }
    for (auto&[k, v] : checks) {
        if (gVM->getTypeString(cargs[k]) != v) {
            throw VMError("Function:call", "Typecheck mismatch: " + v + " expected, but " + gVM->getTypeString(cargs[k]) + " got");
        }
    }
    auto ienv = std::make_shared<CommonEnvironment>(env);
    auto it = cargs.begin();
    for (auto& v : args) {
        if (it == cargs.end()) {
            ienv->set(v, gVM->VNull);
        }
        else {
            ienv->set(v, *it);
            it++;
        }
    }
    if (earg != "__null__") {
        auto vec = std::make_shared<Array>();
        while (it != cargs.end()) {
            vec->value.push_back(*it);
            it++;
        }
        ienv->set(earg, vec);
    }
    if (indexer != -1) {
        ienv->set("__index__", std::make_shared<Integer>(indexer));
    }
    if (inner->type != Node::Type::Scope) {
        throw VMError("Function:call", "Inner node must be a scope");
    }
    auto v = gVM->ExecuteScope(std::dynamic_pointer_cast<ScopeNode>(inner), ienv);
    gVM->state = VirtualMachine::State::COMMON;
    return v;
}

Mark::Mark(std::string value) : Object(Type::Mark), value(value) {}

std::shared_ptr<Object> Mark::make_copy() {
    return std::make_shared<Mark>(value);
}

std::string Mark::toString() {
    return "[enum " + value + "]";
}

std::shared_ptr<Object> NativeFunction::call(std::vector<std::shared_ptr<Object>> args) {
    return func(args);
}

NativeObject::NativeObject() : CommonObject(ObjectType::NATIVE) {}

void NativeObject::set(std::string name, std::shared_ptr<Object> obj) {
    if (entries.count(name)) entries[name] = obj;
    else entries.insert({name, obj});
}

std::shared_ptr<Object> NativeObject::get(std::string name) {
    auto it = entries.find(name);
    if (it == entries.end()) {
        return gVM->VNull;
    }
    return it->second;
}

std::string NativeObject::toString() {
    return "[object native]";
}

std::shared_ptr<Object> NativeObject::make_copy() {
    auto copy = std::make_shared<NativeObject>();
    for (auto&[k, v] : entries) {
        copy->entries.insert({k, v->make_copy()});
    }
    return copy;
}

bool RangeBasedIterator::hasNext() {
    return (s > 0) ? (c < e) : (c > e);
}

std::shared_ptr<Object> RangeBasedIterator::next() {
    return hasNext() ? std::make_shared<Integer>(c) : gVM->VNull;
}

void RangeBasedIterator::go() {
    if (hasNext()) c += s;
}

RangeBasedIterator::RangeBasedIterator(long long b, long long e, long long s) : c(b), e(e), s(s), Iterator() {}

String::String(char ch) : Object(Type::String) {
    char str[2] = {ch, 0};
    value = str;
    hash = genHash(value);
}

std::shared_ptr<Object> ArrayBasedIterator::make_copy() {
    auto res = std::make_shared<ArrayBasedIterator>(baseArr);
    res->ptr = ptr;
    return res;
}

std::shared_ptr<Object> RangeBasedIterator::make_copy() {
    return std::make_shared<RangeBasedIterator>(c, e, s);
}

std::shared_ptr<Object> Null::make_copy() {
    return std::make_shared<Null>();
}

Environment* NF_Environment;