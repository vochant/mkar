#include "env/common.hpp"
#include "object/null.hpp"
#include "object/reference.hpp"
#include "vm_error.hpp"

std::shared_ptr<Object> CommonEnvironment::get(std::string name) {
    if (entries.count(name)) {
        if (entries.at(name).isConst) {
            return entries.at(name).value;
        }
        else {
            return std::make_shared<Reference>(&entries.at(name).value);
        }
    }
    if (parent) {
        return parent->get(name);
    }
    return std::make_shared<Null>();
}

std::shared_ptr<Object> CommonEnvironment::getUnder(std::string name, long long ident) {
    if (entries.count(name)) {
        if (entries.at(name).isConst) {
            return entries.at(name).value;
        }
        else {
            return std::make_shared<Reference>(&entries.at(name).value);
        }
    }
    return std::make_shared<Null>();  
}

void CommonEnvironment::set(std::string name, std::shared_ptr<Object> obj) {
    if (entries.count(name)) {
        entries[name] = {false, obj};
    }
    else {
        entries.insert({name, {false, obj}});
    }
}

void CommonEnvironment::makeConst(std::string name) {
    entries[name].isConst = true;
}

bool CommonEnvironment::has(std::string name) {
    return entries.count(name);
}

void CommonEnvironment::remove(std::string name) {
    auto it = entries.find(name);
    if (it != entries.end()) entries.erase(it);
    else if (parent) parent->remove(name);
    else throw VMError("CommonEnv:remove", "Entry " + name + " not found");
}

CommonEnvironment::CommonEnvironment(std::shared_ptr<Environment> parent) : parent(parent) {}

#include "object/integer.hpp"