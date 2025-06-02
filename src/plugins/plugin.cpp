#include "plugins/plugin.hpp"

void Plugin::attach(std::shared_ptr<Environment> env) {
    _env = env;
    enable();
}

void Plugin::regist(std::string name, std::shared_ptr<Object> value) {
    _env->set(name, value);
}

void Plugin::regist(std::string name, NFunc func) {
    _env->set(name, std::make_shared<NativeFunction>(func));
}

void plain(Args& args) {
    for (auto& e : args) {
        if (e->type == Object::Type::Reference) {
            e = e->make_copy();
        }
    }
}

Plugin::Plugin() {}