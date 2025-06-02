#pragma once

#include "env/environment.hpp"
#include "object/nativefunction.hpp"

void plain(Args& args);

class Plugin {
private:
    std::shared_ptr<Environment> _env;
public:
    void attach(std::shared_ptr<Environment> env);
protected:
    void regist(std::string name, std::shared_ptr<Object> value);
    void regist(std::string name, NFunc func);
    virtual void enable() = 0;
public:
    Plugin();
};

namespace Plugins {
    class IO : public Plugin {
    protected:
        void enable() override;
    public:
        IO();
    };

    class FileIO : public Plugin {
    protected:
        void enable() override;
    public:
        FileIO();
    };

    class Math : public Plugin {
    protected:
        void enable() override;
    public:
        Math();
    };

    class Base : public Plugin {
    protected:
        void enable() override;
    public:
        Base();
    };

    class MKAR : public Plugin {
    protected:
        void enable() override;
    public:
        MKAR();
    };
}