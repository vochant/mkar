#define LIB_EXPORTS

#include "plugins/plugin.hpp"
#include "object/integer.hpp"
#include "object/string.hpp"
#include "object/array.hpp"
#include "vm_error.hpp"
#include "darchive.hpp"
#include "vm/vm.hpp"

std::function<bool(unsigned int)> onMissingPassword, onIncorrectPassword;

DArchive* g_arch;

Plugins::MKAR::MKAR() {}

std::shared_ptr<Object> Extract_File(Args args) {
    plain(args);
    if(args.size() != 2 || args[1]->type != Object::Type::String || (args[0]->type != Object::Type::Integer && args[0]->type != Object::Type::String)) {
        throw VMError("(MKAR)Extract_File", "Incorrect Format");
    }
    unsigned int fsid = 0;
    if (args[0]->type == Object::Type::String) {
        fsid = g_arch->DumpFSID(std::dynamic_pointer_cast<String>(args[0])->value);
    }
    else {
        fsid = std::dynamic_pointer_cast<Integer>(args[0])->value;
    }

    if (fsid >= g_arch->FSCount()) {
        throw VMError("(MKAR)Extract_File", "Unavailable Path");
    }

    g_arch->Extract(fsid, std::dynamic_pointer_cast<String>(args[1])->value);

    return gVM->VNull;
}

std::shared_ptr<Object> Is_Directory(Args args) {
    plain(args);
    if (args.size() != 1 || (args[0]->type != Object::Type::String && args[0]->type != Object::Type::Integer)) {
        throw VMError("(MKAR)Is_Directory", "Incorrect Format");
    }
    unsigned int fsid = 0;
    if (args[0]->type == Object::Type::String) {
        fsid = g_arch->DumpFSID(std::dynamic_pointer_cast<String>(args[0])->value);
    }
    else {
        fsid = std::dynamic_pointer_cast<Integer>(args[0])->value;
    }

    if (fsid >= g_arch->FSCount()) {
        throw VMError("(MKAR)Is_Directory", "Unavailable Path");
    }

    return g_arch->isDirectory(fsid) ? gVM->True : gVM->False;
}

std::shared_ptr<Object> Is_Symlink(Args args) {
    plain(args);
    if (args.size() != 1 || (args[0]->type != Object::Type::String && args[0]->type != Object::Type::Integer)) {
        throw VMError("(MKAR)Is_Symlink", "Incorrect Format");
    }
    unsigned int fsid = 0;
    if (args[0]->type == Object::Type::String) {
        fsid = g_arch->DumpFSID(std::dynamic_pointer_cast<String>(args[0])->value);
    }
    else {
        fsid = std::dynamic_pointer_cast<Integer>(args[0])->value;
    }

    if (fsid >= g_arch->FSCount()) {
        throw VMError("(MKAR)Is_Symlink", "Unavailable Path");
    }

    return g_arch->isSymlink(fsid) ? gVM->True : gVM->False;
}

std::shared_ptr<Object> List_Directory(Args args) {
    plain(args);
    if (args.size() != 1 || (args[0]->type != Object::Type::String && args[0]->type != Object::Type::Integer)) {
        throw VMError("(MKAR)List_Directory", "Incorrect Format");
    }
    int fsid = 0;
    if (args[0]->type == Object::Type::String) {
        fsid = g_arch->DumpFSID(std::dynamic_pointer_cast<String>(args[0])->value);
    }
    else {
        fsid = std::dynamic_pointer_cast<Integer>(args[0])->value;
    }

    auto res = std::make_shared<Array>();
    auto in = g_arch->listDirectory(fsid);

    for (auto i : in) {
        res->value.push_back(std::make_shared<Integer>(i));
    }

    return res;
}

std::shared_ptr<Object> Get_Name(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::Integer) {
        throw VMError("(MKAR)Get_Name", "Incorrect Format");
    }

    return std::make_shared<String>(g_arch->getName(std::dynamic_pointer_cast<Integer>(args[0])->value));
}

void Plugins::MKAR::enable() {
    regist("extract", Extract_File);
    regist("is_directory", Is_Directory);
    regist("is_symlink", Is_Symlink);
    regist("list_directory", List_Directory);
    regist("get_name", Get_Name);
}