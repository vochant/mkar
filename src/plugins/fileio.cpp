#include "plugins/plugin.hpp"
#include "vm_error.hpp"
#include "iostream"
#include "object/integer.hpp"
#include "object/string.hpp"
#include "object/float.hpp"
#include "object/nativeobject.hpp"
#include "vm/vm.hpp"
#include "util.hpp"
#include "object/file.hpp"
#include "object/reference.hpp"

Plugins::FileIO::FileIO() {}

std::shared_ptr<Object> File_Get_Int(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Get_Int", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Get_Int" , "File Closed");   
    }
    long long tmp;
    *(std::dynamic_pointer_cast<File>(args[0])->fs) >> tmp;
    return std::make_shared<Integer>(tmp);
}

std::shared_ptr<Object> File_Get_String(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Get_String", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Get_String" , "File Closed");   
    }
    std::string tmp;
    *(std::dynamic_pointer_cast<File>(args[0])->fs) >> tmp;
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> File_Get_Float(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Get_Float", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Get_Float" , "File Closed");   
    }
    double tmp;
    *(std::dynamic_pointer_cast<File>(args[0])->fs) >> tmp;
    return std::make_shared<Float>(tmp);
}

std::shared_ptr<Object> File_Get_Line(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Get_Line", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Get_Line" , "File Closed");   
    }
    std::string tmp;
    std::getline(*(std::dynamic_pointer_cast<File>(args[0])->fs), tmp);
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> File_Get_Char(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Get_Char" , "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Get_Char" , "File Closed");   
    }
    char tmp;
    std::dynamic_pointer_cast<File>(args[0])->fs->get(tmp);
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> File_Print(Args args) {
    plain(args);
    if(args.size() <= 1 || args[0]->type != Object::Type::File)
    {
        throw VMError("(FileIO)File_Print" , "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)File_Print" , "File Closed");   
    }
    bool isFirst = true;
    for (size_t i = 1; i < args.size(); i++) {
        if (isFirst) isFirst = false;
        else *(std::dynamic_pointer_cast<File>(args[0])->fs) << ' ';
        *(std::dynamic_pointer_cast<File>(args[0])->fs) << args[i]->toString();
    }
    return gVM->VNull;
}

std::shared_ptr<Object> File_Print_Ln(Args args) {
    plain(args);
    auto res = File_Print(args);
    *(std::dynamic_pointer_cast<File>(args[0])->fs) << '\n';
    return res;
}

std::shared_ptr<Object> FFastIO_Get_Int(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)FFastIO:Get_Int", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)FFastIO:Get_Int" , "File Closed");   
    }
    long long tmp , f = 1;
    char ch;
    auto& fs = *(std::dynamic_pointer_cast<File>(args[0])->fs);
    fs.get(ch);
    while(ch < '0' || ch > '9') {
        if(ch == '-')
        {
            f = -1;
        }
        fs.get(ch);
    }
    while(ch >= '0' && ch <= '9') {
        tmp = tmp * 10 + ch - '0';
        fs.get(ch);
    }
    return std::make_shared<Integer>(f * tmp);
}

std::shared_ptr<Object> FFastIO_Get_Float(Args args) {
    plain(args);
    if(args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)FFastIO:Get_Float", "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)FFastIO:Get_Float" , "File Closed");   
    }
    auto& fs = *(std::dynamic_pointer_cast<File>(args[0])->fs);
    double tmp , f = 1 , s = 1;
    char ch;
    fs.get(ch);
    while(ch < '0' || ch > '9') {
        if(ch == '-')
        {
            f = -1;
        }
        if(ch == '.')
        {
            goto readt;
        }
        fs.get(ch);
    }
    while(ch >= '0' && ch <= '9' && ch != '.') {
        tmp = tmp * 10 + ch - '0';
        fs.get(ch);
    }
    readt:while(ch == '.') {fs.get(ch);}
    while(ch >= '0' && ch <= '9') {
        tmp = tmp * 10 + ch - 0;
        s *= 10;
        fs.get(ch);
    }
    return std::make_shared<Float>(f * (tmp / s));
}

void FWrite_Int_only(std::fstream& fs, long long x)
{
    if(x < 0) {
        fs.put('-');
        x = -x;
    }
    if(x > 9) {
        FWrite_Int_only(fs, x / 10);
    }
    fs.put(x % 10 + '0');
} 

std::shared_ptr<Object> FFastIO_Print_Int(Args args) {
    plain(args);
    if(args.size() <= 1 || args[0]->type != Object::Type::File)
    {
        throw VMError("(FileIO)FFastIO:Print_Int" , "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)FFastIO:Print_Int" , "File Closed");   
    }
    auto& fs = *(std::dynamic_pointer_cast<File>(args[0])->fs);
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i]->type != Object::Type::Integer) {
            throw VMError("(FileIO)FFastIO:Print_Int" , "Incorrect Format");
        }
    }
    bool isFirst = true;
    for (size_t i = 1; i < args.size(); i++) {
        if (isFirst) isFirst = false;
        else std::cout << ' ';
        FWrite_Int_only(fs, std::dynamic_pointer_cast<Integer>(args[i])->value);
    }
    return gVM->VNull;
}

void FWrite_Float_only(std::fstream& fs, double x , long long k)
{
    long long n = _FastPow(10 , k);
    if (x == 0)
    {
        fs.put('0');
        fs.put('.');
        for (int i = 1 ; i <= k ; i++)
        {
            fs.put('0');
        }
        return;
    }
    if (x < 0)
    {
        fs.put('-');
        x = -x;
    }
    long long y = (long long)(x * n) % n;
    x = (long long)x;
    FWrite_Int_only(fs, x);
    fs.put('.');
    int bit[20],p=0,i;
    for (; p < k ; y /= 10) {
        bit[++p] = y % 10;
    }
    for (i = p ; i > 0 ; i--) {
        fs.put(bit[i] + 48);
    }
}

std::shared_ptr<Object> FFastIO_Print_Double(Args args) {
    plain(args);
    if(args.size() == 2)
    {
        args.push_back(std::make_shared<Integer>(6));
    }
    if(args.size() != 3 || args[0]->type != Object::Type::File)
    {
        throw VMError("(FileIO)FFastIO:Print_Double" , "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        throw VMError("(FileIO)FFastIO:Print_Double" , "File Closed");   
    }
    if (args[1]->type == Object::Type::Integer) {
        args[1] = std::make_shared<Float>(std::dynamic_pointer_cast<Integer>(args[1])->value);
    }
    if (args[1]->type != Object::Type::Float || args[2]->type != Object::Type::Integer) {
        throw VMError("(FileIO)FFastIO:Print_Double" , "Incorrect Format");
    }
    auto& fs = *(std::dynamic_pointer_cast<File>(args[0])->fs);
    FWrite_Float_only(fs, std::dynamic_pointer_cast<Float>(args[1])->value, std::dynamic_pointer_cast<Integer>(args[2])->value);
    return gVM->VNull;
}

std::shared_ptr<Object> File_Open(Args args) {
    plain(args);
    if (args.size() != 2 || args[0]->type != Object::Type::String || args[1]->type != Object::Type::String) {
        throw VMError("(FileIO)File_Open" , "Incorrect Format");
    }
    return std::make_shared<File>(std::dynamic_pointer_cast<String>(args[0])->value, std::dynamic_pointer_cast<String>(args[1])->value);
}

std::shared_ptr<Object> File_Close(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_Close" , "Incorrect Format");
    }
    if (!std::dynamic_pointer_cast<File>(args[0])->isClosed) {
        std::dynamic_pointer_cast<File>(args[0])->close();
    }
    return gVM->VNull;
}

std::shared_ptr<Object> File_IsOK(Args args) {
    plain(args);
    if (args.size() != 1 || args[0]->type != Object::Type::File) {
        throw VMError("(FileIO)File_IsOK" , "Incorrect Format");
    }
    if (std::dynamic_pointer_cast<File>(args[0])->isClosed) return gVM->False;
    if (std::dynamic_pointer_cast<File>(args[0])->fs->good()) return gVM->True;
    return gVM->False;
}

void Plugins::FileIO::enable() {
    regist("fgetInt" , File_Get_Int);
    regist("finput" , File_Get_String);
    regist("fgetFloat" , File_Get_Float);
    regist("fgetLine" , File_Get_Line);
    regist("fgetChar" , File_Get_Char);
    regist("fprint" , File_Print);
    regist("fprintln" , File_Print_Ln);
    regist("fopen", File_Open);
    regist("fclose", File_Close);
    regist("fisok", File_IsOK);
    auto FFastIO = std::make_shared<NativeObject>();
    FFastIO->set("getInt", std::make_shared<NativeFunction>(FFastIO_Get_Int));
    FFastIO->set("getFloat" , std::make_shared<NativeFunction>(FFastIO_Get_Float));
    FFastIO->set("printInt" , std::make_shared<NativeFunction>(FFastIO_Print_Int));
    FFastIO->set("printFloat", std::make_shared<NativeFunction>(FFastIO_Print_Double));
    regist("FFastIO", FFastIO);
}