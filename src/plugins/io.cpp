#include "plugins/plugin.hpp"
#include "vm_error.hpp"
#include "iostream"
#include "object/integer.hpp"
#include "object/string.hpp"
#include "object/float.hpp"
#include "object/nativeobject.hpp"
#include "vm/vm.hpp"
#include "util.hpp"

Plugins::IO::IO() {}

std::shared_ptr<Object> Get_Int(Args args) {
    if(args.size()) {
        throw VMError("(IO)Get_Int", "Incorrect Format");
    }
    long long tmp;
    std::cin >> tmp;
    return std::make_shared<Integer>(tmp);
}

std::shared_ptr<Object> Get_String(Args args) {
    if(args.size()) {
        throw VMError("(IO)Get_String", "Incorrect Format");
    }
    std::string tmp;
    std::cin >> tmp;
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> Get_Float(Args args) {
    if(args.size()) {
        throw VMError("(IO)Get_Float", "Incorrect Format");
    }
    double tmp;
    std::cin >> tmp;
    return std::make_shared<Float>(tmp);
}

std::shared_ptr<Object> Get_Line(Args args) {
    if(args.size()) {
        throw VMError("(IO)Get_Line", "Incorrect Format");
    }
    std::string tmp;
    std::getline(std::cin, tmp);
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> Get_Char(Args args) {
    if(args.size()) {
        throw VMError("(IO)Get_Char" , "Incorrect Format");
    }
    char tmp;
    std::cin.get(tmp);
    return std::make_shared<String>(tmp);
}

std::shared_ptr<Object> Print(Args args) {
    if(args.size() == 0)
    {
        throw VMError("(IO)Print" , "Incorrect Format");
    }
    bool isFirst = true;
    for (auto& e : args) {
        if (isFirst) isFirst = false;
        else std::cout << ' ';
        std::cout << e->toString();
    }
    return gVM->VNull;
}

std::shared_ptr<Object> Print_Ln(Args args) {
    auto res = Print(args);
    std::cout << '\n';
    return res;
}

std::shared_ptr<Object> FastIO_Get_Int(Args args) {
    if(args.size()) {
        throw VMError("(IO)FastIO:Get_Int", "Incorrect Format");
    }
    long long tmp , f = 1;
    char ch;
    std::cin.get(ch);
    while(ch < '0' || ch > '9') {
        if(ch == '-')
        {
            f = -1;
        }
        std::cin.get(ch);
    }
    while(ch >= '0' && ch <= '9') {
        tmp = tmp * 10 + ch - '0';
        std::cin.get(ch);
    }
    return std::make_shared<Integer>(f * tmp);
}

std::shared_ptr<Object> FastIO_Get_Float(Args args) {
    if(args.size()) {
        throw VMError("(IO)FastIO:Get_Float", "Incorrect Format");
    }
    double tmp , f = 1 , s = 1;
    char ch;
    std::cin.get(ch);
    while(ch < '0' || ch > '9') {
        if(ch == '-')
        {
            f = -1;
        }
        if(ch == '.')
        {
            goto readt;
        }
        std::cin.get(ch);
    }
    while(ch >= '0' && ch <= '9' && ch != '.') {
        tmp = tmp * 10 + ch - '0';
        std::cin.get(ch);
    }
    readt:while(ch == '.') {std::cin.get(ch);}
    while(ch >= '0' && ch <= '9') {
        tmp = tmp * 10 + ch - 0;
        s *= 10;
        std::cin.get(ch);
    }
    return std::make_shared<Float>(f * (tmp / s));
}

void Write_Int_only(long long x)
{
    if(x < 0) {
        std::cout.put('-');
        x = -x;
    }
    if(x > 9) {
        Write_Int_only(x / 10);
    }
    std::cout.put(x % 10 + '0');
} 

std::shared_ptr<Object> FastIO_Print_Int(Args args) {
    plain(args);
    if(args.size() == 0)
    {
        throw VMError("(IO)FastIO:Print_Int" , "Incorrect Format");
    }
    for (auto& e : args) {
        if (e->type != Object::Type::Integer) {
            throw VMError("(IO)FastIO:Print_Int" , "Incorrect Format");
        }
    }
    bool isFirst = true;
    for (auto& e : args) {
        if (isFirst) isFirst = false;
        else std::cout << ' ';
        Write_Int_only(std::dynamic_pointer_cast<Integer>(e)->value);
    }
    return gVM->VNull;
}

void Write_Float_only(double x , long long k)
{
    long long n = _FastPow(10 , k);
    if (x == 0)
    {
        std::cout.put('0');
        std::cout.put('.');
        for (int i = 1 ; i <= k ; i++)
        {
            std::cout.put('0');
        }
        return;
    }
    if (x < 0)
    {
        std::cout.put('-');
        x = -x;
    }
    long long y = (long long)(x * n) % n;
    x = (long long)x;
    Write_Int_only(x);
    std::cout.put('.');
    int bit[20],p=0,i;
    for (; p < k ; y /= 10) {
        bit[++p] = y % 10;
    }
    for (i = p ; i > 0 ; i--) {
        std::cout.put(bit[i] + 48);
    }
}

std::shared_ptr<Object> FastIO_Print_Double(Args args) {
    plain(args);
    if(args.size() == 1)
    {
        args.push_back(std::make_shared<Integer>(6));
    }
    if(args.size() != 2)
    {
        throw VMError("(IO)FastIO:Print_Double" , "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) {
        args[0] = std::make_shared<Float>(std::dynamic_pointer_cast<Integer>(args[0])->value);
    }
    if (args[0]->type != Object::Type::Float || args[1]->type != Object::Type::Integer) {
        throw VMError("(IO)FastIO:Print_Double" , "Incorrect Format");
    }
    Write_Float_only(std::dynamic_pointer_cast<Float>(args[0])->value, std::dynamic_pointer_cast<Integer>(args[1])->value);
    return gVM->VNull;
}

void Plugins::IO::enable() {
    regist("getInt" , Get_Int);
    regist("input" , Get_String);
    regist("getFloat" , Get_Float);
    regist("getLine" , Get_Line);
    regist("getChar" , Get_Char);
    regist("print" , Print);
    regist("println" , Print_Ln);
    auto FastIO = std::make_shared<NativeObject>();
    FastIO->set("getInt", std::make_shared<NativeFunction>(FastIO_Get_Int));
    FastIO->set("getFloat" , std::make_shared<NativeFunction>(FastIO_Get_Float));
    FastIO->set("printInt" , std::make_shared<NativeFunction>(FastIO_Print_Int));
    FastIO->set("printFloat", std::make_shared<NativeFunction>(FastIO_Print_Double));
    regist("FastIO", FastIO);
}