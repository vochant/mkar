#define _USE_MATH_DEFINES

#include "plugins/plugin.hpp"
#include "vm_error.hpp"
#include "object/integer.hpp"
#include "object/float.hpp"
#include "object/nativeobject.hpp"
#include "object/boolean.hpp"
#include "vm/vm.hpp"
#include <cmath>

#ifndef M_SQRT2
# define M_SQRT2 sqrt(2)
#endif

#ifndef M_SQRT1_2
# define M_SQRT1_2 (0.5 * M_SQRT2)
#endif

Plugins::Math::Math() {}

bool Detect(Args& args, size_t count) {
    plain(args);
    if (~count && args.size() != count) return true;
    for (auto& e : args) {
        if (e->type != Object::Type::Integer && e->type != Object::Type::Float) {
            return true;
        }
    }
    return false;
}

template<typename _Tp>
_Tp Math_FastPow_Core(_Tp base, long long sup) {
    _Tp res = 1;
    while (sup) {
        if (sup & 1) res *= base;
        base *= base;
        sup >>= 1;
    }
    return res;
}

std::shared_ptr<Object> Math_Pow(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Pow", "Incorrect Format");
    }
    if (args[1]->type == Object::Type::Integer) {
        auto sup = std::dynamic_pointer_cast<Integer>(args[1])->value;
        if (sup <= 0) {
            if (args[0]->type == Object::Type::Float && std::dynamic_pointer_cast<Float>(args[0])->value == 0) {
                return std::make_shared<Float>(NAN);
            }
            if (args[0]->type == Object::Type::Integer && std::dynamic_pointer_cast<Integer>(args[0])->value == 0) {
                return std::make_shared<Float>(NAN);
            }
            if (sup == 0) {
                if (args[0]->type == Object::Type::Float) return std::make_shared<Float>(1) ;
                else return std::make_shared<Integer>(1);
            }
            if (args[0]->type == Object::Type::Float) {
                return std::make_shared<Float>(1 / Math_FastPow_Core(std::dynamic_pointer_cast<Float>(args[0])->value, -sup));
            }
            else {
                return std::make_shared<Float>(1 / Math_FastPow_Core(std::dynamic_pointer_cast<Float>(args[0])->value * 1.0, -sup));
            }
        }
        if (args[0]->type == Object::Type::Float) {
            return std::make_shared<Float>(Math_FastPow_Core(std::dynamic_pointer_cast<Float>(args[0])->value, sup));
        }
        else {
            return std::make_shared<Integer>(Math_FastPow_Core(std::dynamic_pointer_cast<Integer>(args[0])->value, sup));
        }
    }
    else if (args[0]->type == Object::Type::Float) {
        return std::make_shared<Float>(pow(std::dynamic_pointer_cast<Float>(args[0])->value, std::dynamic_pointer_cast<Float>(args[1])->value));
    }
    else {
        return std::make_shared<Float>(pow(std::dynamic_pointer_cast<Integer>(args[0])->value, std::dynamic_pointer_cast<Float>(args[1])->value));
    }
}

std::shared_ptr<Object> Math_Sin(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Sin", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(sin(value));
}

std::shared_ptr<Object> Math_Cos(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Cos", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(cos(value));
}

std::shared_ptr<Object> Math_Tan(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Tan", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(tan(value));
}

std::shared_ptr<Object> Math_Sec(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Sec", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(1/cos(value));
}

std::shared_ptr<Object> Math_Csc(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Csc", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(1/sin(value));
}

std::shared_ptr<Object> Math_Cot(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Cot", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(1/tan(value));
}

std::shared_ptr<Object> Math_Log(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Log", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(log(value));
}

std::shared_ptr<Object> Math_Log10(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Log10", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(log10(value));
}

std::shared_ptr<Object> Math_Log2(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Log2", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(log2(value));
}

std::shared_ptr<Object> Math_Floor(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Floor", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) return args[0];
    return std::make_shared<Integer>(floor(std::dynamic_pointer_cast<Float>(args[0])->value));
}

std::shared_ptr<Object> Math_Ceil(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Ceil", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) return args[0];
    return std::make_shared<Integer>(ceil(std::dynamic_pointer_cast<Float>(args[0])->value));
}

std::shared_ptr<Object> Math_Round(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Round", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) return args[0];
    return std::make_shared<Integer>(round(0.5 + std::dynamic_pointer_cast<Float>(args[0])->value));
}

std::shared_ptr<Object> Math_Exp(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Exp", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(exp(value));
}

std::shared_ptr<Object> Math_Exp2(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Exp2", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(exp2(value));
}

std::shared_ptr<Object> Math_Sqrt(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Sqrt", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(sqrt(value));
}

std::shared_ptr<Object> Math_Cbrt(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Cbrt", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(cbrt(value));
}

std::shared_ptr<Object> Math_Arcsin(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arcsin", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(asin(value));
}

std::shared_ptr<Object> Math_Arccos(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arccos", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(acos(value));
}

std::shared_ptr<Object> Math_Arctan(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arctan", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(atan(value));
}

std::shared_ptr<Object> Math_Arcsec(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arcsec", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(acos(1/value));
}

std::shared_ptr<Object> Math_Arccsc(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arccsc", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(asin(1/value));
}

std::shared_ptr<Object> Math_Arccot(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Arccot", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(atan(1/value));
}

std::shared_ptr<Object> Math_Arctan2(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Arctan2", "Incorrect Format");
    }
    double va, vb;
    if (args[0]->type == Object::Type::Float) va = std::dynamic_pointer_cast<Float>(args[0])->value;
    else va = std::dynamic_pointer_cast<Integer>(args[0])->value;
    if (args[0]->type == Object::Type::Float) vb = std::dynamic_pointer_cast<Float>(args[0])->value;
    else vb = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(atan2(va, vb));
}

std::shared_ptr<Object> Math_Sinh(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Sinh", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(sinh(value));
}

std::shared_ptr<Object> Math_Cosh(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Cosh", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(cosh(value));
}

std::shared_ptr<Object> Math_Tanh(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Tanh", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(tanh(value));
}

std::shared_ptr<Object> Math_Scale(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Scale", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    if (args[1]->type != Object::Type::Integer) {
        throw VMError("(Math)Math:Scale", "Incorrect Format");
    }
    long long scal = std::dynamic_pointer_cast<Integer>(args[1])->value;
    return std::make_shared<Float>(scalbln(value, scal));
}

std::shared_ptr<Object> Math_Hypot(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Hypot", "Incorrect Format");
    }
    double va, vb;
    if (args[0]->type == Object::Type::Float) va = std::dynamic_pointer_cast<Float>(args[0])->value;
    else va = std::dynamic_pointer_cast<Integer>(args[0])->value;
    if (args[0]->type == Object::Type::Float) vb = std::dynamic_pointer_cast<Float>(args[0])->value;
    else vb = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(hypot(va, vb));
}

std::shared_ptr<Object> Math_Erf(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Erf", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(erf(value));
}

std::shared_ptr<Object> Math_Erfc(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Erfc", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(erfc(value));
}

std::shared_ptr<Object> Math_Tgamma(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Tgamma", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(tgamma(value));
}

std::shared_ptr<Object> Math_Lgamma(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Lgamma", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(lgamma(value));
}

std::shared_ptr<Object> Math_Trunc(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Trunc", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Integer) return args[0];
    return std::make_shared<Integer>(trunc(std::dynamic_pointer_cast<Float>(args[0])->value));
}

std::shared_ptr<Object> Math_Remainder(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Remainder", "Incorrect Format");
    }
    double va, vb;
    if (args[0]->type == Object::Type::Float) va = std::dynamic_pointer_cast<Float>(args[0])->value;
    else va = std::dynamic_pointer_cast<Integer>(args[0])->value;
    if (args[0]->type == Object::Type::Float) vb = std::dynamic_pointer_cast<Float>(args[0])->value;
    else vb = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(remainder(va, vb));
}

std::shared_ptr<Object> Math_Normal(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Normal", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Integer>(value > 0 ? 1 : (0 - (value < 0)));
}

std::shared_ptr<Object> Math_Sign(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Sign", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Boolean>(std::signbit(value));
}

std::shared_ptr<Object> Math_FPClassify(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:FPClassify", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Integer>(std::fpclassify(value));
}

std::shared_ptr<Object> Math_IsFinite(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:IsFinite", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Boolean>(std::isfinite(value));
}

std::shared_ptr<Object> Math_IsInf(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:IsInf", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Boolean>(std::isinf(value));
}

std::shared_ptr<Object> Math_IsNaN(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:IsNaN", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Boolean>(std::isnan(value));
}

std::shared_ptr<Object> Math_IsNormal(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:IsNormal", "Incorrect Format");
    }
    double value;
    if (args[0]->type == Object::Type::Float) value = std::dynamic_pointer_cast<Float>(args[0])->value;
    else value = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Boolean>(std::isnormal(value));
}

std::shared_ptr<Object> Math_Abs(Args args) {
    if (Detect(args, 1)) {
        throw VMError("(Math)Math:Abs", "Incorrect Format");
    }
    if (args[0]->type == Object::Type::Float) {
        return std::make_shared<Float>(fabs(std::dynamic_pointer_cast<Float>(args[0])->value));
    }
    else {
        return std::make_shared<Integer>(abs(std::dynamic_pointer_cast<Integer>(args[0])->value));
    }
}

std::shared_ptr<Object> Math_Dim(Args args) {
    if (Detect(args, 2)) {
        throw VMError("(Math)Math:Dim", "Incorrect Format");
    }
    double va, vb;
    if (args[0]->type == Object::Type::Float) va = std::dynamic_pointer_cast<Float>(args[0])->value;
    else va = std::dynamic_pointer_cast<Integer>(args[0])->value;
    if (args[0]->type == Object::Type::Float) vb = std::dynamic_pointer_cast<Float>(args[0])->value;
    else vb = std::dynamic_pointer_cast<Integer>(args[0])->value;
    return std::make_shared<Float>(fdim(va, vb));
}

std::shared_ptr<Object> Math_Max(Args args) {
    if (Detect(args, -1)) {
        throw VMError("(Math)Math:Max", "Incorrect Format");
    }
    if (args.size() == 0) return gVM->VNull;
    double value = std::dynamic_pointer_cast<Float>(args[0])->value;
    for (size_t i = 1; i < args.size(); i++) {
        if (std::dynamic_pointer_cast<Float>(args[i])->value > value) {
            value = std::dynamic_pointer_cast<Float>(args[i])->value;
        }
    }
    return std::make_shared<Float>(value);
}

#include <random>

std::mt19937_64 _math_gRND(std::random_device{}());

std::shared_ptr<Object> Math_Random(Args args) {
    return std::make_shared<Float>(_math_gRND() / pow(2.0, 64));
}

std::shared_ptr<Object> Math_Min(Args args) {
    if (Detect(args, -1)) {
        throw VMError("(Math)Math:Min", "Incorrect Format");
    }
    if (args.size() == 0) return gVM->VNull;
    double value = std::dynamic_pointer_cast<Float>(args[0])->value;
    for (size_t i = 1; i < args.size(); i++) {
        if (std::dynamic_pointer_cast<Float>(args[i])->value < value) {
            value = std::dynamic_pointer_cast<Float>(args[i])->value;
        }
    }
    return std::make_shared<Float>(value);
}

void Plugins::Math::enable() {
    regist("NaN", std::make_shared<Float>(NAN));
    regist("Infinity", std::make_shared<Float>(INFINITY));
    auto _Math = std::make_shared<NativeObject>();
    _Math->set("FP_INFINITE", std::make_shared<Integer>(FP_INFINITE));
    _Math->set("FP_NAN", std::make_shared<Integer>(FP_NAN));
    _Math->set("FP_ZERO", std::make_shared<Integer>(FP_ZERO));
    _Math->set("FP_SUBNORMAL", std::make_shared<Integer>(FP_SUBNORMAL));
    _Math->set("FP_NORMAL", std::make_shared<Integer>(FP_NORMAL));
    _Math->set("PI", std::make_shared<Float>(M_PI));
    _Math->set("E", std::make_shared<Float>(M_E));
    _Math->set("LN10", std::make_shared<Float>(M_LN10));
    _Math->set("LN2", std::make_shared<Float>(M_LN2));
    _Math->set("LOG10E", std::make_shared<Float>(M_LOG10E));
    _Math->set("LOG2E", std::make_shared<Float>(M_LOG2E));
    _Math->set("SQRT2", std::make_shared<Float>(M_SQRT2));
    _Math->set("SQRT1_2", std::make_shared<Float>(M_SQRT1_2));
    _Math->set("pow", std::make_shared<NativeFunction>(Math_Pow));
    _Math->set("sin", std::make_shared<NativeFunction>(Math_Sin));
    _Math->set("cos", std::make_shared<NativeFunction>(Math_Cos));
    _Math->set("tan", std::make_shared<NativeFunction>(Math_Tan));
    _Math->set("sec", std::make_shared<NativeFunction>(Math_Sec));
    _Math->set("csc", std::make_shared<NativeFunction>(Math_Csc));
    _Math->set("cot", std::make_shared<NativeFunction>(Math_Cot));
    _Math->set("log", std::make_shared<NativeFunction>(Math_Log));
    _Math->set("ln", std::make_shared<NativeFunction>(Math_Log));
    _Math->set("log10", std::make_shared<NativeFunction>(Math_Log10));
    _Math->set("lg", std::make_shared<NativeFunction>(Math_Log10));
    _Math->set("log2", std::make_shared<NativeFunction>(Math_Log2));
    _Math->set("floor", std::make_shared<NativeFunction>(Math_Floor));
    _Math->set("ceil", std::make_shared<NativeFunction>(Math_Ceil));
    _Math->set("round", std::make_shared<NativeFunction>(Math_Round));
    _Math->set("asin", std::make_shared<NativeFunction>(Math_Arcsin));
    _Math->set("acos", std::make_shared<NativeFunction>(Math_Arccos));
    _Math->set("atan", std::make_shared<NativeFunction>(Math_Arctan));
    _Math->set("asec", std::make_shared<NativeFunction>(Math_Arcsec));
    _Math->set("acsc", std::make_shared<NativeFunction>(Math_Arccsc));
    _Math->set("acot", std::make_shared<NativeFunction>(Math_Arccot));
    _Math->set("atan2", std::make_shared<NativeFunction>(Math_Arctan2));
    _Math->set("sqrt", std::make_shared<NativeFunction>(Math_Sqrt));
    _Math->set("cbrt", std::make_shared<NativeFunction>(Math_Cbrt));
    _Math->set("exp", std::make_shared<NativeFunction>(Math_Exp));
    _Math->set("exp2", std::make_shared<NativeFunction>(Math_Exp2));
    _Math->set("sinh", std::make_shared<NativeFunction>(Math_Sinh));
    _Math->set("cosh", std::make_shared<NativeFunction>(Math_Cosh));
    _Math->set("tanh", std::make_shared<NativeFunction>(Math_Tanh));
    _Math->set("scale", std::make_shared<NativeFunction>(Math_Scale));
    _Math->set("hypot", std::make_shared<NativeFunction>(Math_Hypot));
    _Math->set("erf", std::make_shared<NativeFunction>(Math_Erf));
    _Math->set("erfc", std::make_shared<NativeFunction>(Math_Erfc));
    _Math->set("tgamma", std::make_shared<NativeFunction>(Math_Tgamma));
    _Math->set("lgamma", std::make_shared<NativeFunction>(Math_Lgamma));
    _Math->set("trunc", std::make_shared<NativeFunction>(Math_Trunc));
    _Math->set("remainder", std::make_shared<NativeFunction>(Math_Remainder));
    _Math->set("normal", std::make_shared<NativeFunction>(Math_Normal));
    _Math->set("sign", std::make_shared<NativeFunction>(Math_Sign));
    _Math->set("fpclassify", std::make_shared<NativeFunction>(Math_FPClassify));
    _Math->set("isfinite", std::make_shared<NativeFunction>(Math_IsFinite));
    _Math->set("isinf", std::make_shared<NativeFunction>(Math_IsInf));
    _Math->set("isnan", std::make_shared<NativeFunction>(Math_IsNaN));
    _Math->set("isnormal", std::make_shared<NativeFunction>(Math_IsNormal));
    _Math->set("abs", std::make_shared<NativeFunction>(Math_Abs));
    _Math->set("dim", std::make_shared<NativeFunction>(Math_Dim));
    _Math->set("max", std::make_shared<NativeFunction>(Math_Max));
    _Math->set("min", std::make_shared<NativeFunction>(Math_Min));
    _Math->set("random", std::make_shared<NativeFunction>(Math_Random));
    regist("Math", _Math);
}