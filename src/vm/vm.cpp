#include "vm/vm.hpp"
#include "vm/gct.hpp"

#include "vm_error.hpp"

#include "object/array.hpp"
#include "object/boolean.hpp"
#include "object/byte.hpp"
#include "object/bytearray.hpp"
#include "object/function.hpp"
#include "object/float.hpp"
#include "object/integer.hpp"
#include "object/nativefunction.hpp"
#include "object/null.hpp"
#include "object/reference.hpp"
#include "object/string.hpp"
#include "object/file.hpp"
#include "object/mark.hpp"
#include "object/abit.hpp"

// temp
#include "object/commonobject.hpp"

#include "env/common.hpp"

#include <sstream>

int VirtualMachine::Execute(std::shared_ptr<ProgramNode> program, std::shared_ptr<Environment> env) {
    if (program->mainScope->type != Node::Type::Scope) {
        throw VMError("VM:Execute", "The main scope of the program must be a scope");
    }
    auto v = ExecuteScope(std::dynamic_pointer_cast<ScopeNode>(program->mainScope), env, true);
    if (v->type == Object::Type::Reference) {
        v = v->make_copy();
    }
    if (v->type == Object::Type::Integer) {
        return std::dynamic_pointer_cast<Integer>(v)->value;
    }
    return 0;
}

std::shared_ptr<Object> VirtualMachine::ExecuteArray(std::shared_ptr<ArrayNode> arr, std::shared_ptr<Environment> env) {
    auto res = std::make_shared<Array>();
    for (auto& i : arr->elements) {
        auto v = ExecuteCommon(i, env);
        if (v->type == Object::Type::Reference) {
            v = v->make_copy();
        }
        res->value.push_back(v);
    }
    return res;
}

std::shared_ptr<Object> VirtualMachine::ExecuteAssign(std::shared_ptr<AssignNode> assign, std::shared_ptr<Environment> env) {
    auto l = ExecuteValue(assign->left, env), r = ExecuteCommon(assign->right, env);
    if (assign->_op != "=") {
        r = CalculateInfix(assign->_op.substr(0, assign->_op.length() - 1), l->make_copy(), r, env);
    }
    if (l->type != Object::Type::Reference) {
        throw VMError("VM:ExecuteAssign", "Assign to constant");
    }
    *(std::dynamic_pointer_cast<Reference>(l)->ptr) = r;
    return r;
}

std::shared_ptr<Object> VirtualMachine::ExecuteBoolean(std::shared_ptr<BooleanNode> b, std::shared_ptr<Environment> env) {
    return b->value ? True : False;
}

std::shared_ptr<Object> VirtualMachine::ExecuteBreakContinue(std::shared_ptr<BreakContinueNode> bc, std::shared_ptr<Environment> env) {
    if (bc->isContinue) state = State::CONTINUE;
    else state = State::BREAK;
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteCall(std::shared_ptr<CallNode> call, std::shared_ptr<Environment> env) {
    std::vector<std::shared_ptr<Object>> args;
    size_t ix = 0;
    for (size_t i = 0; i < call->args.size(); i++) {
        auto obj = ExecuteValue(call->args[i], env);
        if (ix < call->expands.size() && call->expands[ix] == i) {
            if (obj->type == Object::Type::Reference) {
                obj = obj->make_copy();
            }
            if (obj->type == Object::Type::Array) {
                auto cast = std::dynamic_pointer_cast<Array>(obj);
                for (auto& j : cast->value) {
                    args.push_back(j);
                }
            }
            else if (obj->type == Object::Type::Iterator) {
                auto cast = std::dynamic_pointer_cast<Array>(std::dynamic_pointer_cast<Iterator>(obj)->toArray());
                for (auto& j : cast->value) {
                    args.push_back(j);
                }
            }
            else {
                throw VMError("VM:ExecuteCall", "Expanding argument must be array or iterator");
            }
            ix++;
            continue;
        }
        args.push_back(obj);
    }
    auto callable = ExecuteCommon(call->to_run, env);
    if (callable->type != Object::Type::Executable) {
        throw VMError("VM:ExecuteCall", "Not Executable");
    }
    return std::dynamic_pointer_cast<Executable>(callable)->call(args);
}

std::shared_ptr<Object> VirtualMachine::ExecuteCFor(std::shared_ptr<CForNode> r, std::shared_ptr<Environment> env) {
    auto inner = std::make_shared<CommonEnvironment>(env);
    auto res = ExecuteStatement(r->_init, inner);
    if (state == State::RETURN) {
        return res;
    }
    if (state == State::BREAK) {
        state = State::COMMON;
        return VNull;
    }
    while (true) {
        if (r->_cond->type != Node::Type::Expr) {
            throw VMError("VM:ExecuteCFor", "Condition must be an expression");
        }
        auto v = isTrue(ExecuteExpr(std::dynamic_pointer_cast<ExprNode>(r->_cond), inner));
        if (!v) break;
        auto v2 = ExecuteStatement(r->_body, inner);
        if (state == State::RETURN) {
            return v2;
        }
        if (state == State::BREAK) {
            state = State::COMMON;
            break;
        }
        state = State::COMMON;
        auto v3 = ExecuteStatement(r->_next, inner);
        if (state == State::RETURN) {
            return v3;
        }
        if (state == State::BREAK) {
            state = State::COMMON;
            return VNull;
        }
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteCreation(std::shared_ptr<CreationNode> cr, std::shared_ptr<Environment> env) {
    auto cenv = std::dynamic_pointer_cast<CommonEnvironment>(cr->isGlobal ? gVM->inner : env);
    for (auto&[k, v] : cr->creations) {
        if (!cr->allowOverwrite && cenv->has(k)) {
            throw VMError("VM:ExecuteCreation", "Unable to overwrite variable " + k);
        }
        auto rv = ExecuteCommon(v, env);
        cenv->set(k, rv);
        if (cr->isConst) {
            cenv->makeConst(k);
        }
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteDecorate(std::shared_ptr<DecorateNode> dec, std::shared_ptr<Environment> env) {
    auto d = ExecuteCommon(dec->decorator, env), v = ExecuteCommon(dec->inner, env);
    if (d->type != Object::Type::Executable) {
        throw VMError("VM:ExecuteDecorate", "Decorator must be executable");
    }
    auto de = std::dynamic_pointer_cast<Executable>(d);
    return de->call({v});
}

std::shared_ptr<Object> VirtualMachine::ExecuteEnum(std::shared_ptr<EnumerateNode> e, std::shared_ptr<Environment> env) {
    inner->set(e->_name, std::make_shared<Mark>(e->_name));
    auto _enum = std::make_shared<MpcEnum>();
    size_t index = 0;
    for (auto& i : e->items) {
        _enum->entries.insert({i, index++});
    }
    GENT.insert({e->_name, _enum});
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteError(std::shared_ptr<ErrorNode> err, std::shared_ptr<Environment> env) {
    throw VMError("VM:ExecuteError", "Hit user defined error node");
}

std::shared_ptr<Object> VirtualMachine::ExecuteExpr(std::shared_ptr<ExprNode> expr, std::shared_ptr<Environment> env) {
    switch (expr->inner->type) {
    case Node::Type::Assign:
        return ExecuteAssign(std::dynamic_pointer_cast<AssignNode>(expr->inner), env);
    case Node::Type::Infix:
        return ExecuteInfix(std::dynamic_pointer_cast<InfixNode>(expr->inner), env);
    case Node::Type::Call:
        return ExecuteCall(std::dynamic_pointer_cast<CallNode>(expr->inner), env);
    case Node::Type::Index:
        return ExecuteIndex(std::dynamic_pointer_cast<IndexNode>(expr->inner), env);
    case Node::Type::InDecrement:
        return ExecuteInDecrement(std::dynamic_pointer_cast<InDecrementNode>(expr->inner), env);
    case Node::Type::Ternary:
        return ExecuteTernary(std::dynamic_pointer_cast<TernaryNode>(expr->inner), env);
    case Node::Type::Object:
        return ExecuteObject(std::dynamic_pointer_cast<ObjectNode>(expr->inner), env);
    case Node::Type::Integer:
        return ExecuteInteger(std::dynamic_pointer_cast<IntegerNode>(expr->inner), env);
    case Node::Type::Float:
        return ExecuteFloat(std::dynamic_pointer_cast<FloatNode>(expr->inner), env);
    case Node::Type::Boolean:
        return ExecuteBoolean(std::dynamic_pointer_cast<BooleanNode>(expr->inner), env);
    case Node::Type::Identifier:
        return ExecuteIdentifier(std::dynamic_pointer_cast<IdentifierNode>(expr->inner), env);
    case Node::Type::Function:
        return ExecuteFunction(std::dynamic_pointer_cast<FunctionNode>(expr->inner), env);
    case Node::Type::Array:
        return ExecuteArray(std::dynamic_pointer_cast<ArrayNode>(expr->inner), env);
    case Node::Type::Null:
        return ExecuteNull(std::dynamic_pointer_cast<NullNode>(expr->inner), env);
    case Node::Type::String:
        return ExecuteString(std::dynamic_pointer_cast<StringNode>(expr->inner), env);
    case Node::Type::Group:
        return ExecuteGroup(std::dynamic_pointer_cast<GroupNode>(expr->inner), env);
    case Node::Type::Prefix:
        return ExecutePrefix(std::dynamic_pointer_cast<PrefixNode>(expr->inner), env);
    case Node::Type::Decorate:
        return ExecuteDecorate(std::dynamic_pointer_cast<DecorateNode>(expr->inner), env);
    case Node::Type::Expr:
        return ExecuteExpr(std::dynamic_pointer_cast<ExprNode>(expr->inner), env);
    default:
        throw VMError("VM:ExecuteExpr", "Unable to get value - unknown node type");
    }
}

std::shared_ptr<Object> VirtualMachine::ExecuteFloat(std::shared_ptr<FloatNode> fl, std::shared_ptr<Environment> env) {
    return std::make_shared<Float>(fl->value);
}

std::shared_ptr<Object> VirtualMachine::ExecuteFor(std::shared_ptr<ForNode> f, std::shared_ptr<Environment> env) {
    auto r = ExecuteCommon(f->_elem, env);
    if (r->type == Object::Type::Array) r = Array2Iterator(std::dynamic_pointer_cast<Array>(r));
    if (r->type != Object::Type::Iterator) {
        throw VMError("VM:ExecuteFor", "Element is not an iterator");
    }
    auto it = std::dynamic_pointer_cast<Iterator>(r);
    auto inner = std::make_shared<CommonEnvironment>(env);
    while (it->hasNext()) {
        inner->set(f->_var, it->next());
        auto v = ExecuteStatement(f->_body, inner);
        if (state == State::BREAK) {
            state = State::COMMON;
            return VNull;
        }
        if (state == State::RETURN) {
            return v;
        }
        state = State::COMMON;
        it->go();
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteFunction(std::shared_ptr<FunctionNode> f, std::shared_ptr<Environment> env) {
    auto func = std::make_shared<Function>(f->inner, env);
    func->earg = f->moreName;
    for (auto& i : f->args) {
        func->args.push_back(i);
    }
    for (auto& i : f->typechecks) {
        func->checks.insert(i);
    }
    return func;
}

std::shared_ptr<Object> VirtualMachine::ExecuteGroup(std::shared_ptr<GroupNode> group, std::shared_ptr<Environment> env) {
    return ExecuteCommon(group->v, env);
}

std::shared_ptr<Object> VirtualMachine::ExecuteIdentifier(std::shared_ptr<IdentifierNode> id, std::shared_ptr<Environment> env) {
    return env->get(id->id);
}

std::shared_ptr<Object> VirtualMachine::ExecuteIf(std::shared_ptr<IfNode> r, std::shared_ptr<Environment> env) {
    bool cond = isTrue(ExecuteCommon(r->_cond, env));
    if (cond) {
        auto v = ExecuteStatement(r->_then, env);
        if (state == State::RETURN) {
            return v;
        }
    }
    else if (r->_else) {
        auto v = ExecuteStatement(r->_else, env);
        if (state == State::RETURN) {
            return v;
        }
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteInDecrement(std::shared_ptr<InDecrementNode> idc, std::shared_ptr<Environment> env) {
    auto a = ExecuteValue(idc->body, env);
    if (a->type != Object::Type::Reference) {
        throw VMError("VM:ExecuteXcrement", "Cannot use increment/decrement on rval");
    }
    auto ptr = std::dynamic_pointer_cast<Reference>(a)->ptr;
    auto rv = *ptr;
    if (rv->type == Object::Type::Integer) {
        rv = rv->make_copy();
        if (idc->isAfter) {
            auto cpy = rv->make_copy();
            std::dynamic_pointer_cast<Integer>(rv)->value += idc->isDecrement ? -1 : 1;
            *ptr = rv;
            return cpy;
        }
        else {
            std::dynamic_pointer_cast<Integer>(rv)->value += idc->isDecrement ? -1 : 1;
            *ptr = rv;
            return rv->make_copy();
        }
    }
    else if (rv->type == Object::Type::Float) {
        rv = rv->make_copy();
        if (idc->isAfter) {
            auto cpy = rv->make_copy();
            std::dynamic_pointer_cast<Float>(rv)->value += idc->isDecrement ? -1 : 1;
            *ptr = rv;
            return cpy;
        }
        else {
            std::dynamic_pointer_cast<Float>(rv)->value += idc->isDecrement ? -1 : 1;
            *ptr = rv;
            return rv->make_copy();
        }
    }
    else if (rv->type == Object::Type::Iterator) {
        if (idc->isDecrement) {
            throw VMError("VM:ExecuteXcrement", "Common Iterator does not support decreament");
        }
        if (idc->isAfter) {
            auto v = std::dynamic_pointer_cast<Iterator>(rv)->next();
            std::dynamic_pointer_cast<Iterator>(rv)->go();
            return v;
        }
        else {
            std::dynamic_pointer_cast<Iterator>(rv)->go();
            return std::dynamic_pointer_cast<Iterator>(rv)->next();
        }
    }
    throw VMError("VM:ExecuteXcrement", "Unknown object type");
}

std::shared_ptr<Object> VirtualMachine::ExecuteIndex(std::shared_ptr<IndexNode> ix, std::shared_ptr<Environment> env) {
    auto l = ExecuteValue(ix->left, env), inx = ExecuteCommon(ix->index, env);
    bool isr;
    if (isr = (l->type == Object::Type::Reference)) {
        l = *(std::dynamic_pointer_cast<Reference>(l)->ptr);
    }
    if (inx->type == Object::Type::CommonObject) {
        return std::dynamic_pointer_cast<CommonObject>(inx)->get(inx->toString());
    }
    if (inx->type == Object::Type::Boolean) {
        inx = std::make_shared<Integer>(std::dynamic_pointer_cast<Boolean>(inx)->value);
    }
    if (inx->type == Object::Type::Byte) {
        inx = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(inx)->value);
    }
    if (inx->type == Object::Type::ByteArray) {
        auto arr = std::dynamic_pointer_cast<ByteArray>(inx);
        auto res = std::make_shared<Array>();
        for (auto i : arr->value) {
            res->value.push_back(std::make_shared<Integer>(i));
        }
        inx = res;
    }
    if (inx->type != Object::Type::Integer && inx->type != Object::Type::Array) {
        throw VMError("VM:ExecuteIndex", "Unsupported index type");
    }
    if (l->type == Object::Type::String) {
        if (inx->type == Object::Type::Integer) {
            long long sl = std::dynamic_pointer_cast<String>(l)->value.length();
            return std::make_shared<String>(std::dynamic_pointer_cast<String>(l)->value.at((std::dynamic_pointer_cast<Integer>(inx)->value % sl + sl) % sl));
        }
        else {
            std::string rstr = "";
            auto arr = std::dynamic_pointer_cast<Array>(inx);
            auto& str = std::dynamic_pointer_cast<String>(l)->value;
            long long sl = str.length();
            for (auto& e : arr->value) {
                if (e->type == Object::Type::Boolean) {
                    e = std::make_shared<Integer>(std::dynamic_pointer_cast<Boolean>(e)->value);
                }
                if (e->type == Object::Type::Byte) {
                    e = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(e)->value);
                }
                if (e->type != Object::Type::Integer) {
                    throw VMError("VM:ExecuteIndex", "Unsupported index type");
                }
                rstr += str.at((std::dynamic_pointer_cast<Integer>(e)->value % sl + sl) % sl);
            }
            return std::make_shared<String>(rstr);
        }
    }
    else if (l->type == Object::Type::Array) {
        if (inx->type == Object::Type::Integer) {
            long long al = std::dynamic_pointer_cast<Array>(l)->value.size();
            if (isr) {
                // std::dynamic_pointer_cast<Array>(l)->value[(std::dynamic_pointer_cast<Integer>(inx)->value % al + al) % al] = std::dynamic_pointer_cast<Array>(l)->value[(std::dynamic_pointer_cast<Integer>(inx)->value % al + al) % al]->make_copy();
                return std::make_shared<Reference>(&(std::dynamic_pointer_cast<Array>(l)->value[(std::dynamic_pointer_cast<Integer>(inx)->value % al + al) % al]));
            }
            else {
                return std::dynamic_pointer_cast<Array>(l)->value[(std::dynamic_pointer_cast<Integer>(inx)->value % al + al) % al];
            }
        }
        else {
            auto res = std::make_shared<Array>();
            auto& arr = std::dynamic_pointer_cast<Array>(l)->value;
            auto idx = std::dynamic_pointer_cast<Array>(inx);
            long long al = arr.size();
            for (auto& e : idx->value) {
                if (e->type == Object::Type::Boolean) {
                    e = std::make_shared<Integer>(std::dynamic_pointer_cast<Boolean>(e)->value);
                }
                if (e->type == Object::Type::Byte) {
                    e = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(e)->value);
                }
                if (e->type != Object::Type::Integer) {
                    throw VMError("VM:ExecuteIndex", "Unsupported index type");
                }
                res->value.push_back(arr[(std::dynamic_pointer_cast<Integer>(e)->value % al + al) % al]);
            }
            return res;
        }
    }
    throw VMError("VM:ExecuteIndex", "Unsupported element type");
}

std::shared_ptr<Object> VirtualMachine::ExecuteInfix(std::shared_ptr<InfixNode> calc, std::shared_ptr<Environment> env) {
    if (calc->_op == "||") {
        if (isTrue(ExecuteCommon(calc->left, env))) return True;
        if (isTrue(ExecuteCommon(calc->right, env))) return True;
        return False;
    }
    if (calc->_op == "&&") {
        if (!isTrue(ExecuteCommon(calc->left, env))) return False;
        if (!isTrue(ExecuteCommon(calc->right, env))) return False;
        return True;
    }
    if (calc->_op == "." || calc->_op == "::") {
        if (calc->right->type != Node::Type::Identifier) {
            throw VMError("VM:ExecuteInfix", "Getter right must be an identifier");
        }
        return CalculateGetter(ExecuteValue(calc->left, env), std::dynamic_pointer_cast<IdentifierNode>(calc->right)->id, env, calc->_op == "::");
    }
    auto le = ExecuteCommon(calc->left, env), ri = ExecuteCommon(calc->right, env);
    return CalculateInfix(calc->_op, le, ri, env);
}

std::shared_ptr<Object> VirtualMachine::ExecuteInteger(std::shared_ptr<IntegerNode> iv, std::shared_ptr<Environment> env) {
    if (-32 <= iv->value && iv->value <= 512) {
        return IntegerConstants[iv->value + 32];
    }
    return std::make_shared<Integer>(iv->value);
}

std::shared_ptr<Object> VirtualMachine::ExecuteNull(std::shared_ptr<NullNode> nl, std::shared_ptr<Environment> env) {
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteObject(std::shared_ptr<ObjectNode> obj, std::shared_ptr<Environment> env) {
    return obj->obj;
}

std::shared_ptr<Object> VirtualMachine::ExecutePrefix(std::shared_ptr<PrefixNode> calc, std::shared_ptr<Environment> env) {
    auto obj = ExecuteCommon(calc->right, env);
    if (calc->_op == "-") {
        if (obj->type == Object::Type::Integer) {
            return std::make_shared<Integer>(-(std::dynamic_pointer_cast<Integer>(obj)->value));
        }
        else if (obj->type == Object::Type::Float) {
            return std::make_shared<Float>(-(std::dynamic_pointer_cast<Float>(obj)->value));
        }
        throw VMError("VM:ExecutePrefix", "Unsupported type for operator-");
    }
    else if (calc->_op == "+") {
        if (obj->type == Object::Type::Integer || obj->type == Object::Type::Float) {
            return obj;
        }
        throw VMError("VM:ExecutePrefix", "Unsupported type for operator+");
    }
    else if (calc->_op == "!") {
        bool v = isTrue(obj);
        return v ? False : True;
    }
    else if (calc->_op == "~") {
        if (obj->type == Object::Type::Integer) {
            return std::make_shared<Integer>(~(std::dynamic_pointer_cast<Integer>(obj)->value));
        }
        else if (obj->type == Object::Type::Byte) {
            return std::make_shared<Byte>(~(std::dynamic_pointer_cast<Byte>(obj)->value));
        }
        else if (obj->type == Object::Type::ByteArray) {
            auto res = std::make_shared<ByteArray>(), cast = std::dynamic_pointer_cast<ByteArray>(obj);
            for (auto& e : cast->value) {
                res->value.push_back(~e);
            }
            return res;
        }
        throw VMError("VM:ExecutePrefix", "Unsupported type for operator~");
    }
    throw VMError("VM:ExecutePrefix", "Unknown operator " + calc->_op);
}

std::shared_ptr<Object> VirtualMachine::ExecuteRemove(std::shared_ptr<RemoveNode> rmv, std::shared_ptr<Environment> env) {
    env->remove(rmv->toRemove);
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteReturn(std::shared_ptr<ReturnNode> ret, std::shared_ptr<Environment> env) {
    std::shared_ptr<Object> res;
    if (ret->isReference) {
        auto v = ExecuteValue(ret->obj, env);
        if (v->type != Object::Type::Reference) {
            throw VMError("VM:ExecuteReturn", "Unable to return a non-reference");
        }
        res = v;
    }
    else {
        res = ExecuteCommon(ret->obj, env);
    }
    state = State::RETURN;
    return res;
}

std::shared_ptr<Object> VirtualMachine::ExecuteScope(std::shared_ptr<ScopeNode> scope, std::shared_ptr<Environment> env, bool notIsolated) {
    auto inner = notIsolated ? env : std::dynamic_pointer_cast<Environment>(std::make_shared<CommonEnvironment>(env));
    for (auto& s : scope->statements) {
        auto v = ExecuteStatement(s, inner);
        if (state == State::RETURN) {
            return v;
        }
        if (state != State::COMMON) {
            return VNull;
        }
        lastObject = v;
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteString(std::shared_ptr<StringNode> str, std::shared_ptr<Environment> env) {
    return std::make_shared<String>(str->value);
}

std::shared_ptr<Object> VirtualMachine::ExecuteTernary(std::shared_ptr<TernaryNode> tern, std::shared_ptr<Environment> env) {
    bool cond = isTrue(ExecuteCommon(tern->_cond, env));
    if (cond) return ExecuteCommon(tern->_if, env);
    else return ExecuteCommon(tern->_else, env);
}

std::shared_ptr<Object> VirtualMachine::ExecuteWhile(std::shared_ptr<WhileNode> wh, std::shared_ptr<Environment> env) {
    auto inner = std::make_shared<CommonEnvironment>(env);
    if (wh->isDoWhile) {
        do {
            auto v = ExecuteStatement(wh->_body, inner);
            if (state == State::BREAK) {
                state = State::COMMON;
                return VNull;
            }
            if (state == State::RETURN) {
                return v;
            }
            state = State::COMMON;
        }
        while (isTrue(ExecuteCommon(wh->_cond, inner)));
    }
    else {
        while (isTrue(ExecuteCommon(wh->_cond, inner))) {
            auto v = ExecuteStatement(wh->_body, inner);
            if (state == State::BREAK) {
                state = State::COMMON;
                return VNull;
            }
            if (state == State::RETURN) {
                return v;
            }
            state = State::COMMON;
        }
    }
    return VNull;
}

std::shared_ptr<Object> VirtualMachine::ExecuteValue(std::shared_ptr<Node> v, std::shared_ptr<Environment> env) {
    if (v->type == Node::Type::Expr) return ExecuteExpr(std::dynamic_pointer_cast<ExprNode>(v), env);
    else return ExecuteExpr(std::make_shared<ExprNode>(v), env);
}

std::shared_ptr<Object> VirtualMachine::ExecuteCommon(std::shared_ptr<Node> v, std::shared_ptr<Environment> env) {
    auto r = ExecuteValue(v, env);
    if (r->type == Object::Type::Reference) {
        return r->make_copy();
    }
    return r;
}

std::shared_ptr<Object> VirtualMachine::ExecuteStatement(std::shared_ptr<Node> v, std::shared_ptr<Environment> env) {
    switch (v->type) {
    case Node::Type::BreakContinue:
        return ExecuteBreakContinue(std::dynamic_pointer_cast<BreakContinueNode>(v), env);
    case Node::Type::CFor:
        return ExecuteCFor(std::dynamic_pointer_cast<CForNode>(v), env);
    case Node::Type::Scope:
        return ExecuteScope(std::dynamic_pointer_cast<ScopeNode>(v), env);
    case Node::Type::Creation:
        return ExecuteCreation(std::dynamic_pointer_cast<CreationNode>(v), env);
    case Node::Type::If:
        return ExecuteIf(std::dynamic_pointer_cast<IfNode>(v), env);
    case Node::Type::Return:
        return ExecuteReturn(std::dynamic_pointer_cast<ReturnNode>(v), env);
    case Node::Type::For:
        return ExecuteFor(std::dynamic_pointer_cast<ForNode>(v), env);
    case Node::Type::While:
        return ExecuteWhile(std::dynamic_pointer_cast<WhileNode>(v), env);
    case Node::Type::Enumerate:
        return ExecuteEnum(std::dynamic_pointer_cast<EnumerateNode>(v), env);
    case Node::Type::Remove:
        return ExecuteRemove(std::dynamic_pointer_cast<RemoveNode>(v), env);
    case Node::Type::Expr:
        return ExecuteExpr(std::dynamic_pointer_cast<ExprNode>(v), env);
    default:
        throw VMError("VM:ExecuteStat", "Unknown Statement Type");
    }
}

bool VirtualMachine::isTrue(std::shared_ptr<Object> obj) {
    if (obj->type == Object::Type::Reference) {
        obj = obj->make_copy();
    }
    if (obj->type == Object::Type::Boolean) {
        return std::dynamic_pointer_cast<Boolean>(obj)->value;
    }
    if (obj->type == Object::Type::Integer) {
        return std::dynamic_pointer_cast<Integer>(obj)->value;
    }
    if (obj->type == Object::Type::Float) {
        return std::dynamic_pointer_cast<Float>(obj)->value;
    }
    if (obj->type == Object::Type::File) {
        return !(std::dynamic_pointer_cast<File>(obj)->fs->good());
    }
    if (obj->type == Object::Type::Iterator) {
        return std::dynamic_pointer_cast<Iterator>(obj)->hasNext();
    }
    if (obj->type == Object::Type::Byte) {
        return std::dynamic_pointer_cast<Byte>(obj)->value;
    }
    return true;
}

std::shared_ptr<Object> VirtualMachine::CalculateInfix(std::string op, std::shared_ptr<Object> a, std::shared_ptr<Object> b, std::shared_ptr<Environment> env) {
    if (op == "===" && a->type != b->type) return False;
    if (op == "!==" && a->type != b->type) return True;
    if (a->type <= Object::Type::Float && b->type <= Object::Type::Float) {
        if (a->type == Object::Type::Boolean) a = std::make_shared<Byte>(isTrue(a));
        if (b->type == Object::Type::Boolean) b = std::make_shared<Byte>(isTrue(b));
        if (a->type == Object::Type::Null) a = std::make_shared<Byte>(0);
        if (b->type == Object::Type::Null) b = std::make_shared<Byte>(0);
        if (a->type == Object::Type::Byte && b->type == Object::Type::Byte) {
            return CalculateInteger<Byte>(op, std::dynamic_pointer_cast<Byte>(a), std::dynamic_pointer_cast<Byte>(b));
        }
        if (a->type == Object::Type::Byte) a = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(a)->value);
        if (b->type == Object::Type::Byte) b = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(b)->value);
        if (a->type == Object::Type::Integer && b->type == Object::Type::Integer) {
            return CalculateInteger<Integer>(op, std::dynamic_pointer_cast<Integer>(a), std::dynamic_pointer_cast<Integer>(b));
        }
        if (a->type == Object::Type::Integer) a = std::make_shared<Float>(std::dynamic_pointer_cast<Integer>(a)->value);
        if (b->type == Object::Type::Integer) b = std::make_shared<Float>(std::dynamic_pointer_cast<Integer>(b)->value);
        return CalculateFloat(op, std::dynamic_pointer_cast<Float>(a), std::dynamic_pointer_cast<Float>(b));
    }
    if (op == "==" || op == "!=" || op == ">" || op == "<" || op == ">=" || op == "<=" || op == "===" || op == "!==") {
        return CalculateRelationship(op, a, b);
    }
    if (op == "*" && (b->type == Object::Type::Byte || b->type == Object::Type::Integer || b->type == Object::Type::Boolean)) {
        if (b->type == Object::Type::Boolean) b = std::make_shared<Integer>(isTrue(b));
        if (b->type == Object::Type::Byte) b = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(b)->value);
        long long rep = std::dynamic_pointer_cast<Integer>(b)->value;
        if ((a->type == Object::Type::Array || a->type == Object::Type::Iterator) && (b->type == Object::Type::Byte || b->type == Object::Type::Integer || b->type == Object::Type::Boolean)) {
            if (a->type == Object::Type::Iterator) a = std::dynamic_pointer_cast<Iterator>(a)->toArray();
            if (rep <= 0) return std::make_shared<Array>();
            auto res = std::make_shared<Array>(), cas = std::dynamic_pointer_cast<Array>(a);
            while (rep--) {
                res->value.insert(res->value.end(), cas->value.begin(), cas->value.end());
            }
            return res;
        }
        else if (a->type == Object::Type::String) {
            if (rep <= 0) return std::make_shared<String>("");
            std::stringstream ss;
            auto cas = std::dynamic_pointer_cast<String>(a);
            StringHash hash = {0, 0};
            while (rep--) {
                ss << cas->value;
                hash = concatHash(hash, cas->hash, cas->value.length());
            }
            return std::make_shared<String>(ss.str(), hash);
        }
        else if (a->type == Object::Type::ByteArray) {
            if (rep <= 0) return std::make_shared<ByteArray>();
            auto res = std::make_shared<ByteArray>(), cas = std::dynamic_pointer_cast<ByteArray>(a);
            while (rep--) {
                res->value.insert(res->value.end(), cas->value.begin(), cas->value.end());
            }
            return res;
        }
    }
    if (op == "*" && (a->type == Object::Type::Byte || a->type == Object::Type::Integer || a->type == Object::Type::Boolean)) {
        if (a->type == Object::Type::Boolean) a = std::make_shared<Integer>(isTrue(a));
        if (a->type == Object::Type::Byte) a = std::make_shared<Integer>(std::dynamic_pointer_cast<Byte>(a)->value);
        long long rep = std::dynamic_pointer_cast<Integer>(a)->value;
        if ((b->type == Object::Type::Array || b->type == Object::Type::Iterator) && (a->type == Object::Type::Byte || a->type == Object::Type::Integer || a->type == Object::Type::Boolean)) {
            if (b->type == Object::Type::Iterator) b = std::dynamic_pointer_cast<Iterator>(b)->toArray();
            if (rep <= 0) return std::make_shared<Array>();
            auto res = std::make_shared<Array>(), cas = std::dynamic_pointer_cast<Array>(b);
            while (rep--) {
                res->value.insert(res->value.end(), cas->value.begin(), cas->value.end());
            }
            return res;
        }
        else if (b->type == Object::Type::String) {
            if (rep <= 0) return std::make_shared<String>("");
            std::stringstream ss;
            auto cas = std::dynamic_pointer_cast<String>(b);
            StringHash hash = {0, 0};
            while (rep--) {
                ss << cas->value;
                hash = concatHash(hash, cas->hash, cas->value.length());
            }
            return std::make_shared<String>(ss.str(), hash);
        }
        else if (b->type == Object::Type::ByteArray) {
            if (rep <= 0) return std::make_shared<ByteArray>();
            auto res = std::make_shared<ByteArray>(), cas = std::dynamic_pointer_cast<ByteArray>(b);
            while (rep--) {
                res->value.insert(res->value.end(), cas->value.begin(), cas->value.end());
            }
            return res;
        }
    }
    if (op != "+") {
        throw VMError("VM:CalculateInfix", "No that operator " + op + " between these objects");
    }
    if ((a->type == Object::Type::Array || a->type == Object::Type::Iterator) && (b->type == Object::Type::Array || b->type == Object::Type::Iterator)) {
        if (a->type == Object::Type::Iterator) a = std::dynamic_pointer_cast<Iterator>(a)->toArray();
        if (b->type == Object::Type::Iterator) b = std::dynamic_pointer_cast<Iterator>(b)->toArray();
        return CalculateArrStrExt(a, b);
    }
    return CalculatePlusToString(a, b);
}

std::shared_ptr<Object> VirtualMachine::CalculatePlusToString(std::shared_ptr<Object> a, std::shared_ptr<Object> b) {
    return std::make_shared<String>(a->toString() + b->toString());
}

template<typename _Tp>
_Tp VM_fastPow(_Tp base, long long sup) {
    _Tp res = 1;
    while (sup) {
        if (sup & 1) res *= base;
        base *= base;
        sup >>= 1;
    }
    return res;
}

template<typename _Tp>
std::shared_ptr<Object> VirtualMachine::CalculateInteger(std::string op, std::shared_ptr<_Tp> a, std::shared_ptr<_Tp> b) {
    auto av = a->value, bv = b->value;
    if (op == "+") return std::make_shared<_Tp>(av + bv);
    if (op == "-") return std::make_shared<_Tp>(av - bv);
    if (op == "*") return std::make_shared<_Tp>(av * bv);
    if (op == "/") return std::make_shared<_Tp>(av / bv);
    if (op == "%") return std::make_shared<_Tp>(av % bv);
    if (op == "^") return std::make_shared<_Tp>(av ^ bv);
    if (op == "&") return std::make_shared<_Tp>(av & bv);
    if (op == "|") return std::make_shared<_Tp>(av | bv);
    if (op == "<<") return std::make_shared<_Tp>(av << bv);
    if (op == ">>") return std::make_shared<_Tp>(av >> bv);
    if (op == ">") return av > bv ? True : False;
    if (op == ">=") return av >= bv ? True : False;
    if (op == "<") return av < bv ? True : False;
    if (op == "<=") return av <= bv ? True : False;
    if (op == "==" || op == "===") return av == bv ? True : False;
    if (op == "!=" || op == "!==") return av != bv ? True : False;
    if (op == "**") return std::make_shared<_Tp>(VM_fastPow(av, bv));
    if (op == "...") {
        auto res = std::make_shared<Array>();
        if (av <= bv) {
            while (av <= bv) {
                res->value.push_back(std::make_shared<_Tp>(av));
                av++;
            }
        }
        else {
            while (av >= bv) {
                res->value.push_back(std::make_shared<_Tp>(av));
                av--;
            }
        }
        return res;
    }
    throw VMError("VM:CalcInteger", "Unknown operator " + op);
}

std::shared_ptr<Object> VirtualMachine::CalculateFloat(std::string op, std::shared_ptr<Float> a, std::shared_ptr<Float> b) {
    double av = a->value, bv = b->value;
    if (op == "+") return std::make_shared<Float>(av + bv);
    if (op == "-") return std::make_shared<Float>(av - bv);
    if (op == "*") return std::make_shared<Float>(av * bv);
    if (op == "/") return std::make_shared<Float>(av / bv);
    if (op == "%") return std::make_shared<Float>(fmod(av, bv));
    if (op == ">") return (av > bv) ? True : False;
    if (op == ">=") return (av >= bv) ? True : False;
    if (op == "<") return (av < bv) ? True : False;
    if (op == "<=") return (av <= bv) ? True : False;
    if (op == "==" || op == "===") return (av == bv) ? True : False;
    if (op == "!=" || op == "!==") return (av != bv) ? True : False;
    if (op == "**") return std::make_shared<Float>(pow(av, bv));
    throw VMError("VM:CalcFloat", "Unknown operator " + op);
}

std::shared_ptr<Object> VirtualMachine::CalculateArrStrExt(std::shared_ptr<Object> a, std::shared_ptr<Object> b) {
    auto aa = std::dynamic_pointer_cast<Array>(a), ab = std::dynamic_pointer_cast<Array>(b), ac = std::make_shared<Array>();
    ac->value.insert(ac->value.end(), aa->value.begin(), aa->value.end());
    ac->value.insert(ac->value.end(), ab->value.begin(), ab->value.end());
    return ac;
}

std::shared_ptr<Object> VirtualMachine::CalculateRelationship(std::string op, std::shared_ptr<Object> a, std::shared_ptr<Object> b) {
    if (op == "===") {
        if (a->type == Object::Type::Null) return True;
        if (a->type == Object::Type::String) return (std::dynamic_pointer_cast<String>(a)->hash) == (std::dynamic_pointer_cast<String>(b)->hash) ? True : False;
        if (a->type == Object::Type::Array) {
            auto ac = std::dynamic_pointer_cast<Array>(a), bc = std::dynamic_pointer_cast<Array>(b);
            if (ac->value.size() != bc->value.size()) return False;
            for (auto ait = ac->value.begin(), bit = bc->value.begin(); ait != ac->value.end(); ait++, bit++) {
                if (!isTrue(CalculateRelationship("===", *ait, *bit))) return False;
            }
            return True;
        }
        return False;
    }
    if (op == "!==") {
        if (a->type == Object::Type::Null) return False;
        if (a->type == Object::Type::String) return (std::dynamic_pointer_cast<String>(a)->hash) == (std::dynamic_pointer_cast<String>(b)->hash) ? False : True;
        if (a->type == Object::Type::Array) {
            auto ac = std::dynamic_pointer_cast<Array>(a), bc = std::dynamic_pointer_cast<Array>(b);
            if (ac->value.size() != bc->value.size()) return True;
            for (auto ait = ac->value.begin(), bit = bc->value.begin(); ait != ac->value.end(); ait++, bit++) {
                if (!isTrue(CalculateRelationship("===", *ait, *bit))) return True;
            }
            return False;
        }
        return True;
    }
    if (a->type == Object::Type::String && b->type == Object::Type::String) {
        if (op == "==") return (std::dynamic_pointer_cast<String>(a)->hash == std::dynamic_pointer_cast<String>(b)->hash) ? True : False;
        if (op == "!=") return (std::dynamic_pointer_cast<String>(a)->hash == std::dynamic_pointer_cast<String>(b)->hash) ? False : True;
        if (op == "<") return (std::dynamic_pointer_cast<String>(a)->value < std::dynamic_pointer_cast<String>(b)->value) ? True : False;
        if (op == ">") return (std::dynamic_pointer_cast<String>(a)->value > std::dynamic_pointer_cast<String>(b)->value) ? True : False;
        if (op == "<=") return (std::dynamic_pointer_cast<String>(a)->value <= std::dynamic_pointer_cast<String>(b)->value) ? True : False;
        if (op == ">=") return (std::dynamic_pointer_cast<String>(a)->value >= std::dynamic_pointer_cast<String>(b)->value) ? True : False;
    }
    else {
        if (op == "!=") return True;
        return False;
    }
}

std::shared_ptr<Object> VirtualMachine::CalculateGetter(std::shared_ptr<Object> a, std::string b, std::shared_ptr<Environment> env, bool isForced) {
    long long ident = isForced ? -1 : getIdent(env);
    Object::Type type;
    if (a->type == Object::Type::Reference) type = (*std::dynamic_pointer_cast<Reference>(a)->ptr)->type;
    else type = a->type;
    if (type == Object::Type::Mark) {
        if (a->type == Object::Type::Reference) a = *std::dynamic_pointer_cast<Reference>(a)->ptr;
        auto mrk = std::dynamic_pointer_cast<Mark>(a);
        auto it = GENT.find(mrk->value);
        if (it == GENT.end()) {
            return VNull;
        }
        auto v = it->second->entries.find(b);
        if (v == it->second->entries.end()) {
            return VNull;
        }
        return std::make_shared<Integer>(v->second);
    }
    if (type == Object::Type::CommonObject) {
        if (a->type == Object::Type::Reference) a = *std::dynamic_pointer_cast<Reference>(a)->ptr;
        return std::dynamic_pointer_cast<CommonObject>(a)->get(b);
    }
    auto f = env->get(b);
    if (f->type == Object::Type::Reference) {
        f = f->make_copy();
    }
    if (f->type != Object::Type::Executable) {
        return VNull;
    }
    auto scop = std::make_shared<ScopeNode>();
    auto call = std::make_shared<CallNode>(std::make_shared<ObjectNode>(f));
    call->args.push_back(std::make_shared<ObjectNode>(a));
    call->args.push_back(std::make_shared<IdentifierNode>("__args"));
    call->expands.push_back(1);
    auto re = std::make_shared<ReturnNode>(call);
    scop->statements.push_back(re);
    auto func = std::make_shared<Function>(scop, env);
    func->earg = "__args";
    return func;
}

std::shared_ptr<Object> VirtualMachine::Array2Iterator(std::shared_ptr<Array> arr) {
    return std::make_shared<ArrayBasedIterator>(arr);
}

long long VirtualMachine::getIdent(std::shared_ptr<Environment> env) {
    auto item = env->get("__index__");
    if (item->type == Object::Type::Integer) {
        return std::dynamic_pointer_cast<Integer>(item)->value;
    }
    return 0;
}

VirtualMachine::VirtualMachine(std::shared_ptr<Environment> outer) {
    outer = outer;
    inner = std::make_shared<CommonEnvironment>(outer);
    state = State::COMMON;
    for (int i = -32; i <= 512; i++) IntegerConstants[i + 32] = std::make_shared<Integer>(i);
    True = std::make_shared<Boolean>(true);
    False = std::make_shared<Boolean>(false);
    VNull = std::make_shared<Null>();
    lastObject = VNull;
}

std::string VirtualMachine::getTypeString(std::shared_ptr<Object> obj) {
    if (obj->type == Object::Type::Reference) {
        obj = obj->make_copy();
    }
    if (obj->type == Object::Type::Array) return "array";
    else if (obj->type == Object::Type::Boolean) return "boolean";
    else if (obj->type == Object::Type::Byte) return "byte";
    else if (obj->type == Object::Type::ByteArray) return "ByteArray";
    else if (obj->type == Object::Type::CommonObject) return "Object";
    else if (obj->type == Object::Type::Executable) return "executable";
    else if (obj->type == Object::Type::File) return "File";
    else if (obj->type == Object::Type::Float) return "float";
    else if (obj->type == Object::Type::Integer) return "int";
    else if (obj->type == Object::Type::Iterator) return "iterator";
    else if (obj->type == Object::Type::Map) return "Map";
    else if (obj->type == Object::Type::Mark) return "BaseType";
    else if (obj->type == Object::Type::Native) return "native";
    else if (obj->type == Object::Type::Null) return "nulltype";
    else if (obj->type == Object::Type::Segment) return "segment";
    else if (obj->type == Object::Type::Set) return "set";
    else if (obj->type == Object::Type::String) return "string";
    else return "unknown";
}

VirtualMachine* gVM;