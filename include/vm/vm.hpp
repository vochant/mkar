#pragma once

#include "object/object.hpp"
#include "env/environment.hpp"

#include "ast/array.hpp"
#include "ast/assign.hpp"
#include "ast/boolean.hpp"
#include "ast/break_continue.hpp"
#include "ast/call.hpp"
#include "ast/cfor.hpp"
#include "ast/creation.hpp"
#include "ast/decorate.hpp"
#include "ast/enumerate.hpp"
#include "ast/expr.hpp"
#include "ast/float.hpp"
#include "ast/for.hpp"
#include "ast/function.hpp"
#include "ast/group.hpp"
#include "ast/identifier.hpp"
#include "ast/if.hpp"
#include "ast/indecrement.hpp"
#include "ast/index.hpp"
#include "ast/infix.hpp"
#include "ast/integer.hpp"
#include "ast/null.hpp"
#include "ast/object.hpp"
#include "ast/prefix.hpp"
#include "ast/program.hpp"
#include "ast/remove.hpp"
#include "ast/return.hpp"
#include "ast/scope.hpp"
#include "ast/string.hpp"
#include "ast/ternary.hpp"
#include "ast/while.hpp"

#include "object/array.hpp"
#include "object/integer.hpp"
#include "object/float.hpp"

#include <stack>
#include <vector>

class VirtualMachine {
public:
    std::shared_ptr<Environment> outer, inner;
    enum class State {
        COMMON, BREAK, CONTINUE, RETURN
    } state;
public:
    int Execute(std::shared_ptr<ProgramNode> program, std::shared_ptr<Environment> env);

    std::shared_ptr<Object> ExecuteArray(std::shared_ptr<ArrayNode> arr, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteAssign(std::shared_ptr<AssignNode> assign, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteBoolean(std::shared_ptr<BooleanNode> b, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteBreakContinue(std::shared_ptr<BreakContinueNode> bc, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteCall(std::shared_ptr<CallNode> call, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteCFor(std::shared_ptr<CForNode> r, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteCreation(std::shared_ptr<CreationNode> cr, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteDecorate(std::shared_ptr<DecorateNode> dec, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteEnum(std::shared_ptr<EnumerateNode> e, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteError(std::shared_ptr<ErrorNode> err, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteExpr(std::shared_ptr<ExprNode> expr, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteFloat(std::shared_ptr<FloatNode> fl, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteFor(std::shared_ptr<ForNode> r, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteFunction(std::shared_ptr<FunctionNode> f, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteGroup(std::shared_ptr<GroupNode> group, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteIdentifier(std::shared_ptr<IdentifierNode> id, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteIf(std::shared_ptr<IfNode> r, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteInDecrement(std::shared_ptr<InDecrementNode> id, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteIndex(std::shared_ptr<IndexNode> ix, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteInfix(std::shared_ptr<InfixNode> calc, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteInteger(std::shared_ptr<IntegerNode> iv, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteNull(std::shared_ptr<NullNode> nl, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteObject(std::shared_ptr<ObjectNode> obj, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecutePrefix(std::shared_ptr<PrefixNode> calc, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteRemove(std::shared_ptr<RemoveNode> rmv, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteReturn(std::shared_ptr<ReturnNode> ret, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteScope(std::shared_ptr<ScopeNode> scope, std::shared_ptr<Environment> env, bool notIsolated = false);
    std::shared_ptr<Object> ExecuteString(std::shared_ptr<StringNode> str, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteTernary(std::shared_ptr<TernaryNode> tern, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteWhile(std::shared_ptr<WhileNode> wh, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteValue(std::shared_ptr<Node> v, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteCommon(std::shared_ptr<Node> v, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> ExecuteStatement(std::shared_ptr<Node> v, std::shared_ptr<Environment> env);
public:
    std::shared_ptr<Object> IntegerConstants[545]; // [-32, 512]
    std::shared_ptr<Object> True, False, VNull;
    bool isTrue(std::shared_ptr<Object> obj);
    std::shared_ptr<Object> CalculateInfix(std::string op, std::shared_ptr<Object> a, std::shared_ptr<Object> b, std::shared_ptr<Environment> env);
    std::shared_ptr<Object> CalculatePlusToString(std::shared_ptr<Object> a, std::shared_ptr<Object> b);
    template<typename _Tp>
    std::shared_ptr<Object> CalculateInteger(std::string op, std::shared_ptr<_Tp> a, std::shared_ptr<_Tp> b);
    std::shared_ptr<Object> CalculateFloat(std::string op, std::shared_ptr<Float> a, std::shared_ptr<Float> b);
    std::shared_ptr<Object> CalculateArrStrExt(std::shared_ptr<Object> a, std::shared_ptr<Object> b);
    std::shared_ptr<Object> CalculateRelationship(std::string op, std::shared_ptr<Object> a, std::shared_ptr<Object> b);
    std::shared_ptr<Object> CalculateGetter(std::shared_ptr<Object> a, std::string b, std::shared_ptr<Environment> env, bool isForced);
    std::shared_ptr<Object> Array2Iterator(std::shared_ptr<Array> arr);
    long long getIdent(std::shared_ptr<Environment> env);
    std::string getTypeString(std::shared_ptr<Object> obj);
public:
    VirtualMachine(std::shared_ptr<Environment> outer);
    std::shared_ptr<Object> lastObject;
};

extern VirtualMachine* gVM;