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
#include "ast/prefix.hpp"
#include "ast/program.hpp"
#include "ast/remove.hpp"
#include "ast/return.hpp"
#include "ast/scope.hpp"
#include "ast/string.hpp"
#include "ast/ternary.hpp"
#include "ast/while.hpp"
#include "ast/object.hpp"

#include "compiler_error.hpp"
#include "util.hpp"

Node::Node(Type type) : type(type) {}

ArrayNode::ArrayNode() : Node(Node::Type::Array) {}
AssignNode::AssignNode(std::string _op) : _op(_op), Node(Node::Type::Assign) {}
BooleanNode::BooleanNode(bool value) : value(value), Node(Node::Type::Boolean) {}
BreakContinueNode::BreakContinueNode(bool isContinue) : Node(Node::Type::BreakContinue), isContinue(isContinue) {}
CallNode::CallNode(std::shared_ptr<Node> to_run) : to_run(to_run), Node(Node::Type::Call) {}
CForNode::CForNode() : Node(Node::Type::CFor) {}
CreationNode::CreationNode(bool isGlobal, bool allowOverwrite, bool isConst) : isGlobal(isGlobal), allowOverwrite(allowOverwrite), isConst(isConst), Node(Node::Type::Creation) {}
DecorateNode::DecorateNode() : Node(Node::Type::Decorate) {}
EnumerateNode::EnumerateNode() : Node(Node::Type::Enumerate) {}
ErrorNode::ErrorNode() : Node(Node::Type::Error) {}
ExprNode::ExprNode(std::shared_ptr<Node> inner) : inner(inner), Node(Node::Type::Expr) {}
FloatNode::FloatNode(double value) : value(value), Node(Node::Type::Float) {}
ForNode::ForNode() : Node(Node::Type::For) {}
FunctionNode::FunctionNode() : Node(Node::Type::Function), moreName("__null__") {}
GroupNode::GroupNode(std::shared_ptr<Node> v) : v(v), Node(Node::Type::Group) {}
IdentifierNode::IdentifierNode(std::string id) : id(id), Node(Node::Type::Identifier) {}
IfNode::IfNode() : Node(Node::Type::If) {}
InDecrementNode::InDecrementNode(std::shared_ptr<Node> body, bool isDecrement, bool isAfter) : body(body), isDecrement(isDecrement), isAfter(isAfter), Node(Node::Type::InDecrement) {}
IndexNode::IndexNode(std::shared_ptr<Node> left, std::shared_ptr<Node> index) : left(left), index(index), Node(Node::Type::Index) {}
InfixNode::InfixNode(std::string _op) : _op(_op), Node(Node::Type::Infix) {}
IntegerNode::IntegerNode(long long value) : value(value), Node(Node::Type::Integer) {}
NullNode::NullNode() : Node(Node::Type::Null) {}
PrefixNode::PrefixNode(std::string _op) : _op(_op), Node(Node::Type::Prefix) {}
ProgramNode::ProgramNode(std::shared_ptr<Node> mainScope) : mainScope(mainScope), Node(Node::Type::Program) {}
RemoveNode::RemoveNode(std::string toRemove) : toRemove(toRemove), Node(Node::Type::Remove) {}
ReturnNode::ReturnNode(std::shared_ptr<Node> obj) : obj(obj), Node(Node::Type::Return), isReference(false) {}
ScopeNode::ScopeNode() : Node(Node::Type::Scope) {}
StringNode::StringNode(std::string value) : value(unescape(value)), Node(Node::Type::String) {}
TernaryNode::TernaryNode(std::shared_ptr<Node> _cond) : _cond(_cond), Node(Node::Type::Ternary) {}
WhileNode::WhileNode(bool isDoWhile) : isDoWhile(isDoWhile), Node(Node::Type::While) {}
ObjectNode::ObjectNode(std::shared_ptr<Object> obj) : obj(obj), Node(Node::Type::Object) {}

Node::~Node() = default;