#pragma once

#include "ast/base/node.hpp"
#include "ast/scope.hpp"
#include "lexer/lexer.hpp"

#include <functional>

std::string noNext();

class Parser {
private:
    enum class OperatorPriority {
        Lowest, Range, Assign, LogicalOr, LogicalAnd, BitwiseOr, BitwiseXor, BitwiseAnd,
        Equals, LessGreater, BitwiseMovement, Sum, Product, Pow, Single, Suffix
    };
    std::shared_ptr<Token> _current, _prev;
    Lexer lexer;
    std::function<std::string()> _getNext;
    int stacking;
    std::string source;
    void parse_token();
public:
    Parser(const std::string code, const std::string src = "[stdin]", std::function<std::string()> getMext = noNext);
    std::shared_ptr<Node> parse_program();
private:
    std::shared_ptr<Node> parse_decorate();
    std::shared_ptr<Node> parse_statement();
    std::shared_ptr<Node> parse_scope();
    std::shared_ptr<Node> parse_expr();
    std::shared_ptr<Node> parse_expr_level(OperatorPriority pri);
    std::shared_ptr<Node> parse_if();
    std::shared_ptr<Node> parse_for();
    std::shared_ptr<Node> parse_while();
    std::shared_ptr<Node> parse_function();
    std::shared_ptr<Node> parse_function_creation();
    std::shared_ptr<Node> parse_enumerate_creation();
    std::shared_ptr<Node> parse_creation();
    std::shared_ptr<Node> parse_number();
    std::shared_ptr<Node> parse_string();
    std::shared_ptr<Node> parse_boolean();
    std::shared_ptr<Node> parse_array();
    std::shared_ptr<Node> parse_return();
    std::shared_ptr<Node> parse_infix(std::shared_ptr<Node> left);
    std::shared_ptr<Node> parse_prefix();
    std::shared_ptr<Node> parse_remove();
    std::shared_ptr<Node> parse_assign(std::shared_ptr<Node> left);
    std::shared_ptr<Node> parse_ternary(std::shared_ptr<Node> cond);
    std::shared_ptr<Node> parse_group();
    std::shared_ptr<Node> parse_call(std::shared_ptr<Node> left);
    std::shared_ptr<Node> parse_index(std::shared_ptr<Node> left);
    std::shared_ptr<Node> parse_identifier();
    std::shared_ptr<Node> parse_in_decrement_before();
    std::shared_ptr<Node> parse_named_constant();
    std::shared_ptr<Node> parse_in_decrement_after(std::shared_ptr<Node> left);
    std::shared_ptr<Node> parse_break_continue();
private:
    static const std::map<Token::Type, OperatorPriority> priorityTable;
    bool pricmp(OperatorPriority a, OperatorPriority b);
    OperatorPriority getpri(Token::Type type);
    std::shared_ptr<Node> lookupIn(Token::Type type, std::shared_ptr<Node> left);
    std::shared_ptr<Node> lookupPre(Token::Type type);

    bool shouldEnd();
};