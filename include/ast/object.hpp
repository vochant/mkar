#pragma once

#include "ast/base/node.hpp"
#include "object/object.hpp"

class ObjectNode : public Node {
public:
    std::shared_ptr<Object> obj;
    ObjectNode(std::shared_ptr<Object> obj);
};