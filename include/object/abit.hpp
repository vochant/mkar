#pragma once

#include "object/iterator.hpp"

class ArrayBasedIterator : public Iterator {
public:
    std::shared_ptr<Array> baseArr;
    size_t ptr;
    bool hasNext() override;
    std::shared_ptr<Object> next() override;
    void go() override;
    std::shared_ptr<Object> make_copy() override;
public:
    ArrayBasedIterator(std::shared_ptr<Array> baseArr);
};