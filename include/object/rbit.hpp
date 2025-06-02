#pragma once

#include "object/iterator.hpp"

class RangeBasedIterator : public Iterator {
public:
    long long e, s, c;
    bool hasNext() override;
    std::shared_ptr<Object> next() override;
    void go() override;
    std::shared_ptr<Object> make_copy() override;
public:
    RangeBasedIterator(long long b, long long e, long long s);
};