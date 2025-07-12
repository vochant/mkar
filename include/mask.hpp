#pragma once

#include "bitio.hpp"

#include <utility>

struct TreapNode {
    unsigned char val;
    unsigned int pri, siz;
    TreapNode *ls, *rs;

    void update();
    TreapNode(unsigned char val);
};

class MaskTreap {
private:
    TreapNode* root;

    unsigned int get_size(TreapNode* u);
    std::pair<TreapNode*, TreapNode*> split(TreapNode* u, unsigned int rank);
    TreapNode* merge(TreapNode* l, TreapNode* r);

public:
    unsigned char access_and_delete(unsigned int rank);
    MaskTreap();
};

class Mask {
public:
    unsigned char mapping[256], rmapping[256];
    int version;
public:
    void write(BitOutput& os);
    void versionId(int version);
    void read(BitInput& is);
    void mask(void* buf, size_t len);
    void unmask(void* buf, size_t len);
};