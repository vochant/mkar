#include "mask.hpp"
#include "random_src.hpp"

std::random_device gRD;
std::mt19937 gRnd(gRD());

void BitOutput::write(unsigned short adata, unsigned char len) {
    while (len + bufferLength >= 8) {
        unsigned char freeLength = 8 - bufferLength;
        unsigned short mask = (((1 << freeLength) - 1) << (len - freeLength));
        data |= ((adata & mask) >> (len - freeLength));
        os.write((const char*) &data, 1);
        data = 0;
        bufferLength = 0;
        len -= freeLength;
    }
    if (len) {
        unsigned char freeLength = 8 - bufferLength;
        unsigned short mask = (1 << len) - 1;
        data |= ((adata & mask) << (freeLength - len));
        bufferLength += len;
    }
}

BitOutput::BitOutput(std::ofstream& os) : os(os), data(0), bufferLength(0) {}

BitOutput::~BitOutput() {
    if (bufferLength) os.write((const char*) &data, 1);
}

unsigned short BitInput::read(unsigned char len) {
    unsigned short res = 0;
    if (len && !bufferLength) {
        is.read((char*) &data, 1);
        bufferLength = 8;
    }
    while (len && bufferLength <= len) {
        unsigned short mask = (1 << bufferLength) - 1;
        res <<= bufferLength;
        res |= (data & mask);
        len -= bufferLength;
        if (len) {
            is.read((char*) &data, 1);
            bufferLength = 8;
        }
        else bufferLength = 0;
    }
    if (len) {
        unsigned short mask = (((1 << len) - 1) << (bufferLength - len));
        res <<= len;
        res |= ((data & mask) >> (bufferLength - len));
        bufferLength -= len;
    }
    return res;
}

BitInput::BitInput(std::ifstream& is) : is(is), data(0), bufferLength(0) {}

void TreapNode::update() {
    siz = 1 + (ls ? ls->siz : 0) + (rs ? rs->siz : 0);
}

TreapNode::TreapNode(unsigned char val) : val(val), pri(gRnd()), siz(1), ls(nullptr), rs(nullptr) {}

unsigned int MaskTreap::get_size(TreapNode* u) {
    return u ? u->siz : 0;
}

std::pair<TreapNode*, TreapNode*> MaskTreap::split(TreapNode* u, unsigned int rank) {
    if (rank == 0) return {nullptr, u};
    if (rank == u->siz) return {u, nullptr};
    if (rank <= get_size(u->ls)) {
        auto[a, b] = split(u->ls, rank);
        u->ls = b;
        u->update();
        return {a, u};
    }
    else {
        auto[a, b] = split(u->rs, rank - get_size(u->ls) - 1);
        u->rs = a;
        u->update();
        return {u, b};
    }
}

TreapNode* MaskTreap::merge(TreapNode* l, TreapNode* r) {
    if (!l && !r) return nullptr;
    if (!l) return r;
    if (!r) return l;
    if (l->pri > r->pri) {
        l->rs = merge(l->rs, r);
        l->update();
        return l;
    }
    else {
        r->ls = merge(l, r->ls);
        r->update();
        return r;
    }
}

unsigned char MaskTreap::access_and_delete(unsigned int rank) {
    auto[a, bc] = split(root, rank);
    auto[b, c] = split(bc, 1);
    root = merge(a, c);
    unsigned char res = b->val;
    delete b;
    return res;
}

MaskTreap::MaskTreap() {
    root = nullptr;
    for (unsigned short i = 0; i < 256; i++) {
        root = merge(root, new TreapNode(i));
    }
}

void Mask::write(BitOutput& os) {
    MaskTreap treap;
    unsigned char limit = 128, len = 8;
    for (unsigned char i = 0, ci = 0; i < 255; i++, ci++) {
        unsigned short ord = gRD() % (256 - i);
        unsigned char ch = treap.access_and_delete(ord);
        mapping[i] = ch;
        rmapping[ch] = i;
        if (ci == limit) {
            len--;
            ci = 0;
            limit >>= 1;
        }
        os.write(ord, len);
    }
    mapping[255] = treap.access_and_delete(0);
    rmapping[mapping[255]] = 255;
}

void Mask::read(BitInput& is) {
    MaskTreap treap;
    unsigned char limit = 128, len = 8;
    for (unsigned char i = 0, ci = 0; i < 255; i++, ci++) {
        if (ci == limit) {
            len--;
            ci = 0;
            limit >>= 1;
        }
        unsigned short ord = is.read(len);
        unsigned char ch = treap.access_and_delete(ord);
        mapping[i] = ch;
        rmapping[ch] = i;
    }
    mapping[255] = treap.access_and_delete(0);
    rmapping[mapping[255]] = 255;
}

void Mask::mask(void* buf, size_t len) {
    unsigned char* buffer = (unsigned char*) buf;
    for (long long i = 1; i < len; i++) buffer[i] += buffer[i - 1];
    for (long long i = 0; i < len; i++) buffer[i] = mapping[buffer[i]];
    for (long long i = 1; i < len; i++) buffer[i] ^= buffer[i - 1];
    for (long long i = len - 1; i > 0; i--) {
        long long lb = ((i + 1) & -(i + 1));
        if (lb != i + 1) buffer[i] ^= buffer[i - lb];
    }
}

void Mask::unmask(void* buf, size_t len) {
    unsigned char* buffer = (unsigned char*) buf;
    for (long long i = 1; i < len; i++) {
        long long lb = ((i + 1) & -(i + 1));
        if (lb != i + 1) buffer[i] ^= buffer[i - lb];
    }
    for (long long i = len - 1; i > 0; i--) buffer[i] ^= buffer[i - 1];
    for (long long i = 0; i < len; i++) buffer[i] = rmapping[buffer[i]];
    for (long long i = len - 1; i > 0; i--) buffer[i] -= buffer[i - 1];
}