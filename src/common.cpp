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

class SplitMix64 {
private:
    unsigned long long state;
public:
    explicit SplitMix64(unsigned long long seed) : state(seed) {}
    unsigned long long next() {
        unsigned long long z = (state += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
};

class Xoshiro256pp {
private:
    unsigned long long s[4];

    static inline unsigned long long rotl(const unsigned long long x, int k) {
        return (x << k) | (x >> (64 - k));
    }

public:
    explicit Xoshiro256pp(unsigned long long seed) {
        SplitMix64 sm64(seed);
        for (int i = 0; i < 4; i++) {
            s[i] = sm64.next();
        }
    }

    unsigned long long next() {
        const unsigned long long result = rotl(s[0] + s[3], 23) + s[0];

        const unsigned long long t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;

        s[3] = rotl(s[3], 45);

        return result;
    }
};

class Xoshiro256ppByteStream {
private:
    Xoshiro256pp rng;
    unsigned char buffer[8];
    int buffer_index;

    void refill_buffer() {
        unsigned long long val = rng.next();
        for (int i = 0; i < 8; ++i) {
            buffer[i] = ((val >> (56 - 8 * i)) & 0xFF);
        }
        buffer_index = 0;
    }

public:
    explicit Xoshiro256ppByteStream(unsigned long long seed) : rng(seed), buffer_index(8) {}

    unsigned char next_byte() {
        if (buffer_index >= 8) {
            refill_buffer();
        }
        return buffer[buffer_index++];
    }
};

void Mask::write(BitOutput& os) {
    version = 2;
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
    version = 0;
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
    if (version < 2) {
        for (long long i = 1; i < len; i++) buffer[i] += buffer[i - 1];
        for (long long i = 0; i < len; i++) buffer[i] = mapping[buffer[i]];
    }
    if (version == 1) {
        unsigned short e = 1;
        for (long long i = 0; i < len; i++) {
            buffer[i] += e;
            e = ((e * 101) & 255);
        }
    }
    else if (version == 2) {
        unsigned long long seed = 0;
        for (int i = 0; i <= 7; i++) {
            seed |= (((unsigned long long) mapping[i << 2]) << (i << 3));
        }
        Xoshiro256ppByteStream bs(seed);
        for (long long i = 0; i < len; i++) {
            buffer[i] += bs.next_byte();
        }
    }
    if (version >= 2) {
        unsigned char acc = 10;
        for (int i = 0; i < len; i++) {
            buffer[i] = mapping[(buffer[i] + acc) & 0xFF];
            acc ^= buffer[i];
        }
        for (long long i = 0; i < len; i++) buffer[i] = mapping[buffer[i]];
    }
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
    if (version >= 2) {
        for (long long i = 0; i < len; i++) buffer[i] = rmapping[buffer[i]];
        unsigned char acc = 10;
        for (int i = 0; i < len; i++) {
            unsigned char y = buffer[i];
            unsigned char x = (rmapping[buffer[i]] - acc) & 0xFF;
            buffer[i] = x;
            acc ^= y;
        }
    }
    if (version == 1) {
        unsigned short e = 1;
        for (long long i = 0; i < len; i++) {
            buffer[i] -= e;
            e = ((e * 101) & 255);
        }
    }
    else if (version == 2) {
        unsigned long long seed = 0;
        for (int i = 0; i <= 7; i++) {
            seed |= (((unsigned long long) mapping[i << 2]) << (i << 3));
        }
        Xoshiro256ppByteStream bs(seed);
        for (long long i = 0; i < len; i++) {
            buffer[i] -= bs.next_byte();
        }
    }
    if (version < 2) {
        for (long long i = 0; i < len; i++) buffer[i] = rmapping[buffer[i]];
        for (long long i = len - 1; i > 0; i--) buffer[i] -= buffer[i - 1];
    }
}

void Mask::versionId(int version) {
    this->version = version;
}