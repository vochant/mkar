#include "earchive.hpp"
#include "conf.hpp"
#include "mask.hpp"
#include "platform.hpp"
#include <zstd.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cstring>
#include <iostream>

class EArchiveException : public std::exception {
private:
    std::string desc;

public:
    EArchiveException(const std::string desc) : desc("EArchive: " + desc) {}

    const char* what() const noexcept {
        return desc.c_str();
    }
};

std::pair<size_t, unsigned char*> EArchive::compress_data(const unsigned char* in, size_t len) {
    size_t compressBound = ZSTD_compressBound(len);
    unsigned char* out = new unsigned char[compressBound];
    size_t compressedSize = ZSTD_compress(out, compressBound, in, len, 11);

    if (ZSTD_isError(compressedSize)) {
        delete[] out;
        throw EArchiveException("Compression failed: " + std::string(ZSTD_getErrorName(compressedSize)));
    }

    return {compressedSize, out};
}

using namespace CryptoPP;

std::pair<size_t, unsigned char*> EArchive::encrypt_data(const unsigned char* in, size_t len, unsigned int kix) {
    auto it = keys.find(kix);
    std::string password;
    if (it != keys.end()) {
        password = it->second;
    }
    else throw EArchiveException("Missing password for key index: " + std::to_string(kix));

    AutoSeededRandomPool rng;

    byte salt[SALT_SIZE];
    byte iv[IV_SIZE];
    rng.GenerateBlock(salt, sizeof(salt));
    rng.GenerateBlock(iv, sizeof(iv));

    SecByteBlock key(KEY_SIZE);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(
        key, key.size(),
        0,
        (byte*)password.data(), password.size(),
        salt, sizeof(salt),
        PBKDF2_ITERATIONS
    );

    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string cipher;
    StringSource ss(in, len, true,
        new StreamTransformationFilter(enc,
            new StringSink(cipher)
        )
    );

    size_t totalSize = SALT_SIZE + IV_SIZE + cipher.size();
    unsigned char* out = new unsigned char[totalSize + 4];

    for (size_t i = 0; i < 4; i++) {
        out[i] = (kix >> (i << 3)) & 0xff;
    }
    memcpy(out + 4, salt, SALT_SIZE);
    memcpy(out + 4 + SALT_SIZE, iv, IV_SIZE);
    memcpy(out + 4 + SALT_SIZE + IV_SIZE, cipher.data(), cipher.size());

    return {totalSize + 4, out};
}

void EArchive::AddPath(std::filesystem::path path, unsigned int fsid) {
    std::error_code ec;
    unsigned char prop = 0;
    auto it = props.find(path.lexically_normal().generic_u8string());
    if (it != props.end()) prop = it->second;
    prop |= maskProp;

    Mask mask;
    BitOutput ob(os);
    
    ob.write(prop, 7);
    mask.write(ob);

    unsigned char* content;
    size_t fsize;

    if (prop & Conf::PATH) {
        unsigned int subcount = subs[fsid].size();
        
        content = new unsigned char[(subcount + 1) * 4];
        for (size_t i = 0; i < 4; i++) {
            content[i] = (subcount >> (i << 3)) & 0xff;
        }
        for (unsigned int i = 0; i < subcount; i++) {
            for (size_t j = 0; j < 4; j++) {
                content[(i + 1) * 4 + j] = (subs[fsid][i] >> (j << 3)) & 0xff;
            }
        }
        fsize = (subcount + 1) * 4;
    }
    else {
        size_t size = std::filesystem::file_size(toPlatformPath(path), ec);
        if (ec) {
            good = false;
            return;
        }
        if (prop & Conf::SCRIPT) content = new unsigned char[size + 4];
        else content = new unsigned char[size];
        std::ifstream file(toPlatformPath(path), std::ios::binary);
        if (!file) {
            good = false;
            delete[] content;
            return;
        }
        if (!file.read((char*) (content + ((prop & Conf::SCRIPT) ? 4 : 0)), size)) {
            good = false;
            delete[] content;
            return;
        }
        fsize = size + ((prop & Conf::SCRIPT) ? 4 : 0);

        if (prop & Conf::SCRIPT) {
            auto it = execpri.find(path.lexically_normal().generic_u8string());
            if (it == execpri.end()) {
                good = false;
                delete[] content;
                return;
            }
            unsigned int pri = it->second;
            for (size_t j = 0; j < 4; j++) {
                content[j] = (pri >> (j << 3)) & 0xff;
            }
        }

        if (prop & Conf::SYMLINK) {
            std::string p((char*) content, fsize);
            std::filesystem::path pth(p);
            auto it = pth2fsid.find(pth.lexically_normal().generic_u8string());
            if (it == pth2fsid.end()) {
                delete[] content;
                throw EArchiveException("Symlink target not found: " + pth.lexically_normal().generic_u8string());
            }
            fsize = 4;
            delete[] content;
            content = new unsigned char[4];
            unsigned int fsid = it->second;
            for (size_t j = 0; j < 4; j++) {
                content[j] = (fsid >> (j << 3)) & 0xff;
            }
        }
    }

    if (prop & Conf::COMPRESSED) {
        auto[nfsize, ncontent] = compress_data(content, fsize);
        delete[] content;
        if (ncontent == nullptr) {
            good = false;
            return;
        }
        content = ncontent;
        fsize = nfsize;
    }

    if (prop & Conf::ENCRYPTED) {
        auto it = enckix.find(path.lexically_normal().generic_u8string());
        unsigned int kix;
        if (it == enckix.end()) kix = 0;
        else kix = it->second;
        auto[nfsize, ncontent] = encrypt_data(content, fsize, kix);
        delete[] content;
        if (ncontent == nullptr) {
            good = false;
            return;
        }
        content = ncontent;
        fsize = nfsize;
    }

    std::cout << "Add " << path.lexically_normal().generic_u8string() << '\n';
    mask.mask(content, fsize);
    mask.mask(content, fsize);
    mask.mask(content, fsize);
    os.write((const char*) content, fsize);

    fileNames.push_back((path.has_filename() ? path : path.parent_path()).filename().u8string());
    fileOffsets.push_back(prevSize);
    prevSize += 225 + fsize;

    delete[] content;
}

void EArchive::MaskProp(unsigned char prop) {
    maskProp |= prop;
}

void EArchive::AddProp(std::filesystem::path path, unsigned char prop) {
    auto it = props.find(path.lexically_normal().generic_u8string());
    if (it != props.end()) it->second |= prop;
    else props.insert({path.lexically_normal().generic_u8string(), prop});
}

bool EArchive::isGood() { return good; }

void EArchive::FSTable() {
    std::cout << "Added " << fileCount << " files\n";
    std::cout << "Creating the FS Table\n";
    for (unsigned int i = 0; i < fileCount; i++) {
        unsigned short fnsize = fileNames[i].length();
        for (size_t j = 0; j < 2; j++) {
            unsigned char ch = (fnsize >> (j << 3)) & 0xff;
            os.write((char*) &ch, 1);
        }
        os.write(fileNames[i].data(), fnsize);
        unsigned long long foffset = fileOffsets[i];
        for (size_t j = 0; j < 8; j++) {
            unsigned char ch = (foffset >> (j << 3)) & 0xff;
            os.write((char*) &ch, 1);
        }
    }
    unsigned short endTag = 0x8000;
    for (size_t i = 0; i < 2; i++) {
        unsigned char ch = (endTag >> (i << 3)) & 0xff;
        os.write((char*) &ch, 1);
    }

    os.seekp(8, std::ios::beg);
    unsigned long long fstOffset = prevSize;
    std::cout << "Offset: " << fstOffset << '\n';
    for (size_t j = 0; j < 8; j++) {
        unsigned char ch = (fstOffset >> (j << 3)) & 0xff;
        os.write((char*) &ch, 1);
    }
}

void EArchive::RunRoutines() {
    while (!routines.empty()) {
        auto pth = routines.front();
        routines.pop();
        AddPath(pth, pth2fsid[pth.lexically_normal().generic_u8string()]);
        if (!good) return;
    }
}

void EArchive::SetKey(unsigned int key, std::string val) {
    if (keys.find(key) != keys.end()) {
        good = false;
        return;
    }
    keys.insert({key, val});
}

void EArchive::SetKix(std::filesystem::path path, unsigned int kix) {
    auto pth = path.lexically_normal().generic_u8string();
    if (enckix.find(pth) != enckix.end()) {
        good = false;
        return;
    }
    enckix.insert({pth, kix});
}

void EArchive::SetExecPri(std::filesystem::path path, unsigned int pri) {
    auto pth = path.lexically_normal().generic_u8string();
    if (execpri.find(pth) != execpri.end()) {
        good = false;
        throw EArchiveException("Duplicate exec priority for: " + pth);
    }
    execpri.insert({pth, pri});
}

void EArchive::AddRoutine(std::filesystem::path path, bool isRoot) {
    routines.push(path);
    if (isRoot) AddProp(path, Conf::ROOTDIR);
    unsigned int selfId = fileCount++;
    subs.push_back({});

    if (pth2fsid.find(path.lexically_normal().generic_u8string()) != pth2fsid.end()) {
        good = false;
        throw EArchiveException("Duplicate path: " + path.lexically_normal().generic_u8string());
    }

    pth2fsid.insert({path.lexically_normal().generic_u8string(), selfId});

    std::error_code ec;
    if (std::filesystem::is_directory(toPlatformPath(path), ec)) {
        AddProp(path, Conf::PATH);
        auto dit = std::filesystem::directory_iterator(toPlatformPath(path), ec);
        if (ec) {
            good = false;
            throw EArchiveException("Cannot open directory: " + path.lexically_normal().generic_u8string());
        }
        for (const auto& entry : dit) {
            subs[selfId].push_back(fileCount);
            AddRoutine(entry.path(), false);
            if (!good) return;
        }
    }
    if (ec) {
        good = false;
        throw EArchiveException("Cannot test if " + toPlatformPath(path).u8string() + " is a directory");
    }
}

EArchive::EArchive(std::string out) {
    good = true;
    maskProp = 0;

    os.open(toPlatformPath(out), std::ios::binary);
    if (!os) {
        good = false;
        return;
    }

    static unsigned char headers[] = {
        'M', 'K', 'A', 'R',
        0x09, 0x20, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    os.write((char*) headers, 16);

    fileCount = 0;
    prevSize = 16;
}

EArchive::~EArchive() {
    if (os) os.close();
}