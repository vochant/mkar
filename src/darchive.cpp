#include "darchive.hpp"
#include "conf.hpp"
#include "mask.hpp"
#include "mpcc_script.hpp"
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
#include <curl/curl.h>
#include <cstring>
#include <iostream>
#include <stdlib.h>

#ifdef _WIN32
# include <windows.h>
# include <winhttp.h>
# pragma comment(lib, "winhttp.lib")
#endif

char* proxy_string = NULL;
bool proxy_detected = false;

char* get_system_proxy_for_curl() {
    if (proxy_detected) return proxy_string;
    proxy_detected = true;

    const char* env_proxy = getenv("http_proxy");
    if (!env_proxy) {
        env_proxy = getenv("https_proxy");
    }

    if (env_proxy) {
        proxy_string = _strdup(env_proxy);
        if (proxy_string) {
            if (proxy_string) printf("Detected http_proxy: %s\n", proxy_string);
            return proxy_string;
        } else {
            return NULL;
        }
    }

#ifdef _WIN32
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieProxyConfig;
    ZeroMemory(&ieProxyConfig, sizeof(ieProxyConfig));

    if (WinHttpGetIEProxyConfigForCurrentUser(&ieProxyConfig)) {
        if (ieProxyConfig.lpszProxy) {
            int buffer_len = WideCharToMultiByte(CP_UTF8, 0, ieProxyConfig.lpszProxy, -1, NULL, 0, NULL, NULL);
            if (buffer_len > 0) {
                proxy_string = (char*)malloc(buffer_len);
                if (proxy_string) {
                    WideCharToMultiByte(CP_UTF8, 0, ieProxyConfig.lpszProxy, -1, proxy_string, buffer_len, NULL, NULL);
                    printf("Detected IE Proxy: %s\n", proxy_string);
                }
            }
        }
        if (ieProxyConfig.lpszAutoConfigUrl) GlobalFree(ieProxyConfig.lpszAutoConfigUrl);
        if (ieProxyConfig.lpszProxy) GlobalFree(ieProxyConfig.lpszProxy);
        if (ieProxyConfig.lpszProxyBypass) GlobalFree(ieProxyConfig.lpszProxyBypass);
    } else {
        WINHTTP_PROXY_INFO proxyInfo;
        ZeroMemory(&proxyInfo, sizeof(proxyInfo));
        if (WinHttpGetDefaultProxyConfiguration(&proxyInfo)) {
            if (proxyInfo.lpszProxy) {
                int buffer_len = WideCharToMultiByte(CP_UTF8, 0, proxyInfo.lpszProxy, -1, NULL, 0, NULL, NULL);
                if (buffer_len > 0) {
                    proxy_string = (char*)malloc(buffer_len);
                    if (proxy_string) {
                        WideCharToMultiByte(CP_UTF8, 0, proxyInfo.lpszProxy, -1, proxy_string, buffer_len, NULL, NULL);
                        printf("Detected WinHTTP Proxy: %s\n", proxy_string);
                    }
                }
            }
            if (proxyInfo.lpszProxy) GlobalFree(proxyInfo.lpszProxy);
            if (proxyInfo.lpszProxyBypass) GlobalFree(proxyInfo.lpszProxyBypass);
        }
    }
#endif

    return proxy_string;
}


std::pair<size_t, unsigned char*> DArchive::decompress_data(const unsigned char* in, size_t len) {
    size_t decompressBound = ZSTD_getFrameContentSize(in, len);
    if (decompressBound == ZSTD_CONTENTSIZE_ERROR) {
        return {0, nullptr};
    }
    unsigned char* out = new unsigned char[decompressBound];

    size_t actualSize = ZSTD_decompress(out, decompressBound, in, len);
    if (ZSTD_isError(actualSize)) {
        delete[] out;
        return {0, nullptr};
    }

    return {actualSize, out};
}

using namespace CryptoPP;

std::pair<size_t, unsigned char*> DArchive::decrypt_data(const unsigned char* in, size_t len) {
    const byte* salt = in + 4;
    const byte* iv = in + SALT_SIZE + 4;
    const byte* cipherData = in + SALT_SIZE + IV_SIZE + 4;
    size_t cipherLen = len - SALT_SIZE - IV_SIZE - 4;

    unsigned int kix = 0;
    for (unsigned int i = 0; i < 4; i++) {
        kix |= ((unsigned int) in[i]) << (i << 3);
    }

    std::string password;

    if (keys.find(kix) != keys.end()) {
        password = keys[kix];
    }
    else {
        std::cout << "Password #" << kix <<": ";
        std::cin >> password;
        keys.insert({kix, password});
    }

    SecByteBlock key(KEY_SIZE);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(
        key, key.size(),
        0,
        (const byte*) password.data(), password.size(),
        salt, SALT_SIZE,
        PBKDF2_ITERATIONS
    );

    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    std::string recovered;
    StringSource ss(cipherData, cipherLen, true,
        new StreamTransformationFilter(dec,
            new StringSink(recovered)
        )
    );

    size_t dataSize = recovered.size();
    unsigned char* out = new unsigned char[dataSize];
    std::memcpy(out, recovered.data(), dataSize);

    return {dataSize, out};
}

size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    std::ofstream& out = *reinterpret_cast<std::ofstream*>(stream);
    out.write((char*)ptr, size * nmemb);
    return size * nmemb;
}

bool DArchive::download(std::string url, std::filesystem::path save) {
    if (!curlState) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Download file failed: Unable to initialize CURL.\n";
        return false;
    }

    std::ofstream out(save, std::ios::binary);
    if (!out) {
        std::cerr << "Download file failed: Unable to open the output file.\n";
        return false;
    }

    char* _p = get_system_proxy_for_curl();
    curl_easy_setopt(curl, CURLOPT_PROXY, _p);
    if (!curlState && _p) printf("Using proxy server: %s\n", _p);

    if (!curlState) curlState = true;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    out.close();

    if (res != CURLE_OK) {
        std::cerr << "Download file failed: Download failed.\n";
        std::filesystem::remove(save);
        return false;
    }

    return true;
}

std::pair<size_t, unsigned char*> DArchive::extractData(unsigned int fsid, unsigned char& prop) {
    if (fsid >= fileCount) {
        good = false;
        std::cerr << "FSID is out of the range.\n";
        return {0, nullptr};
    }

    is.seekg(fileOffsets[fsid], std::ios::beg);
    
    BitInput ib(is);
    prop = ib.read(7);
    Mask mask;
    mask.read(ib);

    size_t size = fileSizes[fsid];

    unsigned char* data = new unsigned char[size];
    is.read((char*) data, size);
    if (arcVersion == 1) mask.v2();
    mask.unmask(data, size);
    if (arcVersion == 1) {
        mask.unmask(data, size);
        mask.unmask(data, size);
    }

    if (prop & Conf::ENCRYPTED) {
        auto[nsize, ndata] = decrypt_data(data, size);
        delete[] data;
        if (ndata == nullptr) {
            good = false;
            return {0, nullptr};
        }
        data = ndata;
        size = nsize;
    }

    if (prop & Conf::COMPRESSED) {
        auto[nsize, ndata] = decompress_data(data, size);
        delete[] data;
        if (ndata == nullptr) {
            good = false;
            return {0, nullptr};
        }
        data = ndata;
        size = nsize;
    }

    return {size, data};
}

bool DArchive::isGood() { return good; }

void DArchive::FSTable() {
    is.seekg(fstOffset);
    while (true) {
        unsigned short fnSize = 0;
        unsigned long long fileOffset = 0;
        unsigned char tmp = 0;
        for (unsigned int i = 0; i < 2; i++) {
            is.read((char*) &tmp, 1);
            fnSize |= (((unsigned short) tmp) << (i << 3));
        }
        if (fnSize == 0x8000) break;
        char* fn = new char[fnSize];
        is.read(fn, fnSize);
        fileNames.push_back(std::string(fn, fnSize));
        for (unsigned int i = 0; i < 8; i++) {
            is.read((char*) &tmp, 1);
            fileOffset |= (((unsigned long long) tmp) << (i << 3));
        }
        fileOffsets.push_back(fileOffset);
        fileCount++;
    }
    fileOffsets.push_back(fstOffset);

    for (unsigned int i = 0; i < fileCount; i++) {
        fileSizes.push_back(fileOffsets[i + 1] - fileOffsets[i] - 225);
    }

    std::cout << "Got " << fileCount << " files.\n";
}

void DArchive::TestRootdir() {
    for (unsigned int i = 0; i < fileCount; i++) {
        is.seekg(fileOffsets[i], std::ios::beg);
        unsigned char prop;
        is.read((char*) &prop, 1);
        prop >>= 1;
        if (prop & Conf::ROOTDIR) {
            rootdir.push_back(i);
        }
    }
}

std::vector<std::string> extract_segments(const std::filesystem::path& raw_path) {
    std::vector<std::string> segments;

    auto normalized = raw_path.lexically_normal();

    for (const auto& part : normalized) {
        if (part != "/" && part != "\\" && part != "" && !part.has_root_name() && !part.has_root_directory()) {
            segments.push_back(part.u8string());
        }
    }

    return segments;
}

void DArchive::Extract(unsigned int fsid, std::filesystem::path path) {
    unsigned char prop;
    auto[size, data] = extractData(fsid, prop);
    if (!good) return;
    std::error_code ec;

    if (prop & Conf::SYMLINK) {
        unsigned int nfsid = 0;
        if (size != 4) {
            good = false;
            delete[] data;
            return;
        }
        for (unsigned int i = 0; i < 4; i++) {
            nfsid |= (((unsigned int) data[i]) << (i << 3));
        }
        Extract(nfsid, path);
        delete[] data;
        return;
    }

    if (prop & Conf::PATH) {
        std::cout << "Create   " << path.lexically_normal().generic_u8string() << '\n';
        std::filesystem::create_directory(path, ec);
        if (ec) {
            good = false;
            delete[] data;
            return;
        }
        unsigned int count = 0, nfsid;
        for (unsigned int i = 0; i < 4; i++) {
            count |= (((unsigned int) data[i]) << (i << 3));
        }
        for (unsigned int i = 0; i < count; i++) {
            nfsid = 0;
            for (unsigned int j = 0; j < 4; j++) {
                nfsid |= (((unsigned int) data[(i + 1) * 4 + j]) << (j << 3));
            }
            if (nfsid >= fileCount) {
                good = false;
                delete[] data;
                return;
            }
            Extract(nfsid, path / std::filesystem::u8path(fileNames[nfsid]));
            if (!good) {
                delete[] data;
                return;
            }
        }
        delete[] data;
        return;
    }

    if (prop & Conf::SCRIPT) {
        if (safeMode) {
            data += 4;
            size -= 4;
        }
        else {
            unsigned int pri;
            for (unsigned int i = 0; i < 4; i++) {
                pri |= (((unsigned int) data[i]) << (i << 3));
            }
            std::string script((char*) (data + 4), size - 4);
            if (pri == 0) {
                std::cout << "Execute  " << path.lexically_normal().generic_u8string() << '\n';
                RunPostScript(script, path.lexically_normal().generic_u8string());
            }
            else tasks.push_back({pri, script, path.lexically_normal().generic_u8string()});
            delete[] data;
            return;
        }
    }

    if ((prop & Conf::NETWORK) && !safeMode) {
        while (isspace(data[size - 1])) size--;
        std::string url((char*) data, size);
        delete[] data;
        std::cout << "Download " << path.lexically_normal().generic_u8string() << " (" << url << ")\n";
        if (!download(url, path)) {
            std::cerr << "Leaving the URL...\n";
            std::ofstream os(path, std::ios::binary);
            os.write(url.data(), url.size());
            os.close();
        }
        return;
    }

    std::cout << "Extract  " << path.lexically_normal().generic_u8string() << '\n';
    std::ofstream os(path, std::ios::binary);
    os.write((char*) data, size);
    os.close();

    delete[] data;
}

unsigned int DArchive::DumpFSID(std::filesystem::path path) {
    auto split = extract_segments(path);
    if (split.size() == 0) return 0xffffffff;
    
    unsigned int fsid = 0;
    bool found = false;

    for (auto x : rootdir) {
        if (fileNames[x] == split[0]) {
            fsid = x;
            found = true;
            break;
        }
    }

    if (!found) return 0xffffffff;

    for (unsigned int k = 1; k < split.size(); k++) {
        found = false;
        unsigned char prop;
        auto [size, data] = extractData(fsid, prop);
        if (!good) return 0xffffffff;
        while (prop & Conf::SYMLINK) {
            unsigned int nfsid = 0;
            if (size != 4) {
                delete[] data;
                return 0xffffffff;
            }
            for (unsigned int i = 0; i < 4; i++) {
                nfsid |= (((unsigned int) data[i]) << (i << 3));
            }
            delete[] data;
            auto[nsize, ndata] = extractData(nfsid, prop);
            if (!good) return 0xffffffff;
            size = nsize;
            data = ndata;
        }
        if (!(prop & Conf::PATH)) {
            delete[] data;
            return 0xffffffff;
        }
        unsigned int count = 0, nfsid;
        for (unsigned int i = 0; i < 4; i++) {
            count |= (((unsigned int) data[i]) << (i << 3));
        }
        for (unsigned int i = 0; i < count; i++) {
            nfsid = 0;
            for (unsigned int j = 0; j < 4; j++) {
                nfsid |= (((unsigned int) data[(i + 1) * 4 + j]) << (j << 3));
            }
            if (nfsid >= fileCount) {
                delete[] data;
                return 0xffffffff;
            }
            if (fileNames[nfsid] == split[k]) {
                fsid = nfsid;
                found = true;
                break;
            }
        }
        delete[] data;
        if (!found) return 0xffffffff;
    }
    return fsid;
}

void DArchive::SetKey(unsigned int key, std::string val) {
    if (keys.find(key) != keys.end()) {
        good = false;
        return;
    }
    keys.insert({key, val});
}

void DArchive::PostExtract() {
    sort(tasks.begin(), tasks.end(), [](std::tuple<unsigned int, std::string, std::string> a, std::tuple<unsigned int, std::string, std::string> b) {
        return std::get<0>(a) > std::get<0>(b);
    });
    for (auto[pri, src, title] : tasks) {
        std::cout << "Execute  " << src << '\n';
        RunPostScript(src, title);
    }
}

void DArchive::ExtractAll() {
    for (auto x : rootdir) {
        Extract(x, std::filesystem::u8path(fileNames[x]));
        if (!good) return;
    }
}

void DArchive::Safe() { safeMode = true; }

void DArchive::AddRoutine(unsigned int fsid, std::filesystem::path path) {
    routines.push({fsid, path});
}

void DArchive::RunRoutines() {
    while (!routines.empty()) {
        auto[fsid, path] = routines.front();
        routines.pop();
        Extract(fsid, path);
    }
}

bool DArchive::isDirectory(unsigned int fsid) {
    if (fsid >= fileCount) return false;
    unsigned char prop;
    auto [size, data] = extractData(fsid, prop);
    if (!good) return false;
    while (prop & Conf::SYMLINK) {
        unsigned int nfsid = 0;
        if (size != 4) {
            delete[] data;
            return false;
        }
        for (unsigned int i = 0; i < 4; i++) {
            nfsid |= (((unsigned int) data[i]) << (i << 3));
        }
        delete[] data;
        if (nfsid >= fileCount) return false;
        auto[nsize, ndata] = extractData(nfsid, prop);
        if (!good) return false;
        size = nsize;
        data = ndata;
    }
    delete[] data;
    return prop & Conf::PATH;
}

bool DArchive::isSymlink(unsigned int fsid) {
    if (fsid >= fileCount) return false;
    is.seekg(fileOffsets[fsid], std::ios::beg);
    
    BitInput ib(is);
    unsigned char prop = ib.read(7);

    return prop & Conf::SYMLINK;
}

std::vector<unsigned int> DArchive::listDirectory(int fsid) {
    if (fsid < 0 || fsid >= fileCount) return rootdir;

    unsigned char prop;
    auto [size, data] = extractData(fsid, prop);
    if (!good) return {};
    while (prop & Conf::SYMLINK) {
        int nfsid = 0;
        if (size != 4) {
            delete[] data;
            return {};
        }
        for (unsigned int i = 0; i < 4; i++) {
            nfsid |= (((int) data[i]) << (i << 3));
        }
        delete[] data;
        if (nfsid >= fileCount) return {};
        auto[nsize, ndata] = extractData(nfsid, prop);
        if (!good) return {};
        size = nsize;
        data = ndata;
    }
    if (prop & Conf::PATH) {
        std::vector<unsigned int> res;
        unsigned int count = 0, nfsid;
        for (unsigned int i = 0; i < 4; i++) {
            count |= (((unsigned int) data[i]) << (i << 3));
        }
        for (unsigned int i = 0; i < count; i++) {
            nfsid = 0;
            for (unsigned int j = 0; j < 4; j++) {
                nfsid |= (((unsigned int) data[(i + 1) * 4 + j]) << (j << 3));
            }
            if (nfsid < fileCount) res.push_back(nfsid);
        }
        delete[] data;
        return res;
    }
    else {
        delete[] data;
        return {};
    }
}

std::string DArchive::getName(unsigned int fsid) {
    if (fsid >= fileCount) return "**undefined**";
    return fileNames[fsid];
}

unsigned int DArchive::FSCount() { return fileCount; }

DArchive::DArchive(std::string name) {
    curlState = false;
    good = true;
    fileCount = 0;
    safeMode = false;
    is.open(name, std::ios::binary);
    unsigned char header[16];
    is.read((char*) header, 16);
    if (std::string((char*) header, 4) != "MKAR") {
        good = false;
        std::cerr << "Bad magic number.\n";
        return;
    }
    unsigned short impl = (((unsigned short) header[5]) << 8) | header[4];
    unsigned short ver = (((unsigned short) header[7]) << 8) | header[6];
    std::cout << "Implementation: " << impl << "\nStandard Version: " << ver << '\n';
    arcVersion = ver;
    if (impl != 0x2009) {
        good = false;
        std::cerr << "Incompatible implementation.\n";
        return;
    }
    if (ver > 1) {
        good = false;
        std::cerr << "Incompatible standard version.\n";
        return;
    }

    fstOffset = 0;
    for (int i = 0; i < 8; i++) {
        fstOffset |= (((unsigned long long) header[i + 8]) << (i << 3));
    }

    std::cout << "Offset: " << fstOffset << '\n';
}

DArchive::~DArchive() {
    if (curlState) curl_global_cleanup();
    is.close();
}