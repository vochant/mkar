#pragma once

#include <vector>
#include <filesystem>
#include <fstream>
#include <map>
#include <queue>
#include <functional>

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(LIB_EXPORTS)
        #define LIB_API __declspec(dllexport)
    #else
        #define LIB_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define LIB_API __attribute__((visibility("default")))
    #else
        #define LIB_API
    #endif
#endif

class DArchive {
private:
    unsigned int fileCount;
    unsigned long long fstOffset;
    std::vector<std::string> fileNames;
    std::vector<unsigned int> rootdir;
    std::vector<size_t> fileSizes;
    std::vector<size_t> fileOffsets;
    std::map<unsigned int, std::string> keys;
    std::vector<std::tuple<unsigned int, std::string, std::string>> tasks;
    std::ifstream is;
    bool good, safeMode, curlState;
    int arcVersion;
    std::queue<std::pair<unsigned int, std::filesystem::path>> routines;
private:
    std::pair<size_t, unsigned char*> decompress_data(const unsigned char* in, size_t len);
    std::pair<size_t, unsigned char*> decrypt_data(const unsigned char* in, size_t len);
    bool download(std::string url, std::filesystem::path save);
    std::pair<size_t, unsigned char*> extractData(unsigned int fsid, unsigned char& prop);
public:
    bool isGood();
    void FSTable();
    void TestRootdir();
    void Extract(unsigned int fsid, std::filesystem::path path);
    void ExtractAll();
    unsigned int DumpFSID(std::filesystem::path path);
    void SetKey(unsigned int key, std::string val);
    void PostExtract();
    void Safe();
    void AddRoutine(unsigned int fsid, std::filesystem::path path);
    void RunRoutines();
    bool isDirectory(unsigned int fsid);
    bool isSymlink(unsigned int fsid);
    std::vector<unsigned int> listDirectory(int fsid);
    std::string getName(unsigned int fsid);
    unsigned int FSCount();
    DArchive(std::string name);
    ~DArchive();
};

extern LIB_API DArchive* g_arch;
extern LIB_API std::function<bool(unsigned int)> onMissingPassword, onIncorrectPassword;

#undef LIB_API