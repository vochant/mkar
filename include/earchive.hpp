#pragma once

#include <vector>
#include <filesystem>
#include <map>
#include <fstream>
#include <queue>
#include <functional>

class EArchive {
private:
    unsigned int fileCount;
    size_t prevSize;
    std::vector<std::string> fileNames;
    std::vector<size_t> fileOffsets;
    std::vector<std::vector<unsigned int>> subs;
    std::map<std::string, unsigned char> props;
    std::map<unsigned int, std::string> keys;
    std::map<std::string, unsigned int> enckix;
    std::map<std::string, unsigned int> execpri;
    std::map<std::string, unsigned int> pth2fsid;
    std::ofstream os;
    bool good;
    std::queue<std::filesystem::path> routines;
    unsigned char maskProp;
private:
    std::pair<size_t, unsigned char*> compress_data(const unsigned char* in, size_t len);
    std::pair<size_t, unsigned char*> encrypt_data(const unsigned char* in, size_t len, unsigned int key);
public:
    void AddPath(std::filesystem::path path, unsigned int fsid);
    void AddProp(std::filesystem::path path, unsigned char prop);
    void MaskProp(unsigned char prop);
    bool isGood();
    void FSTable();
    void RunRoutines();
    void SetKey(unsigned int key, std::string val);
    void SetKix(std::filesystem::path path, unsigned int kix);
    void SetExecPri(std::filesystem::path path, unsigned int pri);
    void AddRoutine(std::filesystem::path path, bool isRoot = true);
    EArchive(std::string out);
    ~EArchive();
};