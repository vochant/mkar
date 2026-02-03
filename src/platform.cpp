#include "platform.hpp"
#include <exception>

std::filesystem::path toPlatformPath(const std::filesystem::path& path) {
#ifdef _WIN32
    auto absPath = std::filesystem::absolute(path);
    std::wstring ws = absPath.native();
    if (ws.rfind(L"\\\\?\\", 0) == 0) {
        return absPath;
    }
    if (ws.rfind(L"\\\\", 0) == 0) {
        return std::filesystem::path(L"\\\\?\\UNC" + ws.substr(2));
    }
    return std::filesystem::path(L"\\\\?\\" + ws);
#else
    return path;
#endif
}