#include <iostream>

#ifdef _WIN32
# include <windows.h>
#endif

#include "mask.hpp"
#include "earchive.hpp"
#include "darchive.hpp"
#include "platform.hpp"
#include <cstring>
#include "conf.hpp"

int main(int argc, char* argv[]) {
    #ifdef _WIN32
    auto prevICP = GetConsoleCP(), prevOCP = GetConsoleOutputCP();
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
    #endif
   
    std::ios::sync_with_stdio(false);

    if (argc < 3) {
        std::cerr << "Wrong format!\n";
        return 1;
    }

    std::string archive = argv[1];
    std::string method = argv[2];

    bool hasEachE = false, hasAllE = false, hasEachC = false, hasAllC = false;
    
    try {
        if (method == "e") {
            EArchive earch(archive);
            for (int i = 3; i < argc; i++) {
                std::string str = argv[i];
                if (str == "-e") {
                    if (argc - i < 3 || hasAllE) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    try {
                        unsigned int kix = std::strtoul(argv[i + 2], nullptr, 0);
                        earch.SetKix(argv[i + 1], kix);
                        earch.AddProp(argv[i + 1], Conf::ENCRYPTED);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error while parsing KIX: " << e.what() << '\n';
                        return 1;
                    }
                    i += 2;
                    hasEachE = true;
                }
                else if (str == "-E") {
                    if (hasAllE || hasEachE) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.MaskProp(Conf::ENCRYPTED);
                    hasAllE = true;
                }
                else if (str == "-l") {
                    if (argc - i < 2) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.AddProp(argv[i + 1], Conf::SYMLINK);
                    i++;
                }
                else if (str == "-s") {
                    if (argc - i < 3) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    try {
                        unsigned int pri = std::strtoul(argv[i + 2], nullptr, 0);
                        earch.SetExecPri(argv[i + 1], pri);
                        earch.AddProp(argv[i + 1], Conf::SCRIPT);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error while parsing ExecPri: " << e.what() << '\n';
                        return 1;
                    } 
                    i += 2;
                }
                else if (str == "-n") {
                    if (argc - i < 2) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.AddProp(argv[i + 1], Conf::NETWORK);
                    i++;
                }
                else if (str == "-r1") {
                    if (argc - i < 2) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.AddProp(argv[i + 1], Conf::ROOTDIR);
                    i++;
                }
                else if (str == "-r0") {
                    if (argc - i < 2) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.AddRoutine(argv[i + 1], false);
                    i++;
                }
                else if (str == "-c") {
                    if (argc - i < 2 || hasAllC) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.AddProp(argv[i + 1], Conf::COMPRESSED);
                    i++;
                    hasEachC = true;
                }
                else if (str == "-C") {
                    if (hasEachC || hasAllC) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    earch.MaskProp(Conf::COMPRESSED);
                    hasAllC = true;
                }
                else if (str == "-p") {
                    if (argc - i < 3) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    try {
                        unsigned int kix = std::strtoul(argv[i + 1], nullptr, 0);
                        earch.SetKey(kix, argv[i + 2]);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error while parsing KEY: " << e.what() << '\n';
                        return 1;
                    }
                    i += 2;
                }
                else {
                    earch.AddRoutine(str);
                }
            }
            std::cerr << "[routine done]\n";
            earch.RunRoutines();
            earch.FSTable();
        }
        else if (method == "d") {
            DArchive darch(archive);
            onMissingPassword = [](unsigned int kix)->bool {
                std::cout << "Please enter the key for index " << kix << ":\n";
                std::string key;
                std::cin >> key;
                g_arch->SetKey(kix, key);
                return true;
            };
            onIncorrectPassword = [](unsigned int kix)->bool {
                std::cout << "The key for index " << kix << " is incorrect, please try again:\n";
                std::string key;
                std::cin >> key;
                g_arch->SetKey(kix, key);
                return true;
            };
            g_arch = &darch;
            darch.FSTable();
            darch.TestRootdir();
            bool hasMention = false;
            for (int i = 3; i < argc; i++) {
                if (std::string(argv[i]) == "-p") {
                    if (argc - i < 3) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    try {
                        unsigned int kix = std::strtoul(argv[i + 1], nullptr, 0);
                        darch.SetKey(kix, argv[i + 2]);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error while parsing KEY: " << e.what() << '\n';
                        return 1;
                    }
                    i += 2;
                }
                else if (std::string(argv[i]) == "-s") {
                    darch.Safe();
                }
                else {
                    hasMention = true;
                    if (argc - i < 2) {
                        std::cerr << "Wrong format!\n";
                        return 1;
                    }
                    unsigned int fsid;
                    if (argv[i][0] == ':') {
                        fsid = std::strtoul(argv[i] + 1, nullptr, 0);
                    }
                    else {
                        fsid = darch.DumpFSID(argv[i]);
                    }
                    darch.AddRoutine(fsid, argv[i + 1]);
                    i++;
                }
            }
            if (hasMention) darch.RunRoutines();
            else darch.ExtractAll();
            darch.PostExtract();
        }
        else {
            std::cerr << "Unknown operation type!\n";
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    #ifdef _WIN32
    SetConsoleCP(prevICP);
    SetConsoleOutputCP(prevOCP);
    #endif
	return 0;
}