#pragma once

namespace Conf {
constexpr unsigned char 
    ENCRYPTED = 64,
    COMPRESSED = 32,
    ROOTDIR = 16,
    SYMLINK = 8,
    PATH = 4,
    SCRIPT = 2,
    NETWORK = 1;
}

const int SALT_SIZE = 16;
const int IV_SIZE = 16;
const int KEY_SIZE = 16;
const int PBKDF2_ITERATIONS = 100000;