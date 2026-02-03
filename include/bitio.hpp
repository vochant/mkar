#pragma once

#include <fstream>

class BitOutput {
private:
    std::ofstream& os;
    unsigned char data;
    unsigned char bufferLength;
public:
    void write(unsigned short adata, unsigned char len);
    BitOutput(std::ofstream& os);
    ~BitOutput();
};

class BitInput {
private:
    std::ifstream& is;
    unsigned char data;
    unsigned char bufferLength;
public:
    unsigned short read(unsigned char len);
    BitInput(std::ifstream& is);
};