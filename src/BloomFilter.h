//
// Created by Aubin Birba on 2023-10-23.
//

#ifndef FHE_CRYPTOGRAPH_BLOOMFILTER_H
#define FHE_CRYPTOGRAPH_BLOOMFILTER_H

#include <vector>
#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <cmath>


class BloomFilter {

private:
    std::vector<int> bloomFilter;
    int size;
    int expectedInsertions;


public:
        BloomFilter(int expectedInsertions);
        void add(int element);
        bool contains(int element);
        void print();
        std::vector<int> getContents();
        int sha256(int element);
        int sha384(int element);


};


#endif //FHE_CRYPTOGRAPH_BLOOMFILTER_H
