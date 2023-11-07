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
    std::vector<int64_t> bloomFilter;
    int size;
    int64_t expectedInsertions;
    float probabilityOfFalsePositives;


public:
        BloomFilter(int64_t expectedInsertions, float probabilityOfFalsePositives);
        void add(int64_t element);
        void addMultiple(std::vector<int64_t> elements);
        bool contains(int64_t element);
        void print();
        std::vector<int64_t> getContents();
        int sha256(int64_t element);
        int sha384(int64_t element);
        int getSize();
        void clear();




};


#endif //FHE_CRYPTOGRAPH_BLOOMFILTER_H
