//
// Created by Aubin Birba on 2023-10-23.
//

#include "BloomFilter.h"

using namespace std;

BloomFilter::BloomFilter(int expectedInsertions) {
    this->expectedInsertions = expectedInsertions;
    this->size = this->expectedInsertions * 2 / log(2) ;
    this->bloomFilter = vector<int>(size, 0);
}

void BloomFilter::add(int element) {

    int address256 = this->sha256(element);
    int address384 = this->sha384(element);

    this->bloomFilter.at(address256) = 1;
    this->bloomFilter.at(address384) = 1;

}

bool BloomFilter::contains(int element) {
    return this->bloomFilter[element] == 1;
}

void BloomFilter::print() {
    std::cout << "[Bloom filter(" << this->size << ")]: <";
    for (int i=0; i<this->size; i++)
    {
        std::cout << this->bloomFilter[i] << " ";
    }
    std::cout <<">" << std::endl;
}

//hash an integer using SHA-256
int BloomFilter::sha256(int element) {
    // Hash a string using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &element, sizeof(element));
    SHA256_Final(hash, &sha256);

    uint32_t n = 0;
    for (int i = 0; i < 4; i++) {
        n = (n << 8) | hash[i];
    }

    return n % this->size;
}

int BloomFilter::sha384(int element) {
    // Hash a string using SHA-512
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, &element, sizeof(element));
    SHA384_Final(hash, &sha384);

    uint32_t n = 0;
    for (int i = 0; i < 4; i++) {
        n = (n << 8) | hash[i];
    }

    return n % this->size;
}



std::vector<int> BloomFilter::getContents(){
    return this->bloomFilter;
}

