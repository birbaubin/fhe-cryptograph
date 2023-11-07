//
// Created by Aubin Birba on 2023-10-23.
//

#include "BloomFilter.h"

using namespace std;

BloomFilter::BloomFilter(int64_t expectedInsertions, float probabilityOfFalsePositives) {
    this->expectedInsertions = expectedInsertions;
    this->probabilityOfFalsePositives = probabilityOfFalsePositives;
    this->size = ceil((expectedInsertions * log(probabilityOfFalsePositives)) / log(1.0 / (pow(2.0, log(2.0)))));
    this->bloomFilter = vector<int64_t>(size, 0);
}

void BloomFilter::add(int64_t element) {

    int address256 = this->sha256(element);
    int address384 = this->sha384(element);

    this->bloomFilter.at(address256) = 1;
    this->bloomFilter.at(address384) = 1;

}

void BloomFilter::addMultiple(std::vector<int64_t> elements) {
    for (int element : elements) {
        this->add(element);
    }
}

bool BloomFilter::contains(int64_t element) {

    bool answer256 = this->bloomFilter.at(this->sha256(element)) == 1;
    bool answer384 = this->bloomFilter.at(this->sha384(element)) == 1;

    return answer256 && answer384;
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
int BloomFilter::sha256(int64_t element) {
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

int BloomFilter::sha384(int64_t element) {
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


std::vector<int64_t> BloomFilter::getContents(){
    return this->bloomFilter;
}

int BloomFilter::getSize() {
    return this->size;
}

void BloomFilter::clear() {
    this->bloomFilter = vector<int64_t>(size, 0);
}

