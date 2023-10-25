// Created by: Aubin Birba

#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include "openfhe.h"



using namespace lbcrypto;
typedef struct UndirectedEdge
{
    int64_t vertices[2];
    
} 

UndirectedEdge;

std::vector<std::vector<int64_t>> load_graph(std::string filename, size_t dataset_size);

std::vector<UndirectedEdge> generate_complete_graph(std::vector<uint32_t> nodes);

bool decrypt(Ciphertext<DCRTPoly> ciphertext,
             CryptoContext<DCRTPoly> cc,
             KeyPair<DCRTPoly> kp1,
             KeyPair<DCRTPoly> kp2,
             Plaintext *plaintextResult
);

void generateCryptoContextAndKeys(SecurityLevel securityLevel,
                                  usint batchSize,
                                  PlaintextModulus plaintextModulus,
                                  int multiplicativeDepth,
                                  usint ringDim,
                                  CryptoContext<DCRTPoly>* cc,
                                  KeyPair<DCRTPoly>* kp1,
                                  KeyPair<DCRTPoly>* kp2);

void generateCKKSContextAndKeys(SecurityLevel securityLevel,
                                usint batchSize,
                                int multiplicativeDepth,
                                CryptoContext<DCRTPoly>* cc,
                                KeyPair<DCRTPoly>* kp1,
                                KeyPair<DCRTPoly>* kp2);


Ciphertext<DCRTPoly> evalOr(Ciphertext<DCRTPoly> ciphertext1,
                            Ciphertext<DCRTPoly> ciphertext2,
                            CryptoContext<DCRTPoly> cc
);

double getMillies(timeval timestart, timeval timeend);

#endif //UTIL_H