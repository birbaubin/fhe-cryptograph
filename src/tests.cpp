//
// Created by Aubin Birba on 2023-09-27.
//

#include <iostream>
#include <sys/time.h>
#include "openfhe.h"
#include "util.h"
#include "cmath"

using namespace lbcrypto;

Ciphertext<DCRTPoly> evalRotateAndSumCIphertext(Ciphertext<DCRTPoly> ciphertext,
                                                CryptoContext<DCRTPoly> cc);


int main(int argc, char* argv[]) {

    usint batchSize = 1 << 11; // 2^10 = 1024
    PlaintextModulus plaintextModulus = (1 << 16) +1;
    usint ringDim = 1 << 15; // 2^15 = 8192

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    generateCryptoContextAndKeys(SecurityLevel::HEStd_128_classic,
                                 batchSize,
                                 plaintextModulus,
                                 3,
                                 ringDim,
                                 &cc,
                                 &kp1,
                                 &kp2);


//    std::vector<usint> indexList(log(cc->GetRingDimension())+1);
//
//    // Filling the vector with elements of the form 2^i
//    for (int i = 0; i < indexList.size(); ++i)
//    {
//        indexList[i] = std::pow(2, i);
//    }

    std::vector<usint> indexList = {3};

   auto  evalAutoKeys = cc->EvalAutomorphismKeyGen(kp1.secretKey, indexList);


    auto evalAutoKey2 = cc->MultiEvalAutomorphismKeyGen(kp2.secretKey, evalAutoKeys, indexList, kp2.publicKey->GetKeyTag());

    auto evalAutoKeysJoin = cc->MultiAddEvalAutomorphismKeys(evalAutoKeys, evalAutoKey2, kp2.publicKey->GetKeyTag());

    cc->InsertEvalAutomorphismKey(evalAutoKeysJoin);

    Plaintext test_plaintext = cc->MakePackedPlaintext({0, 1, 2, 3, 4});

    auto test_ciphertext = cc->Encrypt(kp2.publicKey, test_plaintext);

    std::cout << "Number of automorphism keys : " << cc->GetEvalAutomorphismKeyMap(kp2.publicKey->GetKeyTag()).size() << std::endl;

    auto ct_rotated = cc->EvalRotate(test_ciphertext, 3);

    Plaintext result;

    decrypt(ct_rotated, cc, kp1, kp2, &result);

    std::cout << "Result of test : " << result->GetPackedValue() << std::endl;

    return 0;
}