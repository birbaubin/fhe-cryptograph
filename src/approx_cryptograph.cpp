

#include <sys/time.h>
#include "openfhe.h"

using namespace lbcrypto;


void approximateCryptograph() {

    uint32_t number_of_runs = 50;
    usint batchSize = 16;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetBatchSize(batchSize);
    parameters.SetMultiplicativeDepth(2);
    // NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
    // and is most secure mode of threshold FHE for BFV and BGV.
    parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers for two parties A and B
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (G_1) started." << std::endl;

    kp1 = cc->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
            std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (G_2) started." << std::endl;

    std::cout << "Joint public key for (s_1 + s_2) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    std::cout << "Joint evaluation multiplication key for (s_1 + s_2) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation multiplication key (s_1 + s_2) is transformed "
                 "into s_2*(s_1 + s_2)..."
              << std::endl;
    auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation summation key for (s_1 + s_2) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (G_1) started." << std::endl;

    std::cout << "Joint key (s_1 s_2) is transformed into s_1*(s_1 + s_2)..." << std::endl;
    auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    std::cout << "Computing the final evaluation multiplication key for (s_1 + "
                 "s_2)*(s_2 + s_2)..."
              << std::endl;
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});

    std::cout << "Round 3 of key generation completed." << std::endl;

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> neighbors_nodex_graph1 = {1, 1, 1, 0, 0};
    std::vector<int64_t> neighbors_nodex_graph2 = {1, 0, 0, 0, 1};
    std::vector<int64_t> neighbors_nodey_graph1 = {1, 1, 1, 0, 1};
    std::vector<int64_t> neighbors_nodey_graph2 = {0, 0, 0, 0, 0};

    Plaintext plaintext_nodex_graph1 = cc->MakePackedPlaintext(neighbors_nodex_graph1);
    Plaintext plaintext_nodex_graph2 = cc->MakePackedPlaintext(neighbors_nodex_graph2);
    Plaintext plaintext_nodey_graph1 = cc->MakePackedPlaintext(neighbors_nodey_graph1);
    Plaintext plaintext_nodey_graph2 = cc->MakePackedPlaintext(neighbors_nodey_graph2);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertext_nodex_graph1;
    Ciphertext<DCRTPoly> ciphertext_nodex_graph2;
    Ciphertext<DCRTPoly> ciphertext_nodey_graph1;
    Ciphertext<DCRTPoly> ciphertext_nodey_graph2;

    double time_mili = 0;

    for( int i = 0; i < number_of_runs; i++)
    {
        timeval t_start, t_end;
        gettimeofday(&t_start, NULL);

        ciphertext_nodex_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph1);
        ciphertext_nodex_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph2);
        ciphertext_nodey_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph1);
        ciphertext_nodey_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph2);

        ////////////////////////////////////////////////////////////
        // Homomorphic Operations
        ////////////////////////////////////////////////////////////

        Ciphertext<DCRTPoly> ciphertext_nodex;
        Ciphertext<DCRTPoly> ciphertext_nodey;

        ciphertext_nodex  = cc->EvalAdd(ciphertext_nodex_graph1, ciphertext_nodex_graph2);
        ciphertext_nodey = cc->EvalAdd(ciphertext_nodey_graph1, ciphertext_nodey_graph2);

        auto ciphertext_common_neighbors  = cc->EvalMult(ciphertext_nodex, ciphertext_nodey);
        auto ciphertextEvalSum = cc->EvalSum(ciphertext_common_neighbors, batchSize);

        ////////////////////////////////////////////////////////////
        // Decryption
        ////////////////////////////////////////////////////////////

        Plaintext plaintextAddNew1;
        Plaintext plaintextAddNew2;
        Plaintext plaintextAddNew3;

        DCRTPoly partialPlaintext1;
        DCRTPoly partialPlaintext2;
        DCRTPoly partialPlaintext3;

        Plaintext plaintextMultipartyNew;
        Plaintext plaintextMultipartyEvalSum;

        const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
        const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

//     Distributed decryption

//     partial decryption by party A
        auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext_nodex}, kp1.secretKey);

        // partial decryption by party B
        auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertext_nodex}, kp2.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
        partialCiphertextVec.push_back(ciphertextPartial1[0]);
        partialCiphertextVec.push_back(ciphertextPartial2[0]);

        // Two partial decryptions are combined
        cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

        std::cout << "\n Plaintext node x neighbors: \n" << std::endl;
        std::cout << neighbors_nodex_graph1 << std::endl;
        std::cout << neighbors_nodex_graph2 << std::endl;

        plaintextMultipartyNew->SetLength(plaintext_nodex_graph1->GetLength());

        std::cout << "\n Fused node x neighbors: \n" << std::endl;
        std::cout << plaintextMultipartyNew << std::endl;

        std::cout << "\n";

        Plaintext plaintextMultipartyMult;

        auto ciphertext_neighbors_1 = cc->MultipartyDecryptLead({ciphertext_common_neighbors}, kp1.secretKey);
        auto ciphertext_neighbors_2 = cc->MultipartyDecryptMain({ciphertext_common_neighbors}, kp2.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertext_neighbors;
        partialCiphertext_neighbors.push_back(ciphertext_neighbors_1[0]);
        partialCiphertext_neighbors.push_back(ciphertext_neighbors_2[0]);


        Plaintext plaintext_neighbors;

        cc->MultipartyDecryptFusion(partialCiphertext_neighbors, &plaintext_neighbors);

        std::cout << "Plaintext of common neighbors : " << plaintext_neighbors << std::endl;

        ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext_nodey}, kp1.secretKey);

        ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertext_nodey}, kp2.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec2;
        partialCiphertextVec2.push_back(ciphertextPartial1[0]);
        partialCiphertextVec2.push_back(ciphertextPartial2[0]);

        // Two partial decryptions are combined
        cc->MultipartyDecryptFusion(partialCiphertextVec2, &plaintextMultipartyNew);

        std::cout << "\n Plaintext node y neighbors: \n" << std::endl;
        std::cout << neighbors_nodey_graph1 << std::endl;
        std::cout << neighbors_nodey_graph2 << std::endl;

        plaintextMultipartyNew->SetLength(plaintext_nodex_graph1->GetLength());

        std::cout << "\n Fused node y neighbors: \n" << std::endl;
        std::cout << plaintextMultipartyNew << std::endl;

        std::cout << "\n";

        ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextEvalSum}, kp1.secretKey);
        ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp2.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
        partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
        partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);

        cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum, &plaintextMultipartyEvalSum);
        plaintextMultipartyEvalSum->SetLength(plaintext_nodex_graph1->GetLength());

        std::cout << "\n Approximate common neighbors of nodes x and y : \n" << std::endl;
        std::cout << plaintextMultipartyEvalSum << std::endl;

        std::cout << "Size of result  :" << plaintextMultipartyNew->GetLength() << std::endl;


        gettimeofday(&t_end, NULL);

        time_mili+= getMillies(t_start, t_end);
        std::cout << "Time for prediction : " << getMillies(t_start, t_end) << std::endl;
    }

    std::cout << "Average time for 100 runs " << time_mili / number_of_runs << std::endl;

}


