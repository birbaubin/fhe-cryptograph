#include "util.h"


using namespace lbcrypto;

std::vector<std::vector<int64_t>> load_graph(std::string filename, size_t dataset_size)


{

    std::vector<std::vector<int64_t>> matrix(dataset_size, std::vector<int64_t>(dataset_size, 0));
    std::ifstream infile(filename.c_str());

    if(!infile.good()) {
        std::cerr << "Input file " << filename << " does not exist, program exiting!" << std::endl;
        exit(0);
    }

    std::string line;


    infile.clear();
    infile.seekg(std::ios::beg);

    std::string source, target;

    while(getline(infile, line))
    {
        std::stringstream str(line);
        std::getline(str, source, ',');
        std::getline(str, target, ',');

        uint32_t int_source = stol(source);
        uint32_t int_target = stol(target);

        matrix[int_target][int_source] = 1;
        matrix[int_source][int_target] = 1;

    }

    return matrix;

}

std::vector<UndirectedEdge> generate_complete_graph(std::vector<uint32_t> nodes)
{

    std::vector<UndirectedEdge> graph;

    for (size_t i = 0; i < nodes.size(); i++)
    {
       for (size_t j = i+1; j < nodes.size(); j++)
       {
            UndirectedEdge edge;
            edge.vertices[0] = nodes.at(i);
            edge.vertices[1] = nodes.at(j);
            graph.push_back(edge);
       }
       
    }

    return graph;
    
}

void generateCryptoContextAndKeys(SecurityLevel securityLevel,
                                  usint batchSize,
                                  PlaintextModulus plaintextModulus,
                                  int multiplicativeDepth,
                                  usint ringDim,
                                  CryptoContext<DCRTPoly>* cc,
                                  KeyPair<DCRTPoly>* kp1,
                                  KeyPair<DCRTPoly>* kp2)
{
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetBatchSize(batchSize);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetRingDim(ringDim);


    // NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
    // and is most secure mode of threshold FHE for BFV and BGV.
    parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);

    *cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    (*cc)->Enable(PKE);
    (*cc)->Enable(KEYSWITCH);
    (*cc)->Enable(LEVELEDSHE);
    (*cc)->Enable(ADVANCEDSHE);
    (*cc)->Enable(MULTIPARTY);

    auto level = parameters.GetSecurityLevel();
    std::cout << "Security level: " << level << std::endl;

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << (*cc)->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << (*cc)->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2((*cc)->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;


    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    *kp1 = (*cc)->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = (*cc)->KeySwitchGen(kp1->secretKey, kp1->secretKey);

    // Generate evalsum key part for A
    (*cc)->EvalSumKeyGen(kp1->secretKey);
    auto evalSumKeys =
            std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>((*cc)->GetEvalSumKeyMap(kp1->secretKey->GetKeyTag()));

    *kp2 = (*cc)->MultipartyKeyGen((kp1->publicKey));

    auto evalMultKey2 = (*cc)->MultiKeySwitchGen(kp2->secretKey, kp2->secretKey, evalMultKey);
    auto evalMultAB = (*cc)->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2->publicKey->GetKeyTag());

    auto evalMultBAB = (*cc)->MultiMultEvalKey(kp2->secretKey, evalMultAB, kp2->publicKey->GetKeyTag());

    auto evalSumKeysB = (*cc)->MultiEvalSumKeyGen(kp2->secretKey, evalSumKeys, kp2->publicKey->GetKeyTag());

    auto evalSumKeysJoin = (*cc)->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2->publicKey->GetKeyTag());

    (*cc)->InsertEvalSumKey(evalSumKeysJoin);

    auto evalMultAAB = (*cc)->MultiMultEvalKey(kp1->secretKey, evalMultAB, kp2->publicKey->GetKeyTag());

    auto evalMultFinal = (*cc)->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    (*cc)->InsertEvalMultKey({evalMultFinal});

}

bool decrypt(Ciphertext<DCRTPoly> ciphertext,
             CryptoContext<DCRTPoly> cc,
             KeyPair<DCRTPoly> kp1,
             KeyPair<DCRTPoly> kp2,
             Plaintext *plaintextResult
)
{

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext}, kp1.secretKey);

    // partial decryption by party B
    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertext}, kp2.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    // Two partial decryptions are combined
    cc->MultipartyDecryptFusion(partialCiphertextVec, plaintextResult);

    return true;

}

Ciphertext<DCRTPoly> evalRotateAndSumCIphertext(Ciphertext<DCRTPoly> ciphertext,
                                                CryptoContext<DCRTPoly> cc)
{

    std::cout << "Inside evalRotateAndSumCIphertext" << std::endl;
    auto ct_result = ciphertext;

//    std::cout << "Number of slots : " << cc->GetRingDimension() << std::endl;
    for(int i=1; i<=log(cc->GetRingDimension())+1; i++)
    {
        auto ct_rotated = cc->EvalRotate(ciphertext, i);
        ct_result = cc->EvalAdd(ct_result, ct_rotated);
    }

    return ct_result;

}

Ciphertext<DCRTPoly> evalOr(Ciphertext<DCRTPoly> ciphertext1,
                            Ciphertext<DCRTPoly> ciphertext2,
                            CryptoContext<DCRTPoly> cc
)
{
    auto ciphertext_add  = cc->EvalAdd(ciphertext1, ciphertext2);
    auto ciphertext_mult = cc->EvalMult(ciphertext1, ciphertext2);
    auto ciphertext_res = cc->EvalSub(ciphertext_add, ciphertext_mult);

    return ciphertext_res;
}

double getMillies(timeval timestart, timeval timeend)
{
    long time1 = (timestart.tv_sec * 1000000) + (timestart.tv_usec );
    long time2 = (timeend.tv_sec * 1000000) + (timeend.tv_usec );
    return (double)(time2-time1)/1000;
}

