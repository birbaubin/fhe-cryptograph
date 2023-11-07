
#include "headers.h"
#include "helpers.h"


//TODO: implement full batching

void CryptoGraph::exactCryptograph(std::vector<std::vector<int64_t>> graph1,
                    std::vector<std::vector<int64_t>> graph2,
                    std::vector<UndirectedEdge> evaluated_edges)
{

    double totalTime = 0;
    usint batchSize = 1 << 11; // 2^11 = 2048
    PlaintextModulus plaintextModulus = (1 << 16) +1; // 2^16 + 1 = 65537
    usint ringDim = 1 << 15; // 2^15 = 32768
    usint maxNumberOfBatches = ringDim / batchSize;
    usint currentNumberOfBatches=0;


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

    std::vector<int64_t> neighbors_nodex_graph1;
    std::vector<int64_t> neighbors_nodey_graph1;
    std::vector<int64_t> neighbors_nodex_graph2;
    std::vector<int64_t> neighbors_nodey_graph2;

    std::vector<std::array<int64_t, 2> > batchEdges;
    timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    for (int i=0; i<evaluated_edges.size(); i++)
    {
        if((currentNumberOfBatches < maxNumberOfBatches) & (i < evaluated_edges.size()-1))
        {

            int64_t nodex = evaluated_edges.at(i).vertices[0];
            int64_t nodey = evaluated_edges.at(i).vertices[1];

            std::cout << "Adding edge " << nodex << " -- " << nodey << " to batch" << std::endl;
            neighbors_nodex_graph1.insert(neighbors_nodex_graph1.end(), graph1.at(nodex).begin(), graph1.at(nodex).end());
            neighbors_nodey_graph1.insert(neighbors_nodey_graph1.end(), graph1.at(nodey).begin(), graph1.at(nodey).end());
            neighbors_nodex_graph2.insert(neighbors_nodex_graph2.end(), graph2.at(nodex).begin(), graph2.at(nodex).end());
            neighbors_nodey_graph2.insert(neighbors_nodey_graph2.end(), graph2.at(nodey).begin(), graph2.at(nodey).end());

            batchEdges.push_back({nodex, nodey});

            for(int j = 0; j < (batchSize - graph1.size()); j++)
            {
                neighbors_nodex_graph1.push_back(0);
                neighbors_nodey_graph1.push_back(0);
                neighbors_nodex_graph2.push_back(0);
                neighbors_nodey_graph2.push_back(0);
            }

            currentNumberOfBatches++;
        }
        else
        {
            std::cout << "Batch is full, evaluating batch" << std::endl;

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

            ciphertext_nodex_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph1);
            ciphertext_nodex_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph2);
            ciphertext_nodey_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph1);
            ciphertext_nodey_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph2);

            ////////////////////////////////////////////////////////////
            // Homomorphic Operations
            ////////////////////////////////////////////////////////////

            Ciphertext<DCRTPoly> ciphertext_nodex = evalOr(ciphertext_nodex_graph1, ciphertext_nodex_graph2, cc);
            Ciphertext<DCRTPoly> ciphertext_nodey = evalOr(ciphertext_nodey_graph1, ciphertext_nodey_graph2, cc);

            Ciphertext<DCRTPoly> ciphertext_common_neighbors  = cc->EvalMult(ciphertext_nodex, ciphertext_nodey);

            Ciphertext<DCRTPoly> ciphertextEvalSum = cc->EvalSum(ciphertext_common_neighbors, batchSize);


            ////////////////////////////////////////////////////////////
            // Decryption
            ////////////////////////////////////////////////////////////

            Plaintext plaintextResult;
            decrypt(ciphertextEvalSum, cc, kp1, kp2, &plaintextResult);
            plaintextResult->SetLength(plaintext_nodex_graph1->GetLength());


            for(int k = 0; k < batchEdges.size(); k++)
            {
                std::cout << "Common neighbors for edge " << batchEdges.at(k).at(0)
                          << " -- " << batchEdges.at(k).at(1) << " : "
                          << plaintextResult->GetPackedValue()[k*batchSize] << std::endl;
            }

            neighbors_nodex_graph1.clear();
            neighbors_nodey_graph1.clear();
            neighbors_nodex_graph2.clear();
            neighbors_nodey_graph2.clear();
            batchEdges.clear();

            if(i == evaluated_edges.size()-1)
            {
                break;
            }


            int64_t nodex = evaluated_edges.at(i).vertices[0];
            int64_t nodey = evaluated_edges.at(i).vertices[1];

            std::cout << "Adding edge " << nodex << " -- " << nodey << " to batch" << std::endl;

            neighbors_nodex_graph1.insert(neighbors_nodex_graph1.end(), graph1.at(nodex).begin(), graph1.at(nodex).end());
            neighbors_nodey_graph1.insert(neighbors_nodey_graph1.end(), graph1.at(nodey).begin(), graph1.at(nodey).end());
            neighbors_nodex_graph2.insert(neighbors_nodex_graph2.end(), graph2.at(nodex).begin(), graph2.at(nodex).end());
            neighbors_nodey_graph2.insert(neighbors_nodey_graph2.end(), graph2.at(nodey).begin(), graph2.at(nodey).end());

            for(int j = 0; j < (batchSize - graph1.size()); j++)
            {
                neighbors_nodex_graph1.push_back(0);
                neighbors_nodey_graph1.push_back(0);
                neighbors_nodex_graph2.push_back(0);
                neighbors_nodey_graph2.push_back(0);
            }

            batchEdges.push_back({nodex, nodey});
            currentNumberOfBatches = 1;

        }
    }


    gettimeofday(&t_end, NULL);

    totalTime += getMillies(t_start, t_end);
    std::cout << "Average time over " << evaluated_edges.size() << " predictions : "
    << totalTime / evaluated_edges.size() << " ms" << std::endl;

}


void CryptoGraph::CommonNeighborsWithBloom(Graph graph1,
                                            Graph graph2,
                      std::vector<UndirectedEdge> evaluated_edges, string datasetName)
{

    double totalTime = 0;
    PlaintextModulus plaintextModulus = (1 << 16) +1; // 2^16 + 1 = 65537
    usint ringDim = 1 << 15; // 2^15 = 32768
    usint currentNumberOfBatches=0;
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    int maxGraphDegree = 351;
    float falsePositiveRate = 0.01;
    BloomFilter testFilter = BloomFilter(maxGraphDegree, falsePositiveRate);
    testFilter.addMultiple(graph1.getAdjacencyMatrix().at(0));

    usint batchSize = 1 << 8; // 2^11 = 2048
    while(batchSize < testFilter.getSize())
    {
        batchSize = batchSize << 1;
    }


    std::cout << "Bloom filter size =  " << testFilter.getSize() << " => Batchsize =  " << batchSize << std::endl;
    usint maxNumberOfBatches = ringDim / batchSize;

    generateCryptoContextAndKeys(SecurityLevel::HEStd_128_classic,
                                 batchSize,
                                 plaintextModulus,
                                 3,
                                 ringDim,
                                 &cc,
                                 &kp1,
                                 &kp2);

    std::vector<int64_t> neighbors_nodex_graph1;
    std::vector<int64_t> neighbors_nodey_graph1;
    std::vector<int64_t> neighbors_nodex_graph2;
    std::vector<int64_t> neighbors_nodey_graph2;

    BloomFilter filter_nodex_graph1 = BloomFilter(maxGraphDegree, falsePositiveRate);
    BloomFilter filter_nodey_graph1 = BloomFilter(maxGraphDegree, falsePositiveRate);
    BloomFilter filter_nodex_graph2 = BloomFilter(maxGraphDegree, falsePositiveRate);
    BloomFilter filter_nodey_graph2 = BloomFilter(maxGraphDegree, falsePositiveRate);

    ofstream logs;
    logs.open( datasetName + "-cn" + ".csv");

    std::vector<std::array<int64_t, 2> > batchEdges;
    timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    for (int i=0; i < evaluated_edges.size(); i++)
    {
        if((currentNumberOfBatches < maxNumberOfBatches) & (i < evaluated_edges.size()-1))
        {


            int64_t nodex = evaluated_edges.at(i).vertices[0];
            int64_t nodey = evaluated_edges.at(i).vertices[1];
#ifdef DEBUG
            std::cout << "Adding edge " << nodex << " -- " << nodey << " to batch" << std::endl;
#endif
            std::vector<int64_t> nodex_graph1 = graph1.getAdjacencyLists().at(nodex);
            std::vector<int64_t> nodey_graph1 = graph1.getAdjacencyLists().at(nodey);
            std::vector<int64_t> nodex_graph2 = graph2.getAdjacencyLists().at(nodex);
            std::vector<int64_t> nodey_graph2 = graph2.getAdjacencyLists().at(nodey);

            filter_nodex_graph1.addMultiple(nodex_graph1);
            filter_nodey_graph1.addMultiple(nodey_graph1);
            filter_nodex_graph2.addMultiple(nodex_graph2);
            filter_nodey_graph2.addMultiple(nodey_graph2);


            std::vector<int64_t> contents = filter_nodex_graph1.getContents();
            neighbors_nodex_graph1.insert(neighbors_nodex_graph1.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodey_graph1.getContents();
            neighbors_nodey_graph1.insert(neighbors_nodey_graph1.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodex_graph2.getContents();
            neighbors_nodex_graph2.insert(neighbors_nodex_graph2.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodey_graph2.getContents();
            neighbors_nodey_graph2.insert(neighbors_nodey_graph2.end(),
                                          contents.begin(),
                                          contents.end());



            batchEdges.push_back({nodex, nodey});

            for(int j = 0; j < (batchSize - filter_nodex_graph1.getSize()); j++)
            {
                neighbors_nodex_graph1.push_back(0);
                neighbors_nodey_graph1.push_back(0);
                neighbors_nodex_graph2.push_back(0);
                neighbors_nodey_graph2.push_back(0);

            }

            currentNumberOfBatches++;

            filter_nodex_graph1.clear();
            filter_nodey_graph1.clear();
            filter_nodex_graph2.clear();
            filter_nodey_graph2.clear();

        }
        else
        {
#ifdef DEBUG
            std::cout << "Batch is full, evaluating batch" << std::endl;
#endif

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

            ciphertext_nodex_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph1);
            ciphertext_nodex_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph2);
            ciphertext_nodey_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph1);
            ciphertext_nodey_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodey_graph2);

            Plaintext plaintextResult;


            Ciphertext<DCRTPoly> ciphertext_nodex = evalOr(ciphertext_nodex_graph1, ciphertext_nodex_graph2, cc);

            Ciphertext<DCRTPoly> ciphertext_nodey = evalOr(ciphertext_nodey_graph1, ciphertext_nodey_graph2, cc);
//
            Ciphertext<DCRTPoly> ciphertext_common_neighbors  = cc->EvalMult(ciphertext_nodex, ciphertext_nodey);
//
            decrypt(ciphertext_common_neighbors, cc, kp1, kp2, &plaintextResult);
            plaintextResult->SetLength(plaintext_nodex_graph1->GetLength());

            Ciphertext<DCRTPoly> ciphertextEvalSum = cc->EvalSum(ciphertext_common_neighbors, batchSize);


            decrypt(ciphertextEvalSum, cc, kp1, kp2, &plaintextResult);
            plaintextResult->SetLength(plaintext_nodex_graph1->GetLength());


            for(int k = 0; k < batchEdges.size(); k++)
            {
                int result = plaintextResult->GetPackedValue()[k*batchSize] / 2;

#ifdef DEBUG
                std::cout << "Common neighbors for edge " << batchEdges.at(k).at(0)
                          << " -- " << batchEdges.at(k).at(1) << " : "
                          << result << std::endl;
#endif

#ifndef DEBUG
                helpers::printProgress((double)i / evaluated_edges.size());
#endif
                logs << batchEdges.at(k).at(0) << ","
                     << batchEdges.at(k).at(1) << ","
                     << result << "\n";

            }


            neighbors_nodex_graph1.clear();
            neighbors_nodey_graph1.clear();
            neighbors_nodex_graph2.clear();
            neighbors_nodey_graph2.clear();
            batchEdges.clear();

            if(i == evaluated_edges.size()-1)
            {
                break;
            }

            int64_t nodex = evaluated_edges.at(i).vertices[0];
            int64_t nodey = evaluated_edges.at(i).vertices[1];
#ifdef DEBUG
            std::cout << "Adding edge " << nodex << " -- " << nodey << " to batch" << std::endl;
#endif
            std::vector<int64_t> nodex_graph1 = graph1.getAdjacencyLists().at(nodex);
            std::vector<int64_t> nodey_graph1 = graph1.getAdjacencyLists().at(nodey);
            std::vector<int64_t> nodex_graph2 = graph2.getAdjacencyLists().at(nodex);
            std::vector<int64_t> nodey_graph2 = graph2.getAdjacencyLists().at(nodey);

            filter_nodex_graph1.clear();
            filter_nodex_graph1.addMultiple(nodex_graph1);
            filter_nodey_graph1.clear();
            filter_nodey_graph1.addMultiple(nodey_graph1);
            filter_nodex_graph2.clear();
            filter_nodex_graph2.addMultiple(nodex_graph2);
            filter_nodey_graph2.clear();
            filter_nodey_graph2.addMultiple(nodey_graph2);

            std::vector<int64_t> contents = filter_nodex_graph1.getContents();
            neighbors_nodex_graph1.insert(neighbors_nodex_graph1.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodey_graph1.getContents();
            neighbors_nodey_graph1.insert(neighbors_nodey_graph1.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodex_graph2.getContents();
            neighbors_nodex_graph2.insert(neighbors_nodex_graph2.end(),
                                          contents.begin(),
                                          contents.end());

            contents = filter_nodey_graph2.getContents();
            neighbors_nodey_graph2.insert(neighbors_nodey_graph2.end(),
                                          contents.begin(),
                                          contents.end());

            for(int j = 0; j < (batchSize - filter_nodex_graph1.getContents().size()); j++)
            {
                neighbors_nodex_graph1.push_back(0);
                neighbors_nodey_graph1.push_back(0);
                neighbors_nodex_graph2.push_back(0);
                neighbors_nodey_graph2.push_back(0);
            }

            batchEdges.push_back({nodex, nodey});
            currentNumberOfBatches = 1;

        }

    }

    logs.close();

    gettimeofday(&t_end, NULL);

    totalTime += getMillies(t_start, t_end);
    std::cout << "Average time over " << evaluated_edges.size() << " predictions : "
              << totalTime / evaluated_edges.size() << " ms" << std::endl;

}






