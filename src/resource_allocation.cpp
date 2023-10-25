//
// Created by Aubin Birba on 2023-10-04.
//


#include <iostream>
#include <sys/time.h>
#include "util.h"
#include "headers.h"

//TODO: implement resource allocation metric

void CryptoGraph::ressourceAllocation(std::vector<std::vector<int64_t>> graph1,
                         std::vector<std::vector<int64_t>> graph2,
                         std::vector<UndirectedEdge> evaluated_edges)
{

    double totalTime = 0;
    usint batchSize = 1 << 8; // 2^11 = 2048
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;
    std::vector<Ciphertext<DCRTPoly>> fused_graph;
    std::vector<Ciphertext<DCRTPoly>> degrees;


    generateCKKSContextAndKeys(SecurityLevel::HEStd_128_classic,
                               batchSize,
                               9,
                               &cc,
                               &kp1,
                               &kp2);

    timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    for (int i=0; i<graph1.size(); i++)
    {

        std::cout << "Computing node " << i << std::endl;
        std::vector<std::complex<double>> neighbors_nodex_graph1(graph1.at(i).begin(), graph1.at(i).end());
        std::vector<std::complex<double>> neighbors_nodex_graph2(graph2.at(i).begin(), graph2.at(i).end());

        Plaintext plaintext_nodex_graph1 = cc->MakeCKKSPackedPlaintext(neighbors_nodex_graph1);
        Plaintext plaintext_nodex_graph2 = cc->MakeCKKSPackedPlaintext(neighbors_nodex_graph2);

        Ciphertext<DCRTPoly> ciphertext_nodex_graph1;
        Ciphertext<DCRTPoly> ciphertext_nodex_graph2;

        ciphertext_nodex_graph1 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph1);
        ciphertext_nodex_graph2 = cc->Encrypt(kp2.publicKey, plaintext_nodex_graph2);

        Ciphertext<DCRTPoly> ciphertext_nodex = evalOr(ciphertext_nodex_graph1, ciphertext_nodex_graph2, cc);

        fused_graph.push_back(ciphertext_nodex);

        Ciphertext<DCRTPoly> degree_nodex = cc->EvalSum(ciphertext_nodex, batchSize);

        std::vector<std::complex<double>> mask(graph1.size(), 0);
        mask.at(i) = 1;

        Plaintext plaintext_mask = cc->MakeCKKSPackedPlaintext(mask);
        Ciphertext<DCRTPoly> masked_degree_nodex = cc->EvalMult(degree_nodex, plaintext_mask);
        degrees.push_back(masked_degree_nodex);
    }

    gettimeofday(&t_end, NULL);
    totalTime += getMillies(t_start, t_end);
    Ciphertext<DCRTPoly> degree_result = cc->EvalAddMany(degrees);
    std::cout << "Precomputation of fusion graph finished in " <<
    totalTime << " ms" << std::endl;

    gettimeofday(&t_start, NULL);
    Plaintext plaintextResult;

    double a = 1;
    double b = 50;
    int degree = 15;

    std::function<double(double)> metric_function;
    std::string metric = "resource_allocation";
    if(metric == "resource_allocation"){
        std::cout << "Using resource allocation metric" << std::endl;
        metric_function = [](double x) -> double { return 1/x; };
    }
    else if(metric == "adamic_adar"){
        metric_function = [](double x) -> double { return 1/log(x); };
    }

    Ciphertext<DCRTPoly> one_over_degree = cc->EvalChebyshevFunction(metric_function, degree_result, a, b, degree);



    for(int i = 0; i < evaluated_edges.size(); i++)
    {
        Ciphertext<DCRTPoly> ciphertext_nodex = fused_graph.at(evaluated_edges.at(i).vertices[0]);

        Ciphertext<DCRTPoly> ciphertext_nodey = fused_graph.at(evaluated_edges.at(i).vertices[1]);

//        std::cout << "About to compute first multiplication" << std::endl;
        Ciphertext<DCRTPoly> ciphertext_common_neighbors = cc->EvalMult(ciphertext_nodex, ciphertext_nodey);

//        std::cout << "About to compute second multiplication" << std::endl;
        Ciphertext<DCRTPoly> selected_neighbor_metrics = cc->EvalMult(ciphertext_common_neighbors, one_over_degree);
//        std::cout << "About to compute sum" << std::endl;
        selected_neighbor_metrics = cc->EvalSum(selected_neighbor_metrics, batchSize);
        decrypt(selected_neighbor_metrics, cc, kp1, kp2, &plaintextResult);
        auto result = plaintextResult->GetCKKSPackedValue()[0];
        std::cout << "Link " << evaluated_edges.at(i).vertices[0] << "--" << evaluated_edges.at(i).vertices[1] << " : " << result.real() << std::endl;

    }


    gettimeofday(&t_end, NULL);
    totalTime = getMillies(t_start, t_end);
    std::cout << "Total time for metric computation : " << totalTime << " ms" << std::endl;
    std::cout << "Average time for metric computation : " << totalTime/evaluated_edges.size() << " ms" << std::endl;

}



