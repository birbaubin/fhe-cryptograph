//
// Created by Aubin Birba on 2023-10-04.
//

#ifndef DEMO_HEADERS_H
#define DEMO_HEADERS_H

#include <iostream>
#include <sys/time.h>
#include "util.h"
#include "BloomFilter.h"
#include "Graph.h"




using namespace std;

class CryptoGraph{

public:
    static void exactCryptograph(std::vector<std::vector<int64_t>> graph1,
                                 std::vector<std::vector<int64_t>> graph2,
                                 std::vector<UndirectedEdge> evaluated_edges);

    void ressourceAllocation(std::vector<std::vector<int64_t>> graph1,
                             std::vector<std::vector<int64_t>> graph2,
                             std::vector<UndirectedEdge> evaluated_edges);

    static void ressourceAllocationWithBloom(Graph graph1,
                                             Graph graph2,
                                             std::vector<UndirectedEdge> evaluated_edges,
                                             string datasetName);

    static void CommonNeighborsWithBloom(Graph graph1,
                                   Graph graph2,
                                   std::vector<UndirectedEdge> evaluated_edges,
                                   string datasetName);

};

void approximateCryptograph();


#endif //DEMO_HEADERS_H
