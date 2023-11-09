#include "headers.h"

int main(int argc, char* argv[]) {
    std::cout << "\n================= Crypto'Graph "
                 "====================="
              << std::endl;
//
//    std::vector<std::vector<int64_t>> graph1 = loadGraphAsAdjacencyMatrix("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net1-polblogs.csv", 1222);
//    std::vector<std::vector<int64_t>> graph2 = loadGraphAsAdjacencyMatrix("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net2-polblogs.csv", 1222);


    Graph graph1 = Graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net1-email.csv", 144);
    Graph graph2 = Graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net2-email.csv", 144);
    //print graph1


    std::cout << "Dataset loaded" << std::endl;
    std::vector<uint32_t> neighbors;

    for(int i = 0; i < graph1.getSize(); i++)
    {
        neighbors.push_back(i);
    }

    std::vector<UndirectedEdge> evaluated_edges = generateCompleteGraph(neighbors);
//    CryptoGraph::CommonNeighborsWithBloom(graph1, graph2, evaluated_edges, "polblogs");
    CryptoGraph::ressourceAllocationWithBloom(graph1, graph2, evaluated_edges, "polblogs");

//    CryptoGraph::exactCryptograph(graph1, graph2, evaluated_edges);


    return 0;
}