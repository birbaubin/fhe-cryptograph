#include "headers.h"

int main(int argc, char* argv[]) {
    std::cout << "\n=================RUNNING Crypto'Graph "
                 "====================="
              << std::endl;

    std::vector<std::vector<int64_t>> graph1 = load_graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net1-email.csv", 144);
    std::vector<std::vector<int64_t>> graph2 = load_graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net2-email.csv", 144);
//

    std::cout << "Dataset loaded" << std::endl;
    std::vector<uint32_t> neighbors;

    for(int i = 0; i < graph1.size(); i++)
    {
        neighbors.push_back(i);
    }

    std::vector<UndirectedEdge> evaluated_edges = generate_complete_graph(neighbors);
//    ressourceAllocation(graph1, graph2, evaluated_edges);

//    BloomFilter bloomFilter(10);
//    bloomFilter.add(9);
//    bloomFilter.print();

    void exactCryptograph(std::vector<std::vector<int64_t>> graph1,
                          std::vector<std::vector<int64_t>> graph2,
                          std::vector<UndirectedEdge> evaluated_edges);

    return 0;
}