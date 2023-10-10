#include "headers.h"

int main(int argc, char* argv[]) {
    std::cout << "\n=================RUNNING Crypto'Graph "
                 "====================="
              << std::endl;

    std::vector<std::vector<int64_t>> graph1 = load_graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net1-polblogs.csv", 1222);
    std::vector<std::vector<int64_t>> graph2 = load_graph("/Users/aubinbirba/Documents/PhD/toy-open-fhe/data/net2-polblogs.csv", 1222);

    std::vector<uint32_t> neighbors;

    for(int i = 0; i < graph1.size(); i++)
    {
        neighbors.push_back(i);
    }

    //print content of neighbrs vector
//    for(int i = 0; i < neighbors.size(); i++)
//    {
//        std::cout << neighbors.at(i) << std::endl;
//    }

    std::vector<UndirectedEdge> evaluated_edges = generate_complete_graph(neighbors);

//    for(int i = 0 ; i < evaluated_edges.size(); i++)
//    {
//        std::cout << evaluated_edges.at(i).vertices[0] << " -- " << evaluated_edges.at(i).vertices[1] << std::endl;
//    }


//
//
//
    exactCryptograph(graph1, graph2, generate_complete_graph(neighbors));



    return 0;
}