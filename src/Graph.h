//
// Created by Aubin Birba on 2023-10-28.
//

#ifndef FHE_CRYPTOGRAPH_GRAPH_H
#define FHE_CRYPTOGRAPH_GRAPH_H

#include <vector>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>


class Graph {


private:
    std::vector<std::vector<int64_t>> adjacencyMatrix;
    std::vector<std::vector<int64_t>> adjacencyLists;
    size_t size;

public:
    Graph(std::string filename, size_t dataset_size);
    std::vector<std::vector<int64_t>> getAdjacencyMatrix();
    std::vector<std::vector<int64_t>> getAdjacencyLists();
    size_t getSize();
    void printAdjacencyMatrix();
    void printAdjacencyLists();
    std::vector<int64_t> getNeighbours(int64_t node);
    std::vector<int64_t> getNeighbours(std::vector<int64_t> nodes);
    std::vector<int64_t> getNodes();


};


#endif //FHE_CRYPTOGRAPH_GRAPH_H
