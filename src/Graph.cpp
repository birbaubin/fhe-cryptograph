//
// Created by Aubin Birba on 2023-10-28.
//

#include "Graph.h"

Graph::Graph(std::string filename, size_t dataset_size) {


    std::vector<std::vector<int64_t>> matrix(dataset_size, std::vector<int64_t>(dataset_size, 0));
    std::vector<std::vector<int64_t>> lists(dataset_size, std::vector<int64_t>(0));
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

        lists[int_source].push_back(int_target);
        lists[int_target].push_back(int_source);

    }

    this->adjacencyMatrix = matrix;
    this->adjacencyLists = lists;

    this->size = dataset_size;
}

std::vector<std::vector<int64_t>> Graph::getAdjacencyMatrix() {
    return this->adjacencyMatrix;
}

std::vector<std::vector<int64_t>> Graph::getAdjacencyLists() {
    return this->adjacencyLists;
}

size_t Graph::getSize() {
    return this->size;
}

void Graph::printAdjacencyMatrix() {
    std::cout << "[Adjacency Matrix(" << this->size << ")]: <" << std::endl;
    for (int i=0; i<this->size; i++)
    {
        std::cout << "("<< i << ")[";
        for (int j=0; j<this->size; j++)
        {
            std::cout << this->adjacencyMatrix[i][j] << " ";
        }
        std::cout << "]" << std::endl;
    }
    std::cout <<">" << std::endl;
}

void Graph::printAdjacencyLists() {
    std::cout << "[Adjacency Lists(" << this->size << ")]: <" << std::endl;
    for (int i=0; i<this->size; i++)
    {
        std::cout << "("<< i << ")[";
        for (int j=0; j<this->adjacencyLists[i].size(); j++)
        {
            std::cout << this->adjacencyLists[i][j] << " ";
        }
        std::cout << "]" << std::endl;
    }
    std::cout <<">" << std::endl;
}

std::vector<int64_t> Graph::getNeighbours(int64_t node) {
    return this->adjacencyLists[node];
}

std::vector<int64_t> Graph::getNeighbours(std::vector<int64_t> nodes) {
    std::vector<int64_t> neighbours;
    for (int i=0; i<nodes.size(); i++)
    {
        std::vector<int64_t> node_neighbours = this->adjacencyLists[nodes[i]];
        neighbours.insert(neighbours.end(), node_neighbours.begin(), node_neighbours.end());
    }
    return neighbours;
}

std::vector<int64_t> Graph::getNodes() {
    std::vector<int64_t> nodes;
    for (int i=0; i<this->size; i++)
    {
        nodes.push_back(i);
    }
    return nodes;
}
