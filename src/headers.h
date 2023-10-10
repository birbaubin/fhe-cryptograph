//
// Created by Aubin Birba on 2023-10-04.
//

#ifndef DEMO_HEADERS_H
#define DEMO_HEADERS_H

#include <iostream>
#include <sys/time.h>
#include "openfhe.h"
#include "util.h"


using namespace std;

void approximateCryptograph();

void exactCryptograph(std::vector<std::vector<int64_t>> graph1,
                      std::vector<std::vector<int64_t>> graph2,
                      std::vector<UndirectedEdge> evaluated_edges);
#endif //DEMO_HEADERS_H
