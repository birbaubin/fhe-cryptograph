import pandas as pd
import numpy as np

pd.set_option('display.max_columns', None)
graph1 = pd.read_csv("net1-email.csv", header=None)
graph2 = pd.read_csv("net2-email.csv", header=None)

#compute the adjacency matrices

graph1_matrix = np.zeros((144,144))
graph2_matrix = np.zeros((144, 144))

for i in range(len(graph1)):
    graph1_matrix[graph1.iloc[i,0], graph1.iloc[i,1]] = 1
    graph1_matrix[graph1.iloc[i,1], graph1.iloc[i,0]] = 1

for i in range(len(graph2)):
    graph2_matrix[graph2.iloc[i,0], graph2.iloc[i,1]] = 1
    graph2_matrix[graph2.iloc[i,1], graph2.iloc[i,0]] = 1


union_graph = np.logical_or(graph1_matrix, graph2_matrix)
#compute the degree vectors

degrees_matrix = np.sum(union_graph, axis=1)

print(max(degrees_matrix))


degrees_matrix = 1/degrees_matrix

np.nan_to_num(degrees_matrix, copy=False)

results = []
for i in range(union_graph.shape[0]):
    for j in range(i+1, union_graph.shape[0]):
        common_neighbors = np.logical_and(union_graph[i,:], union_graph[j,:])
        selected_degrees = np.multiply(degrees_matrix, common_neighbors)
        r_a = np.sum(selected_degrees)
        results.append([i,j,r_a])

results = pd.DataFrame(results)
print(results[(results[0] == 6) & (results[1].isin([131]))])





