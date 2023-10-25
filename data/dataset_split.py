import numpy as np
import pandas as pd

PROJET_PATH = "/Users/aubinbirba/Documents/PhD/toy-open-fhe"


## wheither i and j are neighbors on the graph
def already_neighbors(i, j, graph):
    rows = graph[graph["Source"].isin([i, j]) & graph["Target"].isin([i, j])]
    return True if len(rows) > 0 else False


## attack graph by inserting random edges
# def add_false_edges(graph, proportion):
#     new_edge_number = round(proportion * len(graph))
#     for i in range(new_edge_number):
#         source = random.sample(sorted(nodes_list), 1)[0]
#         target = random.sample(sorted(nodes_list), 1)[0]
#
#         while already_neighbors(source, target, graph):
#             source = random.sample(sorted(nodes_list), 1)[0]
#             target = random.sample(sorted(nodes_list), 1)[0]
#
#         graph = pd.concat([graph, pd.DataFrame([[source, target, 0]],
#                                                columns=["Source", "Target", "p"])],
#                           ignore_index=True)
#
#     return graph


DATASET_NAME = "email"

# data = Dataset(root='/tmp', name=DATASET_NAME)
# adj, features, labels = data.adj, data.features, data.labels
# edges = np.array(adj.nonzero()).T.astype(int)
# np.savetxt(PROJET_PATH + "/datasets/"+DATASET_NAME + ".csv", edges, delimiter=",", fmt="%d")
# dataset = pd.DataFrame(data=edges)
dataset = pd.read_csv("email.csv", header=None)

# graph splitting proportions
q1 = 0
q2 = 0.3
q3 = 0.6

# assign each edge with random value adn split
dataset["p"] = np.random.random(dataset.shape[0])
network1 = dataset[((dataset["p"] > q1) & (dataset["p"] < q2)) | (dataset["p"] > q3)]
network2 = dataset[dataset["p"] > q2]

network1 = network1.drop(["p"], axis=1)
network2 = network2.drop(["p"], axis=1)

network1.to_csv(PROJET_PATH + "/data/" + "net1-" + DATASET_NAME + ".csv", header=False, index=False)
network2.to_csv(PROJET_PATH + "/data/" + "net2-" + DATASET_NAME + ".csv", header=False, index=False)

print("Dataset exported and printed.")

# nodes_list = set(dataset["Source"]).union(set(dataset["Target"]))
# attack_network1 = add_false_edges(network1, 1)
# attack_network1.to_csv("../../datasets/" + "attack-net-" + DATASET_NAME , header=False, index=False, columns=["Source" ,"Target"])