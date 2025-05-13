import json
import re
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split

with open('OverFlow.json', 'r') as f:
    data = json.load(f)

train_data, test_data = train_test_split(data, test_size=0.2, random_state= 42)

abstracted_safe_sequences = []
abstracted_unsafe_sequences = []


def prepare_data(data, mode):
    match mode:
        case 1:
            for content in data:
                for line in content['safe_features']:
                    abstracted_safe_sequences.append(line)
                for line in content['unsafe_features']:
                    abstracted_unsafe_sequences.append(line)

            all_sequences = abstracted_safe_sequences + abstracted_unsafe_sequences
            labels = [0] * len(abstracted_safe_sequences) + [1] * len(abstracted_unsafe_sequences)
        case 2:
            for content in data:
                for line in content['safe_features']:
                    abstracted_safe_sequences.append(line)
            all_sequences = abstracted_safe_sequences
            labels = [0] *len(abstracted_safe_sequences)
        case 3:
            for content in data:
                for line in content['unsafe_features']:
                    abstracted_unsafe_sequences.append(line)
            all_sequences = abstracted_unsafe_sequences
            labels = [1] * len(abstracted_unsafe_sequences)



    return all_sequences, labels

all_sequences, labels = prepare_data(train_data,1)
#should i be using set here?? yes
vocab = {tok: idx for idx, tok in enumerate(set(t for seq in all_sequences for t in seq))}
numerical_sequences = [[vocab[tok] for tok in seq] for seq in all_sequences]

X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in numerical_sequences])
lengths = [len(seq) for seq in numerical_sequences]


from hmmlearn import hmm
model = hmm.MultinomialHMM(n_components=4, n_iter=100)
model.fit(X, lengths)

all_test_sequences, test_labels = prepare_data(test_data,2)



test_numerical_sequences = [[vocab[tok] for tok in seq] for seq in all_test_sequences]


for seq, label in zip(test_numerical_sequences, test_labels):
      x = np.array(seq).reshape(-1,1)
      score = model.score(x)
      print(score)


