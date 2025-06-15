import json
import re
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt


with open('OverFlow2.json', 'r') as f:
    data = json.load(f)

train_data, test_data = train_test_split(data, test_size=0.2, random_state= 42)

abstracted_safe_sequences = []
abstracted_unsafe_sequences = []


def prepare_data(data, mode):
    feature_map = {}

    match mode:
        case 1:
            for content in data:
                tokenized = []
                for line in content['safe_features']:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                if tokenized:
                    abstracted_safe_sequences.append(tokenized)
                tokenized = []
                for line in content['unsafe_features']:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)

                    tokenized.append(feature_map[line])

                if tokenized:
                    abstracted_unsafe_sequences.append(tokenized)
                tokenized = []
#                
            all_sequences = abstracted_safe_sequences + abstracted_unsafe_sequences
            labels = [0] * len(abstracted_safe_sequences) + [1] * len(abstracted_unsafe_sequences)
        case 2:
            for content in data:
                tokenized = []
                for line in content['safe_features']:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                if tokenized:
                    abstracted_safe_sequences.append(tokenized)
                tokenized = []
            all_sequences = abstracted_safe_sequences
            labels = [0] *len(abstracted_safe_sequences)
        case 3:
            for content in data:
                tokenized = []
                for line in content['unsafe_features']:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                if tokenized:
                    abstracted_unsafe_sequences.append(tokenized)
                tokenized = []
#                for line in content['unsafe_features']:
#                    abstracted_unsafe_sequences.append(line)
            all_sequences = abstracted_unsafe_sequences
            labels = [1] * len(abstracted_unsafe_sequences)

#   print(abstracted_safe_sequences)

    return all_sequences, labels,feature_map

all_sequences, labels, feature_map = prepare_data(train_data,1)
safe_sequences, labels, feature_map = prepare_data(train_data,2)
unsafe_sequences, labels, feature_map = prepare_data(train_data,3)
#print(all_sequences)

#should i be using set here?? yes
#vocab = {tok: idx for idx, tok in enumerate(set(t for seq in all_sequences for t in seq))}
#print(vocab)
#numerical_sequences = [[vocab[tok] for tok in seq] for seq in all_sequences]

X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in all_sequences])
length_both = [len(seq) for seq in all_sequences]

Xs = np.concatenate([np.array(seq).reshape(-1, 1) for seq in safe_sequences])
lengths_safe = [len(seq) for seq in safe_sequences]

Xu = np.concatenate([np.array(seq).reshape(-1, 1) for seq in unsafe_sequences])
lengths_unsafe = [len(seq) for seq in unsafe_sequences]



from hmmlearn import hmm
model_both = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)
model_both.fit(X, length_both)

model_safe = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)
model_safe.fit(Xs, lengths_safe)


model_unsafe = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)
model_unsafe.fit(Xu, lengths_unsafe)


all_test_sequences, test_labels,feature_map2 = prepare_data(test_data,1)



#test_numerical_sequences = [[vocab[tok] for tok in seq] for seq in all_test_sequences]

log_likelihoods =  []
for seq, label in zip(all_test_sequences, test_labels):
      x = np.array(seq).reshape(-1,1)
      score = model_safe.score(x)
      log_likelihoods.append((score, label))
      #print(score)
      #result = "unsafe" if abs(score) < 1.5e-16 else "safe"
      #print(result)

safe_scores = [s for s, l in log_likelihoods if l == 0]
unsafe_scores = [s for s, l in log_likelihoods if l == 1]
print(safe_scores)
print(unsafe_scores)

#print(unsafe_scores)
#threshold = (np.mean(np.array(safe_scores)) + np.mean(np.array(unsafe_scores))) / 2
threshold = np.mean(np.array(unsafe_scores))
print(threshold)
all_scores = safe_scores+unsafe_scores
plt.xlim(min(all_scores) - 1e-16, max(all_scores) + 1e-16)

plt.xlabel("Log Likelihood")
plt.ylabel("Frequency")
plt.title("Log Likelihood Distribution (Zoomed In)")
plt.legend()
plt.show()

safe_scores_scaled = [s * 1e16 for s in safe_scores]
unsafe_scores_scaled = [s * 1e16 for s in unsafe_scores]

plt.hist(safe_scores_scaled, bins=20, alpha=0.5, label="Safe", color="green")
plt.hist(unsafe_scores_scaled, bins=20, alpha=0.5, label="Unsafe", color="red")

plt.xlabel("Log Likelihood × 1e-16")
plt.ylabel("Frequency")
plt.title("Rescaled Log Likelihood Distribution")
plt.legend()
plt.show()

#plt.hist(safe_scores, bins=20, alpha=0.5, label="Safe")
#plt.hist(unsafe_scores, bins=20, alpha=0.5, label="Unsafe")
#plt.legend()
#plt.title("HMM Score Distribution")
#plt.xlabel("Log Likelihood")
#plt.ylabel("Frequency")
#plt.show()
