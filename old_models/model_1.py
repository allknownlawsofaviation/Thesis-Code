import json
import re
import numpy as np
from hmmlearn import hmm
import matplotlib
from collections import defaultdict
import matplotlib.pyplot as plt
matplotlib.use('TkAgg') 


with open('change_train.json', 'r',encoding = 'utf-8') as f:
    content =   json.load(f)

with open('change_test.json', 'r', encoding='utf-8') as f:
    test_content = json.load(f)

"""pre-process data"""
sequences = []
labels =[]

for entry in content:
    for line in entry['removed_lines']:
        sequences.append(line)
        labels.append(1)
    for line in entry['added_lines']:
        sequences.append(line)
        labels.append(0)


"""Tokenize operations"""
def extract_tokens(code_line):
    return re.findall(r'[a-zA-Z_][a-zA-Z0-9]*|\S', code_line)


""""create vocabulary"""
vocab = defaultdict(lambda: len(vocab))
numerical_sequences_train = []
counter = 0


for code in sequences:
    tokens = extract_tokens(code)
    seq = []
    for tok in tokens:
        if tok not in vocab:
            vocab[tok] = counter 
            counter +=1
        seq.append(vocab[tok])
    numerical_sequences_train.append(seq)


"""prepare for trainning"""
X = np.concatenate([np.array(seq).reshape(-1,1) for seq in numerical_sequences_train])
lengths = [len(seq) for seq in numerical_sequences_train]

"""train"""
model = hmm.MultinomialHMM(n_components = 4, n_iter = 100, random_state = 42)
model.fit(X, lengths)


"""evaluate"""

log_likelihoods = []
test_sequences = []
test_labels = []

for entry in test_content:
#    for line in entry['removed_lines']:
#        test_sequences.append(line)
#        test_labels.append(1)
    for line in entry['added_lines']:
        test_sequences.append(line)
        test_labels.append(1)
numerical_sequences_test = []
valid_test_labels = []
for i, code  in  enumerate(test_sequences):
    tokens = extract_tokens(code)
    seq = [vocab[token] for token in tokens if token in vocab]
    if seq:
        numerical_sequences_test.append(seq)
        valid_test_labels.append(test_labels[i])

for seq, label in zip(numerical_sequences_test, valid_test_labels):
    x = np.array(seq).reshape(-1,1)
    score = model.score(x)
    print(score)
    log_likelihoods.append((score, label))

safe_scores = [s for s,l in log_likelihoods if l == 0]
unsafe_scores = [s for s, l in log_likelihoods if l == 1]
print(safe_scores)
print('safe scores printed')
print(unsafe_scores)

plt.hist(safe_scores, bins=20, alpha=0.5, label="Safe", color="green")
plt.hist(unsafe_scores, bins=20, alpha=0.5, label="Unsafe", color="red")
plt.xlabel("Log Likelihood")
plt.ylabel("Frequency")
plt.title("Log Likelihood Distribution (Test Set)")
plt.legend()
plt.show()
