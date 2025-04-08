from hmmlearn import hmm
import numpy as np
import json

with open('unsafe_operations_train.json', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the content by adding square brackets to wrap all arrays

# Now load it as valid JSON
vulnerable_sequences = json.loads(content)


#Assign unique indices to each operation
operation_vocab = {op: idx for idx, seq in enumerate(vulnerable_sequences) for op in seq}

numerical_sequences =[[operation_vocab[op] for op in seq] for seq in vulnerable_sequences]

X=np.concatenate([np.array(seq).reshape(-1,1) for seq in numerical_sequences])
lengths = [len(seq) for seq in numerical_sequences]

model = hmm.MultinomialHMM(n_components=3, n_iter=100, random_state=42)
model.fit(X, lengths)


with open('safe_operations_test.json', 'r', encoding='utf-8') as test:
    test_content= test.read()

vulnerable_test_sequences = json.loads(test_content)
test1 = vulnerable_test_sequences[0]
print(test1)
new_numerical_sequence = np.array([[operation_vocab[op]] for op in test1 if op in operation_vocab])
new_sequence = new_numerical_sequence.reshape(-1,1)

score = model.score(new_sequence)
print('HMM score:', score)
