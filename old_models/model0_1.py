from hmmlearn import hmm
import numpy as np
import json
# Create vocab mapping for both safe and unsafe operationis

with open('unsafe_operations_train.json', 'r', encoding='utf-8') as unsafe_file:
    unsafe_content = unsafe_file.read()

with open('safe_operations_train.json', 'r', encoding='utf-8') as safe_file:
    safe_content = safe_file.read()

removed_lines =json.loads(unsafe_content)
added_lines = json.loads(safe_content)




operation_vocab_unsafe = {op: idx for idx, seq in enumerate(removed_lines) for op in seq}

operation_vocab_safe = {op: idx for idx, seq in enumerate(added_lines) for op in seq}

# Convert removed (unsafe) and added (safe) sequences into numerical format
unsafe_sequences = [[operation_vocab_unsafe[op] for op in seq] for seq in removed_lines]
safe_sequences = [[operation_vocab_safe[op] for op in seq] for seq in added_lines]

# Format data for HMM training
X_unsafe = np.concatenate([np.array(seq).reshape(-1, 1) for seq in unsafe_sequences])
lengths_unsafe = [len(seq) for seq in unsafe_sequences]

X_safe = np.concatenate([np.array(seq).reshape(-1, 1) for seq in safe_sequences])
lengths_safe = [len(seq) for seq in safe_sequences]

# Train separate HMMs
unsafe_model = hmm.MultinomialHMM(n_components=3, n_iter=100, random_state=42)
unsafe_model.fit(X_unsafe, lengths_unsafe)

safe_model = hmm.MultinomialHMM(n_components=3, n_iter=100, random_state=42)
safe_model.fit(X_safe, lengths_safe)
