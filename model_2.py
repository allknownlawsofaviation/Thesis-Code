import json
import re
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt


with open('data_with_features_2.json', 'r') as f:
    data = json.load(f)

train_data, test_data = train_test_split(data, test_size=0.2, random_state= 42)




def prepare_data(data, mode,key):

    abstracted_safe_sequences = []
    abstracted_unsafe_sequences = []
    feature_map = {}
    sample =0
    match mode:
        case 1:
            for content in data:
                if content.get('vuln'):
                    if key in content['vuln'] or key =="all":
                        sample +=1
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
                    else:
                        continue
                else:
                    continue
                all_sequences = abstracted_safe_sequences + abstracted_unsafe_sequences
                labels = [0] * len(abstracted_safe_sequences) + [1] * len(abstracted_unsafe_sequences)
            print(f"samples: {sample}")

        case 2:
            for content in data:
                if content.get('vuln'):
                    if  key in content['vuln']or key =="all":
                        tokenized = []
                        for line in content['safe_features']:
                            if line not in feature_map:
                                feature_map[line] = len(feature_map)
                            tokenized.append(feature_map[line])

                        if tokenized:
                            abstracted_safe_sequences.append(tokenized)
                        tokenized = []
                    else:
                        continue
                else:
                    continue
                all_sequences = abstracted_safe_sequences
                labels = [0] *len(abstracted_safe_sequences)

        case 3:
            for content in data:
                if content.get('vuln'):
                    if key in content['vuln'] or key =="all" or content['vuln'] is None:
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
                    else:
                        continue
                else:
                    continue
                all_sequences = abstracted_unsafe_sequences
                labels = [1] * len(abstracted_unsafe_sequences)




    return all_sequences, labels,feature_map


def train(data,mode,key):
    sequences,labels, feature_map = prepare_data(data,mode,key)

    X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in sequences])
    lengths = [len(seq) for seq in sequences]


    model = hmm.MultinomialHMM(n_components=2, n_iter=100, random_state=42)
    model.fit(X, lengths)

    return model


def test(model_safe,model_unsafe,test_data,key):

    all_test_sequences, test_labels,feature_map2 = prepare_data(test_data,1,key)
    positive_items = 0
    negative_items = 0
    num_examples = 0
    false_positives = 0
    false_negatives = 0
    true_positives = 0
    true_negatives = 0
    log_likelihoods =  []
    for seq, label in zip(all_test_sequences, test_labels):
        x = np.array(seq).reshape(-1,1)
        safe_score = model_safe.score(x)
        unsafe_score =model_unsafe.score(x)
        if label == 1:
            if abs(unsafe_score) < abs(safe_score):
                true_positives += 1

            else:
                false_positives += 1
            positive_items +=1

        if label == 0:
            if abs(safe_score) < abs(unsafe_score):
                true_negatives += 1
            else:
                false_negatives += 1
            negative_items += 1
        log_likelihoods.append((safe_score, label))
    print(f"number of positive samples {positive_items}")

    print(f"number of negatives samples {negative_items}")

    print(f"false positives {false_positives}")
    print(f"false negatives {false_negatives}")
    accuracy = (true_positives+true_negatives) *100.0 / max(positive_items+negative_items,1)
    print(f"best accuracy {accuracy}%")
    recall = (true_positives * 100.0) / max(positive_items, 1)
    precision = (true_negatives * 100.0) / max(negative_items, 1)
    F1 = (2*precision*recall)/max(precision+recall,1)
    num_examples = positive_items+negative_items
    print(f"recall {recall}%, precision {precision}%\n")
    print(f"{key}&{num_examples}&{false_positives}&{false_negatives}&{accuracy:.2f}&{recall:.2f}&{precision:.2f}&{F1:.2f}\\\\")
    return log_likelihoods




def plot(log_likelihoods): 
    safe_scores = [s for s, l in log_likelihoods if l == 0]
    unsafe_scores = [s for s, l in log_likelihoods if l == 1]

    threshold = (np.mean(np.array(safe_scores)) + np.mean(np.array(unsafe_scores))) / 2


#    print(threshold)
    all_scores = safe_scores+unsafe_scores



    safe_scores_scaled = [s * 1e16 for s in safe_scores]
    unsafe_scores_scaled = [s * 1e16 for s in unsafe_scores]

    plt.hist(safe_scores_scaled, bins=20, alpha=0.5, label="Safe", color="green")
    plt.hist(unsafe_scores_scaled, bins=20, alpha=0.5, label="Unsafe", color="red")

    plt.xlabel("Log Likelihood × 1e-16")
    plt.ylabel("Frequency")
    plt.title(f"Rescaled Log Likelihood Distribution for {key}")
    plt.legend()
    plt.show()


def test_all(key):
    safe_model= train(train_data,2,key)
    unsafe_model = train(train_data,3,key)

    log_likelihoods = test(safe_model, unsafe_model, test_data,key)
    plot(log_likelihoods)

keys = ["all","DoS", "Exec Code", "Overflow", "+Info","Mem. Corr.","+Priv",]
for key in keys:
    test_all(key)
#plt.xlim(min(all_scores) - 1e-16, max(all_scores) + 1e-16)
#plt.hist(safe_scores, bins=20, alpha=0.5, label="Safe")
#plt.hist(unsafe_scores, bins=20, alpha=0.5, label="Unsafe")
#plt.legend()
#plt.title("HMM Score Distribution")
#plt.xlabel("Log Likelihood")
#plt.ylabel("Frequency")
#plt.show()
