import json
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import re
blank_cwes = [189, 264, 399, 16, 310, 59, 17, 255, 254, 18, 19, 284, 388, 1187, 918, 358, 320, 824, 693, 611, 706, 172, 668, 361, 281, 1021, 664, 275]


feature_map = {}
counter = 0


with open("cwe_with_features.json", 'r') as f:
    cwe_list = json.load(f)



with open("data_with_features_2_2.json",'r') as f:
    data = json.load(f)


def extract_tokens(code_line):
    token = re.findall(r'[a-zA-Z_][a-zA-Z0-9]*|\S', code_line)

    #print(token)
    return token

def prepare_data2(cwe):
    cwe_bad_sequences = []
    cwe_good_sequences = []
    ID = cwe['cwe_id']
    examples = cwe['examples']
    if examples:
        tokenized = []
        for example in examples:
            bad = example['bad']
            if bad:
                for line in bad:
                    tokens = extract_tokens(line)
                    for token in tokens:
                            if token not in feature_map:
                                feature_map[token] = len(feature_map)
                            tokenized.append(feature_map[token])

                            if tokenized:
                                cwe_bad_sequences.append(tokenized)

        data = {
            'id':ID,
            'encoded_bad':cwe_bad_sequences,

        }
        return data


def prepare_data(cwe):

    cwe_bad_sequences = []
    cwe_good_sequences = []
    ID = cwe['cwe_id']
    examples = cwe['examples']
    if examples:
        tokenized = []
        for example in examples:
            bad = example["bad_features"]
            if bad:

                for line in bad:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                if tokenized:
                    cwe_bad_sequences.append(tokenized)

            good = example["good_features"]
            if good:

                for line in good:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                if tokenized:
                    cwe_good_sequences.append(tokenized)
        data = {
            'id':ID,
            'encoded_bad':cwe_bad_sequences,
            'encoded_good':cwe_good_sequences
        }
        return data


trained_models = {}

encoded_cwes=[]
for cwe in cwe_list:
    result = prepare_data2(cwe)
    if not result:
        continue
    encoded_cwes.append(result)

trained_cwes = []
for items in encoded_cwes:
    cwe = items['id']
    bad_sequences = items['encoded_bad']

    if len(bad_sequences) <2:
        continue
    trained_cwes.append(cwe)
    X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in bad_sequences])
    lengths = [len(seq) for seq in bad_sequences]

    model = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)
    print(cwe)
    model.fit(X, lengths)
    trained_models[cwe] = model


def classify_sequence(seq, models, vocab):
    encoded_list = []
    for line in seq:
        sequence = extract_tokens(line)
        encoded = [vocab[token] for token in sequence if token in vocab]
        if not encoded:
            continue
        encoded_list.extend(encoded)
    if not encoded_list:
        return "Unclasfied",{}  # or a default label

    X = np.array(encoded_list).reshape(-1, 1)

    scores = {}
    for cwe, model in models.items():
        try:
            score = abs(model.score(X))
            scores[cwe] = score
        except:
            scores[cwe] = float('-inf')  # can't score
    sorted_scores = sorted(scores, key=scores.get)

    best_cwe = min(scores, key=scores.get)
    return best_cwe,sorted_scores[1]


def youre_not_buying_this_are_you(data, ID):
    tested_items = 0
    correctly_guessed = 0
    for items in data:
        try:
            data_id = items['cwe_id']#.strip('CWE-')
            
        except KeyError:

            continue
        if not data_id:
            continue
        if int(data_id) == ID:
            tested_items += 1
            sequences = items['before']

            predicted_cwe,score_map =classify_sequence(sequences,trained_models,feature_map)

            if predicted_cwe == ID:
                correctly_guessed += 1
#                print(f"predicted CWE: {predicted_cwe}")
    print(f"for CWE-{ID}")
    print(f"number of tests {tested_items}")
    print(f"correct number of guesses {correctly_guessed}")
    try:
        print(f"accuracy {float(correctly_guessed/tested_items)*100}%\n")
    except ZeroDivisionError:
        print("No tests\n")
print(trained_cwes)
for i in trained_cwes:
    youre_not_buying_this_are_you(data,i)





