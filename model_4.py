import json
import math
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import re
from collections import defaultdict
blank_cwes = [189, 264, 399, 16, 310, 59, 17, 255, 254, 18, 19, 284, 388, 1187, 918, 358, 320, 824, 693, 611, 706, 172, 668, 361, 281, 1021, 664, 275]


feature_map = {}
abstract_feature_map = {}
counter = 0
abstract = False

with open("cwe_with_features.json", 'r') as f:
    cwe_list = json.load(f)



with open("data_with_features_2_2.json",'r') as f:
    data = json.load(f)




def extract_tokens(code_line):
    token = re.findall(r'[a-zA-Z_][a-zA-Z0-9]*|\S', code_line)

    #print(token)
    return token

def real_world(data, key):
    cwes = defaultdict(list)
    for items in data:
        try:
            cwe = items['cwe_id']
            cwes[cwe].append(items[key])

        except KeyError:
            continue
    return cwes



def split_real_world(data):
    cwe_train = defaultdict(list)
    cwe_test = defaultdict(list)

    for cwe, samples in data.items():
        if len(samples) < 10:
            continue

        train, test = train_test_split(samples, test_size=0.5, random_state=42)
        cwe_train[cwe] = train
        cwe_test[cwe] = test
        print(f"CWE-{cwe} has {len(samples)}")
    return cwe_train, cwe_test



def prepare_abstract_data(cwe,key):
    cwe_sequences = []

    ID = cwe['cwe_id']
    examples = cwe['examples']
    if examples:
        tokenized = []
        for example in examples:
            bad = example[key]
            if bad:
                for line in bad:
                    if line not in feature_map:
                        feature_map[line] = len(feature_map)
                    tokenized.append(feature_map[line])

                    if tokenized:
                        cwe_sequences.append(tokenized)

        data = {
            'id':ID,
            'encoded_bad':cwe_sequences,

        }
        return data


def prepare_data2(cwe, key):
    cwe_bad_sequences = []

    ID = cwe['cwe_id']
    examples = cwe['examples']
    if examples:
        tokenized = []
        for example in examples:
            bad = example[key]
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


def prepare_train_data(sequences):
    tokenized = []
    for line in sequences:
        tokens = extract_tokens(line)
        for token in tokens:
            if token not in feature_map:
                feature_map[token] = len(feature_map)
            tokenized.append(feature_map[token])

    if tokenized:
        return tokenized
    else:
        return None


def prepare_abstract_train_data(sequences):
    tokenized = []
    for line in sequences:
        if line not in feature_map:
            feature_map[line] = len(feature_map)
        tokenized.append(feature_map[line])

    if tokenized:
        return tokenized
    else:
        return None



def encode(data): #encode sequences from real world data
    encoded_data = defaultdict(list)
    for cwe, sequences in data.items():
        encoded = []

        for seq in sequences:
            if abstract:
                result = prepare_abstract_train_data(seq)
            else:
                result = prepare_train_data(seq)
            if result:
                encoded.append(result)

        encoded_data[cwe].extend(encoded)

        print(f"length encoded:{len(encoded)} and length sequences:{len(sequences)}")
    return encoded_data




def encoded(data, key): #encode sequences scraped from cwe website
    encoded_cwes= defaultdict(list)

    for cwe in data:
        if not abstract:
            result = prepare_data2(cwe, key)
        else:
            result = prepare_abstract_data(cwe, key)
        if not result:
            continue
        ID = result['id']
        bad_sequences = result['encoded_bad']
        encoded_cwes[ID].extend(bad_sequences)

    return encoded_cwes

def combine(real_world, encoded_cwes):
    combined = defaultdict(list)

    all_ids = set(encoded_cwes.keys()) | set(real_world.keys())

    for _id in all_ids:
        if _id == 119:
            print(f" length real world:{len(real_world[_id])} length cwes: {len(encoded_cwes[_id])}")
        combined[_id] = real_world[_id]+ encoded_cwes[_id]

    return combined

trained_cwes =[]




def train(combined):
    trained_models = {}
    for cwe, bad_sequences in combined.items():


        if len(bad_sequences) <2:
            continue
        if cwe not in trained_cwes:
            trained_cwes.append(cwe)
        X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in bad_sequences])
        lengths = [len(seq) for seq in bad_sequences]
        if cwe == 119:
            print(f"lengths: {len(lengths)}")
        model = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)
        #print(cwe)
        model.fit(X, lengths)
        trained_models[cwe] = model
    return trained_models


def train_saftey_tester(combined):
    X = np.concatenate([np.array(seq).reshape(-1,1) for sequences in combined.values() for seq in sequences])
    lengths = [len(seq) for sequences in combined.values() for seq in sequences]

    model = hmm.MultinomialHMM(n_components=4, n_iter=200, random_state=42)
    model.fit(X, lengths)
    return model


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

    scores = []
    for cwe, model in models.items():
        try:
            score = abs(model.score(X))
            scores.append((score,cwe))
        except:
            continue  # can't score
    sorted_scores = sorted(scores, key=lambda x: x[0])

    best_cwe =scores[0][1]
    return best_cwe,sorted_scores[1][1]


def classify(seq, models, vocab, cwe, safe_model):
    encoded_list = []
    for line in seq:
        sequence = extract_tokens(line)
        encoded = [vocab[token] for token in sequence if token in vocab]
        if not encoded:
            continue
        encoded_list.extend(encoded)
    if not encoded_list:
        return -math.inf,-math.inf  # or a default label

    X = np.array(encoded_list).reshape(-1, 1)

    score = models[cwe].score(X)
    safe_score = safe_model[cwe].score(X)
    return score,safe_score


def youre_not_buying_any_of_this_are_you(good_data, bad_data, ID,trained_models, safe_model):
    positive_items = 0
    negative_items = 0
    num_examples = 0
    false_positives = 0
    false_negatives = 0
    true_positives = 0
    true_negatives = 0
    results = []
    for cwe, sequences in bad_data.items():
        if cwe != ID:
            continue
        for seq in sequences:

            score,safe_score  = classify(seq,trained_models,feature_map, cwe, safe_model)

            if abs(score) < abs(safe_score):
                true_positives += 1
                print(f"for the bad code, unsafe score: {score} safe score: {safe_score} true positive")
            else:
                false_negatives += 1

                print(f"for the bad code, unsafe score: {score} safe score: {safe_score} false negative")
            positive_items += 1

    if not positive_items:
        return
    for cwe, sequences in good_data.items():
        if cwe != ID:
            continue
        for seq in sequences:

            score,safe_score  = classify(seq,trained_models,feature_map, cwe, safe_model)

            if abs(score) < abs(safe_score):
                false_positives += 1

                print(f"for the good code, unsafe score: {score} safe score: {safe_score} false positive")
            else:
                true_negatives += 1

                print(f"for the good code, unsafe score: {score} safe score: {safe_score} true negative")
            negative_items +=1

    print(f"for CWE-{ID}")
    print(f"number of positive samples {positive_items}")

    print(f"number of negatives samples {negative_items}")

    print(f"false positives {false_positives}")
    print(f"false negatives {false_negatives}")
    accuracy = (true_positives+true_negatives) *100.0 / max(positive_items+negative_items,1)
    print(f"best accuracy {accuracy}%")
    recall = (true_positives * 100.0) / max(positive_items, 1)
    precision = (true_negatives * 100.0) / max(negative_items, 1)
    print(f"recall {recall}%, precision {precision}%\n")



def youre_not_buying_this_are_you(data, ID, trained_models):
    tested_items = 0
    correctly_guessed = 0
    for cve, sequences in data.items():
        if cve == ID:
            for seq in sequences:
                tested_items +=1
                predicted_cwe,score_map =classify_sequence(seq,trained_models,feature_map)
               # print(predicted_cwe)
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





real_world_bad = real_world(data,'before')
real_world_good = real_world(data,'after')

real_world_good_train, real_world_good_test = split_real_world(real_world_good)

real_world_bad_train, real_world_bad_test = split_real_world(real_world_bad)


encoded_cwe_bad = encoded(cwe_list,'bad')

encoded_real_world_good_train = encode(real_world_good_train)
encoded_real_world_bad_train = encode(real_world_bad_train)

combined_bad = combine(encoded_real_world_bad_train, encoded_cwe_bad)

#trained_models_good = train(combined_good)
trained_models_bad = train(combined_bad)
trained_safe_model = train(encoded_real_world_good_train)

print(trained_cwes)
print(len(feature_map))
#for i in trained_cwes:
youre_not_buying_any_of_this_are_you(real_world_good_test,real_world_bad_test,119,trained_models_bad, trained_safe_model)





