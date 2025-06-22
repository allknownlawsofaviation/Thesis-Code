import json
import math
import numpy as np
#from hmmlearn import hmm
from pomegranate import hmm

from pomegranate.hmm import DenseHMM
from pomegranate.distributions import ConditionalCategorical
from sklearn.model_selection import train_test_split
import re
from collections import defaultdict
blank_cwes = [189, 264, 399, 16, 310, 59, 17, 255, 254, 18, 19, 284, 388, 1187, 918, 358, 320, 824, 693, 611, 706, 172, 668, 361, 281, 1021, 664, 275]


SAFE_ID = 0
UNSAFE_ID = 1
OUT_OF_VOCAB_ID = 2
feature_map = {"SAFE": SAFE_ID, "UNSAFE": UNSAFE_ID,"OUT_OF_VOCAB": OUT_OF_VOCAB_ID}
abstract_feature_map = {}
counter = 0
abstract = False

with open("cwe_with_features.json", 'r') as f:
    cwe_list = json.load(f)



with open("data_with_features_2_2.json",'r') as f:
    data = json.load(f)

def get_reserved_words():
    return set([
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "atomic_cancel",
    "atomic_commit",
    "atomic_noexcept",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char8_t",
    "char16_t",
    "char32_t",
    "class",
    "compl",
    "concept",
    "const",
    "consteval",
    "constexpr",
    "constinit",
    "const_cast",
    "continue",
    "contract_assert",
    "co_await",
    "co_return",
    "co_yield",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "reflexpr",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "synchronized",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq "])

initials = ['_', 'a', 'b', 'c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
set_initials = set(initials)

keywords = get_reserved_words()

def extract_tokens(code_line, keywords):
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9]*|\S', code_line)

    tokens = [t if t in keywords or (t[0] not in set_initials and t[0] <='~'and t[0] >=" ") else "variable" for t in tokens]
    return tokens

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
                    tokens = extract_tokens(line,keywords)
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
        tokens = extract_tokens(line,keywords)
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



def encode(data, final_token):
    encoded_data = defaultdict(list)
    for cwe, sequences in data.items():
        encoded = []

        for seq in sequences:
            if abstract:
                result = prepare_abstract_train_data(seq)
            else:
                result = prepare_train_data(seq)
            if result:
                result.append(final_token)
                encoded.append(result)

        encoded_data[cwe].extend(encoded)

        print(f"length encoded:{len(encoded)} and length sequences:{len(sequences)}")
    return encoded_data




def encoded(data, key,final_token):
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
        for seq in bad_sequences:
            seq.append(final_token)
        encoded_cwes[ID].extend(bad_sequences)

    return encoded_cwes

def combine(real_world_bad,real_world_good, encoded_cwes):
    combined = defaultdict(list)

    all_ids = set(encoded_cwes.keys()) | set(real_world_good.keys()) | set(real_world_bad.keys())

    for _id in all_ids:
        combined[_id] = real_world_good[_id]+ encoded_cwes[_id]+real_world_bad[_id]

    return combined

trained_cwes =[]

def massageX(sequences):
    lengths = [len(seq) for seq in sequences]
    length = max(lengths)
    extended = [seq+[seq[-1]]*(length-len(seq)) for seq in sequences]
    return length,  np.array(extended).reshape(-1,length,1)


def train(combined):
    trained_models = {}
    for cwe, bad_sequences in combined.items():
        if cwe != 119:
            continue

        if len(bad_sequences) <2:
            continue
        if cwe not in trained_cwes:
            trained_cwes.append(cwe)
        length, X = massageX(bad_sequences)
        print(X.shape)
        weights = [1]*X.shape[0]
        model = DenseHMM([ConditionalCategorical(), ConditionalCategorical(), ConditionalCategorical()])
        model.fit(X, sample_weight=[np.array(weights)])
   #     model.from_summaries()
        #print(cwe)
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
        sequence = extract_tokens(line,keywords)
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


def classify(seq, models, vocab, cwe):
    encoded_list = []
    for line in seq:
        sequence = extract_tokens(line,keywords)
        encoded = []
        for token in sequence:
            if token in vocab:
                encoded.append(vocab[token])
            if token not in vocab:
                encoded.append(OUT_OF_VOCAB_ID)
        if not encoded:
            continue
        encoded_list.extend(encoded)
    if not encoded_list:
        return -math.inf,-math.inf  # or a default label

    X = np.array(encoded_list+[UNSAFE_ID]).reshape(-1, 1)
    probability = models[cwe].predict_proba(X)
    print(probability)
    score, posts = models[cwe].score_samples(X)
    print(f"posts {posts[-1,:]}")
    X = np.array(encoded_list+[SAFE_ID]).reshape(-1, 1)


    safe_score, posts = models[cwe].score_samples(X)
    print(f"posts {posts[-1,:]}")
    return score,safe_score


def classify2(seq, models, vocab, cwe):
    encoded_list = []
    for line in seq:
        sequence = extract_tokens(line,keywords)
        encoded = []
        for token in sequence:
            if token in vocab:
                encoded.append(vocab[token])
            if token not in vocab:
                encoded.append(OUT_OF_VOCAB_ID)
        if not encoded:
            continue
        encoded_list.extend(encoded)
    if not encoded_list:
        return -math.inf,-math.inf  # or a default label

    X = np.array(encoded_list).reshape(-1, 1)

    final_state = models[cwe].predict(X)
    print(f"final_state={final_state}")
    probs, states = models[cwe].sample(n_samples =1, currstate=final_state[-1])
    print(f"probs {probs}, {states}")
    return probs[0,UNSAFE_ID],probs[0,SAFE_ID]


def youre_not_buying_any_of_this_are_you(good_data, bad_data, ID,trained_models):
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

            score,safe_score  = classify(seq,trained_models,feature_map, cwe)
            print(f"for the bad code, unsafe score: {score} safe score: {safe_score}")
            if score > safe_score:
                true_positives += 1
            else:
                false_negatives += 1
            positive_items += 1

    if not positive_items:
        return
    for cwe, sequences in good_data.items():
        if cwe != ID:
            continue
        for seq in sequences:

            score,safe_score  = classify(seq,trained_models,feature_map, cwe)
            print(f"for the good code, unsafe score: {score} safe score: {safe_score}")
            if score > safe_score:
                false_positives += 1
            else:
                true_negatives += 1
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


encoded_cwe_bad = encoded(cwe_list,'bad', UNSAFE_ID)

encoded_real_world_good_train = encode(real_world_good_train, SAFE_ID)
encoded_real_world_bad_train = encode(real_world_bad_train, UNSAFE_ID)
print(feature_map)
combined_bad = combine(encoded_real_world_bad_train,encoded_real_world_good_train, encoded_cwe_bad)

#trained_models_good = train(combined_good)
trained_models_bad = train(combined_bad)


print(trained_cwes)
print(len(feature_map))
#for i in trained_cwes:
youre_not_buying_any_of_this_are_you(real_world_good_test,real_world_bad_test,119,trained_models_bad)





