import json
import math
import numpy as np
import matplotlib.pyplot as plt
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import re
from collections import defaultdict
from collections import Counter
from gensim.models import Word2Vec
from tree_sitter import Language, Parser
from sklearn.metrics import f1_score
#import tree_sitter_cpp as tscpp
import pathlib, re
SAFE_ID = 0
UNSAFE_ID = 1
OUT_OF_VOCAB_ID = 2
feature_map = {"SAFE": SAFE_ID, "UNSAFE": UNSAFE_ID,"OUT_OF_VOCAB": OUT_OF_VOCAB_ID}

abstract = False
#abstract_feature_map = {"SAFE": SAFE_ID, "UNSAFE": UNSAFE_ID,"OUT_OF_VOCAB": OUT_OF_VOCAB_ID}
counter = 0


mother_of_all_sequences = []
#Language.build_library('build/my-languages.so','tree-sitter-c')

LIB = 'build/my-languages.so'
C_LANG = Language(LIB,'c')

parser = Parser(C_LANG)
parser.set_language(C_LANG)



with open("cwe_with_features.json", 'r') as f:
    cwe_list = json.load(f)



with open("data_with_features_2_2.json",'r') as f:
    data = json.load(f)

KEYWORDS = {
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
    "xor_eq ",
    "abort",
    "abs",
    "acos",
    "asctime",
    "asin",
    "assert",
    "atan",
    "atan2",
    "atexit",
    "atof",
    "atoi",
    "atol",
    "bsearch",
    "calloc",
    "ceil",
    "clearerr",
    "clock",
    "cos",
    "cosh",
    "ctime",
    "difftime",
    "div",
    "exit",
    "exp",
    "fabs",
    "fclose",
    "feof",
    "ferror",
    "fflush",
    "fgetc",
    "fgetpos",
    "fgets",
    "floor",
    "fmod",
    "fopen",
    "fprintf",
    "fputc",
    "fputs",
    "fread",
    "free",
    "freopen",
    "frexp",
    "fscanf",
    "fseek",
    "fsetpos",
    "ftell",
    "fwrite",
    "getc",
    "getchar",
    "getenv",
    "gets",
    "gmtime",
    "isalnum",
    "isalpha",
    "iscntrl",
    "isdigit",
    "isgraph",
    "islower",
    "isprint",
    "ispunct",
    "isspace",
    "isupper",
    "isxdigit",
    "labs",
    "ldexp",
    "ldiv",
    "localeconv",
    "localtime",
    "log",
    "log10",
    "longjmp",
    "malloc",
    "mblen",
    "mbstowcs",
    "mbtowc",
    "memchr",
    "memcmp",
    "memcpy",
    "memmove",
    "memset",
    "mktime",
    "modf",
    "perror",
    "pow",
    "printf",
    "putc",
    "putchar",
    "puts",
    "qsort",
    "raise",
    "rand",
    "realloc",
    "remove",
    "rename",
    "rewind",
    "scanf",
    "setbuf",
    "setjmp",
    "setlocale",
    "setvbuf",
    "signal",
    "sin",
    "sinh",
    "sprintf",
    "sqrt",
    "srand",
    "sscanf",
    "strcat",
    "strchr",
    "strcmp",
    "strcoll",
    "strcpy",
    "strcspn",
    "strerror",
    "strftime",
    "strlen",
    "strncat",
    "strncmp",
    "strncpy",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
    "strtod",
    "strtok",
    "strtol",
    "strtoll",
    "strtoul",
    "strxfrm",
    "system",
    "tan",
    "tanh",
    "time",
    "tmpfile",
    "tmpnam",
    "tolower",
    "toupper",
    "ungetc",
    "va_arg",
    "va_end",
    "va_start",
    "vfprintf",
    "vprintf",
    "vsprintf",
    "wcstombs",
    "wctomb"

    }

initials = ['_', 'a', 'b', 'c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
set_initials = set(initials)

#keywords = get_reserved_words()

def extract_tokens(code_line, keywords):
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9]*|\S', code_line)

    tokens = [t if t in keywords or (t[0] not in set_initials and t[0] <='~'and t[0] >=" ") else "variable" for t in tokens]
    return tokens




def walk(node, tokens,code):
    if node.type == 'call_expression':
        func_name = code[node.child_by_field_name('function').start_byte:
                        node.child_by_field_name('function').end_byte].decode()
        tokens.append(f"CALL_{func_name}")
    elif node.type == 'identifier':
        ident = code[node.start_byte:node.end_byte].decode()
        if ident not in KEYWORDS:
            tokens.append(ident)
        else:
            tokens.append(ident.upper())
    for child in node.children:
        walk(child, tokens,code)



def trees(sequence):
    together = '\n'.join(sequence)
    code =bytes(together,'utf-8')
    tree = parser.parse(code)
    root = tree.root_node
    token_seq = []
    walk(root, token_seq,code)
    #print(token_seq)
    return token_seq


def extract_file_content(code_list):

    """
    Cleans code by removing comments, annotations, and non-essential whitespace.
    Returns cleaned code as a single string.
    """
    cleaned_code_list = []
    for code in code_list:
    # Remove /* multi-line comments */
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    # Remove // single-line comments
        code = re.sub(r'//.*', '', code)
    # Remove preprocessor directives (#include, #define, etc.)
        code = re.sub(r'^\s*#.*', '', code, flags=re.MULTILINE)
    # Remove annotations like __attribute__, etc.
        code = re.sub(r'__\w+\(.*?\)', '', code)
    # Remove extra blank lines
        code = re.sub(r'\n\s*\n', '\n', code)
        code = code.strip()
        cleaned_code_list.append(code)
    return cleaned_code_list


def gen_tok_pattern():
    """
    Returns a compiled regex for C/C++ tokenization.
    This matches identifiers, numbers, operators, punctuation.
    """
    token_pattern = r"""
        [A-Za-z_][A-Za-z_0-9]*   # Identifiers/keywords
        | \d+\.\d+               # Floating point numbers
        | \d+                    # Integers
        | ==|!=|<=|>=|&&|\|\|    # Logical operators
        | \+\+|--|->             # Increment, decrement, pointer deref
        | [+*/%<>=&|^!-]         # Single-char operators
        | [{}()\[\],;.]          # Punctuation
    """
    return re.compile(token_pattern, re.VERBOSE)

def real_world(data, key):
    cwes = defaultdict(list)
    unknown = []
    for items in data:
        cwe = items.get('cwe_id')
        if cwe:
            cwes[cwe].append(items[key])
        else:
            data = {
                "commit_id":items['commit_id'],
                "code":items[key]
            }
            unknown.append(data)
    return cwes, unknown



def split_real_world(data):
    cwe_train = defaultdict(list)
    cwe_test = defaultdict(list)

    for cwe, samples in data.items():
        if len(samples) < 10:
            continue

        train, test = train_test_split(samples, test_size=0.5, random_state=42)
        cwe_train[cwe] = train
        cwe_test[cwe] = test
        print(f"CWE-{cwe} has total {len(samples)} and {len(cwe_train[cwe])} training samples")
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
                bad = extract_file_content(bad)
                regex_tokens = []
                for seq in bad:
                    regex_tokens.extend(gen_tok_pattern().findall(seq))
                bad_tokens = trees(bad)
                combined_tokens = bad_tokens[:]
                for tok in regex_tokens:
                    if tok not in combined_tokens:
                        combined_tokens.append(tok)
                mother_of_all_sequences.append(combined_tokens)
                for line in combined_tokens:
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



def prepare_tree_data(tree_tokens):
    tokenized = []
    for tok in tree_tokens:
        if tok not in feature_map:
            feature_map[tok] = len(feature_map)
        tokenized.append(feature_map[tok])

    if tokenized:
        return tokenized
    else:
        return None

def encode(data, final_token):
    encoded_data = defaultdict(list)
    for cwe, sequences in data.items():
        encoded = []

        for seq in sequences:
            regex_tokens = []
            sequ = extract_file_content(seq)
            for s in sequ:
                regex_tokens.extend(gen_tok_pattern().findall(s))
            tree_seq = trees(sequ)
            combined_tokens =tree_seq[:]
            for tok in regex_tokens:
                if tok not in combined_tokens:
                    combined_tokens.append(tok)

            mother_of_all_sequences.append(combined_tokens)
            result = prepare_tree_data(combined_tokens)
            if result:

                result.append(final_token)
                encoded.append(result)

        encoded_data[cwe].extend(encoded)

        print(f"length encoded:{len(encoded)} and length sequences:{len(sequences)}")
        print(f" length encoded_data[cwe]: {len(encoded_data[cwe])}") 
    return encoded_data




def encoded(data, key,final_token):
    encoded_cwes= defaultdict(list)

    for cwe in data:
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
    extended = np.concatenate([np.array(seq+[seq[-1]]*(length-len(seq))).reshape(-1,1) for seq in sequences])

    return [length for seq in sequences],  extended
#    return lengths, extended

def train(combined, states):
    trained_models = {}

    for cwe, bad_sequences in combined.items():

        if len(bad_sequences) <2:
            continue
        if cwe not in trained_cwes:
            trained_cwes.append(cwe)
        lengths, X = massageX(bad_sequences)



        model = hmm.MultinomialHMM(n_components=states[cwe], n_iter=100, random_state=42)
        model.fit(X, lengths)
        trained_models[cwe] = model
    return trained_models

def find_best_n_states(combined, vocab_size, min_states=2, max_states=10):
    best_states = {}
    for cwe,sequences in combined.items():
        best_aic = float('inf')
        best_n = min_states
        scores = {}
        if len(sequences) < 2:
            continue
        lengths, X = massageX(sequences)

        for n in range(min_states, max_states+1):
            model = hmm.MultinomialHMM(n_components=n, n_iter=100,algorithm="map", random_state=42)
#            model.n_features = vocab_size
            model.fit(X, lengths)

            logL = model.score(X, lengths)
#            k = n * (n - 1) + n * vocab_size  # params for transitions + emissions
            k = (n - 1) + n * (n - 1) + n * (vocab_size - 1)
            N = sum(lengths)
            bic = - 2 * logL + k * np.log(N)
            aic = -2* logL+2*k
            aic = model.aic(X, lengths)
            scores[n] = aic
            if aic < best_aic:
                best_aic = aic
                best_n = n
        best_states[cwe] = best_n
        print(f"CWE-{cwe}: best_n:{best_n},scores {scores} ")
    return best_states


def improved_tokenizer(sequences, vocab):
    regex_tokens = []
    sequ = extract_file_content(sequences)
    for s in sequ:
        regex_tokens.extend(gen_tok_pattern().findall(s))
    tree_seq = trees(sequ)
    combined_tokens =tree_seq[:]
    for tok in regex_tokens:
        if tok not in combined_tokens:
            combined_tokens.append(tok)
    return combined_tokens

def train_word2vec(all_sequences, vector_size=50, min_count=1, window=5):
    """
    Trains a Word2Vec model from tokenized sequences.
    """
    model = Word2Vec(sentences=all_sequences, vector_size=vector_size,window=window, min_count=min_count, workers=4)
    return model

def encode_with_w2v(seq, vocab, w2v_model, oov_id):
    tokens = improved_tokenizer(seq, vocab)
    encoded = []

    for t in tokens:
        if t in vocab:
            encoded.append(vocab[t])
        elif t in w2v_model.wv:  # In Word2Vec but not in HMM vocab
            # Find most similar token in vocab
            known_tokens = [tok for tok in vocab.keys() if tok in w2v_model.wv]
            if not known_tokens:
                encoded.append(oov_id)
                continue

            most_similar = max(
                known_tokens,
                key=lambda k: w2v_model.wv.similarity(t, k)
            )
            encoded.append(vocab[most_similar])
        else:
            encoded.append(oov_id)  # Complete fallback

    return encoded
def classify_sequence(seq, models, vocab, w2v_model):
    encoded_list = encode_with_w2v(seq, vocab, w2v_model, OUT_OF_VOCAB_ID)
    if not encoded_list:
        return None, None
    X = np.array(encoded_list).reshape(-1, 1)

    scores = []
    for cwe, model in models.items():
        score = abs(model.score(X))
        scores.append((score,cwe))
    sorted_scores = sorted(scores, key=lambda x: x[0])
    best_cwe = sorted_scores[0][1]
    return best_cwe,sorted_scores


def classify(seq, models, vocab, cwe, w2v_model):
    encoded_list = encode_with_w2v(seq, vocab, w2v_model, OUT_OF_VOCAB_ID)
    if not encoded_list:
        return -math.inf,-math.inf  # or a default label

    length = len(encoded_list)+1
#    print(f"length of sample {length}")
    X = np.array(encoded_list+[UNSAFE_ID]).reshape(-1, 1)

    unsafe_score, posts = models[cwe].score_samples(X, lengths =length)
#    print(f"safe posts {posts[-1,:]}")
    X = np.array(encoded_list+[SAFE_ID]).reshape(-1, 1)


    safe_score, posts = models[cwe].score_samples(X, lengths = length)
#    print(f"unposts {posts[-1,:]}")
    return unsafe_score,safe_score


def classify2(seq, models, vocab, cwe,n,w2v_model):
    encoded_list = encode_with_w2v(seq, vocab, w2v_model, OUT_OF_VOCAB_ID)
    if not encoded_list:
        return -math.inf,-math.inf  # or a default label

    X = np.array(encoded_list).reshape(-1, 1)

    final_state = models[cwe].predict(X)
    models[cwe].n_trials =len(encoded_list)
    #print(f"final_state={final_state}")
    final =final_state[-1]
#    print(final)
    probs, states = models[cwe].sample(n,random_state=None, currstate=final)
#    print(f"probs {probs},states {states}")
    return probs,states

def encode_test_sample(seq, vocab, w2v_model):
    encoded_list = encode_with_w2v(seq, vocab, w2v_model, OUT_OF_VOCAB_ID)
    if not encoded_list:
        return None,None  # or a default label
    else:
#        print(encoded_list)
        unk_ratio = encoded_list.count(OUT_OF_VOCAB_ID) / max(len(encoded_list),1)
        return encoded_list, unk_ratio


def state_usage_means(seq,model,cwe, n_samples=1000):
    model[cwe].n_trials = len(seq)
    _, states = model[cwe].sample(n_samples)
    unique, counts = np.unique(states, return_counts=True)
    return counts / counts.sum()  # fraction per state

def graph_hidden_statess(train_data,models):
    state_means_per_cwe = {}
    for cwe, seq in train_data.items():
        means = state_usage_means(seq,models,cwe, n_samples=5000)
        state_means_per_cwe[cwe] = means

# Plot all CWEs on one graph
    for cwe, means in state_means_per_cwe.items():
        plt.plot(range(len(means)), means, marker='o', label=f"CWE-{cwe}")
    plt.xlabel("Hidden State Index")
    plt.ylabel("Mean Fraction of Samples")
    plt.title("State Usage Means per CWE")
    plt.legend()
    plt.show()


def state_usage_means_real_data(seq_list, model):
    state_counts = np.zeros(model.n_components)
    total_states = 0
    for seq in seq_list:
        X = np.array(seq).reshape(-1, 1)
        states = model.predict(X)
        for s in states:
            state_counts[s] += 1
        total_states += len(states)
    return state_counts / total_states if total_states > 0 else state_counts

def graph_hidden_states(train_data, models):
    state_means_per_cwe = {}
    for cwe, seq_list in train_data.items():
        means = state_usage_means_real_data(seq_list, models[cwe])
        state_means_per_cwe[cwe] = means

    # Plot all CWEs on one graph
    for cwe, means in state_means_per_cwe.items():
        plt.plot(range(len(means)), means, marker='o', label=f"CWE-{cwe}")
    plt.xlabel("Hidden State Index")
    plt.ylabel("Mean Fraction of Occurrences")
    plt.title("State Usage per CWE (Decoded from Real Data)")
    plt.legend()
    plt.show()

def z_score_confidence(good_data,bad_data, model, vocab, data_type,w2v_model):
    cwe_mean = {}
    cwe_std = {}
    for cwe, sequences in good_data.items():

        safe_score_list = []
        for seq in sequences:
            match data_type:
                case "train":
                    X = np.array(seq).reshape(-1, 1)
                case "test":
                    encoded_sequence, unk_ratio = encode_test_sample(seq, vocab,w2v_model)
                    if encoded_sequence:
                        X = np.array(encoded_sequence).reshape(-1, 1)
                    else:
                        continue
            score = model[cwe].score(X)
            safe_score_list.append(score)
        safe_scores = np.array(safe_score_list)
        mean = np.mean(safe_scores)
        std = np.std(safe_scores)
        if std == 0:
            std = 1
        cwe_mean[cwe] = mean
        cwe_std[cwe] = std
    results = {}
    for cwe, sequences in bad_data.items():
        count =0
        high_unk_tok_count = 0
        for seq in sequences:
            match data_type:
                case "train":
                    X = np.array(seq).reshape(-1, 1)
                case "test":
                    encoded_sequence, unk_ratio = encode_test_sample(seq, vocab, w2v_model)
                    if encoded_sequence:
                        X = np.array(encoded_sequence).reshape(-1, 1)
                    else:
                        continue
                    if unk_ratio > 0.4:
#                        print(unk_ratio)
                        high_unk_tok_count +=1
            score = model[cwe].score(X)
            z = (score-float(cwe_mean[cwe]))/ float(cwe_std[cwe])
#                print(f"CWE-{cwe}: score={score:.3f}, mean={cwe_mean[cwe]:.3f}, std={cwe_std[cwe]:.3f}, z={z:.2f}")
            if abs(z) > 3:
                count +=1
        outlier_density = count/max(len(sequences),1)*100.0
        OOV_density = high_unk_tok_count/max(len(sequences),1)*100.0
        results[cwe] = (outlier_density,OOV_density)
    return results




def identify_unsafe_state(ID, good_data, bad_data, model, vocab, w2v_model):
    """
    Identify which hidden state is most correlated with unsafe sequences for this CWE.
    """
    state_counts_safe = Counter()
    state_counts_unsafe = Counter()
    for sequence in good_data.get(ID, []):
        encoded = encode_with_w2v(sequence, feature_map,w2v_model, OUT_OF_VOCAB_ID)
        if not encoded:
            continue
        X = np.array(encoded).reshape(-1, 1)
        states = model.predict(X)
        state_counts_safe.update(states)

    for sequence in bad_data.get(ID,[]):
        encoded = encode_with_w2v(sequence, feature_map, w2v_model, OUT_OF_VOCAB_ID)
        if not encoded:
            continue

        X = np.array(encoded).reshape(-1, 1)
        states = model.predict(X)
        state_counts_unsafe.update(states)

    unsafe_ratios ={}
    for s in set(state_counts_safe.keys()) | set(state_counts_unsafe.keys()):
        total = state_counts_safe[s] + state_counts_unsafe[s]
        if total > 0:
            unsafe_ratios[s] = state_counts_unsafe[s] / total
        else:
            unsafe_ratios[s] = 0.0

    if not unsafe_ratios:
        print(f"[WARN] No states found for CWE-{ID}")
        return None, {}


    unsafe_state = max(unsafe_ratios, key=unsafe_ratios.get)
    return unsafe_state, unsafe_ratios

def test_with_state_mapping(good_data, bad_data, ID, model, vocab, w2v_model,states):
    # Step 1: figure out unsafe state for CWE
    unsafe_state, state_ratios = identify_unsafe_state(ID, good_data, bad_data, model, vocab,w2v_model)
    print(f"[DEBUG] CWE-{ID} unsafe state: {unsafe_state}, ratios: {state_ratios}")
    positive_items = negative_items = 0
    false_positives = false_negatives = true_positives = true_negatives = 0

    for sequence in bad_data.get(ID,[]):
        encoded = encode_with_w2v(sequence, vocab, w2v_model, OUT_OF_VOCAB_ID)
        if not encoded:
            continue
        X = np.array(encoded).reshape(-1, 1)
        states = model.predict(X)
        most_common = Counter(states).most_common(1)[0][0]
        if most_common == unsafe_state:
            true_positives += 1
        else:
            false_negatives += 1
        positive_items += 1

    for sequence in good_data.get(ID,[]):
        encoded = encode_with_w2v(sequence, vocab, w2v_model, OUT_OF_VOCAB_ID)
        if not encoded:
            continue
        X = np.array(encoded).reshape(-1, 1)
        states = model.predict(X)
        most_common = Counter(states).most_common(1)[0][0]
        if most_common == unsafe_state:
            false_positives += 1
        else:
            true_negatives += 1
        negative_items += 1

    print("Test With State Mapping")
    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items,states)

    F1 = calculate_F1(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)
    return F1

def calculate_F1(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items):
    # Accuracy (not actually used in F1, but fine to compute)
    total = true_positives + true_negatives + false_positives + false_negatives
    accuracy = (true_positives + true_negatives) / total if total > 0 else 0.0 
    # Recall
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    # Precision
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    # F1 score
    F1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return F1

def print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items, states):
#    print(f"CWE-{ID}:")

#    print(f"false positives {false_positives}")
#    print(f"false negatives {false_negatives}")
    if true_positives+true_negatives == 0:
        accuracy = 0.0
    else:
        accuracy = (true_positives+true_negatives)/(true_negatives+false_positives+false_negatives+true_positives)
#    print(f"best accuracy {accuracy*100.0}%")
    if true_positives ==0:
        recall =0.0
    else:
        recall = (true_positives)/(true_positives+false_negatives)
    if true_positives == 0:
        precision =0.0
    else:
        precision = (true_positives) /(true_positives+false_positives)
    F1 = (2*precision*recall)/(precision+recall) if (precision +recall) >0 else 0.0
    num_examples = positive_items+negative_items
#    print(f"recall {recall*100.0}%, precision {precision*100.0}%")
#    print(f"F1 score: {F1}\n")
    print(f"{ID}&{states}&{positive_items}&{negative_items}&{false_positives}&{false_negatives}&{accuracy*100.0:.2f}&{recall*100.0:.2f}&{precision*100.0:.2f}&{F1:.2f}\\\\")



def test_with_rank(good_data,bad_data, ID, models, w2v_model, thresh,states):

    positive_items = 0
    negative_items = 0
    num_examples = 0
    false_positives = 0
    false_negatives = 0
    true_positives = 0
    true_negatives = 0
    results = []
    for sequence in bad_data.get(ID, []):
        best_cwe, sorted_scores = classify_sequence(sequence,models,feature_map, w2v_model)
        if best_cwe and sorted_scores:
            positive_items +=1
            if best_cwe ==ID:
                true_positives +=1
            for rank, (score, cwe) in enumerate(sorted_scores, start=1):
                if cwe == ID:
                    is_within_rank = rank <= thresh
            if is_within_rank:
                    true_positives += 1
            else:
                false_negatives += 1

        else:
            continue

    if not positive_items:
        return
    for sequence in good_data.get(ID,[]):
        best_cwe,sorted_scores  = classify_sequence(sequence,models,feature_map, w2v_model)

        if best_cwe and sorted_scores:

            negative_items +=1

            for rank, (score, cwe) in enumerate(sorted_scores, start=1):
                if cwe == ID:
                    is_within_rank = rank <= thresh
            if is_within_rank:
                false_positives +=1
            else:
                true_negatives += 1

        else:
            continue
    print("Rank method:")
    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items,states)
    F1 = calculate_F1(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)
    return F1

def find_best_n_states_f1(train_data,good_data, bad_data, vocab, w2v_model, min_states=2, max_states=10, n_samples=1000):
    best_states = {}

    for cwe, sequences in train_data.items():

        if len(sequences) <2:
            continue
        lengths, X = massageX(sequences)

        best_f1 = -1
        best_n = min_states

        for n in range(min_states, max_states + 1):
            model = hmm.MultinomialHMM(n_components=n, n_iter=100, random_state=42)

            model.fit(X, lengths)

            # Identify unsafe state
            F1= test_with_state_mapping(good_data, bad_data, cwe,model,vocab,w2v_model, n)

            # Validation step

            if F1 > best_f1:
                best_f1 =F1
                best_n = n

        best_states[cwe] = best_n
        print(f"CWE-{cwe}: best_n={best_n}, best_f1={best_f1:.3f}")

    return best_states

def find_best_n_states_rank(combined, good_data, bad_data, vocab, w2v_model,
                            min_states=3, max_states=10, rank_thresh=2):
    """
    combined: dict[CWE] -> list of encoded training sequences
    good_data/bad_data: dict[CWE] -> list of *raw* safe/unsafe sequences for testing
    vocab: feature_map
    w2v_model:  trained word2vec model
    rank_thresh: rank threshold for 'positive' match
    """
    best_states = {}

    for cwe in combined.keys():
        if cwe not in good_data or cwe not in bad_data:
            continue
        if len(combined[cwe]) < 2:
            continue

        # Prepare training data for this CWE
        lengths, X = massageX(combined[cwe])

        best_f1 = -1
        best_n = min_states

        for n in range(min_states, max_states + 1):
            model = hmm.MultinomialHMM(n_components=n, n_iter=100, random_state=42)
            model.fit(X, lengths)

            # Build model dict so classify_sequence can work
            models = {cwe: model}

            # Run your rank-based test
            f1 = test_with_rank(good_data, bad_data, cwe, models, w2v_model, rank_thresh, n)

            if f1 is not None and f1 > best_f1:
                best_f1 = f1
                best_n = n

        best_states[cwe] = best_n
        print(f"CWE-{cwe}: best_n={best_n}, best_f1={best_f1:.3f}")

    return best_states

def raw_tokens(data):

    #split data into before patch and after patch
    real_world_bad, unknown_bad = real_world(data,'before')
    real_world_good, unknown_good = real_world(data,'after')
    #split before and after patch into training data and testing data
    print("Splitting good...")
    real_world_good_train, real_world_good_test = split_real_world(real_world_good)
    print("Splitting bad...")
    real_world_bad_train, real_world_bad_test = split_real_world(real_world_bad)

    #encode he CWE data
    encoded_cwe_bad = encoded(cwe_list,'bad', UNSAFE_ID)
    #encode he training data
    encoded_real_world_good_train = encode(real_world_good_train, SAFE_ID)
    encoded_real_world_bad_train = encode(real_world_bad_train, UNSAFE_ID)
    combined_bad = combine(encoded_real_world_bad_train,encoded_real_world_good_train, encoded_cwe_bad)
    real_world_bad, unknown_bad = real_world(data,'before')
    #find best states space and train models:

#    trained_models_bad = train(combined_bad,5)
    w2v_model = train_word2vec(mother_of_all_sequences, vector_size=50, min_count=1, window=5)
    best_states_rank = find_best_n_states_rank(combined_bad, real_world_good_test, real_world_bad_test, feature_map, w2v_model)
    best_n_states_map =  find_best_n_states_f1(combined_bad, real_world_good_test, real_world_bad_test,feature_map,w2v_model)
    print(len(trained_cwes))
    print(len(feature_map))
    trained_models_rank = train(combined_bad, best_states_rank)
    trained_models_map = train(combined_bad, best_n_states_map)
#    print("Confidence Ratios Test data:")
#    results_test_data  = z_score_confidence(real_world_good_test, real_world_bad_test, trained_models_bad, feature_map,"test",w2v_model)
#    print("Confidence Ratios Training data:")
#    results_train_data = z_score_confidence(encoded_real_world_good_train, encoded_real_world_bad_train, trained_models_bad, feature_map,"train", w2v_model)
#    for cwe, result in results_test_data.items():
#        print(f"{cwe}&{results_train_data[cwe][0]:.2f}&{result[0]:.2f}&{result[1]:.2f}\\\\")
    graph_hidden_states(combined_bad,trained_models_bad)
    for cwe in best_states_rank.keys():
        test_with_rank(real_world_good_test,real_world_bad_test,cwe, trained_models_rank[cwe], w2v_model,2,best_states_rank[cwe])
    for cwe in best_n_states_map.keys():
        test_with_state_mapping(real_world_good_test, real_world_bad_test, cwe, trained_models_map[cwe], w2v_model,best_n_states_map[cwe])
#    find_unknown(unknown_bad,trained_models_bad)

def find_unknown(unknown,models):
    for items in unknown:
        code = items['code']
        if len(code) <5:
            continue
        commit = items['commit_id']
        candidates = []

        best,sorted_scores = classify_sequence(code,models,feature_map)
        for cwe in trained_cwes:

            unsafe_scores,safe_scores = classify(code,models,feature_map,cwe)
#            probs,sequences = classify2(code,models,feature_map,cwe,30)
#            most = max(set(sequences), key=sequences.tolist().count) 
            encoded_sequence,_  = encode_test_sample(code,feature_map)
            if encoded_sequence:

                X = np.array(encoded_sequence).reshape(-1, 1)
                state= models[cwe].predict(X, lengths=len(encoded_sequence))
                final_state = state[-1]
                if final_state ==1:
                    candidates.append(cwe)
       # try:
        try:
            print(f"for commit: {commit} lowest scores are:{' '.join(str(sorted_scores[i][1]) for i in range(5))}")
        except KeyError:
            print(sorted_scores)
        print(f"for commit: {commit} candidates are:{candidates}")





raw_tokens(data)
