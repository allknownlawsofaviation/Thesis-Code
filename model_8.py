import json
import math
import numpy as np
from hmmlearn import hmm
from sklearn.model_selection import train_test_split
import re
from collections import defaultdict
from gensim.models import Word2Vec
from tree_sitter import Language, Parser

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


def train(combined):
    trained_models = {}

    for cwe, bad_sequences in combined.items():
#        if cwe != 119:
#            continue

        if len(bad_sequences) <2:
            continue
        if cwe not in trained_cwes:
            trained_cwes.append(cwe)
#        X = np.concatenate([np.array(seq).reshape(-1, 1) for seq in bad_sequences])
        lengths, X = massageX(bad_sequences)


#        lengths = [len(seq) for seq in bad_sequences]
#        if cwe == 119:
#            print(f"lengths: {len(lengths)}")

        model = hmm.MultinomialHMM(n_components=5, n_iter=100, random_state=42)
#        model.startprob_ = np.array([1.0,0.0,0.0])
        model.fit(X, lengths)
        trained_models[cwe] = model
    return trained_models


def train_saftey_tester(combined):
    X = np.concatenate([np.array(seq).reshape(-1,1) for sequences in combined.values() for seq in sequences])
    lengths = [len(seq) for sequences in combined.values() for seq in sequences]

    model = hmm.MultinomialHMM(n_components=3, n_iter=200, random_state=42)

    model.fit(X, lengths)
    return model

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

def outliers(data, model,vocab, data_type, n):

    for cwe, sequences in data.items():
            count = 0
            for seq in sequences:
                match data_type:
                    case "test":

                        encoded_list = []

                        sequence = trees(seq)
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
                            continue  # or a default label
                        unk_ratio = encoded_list.count(OUT_OF_VOCAB_ID) /len(encoded_list)

                    #   if unk_ratio > 0.4:
                    #        print("likely an outlier")
                        X = np.array(encoded_list).reshape(-1, 1)

                    case "train":
                        X = np.array(seq).reshape(-1, 1)

                final_state = model[cwe].predict(X)[-1]
                model[cwe].n_trials = len(seq)

                probs, sample_states = model[cwe].sample(n, currstate = final_state)

                unsafe_count = (sample_states == 1).sum()
                safe_count = (sample_states == 0).sum()

                confidence = unsafe_count / n
                print(confidence)
                is_outlier = confidence < 0.3
                if is_outlier:
                    print(confidence)
                    count +=1
       #         if unsafe_count > safe_count:
        #            print(f"unsafe {is_outlier}")
        #        else:
        #            print(f"safe {is_outlier}")
            print(f"for CWE-{cwe} outlier raio is {count/max(len(sequences),1)}")


def testing_with_decoding(good_data, bad_data, ID,trained_models,w2v_model,n):
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
            best_cwe, sorted_scores = classify_sequence(seq,trained_models,feature_map, w2v_model)

            probs, states = classify2(seq, trained_models,feature_map,cwe,n,w2v_model)
            #print(states)
            if isinstance(states,float):
                continue
            #  print(f"for the bad code, unsafe score: {state_sequence}")
            most = max(set(states), key=states.tolist().count)
            unsafe_count = (states == 1).sum()
            print(f" unsafe chance :{unsafe_count/n}")
            #print(f"'unsafe'{most}")
            if most ==1:
                true_positives +=1

            if most ==0:
                false_negatives += 1
            else:
#                print(most)
                if best_cwe and best_cwe == ID:
                    true_positives +=1
                else:
                    false_negatives +=1
            positive_items += 1

    if not positive_items:
        return
    for cwe, sequences in good_data.items():
        if cwe != ID:
            continue
        for seq in sequences:
            best_cwe,sorted_scores  = classify_sequence(seq,trained_models,feature_map, w2v_model)
            probs, states = classify2(seq, trained_models,feature_map,cwe,n, w2v_model)
            if isinstance(states,float):
                continue
            #print(states)
            most = max(set(states), key=states.tolist().count)
            safe_count = (states ==0).sum()
            print(f"safe:{safe_count/n}")
            if most == 1:
                false_positives += 1
            if most ==0:
                true_negatives += 1
            else:
           #     print(most)
                if best_cwe and best_cwe == ID:
                    false_positives +=1
                else:
                    true_negatives +=1
            negative_items +=1

    print("Predict and Sample Method")
    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)





def print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items):
    print(f"CWE-{ID}:")
   # print(f"number of positive samples {positive_items}")

    #print(f"number of negatives samples {negative_items}")

    print(f"false positives {false_positives}")
    print(f"false negatives {false_negatives}")
    accuracy = (true_positives+true_negatives) / max(positive_items+negative_items,1)
    print(f"best accuracy {accuracy*100.0}%")
    if true_positives ==0:
        recall =0
    else:
        recall = (true_positives)/max(true_positives+false_negatives,1)
#    recall = (true_positives ) / max(positive_items, 1)
#    precision = (true_negatives ) / max(negative_items, 1)
    if true_positives == 0:
        precision =0
    else:
        precision = (true_positives) /max(true_positives+false_positives,1)
    F1 = (2*precision*recall)/max(precision+recall,1)
    num_examples = positive_items+negative_items
    print(f"recall {recall*100.0}%, precision {precision*100.0}%")
    print(f"F1 score: {F1}\n")
#    print(f"{ID}&{positive_items}&{negative_items}&{num_examples}&{false_positives}&{false_negatives}&{accuracy*100.0:.2f}&{recall*100.0:.2f}&{precision*100.0:.2f}&{F1:.2f}\\\\")


def testing_with_scoring(good_data, bad_data, ID,trained_models,w2v_model):
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
            unsafe_score,safe_score  = classify(seq,trained_models,feature_map, cwe,w2v_model)
       #     print(f"for the bad code, unsafe score: {score} safe score: {safe_score}")
            if abs(unsafe_score) < abs(safe_score):
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

            unsafe_score,safe_score  = classify(seq,trained_models,feature_map, cwe,w2v_model)
        #    print(f"for the good code, unsafe score: {score} safe score: {safe_score}")
            if abs(unsafe_score) < abs(safe_score):
                false_positives += 1
            else:
                true_negatives += 1
            negative_items +=1


    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)


def test_with_rank(good_data,bad_data, ID, models, w2v_model):

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
            best_cwe, sorted_scores = classify_sequence(seq,models,feature_map, w2v_model)
            if best_cwe and sorted_scores:
                positive_items +=1
                if best_cwe ==ID:
                    true_positives +=1
                for rank, (score, cwe) in enumerate(sorted_scores, start=1):
                    if cwe == ID:
                        is_within_rank = rank <= 5
                if is_within_rank:
                        true_positives += 1
                else:
                    false_negatives += 1

            else:
                continue

    if not positive_items:
        return
    for cwe, sequences in good_data.items():
        if cwe != ID:
            continue
        for seq in sequences:
            best_cwe,sorted_scores  = classify_sequence(seq,models,feature_map, w2v_model)

            if best_cwe and sorted_scores:

                negative_items +=1

                for rank, (score, cwe) in enumerate(sorted_scores, start=1):
                    if cwe == ID:
                        is_within_rank = rank <= 5
                if is_within_rank:
                    false_positives +=1
                else:
                    true_negatives += 1

            else:
                continue
    print("Rank method:")
    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)


def test_with_predict(good_data,bad_data, ID, models, w2v_model):
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
            positive_items +=1
            encoded_sequence = encode_with_w2v(seq, feature_map, w2v_model, OUT_OF_VOCAB_ID)
            if encoded_sequence:
                X = np.array(encoded_sequence).reshape(-1, 1)
                state= models[cwe].predict(X, lengths=len(encoded_sequence))
                final_state = state[-1]
                if final_state == 1:
                    true_positives += 1
                else:
                    false_negatives += 1



    if not positive_items:
        return
    for cwe, sequences in good_data.items():
        if cwe != ID:
            continue
        for seq in sequences:
            negative_items +=1
            encoded_sequence = encode_with_w2v(seq, feature_map, w2v_model, OUT_OF_VOCAB_ID)
            if encoded_sequence:

                X = np.array(encoded_sequence).reshape(-1, 1)
                state= models[cwe].predict(X, lengths=len(encoded_sequence))
                final_state = state[-1]
                if final_state == 0:
                    false_positives += 1
                else:
                    true_negatives += 1

    print("Predict method")
    print_results(ID,false_positives, false_negatives, true_positives, true_negatives, positive_items, negative_items)




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
    #trained_models_good = train(combined_good)
    trained_models_bad = train(combined_bad)
    w2v_model = train_word2vec(mother_of_all_sequences, vector_size=50, min_count=1, window=5)
    print(len(trained_cwes))
    print(len(feature_map))
#    print("Confidence Ratios Test data:")
#    results_test_data  = z_score_confidence(real_world_good_test, real_world_bad_test, trained_models_bad, feature_map,"test",w2v_model)
#    print("Confidence Ratios Training data:")
#    results_train_data = z_score_confidence(encoded_real_world_good_train, encoded_real_world_bad_train, trained_models_bad, feature_map,"train", w2v_model)
#    for cwe, result in results_test_data.items():
#        print(f"{cwe}&{results_train_data[cwe][0]:.2f}&{result[0]:.2f}&{result[1]:.2f}\\\\")

    for i in trained_cwes:
        testing_with_decoding(real_world_good_test,real_world_bad_test,i,trained_models_bad, w2v_model, 100)
        test_with_predict(real_world_good_test,real_world_bad_test,i, trained_models_bad, w2v_model)
        test_with_rank(real_world_good_test,real_world_bad_test,i,trained_models_bad,w2v_model)
        print("-------------------------------------------------------\n")

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
