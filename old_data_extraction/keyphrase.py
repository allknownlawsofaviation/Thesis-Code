import json
import csv
import pandas
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
from nltk.util import ngrams
from nltk.tokenize import word_tokenize
import nltk
#nltk.download('punkt')




file = pandas.read_csv("all_c_cpp_release2.0.csv")


with open("vulnerabilities.json", "r") as f:
    keyword_data = json.load(f)

def extract_vuln_type(summary, wordlist):
    try:
        Summary = summary
        summary = summary.lower()  # Normalize casing
        matched = []
        for word in wordlist:
            if word.lower() in summary:
                matched.append(word)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]

def extract_matching_keywords(summary, keywords, threshold=85, ngram_range=(3,8)):
    summary= summary.lower()
    tokens = word_tokenize(summary)
    found_phrases = set()

    for n in range(ngram_range[0], ngram_range[1]+1):
        for gram in ngrams(tokens, n):
            candidate = " ".join(gram)

            for kw in keywords:
                if fuzz.partial_ratio(candidate, summary) >= threshold:
                    found_phrases.add(candidate)

    return list(found_phrases)


if isinstance(keyword_data, list):
    keywords = list(set([kw.strip().lower() for kw in keyword_data if isinstance(kw, str)]))
else:
    raise ValueError("Expected list of keywords in vulnerabilities.json")

count = 0

for index, row in file.iterrows():
    summary = str(row['summary'])
    vuln = str(row['vulnerability_classification'])
    types = extract_vuln_type(summary, keyword_data)
    if vuln == "Overflow":
        continue
    if 'denial of service' in types:
        if len(types) == 1:
            matched_keywords = extract_matching_keywords(summary, keywords)
            count += 1
            print(count)
            print(f"{summary}\n")
            print(matched_keywords)
    else:
        continue
