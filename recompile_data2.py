import json
import math
import re
import pandas
import os
import numpy as np
from hmmlearn import hmm
import matplotlib
from collections import defaultdict
import matplotlib.pyplot as  plt


with open('changes.json' ,'r') as f:
    content = json.load(f)

with open('cwe_code_examples.json', 'r') as f:
    cwe_list = json.load(f)


original_file = pandas.read_csv("all_c_cpp_release2.0.csv")

wordlist = []
filepath ="vulnerabilities.json"
if os.path.exists(filepath):
    with open(filepath, "r") as f:
        wordlist = json.load(f)

effects_file ="effect.json"
effect_list = []
if os.path.exists(effects_file):
    with open(effects_file, "r") as another_file:
        effect_list = json.load(another_file)


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


def strip_comments(code_lines):
    """
    Removes both single-line (//...) and multi-line (/*...*/) comments from C code.
    Returns cleaned lines.
    """
    in_block_comment = False
    cleaned_lines = []

    for line in code_lines:
        stripped_line = ""
        i = 0
        while i < len(line):
            if in_block_comment:
                if line[i:i+2] == "*/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
            elif line[i:i+2] == "/*":
                in_block_comment = True
                i += 2
            elif line[i:i+2] == "//":
                break  # rest of the line is a comment
            else:
                stripped_line += line[i]
                i += 1

        stripped_line = stripped_line.strip()
        if stripped_line:
            cleaned_lines.append(stripped_line)

    return cleaned_lines
def clean_code_lines(lines):
    cleaned = []
    for line in lines:
        if line.startswith('//'):
            continue
        line = line.strip()
        line = re.sub(r'//.*', '', line)      # Remove C++ style comments
        line = re.sub(r'/\*.*?\*/', '', line) # Remove inline C-style comments
        line = line.replace('\t', ' ')
        line = line.replace('{', '').replace('}', '')


        if line:
            cleaned.append(line)
    return cleaned

def abstract_features(code_line,features):
    line = code_line.strip()

    if line.startswith('short'):
        features.append("SHORT_USE")

    if re.search(r'\b(xmalloc|malloc|calloc|realloc|new)\b', line):

        features.append("MEM_ALLOC")
    if re.search(r'\bfree\b', line):
        features.append("MEM_FREE")
    if re.search(r'\bmemcpy|strcpy|strncpy|sprintf|snprintf\b', line):
        features.append("MEM_COPY")
    if re.search(r'\bmemset\b', line):
        features.append("MEM_ZERO")

    # === Pointer and access ===
    if "*" in line or "->" in line:
        features.append("POINTER_OP")
    if "[" in line and "]" in line:
        features.append("ARRAY_ACCESS")
    if re.search(r"\*\s*\w+|\w+\s*\*", line):
        features.append("DEREF")
    # === Local array access === #
    if re.search(r'(\bunsigned )?(int|long|short|float|double|char)\b( [a-zA-Z]+\w*\[\w+])',line):
        features.append("LOCAL_ARRAY") 

        # type name[value] ;

    # === Bounds and checks ===
    if "if" in line and any(op in line for op in ["<", ">", "<=", ">=", "=="]):
        features.append("CONDITIONAL")
    if "sizeof" in line:
        features.append("SIZE_CHECK")
    if re.search(r"\bindex|offset|length|size\b", line):
        features.append("INDEX_OP")

    # === Control flow ===
    if re.match(r'^\s*(if|while|for|switch)\b', line):
        features.append("CONTROL_FLOW")
    if re.match(r'^\s*return\b', line):
        features.append("RETURN")

    # === Arithmetic and overflow-prone ===
    if any(op in line for op in ['+', '-', '*', '/']):
        features.append("ARITH_OP")
    if re.search(r'\+\+|--', line):
        features.append("INC_DEC")
    # === Semantic features ====#
        # Unsafe copy
    if re.search(r'\b(strcpy|sprintf|strcat)\b', line) and not re.search(r'\bsizeof\b', line):
        features.append("UNSAFE_COPY")

    # Bounds check
    if "if" in line and re.search(r'(<|<=|>|>=)', line) and re.search(r'(size|len|cap|index)', line):
        features.append("BOUNDS_CHECK_PRESENT")

    # Null check
    if "if" in line and re.search(r'!=|==', line) and "null" in line.lower():
        features.append("PTR_NULL_CHECK")

    # Memory init
    if re.search(r'\b(memset|bzero|calloc)\b', line):
        features.append("MEMORY_INIT")

    # Double free detection would require context — might be weak here.

    # Conditional guard
    if "if" in line and any(f in line for f in ["strcpy", "free", "memcpy"]):
        features.append("CONDITIONAL_GUARD")

    # Off-by-one patterns
    if re.search(r'\bfor\b', line) and ("<=" in line or ">=" in line):
        features.append("OFF_BY_ONE_PATTERN")

    # Unguarded return
    if re.match(r'\s*return\b', line) and "(" in line:
        features.append("UNGUARDED_RETURN")

    return features if features else ["NO_FEATURE"]

#    return features if features else ["NO_OP"]


lookup = {row['cve_id']: row for _, row in original_file.iterrows()}


DoS = []
OverFlow = []
Bypass = []
Info = []
Mem = []
Exec_Code = []
priv = []
Unspecified = []



vuln_list = [DoS, OverFlow, Bypass, Info, Mem, Exec_Code, priv, Unspecified]
vuln_string_list = ['DoS', 'OverFlow', 'Bypass', '+Info', 'Mem_Cor', 'Exec_Code', '+Priv', 'Unspecified']



def recompile_cwes(cwe_list):
    for item in cwe_list:
        examples = item['examples']
        print(examples)
        for example in examples:
            bad = example['bad']
            good =example['good']
            good_features = []
            bad_features = []
            if bad:
                bad = strip_comments(bad)
                bad = clean_code_lines(bad)
                for line in bad:
                    bad_features = abstract_features(line, bad_features)

            if good:
                good = strip_comments(good)
                good = clean_code_lines(good)
                for line in good:
                    good_features = abstract_features(line, good_features)

            example['good'] = good
            example['bad'] = bad
            example['good_features'] = good_features
            example['bad_features'] = bad_features
    return cwe_list


cwe_list =recompile_cwes(cwe_list)

def recompile_data(content):
    for item in content:
        id_ = item['id']
        added = item['before']
        added = strip_comments(added)
        added = clean_code_lines(added)
        removed = item['after']
        removed = strip_comments(removed)
        removed = clean_code_lines(removed)

        safe_features = []
        unsafe_features = []
        if id_ in lookup:
            for line in added:
                safe_features = abstract_features(line, safe_features)
            for line in removed:
                unsafe_features = abstract_features(line, unsafe_features)
        item['before'] = removed
        item['after'] =added
        item['unsafe_features'] = unsafe_features
        item['safe_features']= safe_features
        if not isinstance(id_,str) and math.isnan(id_):
            continue
        cwe_id = lookup[id_]['cwe_id']
        if isinstance(cwe_id,str) and 'CWE-' in cwe_id:
            item['cwe_id'] = int(str(cwe_id).strip('CWE-'))
        else:
            cwe_id = None
        try:
            item['vuln'] = str(lookup[id_]['vulnerability_classification'])

    #        item['summary'] = extract_vuln_type(str(lookup[id_]['summary']), wordlist)
        except KeyError:
            item['vuln'] = None
    return content




    for item in content:
        vuln = item['vuln']
        if not vuln:
            Unspecified.append(item)
            continue
        elif 'Overflow' in vuln:
            OverFlow.append(item)
        elif 'DoS' in vuln:
            DoS.append(item)
        elif 'Bypass' in vuln:
            Bypass.append(item)
        elif '+Info' in vuln:
            Info.append(item)
        elif "Mem. Corr." in vuln:
            Mem.append(item)
        elif "Exec Code" in vuln:
            Exec_Code.append(item)
        elif "+Priv" in vuln:
            priv.append(item)



content = recompile_data(content)

with open("data_with_features_2_2.json", 'w') as f:
    json.dump(content, f, indent = 2)

with open("cwe_with_features.json", 'w') as f:
    json.dump(cwe_list, f, indent =2)
