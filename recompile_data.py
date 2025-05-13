import json
import re
import pandas
import os
import numpy as np
from hmmlearn import hmm
import matplotlib
from collections import defaultdict
import matplotlib.pyplot as  plt


with open('change.json' ,'r') as f:
    content = json.load(f)


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


def extract_effect_type(summary, effect_list):
    try:
        matched = []
        for effect_type in effect_list:
            if effect_type in summary:
                matched.append(effect_type)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]


def abstract_features(code_line,features):
    line = code_line.strip()


    if re.search(r'\b(malloc|calloc|realloc|new)\b', line):

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

    return features if features else ["NO_OP"]


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

for item in content:
    id_ = item['id']
    added = item['added_lines']
    removed = item['removed_lines']
    safe_features = []
    unsafe_features = []
    if id_ in lookup:
        for line in added:
            safe_features = abstract_features(line, safe_features)
        for line in removed:
            unsafe_features = abstract_features(line, unsafe_features)
    item['safe_features']= safe_features
    item['unsafe_features'] = unsafe_features
    try:
        item['vuln'] = str(lookup[id_]['vulnerability_classification'])
        item['summary'] = extract_vuln_type(str(lookup[id_]['summary']), wordlist)
    except KeyError:
        item['vuln'] = None

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

def get_var_name(var):
    for name, value in locals().items():
        if value is var:
            return name

for i in vuln_list:
    print(f' {len(i)} for {get_var_name(i)}')


with open("OverFlow.json", 'w') as f:
    json.dump(OverFlow, f, indent = 2)

with open("data_with_features_2.json", 'w') as f:
    json.dump(content, f, indent =2)
