import os
import pandas
import json

file = pandas.read_csv("all_c_cpp_release2.0.csv")


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




wordlist = []
filepath ="vulnerabilities.json"
if os.path.exists(filepath):
    with open(filepath, "r") as f:
        wordlist = json.load(f)


DoS = []
OverFlow = []
Bypass = []
Info = []
Mem = []
Exec_Code = []
priv = []
Unspecified = []


for index, row in file.iterrows():
    vuln = str(row['vulnerability_classification'])
    item = extract_vuln_type(str(row['summary']),wordlist)
    if not vuln:
        for i in item:
            if i not in Unspecified:
                Unspecified.append(i)
        continue
    elif 'Overflow' in vuln:
        for i in item:
            if i not in OverFlow:
                OverFlow.append(i)
    elif 'DoS' in vuln:
        for i in item:
            if i not in DoS:
                DoS.append(i)
    elif 'Bypass' in vuln:
        for i in item:
            if i not in Bypass:
                Bypass.append(i)
    elif '+Info' in vuln:
        for i in item:
            if i not in Info:
                Info.append(i)
    elif "Mem. Corr." in vuln:
        for i in item:
            if i not in Mem:
                Mem.append(i)
    elif "Exec Code" in vuln:
        for i in item:
            if i not in Exec_Code:
                Exec_Code.append(i)
    elif "+Priv" in vuln:
        for i in item:
            if i  not in priv:
                priv.append(i)

data ={
	'Overflow': OverFlow,
	'DoS' : DoS,
	'Bypass': Bypass,
	'Info' : Info,
	'Mem' : Mem,
	'Exec Code': Exec_Code,
	'Priv': priv,
	'Unspecified' : Unspecified

}

with open('divided_summaries.json', 'w') as f:
	json.dump(data,f, indent =2)
