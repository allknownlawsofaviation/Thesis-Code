import pandas
import requests
import re
import csv
import json

vuln_types = [
    "status code", #eg 404 203 etc
    "incorrect function calls",
    "cross-site scripting",
    "xss",
    "iteratior-invalidation",
    "double-eviction",
    "insufficient data validation",
    "incorrect security ui",
    "use-after-free",
    "use after free",
    "buffer overflow",
    "out-of-bounds read",
    "out-of-bounds write",
    "double free",
    "memory leak",
    "race condition",
    "null pointer dereference",
    "integer overflow",
    "stack overflow",
    "heap overflow",
    "code execution",
    "privilege escalation",
    "denial of service",
    "unspecified vectors",
    "internal bug",
    "early free",
    "out of bounds memory read",
    "out of bounds memory write",
    "out of bounds memory access",
    "exploit heap corruption",
    "insufficient policy enforcement",
    "incorrect handling of confusable characters",
    "incorrect handling of confusable character",
    "incorrect handling of negative zero"
]
file = pandas.read_csv("all_c_cpp_release2.0.csv")

commit_links = file.ref_link
summaries = file.summary
changes = file.files_changed
GITHUB_TOKEN = "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"

def clean_code_line(response,line):
    """cleans lines of code removing exess whitespace, comments and special characters"""
    #removes inline comments
    if line.startswith("*"):
        pass
    elif line.startswith('/*'):
        pass
    elif line.startswith('//'):
        pass
    else:
        line = re.sub(r"/\*.*?\*/", "", line, flags = re.DOTALL)
        line = line.strip()
        return line

#extract the gtihub diffs from the urls in the datbase
def get_diff(commit_url):


    patch_url = commit_url + ".diff"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    #response = requests.get(patch_url, headers=headers)
    #diff_content = response.text

    try:
        response = requests.get(patch_url, headers=headers)
        diff_content = response.text
        added,removed = extract_lines(diff_content)
        return added,removed


    except requests.RequestException as e:
        print(f"Error fetching diff: {response.status_code}")
        return None
   #if response.status_code == 200:
    #    return diff_content
   # else:
    #    print(f"Error fetching diff: {response.status_code}")
     #   return "\n"
# Exracts lines of code 
def extract_lines(response):
    current_file =None
    added_lines = []
    removed_lines =[]

    for line in response.split("\n"):
        match = re.match(r"^diff --git a/(.+) b/\1", line)
        if match:
            current_file = match.group(1)
            continue
        if current_file and re.search(r"README(\.\w+)?$", current_file, re.IGNORECASE):
             continue

        if line.startswith("---"):
            pass
        elif line.startswith("+"): #removed lines
            clean_line = clean_code_line(response,line[1:].strip())
            if clean_line:
                added_lines.append(clean_line)
        elif line.startswith("-"):
            clean_line = clean_code_line(response, line[1:].strip())
            if clean_line:
                removed_lines.append(clean_line)
    return added_lines, removed_lines


inc = 0



def save_to_json(filename):
    inc = 0
    with open(filename,"w") as file:

        for commit in commit_links:
            inc += 1
            added,removed = get_diff(commit)
            data ={
                "added_lines": added,
                "removed_lines": removed
            }
            if not data:
                pass
                print(f"{inc} is not added")
            else:
                json.dump(data, file, indent =4)
                print(f"{inc} is added")


def extract_vuln_type(summary, known_types):
    try:
        summary = summary.lower()  # Normalize casing
        matched = []
        for vuln_type in known_types:
            if vuln_type in summary:
                matched.append(vuln_type)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]
count =1
#save_to_json("changes.json")
for summary in summaries:
    unknown = []
    type = extract_vuln_type(summary,vuln_types)
    if type == ["unknown"]:
        count += 1
        print(count)
        print(type)
        print(f"{summary}\n")
        unknown += summary


    else:
        continue











