import pandas
import requests
import re
import csv
import json


file = pandas.read_csv("all_c_cpp_release2.0.csv")

commit_links = file.ref_link
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
        sequences = extract_lines(diff_content)
        return sequences


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
    unsafe_operations = []

    for line in response.split("\n"):
        match = re.match(r"^diff --git a/(.+) b/\1", line)
        if match:
            current_file = match.group(1)
            continue
        if current_file and re.search(r"README(\.\w+)?$", current_file, re.IGNORECASE):
            continue

        if line.startswith("---"):
            pass
        elif line.startswith("-"): #removed lines
            clean_line = clean_code_line(response,line[1:].strip())
            if clean_line:
                unsafe_operations.append(clean_line)

    return unsafe_operations


inc = 0
def save_to_csv(filename):
    inc = 0
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        for commit in commit_links:
            inc += 1
            diff= get_diff(commit)
            sequences = extract_lines(diff)
            writer.writerow(sequences)
            print(f"{inc} is added")

def save_to_json(filename):
    inc = 0
    with open(filename,"w") as file:
        for commit in commit_links:
            inc += 1
            diff = get_diff(commit)
            if not diff:
                pass
                print(f"{inc} is not added")
            else:
                json.dump(diff, file, indent =4)
                print(f"{inc} is added")
#save_to_csv("unsafe.csv")
save_to_json("unsafe.json")
#inc = 0
#for commit in commit_links:
 #   inc += 1
  #  diff = get_diff(commit)
   # print(inc)

   #print(extract_lines(diff))












