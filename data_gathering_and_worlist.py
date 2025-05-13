import pandas
import requests
import re
import csv
import json
import os
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time

vuln_types = [
    "sql injection",
    "infinite recursion",
    "infinite loop",
    "information leak",
    "status code", #eg 404 203 etc
    "incorrect function calls",
    "cross-site scripting",
    "xss",
    "Untrusted search path vulnerability",
    "buffer over-read",
    "iteratior-invalidation",
    "double-eviction",
    "insufficient data validation",
    "incorrect security ui",
    "use-after-free",
    "use after free",
    "buffer overflow",
    "out of bound read",
    "out of bound read",
    "out-of-bounds read",
    "out-of-bounds write",
    "double free",
    "memory leak",
    "uninitialized variable",
    "divide by zero",
    "rounding error",
    "boundary crossing",
    "boundary error",
    "incorrect error handling",
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
    "service worker",
    "type confusion",
    "out of bounds heap memory read",
    "user enumeration",
    "does not check data types",
    "libmspack",
    "out of bounds write",
    "out of bounds memory read",
    "out of bounds memory write",
    "out of bounds memory access",
    "out-of-bounds memory",
    "exploit heap corruption",
    "insufficient policy enforcement",
    "incorrect handling of confusable characters",
    "incorrect handling of confusable character",
    "incorrect handling of negative zero",
    "incorrect handling of complex species",
    "incorrect handling of failed navigations with invalid urls",
    "incorrect handling of blob urls",
    "incorrect handling of alert box display",
    "incorrect handling of bidirectional domain names with rtl characters",
    "lack of csp enforcement",
    "incorrect handling of csp enforcement",
    "incorrect handling of history on ios",
    "incorrect handling of timer information",
    "incorrect handling of googlechrome:// url scheme on ios",
    "incorrect handling of asynchronous methods",
    "incorrect handling of specified filenames",
    "incorrect handling of back navigations",
    "incorrect handling of cors in serviceworker",
    "incorrect handling of cancelled requests",
    "incorrect handling of download origins",
    "incorrect handling of origin taint checking",
    "incorrect handling of confusable character",
    "incorrect handling of reloads in navigation",
    "incorrectly handled navigation within pdfs",
    "incorrectly handled form actions",
    "incorrectly handled unicode glyphs",
    "incorectly handled the new tab page navigations in non-selected tabs",
    "incorrectly handled back-forward navigation",
    "incorrectly handled rapid transition into and out of full screen mode",
    "incorrectly handled iframes",
    "insufficient check for short files",
    "insufficient origin header validation",
    "insufficient entropy for blinding",
    "improper handling of symbol names embedded in executables",
    "boundary checks",
    "lacks check for insufficient image data in a file",
    "insufficient check for short files",
    "insufficient content restrictions",
    "ioquake3",
    "integer underflow",
    "integer-underflow",
    "off-by-one error",
    "command injection vulnerability",
    "other/unknown vulnerability",
    "untrusted search path vulnerability",
    "insufficient validation of urls",
    "improper handling of symbol names embedded in executables", #improper handling of
    "insufficient validation of untrusted input in ppapi plugins",
    "insufficient validation of untrusted input in blink's mailto",
    "insufficient consistency checks in signature handling",
    "insufficient watchdog timer",
    "uninitialized memory",
    "format string attack",
    "format string vulnerability",
    "insufficiently sanitized devtools urls",
    "insufficiently cleared video memory",
    "insufficiently strict origin checks",
    "insufficiently quick clearing of stale rendered content",
    "insufficient origin checks in blink",
    "implementation in autofill",
    "insufficient enforcement of content security policy",
    "insufficient policy validation",
    "insufficient origin checks for css content",
    "file access permission",
    "insufficient target checks",
    "invalid read",
    "does not properly handle unsigned integers",
    "improper input validation",
    "does not zero out allocated memory",
    "permissions bypass"
    "insufficent file type enforcement",
    "insufficient restrictions on what can be done with apple events",
    "insufficient protection of permission ui",
    "validate of external protocols",
    "insufficiently strict content security policy",
    "lacks a check for insufficient image data in a file",
    "implementation in blink",
    "inappropriate memory management",
    "when caching pdfium", #inparopriat memory management
    "boringssl spake2", #inapropriate implementation in start
    "inappropriate implementation in chromevox",
    "inappropriate implementation in skia canvas composite operations",
    "inappropriate implementation in bookmarks",
    "inappropriate implementation in omnibox",
    "lacks correct size check" #lacks
    "lacks web payments api on blob",
    "data schemes in web payments in google chrome",
    "inappropriate implementation in modal dialog handling",
    "inappropriate implementation in csp reporting",
    "inappropriate implementation in new tab page", #inapropriate implementation in end
    "dismissal of file picker on keyboard events",
    "setting of the see_mask_flag_no_ui flag in file downloads",
    "sharing of texture_2d_array/texture_3d data between tabs in webgl",
    "gain access to cross origin audio",
    "table size handling",
    "www mismatch redirects",
    "allowance of the setdownloadbehavior devtools protocol",
    "array index error",
    "incorrect handling of a confusable character"




]
file = pandas.read_csv("all_c_cpp_release2.0.csv")

commit_links = file.ref_link
summaries = file.summary
changes = file.files_changed

GITHUB = "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"
GITHUB_TOKEN = "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"

def clean_code_line(line):
    """cleans lines of code removing exess whitespace, comments and special characters"""
    #removes inline comments
    if line.startswith("*"):
        pass
    elif line.startswith('/*'):
        pass
    elif line.startswith ('//'):
        pass
    else:
        line = re.sub(r"/\*.*?\*/", "", line, flags = re.DOTALL)
        line = re.sub(r"[{}();]+$", "", line)
        line = line.strip()
        return line

#extract the gtihub diffs from the urls in the datbase
def parse_commit_url(url):
    parts= urlparse(url).path.strip('/').split('/')
    print(parts)
    owner = parts[0]
    repo = parts[1]
    sha = parts[-1]
    return owner, repo, sha

def googlesource_diff(commit_url):
    # Transform: .../+/<commit>  -->  .../+/<commit>^!/#F0
    if not commit_url.endswith('^!'):
        if not commit_url.endswith('/'):
            commit_url += '/'
        commit_url += '^!/#F0'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }

    response = requests.get(commit_url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch: {commit_url} (status {response.status_code})")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    added = [tag.get_text() for tag in soup.find_all(class_='Diff-insert')]
    removed = [tag.get_text() for tag in soup.find_all(class_='Diff-delete')]

    return added, removed


def fetch_diff_from_api(commit_url):
    owner, repo, sha = parse_commit_url(commit_url)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(api_url, headers= headers)
    if response.status_code!= 200:
        print(f"Error {response.status_code}: {response.json().get('message')} - {commit_url}")
        return None
    added, removed = [], []
    for file in response.json().get("files", []):
        patch = file.get("patch")
        if patch:
            added, removed = extract_lines_from_patch(patch)
    return added, removed

def extract_lines_from_patch(patch):
    added, removed = [], []
    for line in patch.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            clean_line = clean_code_line(line[1:].strip())
            if clean_line:
                added.append(clean_line)
        elif line.startswith("-") and not line.startswith('---'):
            clean_line = clean_code_line(line[1:].strip())
            if clean_line:
                removed.append(clean_line)
    return added, removed


def get_diff(commit_url):


    patch_url = commit_url + ".diff"

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    #response = requests.get(patch_url, headers=headers)
    #diff_content = response.text

    try:
        response = requests.get(patch_url, headers=headers)


        if response.status_code == 200:
            time.sleep(5)
            diff_content = response.text

            added,removed = extract_lines(diff_content)
            return added,removed
        elif response.status_code ==403:
            print("403 forbidden")
            print(response.text)
            return None
        else:
            print(f'Unexpected status code:{response.status_code}')
            print(response.text)
            return None

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
        elif line.startswith("++"):
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



def save_to_json(filename,cause_cat,effect_cat,file):
    inc = 0
    result =[]


    for index, row in file.iterrows():
        cause_category = []
        effect_category = []
        commit = row['ref_link']
        commit_id = row['commit_id']
        summary = str(row['summary']).lower()
        if not summary:
            continue
        vuln = str(row['vulnerability_classification']).strip()
        vulnerability = vuln
        score = row['score']
        cve_id = row['cve_id']
        if 'Overflow' in vuln:
            vuln= re.sub('Overflow', '',vuln)
        if 'Exec Code' in vuln:
            vuln = re.sub('Exec Code', 'ExecCode', vuln)
        if  vuln == "nan":
            vuln = extract_effect_type(summary,effect_list)
        for category, phrases in cause_cat.items():
            for phrase in phrases:
                if phrase.lower() in summary:
                    cause_category.append(category)
                    continue
        if not cause_category:
            cause_category = ["Uncategorized"]
        types = extract_vuln_type(summary, wordlist)
        try:
            if "github.com" in  commit:
                added,removed = fetch_diff_from_api(commit)
            elif "googlesource.com" in commit:
                added, removed = googlesource_diff(commit)
        except TypeError:
            continue
        data ={
            "index": index,
            "id": cve_id,
            "commit_id":commit_id,
            "added_lines": added,
            "removed_lines": removed,
            "cause": cause_category,
            "effect": vuln,
            "score" : score,

        }
        if not data:
            pass
            print(f"{inc} is not added")
        else:
            inc += 1
            result.append(data)
            print(f"{inc} is added")
            time.sleep(2)
    with open(filename,"w") as output_file:
        json.dump(result, output_file, indent =4)


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
count =1

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


vector_file = "vector.json"
vectors = []
if os.path.exists(vector_file):
    with open(vector_file, 'r') as vector_f:
        vectors = json.load(vector_f)

with open('bug_cause_categorized.json') as f:
    bug_categories = json.load(f)


def extract_effect_type(summary, effect_list):
    try:
        matched = []
        for effect_type in effect_list:
            if effect_type in summary:
                matched.append(effect_type)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]

def extract_vector(summary, vectors):
    try:
        matched = []
        for vector in vectors:
            if vector in summary:
                matched.append(vector)
        return True if matched else False
    except AttributeError:
        return False


save_to_json("change.json",bug_categories,effect_list,file)

def organize(summaries, effectlist):
    count = 0

    keyword1 = "attackers to"
    keyword2 = "remote authenticated users"
    keyword3 = "allow local users to"
    for summary in summaries:
        if summary != summary:
            continue
        type = extract_effect_type(summary,effectlist)
        if type == ["unknown"]:
#            match = re.search(r'to conduct(\b.*attacks)', summary)
#            if match:

#                phrase = match.group(1).strip()

           if "local user" in summary:
#           if "privilege" in summary:
#if "crash" in summary:
#                phrase = summary.split("attacker",1)[1]
#                if "to " in phrase:
#                    phrase = phrase.split("to ",1)[1]
                count += 1
                print(count)
#                print(phrase)
                print(type)
                print(f"{summary}\n")
#                effectlist.append(phrase)


        else:
            continue


#organize(summaries,effect_list)

def check_csv_file(file,effect_list):
    counter = 1
    for index, row in file.iterrows():
        summary =  str(row['summary']).strip()
        vuln = str(row['vulnerability_classification']).strip()

        if summary == '' and vuln == '':
            continue
        if vuln == '' or vuln == 'Overflow':
            type = extract_effect_type(row['summary'], effect_list)
            if type == ['unknown']:
                counter += 1
                print(counter)
                print(f'{summary}\n')
            else:
                continue



def does_not_properly(sumaries,wordlist):
    count =1
    for summary in summaries:
        keyword ="does not properly"
        type = extract_vuln_type(summary,wordlist)
        if type == ["unknown"]:
            match = re.search(r'^Google Chrome',summary)
            if match:
                match2 = re.search(r'\bdoes not\b.*?[,.]', summary)
           # if  keyword in summary.lower():
                if match2:
                    count += 1
                    phrase = match2.group(0).strip(" ,.")
                    if phrase not in wordlist:
                        wordlist.append(phrase)
                        print(count)
                        print(type)
                        print(f"{summary}\n")

        else:
            continue


def prior_to_google_chrome(summaries,wordlist):
    count =1
    for summary in summaries:
        type = extract_vuln_type(summary, wordlist)
        if type == ["unknown"]:
            match = re.search(r'(.*)\bin Google Chrome\b.*[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+\b(.*),', summary)
            if match:
               phrase = match.group(2).strip(',')
               count +=1
               if len(phrase) > 0:
                   if phrase not in wordlist:
                        wordlist.append(phrase)
                        print(count)
                        print(type)
                        print(phrase)
                        print(f"{summary}\n")

#prior_to_google_chrome(summaries,wordlist)

def unknowns(summary, vuln_types, wordlist):
    count =0
    for summary in summaries:
        type = extract_vuln_type(summary, wordlist)
        if type ==["unknown"]:
            phrases = re.split(r'(?<!\d)\.(?!\d)', summary)
        #    if "does not properly" in summary:
            for phrase in phrases:
               match = re.search(r'\b(does not properly[^,]*)(?=[,])',phrase)
               if match:
                   new_phrase = match.group(0).strip(",. ")
                   wordlist.append(new_phrase)

                   count +=1
                   print(count)
                   print(type)
                   print(f"{summary}\n")
                   print(new_phrase)
        else:
            continue

#unknowns(summaries, vuln_types, wordlist)
def mishandles(summary, vuln_types, wordlist):
    count =0
    for summary in summaries:
        type = extract_vuln_type(summary, wordlist)
        if type ==["unknown"]:
          match = re.search(r'\bdoes not\b.*?[.]',summary)
#          match = re.search(r'\bvectors related to\b.*',summary)
          if match:
            phrase = match.group(0).strip(" ,")
            count +=1
            print(count)
            print(type)
            print(f"{summary}\n")
            print(phrase)
            wordlist.append(phrase)
        else:
            continue
#mishandles(summaries, vuln_types, wordlist)

no_info = [
  "This issue is rated as High severity due to the possibility of remote denial of service",
  "This issue is rated as High due to the possibility of remote denial of service",
    "coders/dds.c in ImageMagick allows remote attackers to cause a denial of service via a crafted DDS file",
    "affected by: Denial of Service",
    "This issue is rated as",
   "The tcmu-runner daemon in tcmu-runner version 1.0.5 to 1.2.0 is vulnerable to a local denial of service attack",
    "A denial of service vulnerability in the Android media framework (libstagefright). Product: Android. Versions: 7.0, 7.1.1, 7.1.2. Android ID: A-36531046."
]


def test(file, no_info, wordlist, vectors):
    count = 0
    keyword0 = "mishandles"
    keyword = "incorrectly"
    keyword1 = "does not properly"
    keyword2 = "does not"
    keyword3 = "there is a possible"
    keyword4 = "improper"
    keyword5 = "has "
    keyword6 = "is too late"
    keyword7 = "uses incinsistent"
    keyword8 = "proceeds with"
    keyword9 = "incorrect"
    keyword10 = "uses"
    for index, row  in file.iterrows():
        summary = str(row['summary'])
        vuln = str(row['vulnerability_classification']).strip()
        types = extract_vuln_type(row['summary'], wordlist)
        if any(info in summary for info in no_info):
            continue
        if extract_vector(summary, vectors):
            continue
        if  'unknown' in types:
            if len(types) == 1:
#                match = re.search(r'\b.+[0-9]+[.][0-9]?[.]*[0-9]?[, ](\b.*, which)',summary)
#                match2 = re.search(r'\b(leveraging\b.*)(?=[.])',summary)
#                if match2:
#                    phrase = match2.group(0)
#                    if "NOTE:" in phrase:
#                       phrase = phrase.split(". NOTE")[0]
                    count += 1
                    print(types)
#                    print(phrase)
                    print(count)
                    print(vuln)
                    print(f"{summary}\n")
#                    wordlist.append(phrase)

            else:
                continue
test(file, no_info, wordlist, vectors)


with open(vector_file, 'w') as vector_f:
    json.dump(vectors, vector_f, indent = 2)

with open(filepath, "w") as f:
    json.dump(wordlist, f,indent = 2)


with open(effects_file, "w") as poopoo:
    json.dump(effect_list, poopoo,indent = 2)
