import pandas
import requests
import re
import csv
import json
import os
from keybert import KeyBERT

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


def extract_vuln_type(summary, known_types, wordlist):
    try:
        Summary = summary
        summary = summary.lower()  # Normalize casing
        matched = []
        for vuln_type in known_types:
            if vuln_type in summary:
                matched.append(vuln_type)
        for word in wordlist:
            if word.lower() in summary:
                matched.append(vuln_type)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]
count =1
#save_to_json("changes.json")
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

def extract_effect_type(summary, effect_list):
    try:
        matched = []
        for effect_type in effect_list:
            if effect_type in summary:
                matched.append(effect_type)
        return matched if matched else ["unknown"]
    except AttributeError:
        return ["none"]

BERT_output = []
BERT_file = "BERT.json"
if os.path.exists(BERT_file):
    with open(BERT_file, "r") as berty:
        BERT_output = json.load(berty)




def dilbert(file, vuln_types, wordlist):
    counter = 0
    model = KeyBERT('distilbert-base-nli-mean-tokens')
    for index, row in file.iterrows():
        summary =  str(row['summary']).strip()
        vuln = str(row['vulnerability_classification']).strip()
        types = extract_vuln_type(summary, vuln_types, wordlist)

        if vuln == "Overflow":
            continue
        if 'denial of service' in types:
            if len(types) == 1:
                keywords = model.extract_keywords(summary, keyphrase_ngram_range=(1,3), stop_words='english', top_n=5)
                keyword_phrases = [kw for kw, score in keywords]
                counter += 1
                print(counter)
                print(vuln)
                print(keyword_phrases)
                print(f'{summary}')

            else:
                continue


dilbert(file, vuln_types, wordlist)


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
        type = extract_vuln_type(summary,vuln_types,wordlist)
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
        type = extract_vuln_type(summary, vuln_types, wordlist)
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
        type = extract_vuln_type(summary, vuln_types, wordlist)
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
        type = extract_vuln_type(summary, vuln_types, wordlist)
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


def test(file, vuln_types, wordlist):
    count = 0
    for index, row  in file.iterrows():
        summary = str(row['summary'])
        vuln = str(row['vulnerability_classification']).strip()
        types = extract_vuln_type(row['summary'], vuln_types, wordlist)
        if vuln == "Overflow":
            continue
        if  'denial of service' in types:
            if len(types) == 1:
#         if "omnibox" in summary.lower():
                 count += 1
                 print(types)
                 print(count)
                 print(vuln)
                 print(f"{summary}\n")
            else:
                continue
#test(file, vuln_types, wordlist)



with open(filepath, "w") as f:
    json.dump(wordlist, f,indent =2)


with open(effects_file, "w") as poopoo:
    json.dump(effect_list, poopoo,indent =2)
