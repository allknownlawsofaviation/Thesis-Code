import pandas
import requests
import re
import base64
import csv
import json
import os
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time

file = pandas.read_csv("all_c_cpp_release2.0.csv")

GITHUB_TOKEN = "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"


def parse_commit_url(url):
    parts= urlparse(url).path.strip('/').split('/')
    print(parts)
    owner = parts[0]
    repo = parts[1]
    sha = parts[-1]
    return owner, repo, sha

def get_file_content(owner, repo, path, ref):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    content = r.json().get('content')
    if content:
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        return decoded.splitlines()
    return None

def extract_hunks_from_patch(patch):
    hunk_header_re = re.compile(r"@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@")
    lines = patch.split("\n")
    hunks = []

    for line in lines:
        match = hunk_header_re.match(line)
        if match:
            _, _, start_new, len_new = match.groups()
            start = int(start_new)
            length = int(len_new or 1)
            hunks.append((start, start +length))
    return hunks

def get_context_lines(lines, start, end, context=10):
    start_idx = max(0, start -context -1)
    end_idx = min(len(lines), end + context -1)
    return lines[start_idx:end_idx]

def get_commit_diff_context(owner, repo, sha, prev_sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"Failed to fetch commit data: {r.status_code}")
        return []
    data = r.json()
    output_before = []
    output_after = []


    for file in data.get("files", []):
        path = file.get("filename")

        if "README" in path:
            continue

        patch = file.get("patch")
        if not patch:
            continue

        hunks = extract_hunks_from_patch(patch)

        before_lines = get_file_content(owner, repo, path, prev_sha)
        after_lines = get_file_content(owner, repo, path, sha)

        if not before_lines or not after_lines:
            continue

        for start, end in hunks:
            context_before = get_context_lines(before_lines, start, end)
            context_after = get_context_lines(after_lines, start, end)


            output_before.extend(context_before)
            output_after.extend(context_after)

        output_before = clean_code(output_before)
        output_after = clean_code(output_after)


        time.sleep(1.2)


    return output_before, output_after

def clean_code(lines):
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//'):
            continue  # skip empty or comment lines

        # Remove inline comments
        line = re.sub(r'/\*.*?\*/', '', line)      # /* comments */
        line = re.sub(r'//.*', '', line)           # // comments

        # Remove braces
        line = line.replace('{', '').replace('}', '')

        line = line.strip()
        if line:
            cleaned.append(line)
    return cleaned



def save_to_json(filename,cause_cat,effect_cat,file):
    inc = 0
    result =[]


    for index, row in file.iterrows():
        cause_category = []
        effect_category = []
        commit = row['ref_link']
        commit_id = row['commit_id']
        prev_id = row['version_before_fix']
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
                if phrase.lower() in summary and category not in cause_category:
                    cause_category.append(category)
                    continue
        if not cause_category:
            cause_category = ["Uncategorized"]
        types = extract_vuln_type(summary, wordlist)
        try:
            if "github.com" in  commit:
                owner, repo, sha = parse_commit_url(commit)
                removed,added = get_commit_diff_context(owner, repo, sha, prev_id)
            elif "googlesource.com" in commit:
                added, removed = googlesource_diff(commit)
        except ValueError:
            continue
        except TypeError:
            continue
        data ={
            "index": index,
            "id": cve_id,
            "commit_id":commit_id,
            "before": removed,
            "after": added,
            "cause": cause_category,
            "effect": vuln,
            "score" : score,
            "summary" : types

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

save_to_json("changes.json",bug_categories,effect_list,file)
