import requests
from bs4 import BeautifulSoup
import json
import time
import pandas
import re

BASE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
HEADERS = {"User-Agent": "Mozilla/5.0"}

file = pandas.read_csv("all_c_cpp_release2.0.csv")

no_examples = []

def scrape_cwe_example(cwe_id):
    url = BASE_URL.format(cwe_id)
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch CWE-{cwe_id}: {e}")
        return None

    soup = BeautifulSoup(response.text, "html.parser")

    title_tag = soup.find("h2")
    print(title_tag.text.strip())
    title = title_tag.text.strip() if title_tag else "Unknown CWE"

    example_list = []
    examples = soup.find_all(string=re.compile(r'Example\s+\d+'))
    print(examples)
    if not examples:
        no_examples.append(cwe_id)

    for example in examples:
        example_tag = example.find_parent()
        bad_code, good_code = [], []
        bad_code_block = example_tag.find_next("div", class_="indent Bad")
        good_code_block = example_tag.find_next("div", class_="indent Good")
#        print(bad_code_block)

#       print(good_code_block)
        if good_code_block:
            header = good_code_block.find("div", class_="CodeHead")
            if "C" in header.text.strip():
    #            print(header.text.strip())
                good_rows  = good_code_block.find("div", class_='top')
                #.text.strip().splitlines()
                good_code  = [line.strip() for line in good_rows.get_text(separator='\n').split('\n') if line.strip()]
#                if good_code:
#                    good_code = clean_code_lines(good_code)

        if bad_code_block:
            header = bad_code_block.find("div", class_="CodeHead")
            if "C" in header.text.strip():
#            print(header.text.strip())
                bad_rows = bad_code_block.find("div", class_='top')
                #.text.strip().splitlines()

                bad_code  = [line.strip() for line in bad_rows.get_text(separator='\n').split('\n') if line.strip()]
#                if bad_code:
#                    bad_code = clean_code_lines(bad_code)
        if bad_code or good_code:
            example_list.append({
                "bad": bad_code,
                "good": good_code,
            })

    return {
        "cwe_id": cwe_id,
        "title": title,
        "examples": example_list
    }

# Example: download several CWE examples
cwe_ids = []  # you can expand this list
dataset = []

for index, row in file.iterrows():
    cwe_id = str(row['cwe_id'])
    if cwe_id=='nan':
        continue
    else:
        cwe_id = int(cwe_id.strip('CWE-'))
        if cwe_id not in cwe_ids:
            cwe_ids.append(cwe_id)



print(cwe_ids)
print(len(cwe_ids))
def clean_code_lines(lines):
    cleaned = []
    for line in lines:
        line = line.strip()
        line = re.sub(r'//.*', '', line)      # Remove C++ style comments
        line = re.sub(r'/\*.*?\*/', '', line) # Remove inline C-style comments
        line = line.replace('\t', ' ')
        if line:
            cleaned.append(line)
    return cleaned

for cwe_id in cwe_ids:
    print(f"Scraping CWE-{cwe_id}...")
    result = scrape_cwe_example(cwe_id)
    if result:
        dataset.append(result)
    time.sleep(1)  # be kind to the server

print(no_examples)
print(len(no_examples))
# Save to JSON
with open("cwe_code_examples.json", "w") as f:
    json.dump(dataset, f, indent=2)

