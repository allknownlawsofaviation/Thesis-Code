import json
from collections import defaultdict
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# Load your phrase list
with open("vulnerabilities.json", "r") as f:
    data = json.load(f)

# Bug categories with patterns
bug_categories = {
    "Improper Input Validation": [r"does not validate", r"does not check", r"fails to check", r"fails to validate", r"improper validation"],
    "Missing Authentication or Confirmation": [r"does not require", r"does not request", r"does not ensure .* confirmation", r"missing confirmation"],
    "Memory Management": [r"use-after-free", r"buffer overflow", r"memory corruption", r"heap", r"stack", r"uninitialized", r"out-of-bounds"],
    "Parsing or Interpretation Errors": [r"parse", r"parsing", r"interpret", r"processing", r"load", r"resolve", r"render", r"mishandles"],
    "Cryptographic Weakness": [r"key length", r"entropy", r"predictable", r"weak randomness", r"crypt", r"initialization vector", r"nonce"],
    "Configuration or Permissions Errors": [r"default configuration", r"permission", r"access control", r"privilege", r"exposure", r"bypass"],
    "Race Condition or Concurrency": [r"race condition", r"concurrent", r"thread", r"sync", r"locking"],
    "Compiler or Build Configuration": [r"compiler", r"compile", r"build", r"PIE", r"ASLR", r"stack protector", r"PIC", r"hardening"],
    "Logical Flaws": [r"incorrect", r"wrong", r"logic", r"mismatch", r"mistaken"],
    "Restriction Flaws": [r"restrict"],
    "Buffer Flaws": [r"buffer"],
    "Free Flaws": [r"free"]
}

# Normalize and categorize
categorized = defaultdict(list)
uncategorized = []

for phrase in data:
    norm = phrase.strip().lower()
    matched = False
    for cat, patterns in bug_categories.items():
        if any(re.search(p, norm) for p in patterns):
            categorized[cat].append(phrase)
            matched = True
            break
    if not matched:
        uncategorized.append(phrase)

# Cluster uncategorized
vectorizer = TfidfVectorizer(stop_words="english")
X = vectorizer.fit_transform(uncategorized)
kmeans = KMeans(n_clusters=10, random_state=42, n_init="auto")
labels = kmeans.fit_predict(X)

for i, phrase in enumerate(uncategorized):
    categorized[f"Uncategorized Cluster {labels[i] + 1}"].append(phrase)

# Save output
with open("bug_cause_categorized.json", "w") as f:
    json.dump(categorized, f, indent=2)

