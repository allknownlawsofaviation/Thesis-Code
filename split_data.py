import json 
import re

from sklearn.model_selection import train_test_split

def fix_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        raw_content =file.read()

    content = "[" + re.sub(r'\]\s*\[', '],[', raw_content.strip()) + "]"

    data = json.loads(content)
    return data


#fixed_data = fix_json_file('safe.json')

#if fixed_data is not None:
#    with open('safe_fixed.json','w', encoding='utf-8') as fixed_file:
#        json.dump(fixed_data, fixed_file, indent=1)
#        print("fixed")
#        print(len(fixed_data))
    # data should be a list of sequences
with open('change.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

train_data, test_data = train_test_split(data, test_size=0.2, random_state= 42)

# Save training data
with open('change_train.json', 'w', encoding='utf-8') as train_file:
    json.dump(train_data, train_file, indent=4)  # Pretty-print JSON

# Save testing data
with open('change_test.json', 'w', encoding='utf-8') as test_file:
    json.dump(test_data, test_file, indent=4)

print("Training and testing JSON files created successfully!")

# Check the size

