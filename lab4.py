
import hashlib
import csv

storage = {}
keys = []
with open('Career_Stats_Passing.csv') as csvfile:
    data_input = csv.reader(csvfile)
    for row in data_input:
        key = row[0]+row[3]
        storage[key] = row
        keys.append(key)
        #print(key)

for key in keys:
    print("Start: {}".format(key))
    hashObject = hashlib.sha1(key.encode('utf-8'))
    key_hash = hashObject.digest()

