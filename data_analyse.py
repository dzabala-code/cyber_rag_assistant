import json
import os
from collections import Counter

with open('data/enterprise-attack.json','r',encoding='utf-8') as f:
    data=json.load(f)

index={}
for i in data['objects']:
    obj_id = i['id']
    index[obj_id] = i

print(len(index))
print(index['course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46']['name'])