import json
import os
from collections import Counter

with open('data/enterprise-attack.json','r',encoding='utf-8') as f:
    data=json.load(f)

liste_objets = data.get("objects", [])
liste_attack=[obj for obj in liste_objets if obj.get('type')=='attack-pattern']
#print(Counter(obj.get("type") for obj in liste_objets))

compteur_attributs = Counter(cle for obj in liste_attack for cle in obj.keys())
mitigations_per_technique={}
for obj in data['objects']:
    if obj['type']=='relationship' and obj['relationship_type']=='mitigates':
        technique = obj['target_ref']
        mitigation = obj['source_ref']
        if technique not in mitigations_per_technique:
            mitigations_per_technique[technique]=[mitigation]
        else:
            mitigations_per_technique[technique].append(mitigation)

#print(compteur_attributs)
count_revoked=0
count_deprecated=0
count_issubtechnique=0

for i in liste_attack:
    if i.get('revoked')==True :
        count_revoked+=1
    if i.get('x_mitre_deprecated')==True:
        count_deprecated+=1
    if i.get('x_mitre_is_subtechnique')==True:
        count_issubtechnique+=1
    if i.get('revoked')==True and i.get('x_mitre_deprecated')==True:
        print('twin')

#print(f'revoked : {count_revoked} deprecated : {count_deprecated} subtechnique : {count_issubtechnique}')

count_norevoke_nodeprecated=0

for list in liste_attack:
   if list.get('revoked',False)==False and list.get('x_mitre_deprecated')==False:
       count_norevoke_nodeprecated+=1

print(count_norevoke_nodeprecated)

alive_technique=[obj for obj in liste_objets
                 if obj.get('type')=='attack-pattern'
                 and not obj.get('revoked',False)
                 and not obj.get('x_mitre_deprecated')]

dead_technique=[obj for obj in liste_objets
                 if obj.get('type')=='attack-pattern'
                 and (obj.get('revoked',False)
                 or obj.get('x_mitre_deprecated'))]

sub_technique=[tech for tech in alive_technique if tech.get('x_mitre_is_subtechnique') is True]
technique_parents = [tech for tech in alive_technique if tech.get('x_mitre_is_subtechnique') is not True]

#No mitigation for techniques 
no_mitigation=[]

for tech in alive_technique:
    id_tech = tech.get('id')

    mitre_id=None
    for ref in tech.get('external_references',[]):
        if ref.get('source_name')=='mitre-attack':
            mitre_id=ref.get('external_id')
            break

    has_mitigation_stix = len(mitigations_per_technique.get(id_tech, [])) > 0
    has_mitigation_mitre = len(mitigations_per_technique.get(mitre_id, [])) > 0 if mitre_id else False

    if not has_mitigation_stix and not has_mitigation_mitre:
        no_mitigation.append(tech)

#For mitigation
alive_mitigation=[obj for obj in liste_objets
                 if obj.get('type')=='course-of-action'
                 and not obj.get('revoked',False)
                 and not obj.get('x_mitre_deprecated',False)]

dead_mitigation=[obj for obj in liste_objets
                 if obj.get('type')=='course-of-action'
                 and (obj.get('revoked',False)
                 or obj.get('x_mitre_deprecated',False))]

#For relationship
alive_relationship=[obj for obj in liste_objets
                 if obj.get('type')=='relationship'
                 and not obj.get('revoked',False)
                 and not obj.get('x_mitre_deprecated',False)]

dead_relationship=[obj for obj in liste_objets
                 if obj.get('type')=='relationship'
                 and (obj.get('revoked',False)
                 or obj.get('x_mitre_deprecated',False))]


id_alive_mitigation=alive_mitigation.get('id')
id_alive_relationship=alive_relationship.get('id')


mitigations_per_technique_clean={}
for obj in alive_relationship:
    if obj['relationship_type']=='mitigates':
        mitigation = obj['source_ref'] if obj['id'] in id_alive_mitigation else obj['description']
    if obj['??'] in 
        if technique not in mitigations_per_technique:
            mitigations_per_technique[technique]=[mitigation]
        else:
            mitigations_per_technique[technique].append(mitigation)


''''
#We put all the fiche in a dictionnary with its id
index={}
for i in data['objects']:
    obj_id = i['id']
    index[obj_id] = i


index_mitigation = index['course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46']['name']
index_phishing = index['attack-pattern--eb2cb5cb-ae87-4de0-8c35-da2a17aafb99']['name']

#We want the id of the phishing
for j in data['objects']:
    if j['type']=='attack-pattern' and j['name']=='Phishing':
        id_phishing=j['id']
        print(id_phishing)

#We want the mitigation for phishing
for g in data['objects']:
    if g['type']=='relationship' and g['relationship_type']=='mitigates' and g['target_ref']==id_phishing:
        mitigation=g['source_ref']
        print(index[mitigation]['name'])

'''



#print(len(mitigations_per_technique))

