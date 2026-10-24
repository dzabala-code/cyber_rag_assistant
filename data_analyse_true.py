import pandas as pd
import json

def load_object(path):
    with open(path,'r',encoding='utf-8') as f:
        data=json.load(f)

    return pd.DataFrame(data["objects"])


def getExternalId (liste):
    for ref in liste:
        if isinstance(ref,dict) and ref.get('source_name')=='mitre-attack':
            return ref.get('external_id')

def filter_alive(df,stix_type):

    filtered_df=df[(df["type"] == str(stix_type))
    & (df["revoked"].fillna(False) == False)
    & (df["x_mitre_deprecated"].fillna(False) == False)
    ].copy()

    return filtered_df

def prepare(df,df_columns,renamed_columns,isRelation):
    if isRelation==False:
        df['mitre_id'] = df['external_references'].apply(getExternalId)
    if (isRelation==True and df['type']=='mitigates') or isRelation==False:
        df=df[df_columns]
        df = df.rename(columns=renamed_columns)
    else:
        return 'Error ! no mitigation !'

    return df


data = load_object('data/enterprise-attack.json')

attack= filter_alive(data,"attack-pattern")
mitigation = filter_alive(data,"course-of-action")
relationship = filter_alive(data,"relationship")

attack = prepare(data,
                ['id','name','description','kill_chain_phases','mitre_id','x_mitre_is_subtechnique']
                ,{'id': 'attack_id','name':'attack_name','description':'attack_description','mitre_id':'attack_mitre_id'},
                False)

mitigation = prepare(data,
                    ['id','name','description','mitre_id'],
                    {'id': 'mitigation_id','name':'mitigation_name','description':'mitigation_description','mitre_id':'mitigation_mitre_id'},
                    False)

relation=prepare(data,
                ['id','description','source_ref','target_ref'],
                 {'id': 'relation_id','description':'relation_description'},
                 True)


columns_relation = ['id','description','source_ref','target_ref']
relationship=relationship[columns_relation]
relationship = relationship.rename(columns={'id': 'relation_id','description':'relation_description'})

mitigation_relation=relationship.merge(mitigation,left_on='source_ref',right_on='mitigation_id',how='inner')
mitigation_relation.drop(columns='source_ref')

merge1=mitigation_relation.merge(attack,left_on='target_ref',right_on='attack_id',how='inner')

merge2=merge1.groupby('attack_mitre_id',as_index=False)[['mitigation_name','mitigation_description','relation_description','mitigation_mitre_id']].agg(list)


final_merge= attack.merge(merge2,on='attack_mitre_id',how='left')

for col in merge2.columns:
    final_merge[col] = final_merge[col].apply(
        lambda x: [] if (isinstance(x, float) and pd.isna(x)) else x
    )

final_merge.to_json("./data/processed/processed_data.jsonl",orient="records",lines=True)



