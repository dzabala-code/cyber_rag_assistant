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

    df=df[df_columns]
    df = df.rename(columns=renamed_columns)

    return df

def filter_mitigate(df):
    filter_df=df[(df['relationship_type']=='mitigates')].copy()
    return filter_df

def build_document(df_attack,df_mitigation,df_relationship):
    mitigation_relation=df_relationship.merge(df_mitigation,left_on='source_ref',right_on='mitigation_id',how='inner')
    mitigation_relation=mitigation_relation.drop(columns='source_ref')

    links=mitigation_relation.merge(df_attack,left_on='target_ref',right_on='attack_id',how='inner')

    mitigations_per_technique=links.groupby('attack_mitre_id',as_index=False)[['mitigation_name','mitigation_description','relation_description','mitigation_mitre_id']].agg(list)
    final_merge= df_attack.merge(mitigations_per_technique,on='attack_mitre_id',how='left')

    for col in mitigations_per_technique.columns:
        final_merge[col] = final_merge[col].apply(
        lambda x: [] if (isinstance(x, float) and pd.isna(x)) else x
        )


    return final_merge

def validate(df_alive,df_final):
    if df_final.shape[0]!=df_alive.shape[0]:
        raise ValueError("df_final not the right shape")
    if df_final["attack_mitre_id"].isna().any():
        raise ValueError("attack mitre id missing")
    if not df_final["attack_mitre_id"].is_unique:
        raise ValueError("Duplicate attack mitre id")
    if not df_final["attack_mitre_id"].str.startswith("T").all():
        raise ValueError("Wrong attack mitre id")

    nan_tocheck =["mitigation_name","mitigation_description","relation_description","mitigation_mitre_id"]
    for df in nan_tocheck:
        is_list = df_final[df].apply(lambda x: isinstance(x, list))
        if not is_list.all():
            raise ValueError("Value not list in mitigation!")


