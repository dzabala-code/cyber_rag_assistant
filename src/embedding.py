import json
import pandas as pd
import re

df = pd.read_json("./data/processed/processed_data.jsonl",lines=True)

longeur_description = df['attack_description'].str.len()
print(longeur_description.describe())
index_max = longeur_description.idxmax()
index_min= longeur_description.idxmin()
#print(df.iloc[index_max]['attack_description'])
#print(df.iloc[index_min]['attack_description'])

contient_citation = df["attack_description"].str.contains(r"\(Citation:", na=False)
total_citations = contient_citation.sum()
#print(total_citations)

def clean_text(text):
    result_citation=re.sub(r"\(Citation[^)]*\)","",text)
    result_balise=re.sub(r"<[^>]*\>","",result_citation)
    resultat_markdonw=re.sub(r"\[([^\]]+)\]\([^)]+\)",r"\1",result_balise)
    result_gras=re.sub(r"\*\*","",resultat_markdonw)
    result_final=re.sub(r"[ \t]+", " ", result_gras)
    return result_final

def validate_clean(column):
    print(f"Double space : {column.str.contains(r' {2,}', regex=True).sum()}")
    print(f"Citations    : {column.str.contains(r'\(Citation', case=False, regex=True).sum()}")
    print(f"Links        : {column.str.contains(r'\]\(http', regex=True).sum()}")
    print(f"Balises      : {column.str.contains(r'<', regex=False).sum()}")
    print(f"Bold         : {column.str.contains(r'\*\*', regex=True).sum()}")

df['attack_description']=df['attack_description'].apply(clean_text)
longeur_description = df['attack_description'].str.len()
print(longeur_description.describe())

print(validate_clean(df['attack_description']))



