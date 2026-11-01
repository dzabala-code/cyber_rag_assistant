Convert the STIX format json into 3 Dataframes : attack, mitigation and relationship. 

We filter out the attacks and mitigations that have been revoked and deprecated.
We also will just get the references of the attack that comes from MITRE and we just pick the important columns.
We then do the merge of the 3 dataframes and replace the NaN value to [] for easier future treatment.

Finally, we convert the merged dataframe to a json (to data/processed). Here, we don't have a lot of data, so we prefer to put lisbility above performances, otehrwise, parquet would have been used.

Embedding:
we are choosing the sentence-transformers (sBERT) :bge-m3 (par BAAI) with 8192 tokens. Our longest description is about
1200 tokens, so we don't need to cut it out.

We are cleaning out the description : 
count     706.000000
mean     1406.760623
std       659.227593
min       207.000000
25%       923.250000
50%      1293.000000
75%      1765.250000
max      4680.000000
Name: attack_description, dtype: float64
count     706.000000
mean     1139.679887
std       536.583796
min       207.000000
25%       749.250000
50%      1037.500000
75%      1397.500000
max      4016.000000
