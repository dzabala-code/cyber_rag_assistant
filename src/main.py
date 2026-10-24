from attack_loader import load_object,filter_alive,prepare,build_document,validate,filter_mitigate
from pathlib import Path

RAW_PATH='data/enterprise-attack.json'
PROCESSED_PATH=Path("./data/processed/processed_data.jsonl")


def main():
    PROCESSED_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = load_object(RAW_PATH)

    attack= filter_alive(data,"attack-pattern")
    mitigation = filter_alive(data,"course-of-action")
    relation = filter_alive(data,"relationship")
    relation=filter_mitigate(relation)

    attack = prepare(attack,
                    ['id','name','description','kill_chain_phases','mitre_id','x_mitre_is_subtechnique']
                    ,{'id': 'attack_id','name':'attack_name','description':'attack_description','mitre_id':'attack_mitre_id'},
                    False)

    mitigation = prepare(mitigation,
                        ['id','name','description','mitre_id'],
                        {'id': 'mitigation_id','name':'mitigation_name','description':'mitigation_description','mitre_id':'mitigation_mitre_id'},
                        False)

    relation=prepare(relation,
                    ['id','description','source_ref','target_ref'],
                    {'id': 'relation_id','description':'relation_description'},
                    True)




    final_merge= build_document(attack,mitigation,relation)
    validate(attack,final_merge)
    final_merge.to_json(PROCESSED_PATH,orient="records",lines=True)



if __name__ == "__main__":
    main()

