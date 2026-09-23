from threatgraph.ingestion.mitre import load_mitre_objects


MITRE_PATH = "data/raw/mitre/enterprise-attack.json"


def main() -> None:
    data = load_mitre_objects(MITRE_PATH)

    print("\nMITRE ATT&CK ingestion summary")
    print("-" * 40)

    print(f"Threat groups: {len(data['groups'])}")
    print(f"Techniques:    {len(data['techniques'])}")
    print(f"Software:      {len(data['software'])}")
    print(f"Mitigations:   {len(data['mitigations'])}")

    print("\nSample threat group")
    print("-" * 40)

    if data["groups"]:
        print(data["groups"][0].model_dump())

    print("\nSample technique")
    print("-" * 40)

    if data["techniques"]:
        print(data["techniques"][0].model_dump())

    apt29 = [
    group
    for group in data["groups"]
    if group.name == "APT29"
    ]

    print("\nAPT29 result")
    print("-" * 40)

    for group in apt29:
        print(group.model_dump())

if __name__ == "__main__":
    main()