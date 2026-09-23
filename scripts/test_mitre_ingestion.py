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
    print(f"Relationships: {len(data['relationships'])}")

    print("\nSample threat group")
    print("-" * 40)

    if data["groups"]:
        print(data["groups"][0].model_dump())

    print("\nSample technique")
    print("-" * 40)

    if data["techniques"]:
        print(data["techniques"][0].model_dump())

    print("\nSample relationship")
    print("-" * 40)

    if data["relationships"]:
        print(data["relationships"][0].model_dump())

    relationship = data["relationships"][0]

    print("\nRelationship details")
    print("-" * 40)

    print("Source:", relationship.source_ref)
    print("Type:", relationship.relationship_type)
    print("Target:", relationship.target_ref)

    entity_lookup = {}

    for group in data["groups"]:
        entity_lookup[group.stix_id] = group

    for technique in data["techniques"]:
        entity_lookup[technique.stix_id] = technique

    for software in data["software"]:
        entity_lookup[software.stix_id] = software

    for mitigation in data["mitigations"]:
        entity_lookup[mitigation.stix_id] = mitigation

    relationship = data["relationships"][0]

    source = entity_lookup.get(relationship.source_ref)
    target = entity_lookup.get(relationship.target_ref)

    print("\nResolved relationship")
    print("-" * 40)

    print(
        getattr(source, "name", relationship.source_ref),
        relationship.relationship_type,
        getattr(target, "name", relationship.target_ref),
    )

    apt29 = next(
    (
        group
        for group in data["groups"]
        if group.name == "APT29"
    ),
    None,
    )

    if apt29:
        print("\nAPT29 relationships")
        print("-" * 40)

        for relationship in data["relationships"]:
            if relationship.source_ref == apt29.stix_id:
                target = entity_lookup.get(
                    relationship.target_ref
                )

                print(
                    relationship.relationship_type,
                    getattr(
                        target,
                        "name",
                        relationship.target_ref,
                    ),
                )

if __name__ == "__main__":
    main()