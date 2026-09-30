from threatgraph.models.schema import RetrievalDocument


def mitre_to_documents(
    data: dict[str, list],
) -> list[RetrievalDocument]:
    """
    Convert normalized MITRE ATT&CK entities into
    text documents suitable for vector retrieval.
    """

    documents: list[RetrievalDocument] = []

    # Attack techniques
    for technique in data["techniques"]:
        text = (
            f"Attack technique: {technique.name}. "
            f"ATT&CK ID: {technique.external_id}. "
            f"Platforms: {', '.join(technique.platforms)}. "
            f"{technique.description or ''}"
        )

        documents.append(
            RetrievalDocument(
                id=technique.stix_id,
                title=technique.name,
                text=text,
                document_type="attack_technique",
                source="MITRE ATT&CK",
                metadata={
                    "external_id": technique.external_id,
                },
            )
        )

    # Threat groups
    for group in data["groups"]:
        text = (
            f"Threat group: {group.name}. "
            f"Aliases: {', '.join(group.aliases)}. "
            f"{group.description or ''}"
        )

        documents.append(
            RetrievalDocument(
                id=group.stix_id,
                title=group.name,
                text=text,
                document_type="threat_group",
                source="MITRE ATT&CK",
                metadata={},
            )
        )

    # Software
    for software in data["software"]:
        text = (
            f"Software: {software.name}. "
            f"Aliases: {', '.join(software.aliases)}. "
            f"{software.description or ''}"
        )

        documents.append(
            RetrievalDocument(
                id=software.stix_id,
                title=software.name,
                text=text,
                document_type="software",
                source="MITRE ATT&CK",
                metadata={},
            )
        )

    # Mitigations
    for mitigation in data["mitigations"]:
        text = (
            f"Mitigation: {mitigation.name}. "
            f"ATT&CK ID: {mitigation.external_id}. "
            f"{mitigation.description or ''}"
        )

        documents.append(
            RetrievalDocument(
                id=mitigation.stix_id,
                title=mitigation.name,
                text=text,
                document_type="mitigation",
                source="MITRE ATT&CK",
                metadata={
                    "external_id": mitigation.external_id,
                },
            )
        )

    return documents


def cisa_to_documents(
    data: dict[str, list],
) -> list[RetrievalDocument]:
    """
    Convert CISA KEV vulnerabilities into
    retrieval documents.
    """

    documents: list[RetrievalDocument] = []

    for vulnerability in data["vulnerabilities"]:

        text = (
            f"Vulnerability: {vulnerability.cve_id}. "
            f"Vendor: {vulnerability.vendor}. "
            f"Product: {vulnerability.product}. "
            f"Name: {vulnerability.vulnerability_name}. "
            f"{vulnerability.description or ''} "
            f"Required action: "
            f"{vulnerability.required_action or ''}. "
            f"Known ransomware use: "
            f"{vulnerability.known_ransomware_use or ''}."
        )

        documents.append(
            RetrievalDocument(
                id=vulnerability.cve_id,
                title=vulnerability.vulnerability_name,
                text=text,
                document_type="vulnerability",
                source="CISA KEV",
                metadata={
                    "vendor": vulnerability.vendor,
                    "product": vulnerability.product,
                },
            )
        )

    return documents