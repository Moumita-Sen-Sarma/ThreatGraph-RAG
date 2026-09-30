from threatgraph.ingestion.cisa import (
    parse_vulnerability,
)


def test_parse_vulnerability():
    obj = {
        "cveID": "CVE-2025-1234",
        "vendorProject": "ExampleVendor",
        "product": "ExampleProduct",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2025-01-01",
        "shortDescription": "Example description.",
        "requiredAction": "Apply updates.",
        "dueDate": "2025-01-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Example notes.",
    }

    vulnerability = (
        parse_vulnerability(obj)
    )

    assert (
        vulnerability.cve_id
        == "CVE-2025-1234"
    )

    assert (
        vulnerability.vendor
        == "ExampleVendor"
    )

    assert (
        vulnerability.product
        == "ExampleProduct"
    )

    assert (
        vulnerability.required_action
        == "Apply updates."
    )