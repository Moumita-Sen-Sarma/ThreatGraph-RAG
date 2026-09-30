from __future__ import annotations

import json
from pathlib import Path

from threatgraph.models.schema import (
    Product,
    Vendor,
    Vulnerability,
)


def parse_vulnerability(
    obj: dict,
) -> Vulnerability:
    return Vulnerability(
        cve_id=obj["cveID"],
        vendor=obj["vendorProject"],
        product=obj["product"],
        vulnerability_name=obj[
            "vulnerabilityName"
        ],
        description=obj.get(
            "shortDescription"
        ),
        date_added=obj.get("dateAdded"),
        due_date=obj.get("dueDate"),
        required_action=obj.get(
            "requiredAction"
        ),
        known_ransomware_use=obj.get(
            "knownRansomwareCampaignUse"
        ),
        notes=obj.get("notes"),
    )


def load_cisa_kev(
    path: str | Path,
) -> dict[str, list]:
    path = Path(path)

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    vulnerabilities: list[
        Vulnerability
    ] = []

    vendors: dict[str, Vendor] = {}
    products: dict[
        tuple[str, str],
        Product,
    ] = {}

    for obj in data.get(
        "vulnerabilities",
        [],
    ):
        vulnerability = (
            parse_vulnerability(obj)
        )

        vulnerabilities.append(
            vulnerability
        )

        vendor_name = (
            vulnerability.vendor
        )

        vendors.setdefault(
            vendor_name,
            Vendor(name=vendor_name),
        )

        product_key = (
            vulnerability.vendor,
            vulnerability.product,
        )

        products.setdefault(
            product_key,
            Product(
                name=vulnerability.product,
                vendor=vulnerability.vendor,
            ),
        )

    return {
        "vulnerabilities": vulnerabilities,
        "vendors": list(
            vendors.values()
        ),
        "products": list(
            products.values()
        ),
    }