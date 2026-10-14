from __future__ import annotations

from pathlib import Path

import httpx

from threatgraph.ingestion.cisa import (
    load_cisa_kev,
)
from threatgraph.ingestion.mitre import (
    load_mitre_objects,
)
from threatgraph.retrieval.documents import (
    cisa_to_documents,
    mitre_to_documents,
)
from threatgraph.retrieval.vector import (
    VectorRetriever,
)


MITRE_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MITRE_PATH = Path(
    "data/raw/mitre/enterprise-attack.json"
)

CISA_PATH = Path(
    "data/raw/cisa/"
    "known_exploited_vulnerabilities.json"
)


def _download_if_missing(
    url: str,
    path: Path,
) -> None:

    if path.exists():
        return

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    response = httpx.get(
        url,
        timeout=60.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    path.write_bytes(
        response.content
    )


def ensure_vector_index(
    retriever: VectorRetriever,
) -> None:
    """
    Ensure the local Qdrant collection exists.

    If it is missing, download the public
    MITRE/CISA source data and rebuild it.
    """

    if retriever.client.collection_exists(
        retriever.COLLECTION_NAME
    ):
        return

    _download_if_missing(
        MITRE_URL,
        MITRE_PATH,
    )

    _download_if_missing(
        CISA_KEV_URL,
        CISA_PATH,
    )

    mitre_data = load_mitre_objects(
        str(MITRE_PATH)
    )

    cisa_data = load_cisa_kev(
        str(CISA_PATH)
    )

    documents = (
        mitre_to_documents(mitre_data)
        + cisa_to_documents(cisa_data)
    )

    retriever.index_documents(
        documents
    )