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


MITRE_PATH = (
    "data/raw/mitre/enterprise-attack.json"
)

CISA_PATH = (
    "data/raw/cisa/"
    "known_exploited_vulnerabilities.json"
)


def main() -> None:

    print("Loading MITRE data...")

    mitre_data = load_mitre_objects(
        MITRE_PATH
    )

    print("Loading CISA KEV...")

    cisa_data = load_cisa_kev(
        CISA_PATH
    )

    print("Creating retrieval documents...")

    documents = (
        mitre_to_documents(mitre_data)
        + cisa_to_documents(cisa_data)
    )

    print(
        f"Documents to index: "
        f"{len(documents)}"
    )

    retriever = VectorRetriever()

    print("Generating embeddings...")

    retriever.index_documents(
        documents
    )

    print("Vector indexing completed.")


if __name__ == "__main__":
    main()