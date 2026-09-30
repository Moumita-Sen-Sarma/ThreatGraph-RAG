from threatgraph.retrieval.vector import (
    VectorRetriever,
)


def main() -> None:

    retriever = VectorRetriever()

    query = (
        "What exploited vulnerabilities affect Microsoft products?"
    )

    print("\nQuery:")
    print(query)

    print("\nResults:")
    print("-" * 60)

    results = retriever.search(
        query,
        top_k=5,
    )

    for index, result in enumerate(
        results,
        start=1,
    ):

        print(
            f"\n{index}. {result['title']}"
        )

        print(
            f"Type: "
            f"{result['document_type']}"
        )

        print(
            f"Source: {result['source']}"
        )

        print(
            f"Score: "
            f"{result['score']:.4f}"
        )


if __name__ == "__main__":
    main()