from threatgraph.llm.client import LLMClient
from threatgraph.rag.vector_rag import VectorRAG
from threatgraph.retrieval.vector import VectorRetriever


def main() -> None:
    retriever = VectorRetriever()
    llm = LLMClient()

    rag = VectorRAG(
        retriever=retriever,
        llm=llm,
    )

    question = (
        "What mitigations can reduce credential theft?"
    )

    result = rag.answer(
        question,
        top_k=5,
    )

    print("\nQUESTION")
    print("-" * 60)
    print(result["question"])

    print("\nANSWER")
    print("-" * 60)
    print(result["answer"])

    print("\nRETRIEVED SOURCES")
    print("-" * 60)

    for index, source in enumerate(
        result["sources"],
        start=1,
    ):
        print(
            f"{index}. "
            f"{source['title']} "
            f"({source['source']}) "
            f"score={source['score']:.4f}"
        )


if __name__ == "__main__":
    main()