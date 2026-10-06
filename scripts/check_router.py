from threatgraph.llm.client import LLMClient
from threatgraph.rag.router import QueryRouter


def main() -> None:
    llm = LLMClient()

    router = QueryRouter(
        llm=llm
    )

    questions = [
        "What techniques does APT29 use?",

        "Which software is associated with APT29?",

        "What mitigations apply to T1003?",

        (
            "If APT29 performs Credential Dumping, "
            "what mitigations should we apply?"
        ),
    ]

    for question in questions:
        print("\nQUESTION")
        print("-" * 60)
        print(question)

        result = router.route(
            question
        )

        print("\nROUTED QUERY")
        print(result.model_dump())


if __name__ == "__main__":
    main()