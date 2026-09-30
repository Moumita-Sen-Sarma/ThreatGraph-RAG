from threatgraph.llm.client import LLMClient


def main() -> None:
    llm = LLMClient()

    response = llm.generate(
        instructions=(
            "You are a concise cybersecurity "
            "assistant."
        ),
        prompt=(
            "In one sentence, explain what "
            "MITRE ATT&CK is."
        ),
    )

    print(response)


if __name__ == "__main__":
    main()