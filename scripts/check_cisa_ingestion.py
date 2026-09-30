from threatgraph.ingestion.cisa import (
    load_cisa_kev,
)


CISA_PATH = (
    "data/raw/cisa/"
    "known_exploited_vulnerabilities.json"
)


def main() -> None:
    data = load_cisa_kev(
        CISA_PATH
    )

    print("\nCISA KEV summary")
    print("-" * 40)

    print(
        "Vulnerabilities:",
        len(data["vulnerabilities"]),
    )

    print(
        "Vendors:",
        len(data["vendors"]),
    )

    print(
        "Products:",
        len(data["products"]),
    )

    print("\nSample vulnerability")
    print("-" * 40)

    if data["vulnerabilities"]:
        print(
            data["vulnerabilities"][0]
            .model_dump()
        )


if __name__ == "__main__":
    main()