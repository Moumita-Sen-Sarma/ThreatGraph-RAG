from pathlib import Path

import httpx


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT_PATH = Path(
    "data/raw/cisa/known_exploited_vulnerabilities.json"
)


def main() -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("Downloading CISA KEV catalog...")

    response = httpx.get(
        CISA_KEV_URL,
        timeout=60.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    OUTPUT_PATH.write_bytes(
        response.content
    )

    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()