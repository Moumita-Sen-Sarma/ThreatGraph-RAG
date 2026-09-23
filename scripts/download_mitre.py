from pathlib import Path

import httpx


MITRE_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_PATH = Path("data/raw/mitre/enterprise-attack.json")


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    print("Downloading MITRE ATT&CK Enterprise data...")

    response = httpx.get(
        MITRE_URL,
        timeout=60.0,
        follow_redirects=True,
    )

    # Stop immediately if the download failed.
    response.raise_for_status()

    OUTPUT_PATH.write_bytes(response.content)

    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()