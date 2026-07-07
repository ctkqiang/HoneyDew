#!/usr/bin/env python3
"""Generate PNG images from Mermaid diagram files using mermaid.ink API."""

import base64
import json
import urllib.request
import urllib.parse
from pathlib import Path


def generate_png(input_file: Path, output_file: Path) -> None:
    """Generate a PNG from a Mermaid .mmd file via mermaid.ink."""
    diagram_text = input_file.read_text(encoding="utf-8")

    # mermaid.ink expects a JSON object with "code" field, then base64url encoded
    payload = json.dumps({"code": diagram_text})
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")

    url = f"https://mermaid.ink/img/{encoded}?type=png"

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "HoneyDew-docs-generator/1.0",
            "Accept": "image/png",
        },
    )

    with urllib.request.urlopen(req, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(
                f"Failed to generate {output_file.name}: HTTP {response.status}"
            )
        data = response.read()
        output_file.write_bytes(data)

    print(f"Generated: {output_file}")


def main() -> None:
    docs_dir = Path(__file__).parent
    for mmd_file in sorted(docs_dir.glob("*.mmd")):
        png_file = docs_dir / f"{mmd_file.stem}.png"
        try:
            generate_png(mmd_file, png_file)
        except Exception as exc:
            print(f"Error generating {png_file.name}: {exc}")
            raise


if __name__ == "__main__":
    main()
