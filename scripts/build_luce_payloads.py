from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


STATIC_KEY_PARTS = [b"sonar", b"pad-", b"literal:SonarSecure-"]
OUTPUT_DIR = Path("generated")
LIST_OUTPUT = OUTPUT_DIR / "luce-list.enc.json"
CATALOGUE_OUTPUT = OUTPUT_DIR / "luce-catalogue.enc.json"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Sonarpad-Tools/1.0 (+https://github.com/Ambro86/Sonarpad-Tools)"
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def encrypt_bytes(payload: bytes, secret_key: str) -> str:
    key = b"".join(STATIC_KEY_PARTS) + secret_key.encode("utf-8")
    encrypted = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(payload))
    return base64.b64encode(encrypted).decode("ascii")


def build_output(source_name: str, payload: bytes, secret_key: str) -> dict[str, str | int]:
    compressed_payload = gzip.compress(payload, compresslevel=9, mtime=0)
    return {
        "version": 1,
        "algorithm": "gzip-xor-base64-v1",
        "source_name": source_name,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_b64": encrypt_bytes(compressed_payload, secret_key),
        "size_bytes": len(payload),
        "compressed_size_bytes": len(compressed_payload),
    }


def write_json(path: Path, obj: dict[str, str | int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    list_url = require_env("LUCE_LIST_URL")
    catalogue_url = require_env("LUCE_CATALOGUE_URL")
    secret_key = require_env("LUCE_ENCRYPTION_KEY")

    list_payload = fetch_bytes(list_url)
    catalogue_payload = fetch_bytes(catalogue_url)

    write_json(LIST_OUTPUT, build_output("luce-list", list_payload, secret_key))
    write_json(
        CATALOGUE_OUTPUT,
        build_output("luce-catalogue", catalogue_payload, secret_key),
    )


if __name__ == "__main__":
    main()
