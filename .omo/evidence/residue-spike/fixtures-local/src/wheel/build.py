"""Deterministic wheel packer for the W2.4b benign fixture (zip of the quartet + RECORD)."""
import base64
import hashlib
import os
import zipfile

SRC = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SRC, "..", "dist", "rt_benign_local-1.0.0-py3-none-any.whl")
DIST = "rt_benign_local-1.0.0.dist-info"


def ssub(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def entry_hash(path: str) -> tuple[str, int]:
    data = open(path, "rb").read()
    return ssub(hashlib.sha256(data).digest()), len(data)


files = [
    "rt_benign_local/__init__.py",
    f"{DIST}/METADATA",
    f"{DIST}/WHEEL",
]
record_lines = []
for rel in files:
    h, size = entry_hash(os.path.join(SRC, rel))
    record_lines.append(f"{rel},sha256={h},{size}")
record_lines.append(f"{DIST}/RECORD,,")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for rel in files:
        z.write(os.path.join(SRC, rel), rel)
    z.writestr(f"{DIST}/RECORD", "\n".join(record_lines) + "\n")
print(OUT)
