"""W2.4b inert-lane confirmation plant: a PEP 427 wheel carrying hostile
`.data/data/.config/...` entries (the exact shape the previous DONECLAIM
falsely claimed border flags). Expected: pip 24.0/25.0.1 installs them under
/usr/local/.config and uninstall prunes EVERYTHING — border must print
0 residue rows. This fixture proves the inertness claim is re-checkable."""
import base64
import hashlib
import os
import zipfile

SRC = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SRC, "..", "dist", "rt_plant_wheel-0.0.1-py3-none-any.whl")
DIST = "rt_plant_wheel-0.0.1.dist-info"
DATA = "rt_plant_wheel-0.0.1.data/data"

FILES = {
    "rt_plant_wheel/__init__.py": '__version__ = "0.0.1"\n',
    f"{DIST}/METADATA": "Metadata-Version: 2.1\nName: rt-plant-wheel\nVersion: 0.0.1\nSummary: inert-lane confirmation plant\nLicense: MIT\n",
    f"{DIST}/WHEEL": "Wheel-Version: 1.0\nGenerator: rt-w24b-inert-plant\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    f"{DATA}/.config/evil.txt": "planted outside site-packages; pip still records + prunes it\n",
    f"{DATA}/.config/systemd/user/evil.service": "[Unit]\nDescription=shape-only plant, no ExecStart side effects\n",
}


def ssub(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


os.makedirs(os.path.dirname(OUT), exist_ok=True)
record = []
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for rel, body in FILES.items():
        raw = body.encode()
        z.writestr(rel, raw)
        record.append(f"{rel},sha256={ssub(hashlib.sha256(raw).digest())},{len(raw)}")
    record.append(f"{DIST}/RECORD,,")
    z.writestr(f"{DIST}/RECORD", "\n".join(record) + "\n")
print(OUT)
