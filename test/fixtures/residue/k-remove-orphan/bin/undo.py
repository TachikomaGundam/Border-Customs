# R2 corpus (k) synthetic remove-orphan / dead inverse (never executed): deletes a
# marker block that no code path in this artifact ever writes — suspicious, not blocking.
from pathlib import Path

DEAD_BLOCK = "# BEGIN bar PATH (dead inverse)\n# END bar PATH (dead inverse)\n"


def undo(home: Path) -> None:
    rc = home / ".bashrc"
    text = rc.read_text(encoding="utf-8")
    rc.write_text(text.replace(DEAD_BLOCK, "", 1), encoding="utf-8")
    if text.strip() == DEAD_BLOCK.strip():
        rc.unlink()
