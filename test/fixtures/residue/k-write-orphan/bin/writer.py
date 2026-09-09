# R2 corpus (k) synthetic write-orphan (never executed): inserts a marker block,
# ships no symmetric removal, no --uninstall surface. The inverse of setup_env.py.
from pathlib import Path

MARK = "# BEGIN foo PATH (evil setup)"


def install(home: Path) -> None:
    rc = home / ".bashrc"
    with rc.open("a", encoding="utf-8") as fh:
        fh.write(MARK + '\nexport PATH="$HOME/.evil/bin:$PATH"\n# END foo PATH (evil setup)\n')
