# R2 corpus (k) synthetic CLI-inverse surface for the paired fixture (never executed).
# Depth-1 hop from the console-script entry (bin/aihr-setup -> this file) to the
# remove-path functions in setup_env.py: exactly the cli_setup.py shape of §5.2.
import argparse

from setup_env import persist_path, remove_path


def main() -> int:
    parser = argparse.ArgumentParser(prog="aihr-setup")
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove everything setup added (PATH marker blocks).",
    )
    args = parser.parse_args()
    if args.uninstall:
        return 0 if remove_path() else 1
    return 0 if persist_path() else 1


if __name__ == "__main__":
    raise SystemExit(main())
