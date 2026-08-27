"""Allow `python -m arkham ...`."""

from arkham.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
