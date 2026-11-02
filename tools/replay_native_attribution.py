"""Read a finalized Windows kernel ETL; emit unqualified investigation evidence."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.monitoring.windows_etw import replay_etl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("etl", type=Path)
    parser.add_argument("--max-entries", type=int, default=10000)
    args = parser.parse_args()
    try:
        report = replay_etl(args.etl, max_entries=args.max_entries)
    except (OSError, ValueError) as error:
        parser.exit(2, f"No native attribution report: {error}\n")
    print(json.dumps(report, indent=2))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
