"""Create attack-like file patterns only inside a fresh, owned temporary directory.
This does not encrypt user files, select processes, or assert prevention success.
"""

import argparse
import json
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.monitoring.honey_pot import safe_root


def run_simulation(directory, files=20, delay=0.03):
    root = Path(directory).resolve(strict=True)
    if not safe_root(root):
        raise ValueError("Simulation requires a local non-reparse directory")
    if not 6 <= files <= 500 or not 0 <= delay <= 1:
        raise ValueError("Use 6–500 files and a delay of 0–1 seconds")
    with tempfile.TemporaryDirectory(prefix="CryptoWardenSimulation-", dir=root) as workspace:
        owned = Path(workspace).resolve()
        if owned.parent != root or not owned.name.startswith("CryptoWardenSimulation-"):
            raise RuntimeError("Simulation workspace escaped its intended root")
        for index in range(files):
            path = owned / f"fixture-{index:03d}.txt"
            with open(path, "xb") as stream:
                stream.write(b"Disposable simulation fixture. " * 256)
        for path in sorted(owned.glob("fixture-*.txt")):
            path.write_bytes(secrets.token_bytes(8192))
            path.rename(path.with_suffix(".txt.enc"))
            time.sleep(delay)
        return {
            "status": "simulation_completed",
            "owned_fixture_files": files,
            "scope": str(owned),
            "prevention_claim": False,
            "next_step": "Inspect the incident journal; process survival does not determine detection success.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        required=True,
        help="An existing protected root for a NEW disposable subdirectory",
    )
    parser.add_argument("--files", type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(run_simulation(args.directory, args.files), indent=2))


if __name__ == "__main__":
    main()
