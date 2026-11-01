"""Run current regression tests; the unsafe v2 probes are archived as inert text."""
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    raise SystemExit(subprocess.run([sys.executable, "-m", "pytest", "tests", "-q"], cwd=root, check=False).returncode)
