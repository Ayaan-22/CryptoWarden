"""Preview owned canary cleanup; --apply removes only unchanged owned files."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.config import Settings
from src.monitoring.honey_pot import CanaryManager
from src.utils.runtime import InstanceLock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument(
        "--apply", action="store_true", help="Remove verified owned canaries (default: preview)"
    )
    args = parser.parse_args()
    cfg = Settings.load(args.config).data
    if not Path(cfg["storage"]["directory"]).exists():
        print("[]")
        return
    lock = InstanceLock(cfg["storage"]["directory"])
    try:
        lock.acquire()
        manager = CanaryManager(cfg["monitoring"]["directories"], cfg["storage"]["directory"])
        print(json.dumps(manager.cleanup(args.apply), indent=2))
    except RuntimeError as error:
        parser.error(str(error))
    finally:
        lock.release()


if __name__ == "__main__":
    main()
