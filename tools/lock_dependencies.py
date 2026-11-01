"""Record installed project dependency closures with PyPI release hashes.
Run only in the intended validated environment, then audit/review the resulting locks.
"""

import json
import urllib.request
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def closure(names):
    pending, found = list(names), {}
    while pending:
        name = pending.pop()
        key = canonicalize_name(name)
        if key in found:
            continue
        dist = metadata.distribution(name)
        found[key] = dist.version
        for raw in dist.requires or []:
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return found


def write_lock(filename, versions, hashes):
    lines = [
        "# Generated from the validated Python 3.11 environment.",
        "# Includes all release-distribution hashes to support platform-specific wheels.",
        "# Regenerate deliberately and run dependency + compatibility checks.",
        "",
    ]
    for name, version in sorted(versions.items()):
        lines.append(f"{name}=={version} \\")
        choices = sorted(hashes[(name, version)])
        for index, digest in enumerate(choices):
            lines.append(
                "    --hash=sha256:" + digest + (" \\" if index + 1 < len(choices) else "")
            )
    (ROOT / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    runtime = closure(
        ["starlette", "anyio", "uvicorn", "watchdog", "psutil", "PyYAML", "websockets"]
    )
    dev = closure(
        [
            *runtime,
            "pytest",
            "pytest-cov",
            "httpx",
            "httpx2",
            "ruff",
            "build",
            "setuptools",
            "wheel",
        ]
    )
    hashes = {}
    for name, version in sorted(dev.items()):
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json", timeout=15
        ) as response:
            data = json.load(response)
        hashes[(name, version)] = {
            item["digests"]["sha256"] for item in data["urls"] if not item.get("yanked")
        }
        if not hashes[(name, version)]:
            raise RuntimeError(f"No release hashes for {name}=={version}")
    write_lock("requirements.lock", runtime, hashes)
    write_lock("requirements-dev.lock", dev, hashes)
    print(f"Locked {len(runtime)} runtime and {len(dev)} development packages")


if __name__ == "__main__":
    main()
