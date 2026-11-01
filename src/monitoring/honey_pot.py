"""Owned canaries: exclusive creation, durable manifest, identity-checked cleanup."""

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from uuid import uuid4

from src.config import MONITOR_DIRECTORIES, config, normalize_path

# Legacy names are NEVER adopted or deleted.
HONEY_POT_FILENAMES = [
    "_passwords.txt",
    "_confidential.docx",
    "backup_keys.dat",
    "private_keys.key",
]


def is_reparse(path):
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def safe_root(path):
    path = Path(path).absolute()
    try:
        if os.name == "nt":
            import ctypes

            if (
                str(path).startswith("\\\\")
                or ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4
            ):
                return False
        return path.is_dir() and not any(is_reparse(parent) for parent in (path, *path.parents))
    except OSError:
        return False


class CanaryManager:
    def __init__(self, directories, runtime):
        self.directories = tuple(map(normalize_path, directories))
        self.runtime = Path(runtime)
        self.manifest = self.runtime / "canaries.json"
        self.records = []
        if self.manifest.exists():
            data = json.loads(self.manifest.read_text(encoding="utf-8"))
            if (
                not isinstance(data, dict)
                or data.get("version") != 1
                or not isinstance(data.get("files"), list)
            ):
                raise ValueError("Invalid canary manifest; refusing to adopt files")
            self.records = data["files"]
        self._validate_records()

    def _validate_records(self):
        for item in self.records:
            path = Path(item["path"])
            if normalize_path(path.parent) != item["root"] or not path.name.startswith(
                ".cw-canary-"
            ):
                raise ValueError("Canary manifest contains an invalid path")
            if not isinstance(item["sha256"], str) or len(item["sha256"]) != 64:
                raise ValueError("Invalid canary fingerprint")

    def _save(self):
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(dir=self.runtime, suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"version": 1, "files": self.records}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.manifest)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @property
    def paths(self):
        return {
            normalize_path(item["path"])
            for item in self.records
            if item["root"] in self.directories
        }

    def setup(self):
        for directory in self.directories:
            if not safe_root(directory):
                raise ValueError(f"Canary root is missing or has a reparse point: {directory}")
            if any(item["root"] == directory for item in self.records):
                continue
            for suffix in (".txt", ".csv", ".dat", ".key"):
                path = Path(directory) / f".cw-canary-{uuid4().hex}{suffix}"
                content = f"CryptoWarden owned integrity canary\n{uuid4().hex}\n".encode()
                with open(path, "xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                    info = os.fstat(stream.fileno())
                self.records.append(
                    {
                        "path": str(path),
                        "root": directory,
                        "inode": info.st_ino,
                        "device": info.st_dev,
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
                # Persist each ownership record before creating the next canary.
                self._save()
        return self.paths

    def status(self, item):
        path = Path(item["path"])
        if not path.exists():
            return "missing"
        try:
            if not safe_root(path.parent) or is_reparse(path):
                return "unsafe_path"
            info = path.stat()
            if info.st_ino != item["inode"] or info.st_dev != item["device"]:
                return "replaced"
            if info.st_size > 4096:
                return "changed"
            return (
                "healthy"
                if hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
                else "changed"
            )
        except OSError:
            return "unreadable"

    def health(self):
        return [
            {"path": item["path"], "status": self.status(item)}
            for item in self.records
            if item["root"] in self.directories
        ]

    def cleanup(self, apply=False):
        results, remaining = [], []
        for item in self.records:
            if item["root"] not in self.directories:
                remaining.append(item)
                continue
            status = self.status(item)
            outcome = status
            if status == "healthy":
                outcome = "would_remove"
                if apply:
                    # Recheck immediately before removing; altered/replaced/reparse files are retained.
                    if self.status(item) == "healthy":
                        Path(item["path"]).unlink()
                        outcome = "removed"
                    else:
                        outcome = "changed_during_cleanup"
            if outcome != "removed":
                remaining.append(item)
            results.append({"path": item["path"], "status": outcome})
        if apply:
            self.records = remaining
            self._save()
        return results


def setup_honey_pots():
    return CanaryManager(MONITOR_DIRECTORIES, config["storage"]["directory"]).setup()


def is_honey_pot_access(filepath, paths):
    return bool(filepath) and normalize_path(filepath) in paths
