"""Validated, fail-closed configuration; paths resolve relative to the config file."""

import ipaddress
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = {
    "monitoring": {
        "directories": [str(Path.home() / "Documents")],
        "ignored_extensions": [".tmp", ".log"],
        "ignored_directories": [
            ".git",
            ".venv",
            "__pycache__",
            ".pytest_cache",
            ".cryptowarden",
            ".agents",
        ],
        "queue_capacity": 4096,
        "poll_interval": 1.0,
    },
    "detection": {
        "max_modifications_per_sec": 5,
        "window_seconds": 10,
        "min_unique_files": 6,
        "rename_threshold": 4,
        "max_entropy_threshold": 7.5,
        "min_file_size_for_entropy": 1024,
        "entropy_check_samples": 8,
        "entropy_timeout": 2.0,
        "suspicious_extensions": [".enc", ".crypt", ".locked", ".wannacry", ".locky", ".aes"],
    },
    "response": {
        "mode": "alert_only",
        "protected_processes": [
            "System",
            "Registry",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
        ],
        "terminate_tree": False,
        "cooldown_seconds": 30,
    },
    "whitelist": {"processes": []},
    "dashboard": {"host": "127.0.0.1", "port": 8001, "auth_token": "", "session_seconds": 3600},
    "storage": {
        "directory": str(PROJECT_ROOT / ".cryptowarden"),
        "retention_days": 30,
        "max_incidents": 10000,
    },
}


class ConfigError(ValueError):
    pass


def normalize_path(path):
    return os.path.normcase(os.path.abspath(os.path.normpath(os.fspath(path))))


def normalize_process_name(name):
    return str(name or "").strip().casefold()


def _merge(defaults, overrides, prefix=""):
    if not isinstance(overrides, dict):
        raise ConfigError(f"{prefix or 'configuration'} must be a mapping")
    for key, value in overrides.items():
        if key not in defaults:
            raise ConfigError(f"Unknown setting: {prefix}{key}")
        if isinstance(defaults[key], dict):
            _merge(defaults[key], value, f"{prefix}{key}.")
        else:
            defaults[key] = value


def _number(section, key, low, high, integer=False):
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ConfigError(f"{key} must be between {low} and {high}")
    if integer and not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer")


def _strings(section, key):
    values = section[key]
    if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
        raise ConfigError(f"{key} must be a list of nonempty strings")
    return values


def load_config(path=None):
    explicit = path is not None or "CRYPTOWARDEN_CONFIG" in os.environ
    filename = Path(
        path or os.environ.get("CRYPTOWARDEN_CONFIG", PROJECT_ROOT / "config.yaml")
    ).absolute()
    data = deepcopy(DEFAULTS)
    if filename.exists():
        try:
            loaded = yaml.safe_load(filename.read_text(encoding="utf-8"))
            _merge(data, {} if loaded is None else loaded)
        except (OSError, yaml.YAMLError) as error:
            raise ConfigError(f"Cannot load configuration: {filename}: {error}") from error
    elif explicit:
        raise ConfigError(f"Configuration does not exist: {filename}")
    return validate_config(data, filename.parent)


def validate_config(overrides, base_directory=None):
    """Validate an in-memory candidate with the same rules as startup configuration."""
    data = deepcopy(DEFAULTS)
    _merge(data, overrides)
    base_directory = Path(base_directory or PROJECT_ROOT)
    m, d, r, w, h, s = (
        data[k]
        for k in ("monitoring", "detection", "response", "whitelist", "dashboard", "storage")
    )
    roots = _strings(m, "directories")
    if not 1 <= len(roots) <= 32:
        raise ConfigError("Use between one and 32 monitored directories")
    resolved = []
    for value in roots:
        value = os.path.expanduser(os.path.expandvars(value))
        if re.search(r"%[^%]+%|\$[A-Za-z_{]", value):
            raise ConfigError(f"Unexpanded variable in directory: {value}")
        item = Path(value)
        resolved.append(normalize_path(item if item.is_absolute() else base_directory / item))
    if len(set(resolved)) != len(resolved):
        raise ConfigError("Duplicate monitoring directories")
    for left in resolved:
        for right in resolved:
            if left != right and Path(left) in Path(right).parents:
                raise ConfigError("Monitoring directories must not overlap")
    m["directories"] = resolved
    for section, key in ((m, "ignored_extensions"), (d, "suspicious_extensions")):
        section[key] = ["." + value.lstrip(".").casefold() for value in _strings(section, key)]
    _strings(m, "ignored_directories")
    _strings(r, "protected_processes")
    _strings(w, "processes")
    if w["processes"]:
        raise ConfigError(
            "Name-only whitelist rules are unsupported; remove them and use executable review records"
        )
    if not isinstance(r["mode"], str) or r["mode"] not in {"alert_only", "dry_run", "terminate"}:
        raise ConfigError("response.mode must be alert_only, dry_run, or terminate")
    if type(r["terminate_tree"]) is not bool:
        raise ConfigError("terminate_tree must be boolean")
    for section, key, low, high, integer in [
        (m, "queue_capacity", 16, 100000, True),
        (m, "poll_interval", 0.2, 60, False),
        (d, "max_modifications_per_sec", 0.1, 10000, False),
        (d, "window_seconds", 1, 60, False),
        (d, "min_unique_files", 2, 10000, True),
        (d, "rename_threshold", 2, 10000, True),
        (d, "max_entropy_threshold", 0, 8, False),
        (d, "min_file_size_for_entropy", 1, 1048576, True),
        (d, "entropy_check_samples", 1, 64, True),
        (d, "entropy_timeout", 0.1, 10, False),
        (r, "cooldown_seconds", 1, 3600, False),
        (h, "port", 1024, 65535, True),
        (h, "session_seconds", 60, 86400, True),
        (s, "retention_days", 1, 365, True),
        (s, "max_incidents", 100, 100000, True),
    ]:
        _number(section, key, low, high, integer)
    try:
        if not isinstance(h["host"], str) or not ipaddress.ip_address(h["host"]).is_loopback:
            raise ConfigError("Dashboard must bind to a loopback IP address")
    except (ValueError, TypeError) as error:
        raise ConfigError("dashboard.host must be a loopback IP address") from error
    if (
        not isinstance(h["auth_token"], str)
        or not h["auth_token"].isascii()
        or (h["auth_token"] and len(h["auth_token"]) < 32)
    ):
        raise ConfigError(
            "auth_token must be empty (generate at startup) or at least 32 characters"
        )
    if not isinstance(s["directory"], str) or not s["directory"].strip():
        raise ConfigError("storage.directory must be a path")
    storage = Path(os.path.expandvars(os.path.expanduser(s["directory"])))
    s["directory"] = normalize_path(storage if storage.is_absolute() else base_directory / storage)
    return data


@dataclass(frozen=True)
class Settings:
    data: dict

    @classmethod
    def load(cls, path=None):
        return cls(load_config(path))


# Imports must not read or validate an unrelated working-copy configuration.
# Entry points load one explicit snapshot; compatibility constants are safe defaults.
config = deepcopy(DEFAULTS)
MONITOR_DIRECTORIES = tuple(config["monitoring"]["directories"])
IGNORED_EXTENSIONS = frozenset(config["monitoring"]["ignored_extensions"])
IGNORED_DIRECTORIES = frozenset(config["monitoring"]["ignored_directories"])
MAX_FILE_MODIFICATIONS_PER_SEC = config["detection"]["max_modifications_per_sec"]
MAX_ENTROPY_THRESHOLD = config["detection"]["max_entropy_threshold"]
MIN_FILE_SIZE_FOR_ENTROPY = config["detection"]["min_file_size_for_entropy"]
ENTROPY_CHECK_SAMPLES = config["detection"]["entropy_check_samples"]
SUSPICIOUS_EXTENSIONS = frozenset(config["detection"]["suspicious_extensions"])
PROTECTED_PROCESS_NAMES = frozenset(
    map(normalize_process_name, config["response"]["protected_processes"])
)
RESPONSE_MODE = config["response"]["mode"]
DASHBOARD_HOST = config["dashboard"]["host"]
DASHBOARD_PORT = config["dashboard"]["port"]
DASHBOARD_AUTH_TOKEN = config["dashboard"]["auth_token"]


def is_whitelisted_process(_name):
    """Basenames cannot establish trust; compatibility shim, never a response exemption."""
    return False
