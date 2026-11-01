"""Explicitly scoped, validated management policy; secrets and listener settings stay private."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from src.config import ConfigError, validate_config
from src.monitoring.honey_pot import safe_root

MANAGED_FIELDS = {
    "monitoring": {"directories", "ignored_extensions", "ignored_directories", "poll_interval"},
    "detection": {
        "max_modifications_per_sec",
        "window_seconds",
        "min_unique_files",
        "rename_threshold",
        "max_entropy_threshold",
        "min_file_size_for_entropy",
        "entropy_check_samples",
        "entropy_timeout",
        "suspicious_extensions",
    },
    "response": {"mode", "terminate_tree", "cooldown_seconds"},
}


def public_policy(settings):
    return {
        section: {key: deepcopy(settings[section][key]) for key in sorted(keys)}
        for section, keys in MANAGED_FIELDS.items()
    }


def candidate_policy(settings, patch):
    if not isinstance(patch, dict) or not patch or set(patch) - set(MANAGED_FIELDS):
        raise ConfigError("Only monitoring, detection and response policy can be changed")
    candidate = deepcopy(settings)
    for section, changes in patch.items():
        if not isinstance(changes, dict) or not changes or set(changes) - MANAGED_FIELDS[section]:
            raise ConfigError(f"Unsupported {section} setting")
        candidate[section].update(deepcopy(changes))
    candidate = validate_config(candidate)
    for root in candidate["monitoring"]["directories"]:
        if not safe_root(root):
            raise ConfigError(
                f"Protected directory does not exist or is not a safe local path: {root}"
            )
        excluded = {name.casefold() for name in candidate["monitoring"]["ignored_directories"]}
        if any(part.casefold() in excluded for part in Path(root).parts):
            raise ConfigError(
                f"An ignored directory name would exclude the entire protected root: {root}"
            )
    return candidate


def preview_policy(settings, patch, revision, reason):
    candidate = candidate_policy(settings, patch)
    old, new = public_policy(settings), public_policy(candidate)
    changes = [
        {"setting": f"{section}.{key}", "before": old[section][key], "after": value}
        for section, values in new.items()
        for key, value in values.items()
        if old[section][key] != value
    ]
    if not changes:
        raise ConfigError("No policy settings changed")
    digest = hashlib.sha256(
        json.dumps({"policy": new, "revision": revision, "reason": reason}, sort_keys=True).encode()
    ).hexdigest()
    warnings = [
        "Applying policy restarts active collectors and creates a recorded coverage gap.",
        "Automatic termination remains unavailable; changing mode does not enable native writer attribution.",
    ]
    if candidate["response"]["mode"] == "terminate":
        warnings.append(
            "Terminate mode permits explicit operator-requested process termination after identity and protection checks."
        )
    if old["monitoring"]["directories"] != new["monitoring"]["directories"]:
        warnings.append(
            "Removed directories will no longer be watched. Existing owned canaries are retained for reviewed cleanup."
        )
    return candidate, {
        "revision": revision,
        "preview_id": digest,
        "changes": changes,
        "warnings": warnings,
        "policy": new,
        "reason": reason,
        "requires_termination_confirmation": old["response"]["mode"] != "terminate"
        and candidate["response"]["mode"] == "terminate",
    }
