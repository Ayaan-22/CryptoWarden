from pathlib import Path

import pytest

from src.monitoring.honey_pot import HONEY_POT_FILENAMES, CanaryManager, is_honey_pot_access


def manager(cfg):
    return CanaryManager(cfg["monitoring"]["directories"], cfg["storage"]["directory"])


def test_existing_user_files_never_adopted_or_deleted(cfg):
    root = Path(cfg["monitoring"]["directories"][0])
    for name in HONEY_POT_FILENAMES:
        (root / name).write_text("USER CONTENT")
    instance = manager(cfg)
    paths = instance.setup()
    assert len(paths) == 4 and all(".cw-canary-" in path for path in paths)
    assert all(row["status"] == "would_remove" for row in instance.cleanup())
    assert all(Path(path).exists() for path in paths)
    instance.cleanup(apply=True)
    assert all((root / name).read_text() == "USER CONTENT" for name in HONEY_POT_FILENAMES)


def test_changed_canary_is_not_deleted(cfg):
    instance = manager(cfg)
    path = next(iter(instance.setup()))
    Path(path).write_text("changed")
    results = instance.cleanup(apply=True)
    assert Path(path).exists()
    assert any(row["status"] == "changed" for row in results)


def test_manifest_persists_and_does_not_duplicate(cfg):
    first = manager(cfg)
    paths = first.setup()
    second = manager(cfg)
    assert second.setup() == paths


def test_windows_case_and_absolute_identity(cfg):
    instance = manager(cfg)
    paths = instance.setup()
    path = next(iter(paths))
    assert is_honey_pot_access(path, paths)
    import os

    if os.name == "nt":
        assert is_honey_pot_access(path.upper(), paths)


def test_replaced_canary_is_not_removed(cfg):
    instance = manager(cfg)
    path = Path(next(iter(instance.setup())))
    old = path.with_suffix(".held")
    path.rename(old)
    path.write_text("new user file")
    assert (
        instance.status(next(row for row in instance.records if row["path"] == str(path)))
        == "replaced"
    )
    instance.cleanup(apply=True)
    assert path.read_text() == "new user file"


def test_tampered_manifest_path_rejected(cfg):
    instance = manager(cfg)
    instance.setup()
    instance.records[0]["path"] = str(Path(cfg["storage"]["directory"]) / "secret")
    instance._save()
    with pytest.raises(ValueError):
        manager(cfg)
