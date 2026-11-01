import os
from pathlib import Path

import pytest

# Configuration can be inspected on Linux without adopting unresolved Windows paths.
os.environ.setdefault("USERPROFILE", str(Path.home()))


@pytest.fixture
def cfg(tmp_path):
    from src.config import load_config

    root = tmp_path / "protected"
    root.mkdir()
    path = tmp_path / "config.yaml"
    path.write_text(
        f"monitoring:\n  directories: ['{root.as_posix()}']\nstorage:\n  directory: '{(tmp_path / 'runtime').as_posix()}'\n",
        encoding="utf-8",
    )
    return load_config(path)


@pytest.fixture(autouse=True)
def forbid_real_kill(monkeypatch):
    import psutil

    def forbidden(*args, **kwargs):
        raise AssertionError("Unit/integration tests must never kill a real process")

    monkeypatch.setattr(psutil.Process, "kill", forbidden)
