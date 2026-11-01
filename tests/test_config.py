import pytest

from src.config import ConfigError, load_config


@pytest.mark.parametrize(
    "content",
    [
        "response:\n  mode: typo\n",
        "response: null",
        "detection:\n  max_entropy_threshold: 9",
        "detection:\n  min_unique_files: true",
        "dashboard:\n  port: 1",
        "dashboard:\n  host: 0.0.0.0",
        "dashboard:\n  auth_token: short",
        "monitoring:\n  directories: []",
        "storage:\n  retention_days: 0",
        "unknown: value",
        "monitoring: [broken",
        "response:\n  terminate_tree: yesplease",
        "monitoring:\n  directories: ['%CW_MISSING_VARIABLE%/files']",
        "monitoring:\n  ignored_extensions: text",
        "false",
        "[]",
        "response:\n  mode: []",
        "whitelist:\n  processes: ['chrome.exe']",
    ],
)
def test_invalid_configuration_fails_closed(tmp_path, content):
    path = tmp_path / "bad.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_explicit_missing_file_is_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")


def test_safe_default_and_relative_resolution(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("monitoring:\n  directories: ['documents']\nstorage:\n  directory: 'runtime'\n")
    cfg = load_config(path)
    assert cfg["response"]["mode"] == "alert_only"
    from src.config import normalize_path

    assert cfg["monitoring"]["directories"][0] == normalize_path(tmp_path / "documents")


def test_overlapping_roots_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("monitoring:\n  directories: ['root','root/child']\n")
    with pytest.raises(ConfigError):
        load_config(path)
