"""Настройки из переменных окружения."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import DEFAULT_STATUS_MAP, EDITABLE_SETTINGS, ConfigError, Settings, normalize_setting


def test_defaults_and_values():
    s = Settings.from_env({})
    assert (s.data_dir, s.repos_root, s.num_ctx, s.repos_root_host) == (Path("/data"), Path("/repos"), 16384, "")
    assert s.hub_status_map == DEFAULT_STATUS_MAP
    s = Settings.from_env({"REPOS_ROOT_HOST": "D:\\work\\repos\\", "MODEL_NUM_CTX": "8192",
                           "HUB_STATUS_MAP": '{"uncertain": "Need info"}'})
    assert s.repos_root_host == "D:/work/repos" and s.num_ctx == 8192
    assert s.hub_status_map["uncertain"] == "Need info" and s.hub_status_map["true_positive"] == "Подтверждено"


@pytest.mark.parametrize("env", [
    {"MODEL_NUM_CTX": "2048"},  # не поместятся системные указания, срез и ответ
    {"MODEL_NUM_CTX": "много"},
    {"MAX_UPLOAD_MB": "0"},
    {"SCA_URGENT_CVSS": "11"},
    {"HUB_STATUS_MAP": "[1]"},
    {"HUB_STATUS_MAP": '{"maybe": "x"}'},
])
def test_bad_values_are_explained(env):
    with pytest.raises(ConfigError) as info:
        Settings.from_env(env)
    assert next(iter(env)) in str(info.value)


def test_stored_settings_override_environment():
    env = Settings.from_env({"OLLAMA_URL": "http://host.docker.internal:11434", "DEFAULT_MODEL": "qwen2.5-coder:14b"})
    assert set(env.editable()) == set(EDITABLE_SETTINGS)
    current = env.with_stored({"ollama_url": "http://127.0.0.1:11434/", "default_model": "gpt-oss:20b",
                               "hub_status_map": {"uncertain": "Need info"}, "sca_urgent_cvss": "7,5",
                               "unknown": 1})
    assert (current.ollama_url, current.default_model, current.sca_urgent_cvss) == (
        "http://127.0.0.1:11434", "gpt-oss:20b", 7.5)
    assert current.hub_status_map == {**DEFAULT_STATUS_MAP, "uncertain": "Need info"}
    assert current.data_dir == env.data_dir and env.default_model == "qwen2.5-coder:14b"  # исходные не меняются
    broken = env.with_stored({"ollama_url": "ftp://x", "sca_urgent_cvss": 42, "hub_status_map": ["x"]})
    assert (broken.ollama_url, broken.sca_urgent_cvss) == (env.ollama_url, env.sca_urgent_cvss)
    assert env.with_stored({}) is env


@pytest.mark.parametrize(("key", "value"), [
    ("ollama_url", "127.0.0.1:11434"), ("ollama_url", "http://a b"), ("default_model", "qwen\t14b"),
    ("hub_status_map", {"maybe": "x"}), ("hub_status_map", {"uncertain": "x" * 101}), ("sca_urgent_cvss", "много"),
    ("sca_urgent_cvss", True), ("sca_urgent_cvss", float("nan")), ("theme", "dark"),
])
def test_bad_setting_values_are_explained(key, value):
    with pytest.raises(ConfigError):
        normalize_setting(key, value)
