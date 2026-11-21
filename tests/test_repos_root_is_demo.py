"""Бэклог 94: признак подключения демо-папки приложения из окружения – три состояния."""
import pytest

from app.config import Settings


@pytest.mark.parametrize("raw, value", [("1", "1"), ("0", "0"), ("", ""), ("yes", ""), (" 1 ", "1")])
def test_repos_root_is_demo_from_env(raw, value):
    assert Settings.from_env({"REPOS_ROOT_IS_DEMO": raw}).repos_root_is_demo == value
    assert Settings.from_env({}).repos_root_is_demo == ""
