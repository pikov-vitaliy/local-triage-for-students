"""Модель по умолчанию по замеру (ADR 0026): gpt-oss:20b в настройках по умолчанию и замена прежнего умолчания
qwen2.5-coder:14b шагом обновления 8 – только если человек его не менял.

Проверяется поведение:
* новая база и настройки без окружения – gpt-oss:20b; DEFAULT_MODEL из окружения – начальное значение новой базы
  и шагом обновления не заменяется;
* база схемы 7: сохранённая qwen2.5-coder:14b (в любом регистре, с пробелами) или пустое значение заменяются
  gpt-oss:20b, другая модель и испорченное значение остаются, нет строки – ничего не появляется;
* замена – один раз: выбранная после обновления qwen2.5-coder:14b при следующих запусках не меняется;
* приложение на базе схемы 7 показывает новую модель по умолчанию на странице «Настройки» и в /api/ollama.
"""

from __future__ import annotations

from pathlib import Path


from app.config import DEFAULT_MODEL, LEGACY_DEFAULT_MODEL, Settings
from app.db import Database

BASE = "http://127.0.0.1:8765"


def test_default_model_is_benchmark_choice():
    assert DEFAULT_MODEL == "gpt-oss:20b" and LEGACY_DEFAULT_MODEL == "qwen2.5-coder:14b"
    assert Settings().default_model == DEFAULT_MODEL
    assert Settings.from_env({}).default_model == DEFAULT_MODEL
    assert Settings.from_env({"DEFAULT_MODEL": "qwen2.5-coder:14b"}).default_model == "qwen2.5-coder:14b"


def test_new_database_keeps_model_from_environment(tmp_path: Path):
    """Новая база шагов обновления не проходит: DEFAULT_MODEL из окружения – начальное значение, как и прежде."""
    path = tmp_path / "triage.db"
    db = Database(path)
    try:
        db.seed_settings(Settings.from_env({"DEFAULT_MODEL": LEGACY_DEFAULT_MODEL}).editable())
    finally:
        db.close()
    db = Database(path)
    try:
        assert db.get_settings()["default_model"] == LEGACY_DEFAULT_MODEL
    finally:
        db.close()
