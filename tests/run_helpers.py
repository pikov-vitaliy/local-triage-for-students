"""Помощники тестов: снимок исполнителя (ADR-0102) для прогона, созданного в тесте напрямую через db.create_run, – как
у прогона, поставленного приложением (TriageRunner.enqueue)."""

from __future__ import annotations

from typing import Any

from app.executors import choose_profile, execution_values


def run_execution(db: Any, settings: Any, model: str, project: Any = None) -> dict[str, Any]:
    """Значения снимка исполнителя для db.create_run(..., execution=...): профиль проекта или приложения."""
    profile = choose_profile(db, settings, project)
    return execution_values(profile, model, "triage", settings.num_ctx, settings.model_json_schema)
