"""Кто исполнял (0.9.12, шаг 7): имя профиля у прогона, ответа модели и в истории разборов («профиль не записан» у
разборов до 0.9.12); журнал прогонов – контракт run-journal/2: поля /1 сохранены с теми же именами и видом, у каждого
прогона добавлен provider (имя, версия, класс, без адреса сервера); в CSV – столбцы «Провайдер» и «Где модель»."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_findings_ui import analysed, card_of  # noqa: E402
from test_web import web  # noqa: E402, F401

# Поля прогона в выгрузке run-journal/1 (0.9.11): /2 обязана сохранить их с теми же именами
V1_TOP = {"active_seconds", "agreement_pct", "answers_per_hour", "cached_verdicts", "context_sha256", "elapsed_seconds",
          "new_answers", "pending", "review_denominator", "reviews", "run", "snapshot", "time_incomplete",
          "tokens_per_second", "verdicts"}
V1_RUN = {"cached", "control", "created_at", "done", "eval_seconds", "failed", "finished_at", "fresh", "id",
          "last_error", "last_tps", "model", "model_calls", "model_seconds", "origin", "output_tokens",
          "partial_stats", "project_id", "project_name", "prompt_version", "scope", "skipped", "started_at", "state",
          "total", "updated_at"}
V1_SNAPSHOT = {"environments", "input", "queue", "workload_sha256"}


def test_run_page_card_and_history_name_the_executor(web):
    pid = analysed(web)
    db = web.app.state.db
    run_id = db._all("SELECT id FROM runs ORDER BY id DESC LIMIT 1")[0]["id"]
    assert "профиль: Ollama из «Настроек» (этот компьютер)" in web.client.get(f"/runs/{run_id}").text
    _, card = card_of(web, pid, "510001")
    assert '<span class="verdict-executor">Ollama из «Настроек» (этот компьютер)</span>' in card
    verdict_id = db.get_case(pid, "510001")["verdict_id"]
    with db._tx() as c:  # ответ до 0.9.12: профиль не записан
        c.execute("UPDATE verdicts SET execution_id = NULL WHERE id = ?", (verdict_id,))
    _, card = card_of(web, pid, "510001")
    assert "профиль не записан – разбор до 0.9.12" in card


def test_journal_export_v2_keeps_v1_fields_and_adds_the_provider(web):
    analysed(web)
    data = web.client.get("/journal/export.json").json()
    assert data["contract"] == "local-triage/run-journal/2" and data["runs"]
    for run in data["runs"]:
        assert V1_TOP <= set(run) and V1_RUN <= set(run["run"]) and V1_SNAPSHOT <= set(run["snapshot"])
        provider = run["provider"]
        assert provider["name"] == "Ollama из «Настроек»" and provider["trust"] == "local"
        assert provider["where"] == "этот компьютер" and "base_url" not in provider, "адреса сервера в выгрузке нет"
    csv = web.client.get("/journal/export.csv").text.lstrip("﻿").splitlines()
    header = csv[0].split(";")
    assert header[-2:] == ["Провайдер", "Где модель"]
    assert csv[1].split(";")[-2:] == ["Ollama из «Настроек»", "этот компьютер"]


def test_legacy_run_in_the_journal(web):
    db = web.app.state.db
    pid = db.create_project("Прежний")
    run_id = db.create_run(pid, "m", "all", "p1", [])  # без снимка – как до 0.9.12
    run = next(r for r in web.client.get("/journal/export.json").json()["runs"] if r["run"]["id"] == run_id)
    assert run["provider"] == {"id": None, "name": "профиль не записан – разбор до 0.9.12", "version": None,
                               "trust": "", "where": ""}
