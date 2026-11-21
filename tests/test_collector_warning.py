"""Сборщик метрик компьютера не работает – предупреждение с инструкцией (HOSTCOL-01): на
странице прогона (там выводятся метрики), в шаге запуска прогона, в списке и профиле внешнего провайдера (без
свежих адресов компьютера внешний запрос из контейнера не уходит). Вне контейнера без следов сборщика – ни слова.
Данные выдуманы."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.telemetry import collector_state  # noqa: E402
from test_run_page_errors import prepared, start_run, wait_run, web  # noqa: E402, F401
from test_web import ORIGIN  # noqa: E402

COMMAND = r".\scripts\host-metrics.ps1 -Action Start"


def snapshot(path: Path, age: float, addresses=("192.0.2.10",)) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": 1, "collector_id": "c1", "sequence": 1, "sampled_at": time.time() - age,
                                "host_scope": "ollama_host", "cpu_pct": 5.0, "addresses": list(addresses),
                                "memory": {"total_bytes": 64 << 30, "available_bytes": 40 << 30}}), encoding="utf-8")


def host_file(web) -> Path:  # noqa: F811
    return web.settings.data_dir / "telemetry" / "host.json"


def warning_hidden(page: str) -> bool:
    """Блок предупреждения на странице прогона есть и скрыт атрибутом hidden (его открывающий тег)."""
    tag = page.split('id="collector-warning"', 1)[1].split(">", 1)[0]
    return " hidden" in f" {tag} "


def test_states(tmp_path):
    path = tmp_path / "telemetry" / "host.json"
    assert collector_state(path, expected=False)["state"] == "not_used"  # вне контейнера, сборщика здесь не было
    missing = collector_state(path, expected=True)
    assert missing["state"] == "missing" and missing["detail"] == "снимков от него нет" and not missing["addresses"]
    snapshot(path, 3)
    fresh = collector_state(path, expected=True)
    assert fresh["state"] == "ok" and fresh["addresses"] and fresh["detail"] == ""
    snapshot(path, 743 * 60)
    stale = collector_state(path, expected=False)  # сборщик здесь работал – и вне контейнера предупреждение есть
    assert stale["state"] == "stale" and stale["detail"] == "последний снимок 12 ч назад" and not stale["addresses"]
    snapshot(path, 5 * 60 + 10)
    assert collector_state(path, expected=True)["detail"] == "последний снимок 5 мин назад"
    snapshot(path, 2, addresses=())
    empty = collector_state(path, expected=True)
    assert empty["state"] == "ok" and not empty["addresses"] and "не прочитались" in empty["detail"]


def test_run_page_warns_and_status_carries_the_state(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    pid = prepared(web)
    run_id = start_run(web, pid)
    wait_run(web, run_id)
    snapshot(host_file(web), 743 * 60)
    page = web.client.get(f"/runs/{run_id}").text
    block = page.split('id="collector-warning"', 1)[1].split("</div>", 1)[0]
    assert not warning_hidden(page)
    assert "Сборщик метрик компьютера не работает" in block and "последний снимок 12 ч назад" in block
    assert COMMAND in block and "приложение перезапускать не нужно" in block
    status = web.client.get(f"/runs/{run_id}/status").json()
    assert status["collector"]["state"] == "stale"
    # сборщик снова пишет снимки – блок на странице скрыт (его же показывает и прячет скрипт по статусу)
    snapshot(host_file(web), 2)
    page = web.client.get(f"/runs/{run_id}").text
    assert warning_hidden(page)
    assert web.client.get(f"/runs/{run_id}/status").json()["collector"]["state"] == "ok"


def test_project_step_warns_before_a_run_on_this_computer(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}").text
    assert "Сборщик метрик компьютера не работает" in page and "снимков от него нет" in page and COMMAND in page
    snapshot(host_file(web), 2)
    assert "Сборщик метрик компьютера не работает" not in web.client.get(f"/projects/{pid}").text


def test_no_warning_outside_container_without_a_collector(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    pid = prepared(web)
    run_id = start_run(web, pid)
    wait_run(web, run_id)
    assert "Сборщик метрик компьютера не работает" not in web.client.get(f"/projects/{pid}").text
    assert warning_hidden(web.client.get(f"/runs/{run_id}").text)
    assert web.client.get(f"/runs/{run_id}/status").json()["collector"]["state"] == "not_used"


def test_external_profile_pages_warn_without_fresh_addresses(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    r = web.client.post("/settings/providers/new", headers=ORIGIN, follow_redirects=False, data={
        "name": "Внешний провайдер", "kind": "chat_completions", "trust": "external", "think": "auto",
        "enabled": "1", "base_url": "https://api.example.com", "default_model": "flash-model",
        "response_mode": "json_object", "action": "save"})
    assert r.status_code == 303, r.text[:2000]
    profile = next(p for p in web.app.state.db.list_providers() if p["trust"] == "external")
    for url in ("/settings/providers", f"/settings/providers/{profile['id']}"):
        page = web.client.get(url).text
        assert "Запросы к внешним провайдерам сейчас не уйдут" in page and COMMAND in page, url
    snapshot(host_file(web), 2, addresses=())  # сборщик работает, адресов нет – внешний запрос всё равно не уйдёт
    assert "адреса компьютера не прочитались" in web.client.get("/settings/providers").text
    snapshot(host_file(web), 2)
    for url in ("/settings/providers", f"/settings/providers/{profile['id']}"):
        assert "Запросы к внешним провайдерам сейчас не уйдут" not in web.client.get(url).text, url
    # профиль этого компьютера о внешних запросах не предупреждает
    snapshot(host_file(web), 743 * 60)
    assert "Запросы к внешним провайдерам" not in web.client.get("/settings/providers/1").text


def test_external_phrase_only_when_external_requests_really_stop(web, monkeypatch):  # noqa: F811
    """Сборщик молчит 2 минуты: метрики уже не видны, а адреса ещё свежие (до 5 минут) – о внешних запросах ни слова;
    после 5 минут – фраза есть; вне контейнера свежесть адресов не нужна – фразы нет (круг 7 ревью)."""
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    pid = prepared(web)
    run_id = start_run(web, pid)
    wait_run(web, run_id)

    def phrase_shown(url: str) -> bool:
        page = web.client.get(url).text
        block = page.split('class="callout callout-warn collector-warning"', 1)[1].split("</div>", 1)[0]
        if "<span data-collector-external" in block:
            span = block.split("<span data-collector-external", 1)[1]
            return not span.split(">", 1)[0].strip().endswith("hidden")
        return "запросы к внешним провайдерам не уходят" in block

    snapshot(host_file(web), 120)
    assert collector_state(host_file(web), True)["state"] == "stale"
    assert not phrase_shown(f"/runs/{run_id}") and not phrase_shown(f"/projects/{pid}")
    snapshot(host_file(web), 6 * 60)
    assert phrase_shown(f"/runs/{run_id}") and phrase_shown(f"/projects/{pid}")
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    assert not phrase_shown(f"/runs/{run_id}") and not phrase_shown(f"/projects/{pid}")
    status = web.client.get(f"/runs/{run_id}/status").json()["collector"]
    assert status["expected"] is False and status["state"] == "stale"


def test_refusal_text_says_what_to_run():
    assert COMMAND in llm_net.HOST_UNKNOWN and "после перезагрузки" in llm_net.HOST_UNKNOWN


@pytest.mark.parametrize("age", [0, 59])
def test_a_minute_of_silence_is_not_yet_a_stop(tmp_path, age):
    path = tmp_path / "host.json"
    snapshot(path, age)
    assert collector_state(path, expected=True)["state"] == "ok"
