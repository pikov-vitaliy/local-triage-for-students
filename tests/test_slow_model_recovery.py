"""Сбои перезагрузки и приоритет команд управления на поддельном сервере Ollama."""

from __future__ import annotations

import threading
import time

import pytest

from app import journal, llm_ollama, metrics, triage
from test_slow_model import MODEL, answer, findings, generates
from test_triage import Env, env, wait_state  # noqa: F401


@pytest.fixture(autouse=True)
def no_hardware(monkeypatch):
    """Проверки очереди не обращаются к видеокарте."""
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)


def prepare(env: Env, count: int = 6) -> None:
    env.fake.answers = [answer(100)] * 3 + [answer(10)] * (count - 3)
    env.load(findings(count))


def saved_state(env: Env, run_id: int) -> dict:
    return journal.detail(env.db, run_id)["snapshot"]["slow_model"]


def test_failed_unload_counts_attempts_and_never_tries_a_third_time(env: Env, monkeypatch):
    def fail(handler, body):
        handler._send(500, {"error": "ошибка выгрузки"})

    monkeypatch.setattr(env.fake.server.RequestHandlerClass, "_generate", fail)
    prepare(env, 12)
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 12, 0)
    assert len(generates(env.fake)) == 2
    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow["reloads"] == 2 and slow["warning"]
    assert "перезагрузить модель не удалось:" in slow["text"]
    saved = saved_state(env, run["id"])
    assert [(event["action"], event["reloads"]) for event in saved["events"]] == [
        ("warning", 1), ("warning", 2),
    ]
    # После восстановления состояния из журнала лимит также исчерпан.
    assert env.runner._slow_state(run).reloads == 2


@pytest.mark.parametrize("control, expected", [("pause", "paused"), ("stop", "stopped")])
def test_control_before_reload_does_not_unload(env: Env, control: str, expected: str):
    entered, release = threading.Event(), threading.Event()

    def fifth(body):
        entered.set()
        assert release.wait(5), "команда управления не пришла"
        return answer(10)

    prepare(env)
    env.fake.answers[4] = fifth
    run_id = env.runner.enqueue(env.project_id, MODEL, "all")
    try:
        assert entered.wait(5)
        assert getattr(env.runner, control)(run_id)
    finally:
        release.set()
    run = wait_state(env.db, run_id, (expected,))
    assert run["done"] == 5
    assert not generates(env.fake)
    assert env.runner.run_status(run_id)["slow_model"] is None


@pytest.mark.parametrize("control, expected", [("pause", "paused"), ("stop", "stopped")])
def test_control_interrupts_wait_for_unload(env: Env, monkeypatch, control: str, expected: str):
    polled = threading.Event()
    handler_class = env.fake.server.RequestHandlerClass
    original_get = handler_class.do_GET

    def still_loaded(handler):
        if handler.path != "/api/ps":
            return original_get(handler)
        handler._record("GET", None)
        handler._send(200, {"models": [{"name": MODEL}]})
        polled.set()

    monkeypatch.setattr(handler_class, "do_GET", still_loaded)
    monkeypatch.setattr(triage, "SLOW_RELOAD_WAIT_S", 10.0)
    prepare(env)
    run_id = env.runner.enqueue(env.project_id, MODEL, "all")
    assert polled.wait(5)
    started = time.monotonic()
    assert getattr(env.runner, control)(run_id)
    run = wait_state(env.db, run_id, (expected,), timeout=2)
    assert time.monotonic() - started < 2
    assert run["done"] == 5 and len(env.fake.chats()) == 5
    assert len(generates(env.fake)) == 1
    slow = saved_state(env, run_id)
    assert slow["reloads"] == 1 and slow["warning"]
    assert "перезагружена" not in slow["text"]


@pytest.mark.parametrize("failure", ["http", "timeout", "still_loaded"])
def test_ps_failure_is_not_a_successful_reload(env: Env, monkeypatch, failure: str):
    handler_class = env.fake.server.RequestHandlerClass
    original_get = handler_class.do_GET

    def fail_ps(handler):
        if handler.path != "/api/ps":
            return original_get(handler)
        handler._record("GET", None)
        if failure == "http":
            handler._send(500, {"error": "ошибка списка моделей"})
        elif failure == "timeout":
            time.sleep(0.5)
            handler._send(200, {"models": []})
        else:
            handler._send(200, {"models": [{"name": MODEL}]})

    monkeypatch.setattr(handler_class, "do_GET", fail_ps)
    monkeypatch.setattr(llm_ollama, "PS_TIMEOUT_S", 0.15)
    monkeypatch.setattr(triage, "SLOW_RELOAD_WAIT_S", 0.3)
    monkeypatch.setattr(triage, "SLOW_RELOAD_POLL_S", 0.02)
    prepare(env)
    run = env.run()
    assert (run["state"], run["done"]) == ("done", 6)
    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow["reloads"] == 1 and slow["warning"]
    assert "перезагрузить модель не удалось:" in slow["text"]
    assert "перезагружена" not in slow["text"]
    assert [event["action"] for event in saved_state(env, run["id"])["events"]] == ["warning"]
