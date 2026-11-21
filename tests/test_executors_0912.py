"""Снимок исполнителя и выбор профиля (0.9.12, ADR-0102): снимок пишется вместе с прогоном и вопросом и замораживает
параметры при постановке; профиль выключен – отказ при постановке, пауза перед отправкой (и между повторами);
прогон без снимка (до 0.9.12) не обрабатывается, «Продолжить» – новый прогон с parent_run_id; «Повторить ошибочные»
переносит снимок только при включённом профиле и прежнем адресе; вопрос идёт профилем разбора; уровень рассуждения
разрешает вызывающий по сведениям сервера."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import ask  # noqa: E402
from app.db import DEFAULT_PROVIDER_ID  # noqa: E402
from app.executors import (ASK_NUM_PREDICT, ProfileError, applied_think, choose_profile, generation, operation_options, think_rule)
from app.llm_ollama import OllamaClient  # noqa: E402
from app.triage import DISABLED_PROFILE_NOTE, LEGACY_RUN_NOTE, PROMPT_VERSION, TriageError  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from run_helpers import run_execution  # noqa: E402
from test_triage import Env, sast, wait_state  # noqa: E402

MODEL = "qwen2.5-coder:14b"


def started(tmp_path: Path, fake: FakeOllama, mask_key: bytes) -> Env:
    """Окружение тестов прогона с запущенным потоком (как фикстура env в test_triage)."""
    env = Env(tmp_path, fake, mask_key)
    env.runner.start()
    return env


def disable(db, provider_id: int = DEFAULT_PROVIDER_ID) -> None:
    with db._tx() as c:
        c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (provider_id,))


def snapshot_of(db, run_id: int) -> dict:
    return db.get_execution(db.get_run(run_id)["execution_id"])


# ============================================================================ параметры по виду операции

def test_auto_options_reproduce_current_behaviour_per_operation():
    assert operation_options("triage", 16384, {})["num_predict"] == 3072
    assert operation_options("ask", 16384, {})["num_predict"] == ASK_NUM_PREDICT == 1536
    assert operation_options("triage", 8192, {})["num_predict"] == 2048  # не больше четверти окна
    assert operation_options("ask", 4096, {})["num_predict"] == 1024
    explicit = operation_options("triage", 16384, {"num_predict": 9000})
    assert explicit["num_predict"] == 4096, "явное число тоже не больше четверти окна"
    assert set(operation_options("ask", 16384, {})) == {"temperature", "seed", "num_ctx", "num_predict"}


def test_generation_keeps_only_valid_values():
    profile = {"generation_json": json.dumps({"timeout_s": 120, "num_predict": 1000, "ask_num_predict": True,
                                              "think": "medium", "lies": 1})}
    assert generation(profile) == {"timeout_s": 120.0, "num_predict": 1000, "think": "medium"}
    assert generation({"generation_json": "мусор"}) == {}
    assert think_rule({}) == "auto" and think_rule({"think": "high"}) == "high"


def test_applied_think_follows_the_model_on_the_server():
    gptoss = {"details": {"family": "gptoss"}}
    assert applied_think("auto", "gpt-oss:20b", None) == "low"
    assert applied_think("auto", "my-alias", gptoss) == "low", "псевдоним семейства gpt-oss – по сведениям сервера"
    assert applied_think("high", "my-alias", gptoss) == "high"
    assert applied_think("high", MODEL, {"details": {"family": "qwen2"}}) is None, "другой модели уровень не уходит"


def test_client_does_not_choose_think_itself():
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)
        client.chat_json("gpt-oss:20b", [{"role": "user", "content": "x"}], {"verdict": ""}, ["verdict"], {})
        assert "think" not in fake.chats()[-1], "уровень не передан – клиент его не добавляет"
        client.chat_json("gpt-oss:20b", [{"role": "user", "content": "x"}], {"verdict": ""}, ["verdict"], {},
                         think="medium")
        assert fake.chats()[-1]["think"] == "medium"
    finally:
        fake.close()


# ============================================================================ снимок при постановке

def test_enqueue_writes_snapshot_with_the_run_and_freezes_options(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run = env.run(MODEL)
        assert run["state"] == "done"
        snap = snapshot_of(env.db, run["id"])
        data = json.loads(snap["options_json"])
        assert snap["provider_id"] == DEFAULT_PROVIDER_ID and snap["base_url"] == fake.url
        assert data["options"]["num_ctx"] == 8192 and data["options"]["num_predict"] == 2048
        assert data["operation"] == "triage" and data["think"] == "auto" and data["timeout_s"] == 900.0
        verdict_id = env.db.get_case(env.project_id, "A")["verdict_id"]
        assert env.db.verdict_execution(verdict_id)["id"] == snap["id"], "ответ модели помнит исполнителя"
        assert fake.chats()[-1]["options"]["num_ctx"] == 8192
    finally:
        env.close()
        fake.close()


def test_settings_changed_between_pause_and_resume_do_not_change_the_snapshot(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run_id = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"],
                                   execution=run_execution(env.db, env.settings, MODEL))
        env.db.set_run_state(run_id, "paused")
        env.db.set_settings({"ollama_url": "http://127.0.0.1:9"})  # адрес и профиль 1 сменились
        assert env.runner.resume(run_id)
        env.runner.start()
        assert wait_state(env.db, run_id, ("done", "error", "stopped", "paused"))["state"] == "done"
        assert fake.chats(), "прогон ушёл по адресу снимка, а не по новому"
    finally:
        env.close()
        fake.close()


def test_disabled_profile_refuses_enqueue(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        env.db.ensure_default_profile(fake.url, MODEL)
        disable(env.db)
        with pytest.raises(TriageError, match="выключен"):
            env.runner.enqueue(env.project_id, MODEL, "all")
        with pytest.raises(ProfileError):
            choose_profile(env.db, env.settings)
    finally:
        env.close()
        fake.close()


def test_profile_disabled_between_attempts_pauses_before_the_second_send(tmp_path: Path, mask_key: bytes):
    """Ответ не по формату – повтор; профиль выключили между попытками: второй запрос не уходит, находка остаётся
    в очереди, прогон на паузе с причиной."""
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])

        def first(body):
            disable(env.db)  # выключение – пока модель отвечает на первую попытку
            return "не JSON"

        fake.answers = [first]
        run = env.run(MODEL)
        assert run["state"] == "paused" and DISABLED_PROFILE_NOTE in run["last_error"]
        assert len(fake.chats()) == 1, "второй запрос не отправлен"
        assert env.db.pending_hub_ids(run["id"]) == ["A"]
    finally:
        env.close()
        fake.close()


def test_profile_disabled_while_waiting_for_generation_right(tmp_path: Path, mask_key: bytes):
    from app.llm import GENERATION
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert GENERATION.try_acquire("ask")  # право держит вопрос: прогон ждёт
        run_id = env.runner.enqueue(env.project_id, MODEL, "all")
        env.runner.start()
        wait_state(env.db, run_id, ("running",))
        disable(env.db)
        GENERATION.release()
        run = wait_state(env.db, run_id, ("paused", "done", "error"))
        assert run["state"] == "paused" and fake.chats() == []
    finally:
        env.close()
        fake.close()


# ============================================================================ продолжение новым прогоном

def test_legacy_run_is_not_processed_and_continues_as_a_new_run(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        legacy = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"])  # без снимка – как до 0.9.12
        env.runner.start()
        run = wait_state(env.db, legacy, ("paused",))
        assert run["last_error"] == LEGACY_RUN_NOTE and fake.chats() == []
        assert env.runner.continuation_reason(run)
        new_id = env.runner.continue_as_new(legacy)
        new = wait_state(env.db, new_id, ("done", "error", "paused"))
        assert new["state"] == "done" and new["parent_run_id"] == legacy and new["execution_id"]
        old = env.db.get_run(legacy)
        assert old["state"] == "stopped" and f"№{new_id}" in old["last_error"] and old["execution_id"] is None
    finally:
        env.close()
        fake.close()


def test_retry_errors_carries_snapshot_or_refuses_without_touching_the_old_run(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama(answers=["не JSON", "не JSON"])
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run = env.run(MODEL)
        errors = [r["hub_id"] for r in env.db.run_errors(run["id"])]
        assert errors == ["A"]
        snap = run["execution_id"]
        # адрес профиля сменился – отказ, прежний прогон не тронут
        env.db.set_settings({"ollama_url": "http://127.0.0.1:9"})
        with pytest.raises(TriageError, match="Адрес профиля"):
            env.runner.retry_errors(run["id"], errors)
        assert env.db.get_run(run["id"])["state"] == run["state"]
        env.db.set_settings({"ollama_url": fake.url})  # адрес вернули – снимок переносится
        new_id = env.runner.retry_errors(run["id"], errors)
        new = wait_state(env.db, new_id, ("done", "error", "paused"))
        assert new["execution_id"] == snap and new["parent_run_id"] == run["id"] and new["origin"] == "retry"
        disable(env.db)
        with pytest.raises(TriageError, match="выключен"):
            env.runner.retry_errors(new_id, ["A"])
    finally:
        env.close()
        fake.close()


def test_retry_errors_of_a_legacy_run_gets_its_own_snapshot(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        legacy = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"])
        env.db.set_run_state(legacy, "stopped")
        new_id = env.runner.retry_errors(legacy, ["A"])
        new = env.db.get_run(new_id)
        assert new["execution_id"] and new["parent_run_id"] == legacy
    finally:
        env.close()
        fake.close()


# ============================================================================ вопрос к модели

def prepared_answer(env, fake) -> None:
    env.load([sast("A", 15)])
    assert env.run(MODEL)["state"] == "done"


def test_question_gets_its_own_snapshot_and_the_verdict_profile(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        prepared_answer(env, fake)
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда значение?",
                             MODEL)
        assert q["state"] == "done" and q["execution_id"]
        snap = env.db.get_execution(q["execution_id"])
        assert json.loads(snap["options_json"])["operation"] == "ask"
        assert json.loads(snap["options_json"])["options"]["num_predict"] == min(1536, 8192 // 4)
        assert fake.chats()[-1]["options"]["num_predict"] == min(1536, 8192 // 4)
    finally:
        env.close()
        fake.close()


def test_question_on_answer_of_a_disabled_profile_is_refused(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        prepared_answer(env, fake)
        disable(env.db)
        with pytest.raises(ask.AskError, match="выключен") as e:
            ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        assert e.value.status == 409 and env.db.list_questions(env.project_id, "A") == []
    finally:
        env.close()
        fake.close()


def test_question_on_a_legacy_answer_goes_to_the_project_profile(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        prepared_answer(env, fake)
        verdict_id = env.db.get_case(env.project_id, "A")["verdict_id"]
        with env.db._tx() as c:  # ответ, полученный до 0.9.12: снимка нет
            c.execute("UPDATE verdicts SET execution_id = NULL WHERE id = ?", (verdict_id,))
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        assert q["state"] == "done" and env.db.get_execution(q["execution_id"])["provider_id"] == DEFAULT_PROVIDER_ID
    finally:
        env.close()
        fake.close()


def test_every_creation_path_fills_execution_id(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        prepared_answer(env, fake)
        ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        for table in ("runs", "verdicts", "questions"):
            rows = env.db._all(f"SELECT execution_id FROM {table}")
            assert rows and all(r["execution_id"] for r in rows), table
    finally:
        env.close()
        fake.close()


def test_cached_answer_keeps_its_own_executor(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        first = env.run(MODEL)
        verdict_id = env.db.get_case(env.project_id, "A")["verdict_id"]
        second = env.runner.enqueue(env.project_id, MODEL, "all", fresh=False)
        wait_state(env.db, second, ("done", "error", "paused"))
        assert env.db.get_case(env.project_id, "A")["verdict_id"] == verdict_id
        assert env.db.verdict_execution(verdict_id)["id"] == first["execution_id"]
    finally:
        env.close()
        fake.close()
