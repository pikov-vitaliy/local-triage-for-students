"""Очередь триажа, этап 2: принятый «Стоп» переживает перезапуск, замеры неудачных ответов модели входят
в скорость прогона (неполные – с пометкой), ответ про изменившийся код не привязывается, настройки из базы,
журнал без текста кода и ответов модели."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import triage  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import FINAL_RUN_STATES, STOPPED_NOTE  # noqa: E402
from app.triage import CODE_CHANGED_NOTE, PARTIAL_NOTE, TriageRunner, case_hash, current_code  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_triage import JAVA, REL, Env, env, gated, sast, wait_state  # noqa: E402, F401

CODE_MARK = "SECRET_CODE_LINE_4242"
ANSWER_MARK = "MODEL_ANSWER_TEXT_4242"


def test_accepted_stop_is_saved_and_applied_after_restart(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    environment = Env(tmp_path, fake, mask_key)  # поток очереди не запущен: «перезапуск» – новый экземпляр
    try:
        environment.load([sast("A", 15), sast("B", 20)])
        run_id = environment.db.create_run(environment.project_id, "qwen2.5-coder:14b", "all",
                                           triage.PROMPT_VERSION, ["A", "B"])
        environment.db.set_run_state(run_id, "running")  # как будто поток взял прогон и ждёт ответа модели
        assert environment.runner.stop(run_id)
        assert environment.db.get_run(run_id)["control"] == "stop"  # команда записана в базу
        assert environment.runner.run_status(run_id)["control"] == "stop"
        restarted = TriageRunner(environment.db, environment.settings, mask_key=mask_key)
        restarted.start()  # приложение перезапустилось раньше, чем закончилась текущая находка
        try:
            run = environment.db.get_run(run_id)
            assert (run["state"], run["last_error"]) == ("stopped", STOPPED_NOTE)
            assert not restarted.resume(run_id)  # остановленный прогон не продолжить
        finally:
            restarted.shutdown()
    finally:
        environment.close()
        fake.close()


def test_pause_command_is_saved_and_cleared(env: Env):
    entered, gate, handler = gated()
    env.fake.answers = [handler]
    env.load([sast("A", 15), sast("B", 20)])
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    assert entered.wait(10)
    assert env.runner.pause(run_id) and env.db.get_run(run_id)["control"] == "pause"
    assert env.runner.resume(run_id) and env.db.get_run(run_id)["control"] == ""
    assert env.runner.stop(run_id) and env.db.get_run(run_id)["control"] == "stop"
    gate.set()
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert (run["state"], run["control"]) == ("stopped", "")


def test_failed_answers_count_in_speed(env: Env):
    env.fake.answers = ["не JSON", "снова не JSON"]  # дважды не по формату: оба ответа сгенерированы целиком
    env.load([sast("A", 15)])
    run = env.run()
    assert (run["state"], run["failed"], run["partial_stats"]) == ("done", 1, 0)
    assert run["output_tokens"] == 600 and run["eval_seconds"] == pytest.approx(6.0)  # 2 × 300 токенов за 3 с
    assert env.runner.run_status(run["id"])["tps_avg"] == pytest.approx(100.0)


def test_transport_failure_marks_partial_stats(env: Env):
    env.fake.answers = [("drop",)]  # соединение оборвалось, сервер жив: что успела модель, неизвестно
    env.load([sast("A", 15), sast("B", 20)])
    run = env.run()
    assert (run["state"], run["failed"], run["partial_stats"]) == ("done", 1, 1)
    [_, failed] = env.db.recent_items(run["id"])
    assert failed["stats_partial"] == 1 and failed["error"].endswith(PARTIAL_NOTE)
    assert env.runner.run_status(run["id"])["run"]["partial_stats"] == 1


def test_answer_without_substance_is_asked_again(env: Env):
    # «истинная» без способа исправления не принимается: повтор с перечнем замечаний
    env.fake.answers = [verdict_answer("true_positive", fix=""), verdict_answer("true_positive")]
    env.load([sast("A", 15)])
    run = env.run()
    assert (run["state"], run["failed"], len(env.fake.chats())) == ("done", 0, 2)
    case = env.db.get_case(env.project_id, "A")
    assert case["verdict"]["data"]["fix"] and case["verdict"]["stats"]["attempts"] == 2


def test_answer_about_changed_code_is_not_linked(env: Env):
    entered, gate, handler = gated(verdict_answer("true_positive"))
    env.fake.answers = [handler]
    env.load([sast("A", 15)])
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    assert entered.wait(10)
    shown = env.db.get_case(env.project_id, "A")["case_hash"]  # срез сохранён до обращения к модели
    path = env.settings.repos_root / "billing-core" / REL
    path.write_text(JAVA.replace("byOwner", "findByOwner"), encoding="utf-8")  # правка в рабочей копии
    gate.set()
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert (run["state"], run["skipped"]) == ("done", 1)
    [item] = env.db.recent_items(run_id)
    assert item["error"] == CODE_CHANGED_NOTE
    case = env.db.get_case(env.project_id, "A")
    assert case["case_hash"] == shown and case["verdict_id"] is None  # ответ не привязан
    assert env.db.find_verdict(shown, "qwen2.5-coder:14b", triage.PROMPT_VERSION) is not None  # но он в кэше


def test_current_code_matches_run_fingerprint(env: Env):
    env.load([sast("A", 15)])
    assert env.run()["state"] == "done"
    source = env.db.case_input(env.project_id, "A")
    f, ctx, chash = current_code(env.settings, source, env.runner._mask_key)
    assert chash == env.db.get_case(env.project_id, "A")["case_hash"] == case_hash(f, ctx)


def test_run_uses_ollama_url_from_settings(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    environment = Env(tmp_path, fake, mask_key)
    # в окружении – адрес, где Ollama нет; в настройках из интерфейса – рабочий
    dead = Settings(data_dir=environment.settings.data_dir, repos_root=environment.settings.repos_root,
                    ollama_url="http://127.0.0.1:9", num_ctx=8192)
    environment.db.set_settings({"ollama_url": fake.url})
    runner = TriageRunner(environment.db, dead, mask_key=mask_key)
    try:
        runner.start()
        environment.load([sast("A", 15)])
        run_id = runner.enqueue(environment.project_id, "qwen2.5-coder:14b", "all")
        assert wait_state(environment.db, run_id, FINAL_RUN_STATES)["state"] == "done" and fake.chats()
        assert runner.current_settings().ollama_url == fake.url
    finally:
        runner.shutdown()
        environment.close()
        fake.close()


# ============================================================================ журнал без данных находок

def _assert_clean_log(caplog, *marks: str) -> list[str]:
    text = caplog.text
    for mark in marks:
        assert mark not in text
    ids = re.findall(r"ошибка ([0-9a-f]{8})", text)
    assert ids, text
    return ids


def test_failure_logs_have_type_and_id_without_code_or_answer(env: Env, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def broken_context(*args, **kwargs):
        try:
            raise KeyError(f"{ANSWER_MARK}")
        except KeyError as cause:
            raise ValueError(f"не разобрано: {CODE_MARK}") from cause

    monkeypatch.setattr(triage, "build_context", broken_context)
    env.load([sast("A", 15)])
    run = env.run()
    [item] = env.db.recent_items(run["id"])
    ids = _assert_clean_log(caplog, CODE_MARK, ANSWER_MARK)
    assert "ValueError ← KeyError" in caplog.text and "broken_context" in caplog.text
    assert item["error"] == f"Не удалось собрать контекст: ValueError (ошибка {ids[-1]})"


def test_parse_failure_and_internal_error_logs_are_clean(env: Env, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def bad_parse(obj, ctx=None):
        raise RuntimeError(f"ответ модели: {ANSWER_MARK}; код: {CODE_MARK}")

    monkeypatch.setattr(triage, "parse_verdict", bad_parse)
    env.load([sast("A", 15)])
    run = env.run()
    assert run["failed"] == 1 and run["output_tokens"] == 300  # ответ сгенерирован – в скорости он учтён
    _assert_clean_log(caplog, CODE_MARK, ANSWER_MARK)
    caplog.clear()

    def broken(run_id):
        raise RuntimeError(f"внутренняя ошибка с кодом {CODE_MARK}")

    monkeypatch.setattr(env.db, "next_pending_item", broken)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all", fresh=True)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    _assert_clean_log(caplog, CODE_MARK)
    # номер – из записи об этом прогоне: в журнал в это же время пишут и фоновые циклы других прогонов (их запись после
    # нужной делала «последний номер» чужим – нестабильное падение 11.11)
    own = re.findall(r"прерван внутренней ошибкой[^\n]*ошибка ([0-9a-f]{8})", caplog.text)
    assert own, caplog.text
    assert run["state"] == "error" and f"(ошибка {own[-1]})" in run["last_error"]
    assert CODE_MARK not in run["last_error"]


def test_log_failure_helper(caplog):
    from app.logsafe import error_frames, error_types, log_failure

    log = logging.getLogger("local_triage.test")
    caplog.set_level(logging.DEBUG)
    try:
        try:
            raise OSError(CODE_MARK)
        except OSError:
            raise RuntimeError(ANSWER_MARK)  # noqa: B904 – цепочка через __context__
    except RuntimeError as e:
        assert error_types(e) == "RuntimeError ← OSError"
        assert "test_log_failure_helper" in error_frames(e)
        eid = log_failure(log, "проверка %s", e, 7)
    assert re.fullmatch(r"[0-9a-f]{8}", eid)
    assert f"проверка 7: RuntimeError ← OSError [ошибка {eid}]" in caplog.text
    assert CODE_MARK not in caplog.text and ANSWER_MARK not in caplog.text
