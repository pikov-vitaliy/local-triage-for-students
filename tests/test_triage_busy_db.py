"""Занятая база в прогоне (Э2): запись результата находки повторяется, затем прогон встаёт на
паузу с причиной, а находка остаётся в очереди – «Продолжить» её берёт (незаписанный ответ модели получается заново);
это не «ошибка» находки и не «ошибка» прогона; принятый «Стоп» не теряется. Модель поддельная."""

from __future__ import annotations

import time

import pytest

from app import triage
from app.db import FINAL_RUN_STATES, BUSY_TEXT, DatabaseBusy
from fake_ollama import verdict_answer
from test_triage import Env, env, sast, wait_state  # noqa: F401


def busy_times(env: Env, monkeypatch, method: str, times: int) -> list[int]:  # noqa: F811
    """Метод базы отвечает «база занята» первые times вызовов (times < 0 – всегда)."""
    original = getattr(env.db, method)
    calls = [0]

    def flaky(*args, **kwargs):
        calls[0] += 1
        if times < 0 or calls[0] <= times:
            raise DatabaseBusy(BUSY_TEXT)
        return original(*args, **kwargs)

    monkeypatch.setattr(env.db, method, flaky)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    return calls


def test_busy_write_is_retried(env: Env, monkeypatch):  # noqa: F811
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive")]
    calls = busy_times(env, monkeypatch, "save_verdict", 1)
    run = env.run()
    assert run["state"] == "done" and run["failed"] == 0
    assert calls[0] == 2 and env.db.get_case(env.project_id, "A")["verdict"]


@pytest.mark.parametrize("method", ["save_verdict", "save_case", "finish_item"])
def test_lost_commit_answer_is_retried_without_duplicate(env: Env, monkeypatch, method):  # noqa: F811
    """Сервер подтвердил COMMIT, ответ потерян. Эти записи безопасно повторить: нет ни ошибки находки, ни второго вердикта."""
    from contextlib import contextmanager

    from app.storage import CommitUnknown
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive"), verdict_answer("true_positive")]
    real_tx, real = env.db._tx, getattr(env.db, method)
    inside, lost = [False], [0]

    @contextmanager
    def tx(*args, **kwargs):
        with real_tx(*args, **kwargs) as c:
            yield c
        if inside[0] and not lost[0]:
            lost[0] = 1
            raise CommitUnknown("результат неизвестен")

    def spy(*args, **kwargs):
        inside[0] = True
        try:
            return real(*args, **kwargs)
        finally:
            inside[0] = False
    monkeypatch.setattr(env.db, "_tx", tx)
    monkeypatch.setattr(env.db, method, spy)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert lost[0] == 1
    assert run["state"] == "done" and run["failed"] == 0 and run["done"] == 1, run
    assert env.db._scalar("SELECT COUNT(*) FROM verdicts") == 1, "повтор записи не задвоил вердикт"
    assert env.db.get_case(env.project_id, "A")["verdict"]


def test_lost_commit_answer_of_cached_item_pauses_and_goes_on(env: Env, monkeypatch):  # noqa: F811
    """Находка с готовым вердиктом: завершение без повтора подтвердилось, ответ потерян – пауза, а не ошибка всего прогона."""
    from app.storage import CommitUnknown
    env.load([sast("A", 15), sast("B", 15)])
    env.fake.answers = [verdict_answer("true_positive"), verdict_answer("true_positive")]
    first = wait_state(env.db, env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all"), FINAL_RUN_STATES)
    assert first["state"] == "done" and first["done"] == 2, first
    real, lost = env.db.finish_item, [0]

    def once(*args, **kwargs):
        real(*args, **kwargs)
        if not lost[0]:
            lost[0] = 1
            raise CommitUnknown("результат неизвестен")
    monkeypatch.setattr(env.db, "finish_item", once)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert lost[0] == 1 and run["state"] == "paused" and run["failed"] == 0, run
    assert run["last_error"] == triage.DB_UNKNOWN_PAUSE, "запись могла подтвердиться: текст не утверждает обратного"
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done" and run["failed"] == 0 and run["done"] == 2, run


def test_lost_commit_answer_at_run_start_is_a_pause_not_an_error(env: Env, monkeypatch):  # noqa: F811
    """Старт прогона подтвердился, ответ потерян: пауза с честным текстом, а не «внутренняя ошибка»."""
    from app.storage import CommitUnknown
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive")]
    real, lost = env.db.set_run_state, [0]

    def once(run_id, state, *args, **kwargs):
        result = real(run_id, state, *args, **kwargs)
        if state == "running" and not lost[0]:
            lost[0] = 1
            raise CommitUnknown("результат неизвестен")
        return result
    monkeypatch.setattr(env.db, "set_run_state", once)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert lost[0] == 1 and run["state"] == "paused" and run["last_error"] == triage.DB_UNKNOWN_PAUSE, run
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done" and run["failed"] == 0, run


def test_lost_commit_when_start_was_not_saved_does_not_loop(env: Env, monkeypatch):  # noqa: F811
    """Запись старта не подтвердилась: прогон не берётся снова и снова, а встаёт на паузу и не держит очередь."""
    from app.storage import CommitUnknown
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive")]
    real, calls = env.db.set_run_state, [0]

    def lost(run_id, state, *args, **kwargs):
        if state == "running":
            calls[0] += 1
            raise CommitUnknown("результат неизвестен")
        return real(run_id, state, *args, **kwargs)
    monkeypatch.setattr(env.db, "set_run_state", lost)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert run["state"] == "paused" and calls[0] == 1, run
    monkeypatch.undo()
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done" and run["failed"] == 0, run


def test_busy_outside_item_is_a_pause_not_an_internal_error(env: Env, monkeypatch):  # noqa: F811
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive")]
    from app import journal
    real, calls = journal.environment, [0]

    def busy(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 1:
            raise DatabaseBusy(BUSY_TEXT)
        return real(*args, **kwargs)
    monkeypatch.setattr(journal, "environment", busy)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert run["state"] == "paused" and run["last_error"] == triage.DB_RUN_PAUSE, run
    assert "находка осталась" not in run["last_error"], "находка в этот момент не разбиралась"
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done", run


def test_failed_pause_is_kept_and_queue_thread_survives(env: Env, monkeypatch):  # noqa: F811
    env.runner.shutdown()  # поток очереди не должен взять этот прогон
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    real = env.db.set_run_state

    def full(*args, **kwargs):
        raise RuntimeError("нет места на диске")
    monkeypatch.setattr(env.db, "set_run_state", full)
    env.runner._pause_after_db_failure(run_id, triage.DB_UNKNOWN_PAUSE)  # исключение не выходит наружу
    assert env.runner._unsaved_pauses[run_id] == triage.DB_UNKNOWN_PAUSE
    monkeypatch.setattr(env.db, "set_run_state", real)
    env.runner._save_pending_errors()
    assert run_id not in env.runner._unsaved_pauses
    assert env.db.get_run(run_id)["state"] == "paused", "прогон из очереди тоже встаёт на паузу"


def test_finished_run_is_not_paused_and_its_memory_is_cleared(env: Env):  # noqa: F811
    env.runner.shutdown()  # поток очереди не должен взять этот прогон
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    env.db.set_run_state(run_id, "done")
    env.runner._slow[run_id] = object()
    env.runner._pause_after_db_failure(run_id, triage.DB_UNKNOWN_PAUSE)
    assert env.db.get_run(run_id)["state"] == "done" and run_id not in env.runner._slow


@pytest.mark.parametrize("command, state", [("stop", "stopped"), ("pause", "paused")])
def test_command_with_lost_commit_answer_still_acts(env: Env, monkeypatch, command, state):  # noqa: F811
    """Команда записалась, ответ потерян: оператор узнаёт о неизвестном исходе, а команда действует."""
    from app.storage import CommitUnknown
    env.runner.shutdown()  # поток очереди не должен взять этот прогон
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    real = env.db.set_run_control

    def lost(*args, **kwargs):
        real(*args, **kwargs)
        raise CommitUnknown("результат неизвестен")
    monkeypatch.setattr(env.db, "set_run_control", lost)
    with pytest.raises(CommitUnknown):
        getattr(env.runner, command)(run_id)
    assert env.runner._controls[run_id] == command
    assert env.runner._apply_control(run_id)
    assert env.db.get_run(run_id)["state"] == state


def test_stop_in_memory_survives_deferred_pause(env: Env, monkeypatch):  # noqa: F811
    """«Стоп» только в памяти, база отказывает и при записи паузы: когда база вернётся, прогон остановлен, а не на паузе."""
    from app import journal
    env.load([sast("A", 15)])
    real_state = env.db.set_run_state
    down = [True]

    def state(run_id, value, *args, **kwargs):
        if down[0] and value in ("paused", "stopped"):
            raise RuntimeError("нет места на диске")
        return real_state(run_id, value, *args, **kwargs)

    def busy(db, run_id, *args, **kwargs):
        env.runner._controls[run_id] = "stop"
        raise DatabaseBusy(BUSY_TEXT)
    monkeypatch.setattr(env.db, "set_run_state", state)
    monkeypatch.setattr(journal, "environment", busy)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    deadline = time.monotonic() + 15
    while run_id not in env.runner._unsaved_pauses and time.monotonic() < deadline:
        time.sleep(0.05)
    assert run_id in env.runner._unsaved_pauses
    time.sleep(0.2)  # finally потока завершился
    assert env.runner._controls.get(run_id) == "stop"
    down[0] = False
    env.runner._wake.set()
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "stopped", run


def test_resume_cancels_deferred_pause(env: Env):  # noqa: F811
    """Запись паузы подтвердилась, ответ потерян, и пауза отложена; «Продолжить» оператора важнее."""
    env.runner.shutdown()
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    env.db.set_run_state(run_id, "paused", last_error="x")
    env.runner._unsaved_pauses[run_id] = triage.DB_UNKNOWN_PAUSE
    assert env.runner.resume(run_id)
    assert run_id not in env.runner._unsaved_pauses
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "queued"


def test_resume_of_running_with_deferred_pause_requeues(env: Env):  # noqa: F811
    """Итог паузы не записан, обработчик вышел, в базе прогон ещё идёт: «Продолжить» возвращает его в очередь."""
    env.runner.shutdown()
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    env.runner._unsaved_pauses[run_id] = triage.DB_UNKNOWN_PAUSE
    env.runner._controls[run_id] = "pause"
    assert env.runner.resume(run_id)
    assert run_id not in env.runner._unsaved_pauses and run_id not in env.runner._controls
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "queued"


def test_resume_with_lost_commit_answer_is_not_undone_by_deferred_pause(env: Env, monkeypatch):  # noqa: F811
    from app.storage import CommitUnknown
    env.runner.shutdown()
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    env.db.set_run_state(run_id, "paused", last_error="x")
    env.runner._unsaved_pauses[run_id] = triage.DB_UNKNOWN_PAUSE
    real = env.db.set_run_state

    def lost(*args, **kwargs):
        real(*args, **kwargs)
        raise CommitUnknown("результат неизвестен")
    monkeypatch.setattr(env.db, "set_run_state", lost)
    with pytest.raises(CommitUnknown):
        env.runner.resume(run_id)
    monkeypatch.undo()
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "queued"


@pytest.mark.parametrize("in_memory", [True, False])
def test_resume_does_not_undo_accepted_stop(env: Env, in_memory):  # noqa: F811
    env.runner.shutdown()
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    env.runner._unsaved_pauses[run_id] = triage.DB_UNKNOWN_PAUSE
    if in_memory:
        env.runner._controls[run_id] = "stop"
    else:
        env.db.set_run_control(run_id, "stop")
    assert not env.runner.resume(run_id)
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "stopped"


def test_deferred_pause_cannot_appear_after_resume(env: Env, monkeypatch):  # noqa: F811
    """Запись паузы подтвердилась, ответ потерян: пока пауза откладывается, «Продолжить» ждёт замок и потому её снимает."""
    from app.storage import CommitUnknown
    env.runner.shutdown()
    run_id = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(run_id, "running")
    real = env.db.set_run_state

    def lost(*args, **kwargs):
        real(*args, **kwargs)
        raise CommitUnknown("результат неизвестен")
    monkeypatch.setattr(env.db, "set_run_state", lost)
    locks: list[bool] = []
    original_log = triage.log_failure

    def seen(*args, **kwargs):
        locks.append(env.runner._lock.locked())
        return original_log(*args, **kwargs)
    monkeypatch.setattr(triage, "log_failure", seen)
    env.runner._pause_after_db_failure(run_id, triage.DB_UNKNOWN_PAUSE)
    assert locks == [False] and run_id in env.runner._unsaved_pauses, "журнал – уже вне замка, запись отложена внутри"
    monkeypatch.undo()
    assert env.runner.resume(run_id)
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "queued"


def test_deferred_stop_and_error_clear_slow_state(env: Env):  # noqa: F811
    env.runner.shutdown()
    stopped = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(stopped, "running")
    env.db.set_run_control(stopped, "stop")
    env.runner._unsaved_pauses[stopped] = triage.DB_UNKNOWN_PAUSE
    env.runner._slow[stopped] = object()
    failed = env.db.create_run(env.project_id, "all", "m", "p1", ["A"])
    env.db.set_run_state(failed, "running")
    env.runner._unsaved_errors[failed] = "сбой"
    env.runner._slow[failed] = object()
    env.runner._save_pending_errors()
    assert env.db.get_run(stopped)["state"] == "stopped" and stopped not in env.runner._slow
    assert env.db.get_run(failed)["state"] == "error" and failed not in env.runner._slow


def test_other_error_after_unknown_commit_keeps_the_uncertainty(monkeypatch):
    from app.storage import CommitUnknown
    errors = [CommitUnknown("результат неизвестен"), RuntimeError("нет места на диске")]

    def write():
        raise errors.pop(0)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    with pytest.raises(CommitUnknown) as caught:
        triage.retry_busy(write)
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_busy_after_unknown_commit_keeps_the_uncertainty(monkeypatch):
    from app.storage import CommitUnknown
    errors = [CommitUnknown("результат неизвестен"), DatabaseBusy(BUSY_TEXT), DatabaseBusy(BUSY_TEXT)]

    def write():
        raise errors.pop(0)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    with pytest.raises(CommitUnknown):
        triage.retry_busy(write)


def test_commit_unknown_every_time_pauses_and_keeps_the_item(env: Env, monkeypatch):  # noqa: F811
    from app.storage import CommitUnknown
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive"), verdict_answer("true_positive")]
    real, calls = env.db.save_verdict, [0]

    def lost(*args, **kwargs):
        calls[0] += 1
        real(*args, **kwargs)
        raise CommitUnknown("результат неизвестен")
    monkeypatch.setattr(env.db, "save_verdict", lost)
    monkeypatch.setattr(triage, "DB_RETRY_WAIT_S", 0.0)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert run["state"] == "paused" and run["failed"] == 0 and calls[0] == triage.DB_WRITE_RETRIES, run
    assert env.db._scalar("SELECT COUNT(*) FROM verdicts") == 1, "все попытки – с одним номером"
    assert env.db.next_pending_item(run_id) is not None, "находка осталась в очереди"
    monkeypatch.undo()
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done" and run["failed"] == 0 and env.db.get_case(env.project_id, "A")["verdict"]


def test_still_busy_pauses_run_and_keeps_the_item(env: Env, monkeypatch):  # noqa: F811
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive"), verdict_answer("true_positive")]
    busy_times(env, monkeypatch, "save_verdict", -1)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    run = wait_state(env.db, run_id, ("paused",) + FINAL_RUN_STATES)
    assert (run["state"], run["last_error"]) == ("paused", triage.DB_BUSY_PAUSE)
    assert run["failed"] == 0 and env.db.next_pending_item(run_id) is not None, "находка осталась в очереди"
    chats = len(env.fake.chats())
    monkeypatch.undo()
    assert env.runner.resume(run_id)
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done" and run["failed"] == 0
    assert env.db.get_case(env.project_id, "A")["verdict"]
    assert len(env.fake.chats()) == chats + 1, "незаписанный ответ получен заново – одна находка"


def test_pause_that_cannot_be_written_is_saved_later_not_as_error(env: Env, monkeypatch):  # noqa: F811
    env.load([sast("A", 15)])
    env.fake.answers = [verdict_answer("true_positive")]
    busy_times(env, monkeypatch, "save_verdict", -1)
    real_state = env.db.set_run_state

    def busy_pause(run_id, state, **kwargs):
        if state in ("paused", "stopped") and kwargs.get("last_error") == triage.DB_BUSY_PAUSE and not released:
            raise DatabaseBusy(BUSY_TEXT)
        return real_state(run_id, state, **kwargs)

    released = False
    monkeypatch.setattr(env.db, "set_run_state", busy_pause)
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all")
    deadline = time.monotonic() + 10
    while run_id not in env.runner._unsaved_pauses and time.monotonic() < deadline:
        time.sleep(0.02)  # поток прогона доходит до отложенной записи паузы
    assert env.runner._unsaved_pauses.get(run_id) == triage.DB_BUSY_PAUSE
    assert env.db.get_run(run_id)["state"] != "error"
    released = True
    env.runner._save_pending_errors()  # база освободилась – отложенная пауза записана
    run = env.db.get_run(run_id)
    assert (run["state"], run["last_error"]) == ("paused", triage.DB_BUSY_PAUSE)


def test_accepted_stop_survives_busy_state_write(env: Env, monkeypatch):  # noqa: F811
    env.load([sast("A", 15), sast("B", 20)])
    run_id = env.db.create_run(env.project_id, "qwen2.5-coder:14b", "all", triage.PROMPT_VERSION, ["A", "B"])
    env.db.set_run_state(run_id, "running")
    env.runner._controls[run_id] = "stop"
    calls = busy_times(env, monkeypatch, "set_run_state", 1)
    triage.retry_busy(lambda: env.runner._finish(run_id, "paused", "причина"))
    assert calls[0] == 2 and env.db.get_run(run_id)["state"] == "stopped", "стоп не потерян при повторе"


def test_busy_reread_is_not_a_code_change(env: Env):  # noqa: F811
    env.load([sast("A", 15)])

    def busy():
        raise DatabaseBusy(BUSY_TEXT)

    with pytest.raises(DatabaseBusy):
        env.runner._code_changed(None, None, 1000, "x", busy)


def test_deferred_pause_keeps_a_later_stop(env: Env):  # noqa: F811
    """Пауза из-за занятой базы ждёт записи, а оператор тем временем нажал «Стоп»: записывается «остановлен»."""
    env.load([sast("A", 15)])
    run_id = env.db.create_run(env.project_id, "qwen2.5-coder:14b", "all", triage.PROMPT_VERSION, ["A"])
    env.db.set_run_state(run_id, "running")
    env.runner._unsaved_pauses[run_id] = triage.DB_BUSY_PAUSE
    assert env.db.set_run_control(run_id, "stop")  # команда записана в базу, в памяти её уже нет
    env.runner._save_pending_errors()
    run = env.db.get_run(run_id)
    assert run["state"] == "stopped" and run_id not in env.runner._unsaved_pauses


def test_pause_does_not_replace_accepted_stop_kept_in_the_database(env: Env):  # noqa: F811
    """Принятый «Стоп» остался только в базе (команда в памяти уже снята): новая «Пауза» его не заменяет."""
    env.load([sast("A", 15)])
    run_id = env.db.create_run(env.project_id, "qwen2.5-coder:14b", "all", triage.PROMPT_VERSION, ["A"])
    env.db.set_run_state(run_id, "running")
    assert env.db.set_run_control(run_id, "stop")
    assert not env.runner.pause(run_id)
    assert env.db.get_run(run_id)["control"] == "stop"
    env.runner._unsaved_pauses[run_id] = triage.DB_BUSY_PAUSE
    env.runner._save_pending_errors()
    assert env.db.get_run(run_id)["state"] == "stopped"
