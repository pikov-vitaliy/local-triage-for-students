"""Одно право на генерацию (BUG-03 ревью 24.10, ADR-0099): «Спросить модель» не идёт параллельно прогону, прогон
дожидается начатого вопроса, ошибка и остановка освобождают право; вопрос к сменившемуся разбору не задаётся.
Модель – поддельная, события вместо ожидания по времени."""

from __future__ import annotations

import threading

import pytest

from app import ask
from app.ask import AskError
from app.db import FINAL_RUN_STATES
from app.llm import GENERATION
from fake_ollama import ask_answer, verdict_answer
from test_ask import asked
from test_code_snapshots import analysed as analysed_web, card_url  # noqa: E402
from test_triage import Env, env, gated, sast, wait_state  # noqa: F401
from test_web import ORIGIN, web  # noqa: F401


def analysed_two(env: Env) -> None:  # noqa: F811
    """Находка A уже разобрана (есть о чём спрашивать), B – ещё нет."""
    env.load([sast("A", 15), sast("B", 20)])
    assert env.run(scope="selected", hub_ids=["A"])["state"] == "done"
    assert env.db.get_case(env.project_id, "A")["verdict"]


def test_question_is_refused_while_run_generates(env: Env):  # noqa: F811
    analysed_two(env)
    entered, gate, handler = gated()
    env.fake.answers = [handler]
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "selected", ["B"])
    assert entered.wait(10)
    chats = len(env.fake.chats())
    with pytest.raises(AskError) as refused:
        asked(env, "Откуда приходит значение?")
    assert refused.value.status == 409 and refused.value.args[0] == ask.RUN_BUSY
    assert len(env.fake.chats()) == chats, "вопрос не дошёл до модели"
    assert ask.run_busy() and not ask.busy()
    gate.set()
    assert wait_state(env.db, run_id, FINAL_RUN_STATES)["state"] == "done"
    assert GENERATION.busy() == ""
    env.fake.answers = [ask_answer()]
    assert asked(env, "Откуда приходит значение?")["state"] == "done", "после прогона вопрос задаётся"


def test_run_waits_for_question_in_progress(env: Env):  # noqa: F811
    analysed_two(env)
    entered, gate = threading.Event(), threading.Event()

    def slow_answer(body):
        entered.set()
        gate.wait(15)
        return ask_answer()

    env.fake.answers = [slow_answer, verdict_answer("true_positive")]
    result: dict = {}
    worker = threading.Thread(target=lambda: result.update(asked(env, "Что делает метод?")))
    worker.start()
    assert entered.wait(10)
    chats = len(env.fake.chats())
    run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "selected", ["B"])
    # прогон не отправил запрос, пока модель отвечает на вопрос
    assert not wait_until(lambda: len(env.fake.chats()) > chats, 1.0)
    gate.set()
    worker.join(15)
    assert result.get("state") == "done"
    assert wait_state(env.db, run_id, FINAL_RUN_STATES)["state"] == "done"
    assert len(env.fake.chats()) == chats + 1


def test_failed_question_releases_the_right(env: Env):  # noqa: F811
    analysed_two(env)
    env.fake.answers = ["не JSON", "снова не JSON"]  # дважды не по формату – вопрос с ошибкой
    q = asked(env, "Что делает метод?")
    assert q["state"] == "error"
    assert GENERATION.busy() == ""
    env.fake.answers = [verdict_answer("true_positive")]
    assert env.run(scope="selected", hub_ids=["B"])["state"] == "done"


@pytest.mark.parametrize("change", ["verdict", "code"])
def test_question_to_replaced_answer_is_not_asked(env: Env, monkeypatch, change):  # noqa: F811
    analysed_two(env)
    case = env.db.get_case(env.project_id, "A")
    take = GENERATION.try_acquire

    def replaced_while_waiting(holder: str) -> bool:
        if change == "verdict":  # новый ответ модели по тому же срезу
            vid = env.db.save_verdict(case["case_hash"], "other-model", "sast-v6", verdict_answer("true_positive"), {})
            env.db.save_case(env.project_id, "A", case["case_hash"], case["context"], vid)
        else:  # другой срез при том же ответе (отпечаток входных данных сменился)
            env.db._conn.execute("UPDATE cases SET case_hash = 'другой' WHERE project_id = ? AND hub_id = 'A'",
                                 (env.project_id,))
        return take(holder)

    monkeypatch.setattr(GENERATION, "try_acquire", replaced_while_waiting)
    chats = len(env.fake.chats())
    with pytest.raises(AskError) as refused:
        asked(env, "Откуда приходит значение?")
    assert refused.value.args[0] == ask.REANALYZED
    assert len(env.fake.chats()) == chats and GENERATION.busy() == ""
    assert env.db.list_questions(env.project_id, "A") == []


def wait_until(check, seconds: float) -> bool:
    done = threading.Event()
    deadline = 0.0
    while deadline < seconds:
        if check():
            return True
        done.wait(0.05)
        deadline += 0.05
    return check()


def test_http_question_during_run_is_refused_and_card_says_why(web):  # noqa: F811
    """Маршрут «Спросить модель» при занятом прогоном праве: 409 с причиной, текст вопроса не теряется, в карточке –
    подпись у кнопки."""
    pid = analysed_web(web)
    url = card_url(web, pid, "510001")
    assert GENERATION.try_acquire("triage")
    try:
        r = web.client.post(url + "/ask", headers={**ORIGIN, "Accept": "application/json"},
                            data={"question": "Откуда приходит значение?", "model": "qwen2.5-coder:14b"})
        assert r.status_code == 409 and r.json()["detail"] == ask.RUN_BUSY
        plain = web.client.post(url + "/ask", headers=ORIGIN,
                                data={"question": "Откуда приходит значение?", "model": "qwen2.5-coder:14b"})
        assert plain.status_code == 409 and "Откуда приходит значение?" in plain.text
        assert "Идёт разбор находок в прогоне" in web.client.get(url).text
    finally:
        GENERATION.release()
    assert "Идёт разбор находок в прогоне" not in web.client.get(url).text


def runner_waiting(monkeypatch) -> threading.Event:
    """Событие «прогон вошёл в ожидание права на генерацию»."""
    waiting = threading.Event()
    real = GENERATION.acquire

    def acquire(holder, interrupted, poll_s=0.25):
        if holder == "triage":
            waiting.set()
        return real(holder, interrupted, poll_s=0.02)

    monkeypatch.setattr(GENERATION, "acquire", acquire)
    return waiting


@pytest.mark.parametrize("command", ["pause", "stop"])
def test_pause_and_stop_end_the_wait_for_a_question(env: Env, monkeypatch, command):  # noqa: F811
    """Прогон ждёт, пока модель ответит на вопрос; «Пауза» или «Стоп» выполняются сразу, новая находка не начинается."""
    analysed_two(env)
    waiting = runner_waiting(monkeypatch)
    assert GENERATION.try_acquire("ask")  # модель отвечает на вопрос
    try:
        chats = len(env.fake.chats())
        run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "selected", ["B"])
        assert waiting.wait(10)
        assert getattr(env.runner, command)(run_id)
        expected = "paused" if command == "pause" else "stopped"
        assert wait_state(env.db, run_id, (expected,) + FINAL_RUN_STATES)["state"] == expected
    finally:
        GENERATION.release()
    assert not wait_until(lambda: len(env.fake.chats()) > chats, 0.5), "после команды запроса к модели нет"
    assert env.db.next_pending_item(run_id) is not None


def test_shutdown_while_waiting_does_not_start_an_item(env: Env, monkeypatch):  # noqa: F811
    analysed_two(env)
    waiting = runner_waiting(monkeypatch)
    assert GENERATION.try_acquire("ask")
    try:
        chats = len(env.fake.chats())
        run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "selected", ["B"])
        assert waiting.wait(10)
        stopper = threading.Thread(target=env.runner.shutdown)
        stopper.start()
    finally:
        GENERATION.release()  # право освободилось – но прогон уже остановлен
    stopper.join(15)
    assert not wait_until(lambda: len(env.fake.chats()) > chats, 0.5)
    assert env.db.get_run(run_id)["state"] == "paused" and GENERATION.busy() == ""


def test_pause_cancelled_while_leaving_the_wait_keeps_running(env: Env, monkeypatch):  # noqa: F811
    """Ожидание права прервала «Пауза», а до её выполнения оператор нажал «Продолжить»: прогон не встаёт на ложную
    паузу «Приложение остановлено» и продолжает работу, когда право освободится."""
    analysed_two(env)
    waiting = runner_waiting(monkeypatch)
    real_apply = env.runner._apply_control
    raced = []

    def resume_first(run_id):
        if not raced and run_id in env.runner._controls:
            raced.append(1)
            env.runner.resume(run_id)  # «Продолжить» успели нажать между выходом из ожидания и выполнением паузы
        return real_apply(run_id)

    monkeypatch.setattr(env.runner, "_apply_control", resume_first)
    env.fake.answers = [verdict_answer("true_positive")]
    assert GENERATION.try_acquire("ask")
    try:
        run_id = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "selected", ["B"])
        assert waiting.wait(10)
        assert env.runner.pause(run_id)
        assert wait_until(lambda: bool(raced), 5)
    finally:
        GENERATION.release()
    run = wait_state(env.db, run_id, FINAL_RUN_STATES)
    assert run["state"] == "done", run
