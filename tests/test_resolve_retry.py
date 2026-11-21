"""0.9.19 (ADR-0113): сбой службы имён (DNS) до отправки – повтор, а не потеря строки.

Случай: после трёх удачных обращений к провайдеру четвёртое падает на разрешении имени
сервера – служба имён хоста отвечает отказом на доли секунды. Ни один байт не ушёл, поэтому
повтор безопасен: служба имён опрашивается до трёх раз с паузами, клиент не считает такую попытку отправкой, а
исследование провайдером повторяет ход модели (раз на строку) и запрос инструмента после паузы."""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import llm_net  # noqa: E402
from app import sca_research_net as net  # noqa: E402
from app.llm import LlmError, ResolveError, outcome_unknown  # noqa: E402
from app.llm_chat import ChatCompletionsClient  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402
from test_llm_chat import ENUMS, FIELDS, MESSAGES, REQUIRED, client_of, fake  # noqa: E402, F401
from test_sca_research_net import _answer, _tool_call, good_row, manifest_rows, runner_for, start_run  # noqa: E402
from test_web import web  # noqa: E402, F401

DNS_TEXT = ("Имя сервера «api.example.invalid» не найдено службой имён (DNS) (3 попытки подряд): проверьте адрес сервера "
            "в профиле и сеть; если имя верное, повторите через минуту.")
ADDRESS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


# ============================================================================ служба имён: повтор отрицательного ответа

def test_negative_dns_answer_is_retried_with_pauses(monkeypatch):
    calls, waits = [], []

    def flaky(host, port, *args, **kwargs):
        calls.append(host)
        if len(calls) < 3:
            raise socket.gaierror(socket.EAI_NONAME, "нет такого имени")
        return ADDRESS
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", flaky)
    monkeypatch.setattr(llm_net, "_sleep", waits.append)
    infos = llm_net._getaddrinfo("api.example.invalid", 443, 5.0, "external")
    assert infos[0][4][0] == "93.184.216.34" and calls == ["api.example.invalid"] * 3
    assert waits == list(llm_net.RESOLVE_RETRY_WAIT_S) == [1.0, 2.0]


@pytest.mark.parametrize("errno, wanted", [
    (socket.EAI_NONAME, "не найдено службой имён (DNS) (3 попытки подряд)"),
    (socket.EAI_AGAIN, "временно не ответила (3 попытки подряд)"),
])
def test_persistent_dns_failure_is_resolve_error_after_three_attempts(monkeypatch, errno, wanted):
    calls, waits = [], []

    def failing(host, *args, **kwargs):
        calls.append(host)
        raise socket.gaierror(errno, "сбой службы имён")
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", failing)
    monkeypatch.setattr(llm_net, "_sleep", waits.append)
    with pytest.raises(ResolveError) as info:
        llm_net._getaddrinfo("api.example.invalid", 443, 5.0, "external")
    assert wanted in str(info.value) and len(calls) == llm_net.RESOLVE_ATTEMPTS == 3 and waits == [1.0, 2.0]
    assert isinstance(info.value, LlmError) and info.value.sent is False
    assert info.value.status is None and info.value.reason is None, "исход известен: запрос не отправлен"
    assert "Ollama" not in str(info.value)


def test_other_resolution_errors_are_not_retried(monkeypatch):
    """Повторяется только отрицательный ответ службы имён: иная ошибка, зависание (свой срок, тесты test_llm) и
    занятые места – сразу ResolveError, без пауз."""
    calls = []

    def other(host, *args, **kwargs):
        calls.append(host)
        raise OSError("что-то другое")
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", other)
    monkeypatch.setattr(llm_net, "_sleep", lambda seconds: pytest.fail("паузы быть не должно"))
    with pytest.raises(ResolveError, match="не разрешено"):
        llm_net._getaddrinfo("api.example.invalid", 443, 5.0, "external")
    assert len(calls) == 1


def test_local_wording_keeps_the_ollama_hint(monkeypatch):
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, "x")))
    with pytest.raises(ResolveError, match="укажите адрес Ollama") as info:
        llm_net._getaddrinfo("ollama", 11434, 5.0, "local")
    assert "3 попытки подряд" in str(info.value)


# ============================================================================ клиент: попытка без отправки – не отправка

def _flaky_request(monkeypatch, path_of, times: int = 1, skip: int = 0) -> list[str]:
    """_request клиента: запросы по пути path_of(client) с номера skip (от нуля) – times раз ResolveError, остальные –
    настоящие."""
    real = ChatCompletionsClient._request
    hits: list[str] = []
    seen: list[str] = []

    def flaky(self, path, payload=None, **kwargs):
        if path == path_of(self):
            seen.append(path)
            if skip < len(seen) <= skip + times:
                hits.append(path)
                raise ResolveError(DNS_TEXT)
        return real(self, path, payload, **kwargs)
    monkeypatch.setattr(ChatCompletionsClient, "_request", flaky)
    return hits


def test_unsent_attempt_is_not_counted_as_a_send(fake, monkeypatch):  # noqa: F811
    hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1)
    with pytest.raises(ResolveError) as info:
        client_of(fake).chat_turn("test-model", MESSAGES)
    assert info.value.sends == 0 and info.value.sent is False and fake.chats() == [] and hits == ["/chat/completions"]
    turn = client_of(fake).chat_turn("test-model", MESSAGES)
    assert turn.sends == 1 and len(fake.chats()) == 1


# ============================================================================ исследование провайдером: повтор хода и инструмента

def test_pause_respects_the_deadline_and_the_stop(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(net, "_sleep", slept.append)
    assert net._pause(lambda: False, 10.0, time.monotonic() + 5.0) is False and slept == []
    assert net._pause(lambda: False, 1.2, None) is True
    assert len(slept) == 3 and all(0 < s <= 0.5 for s in slept) and round(sum(slept), 3) == 1.2
    slept.clear()
    flags = iter([False, False, True])
    assert net._pause(lambda: next(flags), 10.0, None) is True and len(slept) == 2, "остановка прерывает паузу"


def test_turn_is_retried_once_after_a_name_service_failure(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    waits: list[float] = []
    monkeypatch.setattr(net, "_sleep", waits.append)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1)
        fake.answers += [_answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["usage"]["sends"] == 1, "попытка без отправки не считается"
        assert hits == ["/chat/completions"] and len(fake.chats()) == 2
        assert round(sum(waits), 3) == net.RESOLVE_ROW_WAIT_S, "пауза перед повтором хода"
        summary = db.research_run(run["id"])
        assert summary["rows_saved"] == 2 and summary["rows_failed"] == 0 and summary["rows_unknown"] == 0


def test_second_name_service_failure_fails_the_row_honestly(web, monkeypatch):  # noqa: F811
    """Повтор хода на строку один: второй сбой – строка «не получена» (не «результат неизвестен»: ничего не ушло),
    причина называет сбой и повтор, отправок ноль, серия обрывов не растёт."""
    db = web.app.state.db
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 99)
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        for row in rows:
            got = states[row["input_ref"]]
            assert got["state"] == "failed" and "не найдено службой имён" in got["reason"], got
            assert net.RESOLVE_RETRY_NOTE in got["reason"] and "Результат неизвестен" not in got["reason"]
            assert got["usage"]["sends"] == 0
        assert len(hits) == 2 * len(rows) and fake.chats() == []
        summary = db.research_run(run["id"])
        assert summary["state"] == "done" and summary["rows_failed"] == len(rows) and summary["rows_unknown"] == 0


def test_tool_request_is_retried_once_after_a_name_service_failure(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    waits: list[float] = []
    monkeypatch.setattr(net, "_sleep", waits.append)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: "/v1/tools/search", 1)
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="zod 1.0")]}, "tool_calls"),
            _answer(good_row(rows[0], task)), _answer(good_row(rows[1], task)),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "ok" and hits == ["/v1/tools/search"]
        assert first["usage"]["search_calls"] == 1, "попытка без отправки – не вызов инструмента"
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 1
        assert round(sum(waits), 3) == net.RESOLVE_TOOL_WAIT_S


def test_stop_during_the_pause_returns_the_row_to_the_queue(web, monkeypatch):  # noqa: F811
    """Остановка во время паузы: повтор не отправляется, строка в очередь (ничего не ушло – «Продолжить» возьмёт её
    заново), отправок ноль."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        runner = runner_for(web)
        monkeypatch.setattr(net, "_sleep", lambda seconds: runner.stop(run["id"]))
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 99)
        runner.run(run["id"])
        states = db.research_run_rows(run["id"])
        assert [r["state"] for r in states] == ["queued"] * len(states) and all(r["usage"].get("sends", 0) == 0 for r in states)
        assert len(hits) == 1 and fake.chats() == []
        assert db.research_run(run["id"])["state"] == "stopped"


# ============================================================================ круг 51: срок, прежние отправки, инструмент, остановка

class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


HTTP_429 = ("http", 429, {"error": {"message": "slow down"}}, {"Retry-After": "1"})


def test_resolution_retries_stay_within_the_request_deadline(monkeypatch):
    """В2 круга 51: попытки и паузы – в пределах срока запроса; пауза, которая съела бы остаток, не делается."""
    clock, calls = FakeClock(), []

    def failing(host, *args, **kwargs):
        calls.append(host)
        clock.t += 0.2  # медленный отрицательный ответ
        raise socket.gaierror(socket.EAI_NONAME, "x")
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", failing)
    monkeypatch.setattr(llm_net, "_now", clock.now)
    monkeypatch.setattr(llm_net, "_sleep", clock.sleep)
    for timeout, attempts, word in ((5.0, 3, "3 попытки"), (2.0, 2, "2 попытки"), (0.5, 1, "1 попытка")):
        calls.clear()
        clock.t = 1000.0
        with pytest.raises(ResolveError, match=f"[(]{word} подряд[)]"):
            llm_net._getaddrinfo("api.example.invalid", 443, timeout, "external")
        assert len(calls) == attempts, timeout
        assert clock.t - 1000.0 <= timeout + 0.2, "цикл не выходит за срок (кроме последней медленной попытки)"


def test_pause_checks_the_deadline_before_every_slice(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(net, "_now", clock.now)
    monkeypatch.setattr(net, "_sleep", clock.sleep)
    assert net._pause(lambda: False, 2.0, clock.t + 1.2) is False and clock.t == 1000.0, "срок ближе паузы – без ожидания"

    def slow_stop() -> bool:  # проверка остановки сама занимает время: срок подходит во время паузы
        clock.t += 0.7
        return False
    assert net._pause(slow_stop, 2.0, clock.t + 2.5) is False and clock.t < 1003.2, "срок подошёл в паузе – повтора нет"
    clock.t = 1000.0
    assert net._pause(lambda: False, 2.0, clock.t + 60.0) is True and clock.t == 1002.0


def test_dns_after_an_http_retry_is_not_a_drop_and_the_retry_is_spent(web, monkeypatch):  # noqa: F811
    """Б1 круга 51: 429 → повтор транспорта → сбой службы имён. Первая отправка получила ответ, поэтому ошибка не
    «результат неизвестен»; ход повторяется после паузы, а повтор транспорта на строку один: второе 429 уже не
    повторяется – строка «не получена» с ответом 429, отправок две (429 и 429), сбой не считается."""
    db = web.app.state.db
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1, skip=1)
        fake.answers += [HTTP_429, HTTP_429, _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "failed" and "429" in first["reason"], first["reason"]
        assert "Результат неизвестен" not in first["reason"] and net.RESOLVE_RETRY_NOTE not in first["reason"]
        assert first["usage"]["sends"] == 2 and hits == ["/chat/completions"]
        assert states[rows[1]["input_ref"]]["state"] == "saved"
        summary = db.research_run(run["id"])
        assert summary["rows_unknown"] == 0 and summary["rows_failed"] == 1 and summary["rows_saved"] == 1


def test_dns_on_the_correction_request_is_a_known_error(fake, monkeypatch):  # noqa: F811
    """Б1 круга 51 (путь разбора находок): ответ не по формату → запрос исправления → сбой службы имён: первый ответ
    получен, ошибка известна – не обрыв; отправок одна."""
    hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1, skip=1)
    fake.answers += ["не JSON вовсе"]
    with pytest.raises(ResolveError) as info:
        client_of(fake).chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS)
    assert info.value.sent is False and not outcome_unknown(info.value) and len(fake.chats()) == 1 and len(hits) == 1


def test_dns_after_a_real_drop_keeps_the_first_outcome_unknown(web, monkeypatch):  # noqa: F811
    """Б1 круга 51: обрыв (ADR-0107) → повтор по отметке → сбой службы имён → пауза → повтор → ответ: строка сохранена,
    отправок две. Второй сбой службы имён после обрыва – «результат неизвестен» первого запроса, не «не получена»."""
    db = web.app.state.db
    monkeypatch.setattr(net, "drop_retry_allowed", lambda execution: True)
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1, skip=1)
        fake.answers += [("drop",), _answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["usage"]["sends"] == 2 and hits == ["/chat/completions"]
        assert states[rows[1]["input_ref"]]["state"] == "saved"
        # второе получение: обрыв, затем служба имён не отвечает дважды
        pid, task, _consent, again = start_run(web, fake, project=(pid, task), rows=[rows[0]["input_ref"]])
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 2, skip=1)
        fake.answers += [("drop",)]
        runner_for(web).run(again["id"])
        row = db.research_run_rows(again["id"])[0]
        assert row["state"] == "unknown" and net.UNKNOWN_NOTE in row["reason"] and net.RESOLVE_RETRY_NOTE in row["reason"]
        assert row["usage"]["sends"] == 1 and len(hits) == 2 and db.research_run(again["id"])["rows_unknown"] == 1


def test_dns_after_three_successful_turns_is_retried(web, monkeypatch):  # noqa: F811
    """Сценарий сбоя: три хода с инструментами прошли, четвёртый упал на службе имён – повтор после паузы,
    строка сохранена, отправок четыре (три хода и ответ), неотправленная попытка не считается."""
    db = web.app.state.db
    waits: list[float] = []
    monkeypatch.setattr(net, "_sleep", waits.append)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: c.generate_path, 1, skip=3)
        search = lambda cid: ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call(cid, "search", query=f"zod {cid}")]}, "tool_calls")  # noqa: E731
        fake.answers += [search("s1"), search("s2"), search("s3"), _answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["usage"]["sends"] == 4 and first["usage"]["search_calls"] == 3
        assert hits == ["/chat/completions"] and round(sum(waits), 3) == net.RESOLVE_ROW_WAIT_S
        assert [t["status"] for t in first["tools"]] == ["ok", "ok", "ok"]


def test_tool_dns_twice_is_not_counted_and_the_row_continues(web, monkeypatch):  # noqa: F811
    """В1 круга 51: второй сбой службы имён у инструмента – модели уходит ошибка инструмента (как 404), строка
    продолжается по собранному; ни одна из попыток не считается вызовом."""
    db = web.app.state.db
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hits = _flaky_request(monkeypatch, lambda c: "/v1/tools/search", 2)
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="zod 1.0")]}, "tool_calls"),
            _answer(good_row(rows[0], task)), _answer(good_row(rows[1], task)),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "error" and "службой имён" in first["tools"][0]["error"]
        assert first["usage"]["search_calls"] == 0 and len(hits) == 2
        assert [r for r in fake.requests if r["path"] == "/v1/tools/search"] == []
        tool_messages = [m for m in fake.chats()[1]["messages"] if m.get("role") == "tool"]
        assert tool_messages and "службой имён" in tool_messages[0]["content"]


def test_tool_429_then_dns_counts_one_call(web, monkeypatch):  # noqa: F811
    """В1 круга 51: 429 (отправлено) → повтор → сбой службы имён (не отправлено): вызов один, модели – ошибка."""
    db = web.app.state.db
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [HTTP_429]
        hits = _flaky_request(monkeypatch, lambda c: "/v1/tools/search", 1, skip=1)
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="zod 1.0")]}, "tool_calls"),
            _answer(good_row(rows[0], task)), _answer(good_row(rows[1], task)),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "error"
        assert first["usage"]["search_calls"] == 1 and len(hits) == 1
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 1


def test_stop_during_the_tool_pause_does_not_save_the_row(web, monkeypatch):  # noqa: F811
    """В3 круга 51: «Остановить» во время паузы перед повтором инструмента – повтор не отправляется, строка в очередь,
    даже если в том же сообщении модели был готовый ответ; лишней попытки инструмента нет."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        runner = runner_for(web)
        monkeypatch.setattr(net, "_sleep", lambda seconds: runner.stop(run["id"]))
        hits = _flaky_request(monkeypatch, lambda c: "/v1/tools/search", 99)
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [
            _tool_call("s1", "search", query="q"),
            {"id": "a1", "type": "function", "function": {"name": "answer",
                                                          "arguments": json.dumps({"row": good_row(rows[0], task)}, ensure_ascii=False)}},
        ]}, "tool_calls")]
        runner.run(run["id"])
        states = db.research_run_rows(run["id"])
        assert [r["state"] for r in states] == ["queued"] * len(states), states
        assert len(hits) == 1 and len(fake.chats()) == 1 and [r for r in fake.requests if r["path"] == "/v1/tools/search"] == []
        assert db.research_run(run["id"])["state"] == "stopped" and db.research_run(run["id"])["rows_saved"] == 0
