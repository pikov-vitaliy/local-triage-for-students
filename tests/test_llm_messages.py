"""Клиент Messages API (0.9.14, ADR-0106, шаг 4 плана) на проверяющем поддельном сервере tests/fake_messages_api.py:
тело запроса (system отдельно, блоки, обязательный max_tokens, инструмент answer с принудительным выбором), заголовки
(x-api-key – секрет, anthropic-version – служебный), нормализация ответа и вызовов инструментов, исправляющий ход
через tool_result, режим none, stop_reason → finish_reason и известные ошибки (LlmError.reason), классификатор
неизвестного исхода, 529, недоступный /models с резервным именем, блоки thinking, https у класса external.
Каждый тест проверяет, что сервер не нашёл нарушений контракта. Данные выдуманы."""

from __future__ import annotations

import json
import socket
import ssl
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.llm import LlmError, PromptOverflowError, SendNotAllowed, outcome_unknown  # noqa: E402
from app.llm_messages import API_VERSION, MessagesClient, to_app_message, to_wire_messages  # noqa: E402
from fake_messages_api import CERTS, FakeMessagesApi, tool_use_block  # noqa: E402

KEY = "sk-messages-test-0123456789"
FIELDS = {"verdict": "вердикт", "why": "почему"}
REQUIRED = ["verdict", "why"]
ENUMS = {"verdict": ["true_positive", "false_positive", "uncertain"]}
GOOD = {"verdict": "false_positive", "why": "значение – константа"}
BAD = {"verdict": "может быть", "why": "не знаю"}
MESSAGES = [{"role": "system", "content": "Ответь по правилам."}, {"role": "user", "content": "Находка 1"}]


@pytest.fixture
def fake():
    with FakeMessagesApi() as server:
        yield server
        assert server.violations == [], f"нарушения контракта Messages API: {server.violations}"


def test_version_and_list_cost_one_models_request(fake):
    """Без лишних запросов: опрос версии и списка моделей у Messages API – один GET /models."""
    client = client_of(fake)
    client.version()
    client.list_models()
    assert len([r for r in fake.requests if r["path"].endswith("/models")]) == 1


def client_of(fake: FakeMessagesApi, **kw) -> MessagesClient:
    client = MessagesClient(fake.url, timeout=30)
    client.trust = "local"  # поддельный сервер на 127.0.0.1; класс external – отдельный тест ниже
    client.sleep = lambda _s: None
    client.auth = lambda: {"x-api-key": KEY}
    for k, v in kw.items():
        setattr(client, k, v)
    return client


def ask(client: MessagesClient, **kw):
    return client.chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS, **kw)


def lower(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


# ============================================================================ тело и заголовки

def test_body_headers_and_forced_answer_tool(fake):
    fake.answers.append(GOOD)
    obj, stats = ask(client_of(fake, max_output=4096), options={"num_predict": 700})
    assert obj == GOOD and stats.attempts == 1 and stats.prompt_tokens == 120 and stats.output_tokens == 40
    body = fake.messages_calls()[0]
    assert body["system"] == "Ответь по правилам." and body["max_tokens"] == 4096, \
        "предел профиля, а не num_predict Ollama"
    assert [m["role"] for m in body["messages"]] == ["user"]
    assert body["tool_choice"] == {"type": "tool", "name": "answer"}
    tool = body["tools"][0]
    assert tool["name"] == "answer" and set(tool["input_schema"]["properties"]) == {"verdict", "why"}
    assert "strict" not in tool and "thinking" not in body and "reasoning_effort" not in body
    sent = lower(fake.headers()[-1])
    assert sent["x-api-key"] == KEY and sent["anthropic-version"] == API_VERSION and "authorization" not in sent


def test_strict_mode_marks_the_tool(fake):
    fake.answers.append(GOOD)
    ask(client_of(fake, response_mode="tool_strict"))
    assert fake.messages_calls()[0]["tools"][0]["strict"] is True


def test_max_output_is_used_without_num_predict(fake):
    fake.answers.append(GOOD)
    ask(client_of(fake, max_output=2048))
    assert fake.messages_calls()[0]["max_tokens"] == 2048


def test_probe_uses_profile_limit_and_timeout(fake):
    """Пробный ответ – с пределом и сроком профиля (ревью круг 15, находка 4); срок восстанавливается и после ошибки."""
    client = client_of(fake, max_output=32, timeout=45.0)
    fake.answers.append({"ok": True})
    client.probe("test-model")
    assert fake.messages_calls()[0]["max_tokens"] == 32 and client.timeout == 45.0
    fake.answers.append(("blocks", [{"type": "text", "text": "нет"}], "refusal"))
    with pytest.raises(LlmError):
        client.probe("test-model", timeout=5.0)
    assert client.timeout == 45.0
    for mode in ("tool_strict", "none"):
        fake.answers.append({"ok": True} if mode != "none" else ("text", '{"ok": true}'))
        client_of(fake, response_mode=mode).probe("test-model")


# ============================================================================ исправляющий ход

def test_first_answer_invalid_second_valid_means_one_correction(fake):
    first = tool_use_block("answer", BAD)
    second = tool_use_block("answer", GOOD)
    fake.answers += [("blocks", [first, second], "tool_use"), GOOD]
    obj, stats = ask(client_of(fake))
    assert obj == GOOD and stats.attempts == 2 and len(fake.messages_calls()) == 2
    replay = fake.messages_calls()[1]["messages"]
    assert replay[1]["role"] == "assistant" and [b["id"] for b in replay[1]["content"]] == [first["id"], second["id"]]
    results = [b for b in replay[2]["content"] if b["type"] == "tool_result"]
    assert [b["tool_use_id"] for b in results] == [first["id"], second["id"]]
    assert "verdict" in results[0]["content"] and results[1]["content"] == "не использован"
    assert replay[2]["content"][-1]["type"] == "text", "текст – после результатов"


def test_text_instead_of_answer_gets_a_text_correction(fake):
    fake.answers += [("text", "Думаю, это ложное срабатывание."), GOOD]
    obj, _ = ask(client_of(fake))
    assert obj == GOOD
    replay = fake.messages_calls()[1]["messages"]
    assert all(b["type"] != "tool_result" for b in replay[2]["content"])
    assert "answer" in replay[2]["content"][-1]["text"]


def test_other_tool_instead_of_answer_is_closed_and_corrected(fake):
    fake.answers += [("tools", [("search", {"query": "x"})]), GOOD]
    # другой инструмент в ответе на принудительный answer: закрывается «не использован», затем исправление
    obj, _ = ask(client_of(fake))
    assert obj == GOOD
    replay = fake.messages_calls()[1]["messages"]
    assert [b["content"] for b in replay[2]["content"] if b["type"] == "tool_result"] == ["не использован"]


def test_none_mode_extracts_text_and_corrects_by_text(fake):
    fake.answers += [("text", "нет JSON"), ("text", json.dumps(GOOD, ensure_ascii=False))]
    obj, stats = ask(client_of(fake, response_mode="none"))
    assert obj == GOOD and stats.attempts == 2
    first, second = fake.messages_calls()
    assert "tools" not in first and "tool_choice" not in first
    assert all(isinstance(m["content"], str) or all(b["type"] == "text" for b in m["content"])
               for m in second["messages"]), "в режиме none tool_result не выдумывается"


def test_format_budget_exhausted_is_a_known_error(fake):
    fake.answers += [BAD, BAD, BAD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    e = info.value
    assert e.reason == "bad_format" and e.sent is True and outcome_unknown(e) is False
    assert e.stats.prompt_tokens == 360 and len(fake.messages_calls()) == 3


# ============================================================================ stop_reason и известные исходы

def test_length_with_valid_object_is_accepted(fake):
    fake.answers.append(("blocks", [tool_use_block("answer", GOOD)], "max_tokens"))
    assert ask(client_of(fake))[0] == GOOD


def test_length_with_broken_object_is_known_and_keeps_usage(fake):
    fake.answers += [("blocks", [tool_use_block("answer", {"verdict": "tr"})], "max_tokens"), GOOD]
    with pytest.raises(LlmError, match="оборван") as info:
        ask(client_of(fake))
    e = info.value
    assert e.reason == "length" and outcome_unknown(e) is False and e.stats.prompt_tokens == 120
    assert len(fake.messages_calls()) == 1, "после обрыва по длине повтора нет"


@pytest.mark.parametrize("stop,reason", [("refusal", "refusal"), ("pause_turn", "pause_turn"),
                                         ("model_context_window_exceeded", "context_window"),
                                         ("something_new", "unknown_stop")])
def test_stop_reasons_are_known_errors_with_usage(fake, stop, reason):
    fake.answers.append(("blocks", [{"type": "text", "text": "…"}], stop))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    e = info.value
    assert e.reason == reason and e.sent is True and outcome_unknown(e) is False
    assert e.stats is not None and e.stats.prompt_tokens == 120
    assert len(fake.messages_calls()) == 1, "известный исход – без повторной генерации"


def test_unsupported_block_and_duplicate_ids_are_known(fake):
    fake.answers.append(("blocks", [{"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {}}],
                         "end_turn"))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.reason == "unsupported_block" and outcome_unknown(info.value) is False
    block = tool_use_block("answer", GOOD)
    fake.answers.append(("blocks", [block, dict(block)], "tool_use"))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.reason == "bad_tool"


def test_thinking_blocks_are_not_text_and_are_replayed(fake):
    thinking = {"type": "thinking", "thinking": "размышление", "signature": "sig-1"}
    fake.forbid_thinking = True  # запрос не должен передавать поля рассуждения
    fake.answers += [("blocks", [thinking, tool_use_block("answer", BAD)], "tool_use"), GOOD]
    obj, _ = ask(client_of(fake))
    assert obj == GOOD
    replay = fake.messages_calls()[1]["messages"][1]["content"]
    assert replay[0] == thinking, "блок thinking воспроизводится без изменений"


def test_thinking_text_is_not_taken_as_answer():
    message, finish = to_app_message({"content": [{"type": "thinking", "thinking": "секрет"},
                                                   {"type": "text", "text": "ответ"}], "stop_reason": "end_turn"})
    assert message["content"] == "ответ" and finish == "stop"


# ============================================================================ классификатор неизвестного исхода

@pytest.mark.parametrize("sent,status,reason,unknown", [
    (False, None, None, False), (True, None, None, True), (True, None, "refusal", False),
    (True, 502, None, True), (True, 504, None, True), (True, 429, None, False), (True, 400, None, False),
])
def test_outcome_unknown_table(sent, status, reason, unknown):
    e = LlmError("x", status=status, reason=reason)
    e.sent = sent
    assert outcome_unknown(e) is unknown


def test_chat_completions_length_error_is_now_known():
    """Поведение API чат-завершений 0.9.13 меняется: ответ, оборванный по длине, и исчерпанный бюджет исправлений –
    известный исход (ответ получен), а не «результат неизвестен»."""
    from app.llm_chat import ChatCompletionsClient
    from fake_chat_api import FakeChatApi
    with FakeChatApi() as chat:
        chat.answers.append(("message", {"role": "assistant", "content": '{"verdict": "tr'}, "length"))
        client = ChatCompletionsClient(chat.url, timeout=30)
        client.trust, client.sleep = "local", (lambda _s: None)
        with pytest.raises(LlmError) as info:
            client.chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS)
        assert info.value.reason == "length" and outcome_unknown(info.value) is False
        chat.answers.append(("message", {"role": "assistant", "content": ""}, "content_filter"))
        with pytest.raises(LlmError) as info:
            client.chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS)
        assert info.value.reason == "finish_error" and outcome_unknown(info.value) is False


# ============================================================================ повторы и обрыв

def test_529_is_retried_once(fake):
    fake.answers += [("http", 529, {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}},
                      {"retry-after": "1"}), GOOD]
    obj, stats = ask(client_of(fake))
    assert obj == GOOD and stats.attempts == 2


def test_529_twice_is_an_error(fake):
    over = ("http", 529, {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
    fake.answers += [over, over, GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.status == 529 and len(fake.messages_calls()) == 2 and outcome_unknown(info.value) is False
    assert "busy" in info.value.detail


def test_529_then_bad_format_then_529_spends_the_budget(fake):
    over = ("http", 529, {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
    fake.answers += [over, BAD, over, GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.status == 529 and len(fake.messages_calls()) == 3, "один HTTP-повтор на обращение, всего ≤ 3"


@pytest.mark.parametrize("status", [502, 504])
def test_gateway_errors_are_unknown_and_not_retried(fake, status):
    fake.answers += [("http", status, {"type": "error", "error": {"type": "api_error", "message": "gw"}}), GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert outcome_unknown(info.value) is True and len(fake.messages_calls()) == 1


def test_drop_after_send_is_unknown(fake):
    fake.answers += [("drop",), GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.sent is True and outcome_unknown(info.value) is True and len(fake.messages_calls()) == 1


def test_overflow_is_refused_before_send(fake):
    with pytest.raises(PromptOverflowError):
        ask(client_of(fake, context_window=200, max_output=180))
    assert fake.messages_calls() == []


# ============================================================================ модели

def test_models_listed_with_exact_names(fake):
    fake.models = ["Claude-Like-Model", "claude-like-model:latest"]
    client = client_of(fake)
    names = [m["name"] for m in client.list_models()]
    assert names == ["Claude-Like-Model", "claude-like-model:latest"], "имена без нормализации Ollama"
    assert client.version().startswith("Messages API, моделей: 2")
    assert client.model_info("Claude-Like-Model")["name"] == "Claude-Like-Model"


@pytest.mark.parametrize("mode", [404, 405, 501])
def test_models_unavailable_uses_the_fallback_name(fake, mode):
    fake.models_mode = mode
    client = client_of(fake, fallback_model="my-model")
    assert "недоступен" in client.version()
    assert [m["name"] for m in client.list_models()] == ["my-model"]
    empty = client_of(fake, fallback_model="")
    with pytest.raises(LlmError, match="имя модели не задано") as info:
        empty.list_models()
    assert info.value.status == mode


@pytest.mark.parametrize("mode", [401, 403])
def test_models_auth_errors_are_not_masked_by_the_fallback(fake, mode):
    fake.models_mode = mode
    with pytest.raises(LlmError) as info:
        client_of(fake, fallback_model="my-model").list_models()
    assert info.value.status == mode


def test_unload_is_not_supported(fake):
    client = client_of(fake)
    assert client.ps() == []
    with pytest.raises(LlmError, match="не поддерживается"):
        client.unload_model("x")


# ============================================================================ ход с инструментами (исследование)

TOOLS = [{"type": "function", "function": {"name": "search", "description": "поиск",
                                           "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}}},
         {"type": "function", "function": {"name": "answer", "description": "строка ответа",
                                           "parameters": {"type": "object", "properties": {"row": {"type": "object"}}}}}]


def test_turn_normalizes_calls_and_replays_results_in_one_user_message(fake):
    fake.answers.append(("tools", [("search", {"query": "demo 1.0"}), ("answer", {"row": {"input_ref": "r1"}})]))
    client = client_of(fake)
    turn = client.chat_turn("test-model", MESSAGES, tools=TOOLS)
    assert turn.finish_reason == "tool_calls" and turn.usage["prompt_tokens"] == 120 and turn.sends == 1
    calls = turn.tool_calls
    assert [c["function"]["name"] for c in calls] == ["search", "answer"]
    assert isinstance(calls[0]["function"]["arguments"], str)
    assert json.loads(calls[0]["function"]["arguments"]) == {"query": "demo 1.0"}
    body = fake.messages_calls()[0]
    assert body["tool_choice"] == {"type": "auto"} and [t["name"] for t in body["tools"]] == ["search", "answer"]
    history = MESSAGES + [turn.message] + [
        {"role": "tool", "tool_call_id": calls[0]["id"], "content": "результаты поиска"},
        {"role": "tool", "tool_call_id": calls[1]["id"], "content": "строка принята на проверку"},
        {"role": "user", "content": "Дайте итог."}]
    fake.answers.append(("text", "готово"))
    second = client.chat_turn("test-model", history, tools=TOOLS)
    assert second.finish_reason == "stop" and second.content == "готово"
    sent = fake.messages_calls()[1]["messages"]
    assert [m["role"] for m in sent] == ["user", "assistant", "user"]
    assert [b["type"] for b in sent[2]["content"]] == ["tool_result", "tool_result", "text"]


def test_turn_length_is_reported_as_length(fake):
    fake.answers.append(("blocks", [tool_use_block("search", {"query": "x"})], "max_tokens"))
    turn = client_of(fake).chat_turn("test-model", MESSAGES, tools=TOOLS)
    assert turn.finish_reason == "length", "исследование по length не выполняет инструменты"


def test_turn_known_error_carries_sends(fake):
    fake.answers.append(("blocks", [{"type": "text", "text": "нет"}], "refusal"))
    with pytest.raises(LlmError) as info:
        client_of(fake).chat_turn("test-model", MESSAGES, tools=TOOLS)
    assert info.value.reason == "refusal" and info.value.sends == 1 and info.value.stats.prompt_tokens == 120


def test_to_wire_messages_hoists_system_and_merges_users():
    system, wire = to_wire_messages([{"role": "system", "content": "A"}, {"role": "system", "content": "B"},
                                     {"role": "user", "content": "u1"}, {"role": "user", "content": "u2"}])
    assert system == "A\n\nB" and len(wire) == 1 and [b["text"] for b in wire[0]["content"]] == ["u1", "u2"]
    with pytest.raises(LlmError):
        to_wire_messages([{"role": "developer", "content": "x"}])


# ============================================================================ внешний класс по https

def test_external_over_https_with_name_check(monkeypatch):
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    monkeypatch.setattr(llm_net, "external_address_ok", lambda ip, hosts=None: str(ip) == "127.0.0.1")
    monkeypatch.setattr(llm_net, "_tls_context", lambda: ssl.create_default_context(cafile=str(CERTS / "ca.pem")))
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host == "external-test.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", getaddrinfo)
    with FakeMessagesApi(tls=True) as server:
        server.answers.append(GOOD)
        client = MessagesClient(server.url, timeout=30)
        client.auth = lambda: {"x-api-key": KEY}
        assert client.trust == "external"
        assert ask(client)[0] == GOOD
        monkeypatch.delenv("LLM_EXTERNAL")
        with pytest.raises(SendNotAllowed, match="LLM_EXTERNAL=1"):
            ask(client)
        assert len(server.messages_calls()) == 1 and server.violations == []
        plain = MessagesClient(server.url.replace("https://", "http://"))
        with pytest.raises(LlmError, match="только https"):
            plain.version()


# ============================================================================ ревью круг 15: строгий разбор и срок

@pytest.mark.parametrize("payload", ["[]", "null", '{"content": null, "stop_reason": "end_turn"}',
                                     '{"content": [null, {"type": "text", "text": "x"}], "stop_reason": "end_turn"}',
                                     '{"content": [{"type": "text"}], "stop_reason": "end_turn"}'])
def test_broken_response_is_a_known_protocol_error(fake, payload):
    """Ответ получен (HTTP 200), но не по протоколу: известная ошибка bad_response, без AttributeError и без молчаливого
    отбрасывания блоков (находка 6)."""
    fake.answers.append(("http", 200, payload))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.reason == "bad_response" and outcome_unknown(info.value) is False
    assert len(fake.messages_calls()) == 1


def test_deadline_before_a_correction_is_known_and_not_counted(fake, monkeypatch):
    """Первый ответ получен и невалиден, срок обращения истёк до исправляющей отправки: запрос не уходит, исход
    известен (reason deadline), отправок – одна (находка 7)."""
    import app.llm_chat as chat
    clock = {"t": 1000.0}
    monkeypatch.setattr(chat.time, "monotonic", lambda: clock["t"])
    client = client_of(fake, timeout=30)
    real_request = client._request

    def request_then_expire(*args, **kwargs):
        result = real_request(*args, **kwargs)
        clock["t"] += 60  # ответ пришёл, а срок обращения уже истёк
        return result
    client._request = request_then_expire
    fake.answers += [BAD, GOOD]
    with pytest.raises(LlmError) as info:
        ask(client)
    e = info.value
    assert e.reason == "deadline" and outcome_unknown(e) is False
    assert e.stats.attempts == 1 and len(fake.messages_calls()) == 1


def test_turn_rejects_a_tool_that_was_not_offered(fake):
    """Ход исследования: инструмент, которого нет в запросе, – известная ошибка bad_tool с расходом (находка 3);
    в chat_json чужой инструмент закрывается «не использован» и исправляется (проверено выше)."""
    fake.answers.append(("tools", [("unexpected_tool", {"x": 1})]))
    with pytest.raises(LlmError) as info:
        client_of(fake).chat_turn("test-model", MESSAGES, tools=TOOLS)
    e = info.value
    assert e.reason == "bad_tool" and e.sends == 1 and e.stats.prompt_tokens == 120 and outcome_unknown(e) is False


def test_research_keeps_usage_of_a_known_error():
    """Исследование суммирует расход полученного ответа и при известной ошибке хода (находка 5 круга 15). Тест
    вызывает рабочий research_component (KIMI-06: прежний тест повторял суммирование сам и прошёл бы и без него)."""
    from app.llm_chat import usage_stats
    from app.sca_research_net import RowOutcome, research_component

    class RefusingClient:
        def chat_turn(self, *args, **kwargs):
            error = LlmError("отказ", reason="refusal",
                             stats=usage_stats("m", {"prompt_tokens": 120, "completion_tokens": 40,
                                                     "cache_hit_tokens": 5}, 1))
            error.sends = 1
            raise error

    outcome = RowOutcome()
    outcome.add_usage({"prompt_tokens": 100, "completion_tokens": 10})  # расход прежних ходов строки
    row = {"input_ref": "pypi:demo", "ecosystem": "pypi", "name": "demo-lib", "version": "1.0.0",
           "identity_kind": "package"}
    with pytest.raises(LlmError):
        research_component(RefusingClient(), "m", {}, row, "система", "2026-10-01", None, 3, lambda: False, outcome)
    assert outcome.usage["prompt_tokens"] == 220 and outcome.usage["completion_tokens"] == 50
    assert outcome.usage["cache_hit_tokens"] == 5 and outcome.usage["sends"] == 1


def test_cache_read_tokens_and_redacted_thinking(fake):
    fake.default_usage = {"input_tokens": 200, "output_tokens": 30, "cache_read_input_tokens": 150}
    redacted = {"type": "redacted_thinking", "data": "opaque"}
    fake.answers += [("blocks", [redacted, tool_use_block("answer", BAD)], "tool_use"), GOOD]
    obj, stats = ask(client_of(fake))
    assert obj == GOOD and stats.cache_hit_tokens == 300 and stats.prompt_tokens == 400
    assert fake.messages_calls()[1]["messages"][1]["content"][0] == redacted


def test_fake_server_rejects_broken_requests(fake):
    """Проверяющий сервер сам ловит нарушения (находка 8): неверная версия API, текстовый блок без строки,
    tool_use без id – 400 и запись в violations; /models без ключа – 401."""
    import urllib.error
    import urllib.request

    def post(body, version=API_VERSION):
        req = urllib.request.Request(fake.url + "/messages", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "x-api-key": KEY,
                                              "anthropic-version": version})
        try:
            with urllib.request.urlopen(req):
                return 200
        except urllib.error.HTTPError as e:
            return e.code
    good = {"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "x"}]}
    assert post(good, version="2020-01-01") == 400
    assert post({**good, "messages": [{"role": "user", "content": [{"type": "text"}]}]}) == 400
    broken_use = {**good, "messages": [{"role": "user", "content": "x"},
                                       {"role": "assistant", "content": [{"type": "tool_use", "name": "a", "input": {}}]},
                                       {"role": "user", "content": "y"}]}
    assert post(broken_use) == 400
    assert len(fake.violations) == 3
    fake.violations.clear()
    try:
        urllib.request.urlopen(fake.url + "/models")
        code = 200
    except urllib.error.HTTPError as e:
        code = e.code
    assert code == 401
