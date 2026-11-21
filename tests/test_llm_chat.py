"""Клиент API чат-завершений (0.9.13, шаг A4, К3–К5 плана): список моделей в общем виде, формат ответа по профилю,
поля рассуждения, общий бюджет отправок (повтор после 429 с Retry-After и повтор не по формату вместе – не больше
трёх), 402 и сбой после отправки – без повтора и с sent, обрыв по длине, фильтр содержимого, один ход с
инструментами (сообщение ассистента целиком), окно модели, статистика «неизвестно», ключ в заголовке и вне ответа;
внешний класс через https с тестовым удостоверяющим центром. Данные выдуманы."""

from __future__ import annotations

import json
import socket
import ssl
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.llm import LlmError, PromptOverflowError, SendNotAllowed  # noqa: E402
from app.llm_chat import ChatCompletionsClient, message_tokens  # noqa: E402
from fake_chat_api import CERTS, FakeChatApi  # noqa: E402

FIELDS = {"verdict": "вердикт", "why": "почему"}
REQUIRED = ["verdict", "why"]
ENUMS = {"verdict": ["true_positive", "false_positive", "uncertain"]}
GOOD = {"verdict": "false_positive", "why": "значение – константа"}
MESSAGES = [{"role": "system", "content": "Ответь объектом JSON."}, {"role": "user", "content": "Находка 1"}]


@pytest.fixture
def fake():
    with FakeChatApi() as server:
        yield server


def client_of(fake: FakeChatApi, **kw) -> ChatCompletionsClient:
    client = ChatCompletionsClient(fake.url, timeout=30)
    client.trust = "local"  # поддельный сервер на 127.0.0.1; внешний класс – отдельный тест ниже
    client.sleep = lambda s: None
    for k, v in kw.items():
        setattr(client, k, v)
    return client


def ask(client: ChatCompletionsClient, **kw):
    return client.chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS, **kw)


# ============================================================================ сведения о сервере

def test_version_and_list_cost_one_models_request(fake):
    """Без лишних запросов: опрос версии и списка моделей (страница проекта, «Проверить»,
    кэш списка) – один GET /models, а не два; спустя MODELS_REUSE_S – снова запрос."""
    client = client_of(fake)
    client.version()
    client.list_models()
    client.model_info("test-model")
    assert [p for p in fake.paths() if p.endswith("/models")] == [fake.prefix + "/models"]
    client._models_memo = (client._models_memo[0] - client.MODELS_REUSE_S - 1, client._models_memo[1])
    client.list_models()
    assert len([p for p in fake.paths() if p.endswith("/models")]) == 2


def test_models_in_common_shape_and_exact_names(fake):
    fake.models = ["Deep-Model", "a-model"]
    client = client_of(fake)
    models = client.list_models()
    assert [m["name"] for m in models] == ["a-model", "Deep-Model"], "имена как у провайдера, без нормализации"
    assert all(m["capabilities"] is None and m["size"] == 0 and m["digest"] == "" for m in models)
    assert client.model_info("Deep-Model")["name"] == "Deep-Model"
    assert client.model_info("deep-model") == {"name": "deep-model", "digest": ""}, "без :latest и смены регистра"
    assert client.version().startswith("API чат-завершений") and client.ps() == []
    with pytest.raises(LlmError, match="не поддерживается"):
        client.unload_model("a-model")


# ============================================================================ ответ модели

def test_json_object_mode_and_reasoning_fields(fake):
    fake.answers.append(GOOD)
    client = client_of(fake, thinking="enabled", effort="high", max_output=4096)
    obj, stats = ask(client)
    assert obj == GOOD
    body = fake.chats()[0]
    assert body["response_format"] == {"type": "json_object"} and body["thinking"] == {"type": "enabled"}
    assert body["reasoning_effort"] == "high" and body["max_tokens"] == 4096 and body["stream"] is False
    assert "temperature" not in body and "seed" not in body
    assert stats.prompt_tokens == 120 and stats.output_tokens == 40 and stats.attempts == 1
    assert stats.eval_tps == 0.0 and stats.prompt_tps == 0.0 and stats.load_s == 0.0, "скорость неизвестна"
    assert stats.think == "enabled,high"


def test_json_schema_and_no_format_modes(fake):
    fake.answers += [GOOD, GOOD]
    ask(client_of(fake, response_mode="json_schema"))
    ask(client_of(fake, response_mode="none"))
    first, second = fake.chats()
    assert first["response_format"]["type"] == "json_schema"
    assert set(first["response_format"]["json_schema"]["schema"]["required"]) == set(REQUIRED)
    assert "response_format" not in second and "thinking" not in second and "reasoning_effort" not in second


def test_profile_limit_wins_over_ollama_num_predict(fake):
    """Прежде num_predict разбора (3072, параметр Ollama) перекрывал предел профиля (8192) – рассуждающая
    модель обрывалась. Предел ответа удалённого протокола – max_output профиля (ADR-0106 п. 9);
    явный max_tokens вызывающего (пробный ответ) – его."""
    fake.answers += [GOOD, GOOD]
    ask(client_of(fake, max_output=8192), options={"num_predict": 3072})
    assert fake.chats()[0]["max_tokens"] == 8192
    client_of(fake, max_output=8192).chat_json("test-model", MESSAGES, FIELDS, REQUIRED, ENUMS, max_tokens=500)
    assert fake.chats()[1]["max_tokens"] == 500


def test_format_retry_then_good(fake):
    fake.answers += ["не JSON вовсе", GOOD]
    obj, stats = ask(client_of(fake))
    assert obj == GOOD and stats.attempts == 2
    retry = fake.chats()[1]["messages"]
    assert retry[-1]["role"] == "user" and retry[-2]["role"] == "assistant"


def test_blank_lines_before_the_body_are_fine(fake):
    fake.answers.append(("blank_then", GOOD))
    assert ask(client_of(fake))[0] == GOOD


def test_one_budget_for_http_and_format_retries(fake):
    """429 с Retry-After → не по формату → годный: три отправки, ожидание по заголовку."""
    waits = []
    fake.answers += [("http", 429, {"error": {"message": "slow down"}}, {"Retry-After": "7"}), "мусор", GOOD]
    client = client_of(fake)
    client.sleep = waits.append
    obj, stats = ask(client)
    assert obj == GOOD and stats.attempts == 3 and waits == [7.0] and len(fake.chats()) == 3


def test_budget_never_exceeds_three_sends(fake):
    fake.answers += [("http", 503, "busy"), "мусор", "мусор", GOOD]
    with pytest.raises(LlmError, match="не по формату"):
        ask(client_of(fake))
    assert len(fake.chats()) == 3


def test_second_429_is_not_retried(fake):
    fake.answers += [("http", 429, "a"), ("http", 429, "b"), GOOD]
    with pytest.raises(LlmError, match="HTTP 429") as info:
        ask(client_of(fake))
    assert len(fake.chats()) == 2 and info.value.status == 429 and info.value.sent is True


def test_retry_after_is_capped(fake):
    waits = []
    fake.answers += [("http", 429, "a", {"Retry-After": "3600"}), GOOD]
    client = client_of(fake)
    client.timeout = 600
    client.sleep = waits.append
    ask(client)
    assert waits == [60.0]


@pytest.mark.parametrize("status, text", [(402, "пополните баланс"), (401, "ключ API не принят"),
                                          (422, "параметры запроса не приняты"), (400, "неверный формат")])
def test_client_errors_are_not_retried(fake, status, text):
    fake.answers += [("http", status, {"error": {"message": "nope"}}), GOOD]
    with pytest.raises(LlmError, match=text) as info:
        ask(client_of(fake))
    assert len(fake.chats()) == 1 and info.value.status == status and info.value.sent is True
    assert "nope" in info.value.detail


def test_drop_after_send_is_unknown_and_not_retried(fake):
    fake.answers += [("drop",), GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert len(fake.chats()) == 1, "после начала отправки повтора нет: запрос мог быть оплачен"
    assert info.value.sent is True and info.value.status is None


def test_refused_connection_is_not_sent():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    client = ChatCompletionsClient(f"http://127.0.0.1:{port}/v1", timeout=5)
    client.trust = "local"
    with pytest.raises(LlmError) as info:
        ask(client)
    assert info.value.sent is False


def test_length_cut_is_an_error_without_retry(fake):
    fake.answers += [("message", {"role": "assistant", "content": '{"verdict": "tr'}, "length"), GOOD]
    with pytest.raises(LlmError, match="оборван"):
        ask(client_of(fake))
    assert len(fake.chats()) == 1


def test_content_filter_is_an_error(fake):
    fake.answers.append(("message", {"role": "assistant", "content": ""}, "content_filter"))
    with pytest.raises(LlmError, match="фильтром"):
        ask(client_of(fake))


def test_admission_is_checked_before_each_send(fake):
    fake.answers += ["мусор", GOOD]
    client = client_of(fake)
    calls = []

    def before_send():
        calls.append(1)
        if len(calls) == 2:
            raise SendNotAllowed("профиль выключен")

    client.before_send = before_send
    with pytest.raises(SendNotAllowed) as info:
        ask(client)
    assert len(fake.chats()) == 1 and info.value.sent is True


def test_window_from_profile_refuses_before_sending(fake):
    client = client_of(fake, context_window=50, max_output=40)
    with pytest.raises(PromptOverflowError):
        ask(client)
    assert fake.chats() == []
    assert message_tokens([{"role": "assistant", "content": "", "reasoning_content": "x" * 400}]) > 50


def test_key_goes_in_header_and_not_into_the_answer(fake):
    key = "test-chat-key-" + "Zq7" * 5
    fake.answers.append({"verdict": "false_positive", "why": f"ключ {key} отражён"})
    client = client_of(fake)
    client.auth = lambda: {"Authorization": f"Bearer {key}"}
    obj, _ = ask(client)
    assert fake.headers[-1]["Authorization"] == f"Bearer {key}"
    assert key not in obj["why"]


# ============================================================================ один ход с инструментами

def test_turn_returns_the_whole_assistant_message(fake):
    message = {"role": "assistant", "content": "", "reasoning_content": "думаю",
               "tool_calls": [{"id": "c1", "type": "function",
                               "function": {"name": "search", "arguments": "{\"query\": \"demo 1.0\"}"}}]}
    fake.answers.append(("message", message, "tool_calls"))
    tools = [{"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}]
    turn = client_of(fake, thinking="enabled").chat_turn("test-model", MESSAGES, tools=tools)
    assert turn.message == message and turn.finish_reason == "tool_calls" and turn.tool_calls[0]["id"] == "c1"
    body = fake.chats()[0]
    assert body["tools"] == tools and body["tool_choice"] == "auto" and "response_format" not in body
    assert turn.usage["prompt_tokens"] == 120 and turn.usage["reasoning_tokens"] == 10 and turn.sends == 1


def test_turn_drop_is_unknown(fake):
    fake.answers.append(("drop",))
    with pytest.raises(LlmError) as info:
        client_of(fake).chat_turn("test-model", MESSAGES)
    assert info.value.sent is True and len(fake.chats()) == 1


# ============================================================================ внешний класс по https

def test_external_over_https_with_name_check(monkeypatch):
    """Настоящий путь класса external: https, имя → закреплённый адрес, сертификат по имени, LLM_EXTERNAL. Адрес
    127.0.0.1 в тесте считается публичным (подмена правила адресов) – иначе поддельный сервер недостижим."""
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
    with FakeChatApi(tls=True) as server:
        server.answers.append(GOOD)
        client = ChatCompletionsClient(server.url, timeout=30)
        assert client.trust == "external"
        assert ask(client)[0] == GOOD
        monkeypatch.delenv("LLM_EXTERNAL")
        with pytest.raises(SendNotAllowed, match="LLM_EXTERNAL=1"):
            ask(client)
        assert len(server.chats()) == 1
        plain = ChatCompletionsClient(server.url.replace("https://", "http://"))
        with pytest.raises(LlmError, match="только https"):
            plain.version()


# ============================================================================ фабрики: протокол из профиля и снимка

def test_factories_pick_the_protocol(fake):
    import json as _json

    from app.executors import Server, chat_settings, client_for, new_client, server_of, service_client
    from app.llm_ollama import OllamaClient
    made = []

    def make_ollama(url):
        made.append(url)
        return OllamaClient(url)

    assert isinstance(new_client(make_ollama, "ollama", "http://127.0.0.1:1"), OllamaClient) and made
    assert isinstance(new_client(make_ollama, "chat_completions", fake.url), ChatCompletionsClient)
    from app.llm_messages import MessagesClient
    assert isinstance(new_client(make_ollama, "messages", fake.url), MessagesClient)  # 0.9.14
    with pytest.raises(LlmError, match="не поддерживается"):
        new_client(make_ollama, "responses", fake.url)
    profile = {"id": 5, "kind": "chat_completions", "base_url": fake.url, "trust": "local", "auth": "none",
               "confirmed_addresses_json": "[]",
               "generation_json": _json.dumps({"context_window": 64000, "max_output": 2048, "timeout_s": 60}),
               "capabilities_json": _json.dumps({"response_mode": "json_schema", "thinking": "disabled",
                                                 "effort": "low"})}
    server = server_of(profile)
    assert server == Server(fake.url, True, "local", (), 5, "none", "chat_completions")
    models = service_client(make_ollama, server).list_models()
    assert [m["name"] for m in models] == ["other-model", "test-model"]
    settings = chat_settings(profile)
    assert (settings["response_mode"], settings["thinking"], settings["effort"], settings["max_output"],
            settings["context_window"]) == ("json_schema", "disabled", "low", 2048, 64000)
    snapshot = {"provider_id": None, "kind": "chat_completions", "base_url": fake.url, "trust": "local",
                "options_json": _json.dumps({"timeout_s": 45, "chat": {"response_mode": "none", "max_output": 512}})}
    client = client_for(make_ollama, snapshot)
    assert isinstance(client, ChatCompletionsClient) and client.response_mode == "none" and client.max_output == 512
    assert client.timeout == 45 and client.trust == "local"
    fake.answers.append(GOOD)
    assert ask(client)[0] == GOOD and fake.chats()[-1]["max_tokens"] == 512


# ============================================================================ ревью A4, круг 1

@pytest.mark.parametrize("status", [502, 504])
def test_gateway_timeouts_are_not_retried(fake, status):
    """Шлюз не дождался провайдера: запрос мог быть обработан и оплачен – повтора нет (неизвестный результат)."""
    fake.answers += [("http", status, "gateway"), GOOD]
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert len(fake.chats()) == 1 and info.value.sent is True


def test_retry_after_as_http_date():
    from app.llm_chat import _retry_after
    assert _retry_after({"Retry-After": "Wed, 21 Oct 2015 07:28:10 GMT"}, now=1445412480.0) == pytest.approx(10.0)
    assert _retry_after({"retry-after": "5"}) == 5.0 and _retry_after({"Retry-After": "soon"}) is None


def test_turn_budget_counts_the_response_schema(fake):
    big = {"type": "json_schema", "json_schema": {"name": "x", "schema": {"description": "y" * 4000}}}
    with pytest.raises(PromptOverflowError):
        client_of(fake, context_window=600, max_output=100).chat_turn("test-model", MESSAGES, response_format=big)
    assert fake.chats() == []


@pytest.mark.parametrize("payload", ["null", "[]", '{"choices": []}', '{"choices": [5]}'])
def test_broken_top_level_answer_is_an_error_after_send(fake, payload):
    fake.answers.append(lambda body: ("http", 200, payload))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.sent is True and len(fake.chats()) == 1


def test_stats_keep_reasoning_and_cache_tokens(fake):
    fake.answers.append(lambda body: ("http", 200, {
        "choices": [{"message": {"role": "assistant", "content": json.dumps(GOOD)}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 30, "prompt_cache_hit_tokens": 20,
                  "completion_tokens_details": {"reasoning_tokens": 12}}}))
    _, stats = ask(client_of(fake))
    assert (stats.reasoning_tokens, stats.cache_hit_tokens, stats.timing) == (12, 20, "app")
    from app.models import LlmStats
    old = LlmStats.from_dict({"model": "m", "prompt_tokens": 1, "output_tokens": 2, "eval_tps": 3.0, "prompt_tps": 4.0,
                              "total_s": 5.0, "load_s": 0.0, "attempts": 1})
    assert (old.reasoning_tokens, old.cache_hit_tokens, old.timing) == (0, 0, ""), "записи 0.9.12 читаются"


def test_closed_json_with_length_is_accepted_like_ollama(fake):
    fake.answers.append(("message", {"role": "assistant", "content": json.dumps(GOOD)}, "length"))
    assert ask(client_of(fake))[0] == GOOD


def test_snapshot_keeps_chat_settings_and_purpose(fake):
    from app.executors import client_for, execution_values
    profile = {"id": 9, "version": 3, "kind": "chat_completions", "base_url": fake.url, "trust": "local",
               "auth": "none", "confirmed_addresses_json": "[]",
               "generation_json": json.dumps({"context_window": 64000, "max_output": 2048}),
               "capabilities_json": json.dumps({"response_mode": "json_schema", "thinking": "enabled",
                                                "effort": "high"})}
    values = execution_values(profile, "test-model", "triage", 16384, "", purpose="research")
    assert values["purpose"] == "research"
    snapshot = {**values, "id": 1}
    client = client_for(lambda url: None, snapshot)
    assert (client.context_window, client.max_output, client.response_mode, client.thinking, client.effort) == (
        64000, 2048, "json_schema", "enabled", "high")


def test_broken_answer_keeps_usage_and_is_known(fake):
    """Ревью круг 16: ответ получен (HTTP 200), но без choices или не JSON – известная ошибка bad_response, расход
    этой попытки не теряется ни в chat_json, ни в chat_turn."""
    from app.llm import outcome_unknown
    fake.answers.append(lambda body: ("http", 200, {"choices": [], "usage": {"prompt_tokens": 120, "completion_tokens": 40}}))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.reason == "bad_response" and outcome_unknown(info.value) is False
    assert info.value.stats.prompt_tokens == 120 and info.value.stats.output_tokens == 40
    fake.answers.append(lambda body: ("http", 200, {"choices": [], "usage": {"prompt_tokens": 70, "completion_tokens": 5}}))
    with pytest.raises(LlmError) as info:
        client_of(fake).chat_turn("test-model", MESSAGES)
    assert info.value.reason == "bad_response" and info.value.stats.prompt_tokens == 70
    fake.answers.append(lambda body: ("http", 200, "not-json"))
    with pytest.raises(LlmError) as info:
        ask(client_of(fake))
    assert info.value.reason == "bad_response" and outcome_unknown(info.value) is False
