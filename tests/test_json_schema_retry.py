"""Схема ответа, совместимость сервера и повтор без эха на поддельной Ollama."""

import copy
import hashlib
import json

import pytest

from app import config, llm, model_traffic, prompts
from fake_ollama import FakeOllama, verdict_answer


MESSAGES = [{"role": "system", "content": "Отвечай JSON."}, {"role": "user", "content": "Находка."}]


def ask(client, **kwargs):
    return client.chat_json(
        "gpt-oss:20b", MESSAGES, prompts.VERDICT_FIELDS, prompts.VERDICT_REQUIRED,
        prompts.VERDICT_ENUMS, types=prompts.VERDICT_TYPES, validate=prompts.check_verdict_answer, **kwargs)


def test_schema_uses_verdict_contract():
    schema = llm.answer_schema(prompts.VERDICT_FIELDS, prompts.VERDICT_REQUIRED,
                               prompts.VERDICT_ENUMS, prompts.VERDICT_TYPES)
    assert schema["required"] == prompts.VERDICT_REQUIRED
    assert set(schema["properties"]) == set(prompts.VERDICT_FIELDS)
    props = schema["properties"]
    for key, kind in prompts.VERDICT_TYPES.items():
        if kind.startswith("list["):
            assert props[key] == {"type": "array", "items": {
                "type": "integer" if kind == "list[int]" else "string"}}
        else:
            assert props[key]["type"] == ("integer" if kind == "percent" else "string")
    for key, values in prompts.VERDICT_ENUMS.items():
        assert props[key]["enum"] == values
    assert props["fix"] == {"type": "string"}
    terms = props["terms"]["items"]
    assert terms["required"] == ["term", "meaning"]
    assert terms["properties"] == {"term": {"type": "string"}, "meaning": {"type": "string"}}


def test_generic_schema_uses_callers_contract():
    schema = llm.answer_schema(prompts.ASK_FIELDS, prompts.ASK_REQUIRED, prompts.ASK_ENUMS, prompts.ASK_TYPES)
    assert set(schema["properties"]) == set(prompts.ASK_FIELDS)
    assert schema["required"] == prompts.ASK_REQUIRED
    assert schema["properties"]["verdict_changes"]["enum"] == list(prompts.ASK_ENUMS["verdict_changes"])
    extra = llm.answer_schema({"n": "число", "ok": "флаг", "i": "целое"}, ["ok"], {},
                              {"n": "number", "ok": "bool", "i": "int"})
    assert extra["properties"] == {"n": {"type": "number"}, "ok": {"type": "boolean"},
                                    "i": {"type": "integer"}}


@pytest.mark.parametrize("mode,formats,seed,roles", [
    ("retry", [False, True], 43, ["system", "user", "user"]),
    ("always", [True, True], 43, ["system", "user", "user"]),
    ("off", [False, False], 42, ["system", "user", "assistant", "user"]),
])
@pytest.mark.parametrize("stream", [False, True])
def test_modes_retry_options_and_messages(mode, formats, seed, roles, stream):
    original = copy.deepcopy(MESSAGES)
    options = {"seed": 42, "temperature": 0.1}
    with FakeOllama() as fake:
        fake.answers = ["Ответ без JSON.", verdict_answer()]
        obj, stats = ask(llm.OllamaClient(fake.url), json_schema=mode, options=options, think="low",
                         progress=(lambda event: None) if stream else None)
        first, second = fake.chats()
    assert stats.attempts == 2 and obj["verdict"] == "false_positive"
    assert ["format" in first, "format" in second] == formats
    assert [m["role"] for m in second["messages"]] == roles
    assert first["messages"] == original == MESSAGES
    assert second["messages"][:2] == original
    assert second["options"] == {**first["options"], "seed": seed}
    assert options == {"seed": 42, "temperature": 0.1}
    assert first["think"] == second["think"] == "low"
    assert "нет объекта JSON" in second["messages"][-1]["content"]
    if mode != "off":
        assert "Ответ без JSON." not in json.dumps(second["messages"], ensure_ascii=False)


def test_no_seed_is_not_added(monkeypatch):
    monkeypatch.delitem(llm.DEFAULT_OPTIONS, "seed")
    with FakeOllama() as fake:
        fake.answers = ["Не JSON.", verdict_answer()]
        ask(llm.OllamaClient(fake.url))
        assert all("seed" not in body["options"] for body in fake.chats())


@pytest.mark.parametrize("mode", ["retry", "always"])
@pytest.mark.parametrize("stream", [False, True])
def test_format_rejection_is_remembered_for_client_only(mode, stream):
    def reply(body):
        if "format" in body:
            return "http", 400, {"error": "unsupported JSON schema in format"}
        return verdict_answer()

    with FakeOllama() as fake:
        fake.default_answer = reply
        fake.answers = ["Не JSON."] if mode == "retry" else []
        client = llm.OllamaClient(fake.url)
        _, stats = ask(client, json_schema=mode, progress=(lambda event: None) if stream else None)
        chats = fake.chats()
        assert ["format" in body for body in chats] == ([False, True, False] if mode == "retry" else [True, False])
        assert stats.attempts == (2 if mode == "retry" else 1)
        assert {k: v for k, v in chats[-2].items() if k != "format"} == chats[-1]
        fake.answers = ["Не JSON."]
        ask(client, json_schema=mode)
        assert all("format" not in body for body in fake.chats()[len(chats):])
        ask(llm.OllamaClient(fake.url), json_schema="always")
        assert "format" in fake.chats()[-2]


@pytest.mark.parametrize("status,detail", [(400, "unknown model"), (500, "invalid format")])
def test_unrelated_server_error_does_not_disable_schema(status, detail):
    with FakeOllama() as fake:
        fake.answers = [("http", status, {"error": detail}), verdict_answer()]
        client = llm.OllamaClient(fake.url)
        with pytest.raises(llm.LlmError):
            ask(client, json_schema="always")
        assert len(fake.chats()) == 1
        ask(client, json_schema="always")
        assert "format" in fake.chats()[-1]


@pytest.mark.parametrize("mode", ["retry", "always", "off"])
def test_uncertain_fix_uses_checks_without_changing_raw(mode):
    answer = verdict_answer("uncertain", fix="", check_by_eye=["Проверить источник.", "Проверить вызов."])
    with FakeOllama() as fake:
        fake.answers = [answer]
        obj, stats = ask(llm.OllamaClient(fake.url), json_schema=mode)
        assert len(fake.chats()) == stats.attempts == 1
    verdict = prompts.parse_verdict(obj)
    assert verdict.fix == "Проверить: Проверить источник.; Проверить вызов."
    assert verdict.raw["fix"] == obj["fix"] == answer["fix"] == ""
    assert verdict.raw["check_by_eye"] == answer["check_by_eye"]


def test_uncertain_without_checks_is_rejected():
    assert prompts.check_verdict_answer(verdict_answer("uncertain", fix="", check_by_eye=[]))


@pytest.mark.parametrize("short", [True, False])
def test_schema_retry_repairs_closed_object_or_true_positive_fix(short):
    good = verdict_answer("true_positive")
    bad = {key: good[key] for key in ("what_code_does", "data_flow", "why")} if short else {**good, "fix": ""}

    def repair(body):
        return good if "format" in body else bad

    with FakeOllama() as fake:
        fake.default_answer = repair
        obj, stats = ask(llm.OllamaClient(fake.url), json_schema="retry")
        assert len(fake.chats()) == stats.attempts == 2
    assert obj["fix"] == good["fix"]


@pytest.mark.parametrize("raw,expected", [("", "always"), ("retry", "retry"), (" ALWAYS ", "always"), ("off", "off")])
def test_config_schema_modes(raw, expected):
    assert config.Settings.from_env({"MODEL_JSON_SCHEMA": raw}).model_json_schema == expected
    assert config.Settings().model_json_schema == config.DEFAULT_MODEL_JSON_SCHEMA


def test_invalid_schema_mode():
    with pytest.raises(config.ConfigError, match="MODEL_JSON_SCHEMA"):
        config.Settings.from_env({"MODEL_JSON_SCHEMA": "sometimes"})


@pytest.mark.parametrize("stream", [False, True])
def test_journal_keeps_exact_schema_retry_and_fallback_bodies(tmp_path, stream):
    recorder = model_traffic.Recorder(tmp_path / "traffic")
    model_traffic.set_recorder(recorder)
    try:
        with FakeOllama() as fake:
            fake.answers = ["Не JSON.", ("http", 400, {"error": "unsupported format"}), verdict_answer()]
            ask(llm.OllamaClient(fake.url), progress=(lambda event: None) if stream else None)
            chats = fake.chats()
        events = [json.loads(line) for path in recorder.folder.glob("*.jsonl")
                  for line in path.read_text(encoding="utf-8").splitlines()]
        requests = [e for e in events if e["event"] == "request" and e["url"].endswith("/api/chat")]
        assert len(requests) == len(chats) == 3
        for event, body in zip(requests, chats):
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            assert event["body"].encode("utf-8") == encoded
            assert event["body_sha256"] == hashlib.sha256(encoded).hexdigest()
            assert event["body_len"] == len(encoded)
            assert any(e["id"] == event["id"] and e["event"] in ("response", "error") for e in events)
    finally:
        model_traffic.set_recorder(None)
