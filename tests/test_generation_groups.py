"""Право на генерацию по группам серверов (0.9.13, шаг A6, ADR-0104 п. 6): «свой контур» – все профили local и lan,
одно право, как в ADR-0099 (одну видеокарту называют разными именами); каждый внешний провайдер (хост и порт) – своё
право: обращение к нему не ждёт локальную видеокарту и не занимает её."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import ask  # noqa: E402
from app.executors import ProbeBusy, Server, probe_generation  # noqa: E402
from app.llm import GENERATION, LlmError, gate_for, gate_key  # noqa: E402
from app.llm_chat import ChatCompletionsClient  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402


@pytest.mark.parametrize("executor", [
    {"trust": "local", "base_url": "http://localhost:11434"},
    {"trust": "local", "base_url": "http://127.0.0.1:11434"},
    {"trust": "lan", "base_url": "http://192.0.2.10:11434"},
    {"trust": "local", "base_url": "http://host.docker.internal:11434"},
    Server("http://192.0.2.10:11434", False, "lan"),
    {},
])
def test_own_circuit_is_one_group(executor):
    assert gate_key(executor) == "own" and gate_for(executor) is GENERATION


def test_external_providers_have_their_own_rights():
    a = gate_for({"trust": "external", "base_url": "https://api.example.com"})
    b = gate_for({"trust": "external", "base_url": "https://API.example.com:443/v1"})
    c = gate_for({"trust": "external", "base_url": "https://other.example.org"})
    assert a is b, "два профиля одного провайдера – по очереди"
    assert a is not c and a is not GENERATION and c is not GENERATION
    assert gate_key({"trust": "external", "base_url": "https://api.example.com:8443"}) == "external:api.example.com:8443"
    assert "api.example.com" in a.label


def test_external_call_does_not_wait_for_the_local_gpu(monkeypatch):
    """Свой контур занят прогоном: проба внешнего профиля право получает (и упирается уже в LLM_EXTERNAL), проба
    своего – понятный отказ с названием группы."""
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    assert GENERATION.try_acquire("triage")
    try:
        external = ChatCompletionsClient("https://api.example.com")
        with pytest.raises(LlmError, match="LLM_EXTERNAL"):
            probe_generation(external, "flash-model")
        local = OllamaClient("http://127.0.0.1:11434")
        with pytest.raises(ProbeBusy, match="Ollama этого компьютера и сети организации"):
            probe_generation(local, "m")
        assert ask.run_busy() and not ask.run_busy({"trust": "external", "base_url": "https://api.example.com"})
    finally:
        GENERATION.release()


def test_external_gate_busy_does_not_block_the_own_circuit():
    gate = gate_for({"trust": "external", "base_url": "https://busy.example.com"})
    assert gate.try_acquire("ask")
    try:
        assert GENERATION.try_acquire("check"), "свой контур свободен"
        GENERATION.release()
        assert ask.busy({"trust": "external", "base_url": "https://busy.example.com"}) and not ask.busy()
        assert not gate.try_acquire("ask"), "к одному провайдеру – по одному запросу"
    finally:
        gate.release()


def test_ipv6_written_two_ways_is_one_group():
    """Ревью A6: [2606:4700:4700::1111] и полная запись того же адреса – одна группа (одно право)."""
    short = gate_key({"trust": "external", "base_url": "https://[2606:4700:4700::1111]"})
    full = gate_key({"trust": "external", "base_url": "https://[2606:4700:4700:0:0:0:0:1111]:443/v1"})
    assert short == full == "external:2606:4700:4700::1111:443"
    assert gate_key({"trust": "external", "base_url": "https://API.Example.com./v1"}) == "external:api.example.com:443"


def test_busy_reason_names_the_holder_and_group():
    gate = gate_for({"trust": "external", "base_url": "https://reason.example.com"})
    assert gate.try_acquire("check")
    try:
        text = ask.busy_text(gate)
        assert "занята проверкой или прогревом" in text and "reason.example.com" in text
    finally:
        gate.release()
    assert gate.try_acquire("triage")
    try:
        assert ask.busy_text(gate) == ask.RUN_BUSY
    finally:
        gate.release()


def test_unicode_and_punycode_names_are_one_group():
    assert gate_key({"trust": "external", "base_url": "https://bücher.example"}) == \
        gate_key({"trust": "external", "base_url": "https://xn--bcher-kva.example"})


def test_trailing_dot_in_any_script_is_one_group():
    """Ревью A6, круг 3: «api.example.com.» и «api.example.com。» (U+3002) – тот же сервер, одно право."""
    plain = gate_key({"trust": "external", "base_url": "https://api.example.com"})
    assert gate_key({"trust": "external", "base_url": "https://api.example.com."}) == plain
    assert gate_key({"trust": "external", "base_url": "https://api.example.com" + chr(0x3002)}) == plain
    assert gate_for({"trust": "external", "base_url": "https://api.example.com" + chr(0x3002)}) is \
        gate_for({"trust": "external", "base_url": "https://api.example.com"})
