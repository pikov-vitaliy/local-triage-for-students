"""Заголовки по протоколу (0.9.14, ADR-0106, шаг 3 плана): секрет ключа – `Authorization: Bearer` у чат-завершений и
`x-api-key` у Messages API (одна функция для снимка, формы и проверки ключа); служебные заголовки протокола –
через точку расширения транспорта `ServerClient.protocol_headers()`: уходят на каждый запрос, в журнале обмена
остаются и не маскируются как секрет. Данные выдуманы."""
from __future__ import annotations

import sys
from keys_support import keys_for  # noqa: E402
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import model_traffic  # noqa: E402
from app.llm_chat import ChatCompletionsClient  # noqa: E402
from app.provider_keys import auth_headers, key_headers, save_key  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402

SECRET = "sk-test-0123456789abcdef"


def test_key_headers_by_kind():
    assert key_headers("chat_completions", SECRET) == {"Authorization": f"Bearer {SECRET}"}
    assert key_headers("ollama", SECRET) == {"Authorization": f"Bearer {SECRET}"}
    assert key_headers("messages", SECRET) == {"x-api-key": SECRET}
    assert "anthropic-version" not in key_headers("messages", SECRET), "версия API – не секрет и не ключ"


def test_auth_headers_follow_the_snapshot_kind(tmp_path: Path):
    save_key(keys_for(tmp_path), 5, SECRET, "https://api.example.test", ["203.0.113.5"])
    assert auth_headers(keys_for(tmp_path), 5, "https://api.example.test", ["203.0.113.5"]) == {"Authorization": f"Bearer {SECRET}"}
    assert auth_headers(keys_for(tmp_path), 5, "https://api.example.test", ["203.0.113.5"], kind="messages") == {"x-api-key": SECRET}


class VersionedClient(ChatCompletionsClient):
    """Клиент с служебным заголовком протокола – как у Messages API."""

    def protocol_headers(self) -> dict[str, str]:
        return {"x-protocol-version": "2026-01-01"}


@pytest.fixture
def fake():
    with FakeChatApi() as server:
        yield server


def test_protocol_headers_go_to_the_wire_and_stay_in_the_journal(fake: FakeChatApi, tmp_path: Path):
    client = VersionedClient(fake.url, timeout=30)
    client.trust = "local"
    client.sleep = lambda _s: None
    client.auth = lambda: {"x-api-key": SECRET}
    fake.answers.append({"verdict": "false_positive", "why": "константа"})
    recorder = model_traffic.Recorder(tmp_path / "traffic")
    model_traffic.set_recorder(recorder)
    try:
        with model_traffic.context(purpose="probe"):
            client.chat_json("m", [{"role": "user", "content": "x"}], {"verdict": "в", "why": "п"}, ["verdict", "why"],
                             {"verdict": ["true_positive", "false_positive", "uncertain"]})
    finally:
        model_traffic.set_recorder(None)
    sent = {k.lower(): v for k, v in fake.headers[-1].items()}
    assert sent.get("x-protocol-version") == "2026-01-01" and sent.get("x-api-key") == SECRET
    assert set(client.secrets) == {SECRET}, "секрет – только значение ключа, версия протокола секретом не считается"
    text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in (tmp_path / "traffic").rglob("*") if p.is_file())
    assert "x-protocol-version: 2026-01-01" in text or '"x-protocol-version"' in text, "служебный заголовок виден в журнале"
    assert SECRET not in text, "ключ в журнал не попадает"


def test_plain_clients_have_no_protocol_headers(fake: FakeChatApi):
    assert ChatCompletionsClient(fake.url).protocol_headers() == {}
