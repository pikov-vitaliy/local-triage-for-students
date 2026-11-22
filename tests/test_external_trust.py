"""Класс доверия external (0.9.13, ADR-0104 п. 1–2): разрешение установки LLM_EXTERNAL, только глобальные адреса,
только https, проверка сертификата по имени хоста при соединении с закреплённым адресом; правила профиля. Сертификаты –
выдуманный тестовый удостоверяющий центр (tests/certs)."""

from __future__ import annotations

import http.server
import ipaddress
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_http, llm_net, providers  # noqa: E402
from app.llm import LlmError, SendNotAllowed  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402
from cert_files import server_pem  # noqa: E402 – ключ без заголовков в репозитории

CERTS = Path(__file__).parent / "certs"
PUBLIC = "93.184.216.34"  # публичный адрес (не этого компьютера); соединений с ним тесты не открывают


def fake_dns(monkeypatch, mapping: dict[str, list[str]]) -> list[str]:
    asked: list[str] = []
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host not in mapping:
            return real(host, port, *args, **kwargs)
        asked.append(host)
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in mapping[host]]
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", getaddrinfo)
    return asked


@pytest.fixture
def external_on(monkeypatch):
    monkeypatch.setenv("LLM_EXTERNAL", "1")


# ============================================================================ адреса

@pytest.mark.parametrize("address, ok", [
    (PUBLIC, True), ("2606:2800:220:1:248:1893:25c8:1946", True),
    ("10.1.2.3", False), ("172.16.0.1", False), ("192.168.1.10", False), ("127.0.0.1", False), ("::1", False),
    ("169.254.1.1", False), ("100.64.0.1", False), ("fc00::1", False), ("fe80::1", False), ("224.0.0.1", False),
    ("0.0.0.0", False), ("203.0.113.5", False), ("::ffff:10.0.0.1", False),
])
def test_external_address_is_global_only(address, ok):
    assert llm_net.external_address_ok(ipaddress.ip_address(address)) is ok


def test_own_address_is_not_external(monkeypatch):
    monkeypatch.setattr(llm_net, "is_own_address", lambda ip: True)
    assert llm_net.external_address_ok(ipaddress.ip_address(PUBLIC)) is False


def test_without_llm_external_nothing_is_resolved(monkeypatch):
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    asked = fake_dns(monkeypatch, {"api.example.com": [PUBLIC]})
    with pytest.raises(SendNotAllowed, match="LLM_EXTERNAL=1"):
        llm_net._resolve("api.example.com", 443, trust="external")
    assert asked == [], "без разрешения установки нет даже обращения к службе имён"


def test_external_name_must_resolve_to_public_addresses(monkeypatch, external_on):
    fake_dns(monkeypatch, {"api.example.com": [PUBLIC], "inside.example.com": [PUBLIC, "10.0.0.7"],
                           "loop.example.com": ["127.0.0.1"]})
    entries = llm_net._resolve("api.example.com", 443, trust="external")
    assert [e[4][0] for e in entries] == [PUBLIC]
    with pytest.raises(LlmError, match="10.0.0.7 – это не адрес в интернете"):
        llm_net._resolve("inside.example.com", 443, trust="external")
    with pytest.raises(LlmError, match="не адрес в интернете"):
        llm_net._resolve("loop.example.com", 443, trust="external")


@pytest.mark.parametrize("url, problem", [
    ("http://api.example.com", "только https"),
    ("https://user:pass@api.example.com", "имени пользователя"),
    ("https://10.0.0.5", "не адрес в интернете"),
    ("https://127.0.0.1:8443", "не адрес в интернете"),
    ("https://api.example.com/v1?x=1", "«?» и «#»"),
    ("https://api.example.com:99999", "неверный порт"),
    ("", "не задан"),
])
def test_external_target_rejects(url, problem):
    with pytest.raises(LlmError, match=problem):
        llm_net.external_target(url)


def test_external_target_keeps_path_prefix():
    t = llm_net.external_target("https://API.Example.com/v1/")
    assert (t.scheme, t.host, t.port, t.prefix, t.base) == ("https", "api.example.com", 443, "/v1",
                                                            "https://API.Example.com/v1")


def test_ollama_client_never_goes_external(monkeypatch, external_on):
    asked = fake_dns(monkeypatch, {"api.example.com": [PUBLIC]})
    client = OllamaClient("https://api.example.com")
    client.trust = "external"
    with pytest.raises(LlmError, match="не поддерживается"):
        client.version()
    assert asked == []


# ============================================================================ TLS по имени хоста

class TlsServer:
    """HTTPS-сервер на 127.0.0.1 с сертификатом external-test.example (тестовый удостоверяющий центр)."""

    def __init__(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(server_pem()))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def tls_get(host: str, port: int) -> int:
    entries = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    deadline = time.monotonic() + 10
    watchdog = llm_net._Watchdog(deadline)
    conn = llm_net._PinnedHTTPSConnection(host, port, entries, deadline, watchdog)
    try:
        conn.request("GET", "/")
        return conn.getresponse().status
    finally:
        watchdog.cancel()
        conn.close()


def test_certificate_is_checked_by_host_name_on_the_pinned_address(monkeypatch):
    def test_ca():
        context = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        return context
    server = TlsServer()
    try:
        # системное хранилище тестовый центр не знает: соединение не устанавливается
        with pytest.raises(ssl.SSLCertVerificationError):
            tls_get("external-test.example", server.port)
        monkeypatch.setattr(llm_net, "_tls_context", test_ca)
        assert tls_get("external-test.example", server.port) == 200, "имя совпало с сертификатом"
        with pytest.raises(ssl.SSLCertVerificationError, match="match|Hostname"):
            tls_get("other.example", server.port)  # тот же адрес, другое имя – отказ
    finally:
        server.close()


def test_transport_reports_wrong_certificate_as_error(monkeypatch):
    """Через общий транспорт: сертификат не того имени – LlmError, ответа нет."""
    server = TlsServer()
    try:
        monkeypatch.setattr(llm_net, "_tls_context", lambda: ssl.create_default_context(cafile=str(CERTS / "ca.pem")))
        client = OllamaClient(f"https://localhost:{server.port}")
        with pytest.raises(LlmError):
            client._request("/")
    finally:
        server.close()
    assert llm_http.ServerClient  # общий транспорт – тот же для всех протоколов


# ============================================================================ правила профиля

def test_profile_rules_for_external(monkeypatch):
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    with pytest.raises(providers.ProfileInvalid, match="только по API внешнего провайдера"):
        providers.check_external({"kind": "ollama", "trust": "external", "enabled": 1})
    with pytest.raises(providers.ProfileInvalid, match="LLM_EXTERNAL=1"):
        providers.check_external({"kind": "chat_completions", "trust": "external", "enabled": 1})
    providers.check_external({"kind": "chat_completions", "trust": "external", "enabled": 0})  # выключенный – можно
    providers.check_external({"kind": "ollama", "trust": "lan", "enabled": 1})  # не внешний – правила нет
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    providers.check_external({"kind": "chat_completions", "trust": "external", "enabled": 1})
    monkeypatch.setenv("LLM_EXTERNAL", "0")
    assert llm_net.external_enabled() is False


def test_ollama_profile_cannot_become_external(tmp_path, monkeypatch):
    from app.db import Database
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    db = Database(tmp_path / "t.db")
    with pytest.raises(providers.ProfileInvalid, match="Ollama"):
        providers.create_profile(db, {"name": "x", "base_url": "https://api.example.com", "trust": "external"})
    with pytest.raises(providers.ProfileInvalid, match="Ollama"):
        providers.save_profile(db, None, {"name": "x", "base_url": "https://api.example.com",
                                                    "trust": "external", "enabled": 1})
    assert not [p for p in db.list_providers() if p["trust"] == "external"]


# ============================================================================ ревью A3, круг 1

@pytest.mark.parametrize("address", ["64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "2002:7f00:1::",
                                     "2002:a00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::7f00:1",
                                     "::ffff:0:a00:1"])
def test_transition_ipv6_ranges_are_not_external(address):
    """NAT64, 6to4, Teredo, IPv4-совместимые и SIIT: за ними может стоять внутренний или собственный адрес."""
    assert llm_net.external_address_ok(ipaddress.ip_address(address)) is False


def test_host_addresses_from_start_script_are_not_external(monkeypatch):
    monkeypatch.setenv("TRIAGE_HOST_ADDRESSES", f"192.0.2.10, {PUBLIC};fe80::1%5")
    assert llm_net.external_address_ok(ipaddress.ip_address(PUBLIC)) is False, "публичный адрес самого хоста"
    monkeypatch.setenv("TRIAGE_HOST_ADDRESSES", "192.0.2.10")
    assert llm_net.external_address_ok(ipaddress.ip_address(PUBLIC)) is True


def test_container_without_fresh_host_addresses_sends_nothing(monkeypatch, external_on):
    """Ревью A3, круг 2: снимка адресов при запуске мало – в контейнере нужны свежие адреса от сборщика метрик."""
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    monkeypatch.setenv("TRIAGE_HOST_ADDRESSES", "192.0.2.10")
    asked = fake_dns(monkeypatch, {"api.example.com": [PUBLIC]})
    for source in (None, lambda: None, lambda: 1 / 0):
        monkeypatch.setattr(llm_net, "HOST_SOURCE", source)
        with pytest.raises(SendNotAllowed, match="сборщик метрик") as refused:
            llm_net._resolve("api.example.com", 443, trust="external")
        # текст паузы – про сборщик, не «включите профиль»
        assert refused.value.note == llm_net.HOST_UNKNOWN_NOTE and "профиль" not in refused.value.note
    assert asked == []
    monkeypatch.setattr(llm_net, "HOST_SOURCE", lambda: ["192.0.2.10", "2a02:6b8:1::5"])
    assert llm_net._resolve("api.example.com", 443, trust="external")
    # новый публичный адрес хоста пришёл от сборщика – он уже не «внешний»; IPv6 хоста – весь его /64
    monkeypatch.setattr(llm_net, "HOST_SOURCE", lambda: [PUBLIC, "2a02:6b8:1::5"])
    with pytest.raises(LlmError, match="не адрес в интернете"):
        llm_net._resolve("api.example.com", 443, trust="external")
    assert llm_net.external_address_ok(ipaddress.ip_address("2a02:6b8:1::abcd")) is False
    assert llm_net.external_address_ok(ipaddress.ip_address("2a02:6b8:2::abcd")) is True


def test_host_addresses_from_the_collector(tmp_path):
    import json as _json
    from app.telemetry import HOST_ADDRESSES_FRESH_S, host_addresses_from, host_snapshot
    path = tmp_path / "host.json"
    snap = {"schema": 1, "collector_id": "x", "sequence": 1, "sampled_at": 1000.0, "host_scope": "ollama_host",
            "memory": {"total_bytes": 10, "available_bytes": 5, "used_bytes": 5}, "cpu_pct": 1.0,
            "addresses": ["192.0.2.10", PUBLIC, 7], "error": None}
    path.write_text(_json.dumps(snap), encoding="utf-8")
    assert host_snapshot(path, 1001.0)["addresses"] == ["192.0.2.10", PUBLIC]
    assert host_addresses_from(path, 1001.0) == ["192.0.2.10", PUBLIC]
    assert host_addresses_from(path, 1000.0 + HOST_ADDRESSES_FRESH_S + 1) is None, "устаревшие адреса – нет данных"
    del snap["addresses"]
    path.write_text(_json.dumps(snap), encoding="utf-8")
    assert host_addresses_from(path, 1001.0) is None, "сборщик старой версии без адресов"


def test_collector_reports_addresses():
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "host-metrics.ps1").read_text(encoding="utf-8-sig")
    assert "addresses=@($addrs)" in script and "Get-NetIPAddress" in script


def test_compose_and_start_script_pass_the_settings():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "LLM_EXTERNAL: ${LLM_EXTERNAL:-0}" in compose and "TRIAGE_HOST_ADDRESSES: ${TRIAGE_HOST_ADDRESSES:-}" in compose
    start = (root / "start.ps1").read_text(encoding="utf-8-sig")
    assert "$env:TRIAGE_HOST_ADDRESSES" in start and "Get-NetIPAddress" in start


def test_one_host_snapshot_per_request(monkeypatch, external_on):
    """Ревью A3, круг 3: адреса хоста читаются один раз на запрос – снимок не «пропадает» между проверками."""
    monkeypatch.setattr(llm_net, "in_container", lambda: True)
    monkeypatch.delenv("TRIAGE_HOST_ADDRESSES", raising=False)
    calls = []

    def source():
        calls.append(1)
        return [PUBLIC] if len(calls) == 1 else None  # второе чтение «устарело»

    monkeypatch.setattr(llm_net, "HOST_SOURCE", source)
    fake_dns(monkeypatch, {"api.example.com": [PUBLIC]})
    with pytest.raises(LlmError, match="не адрес в интернете"):
        llm_net._resolve("api.example.com", 443, trust="external")
    assert len(calls) == 1


def test_disabled_external_profile_is_not_created_without_the_switch(tmp_path, monkeypatch):
    """Ревью A5: создать внешний профиль нельзя без LLM_EXTERNAL даже выключенным; существующий выключенный – правится."""
    from app.db import Database
    db = Database(tmp_path / "t.db")
    db.ensure_default_profile("http://127.0.0.1:11434", "m")  # профиль 1 – умолчание для кода
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    values = {"name": "x", "kind": "chat_completions", "base_url": "https://api.example.com", "trust": "external",
              "enabled": 0}
    with pytest.raises(providers.ProfileInvalid, match="LLM_EXTERNAL=1"):
        providers.save_profile(db, None, values)
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    saved, _ = providers.save_profile(db, None, values)
    monkeypatch.delenv("LLM_EXTERNAL")
    renamed, _ = providers.save_profile(db, saved["id"], {**values, "name": "y"})
    assert renamed["name"] == "y" and renamed["enabled"] == 0
    with pytest.raises(providers.ProfileInvalid, match="LLM_EXTERNAL=1"):
        providers.save_profile(db, saved["id"], {**values, "enabled": 1})


def test_code_default_may_be_a_remote_api_profile(tmp_path, monkeypatch):
    """Решение владельца 21.11.2026: умолчанием для кода можно назначить профиль удалённого API; код внешнему провайдеру
    при этом уходит только проектам с отметкой «код не секретный» (executors.choose_profile)."""
    from app.db import Database
    db = Database(tmp_path / "t.db")
    db.ensure_default_profile("http://127.0.0.1:11434", "m")
    chat = {"name": "c", "kind": "chat_completions", "base_url": "http://127.0.0.1:8080/v1", "trust": "local",
            "enabled": 1}
    with pytest.raises(providers.ProfileInvalid):  # локальный API: разбор кода с ним не запускается (ревью dev36)
        providers.save_profile(db, None, chat, make_default=True)
    assert providers.code_default_ok({"kind": "chat_completions", "trust": "external"})
    assert providers.code_default_ok({"kind": "messages", "trust": "external"})
    assert not providers.code_default_ok({"kind": "chat_completions", "trust": "lan"})
    assert not providers.code_default_ok({"kind": "ollama", "trust": "external"})


@pytest.mark.parametrize("address", ["4000::1", "8000::1", "f000::1"])
def test_reserved_ranges_are_not_external(address):
    """Ревью D1: зарезервированные диапазоны, которые ipaddress может считать и глобальными, – не внешние."""
    assert llm_net.external_address_ok(ipaddress.ip_address(address)) is False


def test_collector_start_replaces_the_previous_one():
    """Ревью D1: запуск сборщика сначала останавливает прежний (в том числе прежней версии, без адресов) и ждёт его
    замок – иначе новый молча завершится, а снимки останутся без адресов компьютера."""
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "host-metrics.ps1").read_text(encoding="utf-8-sig")
    start = script.index("if ($Action -eq 'Start') {")
    block = script[start:script.index("$mutex=New-Object", start)]
    assert "LocalTriageMetricsStart-" in block, "замена – под своим замком (два запуска одновременно)"
    assert "WriteAllText($stopPath" in block and "WaitOne(20000)" in block
    assert block.index("WaitOne(20000)") < block.index("Start-Process")
    # ревью D1, круг 3: чужие процессы не завершаются никогда; успех – свежий снимок нового сборщика
    assert "Stop-Process" not in block and "Get-CimInstance" not in block
    assert "$snap.collector_id -eq $token" in block and "$child.HasExited" in block
