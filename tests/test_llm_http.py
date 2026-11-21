"""Общий транспорт клиентов сервера модели (0.9.13, app/llm_http.py): клиент Ollama стоит на нём без изменения
поведения (его тесты – tests/test_llm.py), а ошибка говорит, началась ли передача байтов запроса: после её начала
исход для сервера неизвестен (К11 плана 0.9.13 – у внешнего провайдера такой запрос не повторяется)."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_http  # noqa: E402
from app.llm import LlmError  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DropAfterRequest:
    """Сервер, который принимает соединение, читает запрос и закрывает соединение без ответа."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            self.received = data

    def close(self) -> None:
        self.sock.close()


def test_ollama_client_uses_the_common_transport():
    assert issubclass(OllamaClient, llm_http.ServerClient)
    assert OllamaClient._request is llm_http.ServerClient._request


def test_refused_connection_is_not_sent():
    client = OllamaClient(f"http://127.0.0.1:{free_port()}", timeout=5)
    with pytest.raises(LlmError) as info:
        client.version()
    assert info.value.sent is False, "соединение не установилось: байты запроса не уходили"


def test_drop_after_the_request_is_sent():
    server = DropAfterRequest()
    try:
        client = OllamaClient(f"http://127.0.0.1:{server.port}", timeout=5)
        with pytest.raises(LlmError, match="прервана") as info:
            client.version()
        server.thread.join(5)
        assert server.received.startswith(b"GET /api/version"), "запрос дошёл до сервера"
        assert info.value.sent is True, "передача началась: исход для сервера неизвестен"
    finally:
        server.close()


def test_new_error_is_not_sent_by_default():
    assert LlmError("x").sent is False


def test_protocol_gets_status_and_reply_headers():
    """Протокол получает статус, тело и заголовки ответа: по Retry-After клиент чат-завершений выбирает ожидание."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"error": "slow down"}'
            self.send_response(429)
            self.send_header("Retry-After", "7")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    seen = {}

    class Probe(OllamaClient):
        def _finish(self, t, path, status, body, secrets, headers):
            seen.update(status=status, body=body, headers={k.lower(): v for k, v in headers.items()})
            return {}

    try:
        Probe(f"http://127.0.0.1:{server.server_address[1]}", timeout=5)._request("/x")
    finally:
        server.shutdown()
        server.server_close()
    assert seen["status"] == 429 and seen["headers"]["retry-after"] == "7" and b"slow down" in seen["body"]
    assert LlmError("x").retry_after is None


class Answering:
    """Сервер, который читает запрос целиком и отвечает заданными статусом и телом."""

    def __init__(self, status: int, body: bytes) -> None:
        import http.server
        outer = self
        self.paths: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _reply(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                outer.paths.append(self.path)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _reply

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.parametrize("status, body", [(500, b'{"error": "boom"}'), (200, b"not json at all")])
def test_server_answered_error_is_sent(status, body):
    """Ревью A2: ошибка из разбора ответа (HTTP 500, не JSON) – запрос до сервера дошёл, sent = True."""
    server = Answering(status, body)
    try:
        with pytest.raises(LlmError) as info:
            OllamaClient(server.url, timeout=5)._request("/api/chat", {"model": "m"})
        assert server.paths == ["/api/chat"] and info.value.sent is True
    finally:
        server.close()


def test_failed_timeout_setup_is_not_sent(monkeypatch):
    """Ревью A2: сбой подготовки срока до передачи байтов – sent = False (ни одного sendall)."""
    from app import llm_net
    calls = []
    real_send = llm_net.http.client.HTTPConnection.send

    def counting_send(self, data):
        calls.append(len(data))
        return real_send(self, data)

    server = Answering(200, b"{}")
    try:
        monkeypatch.setattr(llm_net.http.client.HTTPConnection, "send", counting_send)
        real_remaining = llm_net._remaining
        state = {"connected": False}

        def remaining(deadline):
            if state["connected"]:
                raise TimeoutError
            return real_remaining(deadline)

        real_connect = llm_net._PinnedHTTPConnection.connect

        def connect(self):
            real_connect(self)
            state["connected"] = True

        monkeypatch.setattr(llm_net, "_remaining", remaining)
        monkeypatch.setattr(llm_http, "_remaining", remaining)  # копия у общего транспорта (страж подмен)
        monkeypatch.setattr(llm_net._PinnedHTTPConnection, "connect", connect)
        with pytest.raises(LlmError) as info:
            OllamaClient(server.url, timeout=5)._request("/api/version")
        assert calls == [] and info.value.sent is False
    finally:
        server.close()


class MiniOllama:
    """Ollama в миниатюре: /api/tags – одна модель, /api/chat – заданный ответ (статус, тело)."""

    def __init__(self, chat_status: int, chat_body: bytes) -> None:
        import http.server
        import json as _json
        outer = self
        self.chats = 0

        class Handler(http.server.BaseHTTPRequestHandler):
            def _send(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._send(200, _json.dumps({"models": [{"name": "m:latest", "model": "m:latest",
                                                         "digest": "d" * 64}]}).encode())

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.path == "/api/chat":
                    outer.chats += 1
                    self._send(chat_status, chat_body)
                else:
                    self._send(200, b"{}")

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


FIELDS = {"verdict": "вердикт"}


@pytest.mark.parametrize("status, body, text", [
    (404, b'{"error": "model \\"m\\" not found, try pulling it first"}', "нет на сервере Ollama"),
    (200, b'{"error": "boom"}', "вернула ошибку"),
])
def test_wrapped_errors_after_a_sent_chat_keep_sent(status, body, text):
    """Ревью A2, круг 2: обёртки ошибок клиента Ollama («модели нет», ошибка в теле) не теряют sent = True."""
    server = MiniOllama(status, body)
    try:
        with pytest.raises(LlmError, match=text) as info:
            OllamaClient(server.url, timeout=5).chat_json("m", [{"role": "user", "content": "x"}], FIELDS,
                                                          ["verdict"], {})
        assert server.chats == 1 and info.value.sent is True
    finally:
        server.close()


def test_admission_refusal_before_retry_keeps_sent():
    """Ответ не по формату → перед повтором профиль выключили: отказ допуска, но первый запрос уже ушёл."""
    from app.llm import SendNotAllowed
    server = MiniOllama(200, b'{"message": {"role": "assistant", "content": "no json"}, "done": true}')
    client = OllamaClient(server.url, timeout=5)
    calls = []

    def before_send():
        calls.append(1)
        if server.chats >= 1:
            raise SendNotAllowed("профиль выключен")

    client.before_send = before_send
    try:
        with pytest.raises(SendNotAllowed) as info:
            client.chat_json("m", [{"role": "user", "content": "x"}], FIELDS, ["verdict"], {})
        assert server.chats == 1 and info.value.sent is True
    finally:
        server.close()


def test_nothing_sent_keeps_sent_false():
    with pytest.raises(LlmError) as info:
        OllamaClient(f"http://127.0.0.1:{free_port()}", timeout=5).chat_json(
            "m", [{"role": "user", "content": "x"}], FIELDS, ["verdict"], {})
    assert info.value.sent is False


def test_service_calls_after_a_sent_request_keep_sent():
    """Ревью A3: не только chat_json – version() после ответа 200 без версии: ошибка разбора, запрос ушёл."""
    server = MiniOllama(200, b"{}")
    try:
        with pytest.raises(LlmError, match="нет версии") as info:
            OllamaClient(server.url, timeout=5).version()
        assert info.value.sent is True
    finally:
        server.close()


def test_nested_tracking_reports_to_the_parent():
    """Ревью A3: вложенное обращение отправило запрос успешно, внешнее потом упало – sent = True."""
    from app.llm_http import _note_sent, track_sent
    with pytest.raises(LlmError) as info:
        with track_sent():
            with track_sent():
                _note_sent()
            raise LlmError("ошибка внешнего блока")
    assert info.value.sent is True
    with pytest.raises(LlmError) as clean:
        with track_sent():
            raise LlmError("ничего не уходило")
    assert clean.value.sent is False
