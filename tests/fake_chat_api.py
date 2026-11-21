"""Поддельный сервер API чат-завершений для тестов (0.9.13): настоящий HTTP (или HTTPS с тестовым удостоверяющим
центром, tests/certs) на 127.0.0.1 и свободном порту, в отдельном потоке. Данные выдуманы.

    with FakeChatApi() as fake:
        client = ChatCompletionsClient(fake.url); client.trust = "local"
        fake.answers.append({"verdict": "false_positive"})
        obj, stats = client.chat_json(...)
        fake.chats()              # тела запросов /chat/completions по порядку
        fake.headers              # заголовки этих запросов (ключ – в Authorization)

Что отвечает сервер (prefix – путь из адреса, по умолчанию /v1):
  GET  {prefix}/models            – {"object": "list", "data": [{"id": m} for m in fake.models]}
  POST {prefix}/chat/completions  – ответ из очереди fake.answers; пустая очередь – fake.default_answer
  POST {search_path}              – поиск: fake.search_results (или очередь fake.search_answers)
  POST {fetch_path}               – страница: fake.pages[url] (или очередь fake.fetch_answers)

Элемент очереди ответов:
  dict                           – content = JSON этого объекта, finish_reason stop;
  str                            – content как есть;
  ("message", message, finish)   – сообщение ассистента целиком (content, reasoning_content, tool_calls) и причина;
  ("http", код, тело[, заголовки]) – ответ с кодом ошибки; тело – dict или str;
  ("blank_then", ответ)          – перед телом – пустые строки (сервер держит соединение);
  ("drop",)                      – закрыть соединение без ответа (после чтения запроса);
  функция(тело запроса)          – возвращает любой из вариантов выше.
"""

from __future__ import annotations

import http.server
import json
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any
from cert_files import server_pem  # noqa: E402 – ключ без заголовков в репозитории

CERTS = Path(__file__).parent / "certs"


def chat_reply(content: Any, finish: str = "stop", usage: dict[str, Any] | None = None,
               message: dict[str, Any] | None = None) -> dict[str, Any]:
    msg = dict(message) if message is not None else {
        "role": "assistant", "content": content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)}
    return {"id": "chatcmpl-test", "object": "chat.completion", "model": "test-model",
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            "usage": usage or {"prompt_tokens": 120, "completion_tokens": 40, "total_tokens": 160,
                               "completion_tokens_details": {"reasoning_tokens": 10}}}


class FakeChatApi:
    def __init__(self, models: list[str] | None = None, prefix: str = "/v1", tls: bool = False,
                 search_path: str = "/v1/tools/search", fetch_path: str = "/v1/tools/fetch") -> None:
        self.models = list(models or ["test-model", "other-model"])
        self.prefix = prefix.rstrip("/")
        self.search_path, self.fetch_path = search_path, fetch_path
        # точный запрос OSV (ADR-0112): POST /v1/query от корня адреса; очередь ответов, иначе – без уязвимостей
        self.osv_answers: list[Any] = []
        self.osv_default: Any = {"vulns": []}
        self.answers: list[Any] = []
        self.default_answer: Any = {"ok": True}
        self.search_answers: list[Any] = []
        self.fetch_answers: list[Any] = []
        self.search_results: list[dict[str, Any]] = [
            {"url": "https://advisories.example/demo-1", "title": "Demo advisory", "snippet": "fixed in 2.0",
             "date": "2026-01-01"}]
        self.pages: dict[str, str] = {}
        self.requests: list[dict[str, Any]] = []  # {"path", "body", "headers"}
        self._lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, payload: Any, headers: dict[str, str] | None = None,
                      blank: bool = False) -> None:
                body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                if blank:
                    body = b"\n\n\n" + body
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                outer._record(self.path, None, dict(self.headers))
                if self.path == outer.prefix + "/models":
                    self._send(200, {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "test"}
                                                                for m in outer.models]})
                else:
                    self._send(404, {"error": {"message": "not found"}})

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    body = {}
                outer._record(self.path, body, dict(self.headers))
                if self.path == outer.prefix + "/chat/completions":
                    self._answer(outer._next(outer.answers, outer.default_answer, body))
                elif self.path == outer.search_path:
                    item = outer._next(outer.search_answers, None, body)
                    if item is None:
                        item = {"results": outer.search_results}
                    self._plain(item)
                elif self.path == "/v1/query":
                    self._plain(outer._next(outer.osv_answers, outer.osv_default, body))
                elif self.path == outer.fetch_path:
                    item = outer._next(outer.fetch_answers, None, body)
                    if item is None:
                        url = str(body.get("url") or "")
                        item = ({"url": url, "content": outer.pages[url]} if url in outer.pages
                                else ("http", 404, {"error": {"message": "no content"}}))
                    self._plain(item)
                else:
                    self._send(404, {"error": {"message": "not found"}})

            def _plain(self, item: Any) -> None:
                if isinstance(item, tuple) and item and item[0] == "drop":  # обрыв без ответа – и у инструментов
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                if isinstance(item, tuple) and item and item[0] == "http":
                    self._send(item[1], item[2], item[3] if len(item) > 3 else None)
                else:
                    self._send(200, item)

            def _answer(self, item: Any, blank: bool = False) -> None:
                if isinstance(item, tuple) and item:
                    kind = item[0]
                    if kind == "drop":
                        self.close_connection = True
                        self.connection.shutdown(2)
                        return
                    if kind == "http":
                        self._send(item[1], item[2], item[3] if len(item) > 3 else None)
                        return
                    if kind == "blank_then":
                        self._answer(item[1], blank=True)
                        return
                    if kind == "message":
                        self._send(200, chat_reply(None, item[2] if len(item) > 2 else "stop", message=item[1]),
                                   blank=blank)
                        return
                self._send(200, chat_reply(item), blank=blank)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(server_pem()))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        scheme = "https" if tls else "http"
        host = "external-test.example" if tls else "127.0.0.1"
        self.url = f"{scheme}://{host}:{self.port}{self.prefix}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _record(self, path: str, body: Any, headers: dict[str, str]) -> None:
        with self._lock:
            self.requests.append({"path": path, "body": body, "headers": headers})

    def _next(self, queue: list[Any], default: Any, body: Any) -> Any:
        with self._lock:
            item = queue.pop(0) if queue else default
        return item(body) if isinstance(item, Callable) else item  # type: ignore[arg-type]

    def chats(self) -> list[dict[str, Any]]:
        return [r["body"] for r in self.requests if r["path"].endswith("/chat/completions")]

    @property
    def headers(self) -> list[dict[str, str]]:
        return [r["headers"] for r in self.requests]

    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> FakeChatApi:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
