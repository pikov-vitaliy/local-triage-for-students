"""Проверяющий поддельный сервер Messages API (0.9.14, ADR-0106) – по образцу tests/fake_chat_api.py, но каждый
запрос `POST /v1/messages` проверяется на контракт: заголовки `x-api-key` (если ключ требуется) и
`anthropic-version`, положительный `max_tokens`, `system` отдельным полем, роли только user/assistant, допустимые
типы блоков, инструменты со схемой, `tool_choice`, связь `tool_use` → `tool_result` (каждый вызов предыдущего ответа
закрыт ровно одним результатом в следующем сообщении user, результаты – перед текстом), запрет полей рассуждения.
Нарушение – ответ 400 `invalid_request_error` и запись в `violations` (тест проверяет, что их нет).

Ответы – очередь `answers` (как у FakeChatApi): dict – вызов инструмента `answer` с этим объектом (имя – из
`tool_choice`, иначе «answer»); ("text", "строка"[, stop_reason]) – текстовый ответ; ("tools", [(имя, объект), …]) –
несколько вызовов за ход; ("blocks", [блоки], stop_reason) – произвольные блоки (thinking, неподдерживаемые);
("http", статус, тело[, заголовки]); ("drop",) – обрыв. `usage` – по `default_usage`. Сервер хранит исходные байты
запросов (`requests[i]["raw"]`) и ответов (`raw_responses`) – для сравнения с журналом обмена. `/v1/models` – режим
`models_mode`: "ok", 404, 405, 501, 401, 403. Данные выдуманы."""
from __future__ import annotations

import http.server
import json
import ssl
import threading
import uuid
from pathlib import Path
from typing import Any
from cert_files import server_pem  # noqa: E402 – ключ без заголовков в репозитории

CERTS = Path(__file__).parent / "certs"
API_VERSION_HEADER = "anthropic-version"
API_VERSION = "2023-06-01"
BLOCK_TYPES_ASSISTANT = {"text", "tool_use", "thinking", "redacted_thinking"}
BLOCK_TYPES_USER = {"text", "tool_result", "image", "document"}


class ContractViolation(Exception):
    pass


def message_reply(content: list[dict[str, Any]], stop_reason: str = "end_turn", usage: dict[str, int] | None = None,
                  model: str = "test-model") -> dict[str, Any]:
    return {"id": "msg_" + uuid.uuid4().hex[:12], "type": "message", "role": "assistant", "model": model,
            "content": content, "stop_reason": stop_reason, "stop_sequence": None,
            "usage": usage or {"input_tokens": 120, "output_tokens": 40}}


def tool_use_block(name: str, payload: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:10], "name": name, "input": payload}


class FakeMessagesApi:
    def __init__(self, models: list[str] | None = None, prefix: str = "/v1", tls: bool = False,
                 search_path: str = "/v1/tools/search", fetch_path: str = "/v1/tools/fetch",
                 require_key: bool = True, forbid_thinking: bool = True) -> None:
        self.models = list(models or ["test-model", "other-model"])
        self.models_mode: Any = "ok"
        self.prefix = prefix.rstrip("/")
        self.search_path, self.fetch_path = search_path, fetch_path
        self.require_key, self.forbid_thinking = require_key, forbid_thinking
        self.answers: list[Any] = []
        self.default_answer: Any = {"ok": True}
        self.default_usage: dict[str, int] = {"input_tokens": 120, "output_tokens": 40}
        self.search_answers: list[Any] = []
        self.fetch_answers: list[Any] = []
        self.search_results: list[dict[str, Any]] = [
            {"url": "https://advisories.example/demo-1", "title": "Demo advisory", "snippet": "fixed in 2.0",
             "date": "2026-01-01"}]
        self.pages: dict[str, str] = {}
        self.requests: list[dict[str, Any]] = []  # {"path", "body", "headers", "raw"}
        self.raw_responses: list[bytes] = []
        self.violations: list[str] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
                body = payload.encode() if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False).encode()
                with outer._lock:
                    outer.raw_responses.append(body)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _error(self, status: int, kind: str, message: str) -> None:
                self._send(status, {"type": "error", "error": {"type": kind, "message": message}})

            def do_GET(self) -> None:
                outer._record(self.path, None, dict(self.headers), b"")
                if self.path == outer.prefix + "/models":
                    lower = {k.lower(): v for k, v in dict(self.headers).items()}
                    if outer.require_key and not lower.get("x-api-key"):
                        self._error(401, "authentication_error", "x-api-key header is required")
                        return
                    if lower.get(API_VERSION_HEADER) != API_VERSION:
                        with outer._lock:
                            outer.violations.append(f"/models: заголовок {API_VERSION_HEADER} – не {API_VERSION}")
                        self._error(400, "invalid_request_error", "anthropic-version header is required")
                        return
                    mode = outer.models_mode
                    if mode == "ok":
                        self._send(200, {"data": [{"id": m, "type": "model", "display_name": m} for m in outer.models],
                                         "has_more": False})
                    elif mode in (401, 403):
                        self._error(int(mode), "authentication_error", "invalid x-api-key")
                    else:
                        self._error(int(mode), "not_found_error", "models endpoint is not available")
                else:
                    self._error(404, "not_found_error", "not found")

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    body = {}
                outer._record(self.path, body, dict(self.headers), raw)
                if self.path == outer.prefix + "/messages":
                    try:
                        outer._check(body, dict(self.headers))
                    except ContractViolation as e:
                        with outer._lock:
                            outer.violations.append(str(e))
                        self._error(400, "invalid_request_error", str(e))
                        return
                    self._answer(outer._next(outer.answers, outer.default_answer), body)
                elif self.path == outer.search_path:
                    item = outer._next(outer.search_answers, None)
                    self._plain(item if item is not None else {"results": outer.search_results})
                elif self.path == outer.fetch_path:
                    item = outer._next(outer.fetch_answers, None)
                    if item is None:
                        url = str(body.get("url") or "")
                        item = ({"url": url, "content": outer.pages[url]} if url in outer.pages
                                else ("http", 404, {"error": {"message": "no content"}}))
                    self._plain(item)
                else:
                    self._error(404, "not_found_error", "not found")

            def _plain(self, item: Any) -> None:
                if isinstance(item, tuple) and item and item[0] == "http":
                    self._send(item[1], item[2], item[3] if len(item) > 3 else None)
                else:
                    self._send(200, item)

            def _answer(self, item: Any, body: dict[str, Any]) -> None:
                model = str(body.get("model") or "test-model")
                usage = dict(outer.default_usage)
                if isinstance(item, tuple) and item:
                    kind = item[0]
                    if kind == "drop":
                        self.close_connection = True
                        self.connection.shutdown(2)
                        return
                    if kind == "http":
                        self._send(item[1], item[2], item[3] if len(item) > 3 else None)
                        return
                    if kind == "text":
                        self._send(200, message_reply([{"type": "text", "text": str(item[1])}],
                                                      item[2] if len(item) > 2 else "end_turn", usage, model))
                        return
                    if kind == "tools":
                        blocks = [tool_use_block(name, payload) for name, payload in item[1]]
                        self._send(200, message_reply(blocks, item[2] if len(item) > 2 else "tool_use", usage, model))
                        return
                    if kind == "blocks":
                        self._send(200, message_reply(list(item[1]), item[2] if len(item) > 2 else "end_turn", usage,
                                                      model))
                        return
                choice = body.get("tool_choice") or {}
                name = str(choice.get("name") or "answer") if isinstance(choice, dict) else "answer"
                self._send(200, message_reply([tool_use_block(name, item)], "tool_use", usage, model))

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

    # ------------------------------------------------------------------ контракт запроса

    def _check(self, body: dict[str, Any], headers: dict[str, str]) -> None:
        lower = {k.lower(): v for k, v in headers.items()}
        if self.require_key and not lower.get("x-api-key"):
            raise ContractViolation("нет заголовка x-api-key")
        if lower.get(API_VERSION_HEADER) != API_VERSION:
            raise ContractViolation(f"заголовок {API_VERSION_HEADER} – не {API_VERSION}")
        if "authorization" in lower:
            raise ContractViolation("лишний заголовок Authorization у Messages API")
        if not isinstance(body.get("model"), str) or not body["model"]:
            raise ContractViolation("model обязателен")
        tokens = body.get("max_tokens")
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens <= 0:
            raise ContractViolation("max_tokens обязателен и положителен")
        if self.forbid_thinking and ("thinking" in body or "reasoning_effort" in body):
            raise ContractViolation("поля рассуждения не должны передаваться")
        system = body.get("system")
        if system is not None and not (isinstance(system, str) or (isinstance(system, list) and all(
                isinstance(b, dict) and b.get("type") == "text" for b in system))):
            raise ContractViolation("system – строка или список текстовых блоков")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ContractViolation("messages – непустой список")
        tools = body.get("tools")
        names: set[str] = set()
        if tools is not None:
            if not isinstance(tools, list):
                raise ContractViolation("tools – список")
            for tool in tools:
                if not isinstance(tool, dict) or not tool.get("name") or not isinstance(tool.get("input_schema"), dict):
                    raise ContractViolation("инструмент без name или input_schema")
                if tool["input_schema"].get("type") != "object":
                    raise ContractViolation(f"input_schema инструмента {tool['name']} – не object")
                names.add(str(tool["name"]))
        choice = body.get("tool_choice")
        if choice is not None:
            if not isinstance(choice, dict) or choice.get("type") not in ("auto", "any", "tool", "none"):
                raise ContractViolation("tool_choice.type – auto, any, tool или none")
            if choice.get("type") == "tool" and str(choice.get("name")) not in names:
                raise ContractViolation("tool_choice указывает на неизвестный инструмент")
            if choice.get("type") in ("auto", "any", "tool") and not names:
                raise ContractViolation("tool_choice без инструментов")
        if messages[0].get("role") != "user":
            raise ContractViolation("первое сообщение – user")
        open_ids: list[str] | None = None  # вызовы инструментов последнего сообщения ассистента, ждущие результата
        for i, message in enumerate(messages):
            role = message.get("role")
            if role not in ("user", "assistant"):
                raise ContractViolation(f"недопустимая роль {role!r} в сообщении {i}")
            if role == "system":
                raise ContractViolation("system внутри messages")
            content = message.get("content")
            blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
            if not isinstance(blocks, list) or not blocks:
                raise ContractViolation(f"пустое содержимое сообщения {i}")
            allowed = BLOCK_TYPES_ASSISTANT if role == "assistant" else BLOCK_TYPES_USER
            for block in blocks:
                if not isinstance(block, dict) or block.get("type") not in allowed:
                    raise ContractViolation(f"недопустимый блок {block.get('type') if isinstance(block, dict) else block!r} в сообщении {i} ({role})")
                if block["type"] == "text" and not isinstance(block.get("text"), str):
                    raise ContractViolation(f"текстовый блок без строки text в сообщении {i}")
                if block["type"] == "tool_use" and (not isinstance(block.get("id"), str) or not block.get("id")
                                                   or not block.get("name") or not isinstance(block.get("input"), dict)):
                    raise ContractViolation(f"tool_use без id/name/input в сообщении {i}")
                if block["type"] == "tool_result" and not block.get("tool_use_id"):
                    raise ContractViolation(f"tool_result без tool_use_id в сообщении {i}")
            if role == "assistant":
                if open_ids:
                    raise ContractViolation(f"вызовы инструментов без результатов перед сообщением {i}")
                open_ids = [str(b["id"]) for b in blocks if b.get("type") == "tool_use"]
                continue
            results = [b for b in blocks if b.get("type") == "tool_result"]
            if results:
                if open_ids is None:
                    raise ContractViolation(f"tool_result без предыдущего tool_use (сообщение {i})")
                ids = [str(b.get("tool_use_id") or "") for b in results]
                if sorted(ids) != sorted(open_ids):
                    raise ContractViolation(f"tool_result не совпадают с tool_use: {sorted(ids)} против {sorted(open_ids)}")
                if len(set(ids)) != len(ids):
                    raise ContractViolation("повторный tool_use_id")
                first_text = next((k for k, b in enumerate(blocks) if b.get("type") == "text"), len(blocks))
                last_result = max(k for k, b in enumerate(blocks) if b.get("type") == "tool_result")
                if last_result > first_text:
                    raise ContractViolation("tool_result должны стоять перед текстом")
            elif open_ids:
                raise ContractViolation(f"вызовы инструментов остались без результатов (сообщение {i})")
            open_ids = None
        if open_ids:
            raise ContractViolation("последнее сообщение ассистента содержит незакрытые tool_use")

    # ------------------------------------------------------------------ служебное

    def _record(self, path: str, body: Any, headers: dict[str, str], raw: bytes) -> None:
        with self._lock:
            self.requests.append({"path": path, "body": body, "headers": headers, "raw": raw})

    def _next(self, queue: list[Any], default: Any) -> Any:
        with self._lock:
            return queue.pop(0) if queue else default

    def messages_calls(self) -> list[dict[str, Any]]:
        return [r["body"] for r in self.requests if r["path"] == self.prefix + "/messages"]

    def headers(self) -> list[dict[str, str]]:
        return [r["headers"] for r in self.requests]

    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> FakeMessagesApi:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
