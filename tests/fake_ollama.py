"""Поддельный сервер Ollama для тестов: настоящий HTTP на 127.0.0.1 и свободном порту, в отдельном потоке.

Подключение (корень репозитория должен быть в sys.path, например при запуске `python -m pytest` из корня):

    from tests.fake_ollama import FakeOllama, verdict_answer, fenced

    with FakeOllama() as fake:                 # или fake = FakeOllama() ... fake.close()
        client = OllamaClient(fake.url)
        fake.answers.append(verdict_answer("true_positive"))
        obj, stats = client.chat_json(...)
        fake.chats()                           # тела запросов /api/chat по порядку

Есть и фикстура pytest `fake_ollama`: `from tests.fake_ollama import fake_ollama` в модуле тестов или в conftest.py.

Что отвечает сервер:
  GET  /api/version – {"version": fake.version}
  GET  /api/tags    – модели fake.models. По умолчанию: qwen2.5-coder:14b, gpt-oss:20b, модель эмбеддингов
                      и облачная модель (две последние клиент обязан отбросить)
  GET  /api/ps      – загруженные модели fake.loaded; модель попадает туда после ответа на /api/chat
  POST /api/show    – сведения о модели из fake.models
  POST /api/generate – keep_alive: 0 выгружает модель из fake.loaded (как настоящая Ollama); другое значение
                      загружает её обратно
  POST /api/chat    – ответ из очереди fake.answers; пустая очередь – fake.default_answer (по умолчанию
                      default_reply: верный вердикт, а на вопрос по находке – верный ответ ask_answer)
  Неизвестная модель в /api/chat и /api/show – 404, как у настоящей Ollama.

Элемент очереди fake.answers:
  dict                       – content = JSON этого объекта;
  str                        – content как есть (JSON в ограде, мусор, пустая строка);
  ("http", код, тело)        – ответ с кодом ошибки; тело – dict (как JSON) или str;
  ("ndjson", текст)          – ответ 200 с телом потока как есть (строки NDJSON, можно без done и с недописанной
                               последней строкой), затем соединение закрывается;
  ("reply", content, поля)   – content (dict или str) и поля ответа поверх обычных (done_reason, eval_count, ...);
  ("sleep", секунды, ответ)  – пауза перед ответом;
  ("trickle", секунды, ответ) – заголовки сразу, тело по 16 байт с паузой между кусками;
  ("slow_headers", секунды, ответ) – заголовки по одному байту с паузой;
  ("short", ответ)           – в Content-Length заявлено больше, чем прислано, затем соединение закрывается;
  ("chunked", ответ)         – тело с Transfer-Encoding: chunked;
  ("close", ответ)           – ответ с Connection: close;
  ("drop",)                  – закрыть соединение без ответа;
  функция(тело запроса)      – возвращает любой из вариантов выше.

Другие настройки: fake.delay – пауза перед каждым ответом /api/chat (секунды); fake.redirect = "http://..." –
любой запрос получает 302 с этим адресом; fake.stats – счётчики ответа /api/chat (токены и длительности в нс);
fake.vram_share – доля загруженной модели в видеопамяти для /api/ps.
"""

from __future__ import annotations

import copy
import http.server
import json
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any

# Особые способы передачи ответа /api/chat: элемент очереди (режим, [пауза,] ответ).
TRANSPORT_MODES = ("trickle", "slow_headers", "short", "chunked", "close")

# Счётчики ответа /api/chat: 300 токенов за 3 с – 100 ток/с; промпт 1200 токенов за 0,4 с – 3000 ток/с.
DEFAULT_STATS = {
    "total_duration": 3_600_000_000,
    "load_duration": 100_000_000,
    "prompt_eval_count": 1200,
    "prompt_eval_duration": 400_000_000,
    "eval_count": 300,
    "eval_duration": 3_000_000_000,
}


def model_entry(name: str, *, family: str = "qwen2", parameter_size: str = "14.8B",
                quantization: str = "Q4_K_M", size: int = 8_988_124_298,
                capabilities: Iterable[str] | None = ("completion", "tools"), context_length: int = 32768,
                remote: bool = False) -> dict[str, Any]:
    """Запись модели в формате /api/tags Ollama 0.40. remote=True – облачная модель (remote_host, remote_model);
    capabilities=None – без поля capabilities, как у старых версий Ollama (тогда его отдаёт только /api/show
    из поля show_capabilities записи)."""
    entry: dict[str, Any] = {
        "name": name,
        "model": name,
        "modified_at": "2026-01-01T00:00:00Z",
        "size": size,
        "digest": "0" * 64,
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": family,
            "families": [family],
            "parameter_size": parameter_size,
            "quantization_level": quantization,
            "context_length": context_length,
        },
    }
    if capabilities is not None:
        entry["capabilities"] = list(capabilities)
    if remote:
        entry["remote_model"] = name.replace("-cloud", "")
        entry["remote_host"] = "https://ollama.com:443"
    return entry


def default_models() -> list[dict[str, Any]]:
    return [
        model_entry("qwen2.5-coder:14b", capabilities=("completion", "tools", "insert")),
        model_entry("gpt-oss:20b", family="gptoss", parameter_size="20.9B", quantization="MXFP4",
                    size=13_793_441_244, capabilities=("completion", "tools", "thinking"), context_length=131072),
        model_entry("nomic-embed-text:latest", family="nomic-bert", parameter_size="137M", quantization="F16",
                    size=274_302_450, capabilities=("embedding",), context_length=2048),
        model_entry("gpt-oss:120b-cloud", family="gptoss", parameter_size="116.8B", quantization="MXFP4", size=384,
                    capabilities=("completion", "tools", "thinking"), context_length=131072, remote=True),
    ]


def verdict_answer(verdict: str = "false_positive", confidence: int = 80, **overrides: Any) -> dict[str, Any]:
    """Верный по формату ответ модели (ключи как в app.prompts.VERDICT_FIELDS: sast-v3 и поле explanation прежней
    версии sast-v2 – лишний ключ разбор ответа не мешает); поля можно заменить."""
    texts = {
        "true_positive": ("Подтверждено: параметр id попадает в запрос без параметризации (строка 3).",
                          "Перейти на PreparedStatement и передавать id параметром."),
        "false_positive": ("Ложное срабатывание: id приводится к числу (строка 2) до подстановки в запрос.", ""),
        "uncertain": ("Нужна проверка: не видно, откуда приходит значение id.", "Проверить место вызова метода."),
    }
    comment, fix = texts.get(verdict, texts["uncertain"])
    answer = {
        "what_code_does": "Метод читает номер счёта из запроса и ищет счёт в базе данных.",
        "data_flow": ["строка 1: id берётся из параметра запроса", "строка 3: id входит в текст запроса"],
        "why": ["Значение id читается из запроса (строка 1).", "Затем оно попадает в текст запроса (строка 3)."],
        "verdict": verdict,
        "confidence": confidence,
        "summary": "Анализатор сообщает о внедрении SQL: строка запроса собирается из параметра id.",
        "explanation": "Значение id читается из запроса (строка 1) и попадает в текст запроса (строка 3).",
        "evidence_lines": [1, 3],
        "check_by_eye": ["Откуда берётся id (строка 1).", "Как собирается запрос (строка 3)."],
        "terms": [{"term": "`PreparedStatement`", "meaning": "запрос с параметрами: данные передаются отдельно от текста запроса"}],
        "fix": fix,
        "hub_comment": comment,
        "cwe_fit": "да",
    }
    answer.update(overrides)
    return answer


def ask_answer(text: str = "Значение id приходит из запроса (строка 1) и без проверки попадает в запрос (строка 3).",
               verdict_changes: str = "нет", **overrides: Any) -> dict[str, Any]:
    """Верный по формату ответ модели на вопрос по находке (ключи как в app.prompts.ASK_FIELDS)."""
    return {"answer": text, "verdict_changes": verdict_changes, **overrides}


def is_ask_request(body: dict[str, Any]) -> bool:
    """Запрос «Спросить модель», а не разбор находки: ответ ждут с ключом verdict_changes."""
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    return any("verdict_changes" in str(m.get("content") or "") for m in messages if isinstance(m, dict))


def default_reply(body: dict[str, Any]) -> dict[str, Any]:
    """Ответ по умолчанию: на вопрос по находке – ask_answer(), на разбор находки – verdict_answer()."""
    return ask_answer() if is_ask_request(body) else verdict_answer()


def fenced(obj: Any, lang: str = "json") -> str:
    """Ответ в ограде ```json ... ```, как его часто пишут модели."""
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=2)
    return f"```{lang}\n{text}\n```"


def _norm(name: Any) -> str:
    n = str(name or "").strip().casefold()
    if n and ":" not in n.rsplit("/", 1)[-1]:
        n += ":latest"
    return n


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # клиент ушёл по таймауту – для теста не ошибка
        pass


class FakeOllama:
    """Поддельный сервер Ollama (см. описание модуля)."""

    def __init__(self, models: Iterable[str | dict[str, Any]] | None = None, answers: Iterable[Any] = (),
                 default_answer: Any = None, delay: float = 0.0, version: str = "0.40.4",
                 loaded: Iterable[str] = (), vram_share: float = 1.0, host: str = "127.0.0.1") -> None:
        if models is None:
            self.models = default_models()
        else:
            self.models = [copy.deepcopy(m) if isinstance(m, dict) else model_entry(str(m)) for m in models]
        self.answers: list[Any] = list(answers)
        self.default_answer = default_reply if default_answer is None else default_answer
        self.delay = delay
        self.version = version
        self.vram_share = vram_share
        self.redirect = ""
        self.stats = dict(DEFAULT_STATS)
        self.requests: list[tuple[str, str, Any]] = []  # (метод, путь, тело запроса или None)
        self.headers: list[dict[str, str]] = []  # заголовки запросов в том же порядке
        self.loaded: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        for name in loaded:
            self._load(name, 4096)
        # host – адрес IPv4, на котором слушать: по умолчанию loopback; e2e сервера в сети – частный адрес компьютера
        self.server = _QuietServer((host, 0), self._handler_class())
        self.port = self.server.server_address[1]
        self.url = f"http://{host}:{self.port}"
        # частый опрос – close() не ждёт полсекунды на каждом тесте
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                                        name="fake-ollama", daemon=True)
        self._thread.start()

    # ---------------------------------------------------------------- управление

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> FakeOllama:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def chats(self) -> list[dict[str, Any]]:
        """Тела запросов /api/chat по порядку."""
        with self._lock:
            return [body for method, path, body in self.requests if path == "/api/chat"]

    def paths(self) -> list[str]:
        with self._lock:
            return [path for _, path, _ in self.requests]

    def find_model(self, name: Any) -> dict[str, Any] | None:
        wanted = _norm(name)
        return next((m for m in self.models if wanted in (_norm(m.get("name")), _norm(m.get("model")))), None)

    # ---------------------------------------------------------------- ответы

    def _load(self, name: str, context: int) -> None:
        entry = self.find_model(name) or model_entry(name)
        size = int(entry.get("size") or 0)
        loaded = {
            "name": entry["name"],
            "model": entry["name"],
            "size": size,
            "digest": entry.get("digest", ""),
            "details": copy.deepcopy(entry.get("details", {})),
            "expires_at": "2026-01-01T00:05:00Z",
            "size_vram": int(size * self.vram_share),
            "context_length": context,
        }
        self.loaded = [m for m in self.loaded if _norm(m["name"]) != _norm(name)] + [loaded]

    def _next_answer(self, body: dict[str, Any]) -> Any:
        with self._lock:
            answer = self.answers.pop(0) if self.answers else self.default_answer
        while callable(answer):
            answer = answer(body)
        return answer

    def _chat_reply(self, body: dict[str, Any], content: Any, extra: dict[str, Any]) -> dict[str, Any]:
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        message: dict[str, Any] = {"role": "assistant", "content": text}
        if body.get("think"):
            message["thinking"] = "Рассуждение перед ответом."
        reply = {"model": body.get("model"), "created_at": "2026-01-01T00:00:00Z", "message": message,
                 "done": True, "done_reason": "stop"}
        reply.update(self.stats)
        reply.update(extra)
        return reply

    def _handler_class(self) -> type[http.server.BaseHTTPRequestHandler]:
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, code: int, body: Any, headers: dict[str, str] | None = None) -> None:
                if isinstance(body, (dict, list)):
                    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                else:
                    data = str(body or "").encode("utf-8")
                    ctype = "text/plain; charset=utf-8"
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def _read_body(self) -> Any:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if not raw:
                    return None
                try:
                    return json.loads(raw.decode("utf-8"))
                except ValueError:
                    return raw.decode("utf-8", errors="replace")

            def _record(self, method: str, body: Any) -> bool:
                with fake._lock:
                    fake.requests.append((method, self.path, body))
                    fake.headers.append(dict(self.headers.items()))
                if fake.redirect:
                    self._send(302, "", {"Location": fake.redirect})
                    return False
                return True

            def do_GET(self) -> None:  # noqa: N802
                if not self._record("GET", None):
                    return
                if self.path == "/api/version":
                    self._send(200, {"version": fake.version})
                elif self.path == "/api/tags":
                    self._send(200, {"models": copy.deepcopy(fake.models)})
                elif self.path == "/api/ps":
                    self._send(200, {"models": copy.deepcopy(fake.loaded)})
                else:
                    self._send(404, "404 page not found")

            def do_POST(self) -> None:  # noqa: N802
                body = self._read_body()
                if not self._record("POST", body):
                    return
                body = body if isinstance(body, dict) else {}
                if self.path == "/api/show":
                    entry = fake.find_model(body.get("model"))
                    if entry is None:
                        self._send(404, {"error": f"model '{body.get('model')}' not found"})
                        return
                    capabilities = entry.get("show_capabilities", entry.get("capabilities", []))
                    info = {"details": entry.get("details", {}), "capabilities": capabilities,
                            "model_info": {"general.context_length": entry["details"].get("context_length")}}
                    for key in ("remote_host", "remote_model"):
                        if key in entry:
                            info[key] = entry[key]
                    self._send(200, info)
                elif self.path == "/api/generate":
                    self._generate(body)
                elif self.path == "/api/chat":
                    self._chat(body)
                else:
                    self._send(404, "404 page not found")

            def _generate(self, body: dict[str, Any]) -> None:
                """Выгрузка модели (keep_alive 0) – как POST /api/generate у Ollama; иначе модель загружается."""
                name = str(body.get("model") or "")
                if fake.find_model(name) is None:
                    self._send(404, {"error": f"model '{name}' not found"})
                    return
                with fake._lock:
                    if body.get("keep_alive") in (0, "0"):
                        fake.loaded = [m for m in fake.loaded if _norm(m["name"]) != _norm(name)]
                        reason = "unload"
                    else:
                        fake._load(name, int((body.get("options") or {}).get("num_ctx") or 4096))
                        reason = "load"
                self._send(200, {"model": name, "created_at": "2026-01-01T00:00:00Z", "done": True,
                                 "done_reason": reason})

            def _chat(self, body: dict[str, Any]) -> None:
                if fake.delay:
                    time.sleep(fake.delay)
                answer = fake._next_answer(body)
                while isinstance(answer, tuple) and answer and answer[0] == "sleep":
                    time.sleep(float(answer[1]))
                    answer = answer[2]
                    while callable(answer):
                        answer = answer(body)
                if isinstance(answer, tuple) and answer and answer[0] == "drop":
                    self.close_connection = True
                    return
                if isinstance(answer, tuple) and answer and answer[0] == "http":
                    self._send(int(answer[1]), answer[2] if len(answer) > 2 else "")
                    return
                if isinstance(answer, tuple) and answer and answer[0] == "ndjson":
                    self._send_ndjson(str(answer[1]))
                    return
                if fake.find_model(body.get("model")) is None:
                    self._send(404, {"error": f"model '{body.get('model')}' not found"})
                    return
                extra: dict[str, Any] = {}
                if isinstance(answer, tuple) and answer and answer[0] == "reply":
                    answer, extra = answer[1], dict(answer[2] if len(answer) > 2 else {})
                mode, pause = "", 0.0
                if isinstance(answer, tuple) and answer and answer[0] in TRANSPORT_MODES:
                    mode = answer[0]
                    if mode in ("trickle", "slow_headers"):
                        pause, answer = float(answer[1]), answer[2]
                    else:
                        answer = answer[1]
                options = body.get("options") if isinstance(body.get("options"), dict) else {}
                with fake._lock:
                    fake._load(str(body.get("model")), int(options.get("num_ctx") or 4096))
                reply = fake._chat_reply(body, answer, extra)
                if mode:
                    self._send_raw(json.dumps(reply, ensure_ascii=False).encode("utf-8"), mode, pause)
                elif body.get('stream'):
                    message=reply.get('message',{})
                    content=str(message.get('content') or '')
                    frames=[{'message':{'content':content[k:k+24]},'done':False} for k in range(0,len(content),24)]
                    final={**reply,'message':{'role':'assistant','content':'','thinking':message.get('thinking','')}}
                    frames.append(final)
                    encoded=[json.dumps(f,ensure_ascii=False).encode('utf-8')+b'\n' for f in frames]
                    self.send_response(200)
                    self.send_header('Content-Type','application/x-ndjson')
                    self.send_header('Content-Length',str(sum(map(len,encoded))))
                    self.end_headers()
                    for part in encoded:
                        self.wfile.write(part);self.wfile.flush()
                        time.sleep(getattr(fake,'stream_delay',0))
                else:
                    self._send(200, reply)

            def _send_ndjson(self, text: str) -> None:
                """Тело потока как есть (строки NDJSON; без строки с done – оборванный поток), затем закрытие."""
                data = text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                self.close_connection = True

            def _send_raw(self, data: bytes, mode: str, pause: float) -> None:
                """Ответ 200 с особенностями передачи (см. TRANSPORT_MODES)."""
                head = ["HTTP/1.1 200 OK", "Content-Type: application/json; charset=utf-8"]
                if mode == "chunked":
                    head.append("Transfer-Encoding: chunked")
                elif mode == "short":
                    head.append(f"Content-Length: {len(data) + 50}")  # заявлено больше, чем будет прислано
                else:
                    head.append(f"Content-Length: {len(data)}")
                if mode in ("close", "short"):
                    head.append("Connection: close")
                    self.close_connection = True
                raw_head = ("\r\n".join(head) + "\r\n\r\n").encode("ascii")
                if mode == "slow_headers":
                    for k in range(len(raw_head)):
                        self.wfile.write(raw_head[k:k + 1])
                        self.wfile.flush()
                        time.sleep(pause)
                else:
                    self.wfile.write(raw_head)
                if mode == "chunked":
                    for k in range(0, len(data), 64):
                        part = data[k:k + 64]
                        self.wfile.write(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n")
                    self.wfile.write(b"0\r\n\r\n")
                elif mode == "trickle":
                    for k in range(0, len(data), 16):
                        self.wfile.write(data[k:k + 16])
                        self.wfile.flush()
                        time.sleep(pause)
                else:
                    self.wfile.write(data)
                self.wfile.flush()

        return Handler


def _make_fixture() -> Callable[..., Any] | None:
    try:
        import pytest
    except ImportError:  # модуль годится и без pytest
        return None

    @pytest.fixture
    def fake_ollama():
        with FakeOllama() as fake:
            yield fake

    return fake_ollama


fake_ollama = _make_fixture()
