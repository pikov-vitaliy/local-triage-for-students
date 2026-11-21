"""Журнал обмена приложения с моделью (app/model_traffic.py): события request/response/error, точные байты
запроса и ответа, назначения и привязки, отказ отправки при сбое записи, отключение журнала и сценарий чтения
scripts/model_traffic.py."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import model_traffic  # noqa: E402
from app.config import ConfigError, Settings  # noqa: E402
from app.llm import OllamaClient  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_triage import Env, env, sast  # noqa: E402, F401

SCRIPT = ROOT / "scripts" / "model_traffic.py"
BASE = "http://127.0.0.1:8765"  # имя хоста, которое пропускает защита запросов


@pytest.fixture
def traffic(tmp_path: Path):
    """Регистратор журнала в папке данных среды; после теста снимается, чтобы не влиять на другие тесты."""
    recorder = model_traffic.Recorder(tmp_path / "data" / "model-traffic")
    model_traffic.set_recorder(recorder)
    yield recorder
    model_traffic.set_recorder(None)


def journal_events(recorder: model_traffic.Recorder) -> list[dict]:
    """Все события журнала регистратора по порядку."""
    events = []
    if not recorder.folder.is_dir():
        return events
    for path in sorted(recorder.folder.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def chat_pair(events: list[dict]) -> tuple[dict, dict]:
    """Пара событий последнего обращения POST /api/chat: (request, response или error)."""
    requests = [e for e in events if e["event"] == "request" and e["url"].endswith("/api/chat")]
    assert requests, "в журнале нет запроса /api/chat"
    request = requests[-1]
    rest = [e for e in events if e["id"] == request["id"] and e["event"] in ("response", "error")]
    assert len(rest) == 1, f"у обращения {request['id']} не одна пара, а {len(rest)}"
    return request, rest[0]


def run_script(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONUTF8": "1"}
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8",
                          env=env, timeout=120)


# ============================================================================ настройка и регистратор

def test_settings_model_traffic_log_and_folder():
    assert Settings().model_traffic_log == "on"
    assert Settings.from_env({"MODEL_TRAFFIC_LOG": "off"}).model_traffic_log == "off"
    assert Settings.from_env({"MODEL_TRAFFIC_LOG": " ON "}).model_traffic_log == "on"
    assert Settings.from_env({}).model_traffic_log == "on"
    with pytest.raises(ConfigError):
        Settings.from_env({"MODEL_TRAFFIC_LOG": "sometimes"})
    settings = Settings(data_dir=Path("/data"))
    assert settings.model_traffic_dir == Path("/data") / "model-traffic"


def test_recorder_base64_body_wire_and_day_file(tmp_path: Path):
    recorder = model_traffic.Recorder(tmp_path / "traffic")
    raw_body = b"\xff\xfe\x00\x00"
    raw_wire = b"POST /api/chat HTTP/1.1\r\n\r\n\xff\xfe"
    event_id, ts = recorder.request(method="POST", url="http://127.0.0.1:11434/api/chat", body=raw_body)
    recorder.response(event_id=event_id, request_ts=ts, duration_ms=5, status=200,
                      headers={"Content-Type": "application/json"}, body=b'{"ok": true}', request_wire=raw_wire)
    path = recorder.folder / f"{ts[:10]}.jsonl"  # файл дня – дата момента запроса
    request, response = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    assert request["event"] == "request" and request["id"] == event_id and request["purpose"] == "other"
    assert request["body_encoding"] == "base64" and base64.b64decode(request["body"]) == raw_body
    assert request["body_sha256"] == hashlib.sha256(raw_body).hexdigest() and request["body_len"] == len(raw_body)
    assert response["event"] == "response" and response["id"] == event_id
    assert response["request_wire_encoding"] == "base64" and base64.b64decode(response["request_wire"]) == raw_wire
    assert response["request_wire_sha256"] == hashlib.sha256(raw_wire).hexdigest()
    assert response["request_wire_len"] == len(raw_wire)
    assert response["body"] == '{"ok": true}' and response["body_encoding"] == "utf-8"


def test_context_inherits_unset_values(tmp_path: Path):
    recorder = model_traffic.Recorder(tmp_path / "traffic")
    with model_traffic.context(purpose="triage", run_id=7, hub_id="A", project_id=3):
        event_id, _ = recorder.request(method="GET", url="http://127.0.0.1:11434/api/version", body=None)
        with model_traffic.context(purpose="models"):
            nested_id, _ = recorder.request(method="GET", url="http://127.0.0.1:11434/api/tags", body=None)
    by_id = {e["id"]: e for e in journal_events(recorder)}
    assert by_id[event_id]["purpose"] == "triage" and by_id[event_id]["run_id"] == 7
    assert by_id[nested_id]["purpose"] == "models"  # назначение перекрыто
    assert (by_id[nested_id]["run_id"], by_id[nested_id]["hub_id"], by_id[nested_id]["project_id"]) == (7, "A", 3)


def test_request_write_failure_raises_and_response_failure_is_logged(tmp_path: Path, caplog):
    blocker = tmp_path / "blocked"
    blocker.write_text("файл на месте папки", encoding="utf-8")
    recorder = model_traffic.Recorder(blocker)
    with pytest.raises(OSError):  # сбой записи request поднимается: вызывающий учитывает его (ADR-0083)
        recorder.request(method="GET", url="http://127.0.0.1:11434/api/version", body=None)
    # сбой записи response работу не ломает и пишется в журнал приложения
    folder = tmp_path / "traffic"
    recorder = model_traffic.Recorder(folder)
    event_id, ts = recorder.request(method="GET", url="http://127.0.0.1:11434/api/version", body=None)
    import shutil
    shutil.rmtree(folder)
    folder.write_text("файл", encoding="utf-8")
    with caplog.at_level("ERROR"):
        recorder.response(event_id=event_id, request_ts=ts, duration_ms=1, status=200, headers={}, body=b"{}")
    assert any("событие response журнала обмена с моделью не записано" in record.message
               for record in caplog.records)


# ============================================================================ прогон: события и точные байты

def test_triage_run_records_request_response_with_exact_bytes(env: Env, traffic):
    env.fake.answers = [verdict_answer("true_positive", 90)]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done"
    request, response = chat_pair(journal_events(traffic))
    assert response["event"] == "response" and response["status"] == 200
    assert response["id"] == request["id"] and isinstance(response["duration_ms"], int)
    # тело запроса побайтно совпадает с тем, что получила поддельная Ollama
    body_bytes = request["body"].encode("utf-8")
    assert body_bytes == json.dumps(env.fake.chats()[0], ensure_ascii=False).encode("utf-8")
    assert request["body_sha256"] == hashlib.sha256(body_bytes).hexdigest()
    assert request["body_len"] == len(body_bytes)
    # wire – весь поток запроса: строка запроса, заголовки http.client, тело
    wire = response["request_wire"].encode("utf-8")
    assert wire.startswith(b"POST /api/chat HTTP/1.1\r\n")
    for header in (b"\r\nHost: ", b"\r\nAccept: application/json\r\n", b"\r\nContent-Type: application/json\r\n",
                   b"\r\nContent-Length: ", b"\r\nAccept-Encoding: identity\r\n"):
        assert header in wire, f"в wire нет {header!r}"
    assert wire.endswith(body_bytes)
    assert response["request_wire_sha256"] == hashlib.sha256(wire).hexdigest()
    assert response["request_wire_len"] == len(wire)
    # заголовки запроса разобраны из wire, peer – адрес соединения
    headers = response["request_headers"]
    assert headers["Host"] == f"127.0.0.1:{env.fake.port}"
    assert headers["Content-Length"] == str(len(body_bytes))
    assert response["peer"] == f"127.0.0.1:{env.fake.port}"
    # тело ответа – как получено, с контрольной суммой
    answer_bytes = response["body"].encode("utf-8")
    assert response["body_encoding"] == "utf-8"
    assert response["body_sha256"] == hashlib.sha256(answer_bytes).hexdigest()
    assert response["body_len"] == len(answer_bytes)


def test_streamed_response_body_is_concatenated_chunks(env: Env, traffic):
    env.fake.stream_delay = 0.03  # куски потока приходят по одному
    answer = verdict_answer("false_positive", 80)
    env.fake.answers = [answer]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done"
    _, response = chat_pair(journal_events(traffic))
    assert response["chunks"] > 1
    # тело = все куски подряд, как их отдала поддельная Ollama (кадры NDJSON по 24 знака и завершающий кадр)
    text = json.dumps(answer, ensure_ascii=False)
    reply = {"model": "qwen2.5-coder:14b", "created_at": "2026-01-01T00:00:00Z",
             "message": {"role": "assistant", "content": text}, "done": True, "done_reason": "stop"}
    reply.update(env.fake.stats)
    frames = [{"message": {"content": text[k:k + 24]}, "done": False} for k in range(0, len(text), 24)]
    frames.append({**reply, "message": {"role": "assistant", "content": "", "thinking": ""}})
    expected = b"".join(json.dumps(f, ensure_ascii=False).encode("utf-8") + b"\n" for f in frames)
    assert response["body"].encode("utf-8") == expected
    assert response["body_sha256"] == hashlib.sha256(expected).hexdigest()
    assert response["body_len"] == len(expected)


def test_triage_purpose_run_and_hub_in_events(env: Env, traffic):
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done"
    events = journal_events(traffic)
    chats = [e for e in events if e["event"] == "request" and e["url"].endswith("/api/chat")]
    assert chats
    for request in chats:
        assert request["purpose"] == "triage"
        assert request["run_id"] == run["id"]
        assert request["hub_id"] == "A"
        assert request["project_id"] == env.project_id
    # обращение /api/tags перед отправкой кода – в том же контексте прогона
    tags = [e for e in events if e["event"] == "request" and e["url"].endswith("/api/tags")]
    assert any(t["purpose"] == "triage" and t["run_id"] == run["id"] for t in tags)


def test_service_poll_purposes(traffic, monkeypatch):
    from app import metrics
    from app.routes.common import compute_metrics, compute_models
    monkeypatch.setattr(metrics, "gpu_stats", lambda: {})  # без настоящей видеокарты
    with FakeOllama() as fake:
        assert compute_models(OllamaClient, fake.url)["version"] == fake.version
        assert compute_metrics(OllamaClient, fake.url)["error"] in (None, "")
    by_path = {}
    for event in journal_events(traffic):
        if event["event"] == "request":
            by_path.setdefault(event["url"].rsplit("/", 1)[-1], event["purpose"])
    assert by_path["version"] == "version" and by_path["tags"] == "models" and by_path["ps"] == "status"


def test_ask_purpose_and_context(env: Env, traffic):
    from test_ask import analysed, asked
    analysed(env)
    question = asked(env, "Откуда приходит owner?")
    assert question["state"] == "done"
    requests = [e for e in journal_events(traffic)
                if e["event"] == "request" and e["url"].endswith("/api/chat")]
    ask_request = requests[-1]  # последний /api/chat – вопрос после разбора
    assert ask_request["purpose"] == "ask"
    assert ask_request["hub_id"] == "A" and ask_request["project_id"] == env.project_id
    assert ask_request["run_id"] is None
    triage_request = requests[0]
    assert triage_request["purpose"] == "triage"


# ============================================================================ обрыв и сбой записи

def test_drop_writes_error_event(env: Env, traffic):
    env.fake.answers = [("drop",)]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done" and run["failed"] == 1
    request, failure = chat_pair(journal_events(traffic))
    assert failure["event"] == "error" and failure["id"] == request["id"]
    assert failure["error_type"] == "LlmError" and "прервана" in failure["error"]
    assert failure["received_len"] == 0 and failure.get("received") is None
    assert failure["peer"] == f"127.0.0.1:{env.fake.port}"
    # wire запроса есть и в событии error
    wire = failure["request_wire"].encode("utf-8")
    assert wire.startswith(b"POST /api/chat HTTP/1.1\r\n")
    assert failure["request_wire_sha256"] == hashlib.sha256(wire).hexdigest()


@pytest.mark.parametrize("failure_stage", ["connect", "headers", "body"])
def test_failed_send_records_only_successfully_sent_bytes(traffic, monkeypatch, failure_stage):
    from app import llm, llm_net

    sent = []

    class Socket:
        def sendall(self, data):
            if failure_stage == "headers" or (failure_stage == "body" and sent):
                raise OSError("Отправка прервана")
            sent.append(bytes(data))

        def getpeername(self):
            return ("127.0.0.1", 12345)

        def close(self):
            pass

    def connect(*args):
        if failure_stage == "connect":
            raise ConnectionRefusedError("Соединение отклонено")
        return Socket()

    monkeypatch.setattr(llm_net, "_connect_any", connect)
    with pytest.raises(llm.LlmError):
        OllamaClient("http://127.0.0.1:12345")._request("/api/chat", {"model": "test"})
    request, failure = chat_pair(journal_events(traffic))
    assert request["body_len"] > 0 and failure["event"] == "error"
    wire = failure.get("request_wire", "").encode("utf-8")
    assert wire == b"".join(sent)
    if failure_stage == "body":
        assert failure["request_wire_len"] == len(wire)
        assert failure["request_wire_sha256"] == hashlib.sha256(wire).hexdigest()
        assert wire.startswith(b"POST /api/chat HTTP/1.1\r\n") and wire.endswith(b"\r\n\r\n")
    else:
        assert wire == b""


def test_short_response_writes_error_with_received_bytes(env: Env, traffic):
    env.fake.answers = [("short", verdict_answer("true_positive"))]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done" and run["failed"] == 1
    _, failure = chat_pair(journal_events(traffic))
    assert failure["event"] == "error" and failure["received_len"] > 0
    received = failure["received"].encode("utf-8")
    assert failure["received_sha256"] == hashlib.sha256(received).hexdigest()
    assert failure["received_len"] == len(received)
    assert json.loads(received.decode("utf-8"))["done"] is True


def test_journal_folder_unavailable_does_not_block_request(tmp_path: Path):
    # ADR-0083: папка журнала недоступна для записи (на её месте файл) – запрос к модели всё равно уходит,
    # сбой учтён и виден как предупреждение
    folder = tmp_path / "data" / "model-traffic"
    folder.parent.mkdir(parents=True)
    folder.write_text("не папка", encoding="utf-8")
    model_traffic.reset_failures()
    model_traffic.set_recorder(model_traffic.Recorder(folder))
    try:
        with FakeOllama() as fake:
            client = OllamaClient(fake.url)
            assert client.version()
            assert fake.paths() == ["/api/version"]
        warning = model_traffic.failure_text()
        assert "Журнал обмена с моделью не записан для 1 обращений" in warning
        assert "Обратитесь к автору программы." in warning
    finally:
        model_traffic.set_recorder(None)
        model_traffic.reset_failures()


def test_triage_journal_failure_keeps_triage_and_warns_operator(env: Env, traffic, monkeypatch):
    env.load([sast("A", 15)])
    model_traffic.reset_failures()
    real_write = traffic._write
    calls = {"n": 0}

    def flaky_write(event, day):
        calls["n"] += 1
        if calls["n"] > 1:  # первое событие (список моделей) записано, дальше места нет
            raise OSError("нет места на диске")
        real_write(event, day)

    monkeypatch.setattr(traffic, "_write", flaky_write)
    try:
        run = env.run()
        assert run["state"] == "done" and run["failed"] == 0  # находка разобрана моделью
        assert env.fake.chats(), "запрос к модели отправлен, несмотря на сбой журнала"
        status = env.runner.run_status(run["id"])
        assert "Журнал обмена с моделью не записан" in status["journal_warning"]
        assert "нет места на диске" in status["journal_warning"]
        assert "Обратитесь к автору программы." in status["journal_warning"]
        assert status["feed"][0]["state"] != "error"
    finally:
        model_traffic.reset_failures()


# ============================================================================ отключение журнала

def test_model_traffic_log_off_no_files_and_work_goes_on(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import create_app
    monkeypatch.setenv("MODEL_TRAFFIC_LOG", "off")
    fake = FakeOllama()
    base = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    settings = replace(base, model_traffic_log=Settings.from_env().model_traffic_log)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            answer = client.get("/api/ollama")
            assert answer.status_code == 200 and answer.json()["version"] == fake.version
        assert fake.paths(), "обмен с моделью шёл"
        folder = tmp_path / "data" / "model-traffic"
        assert not folder.is_dir() or not list(folder.glob("*.jsonl")), "журнал выключен – файлов нет"
    finally:
        fake.close()


def test_model_traffic_log_on_by_default_writes_files(tmp_path: Path):
    from fastapi.testclient import TestClient

    from app.main import create_app
    fake = FakeOllama()
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            answer = client.get("/api/ollama")
            assert answer.status_code == 200
        files = list((tmp_path / "data" / "model-traffic").glob("*.jsonl"))
        assert files, "журнал включён по умолчанию – файлы пишутся"
    finally:
        fake.close()


# ============================================================================ сценарий чтения

def test_script_verify_and_corruption_detection(env: Env, traffic, tmp_path: Path):
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done"
    folder = traffic.folder
    result = run_script("verify", "--dir", str(folder))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Совпало" in result.stdout and " из " in result.stdout
    assert run_script("verify", "--dir", str(tmp_path / "missing")).returncode == 0  # пустая папка – не ошибка
    # порча одного байта тела: sha256 перестаёт сходиться, код выхода ненулевой
    path = next(folder.glob("*.jsonl"))
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        event = json.loads(line)
        if event.get("event") == "response" and event.get("body"):
            body = event["body"]
            event["body"] = ("0" if body[0] != "0" else "1") + body[1:]
            lines[index] = json.dumps(event, ensure_ascii=False)
            break
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = run_script("verify", "--dir", str(folder))
    assert result.returncode != 0
    assert "sha256" in result.stdout


def test_script_list_stats_show_dump(env: Env, traffic, tmp_path: Path):
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done"
    folder = traffic.folder
    _, response = chat_pair(journal_events(traffic))
    ident = response["id"][:8]
    result = run_script("list", "--dir", str(folder))
    assert result.returncode == 0, result.stderr
    assert "POST /api/chat" in result.stdout and "triage" in result.stdout and "Обменов:" in result.stdout
    result = run_script("list", "--dir", str(folder), "--purpose", "triage", "--run", str(run["id"]),
                        "--hub", "A")
    assert result.returncode == 0 and "POST /api/chat" in result.stdout
    result = run_script("stats", "--dir", str(folder))
    assert result.returncode == 0 and "triage" in result.stdout
    result = run_script("show", ident, "--dir", str(folder))
    assert result.returncode == 0, result.stderr
    assert "ЗАПРОС POST" in result.stdout and "ОТВЕТ" in result.stdout and "Host:" in result.stdout
    out = tmp_path / "body.bin"
    result = run_script("dump", ident, "--part", "response", "--out", str(out), "--dir", str(folder))
    assert result.returncode == 0, result.stderr
    assert out.read_bytes() == response["body"].encode("utf-8")
    wire_out = tmp_path / "wire.bin"
    result = run_script("dump", ident, "--part", "request", "--out", str(wire_out), "--dir", str(folder))
    assert result.returncode == 0, result.stderr
    assert wire_out.read_bytes() == response["request_wire"].encode("utf-8")


def test_journal_failure_on_first_model_list_is_shown_for_run(env: Env, traffic, monkeypatch):
    """ADR-0083: сбой записи ещё до разбора находок (список моделей) тоже попадает в предупреждение прогона."""
    env.load([sast("A", 15)])
    model_traffic.reset_failures()
    real_write = traffic._write
    calls = {"n": 0}

    def first_fails(event, day):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("файл журнала занят")
        real_write(event, day)

    monkeypatch.setattr(traffic, "_write", first_fails)
    try:
        run = env.run()
        assert run["state"] == "done"
        assert "файл журнала занят" in env.runner.run_status(run["id"])["journal_warning"]
    finally:
        model_traffic.reset_failures()
