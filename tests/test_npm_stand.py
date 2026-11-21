"""Учебный стенд npm (ADR-0155): настройки TRIAGE_STAND, поле stand в /healthz,
Hub выключен на стороне сервера, тексты стенда, сведения о сборке из build.json, команды базы для обёртки
(whoami, ensure-database, summary) и запуск app.serve с остановкой по закрытию stdin. Адреса Hub выдуманы."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import build_info as build_module
from app import hub_ops, metrics
from app.config import ConfigError, Settings, stand_mode
from app.db import HUB_DISABLED_TEXT, Database, HubDisabledInStand
from app.main import create_app
from app.storage import tools
import db_support
from db_support import dsn_display, empty_database, libpq_env
from fake_ollama import FakeOllama
from test_web import BASE, GPU, ORIGIN, web, write_repos  # noqa: F401

TOKEN = "ab" * 16
HUB = "https://hub.example.org"
AS_JSON = {**ORIGIN, "Accept": "application/json"}
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def stand(tmp_path: Path, monkeypatch):
    """Приложение в режиме учебного стенда – как его запускает обёртка npm."""
    monkeypatch.setenv("TRIAGE_STAND", "npm")  # тексты модулей без доступа к настройкам (замок, шаблоны)
    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                        max_upload_mb=1, team_name="Тестовая команда", osv_url="", stand="npm", stand_token=TOKEN)
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        yield SimpleNamespace(client=client, app=app, settings=settings, tmp=tmp_path)
    fake.close()


# ============================================================================ настройки


def test_stand_settings_from_env():
    s = Settings.from_env({"TRIAGE_STAND": "NPM", "TRIAGE_STAND_TOKEN": TOKEN.upper()})
    assert (s.stand, s.stand_token, s.hub_disabled) == ("npm", TOKEN, True)
    plain = Settings.from_env({})
    assert (plain.stand, plain.stand_token, plain.hub_disabled) == ("", "", False)


@pytest.mark.parametrize("env", [{"TRIAGE_STAND": "docker"},
                                 {"TRIAGE_STAND": "npm", "TRIAGE_STAND_TOKEN": "не-шестнадцатеричный-текст"},
                                 {"TRIAGE_STAND": "npm", "TRIAGE_STAND_TOKEN": "ab12"}])
def test_stand_settings_refuse_wrong_values(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_stand_token_is_ignored_outside_stand():
    """Docker-установка с посторонним TRIAGE_STAND_TOKEN в окружении запускается, как до сборки А (ревью, Б3)."""
    s = Settings.from_env({"TRIAGE_STAND_TOKEN": "x"})
    assert (s.stand, s.stand_token, s.hub_disabled) == ("", "", False)


def test_stand_mode_for_texts():
    assert stand_mode({"TRIAGE_STAND": " npm "}) == "npm"
    assert stand_mode({"TRIAGE_STAND": "что-то"}) == "" and stand_mode({}) == ""


# ============================================================================ /healthz


@pytest.mark.parametrize("flag,external", [("1", True), ("0", False), ("", False)])
def test_healthz_reports_stand(stand, monkeypatch, flag: str, external: bool):
    monkeypatch.setenv("LLM_EXTERNAL", flag)
    body = stand.client.get("/healthz").json()
    assert body["status"] == "ok" and body["stand"] == {"token": TOKEN, "external": external}


def test_healthz_without_stand_is_unchanged(web):
    assert "stand" not in web.client.get("/healthz").json()


# ============================================================================ Hub выключен на стороне сервера


def test_probe_in_stand_does_not_queue(stand):
    """«Проверить связь» в стенде: отказ с объяснением, очередь Hub пуста – обновлению схемы стенда мешать нечему."""
    db = stand.app.state.db
    db.set_settings({"hub_url": HUB})
    r = stand.client.post("/settings/hub/probe", headers=AS_JSON)
    assert r.status_code == 409 and r.json()["detail"] == HUB_DISABLED_TEXT
    assert db.hub_ops_list() == []
    assert tools.summary(db._store.conninfo)["hub_ops"] == {}


def test_probe_in_docker_still_queues(web):
    """Тот же обработчик в Docker-установке ставит операцию, как прежде."""
    web.app.state.db.set_settings({"hub_url": HUB})
    r = web.client.post("/settings/hub/probe", headers=AS_JSON)
    assert r.status_code == 200, r.text
    assert [op["purpose"] for op in web.app.state.db.hub_ops_list()] == ["probe"]


def test_worker_addresses_refuse_in_stand(stand):
    headers = {**AS_JSON, hub_ops.WORKER_KEY_HEADER: "0" * 64}
    answers = [stand.client.post("/api/hub/worker/hello", headers=headers, content="{}"),
               stand.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB}, headers=headers)]
    for r in answers:
        assert r.status_code == 503 and r.json()["detail"] == HUB_DISABLED_TEXT
    assert not getattr(stand.app.state, "hub_worker_key", "")  # ключ исполнителя не создавался


def test_worker_key_is_not_issued_in_stand(stand):
    r = stand.client.post("/settings/hub/key/rotate", headers=AS_JSON)
    assert r.status_code == 409 and r.json()["detail"] == HUB_DISABLED_TEXT
    page = stand.client.get("/settings").text
    assert 'id="hub-disabled"' in page
    assert 'id="hub-key-rotate"' not in page and 'id="hub-probe-button"' not in page


def test_queue_is_neither_filled_nor_issued_in_stand(tmp_path: Path):
    """Единственная точка вставки в hub_ops отказывает, выдача исполнителю пуста, сверка с Hub не запускается – даже
    если операция осталась от прежней установки."""
    from app import hub_sync
    db = Database(tmp_path / "triage.db")
    left = db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None)
    db.hub_disabled = True
    with pytest.raises(HubDisabledInStand):
        db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None, key_extra="2")
    assert db.hub_claim("w1", HUB, hub_ops.LEASE_S) is None
    assert db.hub_op(left["id"])["state"] == "queued"
    with pytest.raises(HubDisabledInStand):
        hub_sync.start(db, 1, HUB, 7)
    db.close()


# ============================================================================ тексты стенда


def test_stand_texts_point_to_stand(stand, monkeypatch, tmp_path: Path):
    from app.lockfile import InstanceLock, LockBusy
    from app.routes.projects import repos_missing
    from app.view import make_templates
    from test_lockfile import foreign_lock

    text = repos_missing(stand.settings)
    assert "start.ps1" not in text and "стенд" in text
    warning = make_templates().env.from_string(
        '{% from "macros.html" import collector_warning %}{{ collector_warning(c) }}').render(
        c={"expected": False, "addresses": False, "detail": ""})
    assert "host-metrics.ps1" not in warning and "npx local-triage" in warning
    foreign_lock(tmp_path / "busy")
    with pytest.raises(LockBusy) as busy:
        InstanceLock(tmp_path / "busy").acquire()
    assert "docker compose" not in str(busy.value) and "стенд повторит запуск" in str(busy.value)
    monkeypatch.delenv("TRIAGE_STAND")
    with pytest.raises(LockBusy, match="docker compose down"):
        InstanceLock(tmp_path / "busy").acquire()


# ============================================================================ сведения о сборке пакета


def test_build_info_from_package_file(tmp_path: Path):
    (tmp_path / "build.json").write_text(json.dumps({"commit": "ABCDEF1", "dirty": False, "time": "20.11.2026 21:00"}),
                                         encoding="utf-8")
    assert build_module._from_file(tmp_path) == ("abcdef1", False, "20.11.2026 21:00")
    (tmp_path / "build.json").write_text("не json", encoding="utf-8")
    assert build_module._from_file(tmp_path) == ("", None, "")
    assert build_module._from_file(tmp_path / "нет") == ("", None, "")


def test_build_info_falls_back_to_package_file(tmp_path: Path, monkeypatch):
    """В пакете нет ни LT_BUILD_*, ни .git: коммит, признак правок и время – из build.json."""
    (tmp_path / "build.json").write_text(json.dumps({"commit": "1234567", "dirty": True, "time": "20.11.2026 21:00"}),
                                         encoding="utf-8")
    for name in ("LT_BUILD_COMMIT", "LT_BUILD_DIRTY", "LT_BUILD_TIME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(build_module, "_from_git", lambda root=None: ("", None))
    real = build_module._from_file
    monkeypatch.setattr(build_module, "_from_file", lambda root=None: real(tmp_path))
    build_module.build_info.cache_clear()
    try:
        info = build_module.build_info()
    finally:
        build_module.build_info.cache_clear()
    assert (info["commit"], info["dirty"], info["built"]) == ("1234567", True, "20.11.2026 21:00")


# ============================================================================ команды базы для обёртки


@pytest.fixture
def server_dir(monkeypatch) -> str:
    """Переменные libpq тестового сервера, как их задаёт обёртка, и его каталог данных."""
    parts = db_support.libpq_parts()
    for key, name in (("host", "PGHOST"), ("port", "PGPORT"), ("user", "PGUSER"), ("password", "PGPASSWORD")):
        monkeypatch.setenv(name, str(parts.get(key) or ""))
    # через общее служебное соединение: при отказе сервера оно печатает адрес без пароля (Д14)
    return str(db_support._admin().execute("SHOW data_directory").fetchone()[0])


def test_whoami_matches_only_own_data_directory(server_dir: str):
    assert tools.whoami(server_dir) == (0, {"data_directory": server_dir, "match": True})
    code, answer = tools.whoami(server_dir + "-другой")
    assert code == 1 and answer["match"] is False


def test_ensure_database_creates_only_when_asked(server_dir: str, monkeypatch):
    name = f"stand_probe_{os.getpid()}"
    monkeypatch.setenv("PGDATABASE", name)
    admin = db_support._admin()
    admin.execute(f"DROP DATABASE IF EXISTS {name}")
    try:
        refused = tools.ensure_database(server_dir + "-другой", True)  # чужой сервер – отказ до любой записи
        assert refused == (1, {"data_directory": server_dir, "match": False, "exists": False, "created": False})
        assert tools.ensure_database(server_dir, False)[0] == 1  # пропажа базы прежней установки – не повод создать
        assert admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone() is None
        code, answer = tools.ensure_database(server_dir, True)
        assert (code, answer["exists"], answer["created"]) == (0, True, True)
        code, answer = tools.ensure_database(server_dir, False)
        assert (code, answer["exists"], answer["created"]) == (0, True, False)
    finally:
        admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def test_ensure_database_refuses_odd_name(server_dir: str, monkeypatch, capsys):
    monkeypatch.setenv("PGDATABASE", "Bad-Name")
    assert tools.main(["ensure-database", "--expect-data-dir", server_dir]) == 2
    assert "PGDATABASE" in json.loads(capsys.readouterr().out)["error"]


def test_summary_counts_tables_and_hub_ops():
    conninfo = empty_database()
    db = Database(conninfo)
    db.create_project("п")
    db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None)
    db.close()
    answer = tools.summary(conninfo)
    assert answer["tables"]["projects"] == 1 and answer["hub_ops"] == {"queued": 1}
    assert "meta" in answer["tables"]
    assert "feeds.cwe" in answer["tables"] and "app_state.secrets" in answer["tables"]  # справочники и ключи тоже


def test_test_dsn_display_has_no_password():
    """Сообщение об отказе тестовой базы не печатает пароль ни в одной записи строки подключения (Д14)."""
    for dsn in ("host=127.0.0.1 port=5433 user=triage password=секрет", "password=секрет host=h user=u",
                "postgresql://u:секрет@h:5433/db"):
        assert "секрет" not in dsn_display(dsn)
    assert dsn_display("host=h port=1 user=u dbname=d password=x") == "host=h port=1 user=u dbname=d"


# ============================================================================ запуск app.serve


def test_watch_stdin_stops_server_on_eof():
    from app.serve import watch_stdin
    server = SimpleNamespace(should_exit=False)
    watch_stdin(server, io.BytesIO(b"lines\n"))
    assert server.should_exit is True

    class Broken:
        def read(self, size):
            raise OSError("канал закрыт")

    server = SimpleNamespace(should_exit=False)
    watch_stdin(server, Broken())
    assert server.should_exit is True


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def serve_env(tmp_path: Path, extra: dict[str, str]) -> dict[str, str]:
    """Окружение процесса приложения: без унаследованных PG*, TRIAGE_*, LLM_* – как у обёртки стенда."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PG", "TRIAGE_", "LLM_"))}
    env.update(DATA_DIR=str(tmp_path / "data"), TMP_DIR=str(tmp_path / "tmp"), REPOS_ROOT=str(tmp_path / "repos"),
               OLLAMA_URL="http://127.0.0.1:9", OSV_URL="off", TRIAGE_STAND="npm", TRIAGE_STAND_TOKEN=TOKEN, **extra)
    return env


def serve_command(port: int) -> list[str]:
    return [sys.executable, "-E", "-s", "-X", "utf8", "-m", "app.serve", "--host", "127.0.0.1", "--port", str(port)]


def test_serve_exits_75_when_data_folder_is_busy(tmp_path: Path):
    """Замок папки данных со свежей отметкой (прежний процесс только что убит): отдельный код выхода – обёртка повторит
    запуск, когда отметка устареет."""
    from test_lockfile import foreign_lock
    foreign_lock(tmp_path / "data" / "telemetry")
    (tmp_path / "repos").mkdir()
    proc = subprocess.run(serve_command(free_port()), cwd=ROOT, env=serve_env(tmp_path, {}), stdin=subprocess.PIPE,
                          capture_output=True, timeout=120)
    assert proc.returncode == 75, proc.stderr.decode("utf-8", "replace")[-3000:]


def test_serve_exits_76_when_port_is_taken(tmp_path: Path):
    """Порт слушает другая программа: приложение запускается, порт не перехватывается, код 76 – держатель возьмёт
    следующий; замок папки данных отпущен."""
    (tmp_path / "repos").mkdir()
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        port = int(taken.getsockname()[1])
        env = serve_env(tmp_path, libpq_env(tmp_path / "busy-port" / "triage.db"))
        proc = subprocess.run(serve_command(port), cwd=ROOT, env=env, stdin=subprocess.PIPE, capture_output=True,
                              timeout=120)
    assert proc.returncode == 76, proc.stderr.decode("utf-8", "replace")[-3000:]
    assert not (tmp_path / "data" / "telemetry" / "instance.lock").exists()


def test_serve_stops_gracefully_when_stdin_closes(tmp_path: Path):
    """Держатель закрывает stdin – сервер останавливается штатно: код 0, замок папки данных отпущен."""
    (tmp_path / "repos").mkdir()
    port = free_port()
    log_path = tmp_path / "serve.log"
    env = serve_env(tmp_path, libpq_env(tmp_path / "serve" / "triage.db"))
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(serve_command(port), cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=log_file,
                                stderr=subprocess.STDOUT)
        try:
            deadline, body = time.monotonic() + 90, None
            while time.monotonic() < deadline and proc.poll() is None:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as answer:
                        body = json.loads(answer.read().decode("utf-8"))
                        break
                except OSError:
                    time.sleep(0.3)
            assert body is not None, log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            assert body["stand"]["token"] == TOKEN and body["status"] == "ok"
            assert proc.stdin is not None
            proc.stdin.close()
            code = proc.wait(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
    assert code == 0, log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
    assert not (tmp_path / "data" / "telemetry" / "instance.lock").exists()
