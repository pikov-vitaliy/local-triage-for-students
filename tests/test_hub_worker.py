"""Исполнитель записи в Hub (deploy/hub-worker/hub_worker.py, ADR-0114): настройки, белый список (тот же, что в
приложении), вход по паролю в теле запроса, задания на поддельном Hub и поддельном приложении, отказ без запроса к
Hub, повтор только доставки результата, усечение результата, журнал без секретов, выход из Hub. Сеть – только
127.0.0.1; адреса и учётные данные выдуманы."""

from __future__ import annotations

import getpass
import importlib.util
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app import hub_ops

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hub_worker", ROOT / "deploy" / "hub-worker" / "hub_worker.py")
hw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hw)

KEY = "a" * 64
PASSWORD = "Пароль-секрет-123"
SESSION = "SESSION-COOKIE-VALUE-42"
PRINCIPAL = {"name": "user1", "firstName": "Иван", "lastName": "Тестов", "roles": ["DEVELOPER"]}
SECRET_BODY = "тело-ответа-не-для-журнала"


class Server:
    """HTTP-сервер в потоке на 127.0.0.1 со своим обработчиком."""

    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.owner = self
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeHub(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, status, body=b"{}", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return f"JSESSIONID={SESSION}" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        hub = self.server.owner
        hub.calls.append(("GET", self.path, None))
        if self.path == "/hub/rest/auth/user":
            return self._reply(200, json.dumps(PRINCIPAL).encode()) if self._authed() else self._reply(401)
        if not self._authed():
            return self._reply(401)
        if self.path.startswith("/hub/rest/defects/blank"):
            return self._reply(200, json.dumps({"summary": "s", "description": SECRET_BODY}, ensure_ascii=False).encode())
        return self._reply(404)

    def do_POST(self):
        hub = self.server.owner
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        hub.calls.append(("POST", self.path, body))
        if self.path == "/hub/rest/auth/login":
            form = dict(urllib.parse.parse_qsl(body))
            if form == {"username": "user1", "password": PASSWORD}:
                return self._reply(200, b"", {"Set-Cookie": f"JSESSIONID={SESSION}; Path=/hub"})
            return self._reply(401)
        if self.path == "/hub/rest/auth/logout":
            return self._reply(200)
        if not self._authed() or hub.expire_session:
            hub.expire_session = False
            return self._reply(401)
        if self.path == "/hub/rest/issue/status/update":
            return self._reply(200, json.dumps({"id": 5, "status": "False Positive"}).encode())
        if self.path == "/hub/rest/issue/status/change":  # запрос принят, ответа нет: соединение закрыто
            self.close_connection = True
            self.connection.close()
            return None
        if self.path == "/hub/rest/defects":  # ответ короче заявленного Content-Length
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b'{"id": 1')
            self.close_connection = True
            return None
        if self.path == "/hub/rest/defects/1/link":  # перенаправление на чужой адрес – не выполняется
            return self._reply(302, b"", {"Location": "http://127.0.0.1:9/steal"})
        return self._reply(404)

    def do_PUT(self):
        """`PUT /defects/{id}` (ADR-0125): как интерфейс Hub – 204 без тела."""
        hub = self.server.owner
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        hub.calls.append(("PUT", self.path, body))
        if not self._authed():
            return self._reply(401)
        if self.path == "/hub/rest/defects/9001":
            self.send_response(204)
            self.end_headers()
            return None
        return self._reply(404)


class FakeApp(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        app = self.server.owner
        app.headers.append(dict(self.headers))
        if self.path.startswith("/api/hub/jobs"):
            job = app.jobs.pop(0) if app.jobs else None
            return self._reply(200, {"ok": True, "job": job})
        return self._reply(404, {})

    def do_POST(self):
        app = self.server.owner
        app.headers.append(dict(self.headers))
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8"))
        if self.path == "/api/hub/worker/hello":
            app.hello.append(data)
            return self._reply(200, {"ok": True})
        if self.path.startswith("/api/hub/jobs/"):
            if app.fail_results > 0:
                app.fail_results -= 1
                if app.truncate_errors:  # тело ошибки оборвано: Content-Length больше присланного
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b'{"detail"')
                    self.close_connection = True
                    return None
                return self._reply(503, {"detail": "занято"})
            app.results.append((int(self.path.split("/")[4]), data))
            return self._reply(200, {"ok": True, "outcome": "accepted"})
        return self._reply(404, {})


@pytest.fixture
def servers(monkeypatch):
    monkeypatch.setattr(hw, "HUB_SCHEMES", ("http", "https"))  # поддельный Hub – без TLS
    hub, app = Server(FakeHub), Server(FakeApp)
    hub.calls, hub.expire_session = [], False
    app.jobs, app.hello, app.results, app.headers, app.fail_results = [], [], [], [], 0
    app.truncate_errors = False
    yield hub, app
    hub.close()
    app.close()


def conf_for(hub, app) -> dict:
    return {"app_url": app.url, "hub_url": hub.url, "login": "user1", "key": KEY, "worker_id": "test-1"}


def job(hub, op_id, method, path, body=None) -> dict:
    return {"op_id": op_id, "attempt_id": op_id * 10, "lease_token": f"t{op_id}", "hub_url": hub.url,
            "method": method, "path": path, "body": body, "purpose": "status"}


# ============================================================================ настройки и белый список


def test_whitelist_is_the_same_as_the_app():
    assert hw.ALLOWED == hub_ops.ALLOWED
    assert hw.METHODS == hub_ops.METHODS


def test_worker_version_knows_defect_update():
    """Исполнитель 0.9.23.dev4 выполняет `PUT /defects/{id}` (ADR-0125): новая версия и проверка задания."""
    assert hw.VERSION == "0.10.0.dev10"
    hw.check_job({"hub_url": "https://hub.example.org", "method": "PUT", "path": "/defects/9001",
                  "body": {"id": 9001, "summary": "s"}}, "https://hub.example.org")


@pytest.mark.parametrize("change,needle", [
    ({"key": hw.PLACEHOLDER_KEY}, "нет ключа"),
    ({"key": "abc"}, "неверного вида"),
    ({"login": ""}, "логина"),
    ({"hub_url": "http://hub.example.org"}, "hub_url"),
    ({"hub_url": "https://hub.example.org/hub"}, "hub_url"),
    ({"app_url": "http://127.0.0.1:8765/settings"}, "app_url"),
    ({"app_url": "ftp://x"}, "app_url"),
    ({"worker_id": "имя с пробелом"}, "worker_id"),
])
def test_conf_refusals(change, needle):
    good = {"app_url": "http://127.0.0.1:8765", "hub_url": "https://hub.example.org", "login": "u", "key": KEY}
    with pytest.raises(hw.Stop, match=needle):
        hw.check_conf({**good, **change})


def test_conf_good_and_read(tmp_path):
    path = tmp_path / "hub_worker.conf"
    path.write_text("﻿# комментарий\napp_url = http://127.0.0.1:8765/\nhub_url = \"https://hub.example.org\"\n"
                    f"login = user1\nkey = {KEY}\n", encoding="utf-8")
    conf = hw.check_conf(hw.read_conf(str(path)))
    assert conf["app_url"] == "http://127.0.0.1:8765" and conf["hub_url"] == "https://hub.example.org"
    assert conf["worker_id"] and conf["key"] == KEY
    with pytest.raises(hw.Stop, match="Нет файла"):
        hw.read_conf(str(tmp_path / "нет.conf"))


@pytest.mark.parametrize("method,path,body", [
    ("DELETE", "/defects/1", None),
    # PUT – только `PUT /defects/{id}` (ADR-0125): прочие PUT и отвязка – отказ
    ("PUT", "/defects/1/link", {"x": 1}),
    ("PUT", "/defects/1/unlink", {"x": 1}),
    ("PUT", "/issue/status/update", {"x": 1}),
    ("PUT", "/defects/1?appId=1", {"x": 1}),
    ("PATCH", "/defects/1", {"x": 1}),
    ("POST", "/auth/login", None),
    ("GET", "/defects/1/../2", None),
    ("GET", "/auth/user?x=1", None),
    ("GET", "/auth/user", {"x": 1}),
])
def test_check_job_refuses(method, path, body):
    with pytest.raises(hw.Refused):
        hw.check_job({"hub_url": "https://hub.example.org", "method": method, "path": path, "body": body},
                     "https://hub.example.org")


def test_check_job_refuses_other_hub():
    with pytest.raises(hw.Refused, match="другого адреса"):
        hw.check_job({"hub_url": "https://other.example.org", "method": "GET", "path": "/auth/user"},
                     "https://hub.example.org")


def test_hidden_input_refuses_echo(monkeypatch):
    def warn(prompt):
        import warnings
        warnings.warn("echo", getpass.GetPassWarning)
    monkeypatch.setattr(getpass, "getpass", warn)
    with pytest.raises(hw.Stop, match="нельзя скрыть"):
        hw.hidden_input("пароль: ")


# ============================================================================ работа на поддельных Hub и приложении


def test_put_defect_sends_body_as_is_and_returns_204(servers):
    """`PUT /defects/{id}` (ADR-0125): тело – как в задании (объект чтения с новыми summary и description), один
    запрос к Hub, ответ 204 без тела уходит приложению как есть; прочие PUT не выполняются."""
    hub, app = servers
    body = {"id": 9001, "appId": 1, "summary": "ID5 - новый (SAST)", "description": "<p>текст</p>",
            "updateTs": 1761600000000, "linkedIssues": [{"id": 12, "type": "SAST"}], "settings": None}
    app.jobs = [job(hub, 1, "PUT", "/defects/9001", body), job(hub, 2, "PUT", "/defects/9001/link", body)]
    rc = hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=lambda s: None, max_jobs=2)
    assert rc == 0
    puts = [c for c in hub.calls if c[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1] == "/hub/rest/defects/9001" and json.loads(puts[0][2]) == body
    results = dict(app.results)
    assert results[10]["status"] == 204 and results[10]["body_text"] == "" and not results[10]["not_sent"]
    assert results[20]["not_sent"] and "не входит в белый список" in results[20]["error"]


def test_work_runs_jobs_and_logs_out(servers, capsys):
    hub, app = servers
    status_body = {"issueId": 12, "issueType": "SAST", "status": "False Positive", "reason": "ложное",
                   "expiredAt": "2027-01-01T00:00:00Z"}
    app.jobs = [job(hub, 1, "GET", "/auth/user"),
                job(hub, 2, "POST", "/issue/status/update", status_body),
                job(hub, 3, "DELETE", "/defects/1"),
                job(hub, 4, "GET", "/defects/blank?appId=1&issueIds=12&type=SAST")]
    asked = []
    rc = hw.work(conf_for(hub, app), ask_password=lambda p: asked.append(p) or PASSWORD, sleep=lambda s: None,
                 max_jobs=4)
    assert rc == 0 and len(asked) == 1
    login = [c for c in hub.calls if c[1] == "/hub/rest/auth/login"]
    assert len(login) == 1 and dict(urllib.parse.parse_qsl(login[0][2]))["username"] == "user1"
    assert all("password" not in c[1] for c in hub.calls), "пароль не попадает в адрес"
    posts = [c for c in hub.calls if c[1] == "/hub/rest/issue/status/update"]
    assert len(posts) == 1 and json.loads(posts[0][2]) == status_body
    assert not any(c[0] == "DELETE" or "/defects/1" == c[1].removeprefix("/hub/rest") for c in hub.calls)
    assert hub.calls[-1][1] == "/hub/rest/auth/logout"
    hello = app.hello[0]
    assert hello["worker_id"] == "test-1" and hello["hub_login"] == "user1" and hello["roles"] == ["DEVELOPER"]
    assert all(h.get(hw.KEY_HEADER) == KEY for h in app.headers)
    assert all(h.get("Origin") == app.url for h in app.headers if "Content-Length" in h)
    results = dict(app.results)
    assert results[10]["status"] == 200 and json.loads(results[10]["body_text"])["name"] == "user1"
    assert results[20]["status"] == 200 and results[20]["lease_token"] == "t2" and not results[20]["not_sent"]
    assert results[30]["not_sent"] and results[30]["status"] == 0 and "отклонено" in results[30]["error"]
    assert results[40]["status"] == 200 and SECRET_BODY in results[40]["body_text"]
    out = capsys.readouterr().out
    for secret in (PASSWORD, SESSION, KEY, SECRET_BODY):
        assert secret not in out, secret
    assert "вошли в Hub как Иван Тестов (user1)" in out and "выход из Hub выполнен" in out


def test_delivery_retries_without_repeating_the_hub_request(servers):
    hub, app = servers
    app.fail_results = 2
    app.jobs = [job(hub, 7, "POST", "/issue/status/update", {"issueId": 1, "issueType": "SAST",
                                                              "status": "False Positive", "reason": "x"})]
    pauses = []
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=pauses.append, max_jobs=1)
    assert len([c for c in hub.calls if c[1] == "/hub/rest/issue/status/update"]) == 1
    assert [r[0] for r in app.results] == [70] and pauses[:2] == [2.0, 4.0]


def test_wrong_password_stops_after_three_tries(servers):
    hub, app = servers
    with pytest.raises(hw.Stop, match="Вход в Hub не удался"):
        hw.work(conf_for(hub, app), ask_password=lambda p: "неверный", sleep=lambda s: None, max_jobs=1)
    assert len([c for c in hub.calls if c[1] == "/hub/rest/auth/login"]) == 3 and not app.hello


def test_hub_unreachable_before_send_is_not_sent(servers):
    hub, app = servers
    closed = hw.Hub("http://127.0.0.1:1")  # порт закрыт: соединение отклонено до отправки
    application = hw.App(app.url, KEY, "test-1")
    outcome, status = hw.run_job(closed, application, job(hub, 9, "POST", "/issue/status/update", {"a": 1}) |
                                 {"hub_url": hub.url}, hub.url, sleep=lambda s: None)
    assert status == 0 and outcome == "accepted"
    assert app.results[-1][1]["not_sent"] is True


def test_result_payload_is_shrunk_to_limit():
    big = ("\"" * 10 + "я") * (hw.RESULT_MAX // 12)  # кавычки удваиваются при записи в JSON
    payload = hw.result_payload({"lease_token": "t"}, 200, {}, big.encode("utf-8")[:hw.RESULT_MAX], False, "", 5)
    assert payload["truncated"] and len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) <= hw.PAYLOAD_MAX
    small = hw.result_payload({"lease_token": "t"}, 200, {}, b"{}", False, "", 5)
    assert small["body_text"] == "{}" and not small["truncated"]


def test_app_payload_fits_the_app_limit():
    from app.routes import hub as hub_routes
    assert hw.PAYLOAD_MAX < hub_routes.RESULT_BODY_MAX and hw.RESULT_MAX == hub_ops.RESULT_MAX


def status_body(issue: int = 1) -> dict:
    return {"issueId": issue, "issueType": "SAST", "status": "False Positive", "reason": "x"}


def test_disconnect_after_send_is_sent_not_not_sent(servers):
    """Hub принял запрос и оборвал соединение без ответа: запрос мог выполниться – «отправлен», статус 0
    (у записи – «результат неизвестен»), а не «не отправлено»."""
    hub, app = servers
    app.jobs = [job(hub, 5, "POST", "/issue/status/change", {"issues": [{"issueId": 1, "issueType": "SAST"}],
                                                              "status": "False Positive", "reason": "x"})]
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=lambda s: None, max_jobs=1)
    sent = app.results[-1][1]
    assert sent["status"] == 0 and sent["not_sent"] is False and sent["error"]
    assert hub_ops.outcome_state("status", sent)[0] == "unknown"


def test_short_body_is_an_error(servers):
    hub, app = servers
    app.jobs = [job(hub, 6, "POST", "/defects", {"summary": "s"})]
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=lambda s: None, max_jobs=1)
    sent = app.results[-1][1]
    assert sent["status"] == 200 and "не полностью" in sent["error"] and not sent["not_sent"]
    assert hub_ops.outcome_state("defect_create", sent)[0] == "unknown"


def test_redirect_is_not_followed(servers):
    hub, app = servers
    app.jobs = [job(hub, 8, "POST", "/defects/1/link", {"issueIds": [1], "issueType": "SAST"})]
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=lambda s: None, max_jobs=1)
    sent = app.results[-1][1]
    assert sent["status"] == 302 and sent["headers"]["location"] == "http://127.0.0.1:9/steal"
    assert not any("steal" in c[1] for c in hub.calls)


def test_session_expired_requires_explicit_new_start(servers):
    hub, app = servers
    hub.expire_session = False
    app.jobs = [job(hub, 11, "POST", "/issue/status/update", status_body(1)),
                job(hub, 12, "POST", "/issue/status/update", status_body(2))]
    asked = []

    def ask(prompt):
        asked.append(prompt)
        if len(asked) == 1:
            hub.expire_session = True  # первое задание получит 401
        return PASSWORD

    with pytest.raises(hw.Stop, match="Сессия"):
        hw.work(conf_for(hub, app), ask_password=ask, sleep=lambda s: None, max_jobs=2)
    results = dict(app.results)
    assert results[110]["status"] == 401 and 120 not in results
    assert len(asked) == 1 and len(app.hello) == 1
    assert len([c for c in hub.calls if c[1] == "/hub/rest/issue/status/update"]) == 1


def test_no_keepalive_request_when_idle(servers, monkeypatch):
    hub, app = servers
    monkeypatch.setattr(hw.time, "monotonic", lambda: 10**9)
    app.jobs = [job(hub, 13, "GET", "/auth/user")]
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=lambda s: None, max_jobs=1)
    checks = [c for c in hub.calls if c[0] == "GET" and c[1] == "/hub/rest/auth/user"]
    assert len(checks) == 2, "только явный вход и задание; проверки по таймеру нет"


def test_not_sent_reason_by_type():
    import socket
    import ssl
    assert hw.not_sent_reason(socket.gaierror("x"))
    assert hw.not_sent_reason(ConnectionRefusedError())
    assert hw.not_sent_reason(ssl.SSLCertVerificationError("x"))
    assert not hw.not_sent_reason(ConnectionResetError("ConnectionRefused"))
    assert not hw.not_sent_reason(TimeoutError())
    assert not hw.not_sent_reason("gaierror в тексте")


def test_truncated_error_body_from_app_is_retried(servers):
    """Приложение ответило 503 с оборванным телом: исполнитель не падает, а повторяет доставку результата."""
    hub, app = servers
    app.fail_results, app.truncate_errors = 2, True
    app.jobs = [job(hub, 14, "POST", "/issue/status/update", status_body(3))]
    pauses = []
    hw.work(conf_for(hub, app), ask_password=lambda p: PASSWORD, sleep=pauses.append, max_jobs=1)
    assert [r[0] for r in app.results] == [140] and len(pauses) >= 2
    assert len([c for c in hub.calls if c[1] == "/hub/rest/issue/status/update"]) == 1
