"""Адреса записи в Hub (ADR-0114, app/routes/hub.py): ключ исполнителя и защита источника, приветствие, долгий опрос
очереди, результат с токеном аренды и предел размера, «Проверить связь» и её состояние, новый ключ, адрес Hub в
настройках и номер приложения в параметрах проекта. Исполнитель и Hub поддельные; адреса выдуманы."""

from __future__ import annotations

import json
import re

import pytest

from app import hub_ops
from app.routes import hub as hub_routes
from test_web import ORIGIN, create_project, web  # noqa: F401

HUB = "https://hub.example.org"
AS_JSON = {**ORIGIN, "Accept": "application/json"}
PRINCIPAL = {"name": "user1", "firstName": "Иван", "lastName": "Тестов", "roles": ["DEVELOPER", "MANAGER"]}


def key_of(web) -> str:
    return web.app.state.hub_worker_key


def worker_headers(web, key: str | None = None) -> dict:
    return {**ORIGIN, "Accept": "application/json", hub_ops.WORKER_KEY_HEADER: key or key_of(web)}


def set_hub(web, url: str = HUB) -> None:
    web.app.state.db.set_settings({"hub_url": url})


def jobs(web, wait: int = 0, key: str | None = None, hub_url: str = HUB, worker: str = "w1"):
    return web.client.get("/api/hub/jobs", params={"worker_id": worker, "hub_url": hub_url, "wait": wait},
                          headers=worker_headers(web, key))


def result(web, job: dict, payload: dict, key: str | None = None):
    return web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web, key),
                           content=json.dumps({"lease_token": job["lease_token"], "worker_id": "w1", **payload}))


def start_probe(web) -> dict:
    r = web.client.post("/settings/hub/probe", headers=AS_JSON)
    assert r.status_code == 200, r.text
    return r.json()


# ============================================================================ ключ и источник


def test_key_file_is_created_at_start(web):
    assert re.fullmatch(r"[0-9a-f]{64}", key_of(web))


@pytest.mark.parametrize("key", ["", "0" * 64, "not-a-key"])
def test_worker_addresses_refuse_without_valid_key(web, key):
    headers = {**ORIGIN, "Accept": "application/json", hub_ops.WORKER_KEY_HEADER: key}
    assert web.client.post("/api/hub/worker/hello", headers=headers, content="{}").status_code == 403
    assert web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB},
                          headers=headers).status_code == 403
    assert web.client.post("/api/hub/jobs/1/result", headers=headers, content="{}").status_code == 403


def test_worker_post_without_origin_is_refused_by_guard(web):
    headers = {"Accept": "application/json", hub_ops.WORKER_KEY_HEADER: key_of(web)}
    r = web.client.post("/api/hub/worker/hello", headers=headers, content=json.dumps({"worker_id": "w1"}))
    assert r.status_code == 403 and "не со страницы этого приложения" in r.text


def test_hello_records_worker_and_page_shows_it(web):
    set_hub(web)
    r = web.client.post("/api/hub/worker/hello", headers=worker_headers(web), content=json.dumps(
        {"worker_id": "vm-1", "hub_url": HUB + "/", "hub_user": "Иван Тестов", "hub_login": "user1",
         "roles": ["DEVELOPER"], "version": "1"}))
    assert r.status_code == 200 and r.json()["ok"] and r.json()["hub_url"] == HUB
    page = web.client.get("/settings").text
    assert "на связи" in page and "вошёл в Hub как Иван Тестов (user1)" in page and key_of(web) in page


@pytest.mark.parametrize("payload", [{"worker_id": "bad id"}, {"worker_id": ""}, {}])
def test_hello_refuses_bad_worker_id(web, payload):
    r = web.client.post("/api/hub/worker/hello", headers=worker_headers(web), content=json.dumps(payload))
    assert r.status_code == 400


def test_hello_refuses_non_json(web):
    r = web.client.post("/api/hub/worker/hello", headers=worker_headers(web), content="не json")
    assert r.status_code == 400


# ============================================================================ очередь и результат


def test_jobs_needs_worker_and_https_hub(web):
    for params in ({"worker_id": "w1"}, {"hub_url": HUB}, {"worker_id": "w1", "hub_url": "http://hub.example.org"}):
        r = web.client.get("/api/hub/jobs", params=params, headers=worker_headers(web))
        assert r.status_code == 400


def fake_clock(monkeypatch, on_pause=None) -> dict:
    """Часы опроса без настоящего ожидания: пауза двигает время (и может сделать что-то ещё)."""
    clock = {"t": 0.0, "pauses": 0}

    async def pause(seconds):
        clock["t"] += seconds
        clock["pauses"] += 1
        if on_pause:
            on_pause(clock)

    monkeypatch.setattr(hub_routes, "_monotonic", lambda: clock["t"])
    monkeypatch.setattr(hub_routes, "_pause", pause)
    return clock


def test_long_poll_returns_null_after_wait(web, monkeypatch):
    clock = fake_clock(monkeypatch)
    r = jobs(web, wait=3)
    assert r.status_code == 200 and r.json() == {"ok": True, "job": None} and clock["t"] >= 3
    assert web.app.state.hub_polls == 0, "счётчик опросов вернулся"


def test_long_poll_wait_is_capped(web, monkeypatch):
    clock = fake_clock(monkeypatch)
    assert jobs(web, wait=9999).json()["job"] is None and clock["t"] == hub_ops.WAIT_MAX_S


def test_long_poll_picks_job_queued_while_waiting(web, monkeypatch):
    set_hub(web)

    def queue_on_second_pause(clock):
        if clock["pauses"] == 2:
            web.app.state.db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None)

    fake_clock(monkeypatch, queue_on_second_pause)
    job = jobs(web, wait=10).json()["job"]
    assert job is not None and job["path"] == "/auth/user"


def test_long_poll_stops_when_key_rotated(web, monkeypatch):
    """Ключ выпустили заново, пока шёл опрос: прежний ключ отзывается и в идущем опросе – задание не выдаётся."""
    set_hub(web)
    old = key_of(web)

    def rotate_and_queue(clock):
        if clock["pauses"] == 1:
            web.app.state.hub_worker_key = hub_ops.rotate_worker_key(web.app.state.db)
            web.app.state.db.hub_enqueue(purpose="probe", request=hub_ops.probe_request(), hub_url=HUB, app_id=None)

    fake_clock(monkeypatch, rotate_and_queue)
    r = jobs(web, wait=10, key=old)
    assert r.status_code == 403
    assert web.app.state.db.hub_ops_list(states=("queued",)), "задание осталось в очереди"


def test_long_poll_limit(web):
    web.app.state.hub_polls = hub_routes.POLLS_MAX
    try:
        assert jobs(web).status_code == 429
    finally:
        web.app.state.hub_polls = 0


def test_full_probe_cycle(web):
    set_hub(web)
    answer = start_probe(web)
    assert answer["ok"] and not answer["done"] and "Ждём исполнителя" in answer["text"]["hub-probe-status"]
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is False and state["worker_online"] is False
    job = jobs(web).json()["job"]
    assert job["method"] == "GET" and job["path"] == "/auth/user" and job["hub_url"] == HUB and job["body"] is None
    assert web.client.get(answer["status_url"]).json()["text"]["hub-probe-status"].startswith("Исполнитель выполняет")
    r = result(web, job, {"status": 200, "body_text": json.dumps(PRINCIPAL), "headers": {"Content-Type": "application/json"}})
    assert r.json() == {"ok": True, "outcome": "accepted", "state": "done"}
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and state["probe_ok"] and state["worker_online"]
    assert "вошли как Иван Тестов (user1), роли: DEVELOPER, MANAGER" in state["text"]["hub-probe-status"]
    page = web.client.get(f"/settings?probe={answer['op_id']}").text
    assert "вошли как Иван Тестов" in page and 'data-poll="/settings/hub/probe' not in page
    again = start_probe(web)
    assert again["op_id"] != answer["op_id"], "повторная проверка после успешной ставится снова"


def test_probe_while_open_shows_the_running_one(web):
    set_hub(web)
    first = start_probe(web)
    second = start_probe(web)
    assert second["op_id"] == first["op_id"] and "уже идёт" in second["message"]
    page = web.client.get(f"/settings?probe={first['op_id']}").text
    assert f'data-poll="/settings/hub/probe/{first["op_id"]}"' in page


def test_probe_hub_refusal_and_expired_lease(web):
    set_hub(web)
    answer = start_probe(web)
    job = jobs(web).json()["job"]
    result(web, job, {"status": 401, "body_text": "{}"})
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and not state["probe_ok"] and "войдите в исполнителе заново" in state["text"]["hub-probe-status"]


def test_probe_without_hub_url(web):
    r = web.client.post("/settings/hub/probe", headers=AS_JSON)
    assert r.status_code == 400 and "адрес Hub" in r.json()["detail"]
    r = web.client.post("/settings/hub/probe", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "ok=hub_no_url" in r.headers["location"]
    assert "Сначала укажите адрес Hub" in web.client.get(r.headers["location"]).text


def test_probe_without_script_redirects_to_state(web):
    set_hub(web)
    r = web.client.post("/settings/hub/probe", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and re.search(r"/settings\?probe=\d+#hub$", r.headers["location"])
    assert "Ждём исполнителя" in web.client.get(r.headers["location"]).text


def test_probe_state_unknown_id(web):
    assert web.client.get("/settings/hub/probe/999").status_code == 404


def test_result_wrong_token_and_duplicate(web):
    set_hub(web)
    start_probe(web)
    job = jobs(web).json()["job"]
    bad = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                          content=json.dumps({"lease_token": "0" * 32, "status": 200}))
    assert bad.status_code == 409 and bad.json()["outcome"] == "rejected"
    assert result(web, job, {"status": 200, "body_text": json.dumps(PRINCIPAL)}).json()["outcome"] == "accepted"
    assert result(web, job, {"status": 500}).json() == {"ok": True, "outcome": "duplicate", "state": "done"}


def test_result_over_limit_is_413(web):
    set_hub(web)
    start_probe(web)
    job = jobs(web).json()["job"]
    big = "x" * (hub_routes.RESULT_BODY_MAX + 10)
    r = result(web, job, {"status": 200, "body_text": big})
    assert r.status_code == 413 and "длиннее" in r.json()["detail"]


def test_jobs_only_for_own_hub(web):
    set_hub(web)
    start_probe(web)
    assert jobs(web, hub_url="https://other.example.org").json()["job"] is None
    assert jobs(web).json()["job"] is not None


# ============================================================================ ключ: новый


def test_rotate_key_invalidates_old(web):
    old = key_of(web)
    r = web.client.post("/settings/hub/key/rotate", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "ok=hub_key_rotated" in r.headers["location"]
    new = key_of(web)
    assert new != old
    assert jobs(web, key=old, hub_url=HUB).status_code == 403
    assert jobs(web, key=new).status_code == 200
    assert "Выпущен новый ключ исполнителя" in web.client.get(r.headers["location"]).text


# ============================================================================ настройки и проект


def test_settings_page_has_hub_section(web):
    page = web.client.get("/settings").text
    assert 'id="hub"' in page and 'name="hub_url"' in page and 'form="settings-form"' in page
    assert "ещё не обращался" in page and 'id="hub-probe-button" disabled' in page


def test_project_hub_app_id(web):
    pid = create_project(web.client)
    db = web.app.state.db
    page = web.client.get(f"/projects/{pid}").text
    assert 'name="hub_app_id"' in page
    r = web.client.post(f"/projects/{pid}/params", data={"name": "Demo", "model": "", "hub_app_id": " 4242 "},
                        headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and db.get_project(pid)["hub_app_id"] == 4242
    assert 'value="4242"' in web.client.get(f"/projects/{pid}").text
    r = web.client.post(f"/projects/{pid}/params", data={"name": "Demo", "model": ""}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 303 and db.get_project(pid)["hub_app_id"] == 4242, "поля нет в форме – не меняется"
    for bad in ("abc", "-1", "0", "1.5", "١٢"):
        r = web.client.post(f"/projects/{pid}/params", data={"name": "Demo", "model": "", "hub_app_id": bad},
                            headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 400 and "Приложение в Hub" in r.text, bad
    r = web.client.post(f"/projects/{pid}/params", data={"name": "Demo", "model": "", "hub_app_id": ""},
                        headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and db.get_project(pid)["hub_app_id"] is None


def test_probe_state_closes_expired_lease_without_worker(web):
    """Исполнитель взял проверку и остановился: при чтении состояния истёкшая аренда закрывается – проверка «не
    удалась», новая ставится, а не показывается зависшая."""
    set_hub(web)
    answer = start_probe(web)
    db = web.app.state.db
    from test_hub_queue import past
    assert db.hub_claim("w1", HUB, 120, now=past(300)) is not None
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and not state["probe_ok"] and "не удалась" in state["text"]["hub-probe-status"]
    assert start_probe(web)["op_id"] != answer["op_id"]


def test_corrupted_key_does_not_stop_the_app(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app
    from test_web import BASE
    data = tmp_path / "data"
    data.mkdir()
    from app.db import Database
    from app.storage.local_state import WORKER_SECRET
    db = Database(data / "triage.db")
    db.put_secret(WORKER_SECRET, "испорчен")
    db.close()
    settings = Settings(data_dir=data, repos_root=tmp_path, ollama_url="http://127.0.0.1:9", osv_url="")
    with TestClient(create_app(settings), base_url=BASE) as client:
        page = client.get("/settings").text
        assert "повреждён" in page and 'id="hub-key"' not in page
        r = client.post("/api/hub/worker/hello", headers={**ORIGIN, hub_ops.WORKER_KEY_HEADER: "0" * 64},
                        content="{}")
        assert r.status_code == 503 and "Выпустите ключ заново" in r.json()["detail"]
        assert client.post("/settings/hub/key/rotate", headers=ORIGIN, follow_redirects=False).status_code == 303
        assert 'id="hub-key"' in client.get("/settings").text


@pytest.mark.parametrize("read_back", [True, False])
def test_unknown_outcome_of_key_rotation_does_not_keep_old_key(web, monkeypatch, read_back):
    """Ответ на COMMIT замены ключа потерян: действует то, что в базе; прочитать нельзя – прежний ключ не показывается как действующий."""
    from app.storage.postgresql import CommitUnknown
    old = key_of(web)
    db = web.app.state.db
    real_put = db.put_secret

    def lost(name, value):
        real_put(name, value)
        raise CommitUnknown("ответ потерян")

    monkeypatch.setattr(db, "put_secret", lost)
    if not read_back:
        def down(*_args):
            raise OSError("база не отвечает")

        monkeypatch.setattr(hub_ops, "load_or_create_worker_key", down)
    web.client.post("/settings/hub/key/rotate", headers=ORIGIN, follow_redirects=False)
    state = web.app.state
    if read_back:
        assert state.hub_worker_key != old and state.hub_worker_key == db.secret("hub_worker_key")
    else:
        assert state.hub_worker_key == "" and "Исход замены ключа неизвестен" in state.hub_worker_key_error

