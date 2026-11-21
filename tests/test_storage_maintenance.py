"""Пауза выдачи записи и режим обслуживания (ADR-0128, п. 6.6): что выдаётся исполнителю, что отвергается, что не меняется,
какие страницы открываются при приёмке после переноса."""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.storage.local_state import WORKER_SECRET
from db_support import conninfo_of, database_for_path
from keys_support import worker_key_of
from app.config import Settings
from app.db import Database
from app.hub_ops import WORKER_KEY_HEADER
from app.main import create_app
from app.storage.postgresql import MaintenanceMode
from test_db import load, sast, sca

HUB = "https://hub.example.org"
BASE = "http://127.0.0.1:8765"
READ = {"method": "GET", "path": "/auth/user"}
WRITE = {"method": "POST", "path": "/issue/status/change", "body": {"status": "x"}}


def enqueue(db: Database, purpose: str, request: dict, key: str) -> dict:
    return db.hub_enqueue(purpose=purpose, request=request, hub_url=HUB, app_id=7, targets=[{"hub_id": key}], key_extra=key)


def state_of(db: Database, op_id: int) -> str:
    return db._scalar("SELECT state FROM hub_ops WHERE id = ?", (op_id,))


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


# --- пауза выдачи записи

def test_paused_claim_gives_reads_and_keeps_writes(db: Database):
    write = enqueue(db, "status", WRITE, "w1")
    read = enqueue(db, "probe", READ, "r1")
    db.set_hub_write_paused(True)
    assert db.hub_write_paused()
    got = db.hub_claim("w", HUB, 60)
    assert got["op"]["id"] == read["id"], "чтение выдаётся и в паузе"
    assert db.hub_claim("w", HUB, 60) is None, "запись не выдаётся"
    assert state_of(db, write["id"]) == "queued"
    assert db._scalar("SELECT COUNT(*) FROM hub_attempts WHERE op_id = ?", (write["id"],)) == 0
    db.set_hub_write_paused(False)
    assert db.hub_claim("w", HUB, 60)["op"]["id"] == write["id"], "после снятия паузы задание выдаётся один раз"
    assert db.hub_claim("w", HUB, 60) is None


def test_expired_write_lease_is_not_changed_by_polling_in_pause(db: Database):
    write = enqueue(db, "status", WRITE, "w1")
    read = enqueue(db, "probe", READ, "r1")
    db.hub_claim("w", HUB, 60, now="2026-01-01T00:00:00+00:00")
    db.hub_claim("w", HUB, 60, now="2026-01-01T00:00:00+00:00")
    db.set_hub_write_paused(True)
    assert db.hub_expire_leases() == 1
    assert state_of(db, write["id"]) == "taken", "аренда записи в паузе не трогается"
    assert state_of(db, read["id"]) == "failed", "истёкшее чтение можно поставить снова"
    db.set_hub_write_paused(False)
    assert db.hub_expire_leases() == 1
    assert state_of(db, write["id"]) == "unknown", "после паузы – как обычно: результат неизвестен, повтора нет"


def test_race_of_pause_and_claim_gives_one_order(db: Database):
    """Захват записи либо завершён до паузы и виден как выданный, либо не выполнен."""
    for n in range(10):
        op = enqueue(db, "status", WRITE, f"w{n}")
        got: list = []
        started = threading.Barrier(2)

        def claim():
            started.wait()
            got.append(db.hub_claim("w", HUB, 60))

        thread = threading.Thread(target=claim)
        thread.start()
        started.wait()
        db.set_hub_write_paused(True)
        thread.join(10)
        if got[0] is None:
            assert state_of(db, op["id"]) == "queued"
        else:
            assert state_of(db, op["id"]) == "taken" and got[0]["op"]["id"] == op["id"]
        db.set_hub_write_paused(False)
        with db._tx() as c:
            c.execute("DELETE FROM hub_ops")


def test_pause_is_kept_across_restart(tmp_path: Path):
    path = tmp_path / "triage.db"
    first = Database(path)
    first.set_hub_write_paused(True)
    first.close()
    second = Database(path)
    try:
        assert second.hub_write_paused()
    finally:
        second.close()


# --- приложение

def settings_for(tmp_path: Path, maintenance: bool = False) -> Settings:
    return Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", maintenance=maintenance, hub_url=HUB)


@pytest.fixture
def prepared(tmp_path: Path) -> Path:
    """Установка с данными: проект, выгрузка, одна операция записи в очереди."""
    (tmp_path / "repos").mkdir()
    settings = settings_for(tmp_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        db = client.app.state.db
        pid = db.create_project("Проект")
        load(db, pid, [sast("A"), sca("B")])
        enqueue(db, "status", WRITE, "w1")
        # дефект с недоведёнными последствиями: показ вкладки вне обслуживания довёл бы их
        with db._tx() as c:
            c.execute("INSERT INTO hub_defects(project_id, kind, state, origin, hub_url, app_id, hub_defect_id, effects_done,"
                      " created_at, updated_at) VALUES (?, 'SAST', 'done', 'app', ?, 7, '555', 0, '2026-01-01', '2026-01-01')",
                      (pid, HUB))
            c.execute("UPDATE hub_defects SET draft_owner_id = id")
    return tmp_path


def table_counts(path: Path) -> dict:
    from db_support import connect_db
    with connect_db(path) as c:
        tables = [r[0] for r in c.execute("SELECT table_name FROM information_schema.tables"
                                          " WHERE table_schema = current_schema() ORDER BY 1").fetchall()]
        data = {t: c.execute(f"SELECT md5(COALESCE(string_agg(x::text, ',' ORDER BY x::text), '')) FROM {t} x").fetchone()[0]
                for t in tables}
        data["последовательности"] = [tuple(r) for r in c.execute(
            "SELECT sequencename, last_value FROM pg_sequences WHERE schemaname = current_schema() ORDER BY 1").fetchall()]
    return data


def worker_headers(tmp_path: Path) -> dict:
    return {"Origin": BASE, "Accept": "application/json",
            WORKER_KEY_HEADER: worker_key_of(conninfo_of(database_for_path(tmp_path / "data" / "triage.db")))}


def test_maintenance_serves_pages_and_writes_nothing(prepared: Path):
    settings = settings_for(prepared, maintenance=True)
    before = table_counts(settings.db_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        health = client.get("/healthz")
        assert health.status_code == 200 and health.json()["status"] == "maintenance"
        db = client.app.state.db
        pid = db._scalar("SELECT id FROM projects")
        row = db._one("SELECT id, hub_id FROM findings WHERE project_id = ? AND kind = 'SAST' ORDER BY id LIMIT 1", (pid,))
        sca = db._one("SELECT id FROM findings WHERE project_id = ? AND kind = 'SCA' ORDER BY id LIMIT 1", (pid,))
        pages = ["/", f"/projects/{pid}", f"/projects/{pid}/findings", f"/projects/{pid}/findings/{row['id']}",
                 f"/projects/{pid}/sca", f"/projects/{pid}/sca/findings/{sca['id']}", f"/projects/{pid}/components",
                 f"/projects/{pid}/defects", f"/projects/{pid}/defects/{db._scalar('SELECT id FROM hub_defects')}",
                 "/journal", "/settings"]
        for page in pages:
            answer = client.get(page, follow_redirects=True)
            assert answer.status_code == 200, (page, answer.text[:300])
        refused = client.post("/projects", data={"name": "новый"}, follow_redirects=False, headers={"Origin": BASE})
        assert refused.status_code == 503 and "режиме обслуживания" in refused.text, refused.text[:300]
        with pytest.raises(MaintenanceMode):
            db.create_project("нельзя")
    assert table_counts(settings.db_path) == before, "обслуживание не меняет базу"


def test_maintenance_refuses_every_form_before_it_runs(prepared: Path):
    """Запись идёт не только в основную базу: ни одна форма не выполняется, включая смену ключа исполнителя и загрузку справочника."""
    settings = settings_for(prepared, maintenance=True)
    with TestClient(create_app(settings), base_url=BASE) as client:
        key = client.app.state.db.secret(WORKER_SECRET)
        files = sorted(p.name for p in settings.data_dir.iterdir())
        routers = [router.original_router for router in client.app.routes if hasattr(router, "original_router")]
        forms = sorted({route.path for router in routers for route in router.routes
                        if "POST" in (getattr(route, "methods", None) or ()) and not route.path.startswith("/api/hub/")})
        assert "/settings/hub/key/rotate" in forms and len(forms) > 20
        for form in forms:
            url = re.sub(r"\{[^}]+\}", "1", form)
            answer = client.post(url, follow_redirects=False, headers={"Origin": BASE})
            assert answer.status_code == 503 and "режиме обслуживания" in answer.text, (form, answer.status_code)
        assert sorted(p.name for p in settings.data_dir.iterdir()) == files
        refused = client.post("/projects", follow_redirects=False, headers={"Origin": BASE})
        assert refused.headers.get("Content-Security-Policy") and refused.headers.get("Cache-Control") == "no-store", "защита снаружи"
        assert client.post("/projects", follow_redirects=False).status_code == 403, "запрос без Origin отклоняет защита"
        page = client.post("/projects", follow_redirects=False, headers={"Origin": BASE, "Accept": "text/html"})
        assert page.status_code == 503 and "режиме обслуживания" in page.text and page.headers["content-type"].startswith("text/html")
        assert client.app.state.db.secret(WORKER_SECRET) == key, "ключ в обслуживании не меняется"


def test_maintenance_gives_worker_nothing_and_refuses_results(prepared: Path):
    settings = settings_for(prepared, maintenance=True)
    before = table_counts(settings.db_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        headers = worker_headers(prepared)
        jobs = client.get("/api/hub/jobs", params={"worker_id": "w", "hub_url": HUB, "wait": "0"}, headers=headers)
        assert jobs.status_code == 200 and jobs.json() == {"ok": True, "job": None}
        result = client.post("/api/hub/jobs/1/result", content=json.dumps({"lease_token": "x", "worker_id": "w"}), headers=headers)
        assert result.status_code == 503, result.text
    assert table_counts(settings.db_path) == before


def test_poll_during_pause_and_restart_never_gets_a_write(prepared: Path):
    """Опрос продолжается через смену режима: пауза сохраняется в базе и переживает запуск."""
    settings = settings_for(prepared)
    with TestClient(create_app(settings), base_url=BASE) as client:
        client.app.state.db.set_hub_write_paused(True)
        assert client.get("/healthz").json()["status"] == "hub_write_paused"
    for maintenance in (True, False):
        with TestClient(create_app(settings_for(prepared, maintenance=maintenance)), base_url=BASE) as client:
            headers = worker_headers(prepared)
            for _ in range(3):
                jobs = client.get("/api/hub/jobs", params={"worker_id": "w", "hub_url": HUB, "wait": "0"}, headers=headers)
                assert jobs.json() == {"ok": True, "job": None}
                time.sleep(0.01)
            db = client.app.state.db
            assert db._scalar("SELECT COUNT(*) FROM hub_attempts") == 0
    with TestClient(create_app(settings), base_url=BASE) as client:
        client.app.state.db.set_hub_write_paused(False)
        headers = worker_headers(prepared)
        jobs = client.get("/api/hub/jobs", params={"worker_id": "w", "hub_url": HUB, "wait": "0"}, headers=headers)
        assert jobs.json()["job"]["purpose"] == "status"


def test_healthz_reports_lost_instance(prepared: Path):
    from db_support import _admin, database_for_path
    settings = settings_for(prepared)
    with TestClient(create_app(settings), base_url=BASE) as client:
        assert client.get("/healthz").json()["status"] == "ok"
        _admin().execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                         (database_for_path(settings.db_path),))
        answer = client.get("/healthz")
        assert answer.status_code == 503 and answer.json()["status"] == "instance_lost"


def test_pause_is_set_and_removed_on_settings_page(prepared: Path):
    with TestClient(create_app(settings_for(prepared)), base_url=BASE) as client:
        db = client.app.state.db
        assert 'id="hub-write-pause-form"' in client.get("/settings").text
        answer = client.post("/settings/hub/write-pause", data={"paused": "1"}, follow_redirects=False, headers={"Origin": BASE})
        assert answer.status_code == 303 and db.hub_write_paused()
        page = client.get("/settings").text
        assert 'id="hub-write-paused"' in page and 'name="paused" value="0"' in page
        client.post("/settings/hub/write-pause", data={"paused": "0"}, headers={"Origin": BASE})
        assert not db.hub_write_paused()


def test_unknown_write_needs_a_mark_to_remove_pause_on_page(prepared: Path):
    with TestClient(create_app(settings_for(prepared)), base_url=BASE) as client:
        db = client.app.state.db
        db.set_hub_write_paused(True)
        with db._tx() as c:
            c.execute("UPDATE hub_ops SET state = 'unknown'")
        assert db.hub_unknown_writes() and 'name="accept_unknown"' in client.get("/settings").text
        client.post("/settings/hub/write-pause", data={"paused": "0"}, headers={"Origin": BASE})
        assert db.hub_write_paused(), "без отметки пауза остаётся"
        client.post("/settings/hub/write-pause", data={"paused": "0", "accept_unknown": "1"}, headers={"Origin": BASE})
        assert not db.hub_write_paused()


def test_settings_page_shows_pause(prepared: Path):
    with TestClient(create_app(settings_for(prepared)), base_url=BASE) as client:
        client.app.state.db.set_hub_write_paused(True)
        assert 'id="hub-write-paused"' in client.get("/settings").text
        client.app.state.db.set_hub_write_paused(False)
        assert 'id="hub-write-paused"' not in client.get("/settings").text


def test_second_application_on_same_base_does_not_start(prepared: Path):
    other = Settings(data_dir=prepared / "other", repos_root=prepared / "repos")
    # та же база при другой папке данных – адрес базы один (как в Compose)
    with TestClient(create_app(settings_for(prepared)), base_url=BASE):
        from app.storage import postgresql
        conninfo = postgresql.conninfo_for(settings_for(prepared).db_path)
        real = postgresql.TARGET_RESOLVER
        postgresql.TARGET_RESOLVER = lambda path: conninfo
        try:
            with pytest.raises(RuntimeError, match="другой экземпляр"):
                with TestClient(create_app(other), base_url=BASE):
                    pass
        finally:
            postgresql.TARGET_RESOLVER = real
