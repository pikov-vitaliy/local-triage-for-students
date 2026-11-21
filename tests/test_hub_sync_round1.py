"""Восемь находок круга 1: повтор чтения, миграция и работа оператора."""

import re

import pytest

from app import hub_sync as sync, hub_sync_compare as compare
from app.db import loads
from test_hub_sync import ADAPTER, HUB, FakeSyncHub, VariedSyncHub, begin, finish, run, step, store  # noqa: F401
from test_hub_sync_routes import confirm
from test_hub_status_routes import decide, fid, project, sast, worker_headers
from test_web import ORIGIN, web  # noqa: F401


def test_a1_resume_failed_manual_preserves_successful_risk(store):
    db, _ = store
    hub = VariedSyncHub(2)
    rid = begin(store)
    failed = False
    while run(db, rid)["state"] in sync.ACTIVE:
        op = db._one("SELECT * FROM hub_ops WHERE state='queued'")
        path = loads(op["request_json"], {})["path"]
        if path.startswith("/issue/status?") and "issueId=2" in path and not failed:
            step(db, hub, status=503, body={})
            failed = True
        else:
            step(db, hub)
    assert failed and sync.passport(run(db, rid))["exceptions"] == 1
    remaining = db._all("SELECT request_key FROM hub_sync_requests WHERE state!='done'")
    assert [loads(s["request_key"], [])[2] for s in remaining] == ["manual"]
    before = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    sync.continue_run(db, rid, run(db, rid)["revision"])
    finish(db, hub, rid)
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == before + 1
    risks = [r for r in hub.calls if r["path"].endswith("/riskAcceptance")]
    assert len(risks) == 1
    assert sync.passport(run(db, rid))["exceptions"] == 0


def test_a3_issue_link_to_unlisted_defect_is_inconsistent(store):
    db, _ = store
    hub = FakeSyncHub(1)
    hub.issues[0]["defectId"] = 77
    rid = begin(store)
    finish(db, hub, rid)
    item = db._one("SELECT * FROM hub_sync_items WHERE entity_kind='issue'")
    diff = loads(item["diff_json"], {})
    assert {"composition", "incomplete"} <= set(diff["groups"])
    assert any("77" in note and "отсутствующий" in note for note in diff["notes"])
    assert not sync.passport(run(db, rid))["matches_snapshot"]
    compare.recompare(db, rid)
    assert db._one("SELECT diff_json FROM hub_sync_items")["diff_json"] == item["diff_json"]


def token(response):
    return re.search(r'name="confirmation" value="([^"]+)"', response.text)[1]


@pytest.mark.parametrize("destination", ["same", "hub", "app"])
def test_b2_completed_run_requires_explicit_new_read_bound_to_destination(web, monkeypatch, destination):
    pid = project(web, [])
    confirm(web, pid, monkeypatch)
    db = web.app.state.db
    first = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    finish(db, FakeSyncHub(), first)
    old = run(db, first)
    preview = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
    assert "Есть завершённый прогон" in preview.text and "Начать новое чтение" in preview.text
    assert "принятая база совпала" in preview.text
    count = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    if destination == "hub":
        db.set_settings({"hub_url": "https://another.example.org"})
    elif destination == "app":
        db.update_project(pid, hub_app_id=8)
    form = {"confirmation": token(preview), "confirm": "yes"}
    if destination != "same":
        assert web.client.post(f"/projects/{pid}/hub-sync/start", data=form, headers=ORIGIN).status_code == 409
        assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count
        preview = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
        form["confirmation"] = token(preview)
    response = web.client.post(f"/projects/{pid}/hub-sync/start", data=form, headers=ORIGIN)
    assert response.status_code == 200
    fresh = db._one("SELECT * FROM hub_defect_sync_runs WHERE closed_at IS NULL")
    assert fresh["id"] != first and fresh["state"] == "running"
    assert fresh["hub_url"] == ("https://another.example.org" if destination == "hub" else HUB)
    assert fresh["app_id"] == (8 if destination == "app" else 7)
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count + 1
    assert run(db, first)["closed_at"] and run(db, first)["run_json"] == old["run_json"]
    assert web.client.post(f"/projects/{pid}/hub-sync/start", data=form, headers=ORIGIN).status_code == 409
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count + 1
    busy = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
    assert 'id="hub-sync-confirm"' not in busy.text and "Чтение ещё идёт" in busy.text


def test_b3_old_worker_shows_update_instructions(web, monkeypatch):
    pid = project(web, [])
    headers = worker_headers(web)
    web.client.get("/api/hub/jobs", params={"worker_id": "old", "hub_url": HUB, "wait": 0, "sync_protocol": 1}, headers=headers)
    preview = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
    assert "протокол устарел: обновите исполнитель" in preview.text
    confirm(web, pid, monkeypatch)
    rid = web.app.state.db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    state = web.client.get(f"/projects/{pid}/hub-sync/{rid}/state").json()
    assert "обновите исполнитель" in state["text"]["hub-sync-worker"]
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert 'href="/settings#hub-worker-instructions"' in page and "замените" in page
    assert 'id="hub-worker-instructions"' in web.client.get("/settings").text


def test_b4_issue_fields_are_readable_and_card_is_linked(web, monkeypatch):
    pid = project(web, [sast("1")])
    decide(web, pid, "1", comment="Локальное основание")
    confirm(web, pid, monkeypatch)
    db = web.app.state.db
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    finish(db, VariedSyncHub(1), rid)
    html = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert f'href="/projects/{pid}/findings/{fid(web, pid, "1")}"' in html
    assert "Сравнение полей" in html and "Основание" in html and "Срок" in html
    assert "Локальное основание" in html and "2099-01-01" in html
    assert "состояние Hub становится принятой базой" in html
    assert "Исходные данные и операции" in html and 'id="hub-sync-apply"' in html
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")
    fields = loads(db._one("SELECT diff_json FROM hub_sync_items")["diff_json"], {})["fields"]
    # При неизвестной базе совпавший статус не считается расхождением поля.
    assert {f["field"] for f in fields} == {"reason", "expiredAt"}


def test_b4_defect_card_and_field_comparison(web, monkeypatch):
    from test_hub_defect_update import ready, hub_body
    pid, owner = ready(web, build=False)
    db = web.app.state.db
    confirm(web, pid, monkeypatch, app_confirmed=True)  # синтетический Hub без находок выгрузки – номер подтверждён (ADR-0140)
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    class DefectHub(FakeSyncHub):
        def answer(self, req):
            if req["path"] == "/defects/777":
                return {**hub_body(), "summary": "Заголовок из Hub", "priority": "High"}
            return super().answer(req)
    hub = DefectHub()
    hub.defects = [{"id": 777, "app": {"id": 7}}]
    finish(db, hub, rid)
    html = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert f'href="/projects/{pid}/defects/{owner["id"]}"' in html
    assert "Сравнение полей" in html and "Заголовок из Hub" in html and "Приоритет" in html
    assert "Неотправленные правки сохраняются отдельно" in html
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")


def test_b5_poll_updates_verification_and_branches_while_running(web, monkeypatch):
    pid = project(web, [])
    confirm(web, pid, monkeypatch)
    db = web.app.state.db
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    url = f"/projects/{pid}/hub-sync/{rid}/state"
    before = web.client.get(url).json()
    hub = FakeSyncHub(3)
    hub.issues[0]["branch"] = "release"
    step(db, hub)
    after = web.client.get(url).json()
    assert not after["done"]
    assert "страницы 1" in after["text"]["hub-sync-verification"]
    assert "release" in after["text"]["hub-sync-branches"]
    assert before["text"]["hub-sync-verification"] != after["text"]["hub-sync-verification"]
    step(db, hub)
    step(db, hub, status=503, body={})
    after = web.client.get(url).json()
    assert not after["done"] and "исключения ответов: 1" in after["text"]["hub-sync-verification"]
