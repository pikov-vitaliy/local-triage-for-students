"""Обход Hub: пустой ручной статус, локальный переразбор и размер страницы."""

import re
from dataclasses import replace
from urllib.parse import urlsplit

import pytest

from app import hub_sync as sync, hub_sync_api as api, hub_sync_compare as compare
from app.db import dumps, loads
from app.models import Finding
from app.routes.hub_sync_routes import progress
from app.triage import order_findings
from test_hub_sync import FakeSyncHub, HUB, begin, finish, run, step, store  # noqa: F401
from test_web import ORIGIN, web  # noqa: F401

OLD_ADAPTER = replace(api.ADAPTER, version="hub-sync/2-measured-2026-10-27", manual_empty=False, manual_scope=False,
                      evidence="Замер исполнителем, форма ответов")


def deliver_text(db, body_text, **flags):
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    assert got
    result = {"status": 200, "body_text": body_text, **flags}
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    return got


def waiting_manual(store, adapter=None):
    db, _ = store
    rid, hub = begin(store, adapter or api.ADAPTER), FakeSyncHub(1)
    step(db, hub)
    step(db, hub)
    step(db, hub)
    return rid


@pytest.mark.parametrize("text", ["", " \t\r\n ", "null", " \nnull\t"])
def test_empty_manual_is_absence(store, text):
    db, _ = store
    rid = waiting_manual(store)
    got = deliver_text(db, text)
    assert urlsplit(loads(got["op"]["request_json"], {})["path"]).path == "/issue/status"
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert loads(item["hub_json"], {})["manual"] is None
    assert not loads(item["coverage_json"], {}).get("exceptions")
    assert sync.passport(run(db, rid))["details_complete"]
    assert loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"] == text
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None


@pytest.mark.parametrize("text", ['{}', '[]', '""', '"null"', 'false', '0', 'broken', '{"status":"Open"}'])
def test_unexpected_manual_stays_exception(store, text):
    db, _ = store
    rid = waiting_manual(store)
    got = deliver_text(db, text)
    compare.recompare(db, rid)
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert "manual" not in loads(item["hub_json"], {})
    assert loads(item["coverage_json"], {})["exceptions"]["manual"]["op_id"] == got["op"]["id"]
    assert "incomplete" in loads(item["diff_json"], {})["groups"]
    assert not sync.passport(run(db, rid))["details_complete"]
    assert loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"] == text


@pytest.mark.parametrize("flags", [{"status": 204}, {"status": 404}, {"status": 503},
                                   {"truncated": True}, {"error": "Обрыв"}, {"not_sent": True}])
def test_empty_manual_requires_complete_200(store, flags):
    db, _ = store
    rid = waiting_manual(store, OLD_ADAPTER)
    deliver_text(db, "", **flags)
    compare.recompare(db, rid)
    assert progress(db, run(db, rid))["exceptions"] == 1
    assert not sync.passport(run(db, rid))["details_complete"]


@pytest.mark.parametrize("part", ["risk", "issue_detail", "defect_detail"])
@pytest.mark.parametrize("text", ["", " \t\n ", "null"])
def test_unmeasured_empty_risk_and_details_stay_exceptions(store, part, text):
    db, _ = store
    rid = begin(store, api.ADAPTER)
    hub = FakeSyncHub(0 if part == "defect_detail" else 1, 1 if part == "defect_detail" else 0)
    step(db, hub)
    step(db, hub)
    if part == "risk":
        step(db, hub, body={"id": 1, "appId": 7, "status": "Accepted risk"})
        step(db, hub)
    deliver_text(db, text)
    compare.recompare(db, rid)
    assert progress(db, run(db, rid))["exceptions"] == 1
    assert not sync.passport(run(db, rid))["details_complete"]


@pytest.mark.parametrize("stale", [False, True])
def test_recompare_saved_empty_without_requests_preserves_evidence(store, monkeypatch, stale):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    observed = {"brief": {"id": 1, "appId": 7, "type": "SAST"},
                "detail": {"id": 1, "appId": 7, "status": "Open"}, "manual": None}
    with db._tx() as c:
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,confirmed_json)"
                  " VALUES (?,?,7,'SAST','1',?)", (pid, HUB, dumps(observed)))
    rid = waiting_manual(store, OLD_ADAPTER)
    got = deliver_text(db, " \t\n")
    old = run(db, rid)
    old_data = sync.passport(old)
    old_data["adapter"].pop("manual_empty")  # точный паспорт dev1 без нового поля
    with db._tx() as c:
        c.execute("UPDATE hub_defect_sync_runs SET run_json=? WHERE id=?", (dumps(old_data), rid))
        if stale:
            c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch)"
                      " VALUES (?,?,7,'issue','SAST:1',1)", (pid, HUB))
    assert not old_data["details_complete"] and not old_data["matches_snapshot"]
    assert old_data["groups"]["incomplete"] == 1
    tables = ["hub_ops", "hub_attempts", "hub_issue_states", "hub_entity_versions", "reviews", "findings", "hub_defects"]
    before = {table: db._all("SELECT * FROM " + table + " ORDER BY 1, 2") for table in tables}
    requests = db._all("SELECT * FROM hub_sync_requests ORDER BY 1, 2")
    failed = next(r for r in requests if r["op_id"] == got["op"]["id"])
    def forbidden(*args, **kwargs):
        pytest.fail("Локальный пересчёт не должен планировать или выдавать чтения")
    monkeypatch.setattr(sync, "plan", forbidden)
    monkeypatch.setattr(sync, "advance", forbidden)
    monkeypatch.setattr(db, "_hub_insert", forbidden)
    monkeypatch.setattr(db, "hub_claim", forbidden)
    for _ in range(2):
        compare.recompare(db, rid)
        item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
        data = sync.passport(run(db, rid))
        assert data["adapter"]["version"] == "hub-sync/3-observed-2026-10-30"
        assert data["read_adapter"] == old_data["adapter"]
        assert data["saved_requests"] == old_data["saved_requests"]
        assert data["finished_at"] == old_data["finished_at"]
        assert data["details_complete"] and data["exceptions"] == 0
        assert data["matches_snapshot"] is (not stale)
        assert "incomplete" not in data["groups"]
        assert ("stale" in data["groups"]) is stale
        assert loads(item["hub_json"], {}) == observed
        source = loads(item["source_ops_json"], {})["manual"]
        assert source["op_id"] == got["op"]["id"] and source["to"] == failed["processed_at"]
        assert progress(db, run(db, rid))["counts"]["basis"] == 1
        expected_requests = [{**r, "state": "done"} if r["id"] == failed["id"] else r for r in requests]
        assert db._all("SELECT * FROM hub_sync_requests ORDER BY 1, 2") == expected_requests
        assert {table: db._all("SELECT * FROM " + table + " ORDER BY 1, 2") for table in tables} == before


def seed_large_run(db, pid, count=2000):
    rid = sync.start(db, pid, HUB, 7)
    finish(db, FakeSyncHub(), rid)
    raw = "сохранённый-текст\n" * 200
    with db._tx() as c:
        c.executemany("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json,diff_json) VALUES (?,'issue',?,?,?)",
                      [(rid, f"SAST:{i:04d}", dumps({"detail": {"id": i, "raw": raw}}),
                        dumps({"groups": ["new", "incomplete"], "notes": [], "fields": []})) for i in range(1, count + 1)])
    return rid, raw


def test_2000_objects_page_is_bounded_collapsed_and_raw_is_deferred(web, record_property):
    db = web.app.state.db
    pid = db.create_project("Демо объёма")
    db.update_project(pid, hub_app_id=7)
    rid, raw = seed_large_run(db, pid)
    base = f"/projects/{pid}/hub-sync/{rid}"
    before = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    response = web.client.get(base)
    assert response.status_code == 200
    html = response.text
    record_property("initial_html_bytes", len(response.content))
    record_property("initial_html_lines", len(html.splitlines()))
    assert len(response.content) < 200_000
    assert len(html.splitlines()) < 2000
    groups = re.findall(r'<details[^>]*data-sync-group="[^"]+"[^>]*>', html)
    assert len(groups) == 1 and all(" open" not in tag for tag in groups)
    assert "(2000)" in html and "Показано 50 из 2000" in html
    assert html.count("<summary>Находка ") == 50
    assert "сохранённый-текст" not in html and "SAST:0051</summary>" not in html
    assert "Метки: Новые в Hub; Неполные или несогласованные сведения." in html
    seen = []
    for number in range(1, 41):
        page = web.client.get(base, params={"group": "incomplete", "page": number}).text
        seen.extend(re.findall(r'data-sync-item="([^"]+)"', page))
    assert len(seen) == len(set(seen)) == 2000
    for number, first, last in [(2, 51, 100), (40, 1951, 2000), (999, 1951, 2000)]:
        page = web.client.get(base, params={"group": "incomplete", "page": number}).text
        assert '<details class="panel" data-sync-group="incomplete" open>' in page
        assert f"SAST:{first:04d}</summary>" in page and f"SAST:{last:04d}</summary>" in page
        assert "сохранённый-текст" not in page
    result = web.client.get(base + "/raw", params={"kind": "issue", "key": "SAST:2000"})
    assert result.status_code == 200
    assert result.json()["H: отдельные ответы Hub"]["detail"]["raw"] == raw
    other = db.create_project("Другой демо-проект")
    assert web.client.get(f"/projects/{other}/hub-sync/{rid}/raw", params={"kind": "issue", "key": "SAST:2000"}).status_code == 404
    assert web.client.get(base + "/raw", params={"kind": "issue", "key": "missing"}).status_code == 404
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before


def test_recompare_route_updates_incomplete_and_raw_preserves_empty_response(web):
    db = web.app.state.db
    pid = db.create_project("Демо переразбора")
    db.update_project(pid, hub_app_id=7)
    rid = waiting_manual((db, pid), OLD_ADAPTER)
    deliver_text(db, "")
    base = f"/projects/{pid}/hub-sync/{rid}"
    assert 'id="hub-sync-incomplete"' in web.client.get(base).text
    before = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    html = web.client.post(base + "/recompare", headers=ORIGIN).text
    assert 'id="hub-sync-incomplete"' not in html
    assert 'data-sync-group="incomplete"' not in html
    assert "Основания и риски: 1 / 1" in html
    raw = web.client.get(base + "/raw", params={"kind": "issue", "key": "SAST:1"}).json()
    manual = [op for op in raw["Сохранённые операции"] if loads(op["request_key"], [])[2] == "manual"]
    assert len(manual) == 1 and loads(manual[0]["result_json"], {})["body_text"] == ""
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before


def test_recompare_then_continue_only_unrecoverable_requests(store):
    db, _ = store
    rid, hub = begin(store, OLD_ADAPTER), FakeSyncHub(3)
    step(db, hub)
    step(db, hub)
    step(db, hub)
    step(db, hub)
    step(db, hub)
    deliver_text(db, "")
    deliver_text(db, "")
    step(db, hub)
    # У второго ответа тело недоступно: отсутствие данных не равно пустому телу.
    failed = db._all("SELECT * FROM hub_sync_requests WHERE state='failed' ORDER BY id")
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET result_json=? WHERE id=?", (dumps({"status": 200}), failed[1]["op_id"]))
    compare.recompare(db, rid)
    assert progress(db, run(db, rid))["exceptions"] == 1
    assert progress(db, run(db, rid))["counts"]["basis"] == 2
    before = db._all("SELECT * FROM hub_ops ORDER BY id")
    sync.continue_run(db, rid, run(db, rid)["revision"])
    got = deliver_text(db, "")
    assert got["op"]["request_json"] == next(r for r in before if r["id"] == failed[1]["op_id"])["request_json"]
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == len(before) + 1
    assert sync.passport(run(db, rid))["details_complete"]
    assert progress(db, run(db, rid))["exceptions"] == 0


def test_recompare_does_not_restore_older_empty_over_newer_bad_response(store, monkeypatch):
    db, _ = store
    rid = waiting_manual(store, OLD_ADAPTER)
    deliver_text(db, "")
    # Продолжение было выполнено прежней версией, до исправления адаптера.
    with monkeypatch.context() as patch:
        patch.setattr(sync, "reparse_saved", lambda c, row: None)
        sync.continue_run(db, rid, run(db, rid)["revision"])
    newer = deliver_text(db, "broken")
    compare.recompare(db, rid)
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert "manual" not in loads(item["hub_json"], {})
    assert loads(item["coverage_json"], {})["exceptions"]["manual"]["op_id"] == newer["op"]["id"]
    assert progress(db, run(db, rid))["exceptions"] == 1
