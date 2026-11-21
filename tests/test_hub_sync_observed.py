"""Структуры ответов обхода Hub: сроки, область решения, сравнение без базы и локальный пересчёт."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_sync as sync, hub_sync_api as api, hub_sync_compare as compare
from app.db import dumps, loads
from app.models import Finding
from app.triage import order_findings
from test_hub_sync import FakeSyncHub, HUB, begin, finish, run, step, store  # noqa: F401
from test_hub_sync_dev2 import deliver_text, waiting_manual
from test_hub_status_routes import decide, project, run_worker, sast, send
from test_hub_defect_update import ready
from test_web import web  # noqa: F401

EXPIRY = "2099-04-15T00:00:00Z"
EXPIRY_MS = int(datetime(2099, 4, 15, 23, 59, 59, 999000, tzinfo=UTC).timestamp() * 1000)


def manual_record(**values):
    return {"changedBy": None, "conditionalCategory": None, "createTs": 1800000000000,
            "expiredAt": EXPIRY_MS, "id": 19, "issueId": 1, "issueType": "SAST",
            "oldStatus": "To verify", "reason": "Основание", "status": "False Positive",
            "branch": None, "isConditional": None, **values}


def observation(**manual_values):
    return {"brief": {"id": 1, "type": "SAST", "appId": 7},
            "detail": {"id": 1, "appId": 7, "status": "False Positive"},
            "manual": manual_record(**manual_values)}


def local_finding(store, decision=True):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    if decision:
        db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Основание", reviewed=True)
        with db._tx() as c:
            c.execute("UPDATE reviews SET desired_hub_expired_at=? WHERE project_id=?", (EXPIRY, pid))


def compare_one(store, hub):
    db, pid = store
    with db._tx() as c:
        return compare.compare_issue(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
                                     {"entity_key": "SAST:1"}, hub, api.ADAPTER)


@pytest.mark.parametrize("value,expected", [(EXPIRY_MS, False), (EXPIRY, False),
    ("2099-04-16T02:59:59.999+03:00", False), (0, True), (180000, True),
    ("2001-01-01T00:00:00Z", True), (True, True), (False, True), (10**100, True),
    ("invalid", True), ([], True), (None, False)])
def test_e2_expiry_epoch_milliseconds_and_iso(value, expected):
    assert api.expired(value) is expected


def test_e2_same_utc_day_is_not_a_field_difference(store):
    local_finding(store)
    base, local, diff = compare_one(store, observation())
    assert not base
    assert diff["groups"] == ["matched"] and diff["fields"] == [] and diff["base_pending"]
    assert local["review"]["desired_hub_expired_at"] == EXPIRY
    _, _, changed = compare_one(store, observation(expiredAt=EXPIRY_MS + 86400000))
    assert {"decision_diff", "unknown_base"} <= set(changed["groups"])
    assert [f["field"] for f in changed["fields"]] == ["expiredAt"]
    assert "incomplete" not in changed["groups"]


@pytest.mark.parametrize("extra", [{}, {"conditionalCategory": None, "branch": None, "isConditional": None}])
def test_e3_unconditional_manual_record_covers_issue(extra):
    hub = observation()
    for name in ("conditionalCategory", "branch", "isConditional"):
        hub["manual"].pop(name)
    hub["manual"].update(extra)
    assert api.evidence_problems(hub, "SAST:1", 7, api.ADAPTER) == []


@pytest.mark.parametrize("name,value", [("conditionalCategory", "demo"), ("branch", "main"),
                                         ("isConditional", True), ("isConditional", False)])
def test_e3_filled_scope_keeps_warning(name, value):
    notes = api.evidence_problems(observation(**{name: value}), "SAST:1", 7, api.ADAPTER)
    assert any("Применимость" in note for note in notes)


@pytest.mark.parametrize("status,expected", [("To verify", "matched"), ("Open", "unknown_base"),
                                           ("Fixed", "unknown_base")])
def test_e4_no_decision_default_only_matches_without_base(store, status, expected):
    local_finding(store, decision=False)
    _, local, diff = compare_one(store, {"detail": {"status": status}, "manual": None})
    assert diff["groups"] == [expected]
    assert compare.issue_local_values(local) == {}  # вердикт To verify не выдумывается
    assert "no_decision" not in diff["groups"] and "conflict" not in diff["groups"]


@pytest.mark.parametrize("changed", [False, True])
def test_e4_defect_without_base_compares_local_fields_and_preserves_unknown_origin(web, changed):
    pid, owner = ready(web, build=False)
    db = web.app.state.db
    remote = loads(owner["confirmed_object_json"], {})
    if changed:
        remote["summary"] = "Другой заголовок"
    db.hub_defect_update(owner["id"], confirmed_object_json="")
    before = db.hub_defect(owner["id"])
    with db._tx() as c:
        base, _, diff = compare.compare_defect(c, {"project_id": pid, "hub_url": owner["hub_url"], "app_id": owner["app_id"]},
                                              {"entity_key": owner["hub_defect_id"]}, {"detail": remote})
    assert not base
    # Без принятой базы и новой правки оператора отличие не становится исходящим намерением.
    assert diff["groups"] == (["unknown_base"] if changed else ["matched"]), diff
    assert [f["field"] for f in diff["fields"]] == (["summary"] if changed else [])
    assert db.hub_defect(owner["id"]) == before


def test_e5_operator_decision_is_local_status_without_sent_operation(store):
    local_finding(store)
    _, local, diff = compare_one(store, {"detail": {"status": "To verify"}, "manual": None})
    assert local["status_intent"] is None
    field = next(f for f in diff["fields"] if f["field"] == "status")
    assert field["L"] == {"present": True, "value": "False Positive"}
    assert field["H"] == {"present": True, "value": "To verify"}


@pytest.mark.parametrize("sent", [False, True])
def test_e5_current_intent_is_local_status_regardless_of_entered_mark(web, sent):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    if sent:
        run_worker(web)
    db = web.app.state.db
    assert bool(db.get_review(pid, "101")["entered_hub"]) is sent
    with db._tx() as c:
        _, local, diff = compare.compare_issue(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
            {"entity_key": "SAST:101"}, {"detail": {"status": "To verify"}, "manual": None}, api.ADAPTER)
    assert isinstance(local["status_intent"], dict)
    assert next(f for f in diff["fields"] if f["field"] == "status")["L"] == {"present": True, "value": "False Positive"}


def test_e6_fixed_absent_locally_is_informational_and_reading_complete(store):
    db, _ = store
    rid, hub = begin(store, api.ADAPTER), FakeSyncHub(1)
    step(db, hub)
    step(db, hub)
    step(db, hub, body={"id": 1, "appId": 7, "status": "Fixed"})
    deliver_text(db, "")
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert loads(item["diff_json"], {})["groups"] == ["fixed_external"]
    data = sync.passport(run(db, rid))
    assert data["details_complete"] and data["exceptions"] == 0
    assert not db._all("SELECT * FROM findings ORDER BY 1, 2")


def test_e8_reparse_manual_ms_and_null_scope_without_queue_or_new_observation(store, monkeypatch):
    db, pid = store
    local_finding(store)
    old = replace(api.ADAPTER, version="hub-sync/2-measured-2026-10-27", manual_empty=False, manual_scope=False)
    rid, hub = begin(store, old), FakeSyncHub(1)
    step(db, hub)
    step(db, hub)
    step(db, hub, body=observation()["detail"])
    step(db, hub, body=manual_record())
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    # dev15 (план п. 1.2): применимость ручной записи не установлена – пометка Hub, не неполное чтение; основание из
    # такой записи не берётся
    diff = loads(item["diff_json"], {})
    assert "incomplete" not in diff["groups"]
    assert "Применимость ручного решения к ветке или условию не установлена." in diff["hub_notes"], diff
    tables = ("hub_ops", "hub_attempts", "reviews", "hub_issue_states", "hub_entity_versions")
    before = {table: db._all("SELECT * FROM " + table + " ORDER BY 1, 2") for table in tables}
    def forbidden(*args, **kwargs):
        pytest.fail("Пересчёт поставил или выдал запрос")
    monkeypatch.setattr(sync, "plan", forbidden)
    monkeypatch.setattr(sync, "advance", forbidden)
    monkeypatch.setattr(db, "hub_claim", forbidden)
    monkeypatch.setattr(db, "_hub_insert", forbidden)
    compare.recompare(db, rid)
    after = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert loads(after["diff_json"], {})["groups"] == ["matched"]
    for field in ("hub_json", "source_ops_json", "observed_from", "observed_to"):
        assert after[field] == item[field]
    assert {table: db._all("SELECT * FROM " + table + " ORDER BY 1, 2") for table in tables} == before
    data = sync.passport(run(db, rid))
    assert data["bases_pending"] == 1 and not data["matches_snapshot"]


def test_e8_missing_raw_answer_stays_explicit_and_continue_reads_only_that_part(store):
    db, _ = store
    rid = waiting_manual(store)
    got = deliver_text(db, "")
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET result_json=? WHERE id=?", (dumps({"status": 200}), got["op"]["id"]))
    count = len(db._all("SELECT id FROM hub_ops"))
    compare.recompare(db, rid)
    data = sync.passport(run(db, rid))
    assert data["reparse_missing"] == 1 and data["exceptions"] == 1
    assert not data["details_complete"]
    assert len(db._all("SELECT id FROM hub_ops")) == count
    sync.continue_run(db, rid, run(db, rid)["revision"])
    new = deliver_text(db, "")
    assert "/issue/status?" in loads(new["op"]["request_json"], {})["path"]
    assert len(db._all("SELECT id FROM hub_ops")) == count + 1
    assert sync.passport(run(db, rid))["details_complete"]


def test_e4_normalized_equal_values_keep_original_raw_observation(store):
    local_finding(store)
    hub = observation()
    before = deepcopy(hub)
    _, _, diff = compare_one(store, hub)
    assert diff["base_pending"] and hub == before


def test_e8_missing_raw_counter_clears_when_other_exception_remains(store):
    db, _ = store
    rid = begin(store, api.ADAPTER)
    finish(db, FakeSyncHub(2), rid)
    manual_ops = [r for r in db._all("SELECT * FROM hub_ops ORDER BY id")
                  if "/issue/status?" in loads(r["request_json"], {})["path"]]
    missing, bad = manual_ops
    missing_path = loads(missing["request_json"], {})["path"]
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET result_json=? WHERE id=?", (dumps({"status": 200}), missing["id"]))
        c.execute("UPDATE hub_ops SET result_json=? WHERE id=?", (dumps({"status": 200, "body_text": "broken"}), bad["id"]))
    compare.recompare(db, rid)
    assert sync.passport(run(db, rid))["reparse_missing"] == 1
    sync.continue_run(db, rid, run(db, rid)["revision"])
    while run(db, rid)["state"] in sync.ACTIVE:
        path = loads(db._one("SELECT request_json FROM hub_ops WHERE state='queued'")["request_json"], {})["path"]
        deliver_text(db, "" if path == missing_path else "broken")
    data = sync.passport(run(db, rid))
    assert data["exceptions"] == 1 and data["reparse_missing"] == 0


def test_observed_shapes_full_read_finishes_without_false_exceptions(store):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id=str(i), kind="SAST") for i in range(1, 102)]))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Основание", reviewed=True)
    with db._tx() as c:
        c.execute("UPDATE reviews SET desired_hub_expired_at=? WHERE project_id=?", (EXPIRY, pid))
    hub = FakeSyncHub(105)
    for issue in hub.issues:
        issue["type"] = "SAST"
    rid = begin(store, api.ADAPTER)
    while run(db, rid)["state"] in sync.ACTIVE:
        request = loads(db._one("SELECT request_json FROM hub_ops WHERE state='queued'")["request_json"], {})
        path = urlsplit(request["path"])
        if path.path == "/issue/status":
            ident = int(parse_qs(path.query)["issueId"][0])
            deliver_text(db, dumps(manual_record()) if ident == 1 else " \n")
        elif path.path.startswith("/issue/sast/"):
            ident = int(path.path.rsplit("/", 1)[1])
            status = "False Positive" if ident == 1 else "Fixed" if ident > 101 else "To verify"
            step(db, hub, body={"id": ident, "appId": 7, "status": status})
        else:
            step(db, hub)
    data = sync.passport(run(db, rid))
    assert data["inventory_complete"] and data["details_complete"]
    assert data["exceptions"] == 0
    assert data["groups"] == {"matched": 101, "fixed_external": 4}
    assert data["bases_pending"] == 101 and not data["matches_snapshot"]
    assert data["saved_requests"] == 2 + 1 + 105 * 2
    assert all(loads(r["request_json"], {})["method"] == "GET" for r in db._all("SELECT request_json FROM hub_ops"))
