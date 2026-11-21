"""ADR-0127 dev2a/dev2b: синтетический Hub, объём, остановка, восстановление и сравнение."""

import json
import time
from dataclasses import replace
from urllib.parse import parse_qs, quote, urlsplit
from pathlib import Path

import pytest

from app import hub_sync as sync, hub_sync_api as api, hub_sync_compare as compare
from app.db import Database, loads
from app.models import Finding
from app.triage import order_findings
from test_hub_queue import HUB, past

ADAPTER = api.Adapter(issue_sort=0, first_page=0, serialization="flat", all_branches=True,
                      manual_absent=(200, "null"), risk_absent=(200, "null"), manual_scope=True,
                      evidence="synthetic-fixture-v1")


class FakeSyncHub:
    def __init__(self, count=0, defects=0):
        types = tuple(api.DETAIL_PATHS)
        self.issues = [{"id": i+1, "appId": 7, "type": types[i % 4]} for i in range(count)]
        self.defects = [{"id": i+1, "app": {"id": 7, "name": "Демо"}} for i in range(defects)]
        self.calls = []

    def answer(self, req):
        self.calls.append(req)
        assert req["method"] == "GET" and req["body"] is None
        parts = urlsplit(req["path"])
        q = parse_qs(parts.query)
        if parts.path in ("/issue/v2", "/defects"):
            data = self.issues if parts.path == "/issue/v2" else self.defects
            page, size = int(q["pageIndex"][0]), int(q["pageSize"][0])
            return {"filteredEntities": data[page*size:(page+1)*size], "totalEntitiesCount": len(data)}
        if parts.path == "/issue/status":
            return None
        ident = int(parts.path.rsplit("/", 1)[-1])
        if parts.path.startswith("/defects/"):
            return {"id": ident, "appId": 7, "summary": "Демо", "description": "<p>Текст</p>", "linkedIssues": []}
        return {"id": ident, "appId": 7, "status": "Open"}


class VariedSyncHub(FakeSyncHub):
    """Объёмный набор с основаниями, рисками и ветками, без реальных данных."""
    def answer(self, req):
        path = urlsplit(req["path"])
        q = parse_qs(path.query)
        if path.path in ("/issue/v2", "/defects") or path.path.startswith("/defects/"):
            return super().answer(req)
        self.calls.append(req)
        if path.path == "/issue/status":
            ident = int(q["issueId"][0])
            typ = q["issueType"][0]
        elif path.path.endswith("/riskAcceptance"):
            ident = int(path.path.split("/")[-2])
            typ = path.path.split("/")[2]
            return {"appId":7,"issueId":ident,"issueType":typ,"comment":"Основание риска",
                    "isActive":True,"isConditional":False,"expiredAt":"2099-01-01T00:00:00Z"}
        else:
            ident = int(path.path.rsplit("/", 1)[-1])
        status = {1:"False Positive", 2:"Accepted risk"}.get(ident % 8, "Open")
        if path.path == "/issue/status":
            return ({"id":ident,"issueId":ident,"issueType":typ,"status":status,"reason":"Основание",
                     "expiredAt":"2099-01-01T00:00:00Z"} if status != "Open" else None)
        result = {"id":ident,"appId":7,"status":status}
        if ident % 8 == 3:
            result.update(currentBranch=q.get("branch", ["main"])[0],
                          issueBranchBriefData=[{"branch":"main"},{"branch":"ветка/объём"}])
        return result


@pytest.fixture
def store(tmp_path):
    db = Database(tmp_path / "triage.db")
    pid = db.create_project("Демо")
    db.update_project(pid, hub_app_id=7)
    yield db, pid
    db.close()


def begin(store, adapter=ADAPTER, app_confirmed=False):
    db, pid = store
    return sync.start(db, pid, HUB, 7, adapter=adapter, app_confirmed=app_confirmed)


def run(db, run_id):
    return db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (run_id,))


def step(db, hub, *, status=200, body=..., protocol=2):
    got = db.hub_claim("demo", HUB, 120, sync_protocol=protocol)
    assert got
    req = loads(got["op"]["request_json"], {})
    if body is ...:
        body = hub.answer(req)
    result = {"status": status, "body_text": json.dumps(body), "error": "", "truncated": False}
    outcome = db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    return got, result, outcome


def finish(db, hub, run_id):
    for _ in range(10000):
        if run(db, run_id)["state"] not in sync.ACTIVE:
            return
        step(db, hub)
    pytest.fail("Цепочка не закончилась")


def test_unknown_contract_never_guesses_sort_or_creates_operation(store):
    db, _ = store
    with pytest.raises(ValueError, match="Контракт"):
        begin(store, api.Adapter())
    assert not db._all("SELECT * FROM hub_ops ORDER BY 1, 2")


def test_volume_all_keys_and_exact_request_count_without_acceptance(store, record_property):
    db, pid = store
    hub = VariedSyncHub(1600, 53)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id="1", kind="SAST"), Finding(hub_id="1608", kind="SAST")]))
    before = db._all("SELECT * FROM findings ORDER BY id")
    start = time.monotonic()
    rid = begin(store)
    finish(db, hub, rid)
    data = sync.passport(run(db, rid))
    assert run(db, rid)["state"] == "ready", data
    assert len(hub.calls) == 16 + 1600*2 + 200 + 200 + 2 + 53 + 2
    assert len(db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2")) == 1654
    assert data["saved_requests"] == len(hub.calls)
    assert data["inventory_complete"] and data["details_complete"] and data["comparison_complete"]
    assert not data["matches_snapshot"]
    assert db._all("SELECT * FROM findings ORDER BY id") == before and not db._all("SELECT * FROM reviews ORDER BY 1, 2")
    assert not db._all("SELECT * FROM hub_defects ORDER BY 1, 2") and not db._all("SELECT * FROM hub_entity_versions ORDER BY 1, 2")
    record_property("seconds", time.monotonic()-start)
    record_property("database_bytes", db._scalar("SELECT pg_database_size(current_database())"))
    record_property("max_response_bytes", max(len(r["result_json"].encode()) for r in db._all("SELECT result_json FROM hub_ops")))


def test_stop_queued_and_continue_successful_steps_not_repeated(store):
    db, _ = store
    hub = FakeSyncHub(5)
    rid = begin(store)
    step(db, hub); step(db, hub); step(db, hub)
    sync.stop(db, rid)
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None
    saved = list(hub.calls)
    sync.continue_run(db, rid, run(db, rid)["revision"])
    finish(db, hub, rid)
    assert hub.calls[:len(saved)] == saved
    assert len(hub.calls) == 12


def test_stop_taken_response_saved_without_next_request(store):
    db, _ = store
    hub = FakeSyncHub(2)
    rid = begin(store)
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    sync.stop(db, rid)
    result = {"status": 200, "body_text": json.dumps(hub.answer(loads(got["op"]["request_json"], {})))}
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    assert len(db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2")) == 2
    assert run(db, rid)["state"] == "stopped"
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None
    with pytest.raises(ValueError, match="Списки"):
        sync.continue_run(db, rid, run(db, rid)["revision"])


def test_duplicate_delivery_and_restart_do_not_advance(store):
    db, _ = store
    hub = FakeSyncHub(2)
    rid = begin(store)
    step(db, hub); step(db, hub)
    got, result, _ = step(db, hub)
    count = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    assert db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)["outcome"] == "duplicate"
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count
    sync.recover(db)
    assert run(db, rid)["state"] == "interrupted"
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None
    sync.continue_run(db, rid, run(db, rid)["revision"])
    finish(db, hub, rid)
    assert len(hub.calls) == 6


def test_error_midway_saved_then_only_failed_repeated_by_confirmation(store):
    db, _ = store
    hub = FakeSyncHub(3)
    rid = begin(store)
    step(db, hub); step(db, hub); step(db, hub)
    got, _, _ = step(db, hub, status=503, body={"error": "synthetic"})
    failed_path = loads(got["op"]["request_json"], {})["path"]
    finish(db, hub, rid)
    assert run(db, rid)["state"] == "ready"
    assert sync.passport(run(db, rid))["exceptions"] == 1
    assert not sync.passport(run(db, rid))["details_complete"]
    saved = list(hub.calls)
    sync.continue_run(db, rid, run(db, rid)["revision"])
    finish(db, hub, rid)
    assert hub.calls[:len(saved)] == saved
    assert hub.calls[len(saved)] == api.request(failed_path)
    assert len(hub.calls) == 8
    assert sync.passport(run(db, rid))["details_complete"]
    assert sync.passport(run(db, rid))["exceptions"] == 0


@pytest.mark.parametrize("problem", ["total", "duplicate", "app", "short", "empty", "bad_json"])
def test_changed_hub_invalid_page_never_complete(store, problem):
    db, _ = store
    hub = FakeSyncHub(3)
    rid = begin(store, replace(ADAPTER, issue_size=2))
    step(db, hub)
    body = {"filteredEntities": [hub.issues[-1]], "totalEntitiesCount": 3}
    if problem == "total": body["totalEntitiesCount"] = 4
    if problem == "duplicate": body["filteredEntities"] = [hub.issues[0]]
    if problem == "app": body["filteredEntities"][0] = {**hub.issues[-1], "appId": 8}
    if problem == "short": body.update(filteredEntities=[], totalEntitiesCount=3)
    if problem == "empty": body["filteredEntities"] = []
    if problem == "bad_json": body = []
    step(db, hub, body=body)
    assert run(db, rid)["state"] == "failed"
    assert not sync.passport(run(db, rid))["inventory_complete"]
    assert len(db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2")) == 2


def test_old_worker_cannot_claim_sync_but_can_claim_other_job(store):
    db, _ = store
    begin(store)
    assert db.hub_claim("old", HUB, 120) is None
    db.hub_enqueue(purpose="probe", request={"method":"GET", "path":"/auth/user"}, hub_url=HUB, app_id=None)
    assert db.hub_claim("old", HUB, 120)["op"]["purpose"] == "probe"
    assert db.hub_claim("new", HUB, 120, sync_protocol=2)["op"]["purpose"] == "sync_read"


def test_empty_hub_two_reads_matches_and_second_start_requires_new_confirmation(store):
    db, _ = store
    rid = begin(store)
    with pytest.raises(ValueError, match="Список запусков изменился"):
        begin(store)
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == 1
    hub = FakeSyncHub()
    finish(db, hub, rid)
    assert len(hub.calls) == 2 and sync.passport(run(db, rid))["matches_snapshot"]


def test_expired_read_late_result_never_resumes(store):
    db, _ = store
    rid = begin(store)
    got = db.hub_claim("demo", HUB, 120, now=past(300), sync_protocol=2)
    db.hub_expire_leases()
    out = db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                        {"status": 200, "body_text": '{"filteredEntities":[],"totalEntitiesCount":0}'})
    assert out["outcome"] == "late"
    assert run(db, rid)["state"] == "failed"
    assert not db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2")


def test_b_l_h_and_missing_null():
    assert compare.three_way({"a": 1}, {"a": 1}, {"a": 2})[0]["kind"] == "changed"
    assert compare.three_way({"a": 1}, {"a": 2}, {"a": 1})[0]["kind"] == "pending"
    assert compare.three_way({"a": 1}, {"a": 2}, {"a": 3})[0]["kind"] == "conflict"
    assert compare.three_way({}, {}, {"a": None})[0]["H"] == {"present": True, "value": None}


def test_inconsistent_status_reason_and_expired_risk():
    hub = {"brief": {"issueChangeStatusInfoId": 5}, "detail": {"status": "False Positive"},
           "manual": {"id":6,"issueId":1,"issueType":"SAST","status":"Closed","reason":"closed"}}
    problems = api.evidence_problems(hub, "SAST:1", 7, ADAPTER)
    assert any("противоречат" in p for p in problems) and any("ID" in p for p in problems)
    hub = {"detail":{"status":"Accepted risk"}, "risk":{"appId":7,"issueId":1,"issueType":"SAST",
            "isActive":True,"isConditional":False,"expiredAt":"2000-01-01T00:00:00Z"}}
    assert api.evidence_problems(hub, "SAST:1", 7, ADAPTER)


def test_base_changed_before_first_comparison_stays_stale(store):
    db, pid = store
    rid = begin(store)
    hub = FakeSyncHub(1)
    step(db, hub); step(db, hub); step(db, hub)
    with db._tx() as c:
        c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch)"
                  " VALUES (?, ?,7,'issue','SAST:1',1)", (pid, HUB))
    finish(db, hub, rid)
    item = db._one("SELECT * FROM hub_sync_items")
    assert item["stale_reason"] and "stale" in loads(item["diff_json"], {})["groups"]
    compare.recompare(db, rid)
    assert db._one("SELECT * FROM hub_sync_items")["stale_reason"]
    assert not sync.passport(run(db, rid))["matches_snapshot"]


def test_known_missing_local_key_is_read_and_does_not_imply_deletion(store):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="45", kind="SAST")]))
    rid = begin(store, app_confirmed=True)  # общих находок с Hub нет – номер подтверждён (ADR-0140)
    hub = FakeSyncHub()
    finish(db, hub, rid)
    assert any(r["path"] == "/issue/sast/45" for r in hub.calls)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items")["diff_json"], {})
    assert "absent" in diff["groups"] and "incomplete" in diff["groups"]
    assert not sync.passport(run(db, rid))["matches_snapshot"]


@pytest.mark.parametrize("change", ["branch", "risk", "unknown", "collision", "truncated"])
def test_exceptional_objects_are_visible_and_block_false_match(store, change):
    db, pid = store
    hub = FakeSyncHub(1)
    if change == "unknown":
        hub.issues[0]["type"] = "NEW_KIND"
    if change == "collision":
        db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="DAST")]))
    # коллизия типа: общих находок с выгрузкой нет – номер подтверждён, как сделал бы оператор (dev13)
    rid = begin(store, app_confirmed=change == "collision")
    step(db, hub); step(db, hub)
    if change == "truncated":
        got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                      {"status":200,"body_text":json.dumps(hub.answer(loads(got["op"]["request_json"], {}))),"truncated":True})
        assert run(db, rid)["state"] == "ready"
        assert sync.passport(run(db, rid))["exceptions"] == 1
    elif change in ("branch", "risk"):
        body = {"id":1,"appId":7,"status":"Open"}
        if change == "branch":
            body.update(currentBranch="main", issueBranchBriefData=[{"branch":"ветка/новая", "status":"Closed"}])
        else:
            body["status"] = "Accepted risk"
        step(db, hub, body=body)
        while run(db, rid)["state"] in sync.ACTIVE:
            got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
            req = loads(got["op"]["request_json"], {})
            path = req["path"]
            if "riskAcceptance" in path:
                answer = {"appId":7,"issueId":1,"issueType":"SAST","isActive":False}
            elif "branch=" in path:
                answer = {"id":1,"appId":7,"status":"Closed","currentBranch":"ветка/новая"}
            else:
                answer = hub.answer(req)
            db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                          {"status":200,"body_text":json.dumps(answer)})
        items = db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2")
        incomplete = any("incomplete" in loads(i["diff_json"], {})["groups"] for i in items)
        # разные статусы разных веток допустимы; недействующий риск – пометка Hub, а не неполное чтение (dev15, план
        # п. 1.2): принимается статус без основания и срока риска
        assert not incomplete
        if change == "risk":
            notes = [n for i in items for n in loads(i["diff_json"], {}).get("hub_notes", [])]
            assert "Риск не подтверждён как действующий для этой находки." in notes, notes
    else:
        finish(db, hub, rid)
    assert not sync.passport(run(db, rid))["matches_snapshot"]


def test_queue_progress_and_transport_result_rollback_together(store, monkeypatch):
    db, _ = store
    rid = begin(store)
    hub = FakeSyncHub()
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    result = {"status":200,"body_text":json.dumps(hub.answer(loads(got["op"]["request_json"], {})))}
    original = sync.advance
    def fail(*args):
        raise RuntimeError("synthetic transition failure")
    monkeypatch.setattr(sync, "advance", fail)
    with pytest.raises(RuntimeError):
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    assert db.hub_op(got["op"]["id"])["state"] == "taken"
    assert sync.passport(run(db, rid))["saved_requests"] == 0
    assert db._one("SELECT received_at FROM hub_attempts")["received_at"] is None
    monkeypatch.setattr(sync, "advance", original)
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    finish(db, hub, rid)
    assert sync.passport(run(db, rid))["matches_snapshot"]


def test_sync_purpose_and_worker_allowlists_are_identical_and_read_only(store):
    from app import hub_ops, hub_sync_contract
    from test_hub_worker import hw
    assert hw.ALLOWED == hub_ops.ALLOWED
    source = Path(hub_sync_contract.__file__).read_text(encoding="utf-8")
    worker = Path(hw.__file__).read_text(encoding="utf-8")
    assert source.split("# BEGIN SYNC CONTRACT")[1].split("# END SYNC CONTRACT")[0] == worker.split("# BEGIN SYNC CONTRACT")[1].split("# END SYNC CONTRACT")[0]
    for method in ("POST", "PUT", "DELETE"):
        req = {"method":method,"path":"/defects/1","body":None,"sync_protocol":2}
        with pytest.raises(ValueError): hub_ops.check_operation("sync_read", req, 7)
        with pytest.raises(hw.Refused): hw.check_job({**req,"purpose":"sync_read","hub_url":HUB,"app_id":7}, HUB)
    for path in ("/issue/sast/1?branch="+quote("ветка/новая"),
                 "/issue/SAST/1/riskAcceptance", "/issue/sca/compliance/1", "/issue/dast/1",
                 "/issue/v2?appIds=7&pageIndex=0&pageSize=100&sort=0&ignoreBranchFilter=true"):
        req = {"method":"GET","path":path,"body":None,"sync_protocol":2}
        hub_ops.check_operation("sync_read", req, 7)
        hw.check_job({**req,"purpose":"sync_read","hub_url":HUB,"app_id":7}, HUB)
        with pytest.raises(ValueError): hub_ops.check_operation("read", req, 7)
    db, _ = store
    with pytest.raises(ValueError, match="цель"):
        db.hub_enqueue(purpose="sync_read",request=api.detail("defect","1"),hub_url=HUB,app_id=7)


def test_new_local_key_after_inventory_and_after_comparison_blocks_match(store):
    db, pid = store
    rid = begin(store)
    hub = FakeSyncHub()
    finish(db, hub, rid)
    assert compare.snapshot_current(db, run(db, rid))
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="9", kind="SAST")]))
    assert not compare.snapshot_current(db, run(db, rid))
    compare.recompare(db, rid)
    assert not sync.passport(run(db, rid))["matches_snapshot"]
    assert "stale" in loads(db._one("SELECT diff_json FROM hub_sync_items")["diff_json"], {})["groups"]
    assert len(hub.calls) == 2


def test_wrong_branch_response_is_preserved_as_failed_read(store):
    db, _ = store
    rid = begin(store)
    hub = FakeSyncHub(1)
    step(db, hub); step(db, hub)
    step(db, hub, body={"id":1,"appId":7,"status":"Open","currentBranch":"main",
                       "issueBranchBriefData":[{"branch":"other"}]})
    step(db, hub)  # ручная запись
    got, _, _ = step(db, hub, body={"id":1,"appId":7,"status":"Open","currentBranch":"main"})
    assert run(db, rid)["state"] == "ready"
    assert "другой ветке" in db._one("SELECT coverage_json FROM hub_sync_items")["coverage_json"]
    assert db.hub_op(got["op"]["id"])["result_json"]


def test_reopen_database_recovers_without_claiming_and_can_continue(store):
    db, _ = store
    rid = begin(store)
    hub = FakeSyncHub(2)
    step(db, hub); step(db, hub); step(db, hub)
    path = db.path
    db.close()
    reopened = Database(path)
    try:
        sync.recover(reopened)
        assert run(reopened, rid)["state"] == "interrupted"
        assert reopened.hub_claim("demo", HUB, 120, sync_protocol=2) is None
        sync.continue_run(reopened, rid, run(reopened, rid)["revision"])
        finish(reopened, hub, rid)
        assert run(reopened, rid)["state"] == "ready" and len(hub.calls) == 6
    finally:
        reopened.close()


@pytest.mark.parametrize("part", ["page", "detail"])
@pytest.mark.parametrize("over", [False, True])
def test_result_limit_is_checked_for_page_and_object(store, part, over):
    from app.hub_ops import RESULT_MAX
    db, _ = store
    rid = begin(store)
    hub = FakeSyncHub(1)
    if part == "detail":
        step(db, hub); step(db, hub)
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    body = hub.answer(loads(got["op"]["request_json"], {}))
    body["padding"] = ""
    base = len(json.dumps(body).encode())
    body["padding"] = "x" * (RESULT_MAX - base + (1 if over else -1))
    result = {"status":200,"body_text":json.dumps(body)}
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)
    saved = loads(db.hub_op(got["op"]["id"])["result_json"], {})
    assert saved["truncated"] is over
    assert (run(db, rid)["state"] == "failed") is (over and part == "page")
    if over and part == "detail":
        assert sync.passport(run(db, rid))["exceptions"] == 1
    if over:
        assert not sync.passport(run(db, rid))["matches_snapshot"]
        assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None


@pytest.mark.parametrize("case,expected", [
    ("pending_status", "pending"), ("conflict", "conflict"), ("no_decision", "no_decision"),
    ("reason", "decision_diff"), ("coincident", "coincident"), ("matched", "matched"),
])
def test_issue_comparison_groups_preserve_base_local_and_remote(store, case, expected):
    from copy import deepcopy
    from app.db import dumps, now_iso
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    opened = {"detail":{"id":1,"appId":7,"status":"Open"}, "manual":None}
    false_positive = {"detail":{"id":1,"appId":7,"status":"False Positive"},
                      "manual":{"issueId":1,"issueType":"SAST","status":"False Positive","reason":"Основание","expiredAt":None}}
    base = deepcopy(false_positive if case in ("matched", "reason") else opened)
    remote = deepcopy(false_positive if case in ("matched", "reason", "coincident") else opened)
    if case in ("conflict", "no_decision"):
        remote["detail"]["status"] = "Closed"
    if case == "reason":
        remote["manual"]["reason"] = "Другое основание"
    row = {"project_id":pid,"hub_url":HUB,"app_id":7}
    with db._tx() as c:
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,confirmed_json)"
                  " VALUES (?,?,7,'SAST','1',?)", (pid,HUB,dumps(base)))
        if case != "no_decision":
            c.execute("INSERT INTO reviews(project_id,hub_id,decision,final_verdict,final_comment,updated_at,decision_origin)"
                      " VALUES (?,'1','own','false_positive','Основание',?,'operator')", (pid,now_iso()))
        returned_base, local, diff = compare.compare_issue(c, row, {"entity_key":"SAST:1"}, remote, ADAPTER)
    assert expected in diff["groups"], diff
    assert returned_base == base and local["finding"]


def test_nonempty_accepted_snapshot_matches_until_local_decision_changes(store):
    from app.db import dumps, now_iso
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    first = begin(store)
    finish(db, FakeSyncHub(1), first)
    observed = db._one("SELECT hub_json FROM hub_sync_items WHERE run_id=?", (first,))["hub_json"]
    # Синтетическая ранее принятая база. В dev2b приложение этот слой не записывает.
    with db._tx() as c:
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,confirmed_json)"
                  " VALUES (?,?,7,'SAST','1',?)", (pid,HUB,observed))
        c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,accepted_hash)"
                  " VALUES (?,?,7,'issue','SAST:1',1,?)", (pid,HUB,sync.versions.digest(loads(observed, {}))))
    sync.close(db, first)
    second = begin(store)
    finish(db, FakeSyncHub(1), second)
    assert sync.passport(run(db, second))["matches_snapshot"]
    assert compare.snapshot_current(db, run(db, second))
    with db._tx() as c:
        c.execute("INSERT INTO reviews(project_id,hub_id,decision,final_verdict,final_comment,updated_at,decision_origin)"
                  " VALUES (?,'1','own','false_positive','Основание',?,'operator')", (pid,now_iso()))
    assert not compare.snapshot_current(db, run(db, second))
    count = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    compare.recompare(db, second)
    assert not sync.passport(run(db, second))["matches_snapshot"]
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count
    assert db._one("SELECT confirmed_json FROM hub_issue_states")["confirmed_json"] == dumps(loads(observed, {}))


def test_issue_evidence_finishes_before_defect_details(store):
    db, _ = store
    rid = begin(store)
    hub = FakeSyncHub(2, 1)
    finish(db, hub, rid)
    paths = [r["path"] for r in hub.calls]
    assert paths[-1] == "/defects/1"
    assert sum(p.startswith("/issue/status?") for p in paths) == 2
