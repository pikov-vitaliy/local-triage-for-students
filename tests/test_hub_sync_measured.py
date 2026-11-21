"""Форма замера 27.10 с выдуманными значениями; проверки каждого живого обхода."""

import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_sync as sync, hub_sync_api as api
from app.db import loads
from test_hub_sync import FakeSyncHub, begin, finish, run, step, store, HUB  # noqa: F401


class MeasuredHub(FakeSyncHub):
    def __init__(self, cap=100):
        super().__init__()
        examples = json.loads(Path(__file__).with_name("hub_sync_contract_examples.json").read_text(encoding="utf-8"))
        self.issues = examples["issues"]["filteredEntities"]
        self.defects = examples["defects"]["filteredEntities"]
        self.cap = cap

    def answer(self, req):
        parts = urlsplit(req["path"])
        q = parse_qs(parts.query)
        if parts.path in ("/issue/v2", "/defects"):
            self.calls.append(req)
            assert "ignoreBranchFilter" not in q
            if parts.path == "/issue/v2":
                assert q["sort"] == ["0"] and q["appIds"] == ["7"]
            else:
                assert "sort" not in q and q["appId"] == ["7"]
            objects = self.issues if parts.path == "/issue/v2" else self.defects
            index, size = int(q["pageIndex"][0]), min(int(q["pageSize"][0]), self.cap)
            return {"filteredEntities": objects[index*size:(index+1)*size], "totalEntitiesCount": len(objects)}
        answer = super().answer(req)
        if parts.path.startswith("/issue/") and parts.path != "/issue/status" and "branch" in q:
            answer["currentBranch"] = q["branch"][0]
        return answer


def exceptions(db):
    return [exception for item in db._all("SELECT coverage_json FROM hub_sync_items")
            for exception in loads(item["coverage_json"], {}).get("exceptions", {}).values()]


def test_measured_adapter_starts_and_preserves_examples_and_null(store):
    db, pid = store
    rid = sync.start(db, pid, HUB, 7)
    hub = MeasuredHub()
    finish(db, hub, rid)
    data = sync.passport(run(db, rid))
    assert run(db, rid)["state"] == "ready"
    assert data["adapter"]["version"] == "hub-sync/3-observed-2026-10-30"
    assert data["inventory_complete"] and data["details_complete"]
    assert data["totals"] == {"issue": 3, "defect": 5}
    assert data["branches"] == ["main", "release"]
    assert not data["adapter"]["all_branches"] and data["adapter"]["manual_scope"]
    assert data["adapter"]["risk_absent"] is None
    for row in db._all("SELECT hub_json FROM hub_sync_items WHERE entity_kind='issue'"):
        assert loads(row["hub_json"], {})["manual"] is None
    assert len(hub.calls) == 13
    assert not exceptions(db)


@pytest.mark.parametrize("cap", [1, 2])
def test_server_cap_restarts_from_zero_without_losing_ids(store, cap):
    db, _ = store
    hub = MeasuredHub(cap)
    rid = begin(store, api.ADAPTER)
    finish(db, hub, rid)
    data = sync.passport(run(db, rid))
    assert run(db, rid)["state"] == "ready" and data["inventory_complete"]
    assert data["page_sizes"] == {"issue": cap, "defect": cap}
    assert len([p for p in data["page_checks"] if p["state"] == "restart"]) == 2
    assert {r["entity_key"] for r in db._all("SELECT entity_key FROM hub_sync_items WHERE entity_kind='issue'")} == {"SAST:1", "SCA_S:2", "SAST:3"}
    assert {r["entity_key"] for r in db._all("SELECT entity_key FROM hub_sync_items WHERE entity_kind='defect'")} == {"1", "2", "3", "4", "5"}
    for kind in ("issue", "defect"):
        checks = [p for p in data["page_checks"] if p["kind"] == kind]
        assert checks[0]["index"] == checks[1]["index"] == 0
        assert checks[0]["size"] == 100 and checks[1]["size"] == cap
        assert sum(p["received"] for p in checks if p["state"] == "checked") == data["totals"][kind]
    assert all(r["method"] == "GET" and r["body"] is None for r in hub.calls)


@pytest.mark.parametrize("change", ["total", "duplicate", "lost_id"])
def test_changing_list_cannot_be_complete(store, change):
    db, _ = store
    hub = MeasuredHub(2)
    rid = begin(store, api.ADAPTER)
    step(db, hub)  # урезание 100 до 2
    if change == "total":
        hub.issues.pop()
    elif change == "lost_id":
        hub.issues[0] = {**hub.issues[0], "id": 9}
    else:
        hub.issues[-1] = hub.issues[0]
    finish(db, hub, rid)
    data = sync.passport(run(db, rid))
    assert run(db, rid)["state"] == "failed"
    assert not data["inventory_complete"] and not data["matches_snapshot"]
    assert data["error"].startswith("Чтение неполное:")
    assert db.hub_claim("demo", HUB, 120, sync_protocol=api.SYNC_PROTOCOL) is None


@pytest.mark.parametrize("part,bad", [("manual", []), ("manual", "unexpected"), ("manual", {}),
                                      ("manual", {"issueId": 1, "issueType": "SAST"}), ("risk", None)])
def test_object_exception_continues_other_objects_and_preserves_reason(store, part, bad):
    db, _ = store
    hub = FakeSyncHub(2)
    rid = begin(store, api.ADAPTER)
    failed = None
    while run(db, rid)["state"] in sync.ACTIVE:
        queued = db._one("SELECT request_json FROM hub_ops WHERE state='queued'")
        req = loads(queued["request_json"], {})
        path = req["path"]
        if path == "/issue/sast/1" and part == "risk":
            step(db, hub, body={"id": 1, "appId": 7, "status": "Accepted risk"})
        elif ((part == "manual" and path == "/issue/status?issueId=1&issueType=SAST")
              or (part == "risk" and path == "/issue/SAST/1/riskAcceptance")):
            failed = step(db, hub, body=bad)
        else:
            step(db, hub)
    assert failed is not None
    got, result, _ = failed
    data = sync.passport(run(db, rid))
    assert run(db, rid)["state"] == "ready"
    assert data["inventory_complete"] and data["comparison_complete"]
    assert not data["details_complete"] and not data["matches_snapshot"]
    assert data["exceptions"] == 1 and exceptions(db)[0]["reason"]
    assert exceptions(db)[0]["op_id"] == got["op"]["id"]
    assert loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"] == json.dumps(bad)
    assert any(r["path"] == "/issue/sca/security/2" for r in hub.calls)
    assert db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)["outcome"] == "duplicate"


@pytest.mark.parametrize("offset", [2, 3])
def test_short_page_after_first_page_restarts_both_offset_interpretations(store, offset):
    db, _ = store
    hub = MeasuredHub()
    hub.issues = [{**hub.issues[0], "id": i} for i in range(1, 8)]
    rid = begin(store, replace(api.ADAPTER, issue_size=3))
    step(db, hub)
    # Смещение по урезанному либо запрошенному шагу: оба требуют нового обхода.
    step(db, hub, body={"filteredEntities": hub.issues[offset:offset+2], "totalEntitiesCount": 7})
    hub.cap = 2
    finish(db, hub, rid)
    data = sync.passport(run(db, rid))
    assert data["inventory_complete"] and data["page_sizes"]["issue"] == 2
    assert len(db._all("SELECT * FROM hub_sync_items WHERE entity_kind='issue'")) == 7
    assert sum(p["received"] for p in data["page_checks"] if p["kind"] == "issue" and p["state"] == "checked") == 7
    assert data["page_checks"][0]["state"] == "superseded"


def test_protocol_one_worker_cannot_take_new_contract(store):
    db, _ = store
    begin(store, api.ADAPTER)
    assert db.hub_claim("old", HUB, 120, sync_protocol=1) is None
    assert db.hub_claim("new", HUB, 120, sync_protocol=api.SYNC_PROTOCOL)
