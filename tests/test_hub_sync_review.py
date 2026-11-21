"""Регрессии проверки dev2a/dev2b: только синтетические записи и поддельный исполнитель."""

import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_effects, hub_sync as sync, hub_sync_compare as compare
from app.db import dumps, loads
from app.models import Finding
from app.triage import order_findings
from test_hub_defect_update import ready
from test_hub_status_routes import project, sast, sca, decide, send, run_worker, HUB
from test_hub_sync import store, ADAPTER, FakeSyncHub, begin, finish, run, step  # noqa: F401
from test_web import web  # noqa: F401


@pytest.mark.parametrize("bad", [{"id": None, "type": "SAST"}, {"id": 101, "type": []}, "invalid"])
def test_saved_defect_with_valid_and_invalid_links_cannot_match(web, bad):
    pid, owner = ready(web, build=False)
    db = web.app.state.db
    remote = loads(owner["confirmed_object_json"], {})
    assert remote["linkedIssues"]
    remote["linkedIssues"].append(bad)
    with db._tx() as c:
        _, _, diff = compare.compare_defect(c, {"project_id": pid, "hub_url": owner["hub_url"], "app_id": owner["app_id"]},
                                           {"entity_key": owner["hub_defect_id"]}, {"detail": remote})
    assert "incomplete" in diff["groups"] and "matched" not in diff["groups"]


def test_malformed_composition_is_exception_and_preserves_raw_answer(store):
    db, _ = store
    rid, hub = begin(store), FakeSyncHub(0, 1)
    step(db, hub); step(db, hub)
    body = {"id": 1, "appId": 7, "linkedIssues": [{"id": 1, "type": "SAST"}, {"id": None, "type": "SAST"}]}
    got, _, _ = step(db, hub, body=body)
    assert run(db, rid)["state"] == "ready"
    assert json.loads(loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"]) == body
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None


@pytest.mark.parametrize("part", ["manual", "risk"])
def test_undocumented_null_is_not_absence(store, part):
    db, _ = store
    adapter = replace(ADAPTER, **{part + "_absent": (404, "absent")})
    rid, hub = begin(store, adapter), FakeSyncHub(1)
    step(db, hub); step(db, hub)
    step(db, hub, body={"id": 1, "appId": 7, "status": "Accepted risk" if part == "risk" else "Open"})
    if part == "risk":
        step(db, hub)
    got, _, _ = step(db, hub, body=None)
    assert run(db, rid)["state"] == "ready"
    assert "null" in db._one("SELECT coverage_json FROM hub_sync_items")["coverage_json"]
    assert loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"] == "null"


def test_documented_null_accepts_json_whitespace(store):
    db, _ = store
    rid, hub = begin(store), FakeSyncHub(1)
    step(db, hub); step(db, hub); step(db, hub)
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], {"status": 200, "body_text": " \nnull\t"})
    assert run(db, rid)["state"] == "ready"


@pytest.mark.parametrize("kind", ["sast", "sca_fp", "sca_risk"])
def test_actual_sent_status_reason_and_expiry_match_fresh_hub(web, kind):
    pid = project(web, [(sast if kind == "sast" else sca)("101")])
    decide(web, pid, "101", verdict="true_positive" if kind == "sca_risk" else "false_positive",
           decision="risk_accepted" if kind == "sca_risk" else "disagree")
    response = send(web, pid, "101", kind="findings" if kind == "sast" else "sca/findings")
    assert response.status_code == 200, response.text
    job = run_worker(web)
    db, body = web.app.state.db, job["body"]
    review = db.get_review(pid, "101")
    assert review["entered_hub"] and review["desired_hub_expired_at"] is None
    if kind != "sast":
        assert body["reason"] != review["final_comment"]
    hub = {"detail": {"id": 101, "appId": 7, "status": body["status"]}, "manual": {**body, "id": 1}}
    if kind == "sca_risk":
        hub["risk"] = {"issueId": 101, "issueType": "SCA_S", "appId": 7, "comment": body["reason"],
                       "expiredAt": body["expiredAt"], "isActive": True, "isConditional": False}
    with db._tx() as c:
        _, local, diff = compare.compare_issue(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
                                              {"entity_key": body["issueType"] + ":101"}, hub, ADAPTER)
    assert "decision_diff" not in diff["groups"], diff
    assert local["status_intent"]["op_id"] == job["op_id"]
    assert db.get_review(pid, "101") == review


@pytest.mark.parametrize("changed", ["revision", "finding", "hub", "app", "target", "hash"])
def test_sent_representation_requires_current_scope_and_target(web, changed):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web)
    db, body = web.app.state.db, job["body"]
    if changed == "revision":
        decide(web, pid, "101", comment="Изменённое локальное основание")
    with db._tx() as c:
        if changed == "finding":
            c.execute("UPDATE findings SET data_json='{}' WHERE project_id=?", (pid,))
        elif changed in ("hub", "app"):
            c.execute("UPDATE hub_ops SET hub_url=?,app_id=? WHERE id=?",
                      (HUB + "/other" if changed == "hub" else HUB, 8 if changed == "app" else 7, job["op_id"]))
        elif changed in ("target", "hash"):
            targets = loads(db.hub_op(job["op_id"])["targets_json"], [])
            targets[0]["issue_id" if changed == "target" else "entered_hash"] = 102 if changed == "target" else "different"
            c.execute("UPDATE hub_ops SET targets_json=? WHERE id=?", (dumps(targets), job["op_id"]))
        _, local, diff = compare.compare_issue(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
                                              {"entity_key": "SAST:101"},
                                              {"detail": {"status": "False Positive"}, "manual": body}, ADAPTER)
    assert local["status_intent"] is None
    assert "decision_diff" in diff["groups"]


def test_confirmed_write_after_local_edit_invalidates_old_read_once(store):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    review = db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Первое", reviewed=True)
    rid, hub = begin(store), FakeSyncHub(1)
    step(db, hub); step(db, hub); step(db, hub)
    old = db.hub_claim("reader", HUB, 120, sync_protocol=2)
    op = db.hub_enqueue(purpose="status", project_id=pid, hub_url=HUB, app_id=7,
                        request={"method": "POST", "path": "/issue/status/update", "body": {
                            "issueId": 1, "issueType": "SAST", "status": "False Positive", "reason": "Первое"}},
                        targets=[{"hub_id": "1", "issue_id": 1, "issue_type": "SAST",
                                  "revision": review["revision"], "entered_hash": "synthetic"}])
    write = db.hub_claim("writer", HUB, 120)
    assert write["op"]["id"] == op["id"]
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Второе", reviewed=True)
    result = db.hub_result(write["attempt"]["id"], write["attempt"]["lease_token"], {"status": 200, "body_text": "{}"})
    hub_effects.after_result(db, result["op"])
    hub_effects.after_result(db, result["op"])
    assert db._one("SELECT accepted_epoch FROM hub_entity_versions")["accepted_epoch"] == 1
    assert not db.get_review(pid, "1")["entered_hub"]
    db.hub_result(old["attempt"]["id"], old["attempt"]["lease_token"], {"status": 200, "body_text": "null"})
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=?", (rid,))
    assert loads(item["diff_json"], {})["groups"] == ["stale"]


class BranchRiskHub(FakeSyncHub):
    def answer(self, request):
        path = urlsplit(request["path"])
        if path.path in ("/issue/v2", "/defects", "/issue/status"):
            return super().answer(request)
        self.calls.append(request)
        if path.path.endswith("/riskAcceptance"):
            return {"issueId": 1, "issueType": "SAST", "appId": 7, "comment": "Основание в ветке",
                    "isActive": True, "isConditional": False}
        branch = parse_qs(path.query).get("branch", ["main"])[0]
        return {"id": 1, "appId": 7, "status": "Accepted risk" if branch == "release" else "Open",
                "currentBranch": branch, "issueBranchBriefData": [{"branch": "main"}, {"branch": "release"}]}


def test_risk_only_in_additional_branch_is_read_before_completion(store):
    db, _ = store
    rid, hub = begin(store), BranchRiskHub(1)
    finish(db, hub, rid)
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    assert sum(r["path"].endswith("/riskAcceptance") for r in hub.calls) == 1
    assert loads(item["hub_json"], {})["risk"]["comment"] == "Основание в ветке"
    assert "incomplete" not in loads(item["diff_json"], {})["groups"]
    from app.hub_sync_compare import issue_values
    assert issue_values(loads(item["hub_json"], {})) == {"status": "Open"}  # риск другой ветки не становится решением
    assert run(db, rid)["state"] == "ready" and sync.passport(run(db, rid))["details_complete"]


@pytest.mark.parametrize("part", ["manual", "risk"])
@pytest.mark.parametrize("bad", [[{"reason": "Основание"}], "text", 1, True, []])
def test_bad_evidence_shape_is_saved_as_exception_without_retry(store, part, bad):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    db.save_review(pid, "1", decision="risk_accepted" if part == "risk" else "disagree",
                   final_verdict="false_positive", final_comment="Основание", reviewed=True)
    rid, hub = begin(store), FakeSyncHub(1)
    step(db, hub); step(db, hub)
    step(db, hub, body={"id": 1, "appId": 7, "status": "Accepted risk" if part == "risk" else "False Positive"})
    if part == "risk":
        step(db, hub)
    got, result, outcome = step(db, hub, body=bad)
    assert outcome["outcome"] == "accepted" and run(db, rid)["state"] == "ready"
    assert json.loads(loads(db.hub_op(got["op"]["id"])["result_json"], {})["body_text"]) == bad
    assert db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], result)["outcome"] == "duplicate"
    assert db.hub_claim("demo", HUB, 120, sync_protocol=2) is None


@pytest.mark.parametrize("part", ["manual", "risk"])
@pytest.mark.parametrize("bad", [[{"reason": "Основание"}], "text", 1, True])
def test_saved_bad_evidence_shape_can_be_compared(store, part, bad):
    db, pid = store
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    db.save_review(pid, "1", decision="risk_accepted" if part == "risk" else "disagree",
                   final_verdict="false_positive", final_comment="Основание", reviewed=True)
    with db._tx() as c:
        _, _, diff = compare.compare_issue(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
                                           {"entity_key": "SAST:1"}, {"detail": {"status": "Accepted risk" if part == "risk"
                                                                                else "False Positive"}, part: bad}, ADAPTER)
    assert "incomplete" in diff["groups"]
