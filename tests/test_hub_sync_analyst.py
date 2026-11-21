from db_support import record_queries
"""A1–A12: наблюдаемые формы Hub с выдуманными значениями и независимыми ожиданиями."""

from copy import deepcopy
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app import defect_fields, hub_defects, hub_sync as sync, hub_sync_compare as compare
from app.db import dumps, loads, finding_data_sig, text_hash
from app.models import Finding
from app.triage import order_findings
from test_hub_sync import FakeSyncHub, HUB, begin, finish, run, step, store  # noqa: F401
from test_hub_sync_observed import EXPIRY, compare_one, local_finding, observation
from test_hub_defect_update import hub_body, ready, to_put
from test_hub_worker import hw
from test_web import web  # noqa: F401


def defect_store(store, links=((1, "SAST"),)):
    db, pid = store
    local_finding(store, decision=False)
    body = {"id": 77, "appId": 7, "summary": "ID1 - Демо", "priority": {}, "severity": {},
            "description": "<p>Текст команды</p><p>Информация об объекте сканирования:</p><p>строка 10</p>",
            "linkedIssues": [{"id": i, "type": t} for i, t in links],
            "settings": {"isInheritedARStatusFromDefect": True, "isInheritedFPStatusFromDefect": True}}
    with db._tx() as c:
        ident = c.execute("INSERT INTO hub_defects(project_id,kind,state,hub_url,app_id,hub_defect_id,"
                          "summary,draft_summary,command_text,draft_command_text,confirmed_object_json,"
                          "draft_fields_json,targets_json,created_at,updated_at) VALUES (?,'SAST','done',?,7,'77',"
                          "?,?,'Текст команды','Текст команды',?,?,?,'','')" " RETURNING id",
                          (pid, HUB, body["summary"], body["summary"], dumps(body), dumps(defect_fields.fields_of(body)),
                           dumps([{"hub_id": str(i), "issue_id": i, "issue_type": t} for i, t in links]))).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id=id WHERE id=?", (ident,))
    return db.hub_defect(ident), body


def defect_compare(store, body):
    db, pid = store
    with db._tx() as c:
        return compare.compare_defect(c, {"project_id": pid, "hub_url": HUB, "app_id": 7},
                                      {"entity_key": "77"}, {"detail": body})[2]


def accept_issue(store, body):
    db, pid = store
    with db._tx() as c:
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,confirmed_json)"
                  " VALUES (?,?,7,'SAST','1',?)", (pid, HUB, dumps(body)))


def test_a1_observed_full_object_prepares_and_passes_worker(web):
    pid, row = ready(web)
    body = hub_body(createTs=1800000000000, updateTs=1800000000100)
    body["linkedIssues"][0].update(lastScanTs=1800000000000, severity=2,
                                   scanObject={"id": 21, "name": "demo", "type": "CODE", "url": None})
    saved = deepcopy(body)
    put = to_put(web, pid, row, first=body)
    assert put["body"]["createTs"] == body["createTs"]
    assert put["body"]["linkedIssues"] == body["linkedIssues"]
    hw.validate_defect(put["body"], 777, 7)
    assert body == saved
    # в PUT – только текст дефекта, блок Hub не переносится
    assert "Информация об объекте сканирования" in put["body"]["description"], "dev30: блок Hub сохраняется"


@pytest.mark.parametrize("reverse,conflict", [("absent", False), (77, False), (None, True), (78, True)])
def test_a2_reverse_link_requires_present_evidence(store, reverse, conflict):
    db, pid = store
    _, body = defect_store(store)
    rid = begin(store)
    finish(db, FakeSyncHub(), rid)
    brief = {"id": 1, "appId": 7, "type": "SAST"}
    if reverse != "absent":
        brief["defectId"] = reverse
    with db._tx() as c:
        for kind, key, hub in [("issue", "SAST:1", {"brief": brief, "detail": {"status": "To verify"}, "manual": None}),
                               ("defect", "77", {"brief": {"id": 77}, "detail": body})]:
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,?,?,?)"
                      " ON CONFLICT(run_id,entity_kind,entity_key) DO UPDATE SET hub_json=excluded.hub_json,coverage_json='{}',stale_reason=''",
                      (rid, kind, key, dumps(hub)))
        compare.compare_in(c, sync.run_in(c, rid))
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_kind='defect'", (rid,))
    diff = loads(item["diff_json"], {})
    assert ("incomplete" in diff["groups"]) is conflict, diff


@pytest.mark.parametrize("phase,incomplete", [("refused", False), ("read_failed", False), ("unknown", True), ("unconfirmed", True)])
def test_a3_terminal_preparation_is_not_active(store, phase, incomplete):
    db, _ = store
    owner, body = defect_store(store)
    db.hub_defect_update(owner["id"], update_json=dumps({"phase": phase}), draft_command_text="Локальная правка")
    diff = defect_compare(store, body)
    assert ("incomplete" in diff["groups"]) is incomplete
    assert "pending" in diff["groups"]


def test_a4_local_composition_diff_survives_accepted_remote_base(store):
    db, _ = store
    owner, body = defect_store(store, ((1, "SAST"), (2, "SAST")))
    body["linkedIssues"].pop()
    db.hub_defect_update(owner["id"], confirmed_object_json=dumps(body))
    diff = defect_compare(store, body)
    assert "composition" in diff["groups"]
    assert diff["composition"]["local_only"] == [(2, "SAST")]
    assert "SAST:2" in " ".join(diff["notes"])


def test_a4_base_composition_and_unmapped_pairs_are_visible(store):
    db, _ = store
    owner, body = defect_store(store, ((1, "SAST"), (2, "SAST")))
    body["linkedIssues"].pop(0)
    db.hub_defect_update(owner["id"], targets_json=dumps([{"hub_id": "2", "issue_id": 2, "issue_type": "SAST"}]))
    diff = defect_compare(store, body)
    assert set(diff["groups"]) == {"composition", "unmapped"}
    assert "Относительно принятой базы: добавлены нет; отсутствуют SAST:1." in diff["notes"]
    assert "Состав Hub не сопоставлен с выгрузкой: SAST:2." in diff["notes"]
    db.hub_defect_update(owner["id"], confirmed_object_json=dumps(body))
    diff = defect_compare(store, body)
    # dev15 (план п. 1.3, 1.5): состав принят как есть – несопоставленная связь видна пометкой Hub, а не остатком
    # синхронизации; сама пара по-прежнему записана в сравнении
    assert diff["groups"] == ["matched"] and diff["composition"]["unmapped"] == [(2, "SAST")]
    assert "Состав Hub не сопоставлен с выгрузкой: SAST:2." in diff["hub_notes"]


@pytest.mark.parametrize("changed", [False, True])
def test_a5_hub_block_is_observed_readonly_with_html_equivalence(store, changed):
    _, body = defect_store(store)
    body["description"] = body["description"].replace("<p>", "<div>").replace("</p>", "</div>")
    if changed:
        body["description"] = body["description"].replace("строка 10", "строка 20")
    diff = defect_compare(store, body)
    assert diff["groups"] == (["changed"] if changed else ["matched"])
    if changed:
        field = next(f for f in diff["fields"] if f["field"] == "hub_block")
        assert field["readonly"] and field["B"]["value"] == "строка 10" and field["H"]["value"] == "строка 20"


def test_a6_confirmed_whitespace_does_not_become_pending(store):
    db, _ = store
    owner, body = defect_store(store)
    db.hub_defect_update(owner["id"], draft_command_text="Текст  \nкоманды")
    sent = {"summary": body["summary"], "description": body["description"].replace("Текст команды", "Текст  команды"),
            "command_text": "Текст  \nкоманды", "block": hub_defects.hub_block(body["description"])[0]}
    assert hub_defects.update_content_new(body, sent)
    assert defect_compare(store, body)["groups"] == ["matched"]


def test_a7_settings_paths_merge_independently_and_pairs_stay_atomic(store):
    db, _ = store
    owner, body = defect_store(store)
    fields = defect_fields.fields_of(body)
    fields["settings"]["isInheritedARStatusFromDefect"] = False
    db.hub_defect_update(owner["id"], draft_fields_json=dumps(fields))
    with db._tx() as c:
        from app import defect_drafts
        c.execute("UPDATE hub_defects SET draft_revision=draft_revision+1 WHERE id=?", (owner["id"],))
        defect_drafts.history(c, defect_drafts.owner_in(c, owner), "edit")
    body["settings"]["isInheritedFPStatusFromDefect"] = False
    diff = defect_compare(store, body)
    assert set(diff["groups"]) == {"changed", "pending"}
    assert {f["field"] for f in diff["fields"]} == {"settings/isInheritedARStatusFromDefect", "settings/isInheritedFPStatusFromDefect"}
    conflict = compare.three_way({"settings": {"x": True}}, {"settings": {"x": False}}, {"settings": {"x": None}})
    assert conflict[0]["kind"] == "conflict"
    grouped = compare.defect_comparison({"priority": {"name": "A"}, "priorityId": 1},
        {"priority": {"name": "B"}, "priorityId": 1}, {"priority": {"name": "A"}, "priorityId": 2})
    assert len(grouped) == 1 and grouped[0]["kind"] == "conflict"


def test_a8_later_does_not_reuse_final_verdict(store):
    db, pid = store
    local_finding(store)
    db.save_review(pid, "1", decision="later", final_verdict="false_positive", final_comment="Основание", reviewed=True)
    _, local, diff = compare_one(store, observation())
    assert compare.issue_local_values(local) == {}
    assert local["status_intent"] is None and "decision_diff" not in diff["groups"]
    assert "unknown_base" in diff["groups"] and diff["deferred"]


@pytest.mark.parametrize("actual", ["develop", "main"])
def test_a9_primary_detail_is_bound_to_list_current_branch(store, actual):
    db, _ = store
    local_finding(store, decision=False)
    rid = begin(store)
    fake = FakeSyncHub(1)
    fake.issues[0].update(currentBranch="develop", branch="other")
    step(db, fake); step(db, fake)
    got, _, _ = step(db, fake, body={"id": 1, "appId": 7, "currentBranch": actual, "status": "To verify",
                                   "issueBranchBriefData": [{"branch": "main"}, {"branch": "develop"}]})
    assert parse_qs(urlsplit(loads(got["op"]["request_json"], {})["path"]).query) == {"branch": ["develop"]}
    if actual == "develop":
        step(db, fake)
        step(db, fake, body={"id": 1, "appId": 7, "currentBranch": "main", "status": "Fixed"})
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=?", (rid,))
    diff = loads(item["diff_json"], {})
    assert ("incomplete" in diff["groups"]) is (actual != "develop")
    assert ("detail" in loads(item["hub_json"], {})) is (actual == "develop")


@pytest.mark.parametrize("field", ["updateTs", "scanTs", "commentCount", "cwes", "issueBranchBriefData"])
@pytest.mark.parametrize("decision", [False, True])
def test_a10_metadata_is_not_a_decision_change(store, field, decision):
    local_finding(store, decision=decision)
    body = observation()
    body["detail"].update(updateTs=1, scanTs=2, commentCount=3, cwes=[{"id": "1"}, {"id": "2"}],
                          issueBranchBriefData=[{"branch": "main"}, {"branch": "develop"}])
    accept_issue(store, body)
    body["detail"][field] = list(reversed(body["detail"][field])) if isinstance(body["detail"][field], list) else 9
    _, _, diff = compare_one(store, body)
    assert diff["groups"] == ["matched"] and diff["fields"] == []


def test_a11_reason_conflict_drives_fields_and_groups(store):
    db, pid = store
    local_finding(store)
    accept_issue(store, observation(reason="База"))
    _, _, diff = compare_one(store, observation(reason="Правка Hub"))
    assert "conflict" in diff["groups"] and "decision_diff" in diff["groups"]
    assert next(f for f in diff["fields"] if f["field"] == "reason")["kind"] == "conflict"


def seed_performance(db, pid, count):
    rid = sync.start(db, pid, HUB, 7)
    finish(db, FakeSyncHub(), rid)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id=str(i), kind="SAST") for i in range(1, count + 1)]))
    targets = [{"hub_id": f["hub_id"], "issue_id": int(f["hub_id"]), "issue_type": "SAST", "revision": 1,
                "sig": finding_data_sig(f["data_json"]), "entered_hash": text_hash("Основание")}
               for f in db._all("SELECT * FROM findings WHERE project_id=?", (pid,))]
    body = {"status": "False Positive", "reason": "Основание", "expiredAt": EXPIRY,
            "issues": [{"issueId": int(t["hub_id"]), "issueType": "SAST"} for t in targets]}
    with db._tx() as c:
        c.executemany("INSERT INTO reviews(project_id,hub_id,decision,final_verdict,final_comment,revision,updated_at)"
                      " VALUES (?,?,'disagree','false_positive','Основание',1,'')", [(pid, str(i)) for i in range(1, count + 1)])
        c.execute("INSERT INTO hub_ops(project_id,purpose,op_key,request_json,targets_json,hub_url,app_id,state,created_at,updated_at)"
                  " VALUES (?,'status','bulk',?,?,?,7,'done','','')", (pid, dumps({"body": body}), dumps(targets), HUB))
        for i in range(1, count + 1):
            hub = observation(issueId=i)
            hub["brief"]["id"] = hub["detail"]["id"] = i
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,'issue',?,?)",
                      (rid, f"SAST:{i}", dumps(hub)))
        compare.compare_in(c, sync.run_in(c, rid))
    return rid, body


@pytest.mark.parametrize("count", [1600, 2000])
def test_a12_and_aud08_linear_intents_and_page_sql(web, monkeypatch, count, record_property):
    db = web.app.state.db
    pid = db.create_project("Демо объёма")
    db.update_project(pid, hub_app_id=7)
    rid, _ = seed_performance(db, pid, count)
    calls = {"operations": 0, "targets": 0}
    original = compare.loads
    def counted(raw, default):
        value = original(raw, default)
        if isinstance(value, dict) and isinstance(value.get("body"), dict) and "issues" in value["body"]:
            calls["operations"] += 1
        if isinstance(value, list) and value and isinstance(value[0], dict) and "entered_hash" in value[0]:
            calls["targets"] += len(value)
        return value
    monkeypatch.setattr(compare, "loads", counted)
    queries = []
    stop_recording = record_queries(queries)
    try:
        response = web.client.get(f"/projects/{pid}/hub-sync/{rid}")
    finally:
        stop_recording()
    result = {"count": count, "bytes": len(response.content), "sql": len(queries), **calls}
    record_property("measurement", dumps(result))
    if destination := os.environ.get("HUB_SYNC_MEASUREMENT"):
        with Path(destination).open("a", encoding="utf-8") as out:
            out.write(json.dumps(result) + "\n")
    assert response.status_code == 200
    assert result["bytes"] < 200_000 and result["sql"] < 100, result
    assert calls == {"operations": 1, "targets": count}
    assert "Локальные данные изменились после сравнения" not in response.text
    db.save_review(pid, str(count), decision="later", final_verdict="false_positive", final_comment="", reviewed=True)
    assert not compare.snapshot_current(db, run(db, rid))


def test_a10_content_change_has_separate_readonly_projection(store):
    local_finding(store)
    body = observation()
    body["detail"]["title"] = "Было"
    accept_issue(store, body)
    body["detail"]["title"] = "Стало"
    _, _, diff = compare_one(store, body)
    assert diff["groups"] == ["observed"]
    assert diff["fields"][0]["field"] == "detail/title" and diff["fields"][0]["readonly"]
