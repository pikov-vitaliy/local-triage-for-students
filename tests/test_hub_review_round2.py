"""Круг 2 dev2: решение оператора и подтверждение состава на выдуманных данных."""

import re

import pytest

from app import hub_pull as pull
from app.db import loads
from test_defect import save_sast
from test_hub_defect_guard import created
from test_hub_defects import FIX, REASON, pair_project
from test_hub_pull import accept, read
from test_hub_review_round1 import project_hub
from test_web import web  # noqa: F401


@pytest.mark.parametrize("change", ["unlink", "absent", "other_type", "incomplete_issue"])
def test_accepted_composition_revokes_only_invalid_marks_and_keeps_review(web, change):
    pid = pair_project(web)
    db = web.app.state.db
    urls = {ident: save_sast(web, pid, ident, "true_positive", "", REASON, FIX)[0]
            for ident in ("510001", "510005")}
    defect = created(web, pid, urls["510001"], links=(510001, 510005))
    before = {ident: db.get_review(pid, ident) for ident in urls}
    recorded = {r["hub_id"]: r for r in db._all("SELECT * FROM reviews WHERE project_id=?", (pid,))}
    assert all(r["entered_hub"] and r["reviewed"] for r in before.values())
    body = loads(defect["confirmed_object_json"], {})
    body["linkedIssues"] = [link for link in body["linkedIssues"] if link["id"] != 510001]
    if change == "other_type":
        body["linkedIssues"].append({"id": 510001, "type": "SCA_S"})
    hub = project_hub(db, pid, [] if change == "absent" else [body])
    if change == "incomplete_issue":
        hub.manual[510001] = {"issueId": 510001, "issueType": "SAST", "status": "False Positive",
                             "reason": "Основание из другого состояния", "expiredAt": None}
    rid = read((db, pid), hub)
    assert {ident: db.get_review(pid, ident) for ident in urls} == before
    ops = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    result = accept(db, rid)
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == ops
    # dev15 (план п. 1.2): ручная запись, противоречащая подробному статусу, – пометка Hub, не пропуск; находка
    # принимается по подробному статусу (решения в Hub нет – «Подтверждаю дефект» оператора не трогается)
    assert not any(i["kind"] == "issue" and i["key"] == "SAST:510001" for i in result["skipped"])
    removed = set(urls) if change == "absent" else {"510001"}
    for ident, original in before.items():
        current = db.get_review(pid, ident)
        assert bool(current["entered_hub"]) == (ident not in removed)
        if ident in removed:
            assert current["entered_defect_id"] is None and current["entered_op_id"] is None
            assert current["entered_hub_at"] is None and current["entered_defect_revision"] == 0
            assert all(current[key] == "" for key in (
                "entered_origin", "entered_decision_hash", "entered_text_hash", "entered_parts"))
        own = ("updated_at", "defect_dropped", "dropped_info")  # пометка «выбыла из дефекта» (схема 33)
        assert {k: v for k, v in current.items() if not k.startswith("entered_") and k not in own} == {
            k: v for k, v in original.items() if not k.startswith("entered_") and k not in own}
        assert bool(current["dropped_info"]) == (ident in removed)
        if ident not in removed:
            assert current == original
        card = web.client.get(urls[ident])
        assert card.status_code == 200
        badge = re.search(r'<span[^>]*id="entered-badge"[^>]*>', card.text).group()
        assert (" hidden" in badge) == (ident in removed)
        assert " hidden" not in re.search(r'<span[^>]*id="reviewed-badge"[^>]*>', card.text).group()

    listing = web.client.get(f"/projects/{pid}/findings")
    assert listing.status_code == 200
    for ident in urls:
        finding_id = db._scalar("SELECT id FROM findings WHERE project_id=? AND hub_id=?", (pid, ident))
        html = re.search(rf'<tr id="finding-{finding_id}".*?</tr>', listing.text, re.S).group()
        assert ("не в Hub" in html) == (ident in removed)

    history = db._all("SELECT * FROM hub_defect_history WHERE defect_id=? AND event='hub_sync'", (defect["id"],))
    assert len(history) == 1
    details = loads(history[0]["details_json"], {})
    assert details["run_id"] == rid
    assert {r["hub_id"]: r for r in details["revoked_confirmations"]} == {i: recorded[i] for i in removed}
    if change == "absent":
        assert details["presence"] == "absent"
    else:
        targets = loads(db.hub_defect(defect["id"])["targets_json"], [])
        assert {(t["issue_id"], t["issue_type"]) for t in targets} == {
            (link["id"], link["type"]) for link in body["linkedIssues"]}
    tables = ("reviews", "findings", "imports", "hub_defects", "hub_defect_history", "hub_ops",
              "hub_entity_versions", "hub_sync_pending", "hub_sync_applications", "hub_issue_states")
    snapshot = {t: db._all(f"SELECT * FROM {t} ORDER BY 1, 2") for t in tables}
    assert pull.apply(db, rid, result["token"]) == result
    assert {t: db._all(f"SELECT * FROM {t} ORDER BY 1, 2") for t in tables} == snapshot
