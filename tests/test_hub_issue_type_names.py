"""Hub в ручной записи находки SCA пишет имя типа «SCA Security», а ключ находки –
SCA_S (форма записи риска не наблюдалась – к ней применяется та же таблица). Запись должна считаться своей: без пометки «относится к другой находке», с основанием и отметкой
«Внесено в Hub» при принятии; «SCA Compliance» – SCA_L. Чужой тип и чужой номер по-прежнему чужие."""
import json

import pytest

from app import hub_sync_api as api, hub_sync_compare as compare
from app.db import loads
from test_hub_status_routes import project, sca
from test_sync_golden_path import LiveHub, synchronize
from test_web import web  # noqa: F401

MANUAL = {"id": 900151, "issueId": 900324, "issueType": "SCA Security", "status": "False Positive",
          "oldStatus": "To verify", "reason": "Фронтенд отдаётся статикой, уязвимость не эксплуатируется.",
          "conditionalCategory": None, "changedBy": "demo", "createTs": 1773912765241, "expiredAt": 1798761599999}
HUB_OBJ = {"brief": {"id": 900324, "type": "SCA_S", "currentBranch": "main", "issueChangeStatusInfoId": 900151},
           "detail": {"id": 900324, "appId": 7, "status": "False Positive", "currentBranch": "main",
                      "issueBranchBriefData": [{"branch": "main", "status": "False Positive"}]},
           "manual": MANUAL}
OTHER = "Ручная запись относится к другой находке."


@pytest.mark.parametrize("value, key_type, same", [
    ("SCA Security", "SCA_S", True), ("SCA_S", "SCA_S", True), ("SCA Compliance", "SCA_L", True),
    ("SAST", "SAST", True), ("SCA Security", "SAST", False), ("SAST", "SCA_S", False), ("", "SCA_S", False),
    (None, "SAST", False), ("SCA Security", "SCA_L", False),
])
def test_hub_type_names_match_issue_keys(value, key_type, same):
    assert api.same_issue_type(value, key_type) is same


def test_sca_manual_record_named_sca_security_is_own():
    problems = api.evidence_problems(HUB_OBJ, "SCA_S:900324", 7, api.ADAPTER)
    assert OTHER not in problems, problems
    assert compare.decision_source(HUB_OBJ, "SCA_S:900324") == MANUAL
    assert compare.issue_values(HUB_OBJ, "SCA_S:900324")["reason"] == MANUAL["reason"]
    other = {**HUB_OBJ, "manual": {**MANUAL, "issueId": 900325}}  # чужой номер – по-прежнему чужая запись
    assert OTHER in api.evidence_problems(other, "SCA_S:900324", 7, api.ADAPTER)
    assert compare.decision_source(other, "SCA_S:900324") is None
    foreign = {**HUB_OBJ, "manual": {**MANUAL, "issueType": "SAST"}}  # чужой тип тоже
    assert OTHER in api.evidence_problems(foreign, "SCA_S:900324", 7, api.ADAPTER)


def test_risk_record_named_sca_security_is_valid():
    risk = {"appId": 7, "issueId": 900324, "issueType": "SCA Security", "comment": "Риск принят", "isActive": True,
            "isConditional": False, "expiredAt": 4070995199999}
    assert api.risk_valid(risk, "SCA_S:900324", 7)
    assert not api.risk_valid({**risk, "issueType": "SAST"}, "SCA_S:900324", 7)


class ScaHub(LiveHub):
    """Hub с находками SCA: в списке и подробностях тип SCA_S, в ручной записи – «SCA Security», как у настоящего."""

    def answer(self, request):
        status, body = super().answer(request)
        if request["method"] == "GET" and body:
            data = json.loads(body)
            if "filteredEntities" in data:
                for entry in data["filteredEntities"]:
                    if "type" in entry:
                        entry["type"] = "SCA_S"
            if request["path"].startswith("/issue/status?") and isinstance(data, dict):
                data["issueType"] = "SCA Security"
            body = json.dumps(data, ensure_ascii=False)
        return status, body

    def decision(self, ident, status="False Positive", reason="Основание Hub"):
        super().decision(ident, status, reason)
        self.manual[ident]["issueType"] = "SCA Security"


def test_decision_accepted_without_reason_by_old_version_is_a_difference(web):
    """Ревью dev16, Codex круг 1: решение, принятое прежней версией без основания (ручная запись считалась чужой),
    после обновления – расхождение основания (decision_diff), а не «совпадает»; повторное принятие закрывает его."""
    from app import hub_pull as pull, hub_sync_compare as compare
    db = web.app.state.db
    hub = ScaHub(1)
    pid = project(web, [sca("1")])
    hub.decision(1, status="False Positive", reason="Статика, не эксплуатируется.")
    row = synchronize(db, pid, hub)
    with db._tx() as c:  # как записала прежняя версия: решение из Hub без основания и без отметки
        c.execute("UPDATE reviews SET final_comment='', entered_hub=0, entered_hub_at=NULL WHERE project_id=? AND hub_id='1'", (pid,))
    compare.recompare(db, row["id"])
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SCA_S:1'", (row["id"],))["diff_json"], {})
    assert "decision_diff" in diff["groups"] and "matched" not in diff["groups"], diff["groups"]
    row = synchronize(db, pid, hub)  # новый обход и принятие восстанавливают основание и отметку
    review = db.get_review(pid, "1")
    assert review["final_comment"] == "Статика, не эксплуатируется." and review["entered_hub"] == 1, dict(review)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SCA_S:1'", (row["id"],))["diff_json"], {})
    assert diff["groups"] == ["matched"], diff["groups"]
    assert pull.residual(diff) is False


def test_accepting_sca_false_positive_from_hub_keeps_reason_and_mark(web):
    """Как в настоящем Hub: находка SCA со статусом False Positive и ручной записью типа «SCA Security». После
    принятия – решение с основанием из записи и отметка «Внесено в Hub», без пометки о чужой записи."""
    db = web.app.state.db
    hub = ScaHub(1)
    pid = project(web, [sca("1")])
    hub.decision(1, status="False Positive", reason="Статика, не эксплуатируется.")
    row = synchronize(db, pid, hub)
    item = db._one("SELECT entity_key, diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SCA_S:1'", (row["id"],))
    assert item is not None, "находка SCA не попала в чтение"
    diff = loads(item["diff_json"], {})
    assert not any("другой находке" in n for n in diff.get("hub_notes", [])), diff.get("hub_notes")
    review = db.get_review(pid, "1")
    assert review["final_verdict"] == "false_positive" and review["final_comment"] == "Статика, не эксплуатируется."
    assert review["entered_hub"] == 1 and review["entered_origin"] == "hub_sync", dict(review)
