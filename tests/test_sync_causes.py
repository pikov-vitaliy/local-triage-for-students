"""Причина у каждого отличия синхронизации (0.10.0.dev14): правка без отправки с датой, неудачная отправка с ответом
Hub, Fixed в Hub, противоречие на стороне Hub; противоречия Hub не держат шаг «принято частично». Данные выдуманные."""

import json

from app import hub_onboarding
from app.db import dumps, loads
from test_hub_defect_import import APP_ID
from test_hub_status_routes import HUB, decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, synced, synchronize
from test_web import web  # noqa: F401


class RefusingHub(LiveHub):
    """Hub отказывает в смене статуса исправленной находки, как настоящий (400, «issue was fixed»)."""

    def answer(self, request):
        if request["method"] == "POST" and request["path"] == "/issue/status/update":
            ident = int((request["body"].get("issues") or [request["body"]])[0]["issueId"])
            if self.issues[ident]["status"] == "Fixed":
                return 400, json.dumps({"errorMessage": f"Unable to change status for SAST issue #{ident}: issue was fixed"})
        return super().answer(request)


def causes_of(db, row, key):
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key=?", (row["id"], key))
    return loads(item["diff_json"], {}).get("causes", [])


def test_unsent_edit_has_cause_with_date(web):
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2")])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    found = causes_of(db, synced(db, pid, hub), "SAST:1")
    assert any(c.startswith("Правка решения в приложении от ") and "не отправлена" in c for c in found), found
    assert causes_of(db, synced(db, pid, hub), "SAST:2") == []


def test_failed_send_to_fixed_finding_is_named(web):
    db = web.app.state.db
    hub = RefusingHub(2)
    pid = project(web, [sast("1"), sast("2")])
    synchronize(db, pid, hub)
    decide(web, pid, "2")
    hub.issues[2]["status"] = "Fixed"
    hub.issues[2]["issueBranchBriefData"][0]["status"] = "Fixed"
    send(web, pid, "2")
    drain(db, hub)
    found = causes_of(db, synced(db, pid, hub), "SAST:2")
    assert any("исправлена (Fixed)" in c for c in found), found
    assert any("не прошла" in c and "issue was fixed" in c and "операция" in c for c in found), \
        ("ответ Hub на отправку не теряется и у Fixed (ревью Kimi dev14)", found)


def test_hub_contradiction_is_accepted_by_detail_status(web):
    """dev15 (план п. 1.2): противоречие подробного статуса и ручной записи – пометка Hub, а не
    пропуск. Находка принимается по подробному статусу, основание из противоречащей записи не берётся, после принятия
    – совпадение, пометка названа у находки. Раньше такие находки оставались
    отличием после «Принять»."""
    from test_sync_golden_path import synchronize
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    hub.decision(2, status="False Positive", reason="Основание в Hub.")
    hub.issues[2]["status"] = "Open"  # подробный статус расходится с ручной записью
    hub.issues[2]["issueBranchBriefData"][0]["status"] = "Open"
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    assert result["skipped"] == [], result
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "accepted", state
    review = db.get_review(pid, "2") or {}  # решения Hub (Open) нет – строки решения может и не быть
    assert review.get("final_comment") != "Основание в Hub." and not review.get("entered_hub"), review
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:2'",
                         (row["id"],))["diff_json"], {})
    assert diff["groups"] == ["matched"] and diff["fields"] == [], diff
    assert any(c.startswith("В Hub: подробный статус и ручная запись") for c in diff["causes"]), diff["causes"]
    assert APP_ID == 7

def test_delivered_edit_then_hub_change_is_not_called_unsent(web):
    """Ревью dev14, круг 1: правка доставлена, потом Hub изменил обоснование – конфликт без «не отправлена»."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2")])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    hub.decision(1, status="False Positive", reason="Другое обоснование, записанное в Hub.")
    found = causes_of(db, synced(db, pid, hub), "SAST:1")
    assert found and not any("не отправлена" in c for c in found), found


def test_unknown_send_outcome_is_not_called_failure(web):
    """Ревью dev14, круг 1: исход отправки неизвестен – «неизвестен, сверьте», а не «не прошла»."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2")])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET state='unknown', error='ответа нет' WHERE project_id=? AND purpose='status'", (pid,))
    found = causes_of(db, synced(db, pid, hub), "SAST:1")
    assert any("неизвестен" in c for c in found) and not any("не прошла" in c for c in found), found


def test_only_hub_contradiction_is_something_to_accept(web):
    """dev15: находка с противоречием Hub пригодна к принятию – шаг «Состояние Hub» до принятия «готово к принятию»
    (раньше – «только противоречия на стороне Hub», и находка навсегда оставалась отличием)."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"  # подробный статус расходится с ручной записью
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    synced(db, pid, hub)
    full = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert full["state"] == "ready" and full["pull"]["count"] == 1, full


def test_stored_edit_dates_exclude_delivered():
    """Ревью Codex dev14, круг 3: дата причины – только неотправленных сохранённых правок."""
    from app.hub_sync_compare import causes
    diff = {"groups": ["pending"], "pending_ids": [1, 2], "delivered_pending_ids": [1], "current_pending": False,
            "stored_dates": ["2026-11-08T01:30:00+00:00"]}
    found = causes("issue", "SAST:1", {}, diff, None)
    assert found == ["Правка решения, сохранённая отдельно при синхронизации 2026-11-08 01:30 UTC, в Hub не отправлена: "
                     "откройте её, чтобы восстановить или отбросить."], found


def test_unsent_cause_uses_decision_date_not_mark_date():
    """Ревью Kimi dev14, круг 4: «Проверено» после правки не меняет дату правки в причине."""
    from app.hub_sync_compare import causes
    local = {"review": {"decided_at": "2026-11-07T10:00:00+00:00", "updated_at": "2026-11-08T03:00:00+00:00"}}
    found = causes("issue", "SAST:1", local, {"groups": ["pending"], "current_pending": True}, None)
    assert found == ["Правка решения в приложении от 2026-11-07 10:00 UTC в Hub не отправлена."], found


def test_accepted_contradiction_hides_tab_notes(web):
    """dev15: после принятия находки с противоречием Hub напоминания «не принято» на вкладках находок и дефектов нет."""
    from test_sync_golden_path import synchronize
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    synchronize(db, pid, hub)
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "accepted"
    for page in (f"/projects/{pid}/findings", f"/projects/{pid}/defects"):
        assert 'id="hub-step-note"' not in web.client.get(page).text, page


def test_unaccepted_read_still_shows_tab_note(web):
    """Обратная сторона: прочитано, есть что принять – напоминание на вкладках есть."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    synced(db, pid, hub)
    assert 'id="hub-step-note"' in web.client.get(f"/projects/{pid}/findings").text


class BranchFailHub(LiveHub):
    """Чтение дополнительной ветки находки завершается ошибкой."""

    def answer(self, request):
        if request["method"] == "GET" and "branch=feature" in request["path"]:
            return 500, json.dumps({"errorMessage": "internal"})
        return super().answer(request)


def test_contradiction_with_read_error_keeps_step_partial(web):
    """Ревью Codex dev14, круг 7: противоречие Hub и одновременно ошибка чтения ветки – пропуск не «только противоречия»,
    шаг остаётся «принято частично» (настоящий путь принятия)."""
    from test_sync_golden_path import synchronize
    db = web.app.state.db
    hub = BranchFailHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"].append({"branch": "feature", "status": "Open", "isBranchDefault": False,
                                                 "lastSeen": 1800000000000})
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    reasons = [r for s in result.get("skipped", []) for r in s["reasons"]]
    # dev15: противоречие – пометка, не причина пропуска; пропуск держит ошибка чтения ветки
    assert not any("противоречат" in r for r in reasons) and any("Исключение branch:feature" in r for r in reasons), reasons
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "partial", (state["state"], reasons)


def test_dev13_result_with_incomplete_reasons_stays_partial(web):
    """Ревью Codex dev14, круг 8: результат, принятый dev13, хранил у пропуска только противоречие (ошибка чтения
    вытеснена) – после обновления шаг не становится «принято»: сверка с записью сравнения прогона."""
    from test_sync_golden_path import synchronize
    db = web.app.state.db
    hub = BranchFailHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    hub.decision(1, status="False Positive", reason="Основание в Hub.")
    hub.issues[1]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "Open"
    hub.issues[1]["issueBranchBriefData"].append({"branch": "feature", "status": "Open", "isBranchDefault": False,
                                                 "lastSeen": 1800000000000})
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    for s in result["skipped"]:  # как записывала dev13: problems вытесняли остальные причины
        s["reasons"] = [r for r in s["reasons"] if "противоречат" in r] or s["reasons"]
    with db._tx() as c:
        c.execute("UPDATE hub_defect_sync_runs SET result_json=? WHERE id=?", (dumps(result), row["id"]))
    assert hub_onboarding.state(db, db.get_project(pid), HUB)["state"] == "partial"


def test_unknown_outcome_is_not_called_unsent():
    """Ревью Codex dev14, круг 11: исход отправки этой редакции неизвестен – «доставка не подтверждена», не «не отправлена»."""
    from app.hub_sync_compare import causes
    local = {"review": {"decided_at": "2026-11-07T10:00:00+00:00"}, "status_intent": {"state": "unknown"}}
    found = causes("issue", "SAST:1", local, {"groups": ["pending"], "current_pending": True}, None)
    assert found == ["Правка решения в приложении от 2026-11-07 10:00 UTC: доставка в Hub не подтверждена."], found


# ============================================================================ dev15, план п. 3: справочные отличия Hub


def observed(field, before, after):
    return {"field": "detail/" + field, "kind": "observed", "readonly": True,
            "B": {"present": True, "value": before}, "H": {"present": True, "value": after}}


def test_observed_text_change_names_fields():
    """Бэклог 90: справочное отличие объясняется по полям; «статус и решение не менялись» – только при одинаковой
    проекции решения у базы и Hub."""
    from app.hub_sync_compare import observed_causes
    diff = {"groups": ["observed"], "decision_same": True,
            "fields": [observed("category", {"category": "A"}, {"category": "B"}), observed("eduLink", "a", "b")]}
    assert observed_causes(diff) == [
        "Hub изменил справочный текст находки (поля category, eduLink); статус и решение не менялись."]
    assert observed_causes({**diff, "decision_same": False}) == [
        "Hub изменил справочный текст находки (поля category, eduLink)."]


def test_observed_branches_place_and_other_fields():
    from app.hub_sync_compare import observed_causes
    branches = observed("issueBranchBriefData",
                        [{"branch": "main", "status": "To verify"}, {"branch": "old", "status": "Open"}],
                        [{"branch": "main", "status": "Fixed"}, {"branch": "develop", "status": "Open"}])
    diff = {"groups": ["observed"], "fields": [
        branches, observed("lineNumber", "12", "14"), observed("codebase", {"id": 3}, {"id": 4}),
        {"field": "status", "kind": "changed", "B": {"value": 1}, "H": {"value": 2}}]}
    assert observed_causes(diff) == [
        "Hub изменил сведения веток: develop: появилась; main: статус был To verify, стал Fixed; old: исчезла.",
        "Hub изменил место находки: lineNumber было 12, стало 14.",
        "Hub изменил сведения находки: поля codebase."]


def test_observed_change_has_cause_and_disappears_after_accept(web):
    """Настоящий путь: Hub изменил справку и место – у находки причина по полям; после «Принять состояние
    Hub» – совпадение без причин (после синхронизации расхождений нет)."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    synchronize(db, pid, hub)
    hub.issues[1]["category"] = {"category": "Новое правило", "cwes": [{"id": "CWE-20"}]}
    hub.issues[1]["lineNumber"] = "14"
    found = causes_of(db, synced(db, pid, hub), "SAST:1")
    assert "Hub изменил справочный текст находки (поля category); статус и решение не менялись." in found, found
    assert "Hub изменил место находки: lineNumber было 12, стало 14." in found, found
    row = synchronize(db, pid, hub)
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'", (row["id"],))
    diff = loads(item["diff_json"], {})
    assert diff["groups"] == ["matched"] and diff["causes"] == [], diff
