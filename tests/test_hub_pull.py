"""Принятие Hub: наблюдаемые формы с полностью выдуманными значениями."""

import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_pull as pull, hub_sync as sync, hub_sync_api as api, hub_sync_compare as compare
from app.db import loads
from app.models import Finding
from app.triage import order_findings
from test_hub_sync import HUB, run, store  # noqa: F401
from test_hub_sync_analyst import defect_store
from test_web import web, ORIGIN  # noqa: F401


class PullHub:
    """Миллисекунды, nullable scanObject.url, severity int, currentBranch, пустой manual."""

    def __init__(self, count=1, defects=True):
        self.issues = {i: {"id": i, "appId": 7, "status": "Fixed", "state": "Existing",
                           "severity": 2, "severityDisplayName": "Medium", "currentBranch": "main",
                           "fileName": "demo.c", "lineNumber": "12", "language": "C", "tool": "Demo",
                           "category": {"category": "Demo rule", "cwes": [{"id": "CWE-20"}]},
                           "codebase": {"id": 3, "name": "demo", "defaultBranch": "main"},
                           "updateTs": 1800000000000, "scanTs": 1800000000000,
                           "issueBranchBriefData": [{"branch": "main", "status": "Fixed", "isBranchDefault": True, "lastSeen": 1800000000000}]}
                       for i in range(1, count + 1)}
        self.manual = {}
        self.defects = {77: {"id": 77, "appId": 7, "summary": "ID9 - Демо", "description":
                            "<p>Принятый текст</p><p>Информация об объекте сканирования:</p><p>строка 12</p>",
                            "status": "Open", "createTs": 1800000000000, "updateTs": 1800000000000,
                            "priority": {"name": "High", "rank": 3}, "priorityId": 3,
                            "severity": {"name": "Medium", "rank": 2}, "severityId": 2,
                            "settings": {"isInheritedARStatusFromDefect": False, "isInheritedFPStatusFromDefect": False},
                            "linkedIssues": [{"id": 1, "type": "SAST", "appId": 7, "severity": 2,
                                              "lastScanTs": 1800000000000, "scanObject": {"id": 3, "url": None}}]}}
        if not defects:
            self.defects = {}
        self.calls = []

    def decision(self, ident, status="False Positive", reason="Основание Hub"):
        self.issues[ident]["status"] = status
        self.issues[ident]["issueBranchBriefData"][0]["status"] = status
        self.manual[ident] = {"id": ident + 100, "issueId": ident, "issueType": "SAST", "status": status,
                              "oldStatus": "To verify", "reason": reason, "conditionalCategory": None,
                              "changedBy": "demo", "createTs": 1800000000000, "expiredAt": 4070995199999}

    def answer(self, request):
        self.calls.append(request)
        assert request["method"] == "GET" and request["body"] is None
        path = urlsplit(request["path"])
        query = parse_qs(path.query)
        if path.path in ("/issue/v2", "/defects"):
            if path.path == "/issue/v2":
                entries = [{"id": i, "appId": 7, "type": "SAST", "currentBranch": "main", "status": v["status"],
                            "severity": 2, "scanObject": {"id": 3, "name": "demo", "type": "SAST", "url": None}}
                           for i, v in self.issues.items()]
            else:
                entries = [{"id": i, "app": {"id": 7, "name": "Демо"}, "createTs": 1800000000000} for i in self.defects]
            index, size = int(query["pageIndex"][0]), int(query["pageSize"][0])
            body = {"filteredEntities": entries[index * size:(index + 1) * size], "totalEntitiesCount": len(entries)}
        elif path.path == "/issue/status":
            body = self.manual.get(int(query["issueId"][0]))
            if body is None:
                return 200, ""
        elif path.path.endswith("/riskAcceptance"):
            ident = int(path.path.split("/")[-2])
            body = {"appId": 7, "issueId": ident, "issueType": "SAST", "comment": "Основание риска Hub",
                    "isActive": True, "isConditional": False, "expiredAt": 4070995199999}
        else:
            ident = int(path.path.rsplit("/", 1)[-1])
            body = (self.defects if path.path.startswith("/defects/") else self.issues).get(ident)
            if body is None:
                return 404, ""
        return 200, json.dumps(body, ensure_ascii=False)


def read(store, hub):
    db, pid = store
    previous = db._one("SELECT id,revision FROM hub_defect_sync_runs WHERE project_id=? AND closed_at IS NULL", (pid,))
    rid = sync.start(db, pid, HUB, 7, adapter=api.ADAPTER,
                     previous=(previous["id"], previous["revision"]) if previous else None)
    finish_pull(db, hub, rid)
    return rid


def finish_pull(db, hub, rid):
    for _ in range(1000):
        if run(db, rid)["state"] not in sync.ACTIVE:
            break
        got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
        assert got
        status, body = hub.answer(loads(got["op"]["request_json"], {}))
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                      {"status": status, "body_text": body, "error": "", "truncated": False})
    assert run(db, rid)["state"] == "ready"


def accept(db, rid):
    preview = pull.preview(db, run(db, rid))
    assert preview.get("count"), preview
    return pull.apply(db, rid, preview["token"])


def finding(db, pid, ident="1"):
    return db._one("SELECT * FROM findings WHERE project_id=? AND hub_id=?", (pid, ident))


def test_live_shapes_apply_materializes_fixed_and_defect_without_hub_calls(store, monkeypatch):
    db, pid = store
    hub = PullHub(count=65)
    rid = read(store, hub)
    before = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    monkeypatch.setattr(db, "_hub_insert", lambda *a, **k: pytest.fail("Применение не должно обращаться к Hub"))
    result = accept(db, rid)
    assert result["count"] == 66 and not result["skipped"] and result["pending"] == 0
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before
    assert db._scalar("SELECT COUNT(*) FROM findings") == 65
    assert loads(finding(db, pid)["data_json"], {})["status"] == "Fixed"
    assert db._one("SELECT * FROM imports")["source_kind"] == "hub_sync"
    assert finding(db, pid)["file_import_id"] is None
    defect = db._one("SELECT * FROM hub_defects")
    assert defect["number"] == 9 and defect["draft_summary"] == "ID9 - Демо"
    assert loads(defect["confirmed_object_json"], {}) == hub.defects[77]
    assert db._scalar("SELECT number FROM defects WHERE defect_key='sast:1'") == 9
    assert [(t["issue_id"], t["issue_type"]) for t in loads(defect["targets_json"], [])] == [(1, "SAST")]
    assert sync.passport(run(db, rid))["matches_snapshot"]
    assert compare.snapshot_current(db, run(db, rid))


def test_lost_number_stays_with_defect_and_its_findings(store):
    """ADR-0138: ID убрали из заголовка в Hub – номер остаётся за дефектом и находками, общая синхронизация его не снимает."""
    db, _ = store
    hub = PullHub()
    accept(db, read(store, hub))
    assert db._one("SELECT number FROM hub_defects")["number"] == 9
    hub.defects[77]["summary"] = "Демо"
    accept(db, read(store, hub))
    defect = db._one("SELECT * FROM hub_defects")
    assert defect["number"] == 9 and defect["summary"] == "Демо"
    assert db._scalar("SELECT number FROM defects WHERE defect_key='sast:1'") == 9
    assert loads(defect["number_keys_json"], []) == ["sast:1"]


def test_lost_number_is_not_given_to_keys_that_never_held_it(store):
    db, _ = store
    hub = PullHub()
    accept(db, read(store, hub))
    with db._tx() as c:
        c.execute("DELETE FROM defects WHERE defect_key='sast:1'")
    hub.defects[77]["summary"] = "Демо"
    accept(db, read(store, hub))
    assert db._one("SELECT number FROM hub_defects")["number"] == 9
    assert db._scalar("SELECT COUNT(*) FROM defects WHERE defect_key='sast:1'") == 0


def test_template_model_read_does_not_block_apply(store):
    db, pid = store
    hub = PullHub()
    rid = read(store, hub)
    db.hub_enqueue(purpose="read", request={"method": "GET", "path": "/templates/defects/model?issueType=SAST&issueId=1&appId=7"}, hub_url=HUB, app_id=7,
                   project_id=pid, targets=[{"issue_type": "DEFECT_TEMPLATE_MODEL", "issue_id": 1, "defect_id": 1}])
    assert accept(db, rid)["count"] >= 1


def test_apply_is_idempotent_and_preserves_history(store):
    db, pid = store
    hub = PullHub()
    rid = read(store, hub)
    result = accept(db, rid)
    tables = ("reviews", "findings", "imports", "hub_defects", "hub_entity_versions", "hub_sync_pending", "hub_sync_applications")
    before = {t: db._all(f"SELECT * FROM {t} ORDER BY 1, 2") for t in tables}
    assert pull.apply(db, rid, result["token"]) == result
    assert {t: db._all(f"SELECT * FROM {t} ORDER BY 1, 2") for t in tables} == before
    assert len(before["hub_sync_applications"]) == 2


def test_full_description_without_team_separator_is_accepted(store):
    db, _ = store
    hub = PullHub()
    hub.defects[77]["description"] = "<p>Произвольное описание Hub</p>"
    accept(db, read(store, hub))
    assert loads(db._one("SELECT confirmed_object_json FROM hub_defects")["confirmed_object_json"], {}) == hub.defects[77]
    assert sync.passport(run(db, read(store, hub)))["matches_snapshot"]


def test_reappeared_defect_requires_accepting_presence(store):
    db, _ = store
    hub = PullHub(count=0)
    hub.defects[77]["linkedIssues"] = []
    accept(db, read(store, hub))
    obj = hub.defects.pop(77)
    accept(db, read(store, hub))
    assert db._one("SELECT error FROM hub_defects")["error"]
    hub.defects[77] = obj
    rid = read(store, hub)
    assert not sync.passport(run(db, rid))["matches_snapshot"]
    accept(db, rid)
    assert not db._one("SELECT error FROM hub_defects")["error"]
    assert sync.passport(run(db, read(store, hub)))["matches_snapshot"]


def test_all_supported_types_materialize_without_invented_coordinates(store):
    from test_hub_sync import FakeSyncHub, begin, finish
    db, _ = store
    rid = begin(store)
    finish(db, FakeSyncHub(4), rid)
    accept(db, rid)
    rows = db._all("SELECT kind,data_json FROM findings")
    assert {r["kind"] for r in rows} == {"SAST", "SCA", "SCA-license", "DAST"}
    assert all(not loads(r["data_json"], {})["component"] for r in rows)
    assert sync.passport(run(db, rid))["matches_snapshot"]


def test_foreign_manual_record_is_accepted_without_its_reason(store):
    """dev15 (план п. 1.1–1.2): ручная запись другой находки – пометка Hub, а не пропуск; находка принимается по
    подробному статусу, основание и отметка «Внесено в Hub» из чужой записи не берутся (ревью плана, круг 1)."""
    db, pid = store
    hub = PullHub(count=2, defects=False)
    hub.decision(1)
    hub.manual[1]["issueId"] = 999
    rid = read(store, hub)
    result = accept(db, rid)
    assert result["skipped"] == [] and result["count"] == 2
    review = db.get_review(pid, "1")
    assert review["final_verdict"] == "false_positive" and review["final_comment"] == "" and not review["entered_hub"]
    assert sync.passport(run(db, rid))["matches_snapshot"]


def test_restored_intention_is_not_duplicated_and_new_matching_hub_resolves_it(store):
    db, pid = store
    hub = PullHub(defects=False)
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Моё основание", reviewed=False)
    accept(db, read(store, hub))
    # dev15: в Hub находка исправлена (Fixed) – решение туда не уйдёт; после принятия приложение равно Hub,
    # решение оператора – в истории (`saved`)
    assert db.get_review(pid, "1")["final_comment"] == ""
    assert db._one("SELECT state FROM hub_sync_pending")["state"] == "saved"
    hub.decision(1, reason="Моё основание")
    hub.manual[1]["expiredAt"] = None
    rid = read(store, hub)
    accept(db, rid)
    # Hub принял то же решение – строка истории закрывается как доставленная, новых не появляется
    assert db._scalar("SELECT COUNT(*) FROM hub_sync_pending") == 1
    assert db._one("SELECT state FROM hub_sync_pending")["state"] == "delivered"
    assert sync.passport(run(db, rid))["matches_snapshot"]


def test_pending_decision_survives_hub_change_and_is_restorable(store):
    db, pid = store
    hub = PullHub(defects=False)
    hub.decision(1)
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Моя новая правка", reviewed=False)
    hub.decision(1, "False Positive", "Новое основание Hub")
    rid = read(store, hub)
    result = accept(db, rid)
    # dev15: решение Hub побеждает, правка оператора – история (`saved`), не отличие; после принятия – совпадение
    assert result["pending"] == 0
    review = db.get_review(pid, "1")
    assert review["decision_origin"] == "hub_sync" and review["final_comment"] == "Новое основание Hub"
    pending = db._one("SELECT * FROM hub_sync_pending")
    assert pending["state"] == "saved"
    assert loads(pending["payload_json"], {})["local"]["review"]["final_comment"] == "Моя новая правка"
    assert loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=?", (rid,))["diff_json"], {})["groups"] == ["matched"]
    assert sync.passport(run(db, rid))["matches_snapshot"]
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    ctx = pull.pending_context(db, target, pending["id"])
    pull.restore(db, target, pending["id"], ctx["confirmation"])
    assert db.get_review(pid, "1")["final_comment"] == "Моя новая правка"
    assert not db.get_review(pid, "1")["entered_hub"]
    assert db._one("SELECT confirmed_json FROM hub_issue_states")["confirmed_json"].find("Новое основание Hub") >= 0


def test_unsent_defect_fields_survive_and_hub_fields_composition_win(store):
    db, pid = store
    old, body = defect_store(store)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_summary='Моя правка',draft_revision=draft_revision+1 WHERE id=?", (old["id"],))
        from app import defect_drafts
        defect_drafts.history(c, defect_drafts.owner_in(c, old), "edit")
    hub = PullHub(count=2)
    hub.defects[77]["linkedIssues"] = [{"id": 2, "type": "SAST"}]
    rid = read(store, hub)
    accept(db, rid)
    current = db.hub_defect(old["id"])
    assert current["draft_summary"] == "ID9 - Демо"
    assert loads(current["draft_fields_json"], {})["priorityId"] == 3
    assert [t["hub_id"] for t in loads(current["targets_json"], [])] == ["2"]
    p = db._one("SELECT * FROM hub_sync_pending WHERE entity_kind='defect'")
    assert loads(p["payload_json"], {})["values"]["summary"] == "Моя правка"
    history = loads(db._one("SELECT before_json FROM hub_sync_applications WHERE entity_kind='defect'")["before_json"], {})
    assert history["base"] == body
    assert history["local"]["members"][0]["targets"][0][0] == "1"
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    pull.restore(db, target, p["id"], pull.pending_context(db, target, p["id"])["confirmation"])
    assert db.hub_defect(old["id"])["draft_summary"] == "Моя правка"


def test_new_and_absent_objects_are_retained_then_repeat_matches(store):
    db, pid = store
    hub = PullHub()
    accept(db, read(store, hub))
    original_id = finding(db, pid)["id"]
    hub.issues.clear()
    hub.defects.clear()
    rid = read(store, hub)
    result = accept(db, rid)
    assert not result["skipped"]
    assert finding(db, pid)["id"] == original_id and finding(db, pid)["missing"] == 1
    assert db._one("SELECT * FROM hub_issue_states")["confirmed_presence"] == "absent"
    assert db._scalar("SELECT COUNT(*) FROM hub_defects") == 1
    assert "Отсутствует" in db._one("SELECT * FROM hub_defects")["error"]
    second = read(store, hub)
    assert sync.passport(run(db, second))["matches_snapshot"]


@pytest.mark.parametrize("status", ["Fixed", "Confirmed", "False Positive", "Accepted risk"])
def test_second_sync_after_apply_matches_without_changes(store, status):
    db, pid = store
    hub = PullHub()
    hub.issues[1]["status"] = status
    hub.issues[1]["issueBranchBriefData"][0]["status"] = status
    if status in ("False Positive", "Accepted risk"):
        hub.decision(1, status)
    accept(db, read(store, hub))
    rid = read(store, hub)
    assert sync.passport(run(db, rid))["matches_snapshot"], db._all("SELECT diff_json FROM hub_sync_items WHERE run_id=?", (rid,))
    assert compare.snapshot_current(db, run(db, rid))
    review = db.get_review(pid, "1")
    if status == "Accepted risk":
        assert review["final_comment"] == "Основание риска Hub" and review["kapo_state"] == ""


def test_stale_local_edit_and_stale_base_reject_atomically(store):
    db, pid = store
    hub = PullHub()
    rid = read(store, hub)
    token = pull.preview(db, run(db, rid))["token"]
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    with pytest.raises(ValueError, match="Локальные данные"):
        pull.apply(db, rid, token)
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")
    compare.recompare(db, rid)
    token = pull.preview(db, run(db, rid))["token"]
    with db._tx() as c:
        c.execute("INSERT INTO hub_entity_versions VALUES (?,?,7,'issue','SAST:1',1,'changed','{}')", (pid, HUB))
    with pytest.raises(ValueError, match="база изменилась"):
        pull.apply(db, rid, token)
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")


def test_failure_mid_apply_rolls_back_every_entity(store, monkeypatch):
    db, _ = store
    rid = read(store, PullHub())
    def fail(*args):
        raise RuntimeError("Проверка отката")
    monkeypatch.setattr(pull, "accept_defect", fail)
    with pytest.raises(RuntimeError, match="Проверка отката"):
        accept(db, rid)
    assert not db._all("SELECT * FROM findings ORDER BY 1, 2")
    assert not db._all("SELECT * FROM reviews ORDER BY 1, 2")
    assert not db._all("SELECT * FROM imports ORDER BY 1, 2")
    assert not db._all("SELECT * FROM hub_entity_versions ORDER BY 1, 2")
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")
    assert not run(db, rid)["applied_at"]


def test_new_local_draft_and_unsent_decision_stay_pending(store):
    db, pid = store
    hub = PullHub(defects=False)
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Не отправлено", reviewed=False)
    with db._tx() as c:
        ident = c.execute("INSERT INTO hub_defects(project_id,kind,state,draft_summary,created_at,updated_at)"
                          " VALUES (?,'SAST','preview','Новый черновик','','')" " RETURNING id", (pid,)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id=id WHERE id=?", (ident,))
    before = db.hub_defect(ident)
    rid = read(store, hub)
    accept(db, rid)
    assert db.hub_defect(ident) == before
    # dev15: в Hub находка исправлена (Fixed) – решение туда не уйдёт, после принятия приложение равно Hub;
    # решение оператора – в истории. Черновик нового дефекта не трогается.
    review = db.get_review(pid, "1")
    assert review["final_comment"] == "" and review["final_verdict"] == ""
    saved = db._one("SELECT * FROM hub_sync_pending")
    assert saved["state"] == "saved" and loads(saved["payload_json"], {})["local"]["review"]["final_comment"] == "Не отправлено"


def test_pending_page_links_current_hub_and_saved_intent(web):
    db = web.app.state.db
    pid = db.create_project("Демо намерения")
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    hub = PullHub(defects=False)
    accept(db, read((db, pid), hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Сохранить мою правку", reviewed=False)
    rid = read((db, pid), hub)
    accept(db, rid)
    pending = db._one("SELECT * FROM hub_sync_pending")
    page = web.client.get(f"/projects/{pid}/hub-pending/{pending['id']}")
    # dev15: Fixed – правка в истории («Сохранено до принятия»), заголовок страницы по состоянию (бэклог 89)
    assert page.status_code == 200 and "Сохранить мою правку" in page.text and "Fixed" in page.text
    assert "Сохранено до принятия состояния Hub" in page.text and "Ждёт отправки в Hub" not in page.text
    card = web.client.get(f"/projects/{pid}/findings/{finding(db, pid)['id']}")
    assert card.status_code == 200


def test_old_file_does_not_overwrite_accepted_api(store):
    db, pid = store
    db.set_settings({"hub_url": HUB})
    hub = PullHub(count=2, defects=False)
    accept(db, read(store, hub))
    db.save_import(pid, "old.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST", status="To verify",
                                                                           codebase="old", file="old.c", line=2, severity="low", snippet="old();")]))
    # Hub – источник истины о своём (статус – в hub_issue_states, присутствие); код, трасса и поля – из выгрузки
    assert loads(finding(db, pid)["data_json"], {})["status"] == "To verify"
    assert loads(db._one("SELECT confirmed_json FROM hub_issue_states WHERE issue_id='1'")["confirmed_json"], {})["detail"]["status"] == "Fixed"
    assert loads(finding(db, pid)["file_data_json"], {})["status"] == "To verify"
    assert finding(db, pid)["codebase"] == "old" and finding(db, pid)["severity"] == "low"
    assert loads(finding(db, pid)["data_json"], {})["snippet"] == "old();"
    assert finding(db, pid, "2")["missing"] == 0 and finding(db, pid, "2")["file_presence"] == "absent"


def test_confirmed_route_and_cards_show_hub_and_pending(web):
    db = web.app.state.db
    pid = db.create_project("Демо")
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB})
    hub = PullHub()
    hub.decision(1)
    rid = read((db, pid), hub)
    url = f"/projects/{pid}/hub-sync/{rid}"
    page = web.client.get(url)
    token = re.search(r'name="confirmation" value="([a-f0-9]+)"', page.text)[1]
    before = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    assert web.client.post(url + "/apply", data={"confirmation": token}, headers=ORIGIN).status_code == 409
    response = web.client.post(url + "/apply", data={"confirmation": token, "confirm": "yes"}, headers=ORIGIN)
    assert response.status_code == 200 and 'id="hub-sync-matches"' in response.text
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before
    card = web.client.get(f"/projects/{pid}/findings/{finding(db, pid)['id']}")
    assert card.status_code == 200 and "Основание Hub" in card.text
    assert db.get_review(pid, "1")["entered_hub"] == 1
    defect = db._one("SELECT id FROM hub_defects")
    card = web.client.get(f"/projects/{pid}/defects/{defect['id']}")
    assert card.status_code == 200 and "ID9 - Демо" in card.text


@pytest.mark.parametrize("hub_status", ["To verify", "False Positive"])
def test_apply_never_overwrites_application_analysis(store, hub_status):
    """«Принять состояние Hub» не затирает данные находки, срезы разбора (вердикты модели) и
    «Проверено». Hub – источник истины только о своём: решение Hub (ложное срабатывание, риск) с
    основанием и сроком и присутствие; код, срез, вердикт модели, проверка кода и «Проверено» – приложения."""
    db, pid = store
    db.set_settings({"hub_url": HUB})
    db.save_import(pid, "file.csv", "csv", [], {}, [], order_findings([Finding(
        hub_id="1", kind="SAST", status="To verify", codebase="file-base", file="src/file.c", line=7,
        severity="high", snippet="danger(x);", rule="Rule")]))
    with db._tx() as c:
        vid = c.execute("INSERT INTO verdicts(case_hash,model,prompt_version,verdict,data_json,created_at)"
                        " VALUES ('h','m','p','true_positive','{}','')" " RETURNING id").fetchone()[0]
        c.execute("INSERT INTO cases(project_id,hub_id,case_hash,context_json,verdict_id,updated_at)"
                  " VALUES (?,?,?,?,?,'')", (pid, "1", "h", "{}", vid))
    db.save_review(pid, "1", decision="agree", final_verdict="true_positive", final_comment="Мой разбор", reviewed=True)
    with db._tx() as c:
        c.execute("UPDATE reviews SET verdict_id=?,code_hash='abc',code_chars=10 WHERE project_id=? AND hub_id='1'", (vid, pid))
    before_finding = dict(finding(db, pid))
    before_review = dict(db.get_review(pid, "1"))
    hub = PullHub(defects=False)
    hub.issues[1]["status"] = hub_status
    hub.issues[1]["issueBranchBriefData"][0]["status"] = hub_status
    if hub_status == "False Positive":
        hub.decision(1, hub_status, "Основание Hub")
    accept(db, read(store, hub))
    after = dict(finding(db, pid))
    assert after["data_json"] == before_finding["data_json"] and after["codebase"] == "file-base"
    assert db._one("SELECT verdict_id FROM cases WHERE project_id=? AND hub_id='1'", (pid,))["verdict_id"] == vid
    review = db.get_review(pid, "1")
    for key in ("reviewed", "verdict_id", "code_hash", "code_chars"):
        assert review[key] == before_review[key], key
    if hub_status == "To verify":  # в Hub решения нет – решение оператора не трогается
        assert review["decision"] == "agree" and review["final_comment"] == "Мой разбор"
    else:  # решение Hub – источник истины для решения, основание и срок из Hub
        assert review["decision"] == "hub" and review["final_verdict"] == "false_positive"
        assert review["final_comment"] == "Основание Hub"


def test_final_review_round_hub_decision_lifecycle(store):
    """Ревью 30.10: равное решение Hub не переписывается; снятое в Hub решение (принятое из Hub) снимается без потери
    разбора; отпечаток прежнего текста не держит ложное «в Hub прежний текст»."""
    db, pid = store
    hub = PullHub(defects=False)
    hub.decision(1, "False Positive", "Основание A")
    accept(db, read(store, hub))
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed=1,code_hash='abc',entered_text_hash='old' WHERE project_id=? AND hub_id='1'", (pid,))
    first = db.get_review(pid, "1")
    assert first["decision_origin"] == "hub_sync" and first["final_comment"] == "Основание A"
    accept(db, read(store, hub))  # без изменений в Hub
    same = db.get_review(pid, "1")
    assert same["revision"] == first["revision"] and same["entered_text_hash"] == "old"
    hub.decision(1, "False Positive", "Основание B")
    accept(db, read(store, hub))
    changed = db.get_review(pid, "1")
    assert changed["final_comment"] == "Основание B" and changed["entered_text_hash"] == ""
    assert changed["reviewed"] == 1 and changed["code_hash"] == "abc"
    hub.issues[1]["status"] = hub.issues[1]["issueBranchBriefData"][0]["status"] = "To verify"
    hub.manual.pop(1)
    accept(db, read(store, hub))
    cleared = db.get_review(pid, "1")
    assert cleared["decision"] == "" and cleared["final_verdict"] == "" and not cleared["entered_hub"]
    assert cleared["reviewed"] == 1 and cleared["code_hash"] == "abc"


def test_saved_edit_is_restorable_after_hub_decision_withdrawn(store):
    """Дельта-ревью 30.10: решение Hub снято после сохранения неотправленной правки – правка возвращается в редактор."""
    db, pid = store
    hub = PullHub(defects=False)
    hub.decision(1, "False Positive", "Основание A")
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Правка B", reviewed=True)
    hub.decision(1, "False Positive", "Основание C")
    accept(db, read(store, hub))
    assert db.get_review(pid, "1")["final_comment"] == "Основание C"
    hub.issues[1]["status"] = hub.issues[1]["issueBranchBriefData"][0]["status"] = "To verify"
    hub.manual.pop(1)
    accept(db, read(store, hub))
    assert db.get_review(pid, "1")["decision"] == ""
    pending = db._one("SELECT * FROM hub_sync_pending WHERE state='saved'")  # dev15: история до принятия
    assert loads(pending["payload_json"], {})["local"]["review"]["final_comment"] == "Правка B"
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    pull.restore(db, target, pending["id"], pull.pending_context(db, target, pending["id"])["confirmation"])
    review = db.get_review(pid, "1")
    assert review["final_comment"] == "Правка B" and review["decision_origin"] == "operator" and review["reviewed"] == 1


def test_operator_decision_still_blocks_restore(store):
    db, pid = store
    hub = PullHub(defects=False)
    hub.decision(1)
    accept(db, read(store, hub))
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Правка B", reviewed=False)
    hub.decision(1, "False Positive", "Основание C")
    accept(db, read(store, hub))
    pending = db._one("SELECT * FROM hub_sync_pending WHERE state='saved'")  # dev15: история до принятия
    db.save_review(pid, "1", decision="agree", final_verdict="true_positive", final_comment="Новое решение", reviewed=False)
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    with pytest.raises(ValueError, match="локальное решение"):
        pull.restore(db, target, pending["id"], pull.pending_context(db, target, pending["id"])["confirmation"])
    assert db.get_review(pid, "1")["final_comment"] == "Новое решение"
