"""Сквозная проверка «новый проект с нуля» (0.10.0.dev14: синхронизация – чтобы обе базы были
идентичны; ошибки этого класса не должны возникать на новых проектах). Поддельный Hub хранит состояние и принимает
записи статуса, как настоящий. Инвариант (синхронизация = чтение + «Принять состояние Hub», ADR-0127): после синхронизации следующее
чтение без изменений – «совпадает», без «ждёт отправки», «конфликт», «изменено»; своя запись статуса после чтения
показывается совпавшим изменением (не расхождением), а после принятия – «совпадает»; правка без отправки даёт ровно
одно «ждёт отправки». Данные выдуманные."""

import json
from datetime import datetime, timezone

from app import hub_onboarding, hub_pull as pull, hub_sync as sync, hub_sync_api as api
from app.db import loads
from test_hub_pull import PullHub
from test_hub_status_routes import HUB, REASON, decide, project, sast, send
from test_hub_sync import run
from test_web import web  # noqa: F401


class LiveHub(PullHub):
    """PullHub с записью статуса: POST /issue/status/update меняет статус и ручную запись находки, как Hub."""

    def __init__(self, count=3):
        super().__init__(count, defects=False)
        for issue in self.issues.values():
            issue["status"] = "To verify"
            issue["issueBranchBriefData"][0]["status"] = "To verify"
        self.writes = []

    def answer(self, request):
        if request["method"] == "POST" and request["path"] == "/issue/status/update":
            body = request["body"]
            self.writes.append(body)
            targets = body.get("issues") or [{"issueId": body["issueId"], "issueType": body["issueType"]}]
            for t in targets:
                self.decision(int(t["issueId"]), status=body["status"], reason=body["reason"])
                if body.get("expiredAt"):
                    stamp = datetime.fromisoformat(body["expiredAt"].replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
                    self.manual[int(t["issueId"])]["expiredAt"] = int(stamp.timestamp() * 1000)
            return 200, json.dumps({"id": 1, "status": body["status"]}, ensure_ascii=False)
        return super().answer(request)


def drain(db, hub):
    """Исполнитель: выполнить всё, что стоит в очереди, против поддельного Hub."""
    for _ in range(5000):
        got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
        if not got:
            return
        status, body = hub.answer(loads(got["op"]["request_json"], {}))
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                      {"status": status, "body_text": body, "error": "", "truncated": False})


def synced(db, pid, hub):
    """Прочитать Hub целиком и вернуть прогон."""
    open_run = db._one("SELECT id, revision FROM hub_defect_sync_runs WHERE project_id=? AND closed_at IS NULL", (pid,))
    previous = (open_run["id"], open_run["revision"]) if open_run else None
    rid = sync.start(db, pid, HUB, 7, adapter=api.ADAPTER, previous=previous)
    drain(db, hub)
    row = run(db, rid)
    assert row["state"] == "ready", sync.passport(row)
    return row


def groups(db, row):
    out = {}
    for item in db._all("SELECT entity_key, diff_json FROM hub_sync_items WHERE run_id=?", (row["id"],)):
        for g in loads(item["diff_json"], {}).get("groups", []):
            out.setdefault(g, []).append(item["entity_key"])
    return out


def accept(db, row):
    preview = pull.preview(db, row)
    if preview.get("count"):
        pull.apply(db, row["id"], preview["token"])


def synchronize(db, pid, hub):
    """Синхронизация, как её делает оператор: чтение и «Принять состояние Hub»; вернуть прочитанный прогон."""
    row = synced(db, pid, hub)
    accept(db, row)
    return row


def assert_synced(db, row, accepted=None, skipped=(), unsent=(), sent=()):
    """Инвариант dev15: после команды синхронизации с Hub расхождений
    быть не должно. Сначала – ожидаемый состав принятых и пропущенных
    объектов (пропуск проблемного объекта не прячет остаток), затем у каждого принятого – только «совпадает» с пустыми
    полями отличий и без действующих сохранённых правок; «не отправлено» – только у названных в unsent (решение
    оператора при Hub без решения, с доказанным исходящим намерением); «Отправлено в Hub» с отличием рядом – только у
    названных в sent (доставленное решение, которое Hub потом снял). Итог принятия без
    остатка."""
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    assert sorted(s["key"] for s in result.get("skipped", [])) == sorted(skipped), result.get("skipped")
    applied = {r["entity_key"] for r in db._all("SELECT entity_key FROM hub_sync_applications WHERE run_id=?", (row["id"],))}
    if accepted is None:
        # по умолчанию принят каждый объект прогона, кроме названных пропусков (ревью кода dev15, круг 1: пропуск
        # проблемного объекта не должен прятать остаток)
        accepted = {r["entity_key"] for r in db._all("SELECT entity_key FROM hub_sync_items WHERE run_id=?", (row["id"],))
                    if not r["entity_key"].startswith("local:")} - set(skipped)
    assert applied == set(accepted), (sorted(applied), sorted(accepted))
    assert applied, "принятых объектов нет"
    for item in db._all("SELECT entity_key,diff_json FROM hub_sync_items WHERE run_id=?", (row["id"],)):
        if item["entity_key"] not in applied:
            continue
        diff = loads(item["diff_json"], {})
        if item["entity_key"] in unsent:
            assert diff["groups"] == ["pending"], (item["entity_key"], diff)
            continue
        if item["entity_key"] in sent:
            assert diff["groups"] == ["local_only"] and diff["delivery"]["state"] == "sent", (item["entity_key"], diff)
            continue
        assert diff["groups"] == ["matched"] and diff.get("fields", []) == [], (item["entity_key"], diff)
    live = [p["entity_key"] for p in db._all("SELECT entity_key FROM hub_sync_pending WHERE project_id=?"
                                             " AND state IN ('pending','restored')", (row["project_id"],))]
    assert not set(live) & (applied - set(unsent)), live
    assert result.get("residue", []) == [], result.get("residue")


def test_new_project_decide_send_sync_matches(web):
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2"), sast("3")])
    first = synced(db, pid, hub)
    accept(db, first)
    second = synced(db, pid, hub)
    assert sync.passport(second)["matches_snapshot"], groups(db, second)

    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    assert hub.writes and hub.writes[-1]["reason"] == REASON
    third = synchronize(db, pid, hub)
    assert_synced(db, third)  # своя запись – не расхождение
    fourth = synced(db, pid, hub)
    assert sync.passport(fourth)["matches_snapshot"], ("после синхронизации базы идентичны", groups(db, fourth))
    state = hub_onboarding.state(db, db.get_project(pid), HUB)
    assert state["state"] == "matches", state


def test_unsent_edit_is_exactly_one_pending_and_send_restores_match(web):
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2"), sast("3")])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    synchronize(db, pid, hub)
    assert sync.passport(synced(db, pid, hub))["matches_snapshot"]

    decide(web, pid, "1", comment="Новое обоснование оператора, ещё не отправленное.")
    row = synced(db, pid, hub)
    found = groups(db, row)
    assert found.get("pending") == ["SAST:1"], found
    assert not found.get("conflict") and not found.get("changed"), found

    r = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})  # «Обновить комментарий в Hub»: цепочка Confirmed → False Positive
    assert r.status_code == 200, r.text
    drain(db, hub)
    web.client.get(r.json()["status_url"])  # карточка опрашивает состояние – второй шаг цепочки встаёт в очередь
    drain(db, hub)
    assert [w["status"] for w in hub.writes[-2:]] == ["Confirmed", "False Positive"]
    assert_synced(db, synchronize(db, pid, hub))
    final = synced(db, pid, hub)
    assert sync.passport(final)["matches_snapshot"], groups(db, final)


def test_decision_on_finding_fixed_in_hub_is_unsendable_not_pending(web):
    """Hub после пересканирования поставил «Fixed», а решение оператора отправлено не было: это не «ждёт отправки»."""
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2"), sast("3")])
    synchronize(db, pid, hub)
    decide(web, pid, "2")
    hub.issues[2]["status"] = "Fixed"
    hub.issues[2]["issueBranchBriefData"][0]["status"] = "Fixed"
    row = synced(db, pid, hub)
    found = groups(db, row)
    assert found.get("unsendable") == ["SAST:2"] and not found.get("pending") and not found.get("conflict"), found


# ============================================================================ дефект: создание и синхронизация


class DefectHub(LiveHub):
    """LiveHub по находкам выгрузки проекта; заготовка и справочник дефекта, создание дефекта (Hub ставит связанным
    находкам Open вместо To verify и переформатирует описание – убирает переводы строк между тегами), чтение дефекта."""

    def __init__(self, db, pid):
        super().__init__(0)
        self.issues, self.types = {}, {}
        for f in db._all("SELECT hub_id, kind FROM findings WHERE project_id=?", (pid,)):
            typ = "SAST" if f["kind"] == "SAST" else "SCA_S"
            ident = int(f["hub_id"])
            self.types[ident] = typ
            self.issues[ident] = {**next(iter(PullHub(1).issues.values())), "id": ident, "status": "To verify",
                                  "issueBranchBriefData": [{"branch": "main", "status": "To verify", "isBranchDefault": True,
                                                            "lastSeen": 1800000000000}]}
        self.next_id = 900

    def answer(self, request):
        from test_hub_defects import BLANK, SERVICE
        from urllib.parse import parse_qs, urlsplit
        path = urlsplit(request["path"])
        if request["method"] == "GET" and path.path == "/issue/v2":
            status, body = super().answer(request)
            data = json.loads(body)
            for entry in data["filteredEntities"]:
                entry["type"] = self.types[entry["id"]]
            return status, json.dumps(data, ensure_ascii=False)
        if request["method"] == "GET" and path.path == "/defects/blank":
            ids = [int(i) for i in parse_qs(path.query)["issueIds"][0].split(",")]
            return 200, json.dumps({**BLANK, "linkedIssues": [{"id": i, "type": self.types[i]} for i in ids]},
                                   ensure_ascii=False)
        if request["method"] == "GET" and path.path == "/defects/serviceInfo":
            return 200, json.dumps(SERVICE, ensure_ascii=False)
        if request["method"] == "POST" and path.path == "/defects":
            body = request["body"]
            self.next_id += 1
            links = [{"id": li["id"], "type": li["type"], "appId": 7, "severity": 2, "lastScanTs": 1800000000000,
                      "scanObject": {"id": 3, "url": None}} for li in body["linkedIssues"]]
            self.defects[self.next_id] = {
                "id": self.next_id, "appId": 7, "summary": body["summary"],
                "description": body["description"].replace(">\n<", "><"), "status": "Open",
                "createTs": 1800000000000, "updateTs": 1800000000000, "priority": body.get("priority"),
                "priorityId": 1, "severity": body.get("severity"), "severityId": 2,
                "settings": {"isInheritedARStatusFromDefect": False, "isInheritedFPStatusFromDefect": False},
                "linkedIssues": links}
            for li in body["linkedIssues"]:
                self.issues[li["id"]]["status"] = "Open"
                self.issues[li["id"]]["issueBranchBriefData"][0]["status"] = "Open"
            return 200, json.dumps({"id": self.next_id})
        if request["method"] == "PUT" and path.path.startswith("/defects/"):
            ident = int(path.path.rsplit("/", 1)[-1])
            body = request["body"]
            self.defects[ident].update(summary=body["summary"], description=body["description"].replace(">\n<", "><"),
                                       updateTs=self.defects[ident]["updateTs"] + 1000)
            return 204, ""
        return super().answer(request)


def test_new_project_defect_created_then_sync_matches(web):
    """Новый проект: синхронизация, решение «Подтверждаю дефект», дефект создан в Hub (Hub ставит Open и
    переформатирует описание) – синхронизация без расхождений, следующее чтение «совпадает»."""
    from test_hub_defects import create, shown, sast_ready
    db = web.app.state.db
    pid, url = sast_ready(web)
    hub = DefectHub(db, pid)
    synchronize(db, pid, hub)
    from test_hub_status_routes import AS_JSON
    r = web.client.post(f"{url}/hub-defect", data=shown(web, url), headers=AS_JSON)
    assert r.status_code == 200, r.text
    drain(db, hub)
    web.client.get(r.json()["status_url"])
    row = db.hub_defect(r.json()["defect_id"])
    assert row["state"] == "preview", row
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    for _ in range(6):  # карточка опрашивает состояние – следующие шаги цепочки (чтение, привязка) встают в очередь
        drain(db, hub)
        web.client.get(f"/projects/{pid}/hub/defects/{row['id']}")
        if db.hub_defect(row["id"])["state"] == "done":
            break
    done = db.hub_defect(row["id"])
    assert done["state"] == "done", (done["state"], done["error"])
    third = synchronize(db, pid, hub)
    assert_synced(db, third)  # свой дефект – не расхождение
    fourth = synced(db, pid, hub)
    assert sync.passport(fourth)["matches_snapshot"], ("после синхронизации базы идентичны", groups(db, fourth))


def test_defect_push_with_hub_reformatting_then_sync_matches(web):
    """Правка текста дефекта и «Push в Hub» (Hub переформатирует описание) – синхронизация без расхождений."""
    from test_defect_dev1b import edit
    from test_hub_defect_update import act, form_fields
    from test_hub_defects import create, shown, sast_ready
    from test_hub_status_routes import AS_JSON
    db = web.app.state.db
    pid, url = sast_ready(web)
    hub = DefectHub(db, pid)
    synchronize(db, pid, hub)
    r = web.client.post(f"{url}/hub-defect", data=shown(web, url), headers=AS_JSON)
    drain(db, hub)
    web.client.get(r.json()["status_url"])
    row = db.hub_defect(r.json()["defect_id"])
    create(web, pid, row["id"], priority="Critical")
    for _ in range(6):
        drain(db, hub)
        web.client.get(f"/projects/{pid}/hub/defects/{row['id']}")
        if db.hub_defect(row["id"])["state"] == "done":
            break
    synchronize(db, pid, hub)
    current = db.hub_defect(row["id"])
    assert edit(web, pid, current, [], command_text=current["draft_command_text"] + "\n2) Дополнение оператора.").status_code in (200, 303)
    assert act(web, pid, row["id"], "update").status_code == 200
    drain(db, hub)
    web.client.get(f"/projects/{pid}/defects")
    assert act(web, pid, row["id"], "update-put", form_fields(web, pid, f"hub-update-put-form-{row['id']}")).status_code == 200
    for _ in range(6):
        drain(db, hub)
        web.client.get(f"/projects/{pid}/defects")
    assert "Дополнение оператора" in hub.defects[max(hub.defects)]["description"]
    third = synchronize(db, pid, hub)
    assert_synced(db, third)  # свой Push – не расхождение
    fourth = synced(db, pid, hub)
    assert sync.passport(fourth)["matches_snapshot"], ("после синхронизации базы идентичны", groups(db, fourth))


def test_hub_rescan_fixed_is_explained_change_then_accept_matches(web):
    """Hub сам ставит «Fixed» после пересканирования: чтение показывает «изменено в Hub» с причиной, не «ждёт
    отправки»; оператор принимает – следующее чтение «совпадает» (ADR-0127: изменения не скрываются)."""
    db = web.app.state.db
    hub = LiveHub(3)
    pid = project(web, [sast("1"), sast("2"), sast("3")])
    synchronize(db, pid, hub)
    hub.issues[2]["status"] = "Fixed"
    hub.issues[2]["issueBranchBriefData"][0]["status"] = "Fixed"
    second = synced(db, pid, hub)
    found = groups(db, second)
    assert found.get("changed") == ["SAST:2"] and not found.get("pending"), found
    item = db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:2'", (second["id"],))
    assert any("Hub изменил находку сам" in c for c in loads(item["diff_json"], {}).get("causes", [])), item
    accept(db, second)
    third = synced(db, pid, hub)
    assert sync.passport(third)["matches_snapshot"], groups(db, third)
