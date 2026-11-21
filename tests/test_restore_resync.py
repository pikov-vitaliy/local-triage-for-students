"""После восстановления копии: незавершённый дефект снят, путь назад один – «Синхронизировать» (ADR-0128, п. 9). Сценарии второго ревьюера, круг 7."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
from test_hub_defects import AS_JSON, HUB, HUB_DESCRIPTION, blank, create, hello, sast_ready, shown, to_preview
from test_web import web  # noqa: F401

from app import hub_defects, hub_ops, hub_pull, hub_sync, hub_sync_api
from app.db import HubResyncRequired, loads
from app.hub_status import HUB_ISSUE_TYPE


def brief(defect: dict) -> dict:
    """Краткий вид из tests/hub_sync_contract_examples.json, раздел defects."""
    return {"id": defect["id"], "app": {"id": 7, "name": "Демо"}, "summary": defect["summary"], "status": "Registered",
            "priority": {"name": "Major", "rank": 2}, "severity": {"name": "Medium", "rank": 2}, "source": "Tool", "tool": "x", "stage": "DEV",
            "externalBugs": [], "isActive": True, "createTs": 0, "updateTs": 0, "author": {"id": 1, "fullName": "Иван Тестов"}, "syncStatus": "None",
            "structureUnit": {"id": 1, "name": "x"}, "releaseObject": {"id": 1, "name": "x"}, "linkedIssuesStatusAlert": False}


def defect_of(row: dict, number: int = 777) -> dict:
    """Дефект, созданный в Hub уже после копии, с теми же находками."""
    return {"id": number, "appId": 7, "summary": row["summary"], "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION),
            "status": "Registered", "priority": {"name": "Major", "rank": 2}, "priorityId": 2, "severity": {"name": "Medium", "rank": 2}, "severityId": 2,
            "source": "Tool", "tool": "x", "stage": "DEV", "type": "Software", "externalBugs": [], "isActive": True, "createTs": 0, "updateTs": 5,
            "author": {"id": 1, "fullName": "Иван Тестов"}, "withIssues": True, "linkedIssuesStatusAlert": False,
            "linkedIssues": [{"id": 510001, "type": "SAST", "status": "Open"}]}


class Hub:
    """Ответы общей синхронизации: форма PullHub из tests/test_hub_pull.py, находки – из проекта."""

    def __init__(self, db, pid: int, defect: dict | None):
        self.types = {int(r["hub_id"]): HUB_ISSUE_TYPE[r["kind"]] for r in db._all("SELECT hub_id, kind FROM findings WHERE project_id=?", (pid,))}
        self.defect = defect
        self.manual: dict[int, dict] = {}

    def issue(self, ident: int) -> dict:
        return {"id": ident, "appId": 7, "status": "To verify", "state": "Existing", "severity": 2, "severityDisplayName": "Medium", "currentBranch": "main",
                "fileName": "demo.c", "lineNumber": "12", "language": "C", "tool": "Demo", "category": {"category": "Demo rule", "cwes": [{"id": "CWE-20"}]},
                "codebase": {"id": 3, "name": "demo", "defaultBranch": "main"}, "updateTs": 1800000000000, "scanTs": 1800000000000,
                "issueBranchBriefData": [{"branch": "main", "status": "To verify", "isBranchDefault": True, "lastSeen": 1800000000000}],
                **({"status": self.manual[ident]["status"]} if ident in self.manual else {})}

    def answer(self, request: dict) -> tuple[int, str]:
        path = urlsplit(request["path"])
        if path.path in ("/issue/v2", "/defects"):
            if path.path == "/issue/v2":
                entries = [{"id": i, "appId": 7, "type": kind, "currentBranch": "main", "status": "To verify", "severity": 2,
                            "scanObject": {"id": 3, "name": "demo", "type": kind, "url": None}} for i, kind in self.types.items()]
            else:
                entries = [brief(self.defect)] if self.defect else []
            query = parse_qs(path.query)
            index, size = int(query["pageIndex"][0]), int(query["pageSize"][0])
            return 200, json.dumps({"filteredEntities": entries[index * size:(index + 1) * size], "totalEntitiesCount": len(entries)}, ensure_ascii=False)
        if path.path == "/issue/status":
            manual = self.manual.get(int(parse_qs(path.query)["issueId"][0]))
            return 200, json.dumps(manual, ensure_ascii=False) if manual else ""
        if path.path.endswith("/riskAcceptance"):
            return 200, ""
        if path.path.startswith("/defects/"):
            return 200, json.dumps(self.defect, ensure_ascii=False)
        return 200, json.dumps(self.issue(int(path.path.rsplit("/", 1)[-1])), ensure_ascii=False)


def full_sync(db, pid: int, hub: Hub) -> tuple[int, str]:
    run = hub_sync.start(db, pid, HUB, 7, adapter=hub_sync_api.ADAPTER)
    for _ in range(2000):
        state = db._one("SELECT state FROM hub_defect_sync_runs WHERE id=?", (run,))["state"]
        if state not in hub_sync.ACTIVE:
            return run, state
        got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
        assert got, state
        status, body = hub.answer(loads(got["op"]["request_json"], {}))
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"], {"status": status, "body_text": body, "error": "", "truncated": False})
    raise AssertionError("синхронизация не закончилась")


def accept(db, run: int) -> None:
    preview = hub_pull.preview(db, db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (run,)))
    hub_pull.apply(db, run, preview["token"])


def writes(db) -> list[dict]:
    return [op for op in db._all("SELECT id, purpose, state FROM hub_ops ORDER BY id") if hub_ops.is_write(op["purpose"]) and op["state"] != "cancelled"]


def in_state(web, pid: int, url: str, state: str) -> dict:  # noqa: F811
    if state == "blank":
        assert blank(web, url).status_code == 200
        return web.app.state.db._one("SELECT * FROM hub_defects ORDER BY id DESC LIMIT 1")
    row = to_preview(web, pid, url)
    if state == "creating":
        assert create(web, pid, row["id"]).status_code == 200
    return web.app.state.db.hub_defect(row["id"])


@pytest.mark.parametrize("state", ["blank", "preview", "creating"])
def test_defect_created_after_copy_returns_by_sync_as_one_row(web, state):  # noqa: F811
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    stale_form = shown(web, url)  # карточка, открытая до восстановления
    row = in_state(web, pid, url, state)
    assert row["state"] == state
    db.settle_after_restore()
    assert db.hub_defect(row["id"])["state"] == "cancelled"
    assert writes(db) == [] and db.hub_unknown_writes() == 0

    refused = blank(web, url, stale_form)
    assert refused.status_code >= 400 and "Синхронизировать" in refused.text, "до синхронизации новый дефект не начать"
    with pytest.raises(HubResyncRequired):
        db.set_hub_write_paused(False)

    fresh = db.hub_defect(row["id"])
    run, finished = full_sync(db, pid, Hub(db, pid, defect_of(fresh)))
    assert finished == "ready"
    assert db.on_connection(hub_sync.resync_pending_in) == [pid], "конец прохода ещё ничего не занёс в базу"
    with pytest.raises(HubResyncRequired):
        db.set_hub_write_paused(False)
    assert blank(web, url, stale_form).status_code >= 400
    accept(db, run)
    assert db.on_connection(hub_sync.resync_pending_in) == []

    live = db._all("SELECT id, state, origin, hub_defect_id FROM hub_defects WHERE state NOT IN ('cancelled', 'failed')")
    assert [r["hub_defect_id"] for r in live] == ["777"], "одна живая строка"
    assert writes(db) == [], "в Hub ничего не записано"
    db.set_hub_write_paused(False)
    assert not db.hub_write_paused()


def test_new_defect_after_sync_when_hub_has_none(web):  # noqa: F811
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    to_preview(web, pid, url)
    db.settle_after_restore()
    run, finished = full_sync(db, pid, Hub(db, pid, None))
    assert finished == "ready"
    if db.on_connection(hub_sync.resync_pending_in):
        accept(db, run)
    assert db.on_connection(hub_sync.resync_pending_in) == []
    assert blank(web, url).status_code == 200, "в Hub дефекта нет: заготовка запрашивается заново"


def test_sync_before_restore_does_not_count(web):  # noqa: F811
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    stale_form = shown(web, url)
    run, finished = full_sync(db, pid, Hub(db, pid, None))
    assert finished == "ready"
    db.settle_after_restore()
    assert db.on_connection(hub_sync.resync_pending_in) == [pid]
    with db._tx() as c:  # тот же прежний проход, сравнение пересчитано: признак не снимается
        row = hub_sync.run_in(c, run)
        c.execute("UPDATE settings SET value_json = ? WHERE key = ?", (json.dumps({"since": "9999", "projects": [pid]}), hub_sync.RESYNC_KEY))
        hub_sync.resync_done_in(c, row)
    assert db.on_connection(hub_sync.resync_pending_in) == [pid]
    assert blank(web, url, stale_form).status_code >= 400


def test_operator_can_resume_when_sync_is_impossible(web):  # noqa: F811
    sast_ready(web)
    db = web.app.state.db
    db.settle_after_restore()
    db.set_hub_write_paused(False, accept_unknown=True)
    assert not db.hub_write_paused() and db.on_connection(hub_sync.resync_pending_in) == []


def test_status_from_copy_does_not_block_accept(web):  # noqa: F811
    """Статус с неизвестным исходом в копии: снят; принятие Hub не закрыто, повторно не выдаётся."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    with db._tx() as c:
        for number, state in enumerate(("queued", "taken", "unknown"), start=1):
            c.execute("INSERT INTO hub_ops(project_id, app_id, purpose, op_key, request_json, targets_json, hub_url, state, created_at, updated_at)"
                      " VALUES (?, 7, 'status', ?, '{}', '[]', ?, ?, 'x', 'x')", (pid, f"s{number}", HUB, state))
    assert db.settle_after_restore()["cancelled"] == 3
    assert writes(db) == [] and db.hub_unknown_writes() == 0
    run, finished = full_sync(db, pid, Hub(db, pid, None))
    assert finished == "ready"
    accept(db, run)
    assert db.on_connection(hub_sync.resync_pending_in) == []


def test_accepted_hub_state_returns_the_mark_of_a_cancelled_status(web):  # noqa: F811
    """Решение совпало с Hub: статус из копии снят, но Hub его выполнил. Принятие возвращает отметку и ничего не ставит."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE reviews SET decision='hub', final_verdict='false_positive', final_comment='Основание Hub', desired_hub_expired_at=NULL,"
                  " entered_hub=0 WHERE project_id=? AND hub_id='510001'", (pid,))
        c.execute("INSERT INTO hub_ops(project_id, app_id, purpose, op_key, request_json, targets_json, hub_url, state, created_at, updated_at)"
                  " VALUES (?, 7, 'status', 's', '{}', '[]', ?, 'taken', 'x', 'x')", (pid, HUB))
    db.settle_after_restore()
    hub = Hub(db, pid, None)
    hub.manual[510001] = {"id": 1, "issueId": 510001, "issueType": "SAST", "status": "False Positive", "oldStatus": "To verify",
                          "reason": "Основание Hub", "conditionalCategory": None, "changedBy": "demo", "createTs": 1800000000000, "expiredAt": None}
    run, finished = full_sync(db, pid, hub)
    assert finished == "ready"
    accept(db, run)
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 1 and review["entered_origin"] == "hub_sync"
    assert writes(db) == []


def test_status_and_put_routes_refuse_until_hub_state_is_accepted(web):  # noqa: F811
    """Новая запись при признаке не ставится: статус одной находки, групповая отправка, `PUT`."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    db.settle_after_restore()
    before = db._scalar("SELECT COUNT(*) FROM hub_ops")
    single = web.client.post(f"{url}/hub-status", headers=AS_JSON, data={"status": "False Positive", "comment": "текст", "expires": "2030-01-01"})
    assert single.status_code >= 400 and "Синхронизировать" in single.text
    bulk = web.client.post(f"/projects/{pid}/hub/send-selected", headers=AS_JSON, data={"target": "510001|1|x", "comment": "текст", "expires": "2030-01-01"})
    assert bulk.status_code >= 400 and "Синхронизировать" in bulk.text
    put = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/update-put", headers=AS_JSON, data={"generation": "1", "shown": "x"})
    assert put.status_code >= 400 and "Синхронизировать" in put.text
    assert db._scalar("SELECT COUNT(*) FROM hub_ops") == before


def test_mismatch_row_stays_and_does_not_hold_the_mark(web):  # noqa: F811
    """«Привязка неполная» – дефект уже создан и держит находки: строка остаётся одна, второго дефекта не будет, признак снимается."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert db.hub_defect_update(row["id"], state="mismatch", hub_defect_id="777", error="привязаны не все находки") is not None
    db.settle_after_restore()
    assert db.hub_defect(row["id"])["state"] == "mismatch"
    run, finished = full_sync(db, pid, Hub(db, pid, defect_of(db.hub_defect(row["id"]))))
    assert finished == "ready"
    if db.on_connection(hub_sync.resync_pending_in):
        accept(db, run)
    assert db.on_connection(hub_sync.resync_pending_in) == []
    assert [r["id"] for r in db._all("SELECT id FROM hub_defects WHERE state NOT IN ('cancelled', 'failed')")] == [row["id"]]
    assert writes(db) == []


def test_known_defect_is_of_the_same_hub_and_application(web):  # noqa: F811
    """Тот же номер в другом Hub или приложении – другой дефект; предпросмотр занесения и находка в составе без своей строки пропуск не оправдывают."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert db.hub_defect_update(row["id"], state="mismatch", hub_defect_id="777") is not None
    defect = defect_of(db.hub_defect(row["id"]))
    run, _ = full_sync(db, pid, Hub(db, pid, defect))
    item = {"kind": "defect", "key": "777"}
    with db._tx() as c:
        current = hub_sync.run_in(c, run)
        assert hub_sync._known_defect_in(c, current, item)
        assert not hub_sync._known_defect_in(c, {**current, "hub_url": "https://other.example"}, item)
        assert not hub_sync._known_defect_in(c, {**current, "app_id": 8}, item)
        assert not hub_sync._known_defect_in(c, current, {"kind": "issue", "key": "777"})
        c.execute("UPDATE hub_defects SET state = 'import_preview' WHERE id = ?", (row["id"],))
        assert not hub_sync._known_defect_in(c, current, item), "предпросмотр занесения находки не держит"


def test_defect_with_unheld_finding_keeps_the_mark(web):  # noqa: F811
    """Привязка ушла в Hub после копии, её строка снята: находка свободна, а в Hub уже в дефекте. Дефект не считается известным, признак остаётся."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert db.hub_defect_update(row["id"], state="mismatch", hub_defect_id="777") is not None
    defect = defect_of(db.hub_defect(row["id"]))
    defect["linkedIssues"].append({"id": 510002, "type": "SAST", "status": "Open"})
    db.settle_after_restore()
    run, finished = full_sync(db, pid, Hub(db, pid, defect))
    assert finished == "ready"
    try:
        accept(db, run)
    except ValueError:  # принимать, кроме пропущенного дефекта, может быть нечего
        pass
    assert db.on_connection(hub_sync.resync_pending_in) == [pid]
    with pytest.raises(HubResyncRequired):
        db.set_hub_write_paused(False)


def test_failed_read_of_defect_keeps_the_mark(web):  # noqa: F811
    """Чтение дефекта не удалось: он в базу не занесён, новый стал бы вторым. Признак остаётся и после принятия остального."""
    pid, url = sast_ready(web)
    hello(web)
    db = web.app.state.db
    stale_form = shown(web, url)
    row = to_preview(web, pid, url)
    db.settle_after_restore()
    hub = Hub(db, pid, defect_of(db.hub_defect(row["id"])))
    real = hub.answer
    hub.answer = lambda request: (500, "") if urlsplit(request["path"]).path.startswith("/defects/") else real(request)
    run, finished = full_sync(db, pid, hub)
    assert finished == "ready"
    accept(db, run)
    assert db.on_connection(hub_sync.resync_pending_in) == [pid]
    with pytest.raises(HubResyncRequired):
        db.set_hub_write_paused(False)
    assert blank(web, url, stale_form).status_code >= 400


def test_pages_say_what_to_do_after_restore(web):  # noqa: F811
    pid, url = sast_ready(web)
    db = web.app.state.db
    db.settle_after_restore()
    assert 'id="hub-write-accept-unknown"' in web.client.get("/settings").text
    assert 'id="defects-resync-note"' in web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-defect-blocker"' in web.client.get(url).text


def test_project_without_hub_application_is_not_waited_for(web):  # noqa: F811
    pid, url = sast_ready(web)
    db = web.app.state.db
    db.settle_after_restore()
    assert db.on_connection(hub_sync.resync_pending_in) == [pid]
    with db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = NULL WHERE id = ?", (pid,))
    assert db.on_connection(hub_sync.resync_pending_in) == []
    db.set_hub_write_paused(False)
    assert not db.hub_write_paused()


def test_restore_without_projects_clears_the_old_mark(web):  # noqa: F811
    pid, url = sast_ready(web)
    db = web.app.state.db
    db.settle_after_restore()
    with db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = NULL")
    db.settle_after_restore()
    assert db._scalar("SELECT COUNT(*) FROM settings WHERE key = ?", (hub_sync.RESYNC_KEY,)) == 0
