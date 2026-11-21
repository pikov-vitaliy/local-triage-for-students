"""Сверка номера приложения Hub с выгрузкой проекта в прогоне синхронизации (0.10.0.dev13):
если оператор внесёт неправильный номер, приложение должно это отработать. Без реальных данных."""

import re
from urllib.parse import urlsplit

from app import hub_sync as sync, hub_sync_api
from app.models import Finding
from app.triage import order_findings
from test_hub_sync import ADAPTER, HUB, FakeSyncHub, finish, run, store  # noqa: F401
from test_hub_defect_import import project
from test_web import ORIGIN, web  # noqa: F401


def export(db, pid, *ids, application="Демо"):
    findings = [Finding(hub_id=str(i), kind="SAST", application=application) for i in ids]
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings(findings))


def paths(hub):
    return [urlsplit(req["path"]).path for req in hub.calls]


def test_no_common_findings_stops_before_defects_and_details(store):
    db, pid = store
    hub = FakeSyncHub(30, 2)
    export(db, pid, 900001, 900002)
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    row = run(db, rid)
    check = sync.passport(row)["app_check"]
    assert row["state"] == "stopped", check
    assert check["status"] == "mismatch" and check["stop"] and check["common"] == 0 and check["export"] == 2
    assert check["hub"] == 30
    assert set(paths(hub)) == {"/issue/v2"}, "дефекты и подробности не читаются"
    assert not db._all("SELECT * FROM hub_defects ORDER BY 1") and not db._all("SELECT * FROM hub_issue_states ORDER BY 1")


def test_operator_confirmed_number_reads_everything(store):
    db, pid = store
    hub = FakeSyncHub(30, 2)
    export(db, pid, 900001)
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER, app_confirmed=True)
    finish(db, hub, rid)
    row = run(db, rid)
    check = sync.passport(row)["app_check"]
    assert row["state"] == "ready" and check["status"] == "mismatch" and not check["stop"] and check["confirmed"]
    assert "/defects" in paths(hub)


def test_common_findings_continue_and_are_reported(store):
    db, pid = store
    hub = FakeSyncHub(30, 1)
    sast = [i["id"] for i in hub.issues if i["type"] == "SAST"]
    export(db, pid, sast[0], sast[1], 900001)
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    check = sync.passport(run(db, rid))["app_check"]
    assert run(db, rid)["state"] == "ready"
    assert check["status"] == "match" and check["common"] == 2 and check["export"] == 3 and not check["stop"]


def test_different_name_with_common_findings_is_a_note_not_a_stop(store):
    db, pid = store
    hub = FakeSyncHub(10, 0)
    for issue in hub.issues:
        issue["appName"] = "Другое  имя"
    export(db, pid, hub.issues[0]["id"], application="Демо")
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    check = sync.passport(run(db, rid))["app_check"]
    assert run(db, rid)["state"] == "ready"
    assert check["names_differ"] and check["hub_names"] == ["Другое имя"] and check["export_names"] == ["Демо"]


def test_same_name_in_other_case_is_not_a_difference(store):
    db, pid = store
    hub = FakeSyncHub(4, 0)
    for issue in hub.issues:
        issue["application"] = {"id": 7, "name": "ДЕМО"}
    export(db, pid, hub.issues[0]["id"], application=" Демо ")
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    assert not sync.passport(run(db, rid))["app_check"]["names_differ"]


def test_without_export_skipped_and_empty_hub_is_a_mismatch(store):
    db, pid = store
    hub = FakeSyncHub(5, 0)
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    check = sync.passport(run(db, rid))["app_check"]
    assert run(db, rid)["state"] == "ready" and check["status"] == "skipped" and "выгрузке" in check["reason"]
    export(db, pid, 900001)
    sync.close(db, rid)
    empty = FakeSyncHub(0, 0)
    rid2 = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, empty, rid2)
    check = sync.passport(run(db, rid2))["app_check"]
    # пустой список Hub при непустой выгрузке: соответствие не установлено – остановка (ревью плана dev13, круг 2)
    assert run(db, rid2)["state"] == "stopped" and check["status"] == "mismatch" and check["hub"] == 0 and check["stop"]


def test_pages_show_mismatch_and_confirmation_carries_through(web, monkeypatch):
    monkeypatch.setattr(hub_sync_api, "ADAPTER", ADAPTER)
    pid = project(web)
    db = web.app.state.db
    confirm_page = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
    assert "Применение расхождений в этой сборке отсутствует" not in confirm_page.text
    assert "Принять состояние Hub" in confirm_page.text and 'name="app_confirmed"' not in confirm_page.text
    confirmed = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN, data={"app_confirmed": "yes"})
    assert 'id="hub-sync-app-confirmed"' in confirmed.text and 'name="app_confirmed" value="yes"' in confirmed.text
    plain = re.search(r'name="confirmation" value="([^"]+)"', confirm_page.text)[1]
    forged = web.client.post(f"/projects/{pid}/hub-sync/start", headers=ORIGIN,
                             data={"confirmation": plain, "confirm": "yes", "app_confirmed": "yes"})
    assert forged.status_code == 409, "флажок подтверждения номера – часть подтверждённого режима (ревью dev13)"
    assert not db._all("SELECT * FROM hub_defect_sync_runs ORDER BY 1")
    token = re.search(r'name="confirmation" value="([^"]+)"', confirmed.text)[1]
    started = web.client.post(f"/projects/{pid}/hub-sync/start", headers=ORIGIN,
                              data={"confirmation": token, "confirm": "yes", "app_confirmed": "yes"})
    assert started.status_code == 200, started.text
    row = db._one("SELECT * FROM hub_defect_sync_runs ORDER BY id DESC LIMIT 1")
    assert sync.passport(row)["app_confirmed"] is True
    with db._tx() as c:
        data = sync.passport(row)
        data["app_check"] = {"status": "mismatch", "stop": True, "common": 0, "export": 3, "hub": 5,
                             "hub_names": ["Чужое"], "export_names": ["Демо"], "confirmed": False, "names_differ": True}
        sync.save_run(c, row, data, "stopped")
    page = web.client.get(f"/projects/{pid}/hub-sync/{row['id']}").text
    assert 'id="hub-sync-app-check"' in page and "общих 0 из 3" in page and "«Чужое»" in page
    assert 'id="hub-sync-app-fix"' in page and 'id="hub-sync-app-confirm"' in page


def test_only_rows_of_latest_file_export_count(store):
    """Строки прежней выгрузки остаются в проекте с пометкой «нет в выгрузке» – принадлежность новой выгрузки номеру они
    не доказывают (ревью плана dev13, круг 2)."""
    db, pid = store
    hub = FakeSyncHub(20, 0)
    sast = [i["id"] for i in hub.issues if i["type"] == "SAST"]
    export(db, pid, sast[0], sast[1])
    export(db, pid, 900001, 900002)
    rid = sync.start(db, pid, HUB, 7, adapter=ADAPTER)
    finish(db, hub, rid)
    check = sync.passport(run(db, rid))["app_check"]
    assert run(db, rid)["state"] == "stopped" and check["common"] == 0 and check["export"] == 2
