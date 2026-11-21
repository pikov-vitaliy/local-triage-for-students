"""Подтверждение и совместимость работающего исполнителя после перезапуска приложения."""

import re

from app import hub_sync_api
from test_hub_sync import ADAPTER, FakeSyncHub, finish, step
from test_hub_defect_import import project
from test_hub_status_routes import worker_headers
from test_web import ORIGIN, web  # noqa: F401


def test_stale_defect_confirmation_keeps_base_and_draft_and_does_not_retry(web):
    from app import hub_defects, hub_entity_versions as versions
    from app.db import dumps, loads
    from test_hub_defect_update import ready, hub_body
    from test_hub_sync import HUB
    pid, row = ready(web, build=False)
    db = web.app.state.db
    op = db.hub_enqueue(purpose="defect_read", request={"method":"GET","path":"/defects/777"},
                        project_id=pid, hub_url=HUB, app_id=row["app_id"], targets=[])
    got = db.hub_claim("demo", HUB, 120)
    assert got["op"]["id"] == op["id"]
    with db._tx() as c:
        versions.accept(c, row, row["confirmed_object_json"], {"synthetic":"new-confirmation"})
    db.hub_defect_update(row["id"], verify_op_id=op["id"], body_html=hub_body()["description"])
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                  {"status":200,"body_text":dumps(hub_body())})
    before = db.hub_defect(row["id"])
    history = db._all("SELECT * FROM hub_defect_history ORDER BY id")
    result = hub_defects._conclude(db, before, db.hub_op(op["id"]), ("verify_op_id", op["id"]), "done", "")
    assert result["state"] == "unconfirmed" and "база изменилась" in result["error"]
    for key in ("confirmed_object_json", "draft_summary", "draft_command_text", "draft_fields_json", "draft_revision", "confirm_op_id"):
        assert result[key] == before[key]
    assert db._all("SELECT * FROM hub_defect_history ORDER BY id") == history
    assert db.hub_claim("demo", HUB, 120) is None
    assert loads(db.hub_op(op["id"])["result_json"], {})["status"] == 200


def confirm(web, pid, monkeypatch, app_confirmed=False):
    monkeypatch.setattr(hub_sync_api, "ADAPTER", ADAPTER)
    flag = {"app_confirmed": "yes"} if app_confirmed else {}  # флажок – часть подтверждённого режима (dev13)
    response = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN, data=flag)
    assert response.status_code == 200
    token = re.search(r'name="confirmation" value="([^"]+)"', response.text)[1]
    return web.client.post(f"/projects/{pid}/hub-sync/start", headers=ORIGIN,
                           data={"confirmation": token, "confirm": "yes", **({"app_confirmed": "yes"} if app_confirmed else {})})


def test_confirmation_progress_stop_continue_and_no_implicit_apply(web, monkeypatch):
    monkeypatch.setattr(hub_sync_api, "ADAPTER", ADAPTER)
    pid = project(web)
    db = web.app.state.db
    assert 'id="hub-sync-start"' in web.client.get(f"/projects/{pid}/defects").text
    count = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    assert web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN).status_code == 200
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count
    assert web.client.post(f"/projects/{pid}/hub-sync/start", headers=ORIGIN).status_code == 409
    response = confirm(web, pid, monkeypatch)
    assert response.status_code == 200, response.text
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    base = f"/projects/{pid}/hub-sync/{rid}"
    assert 'id="hub-sync-progress"' in response.text
    assert web.client.post(base + "/apply", headers=ORIGIN).status_code == 409
    assert not db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")
    count = len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2"))
    for _ in range(3):
        assert web.client.get(base + "/state").status_code == 200
    assert len(db._all("SELECT * FROM hub_ops ORDER BY 1, 2")) == count
    assert web.client.post(base + "/stop", headers=ORIGIN).status_code == 200
    assert db.hub_claim("demo", "https://hub.example.org", 120, sync_protocol=2) is None


def test_registration_from_every_poll_and_empty_match(web, monkeypatch):
    pid = project(web)
    db = web.app.state.db
    # Пустой проект: наличие локальных ID обязало бы проверить каждый отсутствующий ID.
    pid = db.create_project("Пустой")
    db.update_project(pid, hub_app_id=7)
    response = confirm(web, pid, monkeypatch)
    assert response.status_code == 200, response.text
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    headers = worker_headers(web)
    url = "/api/hub/jobs?worker_id=demo&hub_url=https://hub.example.org&wait=0"
    assert web.client.get(url, headers=headers).json()["job"] is None
    web.app.state.hub_workers = {}
    response = web.client.get(url + "&sync_protocol=2", headers=headers)
    assert response.json()["job"]["sync_protocol"] == 2
    assert web.app.state.hub_workers["demo"]["sync_protocol"] == 2
    job = response.json()["job"]
    assert web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=headers,
        json={"lease_token":job["lease_token"],"status":200,"body_text":'{"filteredEntities":[],"totalEntitiesCount":0}'}).status_code == 200
    step(db, FakeSyncHub())
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}")
    assert "Принятая база совпадает" in page.text


def test_differences_are_saved_and_visible(web, monkeypatch):
    pid = project(web)
    response = confirm(web, pid, monkeypatch, app_confirmed=True)  # новые объекты, общих с выгрузкой нет (dev13)
    assert response.status_code == 200
    db = web.app.state.db
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    finish(db, FakeSyncHub(2), rid)
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}")
    assert 'data-sync-group="new"' in page.text
    assert "Принятая база совпадает" not in page.text


def test_default_adapter_start_and_runtime_checks_visible(web):
    from test_hub_sync_measured import MeasuredHub
    project(web)
    db = web.app.state.db
    pid = db.create_project("Демо контракт")
    db.update_project(pid, hub_app_id=7)
    response = web.client.post(f"/projects/{pid}/hub-sync/preview", headers=ORIGIN)
    token = re.search(r'name="confirmation" value="([^"]+)"', response.text)[1]
    assert not db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    response = web.client.post(f"/projects/{pid}/hub-sync/start", headers=ORIGIN,
                               data={"confirmation": token, "confirm": "yes"})
    assert response.status_code == 200 and 'id="hub-sync-progress"' in response.text
    rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
    finish(db, MeasuredHub(cap=2), rid)
    page = web.client.get(f"/projects/{pid}/hub-sync/{rid}").text
    assert "перечитывания с меньшим шагом 2" in page
    assert "находки 3 / 3, дефекты 5 / 5" in page
    assert "Ветки: как в Hub по умолчанию" in page and "main, release" in page
    assert "Принятая база совпадает" not in page
