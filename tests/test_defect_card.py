"""Карточка дефекта: ссылки, локальная правка и отказ устаревшей форме."""

from test_hub_defect_update import ready
from test_web import ORIGIN, web  # noqa: F401


def test_open_edit_stale_and_generate(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    url = f"/projects/{pid}/defects/{row['id']}"
    before = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    page = web.client.get(url)
    assert page.status_code == 200, page.text
    assert 'id="defect-draft-form"' in page.text and "Полная подтверждённая база неизвестна" not in page.text
    assert f'href="{url}"' in web.client.get(f"/projects/{pid}/defects").text
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before
    data = {"draft_revision": "1", "summary": "ID5 - Ручная правка (SAST)", "command_text": "Введённый текст"}
    response = web.client.post(url + "/fields", headers=ORIGIN, data=data)
    assert response.status_code == 200, response.text
    assert db.hub_defect(row["id"])["draft_revision"] == 2
    data["command_text"] = "Текст из устаревшей вкладки"
    response = web.client.post(url + "/fields", headers=ORIGIN, data=data)
    assert response.status_code == 409 and data["command_text"] in response.text
    assert db.hub_defect(row["id"])["draft_command_text"] == "Введённый текст"
    saved = db.hub_defect(row["id"])
    history = db._all("SELECT * FROM hub_defect_history ORDER BY id")
    stale = web.client.post(url + "/text-from-decisions", headers=ORIGIN, data={"draft_revision": "1"})
    assert stale.status_code == 409
    assert db.hub_defect(row["id"]) == saved
    assert db._all("SELECT * FROM hub_defect_history ORDER BY id") == history
    response = web.client.post(url + "/text-from-decisions", headers=ORIGIN, data={"draft_revision": "2"})
    assert response.status_code == 200, response.text
    assert "Обоснование:" in db.hub_defect(row["id"])["draft_command_text"]
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == before
    other = db.create_project("Другой")
    assert web.client.get(f"/projects/{other}/defects/{row['id']}").status_code == 404


def test_unstructured_nontext_fields_are_rejected(web):
    pid, row = ready(web, build=False)
    url = f"/projects/{pid}/defects/{row['id']}"
    r = web.client.post(url + "/fields", headers=ORIGIN, data={"draft_revision": "1", "summary": "ID5", "priority": "High"})
    assert r.status_code == 422
    assert web.app.state.db.hub_defect(row["id"])["draft_revision"] == 1


def test_save_empty_text_fields(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    before = db.hub_ops_list()
    r = web.client.post(f"/projects/{pid}/defects/{row['id']}/fields", headers=ORIGIN,
                        data={"draft_revision": "1", "summary": "", "command_text": ""})
    assert r.status_code == 200
    current = db.hub_defect(row["id"])
    assert current["draft_summary"] == current["draft_command_text"] == ""
    assert current["draft_revision"] == 2
    event = db._one("SELECT * FROM hub_defect_history ORDER BY id DESC LIMIT 1")
    assert event["event"] == "edit" and event["summary"] == event["command_text"] == ""
    assert db.hub_ops_list() == before
