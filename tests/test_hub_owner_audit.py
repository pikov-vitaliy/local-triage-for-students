"""Аудит владельца: содержимое подтверждающего чтения и назначение отметки. Данные синтетические."""

import json

import pytest

from app import hub_defects
from test_defect import save_sast
from test_hub_bulk import preview, targets_of
from test_hub_defect_guard import created, link_fields
from test_hub_defects import FIX, REASON, create, hub_job, no_job, pair_project, sast_ready, to_preview, verify
from test_hub_status_routes import AS_JSON, HUB, decide, fid, project, run_worker, sast, send
from test_settings import post_settings
from test_web import ORIGIN, web  # noqa: F401


@pytest.mark.parametrize("field", ["summary", "description"])
@pytest.mark.parametrize("unknown", [False, True])
def test_creation_confirms_sent_content_and_recovers_only_by_read(web, field, unknown):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    post = hub_job(web, status=503 if unknown else 200, body={"id": 555})
    observed = dict(post["body"], id=555)
    if field == "description":
        observed[field] = observed[field].replace(FIX, "Удалить проверку параметров.")
    else:
        observed[field] += " Другой заголовок"
    if unknown:
        assert verify(web, pid, row["id"]).status_code == 200
        hub_job(web, body={"filteredEntities": [{"id": 555, "summary": post["body"]["summary"]}],
                           "totalEntitiesCount": 1})
    hub_job(web, body=observed, raw=True)
    # Короткое независимое воспроизведение из отчёта: ответ взят из POST, а не из локальной строки.
    assert not db.get_review(pid, "510001")["entered_hub"]
    after = db.hub_defect(row["id"])
    assert after["state"] == "unconfirmed" and after["confirm_op_id"] is None
    assert not after["confirmed_object_json"]
    assert after["command_text"] == row["command_text"]
    assert db.defect_number(pid, "sast:510001") is None
    assert json.loads(after["import_json"])["object"] == observed
    diff = json.loads(after["verify_json"])["confirmation"]["diff"]
    assert "Отправлено" in diff and "Прочитано в Hub" in diff
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}")
    assert card.status_code == 200 and 'id="defect-confirmation-diff-' in card.text
    assert 'id="hub-defect-done"' not in web.client.get(url).text
    assert db.hub_defect_bound(pid, "510001")["id"] == row["id"]
    assert hub_defects.sync(db, after)["state"] == "unconfirmed"
    no_job(web)
    assert verify(web, pid, row["id"]).status_code == 200
    normalized = dict(post["body"], id=555)
    normalized["description"] = normalized["description"].replace("<br>", "</p><p>")
    assert hub_job(web, body=normalized, raw=True)["method"] == "GET"
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, "510001")["entered_hub"]
    assert db.hub_defect(row["id"])["command_text"] == row["command_text"]
    assert len([op for op in db.hub_ops_list() if op["purpose"] == "defect_create"]) == 1
    no_job(web)


def test_link_does_not_confirm_changed_parent_content(web):
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = created(web, pid, url)
    sibling, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    response = web.client.post(sibling + "/hub-defect-link", headers=AS_JSON,
                               data=link_fields(web.client.get(sibling).text))
    assert response.status_code == 200
    row_id = response.json()["defect_id"]
    hub_job(web)
    observed = dict(json.loads(parent["confirmed_object_json"]), summary=parent["summary"] + " Изменено",
                    linkedIssues=[{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}])
    hub_job(web, body=observed, raw=True)
    assert not db.get_review(pid, "510005")["entered_hub"]
    assert db.hub_defect(row_id)["state"] == "unconfirmed"
    card = web.client.get(f"/projects/{pid}/defects/{row_id}")
    assert card.status_code == 200 and f'id="defect-confirmation-diff-{row_id}"' in card.text
    assert db.defect_number(pid, "sast:510005") is None
    assert verify(web, pid, row_id).status_code == 200
    hub_job(web, body={**observed, "summary": parent["summary"]}, raw=True)
    assert db.hub_defect(row_id)["state"] == "done"
    assert db.get_review(pid, "510005")["entered_hub"]
    assert len([op for op in db.hub_ops_list() if op["purpose"] == "defect_link"]) == 1


@pytest.mark.parametrize("change", ["hub", "app"])
def test_completed_status_is_scoped_after_settings_change(web, change):
    pid = project(web, [sast("101")])
    db = web.app.state.db
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    run_worker(web)
    original = db.get_review(pid, "101")
    assert original["entered_hub"]
    assert not targets_of(preview(web, pid, "101"))
    operations = db.hub_ops_list()
    if change == "hub":
        assert post_settings(web, hub_url="https://hub2.example.org").status_code == 303
    else:
        response = web.client.post(f"/projects/{pid}/params", headers=ORIGIN,
                                   data={"name": "p", "model": "", "hub_app_id": "8"}, follow_redirects=False)
        assert response.status_code == 303
    page = preview(web, pid, "101")
    assert len(targets_of(page)) == 1 and "статус уже внесён" not in page
    current = db.get_review(pid, "101")
    assert not current["entered_hub"] and current["entered_recorded"]
    assert current["entered_hub_url"] == HUB and current["entered_app_id"] == 7
    assert db.review_stats(pid)["entered"] == 0
    assert db.list_findings(pid, entered="yes")[1] == 0
    assert db.list_projects()[0]["entered"] == 0
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '101')}").text
    assert 'id="entered-scope-note"' in card and "приложению 7" in card
    assert "Записано в Hub:" not in card and "Ставлю отметку" not in card
    assert db.hub_ops_list() == operations
    assert db._one("SELECT entered_hub FROM reviews WHERE project_id = ?", (pid,))["entered_hub"] == 1
    if change == "hub":
        assert post_settings(web, hub_url=HUB).status_code == 303
    else:
        db.update_project(pid, hub_app_id=7)
    assert db.get_review(pid, "101")["entered_hub"]
    assert not targets_of(preview(web, pid, "101"))
    assert "Записано в Hub:" in web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '101')}").text


def test_unscoped_manual_mark_is_not_a_confirmed_status(web):
    pid = project(web, [sast("101")])
    review = decide(web, pid, "101")
    db = web.app.state.db
    db.mark_entered(pid, "101", revision=review["revision"], entered_hash="manual")
    assert len(targets_of(preview(web, pid, "101"))) == 1
    assert post_settings(web, hub_url="https://hub2.example.org").status_code == 303
    assert len(targets_of(preview(web, pid, "101"))) == 1
    assert db.get_review(pid, "101")["entered_origin"] == "manual"
    assert not db.hub_ops_list()


@pytest.mark.parametrize("change", ["hub", "app"])
def test_created_defect_mark_is_scoped_and_history_is_preserved(web, change):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    original = db.get_review(pid, "510001")
    assert original["entered_hub"] and original["entered_origin"] == "defect"
    operations = db.hub_ops_list()
    if change == "hub":
        assert post_settings(web, hub_url="https://hub2.example.org").status_code == 303
    else:
        response = web.client.post(f"/projects/{pid}/params", headers=ORIGIN,
                                   data={"name": "p", "model": "", "hub_app_id": "8"}, follow_redirects=False)
        assert response.status_code == 303
    current = db.get_review(pid, "510001")
    assert not current["entered_hub"] and current["entered_recorded"]
    assert current["entered_op_id"] == original["entered_op_id"]
    assert db.hub_ops_list() == operations
    assert db.hub_defect(row["id"]) == row
    assert db.review_stats(pid)["entered"] == 0
