"""Регрессии первого круга ревью карточки дефекта. Только поддельный исполнитель."""

import json

import pytest

from app import defect_drafts, hub_defects
from app.db import text_hash
from test_hub_defect_import import deliver, take, tab
from test_hub_defect_update import act, phase, ready, read_job, sent_body, to_put
from test_hub_defects import HUB_DESCRIPTION, create, hub_job, sast_ready, to_preview, verify
from test_hub_status_routes import AS_JSON
from test_defect_marks29 import TWO_BOUNDARIES
from test_web import web  # noqa: F401


@pytest.mark.parametrize("origin", ["app", "import"])
@pytest.mark.parametrize("bad", ["missing", "double"])
def test_unknown_put_unparseable_verify_retains_attempt_until_readable(web, origin, bad):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    put = to_put(web, pid, row)
    deliver(web, put, 0, error="TimeoutError")
    attempt = hub_defects.update_state(db.hub_defect(row["id"]))
    assert attempt["sent_object"] == put["body"]
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    malformed = sent_body(db, row["id"])
    # текст не выделяется: две строки «Информация об объекте сканирования:» (31.10: без неё описание – текст)
    extra = "<p>Информация об объекте сканирования:</p><p>a</p>"
    malformed["description"] = (TWO_BOUNDARIES if bad == "missing" else malformed["description"] + extra + extra)
    read_job(web, malformed)
    current = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "unknown"
    assert db.hub_op(put["op_id"])["state"] == "unknown"
    for key in ("generation", "new", "sent", "sent_object", "base", "put_op_id"):
        assert hub_defects.update_state(current)[key] == attempt[key]
    before = db.hub_ops_list()
    page = tab(web, pid)
    assert f'id="hub-update-verify-form-{row["id"]}"' in page
    assert f'id="hub-update-form-{row["id"]}"' not in page
    assert "Запись принята Hub" not in page
    assert web.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200
    assert db.hub_ops_list() == before
    assert act(web, pid, row["id"], "update").status_code == 409
    assert db.hub_ops_list() == before
    assert not db.get_review(pid, "510001")["entered_hub"]
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done"
    assert db.hub_op(put["op_id"])["state"] == "done"
    # Старый ключ записи освобождён: следующий PUT действительно выдаётся исполнителю.
    done = db.hub_defect(row["id"])
    defect_drafts.save(db, done, str(done["draft_revision"]), summary=done["draft_summary"],
                       command=done["draft_command_text"], operations=[{"path": "/stage", "op": "set", "value": "TEST"}])
    next_put = to_put(web, pid, db.hub_defect(row["id"]), first=put["body"])
    assert next_put["op_id"] != put["op_id"]


def test_candidate_text_note_stops_polling_and_allows_new_read(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, status=0, error="TimeoutError")
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"filteredEntities": [{"id": 555, "summary": row["summary"]}], "totalEntitiesCount": 1})
    body = {"id": 555, "appId": 7, "summary": row["summary"], "description": TWO_BOUNDARIES,
            "linkedIssues": [{"id": 510001, "type": "SAST"}]}
    job = take(web)
    deliver(web, job, 200, body)
    current = db.hub_defect(row["id"])
    assert current["state"] == "unknown" and current["hub_defect_id"] == "555"
    assert current["verify_op_id"] is None
    assert hub_defects.view(current)["final"]
    assert not current["confirm_op_id"] and not db.get_review(pid, "510001")["entered_hub"]
    before = db.hub_ops_list()
    deliver(web, job, 200, body)
    assert web.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200
    assert db.hub_ops_list() == before
    assert verify(web, pid, row["id"]).status_code == 200
    body["description"] = hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)
    read = hub_job(web, body=body)
    assert read["op_id"] != job["op_id"] and read["path"] == "/defects/555"
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, "510001")["entered_hub"]


@pytest.mark.parametrize("bad_id", [None, "bad", True, "556"])
def test_incomplete_confirmation_is_recoverable_and_redelivery_does_not_crash(web, bad_id):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    job = take(web)
    body = {} if bad_id is None else {"id": bad_id, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                                    "summary": row["summary"],
                                    "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)}
    deliver(web, job, 200, body)
    current = db.hub_defect(row["id"])
    assert current["state"] == "unknown" and not current["confirm_op_id"]
    deliver(web, job, 200, body)
    before = db.hub_ops_list()
    assert web.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200
    assert web.client.get(f"/projects/{pid}/defects").status_code == 200
    assert db.hub_ops_list() == before
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    assert db.hub_defect(row["id"])["state"] == "done"


def test_copy_after_automatic_mark_keeps_entered_current(web):
    from test_hub_defect_guard import created
    pid, url = sast_ready(web)
    db = web.app.state.db
    created(web, pid, url)
    review = db.get_review(pid, "510001")
    assert review["entered_origin"] == "defect"
    assert review["entered_text_hash"] != review["entered_decision_hash"]
    for part in ("title", "body"):
        response = web.client.post(url + "/defect", headers=AS_JSON,
                                   data={"confirm": "1", "review_revision": str(review["revision"]), "part": part})
        assert response.status_code == 200, response.text
        assert response.json()["entered"] and response.json()["entered_current"]
    assert db.get_review(pid, "510001")["entered_text_hash"] == review["entered_text_hash"]


def test_sync_apply_updates_draft_base_history_and_next_put(web):
    from test_hub_defect_update import to_done
    pid, row = ready(web)
    db = web.app.state.db
    done = to_done(web, pid, row)
    remote = sent_body(db, row["id"])
    remote["description"] = remote["description"].replace("конкатенацией", "сцеплением строк")
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, remote)
    pending = db.hub_defect(row["id"])
    assert pending["draft_command_text"] == done["draft_command_text"]
    assert pending["confirmed_object_json"] == done["confirmed_object_json"]
    before = db.get_review(pid, "510001")
    assert act(web, pid, row["id"], "sync-apply", {"shown": text_hash(pending["sync_json"])}).status_code == 200
    applied = db.hub_defect(row["id"])
    assert applied["draft_command_text"] == applied["command_text"]
    assert "сцеплением строк" in applied["draft_command_text"]
    assert json.loads(applied["confirmed_object_json"]) == remote
    assert applied["draft_revision"] == done["draft_revision"] + 1
    assert db.get_review(pid, "510001") == before
    event = db._one("SELECT * FROM hub_defect_history ORDER BY id DESC LIMIT 1")
    assert event["event"] == "hub_sync" and event["revision"] == applied["draft_revision"]
    # После сверки текст уже совпадает; меняем только поле для проверки следующего полного PUT.
    applied = defect_drafts.save(db, applied, str(applied["draft_revision"]), summary=applied["draft_summary"],
                                 command=applied["draft_command_text"],
                                 operations=[{"path": "/stage", "op": "set", "value": "TEST"}])
    put = to_put(web, pid, applied, first=remote)
    assert "сцеплением строк" in put["body"]["description"]
    assert "конкатенацией" not in put["body"]["description"]


@pytest.mark.parametrize("change", ["local", "independent", "same", "conflict", "metadata"])
def test_sync_merge_preserves_operator_edit_and_conflict_is_atomic(web, change):
    from test_hub_defect_update import hub_body
    pid, row = ready(web, build=False)
    db = web.app.state.db
    remote = hub_body()
    local = row["draft_command_text"] + "\nПравка оператора."
    if change != "metadata":
        row = defect_drafts.save(db, row, str(row["draft_revision"]), summary=row["summary"], command=local)
    if change == "independent":
        remote["summary"] = "ID5 - Уточнение заголовка (SAST)"
    elif change in ("same", "conflict"):
        remote["description"] = hub_defects.description_html(local if change == "same" else "Другой текст Hub.",
                                                               hub_defects.hub_block(remote["description"])[0])
    elif change == "metadata":
        remote["priorityId"] = 4
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, remote)
    before = db.hub_defect(row["id"])
    events = db._all("SELECT * FROM hub_defect_history ORDER BY id")
    operations = db.hub_ops_list()
    r = act(web, pid, row["id"], "sync-apply", {"shown": text_hash(before["sync_json"])})
    after = db.hub_defect(row["id"])
    if change == "local":
        # Hub не изменился: сохранённый локальный текст не требует окна применения.
        assert r.status_code == 409 and after == before
        assert json.loads(after["sync_json"])["matches"]
        assert after["draft_command_text"] == local
        assert db._all("SELECT * FROM hub_defect_history ORDER BY id") == events
        assert db.hub_ops_list() == operations
    elif change == "conflict":
        assert r.status_code == 409
        assert after == before
        assert db._all("SELECT * FROM hub_defect_history ORDER BY id") == events
        assert act(web, pid, row["id"], "update").status_code == 409
        assert db.hub_ops_list() == operations
        # Существующая отмена освобождает локальную форму; правка оператора остаётся.
        assert act(web, pid, row["id"], "sync-cancel", {"shown": text_hash(before["sync_json"])}).status_code == 200
        assert db.hub_defect(row["id"])["draft_command_text"] == before["draft_command_text"]
        assert 'id="draft-blocker"' not in web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    else:
        assert r.status_code == 200, r.text
        assert json.loads(after["confirmed_object_json"]) == remote
        assert after["draft_command_text"] == before["draft_command_text"]
        assert after["draft_summary"] == remote["summary"]
        # принятие Hub (hub_sync); правка оператора, оставшаяся поверх принятого (independent), – отдельным событием
        # edit следующей редакцией: синхронизация видит её неотправленной (ревью dev34, круги 2–3)
        kept = ["edit"] if change == "independent" else []
        assert after["draft_revision"] == before["draft_revision"] + 1 + len(kept)
        assert json.loads(after["draft_fields_json"])["priorityId"] == remote["priorityId"]
        added = db._all("SELECT event FROM hub_defect_history ORDER BY id")[len(events):]
        assert [e["event"] for e in added] == ["hub_sync", *kept]
        assert db.hub_ops_list() == operations


def test_sync_apply_rechecks_draft_inside_transaction(web, monkeypatch):
    from test_hub_defect_update import hub_body
    pid, row = ready(web, build=False)
    db = web.app.state.db
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, {**hub_body(), "stage": "TEST"})
    pending = db.hub_defect(row["id"])
    advance = db.hub_defect_advance
    before_events = db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2")

    def race(*args, **kwargs):
        db.hub_defect_update(row["id"], draft_command_text="Правка другой вкладки", draft_revision=99)
        return advance(*args, **kwargs)

    monkeypatch.setattr(db, "hub_defect_advance", race)
    with pytest.raises(ValueError, match="изменился"):
        hub_defects.apply_import_sync(db, pending, shown=text_hash(pending["sync_json"]))
    after = db.hub_defect(row["id"])
    assert after["draft_command_text"] == "Правка другой вкладки" and after["draft_revision"] == 99
    assert after["confirmed_object_json"] == pending["confirmed_object_json"]
    assert after["sync_json"] == pending["sync_json"]
    assert db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2") == before_events


def test_apply_legacy_sync_preview_requires_full_read(web):
    from test_hub_defect_update import hub_body
    pid, row = ready(web, build=False)
    db = web.app.state.db
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, {**hub_body(), "stage": "TEST"})
    pending = db.hub_defect(row["id"])
    snap = json.loads(pending["sync_json"])
    del snap["read"]["object"]  # сохранённый предпросмотр схемы 28
    raw = json.dumps(snap, ensure_ascii=False)
    db.hub_defect_update(row["id"], sync_json=raw)
    before = db.hub_defect(row["id"])
    events = db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2")
    r = act(web, pid, row["id"], "sync-apply", {"shown": text_hash(raw)})
    assert r.status_code == 409 and "Полный объект" in r.json()["detail"]
    assert db.hub_defect(row["id"]) == before
    assert db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2") == events


@pytest.mark.parametrize("bad_id", [None, "bad", True, 556])
def test_candidate_incomplete_id_is_recoverable(web, bad_id):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, status=0, error="TimeoutError")
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"filteredEntities": [{"id": 555, "summary": row["summary"]}], "totalEntitiesCount": 1})
    body = {"id": bad_id, "appId": 7, "summary": row["summary"],
            "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION),
            "linkedIssues": [{"id": 510001, "type": "SAST"}]}
    job = take(web)
    deliver(web, job, 200, body)
    current = db.hub_defect(row["id"])
    assert current["state"] == "unknown" and current["hub_defect_id"] == "555"
    assert not current["verify_op_id"] and not current["confirm_op_id"]
    assert not db.get_review(pid, "510001")["entered_hub"]
    operations = db.hub_ops_list()
    deliver(web, job, 200, body)
    assert web.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200
    assert db.hub_ops_list() == operations
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={**body, "id": 555})
    assert db.hub_defect(row["id"])["state"] == "done"
