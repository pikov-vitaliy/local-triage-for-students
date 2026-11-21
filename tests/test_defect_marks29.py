"""Отпечаток содержимого, неизменяемое решение, происхождение и восстановление отметок."""

import json

import pytest

from app import defect_drafts, hub_defects
from app.db import dumps, text_hash
from test_hub_defect_import import deliver
from test_hub_defect_update import ready, read_job, sent_body, to_put
from test_hub_defect_update import to_preview as update_preview
from test_hub_defects import HUB_DESCRIPTION, create, hub_job, sast_ready, to_preview
from test_web import web  # noqa: F401


@pytest.mark.parametrize("origin", ["app", "import"])
def test_content_and_decision_are_separate_and_repeat_is_idempotent(web, origin):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    put = to_put(web, pid, row)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    prepared = state["new"]["targets"][0]
    assert prepared["entered_hash"] == "" and prepared["decision_hash"]
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    done = db.hub_defect(row["id"])
    target = json.loads(done["targets_json"])[0]
    seen = json.loads(done["import_json"])
    content = text_hash(dumps({"summary": seen["summary"], "command_text": seen["command_text"]}))
    review = db.get_review(pid, "510001")
    assert target["entered_hash"] == review["entered_text_hash"] == content
    assert target["decision_hash"] == review["entered_decision_hash"] == prepared["decision_hash"]
    assert review["entered_origin"] == "defect" and review["entered_defect_id"] == row["id"]
    assert review["entered_op_id"] == done["confirm_op_id"]
    assert review["entered_defect_revision"] == done["draft_revision"]
    assert json.loads(done["confirmed_object_json"])["summary"] == put["body"]["summary"]
    events = db._all("SELECT * FROM hub_defect_history WHERE event = 'hub_confirm'")
    hub_defects._apply_effects(db, done)
    assert db.get_review(pid, "510001") == review
    assert db._all("SELECT * FROM hub_defect_history WHERE event = 'hub_confirm'") == events
    # Поздняя ручная отметка тем же текстом не становится отметкой операции.
    db.mark_entered(pid, "510001", entered_hash=content)
    hub_defects._apply_effects(db, done)
    assert db.get_review(pid, "510001")["entered_origin"] == "manual"
    # Более ранняя ручная отметка тем же содержимым уступает новому подтверждению.
    # При сравнении только хеша _marked ошибочно пропустил бы эту запись.
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_hub_at = '2000-01-01' WHERE project_id = ?", (pid,))
    # Dev1b не отправляет пустой diff: новая запись меняет только поле, текстовый хеш остаётся тем же.
    defect_drafts.save(db, done, str(done["draft_revision"]), summary=done["draft_summary"],
                       command=done["draft_command_text"], operations=[{"path": "/stage", "op": "set", "value": "TEST"}])
    next_put = to_put(web, pid, done, first=sent_body(db, row["id"]))
    deliver(web, next_put, 204, text="")
    read_job(web, next_put["body"])
    later = db.get_review(pid, "510001")
    assert later["entered_text_hash"] == content and later["entered_origin"] == "defect"
    assert later["entered_op_id"] != review["entered_op_id"]


def test_changed_decision_after_put_is_marked_by_confirmed_composition(web):
    """Решение пересохранено между записью и подтверждением: отметка – по подтверждённому составу, с текущей редакцией;
    отпечаток решения – отправленного текста, по нему карточка покажет, что решение изменилось."""
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    prepared = hub_defects.update_state(db.hub_defect(row["id"]))["new"]["targets"][0]
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive", final_comment="Другое решение", reviewed=True)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    target = json.loads(db.hub_defect(row["id"])["targets_json"])[0]
    review = db.get_review(pid, "510001")
    assert all(target[k] == prepared[k] for k in ("sig", "decision_hash"))
    assert target["revision"] == review["revision"] != prepared["revision"]
    assert review["entered_hub"] and review["entered_origin"] == "defect"
    assert review["entered_decision_hash"] == prepared["decision_hash"] != text_hash("Другое решение")


TWO_BOUNDARIES = "<p>Текст.</p><p>Информация об объекте сканирования:</p><p>a</p><p>Информация об объекте сканирования:</p><p>b</p>"  # текст дефекта не выделяется (две границы)


@pytest.mark.parametrize("description", [TWO_BOUNDARIES, HUB_DESCRIPTION + HUB_DESCRIPTION])
def test_create_does_not_confirm_unparseable_text(web, description):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": row["summary"], "description": description,
                       "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    current = db.hub_defect(row["id"])
    # две разные границы – текст не выделен («неизвестно»); блок заготовки дважды без текста приложения – текст
    # выделяется пустым (dev30 сворачивает повтор блока), содержимое не совпало – «не подтверждено»; создание не
    # подтверждается ни в одном случае
    assert current["state"] in ("unknown", "unconfirmed") and current["hub_defect_id"] == "555"
    assert not current["confirm_op_id"] and not db.get_review(pid, "510001")["entered_hub"]
    assert db.defect_number(pid, "sast:510001") is None
    assert not db._all("SELECT * FROM hub_defect_history WHERE event = 'hub_confirm'")


@pytest.mark.parametrize("description", [None, "<p>Нет границы</p>"])
def test_create_with_other_text_without_hub_block_is_not_confirmed(web, description):
    """Описание без «Информации об объекте сканирования» – читаемый текст; он другой – создание не
    подтверждается, отметок и номеров нет."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": row["summary"], "description": description,
                       "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    current = db.hub_defect(row["id"])
    assert current["state"] != "done" and not current["confirm_op_id"]
    assert not db.get_review(pid, "510001")["entered_hub"] and db.defect_number(pid, "sast:510001") is None


def test_removed_target_rejects_late_effect(web):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    done = db.hub_defect(row["id"])
    target = json.loads(done["targets_json"])[0]
    assert db.on_connection(lambda c: defect_drafts.current_effect(c, done, target))
    db.hub_defect_update(row["id"], targets_json="[]", number_keys_json="[]")
    assert not db.on_connection(lambda c: defect_drafts.current_effect(c, done, target))
    db.mark_entered(pid, "510001", False)
    hub_defects.apply_marks(db, done)
    assert not db.get_review(pid, "510001")["entered_hub"]


@pytest.mark.parametrize("change", ["draft_revision", "draft_fields_json", "conflicts_json", "members"])
def test_second_read_rejects_changed_draft_or_members(web, change, monkeypatch):
    from test_hub_defect_update import hub_body, phase, put_click, to_preview as update_preview
    pid, row = ready(web)
    db = web.app.state.db
    update_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    if change == "members":
        targets = json.loads(db.hub_defect(row["id"])["targets_json"])
        targets[0]["sig"] = "changed"
        fields = {"targets_json": dumps(targets)}
    else:
        fields = {change: {"draft_revision": 100, "draft_fields_json": '{"settings":null}',
                           "conflicts_json": '["конфликт"]'}[change]}
    # Изменение строго после подготовки, непосредственно перед транзакцией постановки PUT.
    # _prep_problem уже прошёл: отказ может дать только повторная проверка в транзакции.
    advance = db.hub_defect_advance

    def race(*args, **kwargs):
        if kwargs.get("op_field") == "update_op_id" and kwargs.get("item", {}).get("purpose") == "defect_update":
            db.hub_defect_update(row["id"], **fields)
        return advance(*args, **kwargs)

    monkeypatch.setattr(db, "hub_defect_advance", race)
    read_job(web, hub_body())
    assert phase(db, row["id"]) == "stale"
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "defect_update"]


def test_link_inherits_owner_and_preserves_unsent_draft(web):
    from test_defect import save_sast
    from test_hub_defect_guard import card_of, created, start_link
    from test_hub_defects import FIX, REASON, pair_project
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = created(web, pid, url)
    saved = defect_drafts.save(db, parent, str(parent["draft_revision"]), summary=parent["summary"], command="Неотправленная правка")
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    linked = start_link(web, pid, "510005")
    row = db.hub_defect(linked)
    assert row["draft_owner_id"] == parent["id"] and row["draft_revision"] == 0
    assert row["draft_command_text"] == ""
    hub_job(web, body={})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]})
    assert db.hub_defect(linked)["state"] == "done"
    assert db.hub_defect(parent["id"])["draft_command_text"] == "Неотправленная правка"
    # правка владельца – событием после подтверждения привязки: синхронизация не сочтёт её принятой
    assert db.hub_defect(parent["id"])["draft_revision"] == saved["draft_revision"] + 1
    events = [e["event"] for e in db._all("SELECT event FROM hub_defect_history WHERE defect_id = ? ORDER BY id", (parent["id"],))]
    assert events[-2:] == ["hub_confirm", "edit"]
    page = web.client.get(f"/projects/{pid}/defects/{linked}").text
    assert "Неотправленная правка" in page and "Pull из Hub" in page and 'id="defect-unmerged"' in page
    assert f'href="/projects/{pid}/defects/{linked}"' in web.client.get(card_of(web, pid, "510005")).text
    response = web.client.get(f"/projects/{pid}/hub/defects/{linked}").json()
    assert response["defect_id"] == linked


@pytest.mark.parametrize("bad_text", [False, True])
def test_app_unconfirmed_blocks_direct_and_stale_link(web, bad_text):
    from test_defect import save_sast
    from test_hub_defect_guard import card_of, created, link_fields
    from test_hub_defect_update import hub_body, phase, act
    from test_hub_defects import FIX, REASON, HUB, pair_project, blank
    from test_hub_status_routes import AS_JSON
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = created(web, pid, url, defect_id=777)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    stale = link_fields(web.client.get(sibling).text)
    changed_reason = REASON + " Проверен дополнительный путь."
    save_sast(web, pid, "510001", "true_positive", "", changed_reason, FIX, defect_confirm="1")
    save_sast(web, pid, "510005", "true_positive", "", changed_reason, FIX)
    from test_hub_defect_update import assemble
    assert assemble(web, pid, row).status_code == 200
    assert db.hub_defect(row["id"])["draft_command_text"] != row["command_text"]
    body = hub_body(summary=row["summary"], description=row["body_html"])
    body["id"] = 777
    put = to_put(web, pid, row, first=body, second=body)
    deliver(web, put, 204, text="")
    observed = dict(put["body"])
    observed["description"] = "<p>Без границы</p>" if bad_text else "<p>Другой текст</p>" + HUB_DESCRIPTION
    read_job(web, observed)
    assert phase(db, row["id"]) == "unconfirmed"
    before = db.hub_ops_list()
    assert web.client.post(sibling + "/hub-defect-link", headers=AS_JSON, data=stale).status_code in (400, 409)
    assert blank(web, sibling).status_code == 400
    with pytest.raises(ValueError, match="Обновление"):
        db.hub_defect_link_start(pid, row["id"], "777", item={}, body_hash=text_hash(row["command_text"]),
                                 kind="SAST", number=row["number"], summary=row["summary"], anchor_hub_id="510005",
                                 targets=[], number_keys=[], command_text=row["command_text"], hub_url=HUB, app_id=7)
    assert len(db.hub_defects(pid)) == 1 and db.hub_ops_list() == before
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, put["body"])
    assert phase(db, row["id"]) == "done"
    assert db.hub_defect(row["id"])["command_text"] != row["command_text"]
    before = db.hub_ops_list()
    assert web.client.post(sibling + "/hub-defect-link", headers=AS_JSON, data=stale).status_code in (400, 409)
    assert db.hub_ops_list() == before
    assert "hub-defect-link-form" in web.client.get(sibling).text
    from test_hub_defect_guard import start_link
    linked = start_link(web, pid, "510005")
    assert db.hub_defect(linked)["command_text"] == db.hub_defect(row["id"])["command_text"]


def test_app_preserves_exact_draft_across_html_normalization(web):
    from test_hub_defect_update import hub_body
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin="app")
    command = row["draft_command_text"].replace("Параметризовать", "Параметризовать  ")
    saved = defect_drafts.save(db, row, str(row["draft_revision"]), summary=row["draft_summary"], command=command)
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    observed = dict(put["body"])
    observed["description"] = observed["description"].replace("  ", " ")
    read_job(web, observed)
    done = db.hub_defect(row["id"])
    assert done["command_text"] == done["draft_command_text"] == command
    assert done["draft_revision"] == saved["draft_revision"]
    # Hub сам схлопнул пробел – текст тот же: повторный Push – «Изменений для отправки нет» (если
    # ничего не меняем, разниц нет), а не новая запись того же текста
    update_preview(web, pid, done, observed)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "cancelled" and state.get("note") == "Изменений для отправки нет", state
    assert hub_body()["id"] == put["body"]["id"]


@pytest.mark.parametrize("saved_hash", [True, False])
def test_legacy_target_fallback_and_valid_empty_command(web, saved_hash):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    # Старая попытка действительно отправила пустой текст команды, а не потеряла его в ответе Hub.
    pending = db.hub_defect(row["id"])
    sent = json.loads(db.hub_op(pending["create_op_id"])["request_json"])
    sent["body"]["description"] = HUB_DESCRIPTION
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET request_json = ? WHERE id = ?", (dumps(sent), pending["create_op_id"]))
    db.hub_defect_update(row["id"], command_text="", body_html=HUB_DESCRIPTION)
    # Уже отправленная старая попытка сохраняла отпечаток решения в entered_hash.
    targets = json.loads(db.hub_defect(row["id"])["targets_json"])
    decision = targets[0].pop("decision_hash")
    targets[0]["entered_hash"] = decision if saved_hash else ""
    db.hub_defect_update(row["id"], targets_json=dumps(targets))
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive",
                   final_comment="Новое текущее решение", reviewed=True)
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": row["summary"], "description": HUB_DESCRIPTION,
                       "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    done = db.hub_defect(row["id"])
    assert done["state"] == "done"
    target = json.loads(done["targets_json"])[0]
    assert target["decision_hash"] == (decision if saved_hash else "")
    assert target["entered_hash"] == text_hash(dumps({"summary": row["summary"], "command_text": ""}))
    # отметка – по подтверждённому составу, с текущей редакцией; пустой отпечаток решения
    # отметке не мешает
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] and target["revision"] == review["revision"]
    assert review["entered_decision_hash"] == (decision if saved_hash else "")


def test_app_recheck_after_update_keeps_polling_and_both_results(web):
    from test_hub_defect_guard import recheck
    from test_hub_defect_update import hub_body
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin="app")
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    confirmed = db.hub_defect(row["id"])["confirm_op_id"]
    response = recheck(web, pid, row["id"])
    assert response.status_code == 200 and response.json()["done"] is False
    assert "Проверяю в Hub" in response.json()["text"]["hub-defect-status"]
    read_job(web, hub_body())
    current = db.hub_defect(row["id"])
    view = hub_defects.view(current)
    assert view["final"] and view["tone"] == "ok"
    # итог «Проверить в Hub» с dev33 не выводится (кнопки нет, у дефекта – Push и Pull); итог обновления – виден
    assert hub_defects.RECHECK_OK not in view["text"] and "Обновлено в Hub" in view["text"]
    assert current["confirm_op_id"] == confirmed


def test_post_keeps_prepared_decision_when_operator_changes_it_before_confirm(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    prepared = json.loads(db.hub_defect(row["id"])["targets_json"])[0]
    db.save_review(pid, "510001", decision="disagree", final_verdict="true_positive", final_comment="Поздняя правка", reviewed=True)
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    done = db.hub_defect(row["id"])
    target = json.loads(done["targets_json"])[0]
    assert done["state"] == "done"
    assert all(target[k] == prepared[k] for k in ("sig", "decision_hash"))
    review = db.get_review(pid, "510001")  # отметка – по подтверждённому составу, с текущей редакцией
    assert target["revision"] == review["revision"] != prepared["revision"] and review["entered_hub"]


@pytest.mark.parametrize("old_origin", ["manual", "defect", ""])
def test_same_content_new_confirmation_replaces_older_mark_provenance(web, old_origin):
    from test_hub_defect_update import to_done
    pid, row = ready(web)
    db = web.app.state.db
    done = to_done(web, pid, row)
    first = db.get_review(pid, "510001")
    with db._tx() as c:
        c.execute("UPDATE reviews SET entered_origin = ?, entered_hub_at = '2000-01-01' WHERE project_id = ?",
                  (old_origin, pid))
    defect_drafts.save(db, done, str(done["draft_revision"]), summary=done["draft_summary"],
                       command=done["draft_command_text"], operations=[{"path": "/stage", "op": "set", "value": "TEST"}])
    put = to_put(web, pid, done, first=sent_body(db, row["id"]))
    deliver(web, put, 204, text="")
    read_job(web, put["body"])
    current = db.get_review(pid, "510001")
    assert current["entered_text_hash"] == first["entered_text_hash"]
    assert current["entered_origin"] == "defect"
    assert current["entered_op_id"] != first["entered_op_id"]
    assert current["entered_op_id"] == db.hub_defect(row["id"])["confirm_op_id"]


@pytest.mark.parametrize("parent_state", ["done", "cancelled"])
def test_link_text_note_recovery_keeps_pinned_owner_and_physical_operation(web, parent_state, monkeypatch):
    from test_defect import save_sast
    from test_hub_defect_guard import created, start_link
    from test_hub_defects import FIX, REASON, pair_project, verify
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    child_id = start_link(web, pid, "510005")
    child = db.hub_defect(child_id)
    prepared = json.loads(child["targets_json"])[0]
    hub_job(web, body={})
    hub_job(web, body={"id": 555, "summary": parent["summary"], "description": TWO_BOUNDARIES,
                       "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]})
    assert db.hub_defect(child_id)["state"] == "unknown"
    assert not db.get_review(pid, "510005")["entered_hub"]
    # Живой состав и состояние владельца меняются, но ссылка на него не перевыбирается.
    db.hub_defect_update(parent["id"], state=parent_state, targets_json="[]", number_keys_json="[]")
    assert verify(web, pid, child_id).status_code == 200
    response = {"id": 555, "summary": parent["summary"], "description": parent["body_html"],
                "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]}
    with monkeypatch.context() as patch:
        patch.setattr(hub_defects, "_apply_effects", lambda *a, **kw: None)
        read = hub_job(web, body=response)
    confirmed = db.hub_defect(child_id)
    assert confirmed["effects_done"] == 0
    before = db.hub_ops_list()
    assert web.client.get(f"/projects/{pid}/defects/{child_id}").status_code == 200
    assert db.hub_ops_list() == before
    assert db.hub_defect(child_id)["effects_done"] == 1
    assert db.hub_defect(child_id)["draft_owner_id"] == parent["id"]
    assert db.hub_defect(child_id)["confirm_op_id"] == read["op_id"]
    mark = db.get_review(pid, "510005")
    seen = hub_defects._read_of(response)
    assert mark["entered_text_hash"] == text_hash(dumps({"summary": seen["summary"], "command_text": seen["command_text"]}))
    assert mark["entered_decision_hash"] == prepared["decision_hash"]
    assert mark["entered_defect_id"] == parent["id"] and mark["entered_op_id"] == read["op_id"]
    event = db._one("SELECT * FROM hub_defect_history WHERE row_id = ? AND event = 'hub_confirm'", (child_id,))
    assert event["defect_id"] == parent["id"] and event["op_id"] == read["op_id"]


@pytest.mark.parametrize("kind", ["SAST", "SCA"])
@pytest.mark.parametrize("changed", [False, True])
def test_updated_import_decision_changed_uses_decision_hash(web, kind, changed):
    from app.routes.hub_defect_routes import decision_changed
    from test_hub_defect_update import SCA_OLD, hub_body, sca_ready
    if kind == "SCA":
        pid, row, url = sca_ready(web)
        first = hub_body(links=((73001, "SCA_S"), (73002, "SCA_S")), summary=SCA_OLD)
        hub_id = "73001"
    else:
        pid, row = ready(web)
        first = hub_body()
        hub_id = "510001"
    db = web.app.state.db
    put = to_put(web, pid, row, first=first)
    deliver(web, put, 204, text="")
    read_job(web, put["body"])
    done = db.hub_defect(row["id"])
    target = json.loads(done["targets_json"])[0]
    assert target["decision_hash"] != target["entered_hash"]
    seen = hub_defects._read_of(put["body"])
    expected = text_hash(dumps({"summary": seen["summary"], "command_text": seen["command_text"]}))
    assert target["entered_hash"] == db.get_review(pid, hub_id)["entered_text_hash"] == expected
    if kind == "SCA":
        assert 'id="entered-changed"' not in web.client.get(url).text
        with db._tx() as c:
            c.execute("UPDATE reviews SET entered_decision_hash = 'другое решение' WHERE project_id = ? AND hub_id = ?",
                      (pid, hub_id))
        assert 'id="entered-changed"' in web.client.get(url).text
    with db._tx() as c:
        c.execute("UPDATE reviews SET revision = revision + 1 WHERE project_id = ? AND hub_id = ?", (pid, hub_id))
    current_hash = text_hash("Другое решение") if changed else target["decision_hash"]
    assert decision_changed(db, pid, hub_id, done, current_hash) is changed
