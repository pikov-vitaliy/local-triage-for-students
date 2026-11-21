"""Проверки dev1b через HTTP, очередь исполнителя и сохранённое состояние."""

import copy
import json

import pytest

from app import defect_fields, defect_references, hub_defects
from app.db import dumps, loads
from test_hub_defect_import import apply_sync, imported, project
from test_hub_defect_update import (act, deliver, hub_body, ops, phase, put_click, read_job, ready,
                                    sent_body, take, to_preview, to_put)
from test_web import ORIGIN, web  # noqa: F401


@pytest.mark.parametrize("variant", ["versions", "sets", "no_defect", "empty", "missing"])
def test_conflict_explains_actual_groups_and_allows_only_local_work(web, variant):
    from app.db import finding_ecosystem
    from app.sca_contract import input_ref
    pid = project(web)
    db = web.app.state.db
    second = db.get_finding_by_hub_id(pid, "73002")
    data = second["data"]
    with db._tx() as c:
        if variant == "versions":
            data["version"] = "2.0.0"
            c.execute("UPDATE findings SET data_json = ? WHERE id = ?", (dumps(data), second["id"]))
        if variant in ("sets", "no_defect"):
            c.execute("INSERT INTO sca_set_members(project_id,hub_id,input_ref,set_no,updated_at)"
                      " VALUES (?, '73002', ?, ?, '') ON CONFLICT(project_id, hub_id) DO UPDATE SET input_ref = excluded.input_ref,"
                      " set_no = excluded.set_no", (pid, input_ref(finding_ecosystem(data), data["component"], data["version"]),
                                                           1 if variant == "sets" else None))
    row = imported(web, pid, body=hub_body(links=((73001, "SCA_S"), (73002, "SCA_S")), summary="ID5 - example-parser (SCA)"))
    if variant == "empty":
        db.hub_defect_update(row["id"], targets_json="[]", conflicts_json='["Цели не определяют единственный набор SCA."]')
    if variant == "missing":
        with db._tx() as c:
            c.execute("UPDATE findings SET missing=1 WHERE id = ?", (second["id"],))
        db.hub_defect_update(row["id"], conflicts_json='["Недостаточно данных."]')
    row = db.hub_defect(row["id"])
    url = f"/projects/{pid}/defects/{row['id']}"
    before = db.hub_ops_list()
    page = web.client.get(url)
    assert page.status_code == 200
    top = page.text.split('id="defect-conflict-explanation"', 1)[1].split('</section>', 1)[0]
    if variant == "versions":
        assert "1.4.2" in top and "2.0.0" in top and "разных версий" in top
    elif variant == "sets":
        assert "разных наборов" in top and "набор 0" in top and "набор 1" in top
    elif variant == "no_defect":
        assert "без дефекта" in top
    elif variant == "empty":
        assert "нет локальных целей" in top
    else:
        assert "73002" in top and "нет в текущей выгрузке" in top
    assert 'id="draft-save" type="submit" disabled' not in page.text
    assert edit(web, pid, row, [set_field("stage", "LOCAL")], command_text="Ручной черновик").status_code == 200
    before_generate = db.hub_defect(row["id"])
    response = web.client.post(url + "/text-from-decisions", headers=ORIGIN,
                               data={"draft_revision": str(before_generate["draft_revision"])})
    assert response.status_code == 200, response.text
    current = db.hub_defect(row["id"])
    assert current["draft_revision"] == before_generate["draft_revision"] + 1
    assert current["draft_fields_json"] == before_generate["draft_fields_json"]
    assert current["conflicts_json"] == before_generate["conflicts_json"]
    assert current["targets_json"] == before_generate["targets_json"]
    assert "73003" not in current["draft_command_text"]
    assert act(web, pid, row["id"], "update").status_code == 409
    assert db.hub_ops_list() == before


def edit(web, pid, row, changes, **extra):
    current = web.app.state.db.hub_defect(row["id"])
    return web.client.post(f"/projects/{pid}/defects/{row['id']}/fields", headers=ORIGIN, data={
        "draft_revision": str(current["draft_revision"]), "summary": current["draft_summary"],
        "command_text": current["draft_command_text"], "changes": json.dumps(changes), **extra})


def set_field(name, value):
    return {"path": "/" + name, "op": "set", "value": value}


def test_dev1_preview_put_and_unknown_recover_with_legacy_contract(web):
    from starlette.requests import Request
    from app.routes.hub_defect_routes import prepare_update
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    current = db.hub_defect(row["id"])
    state = hub_defects.update_state(current)
    for key in ("contract_version", "candidate", "field_diff", "local_changes", "basis", "references"):
        state.pop(key, None)
    prep = prepare_update(Request({"type": "http", "app": web.app}), current)
    state["new"]["prep_sig"] = hub_defects.update_prep_sig(prep, fields_contract=False)
    db.hub_defect_update(row["id"], update_json=dumps(state))
    assert put_click(web, pid, row).status_code == 200
    read_job(web)
    put = take(web)
    assert put["method"] == "PUT" and "contract_version" not in put
    deliver(web, put, 503, text="")
    assert phase(db, row["id"]) == "unknown"
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    read_job(web, {**put["body"], "stage": "legacy extra"})
    assert phase(db, row["id"]) == "done_diff" and take(web) is None


def test_sequential_sync_rebases_fields_preserves_local_and_old_tab_is_stale(web):
    pid = project(web)
    row = imported(web, pid, body=hub_body(stage="DEV", source="one"))
    db = web.app.state.db
    assert edit(web, pid, row, [set_field("source", "LOCAL")]).status_code == 200
    for value in ("TEST", "PROD"):
        before = db.hub_defect(row["id"])
        assert act(web, pid, row["id"], "sync").status_code == 200
        read_job(web, hub_body(stage=value, source="one"))
        snap = loads(db.hub_defect(row["id"])["sync_json"], {})
        assert [x["path"] for x in snap["fields_diff"]] == ["/stage"]
        assert apply_sync(web, pid, row["id"]).status_code == 200
        current = db.hub_defect(row["id"])
        # принятие Hub (+1) и сохранённая локальная правка поля отдельным событием edit (+1, ревью dev34, круг 4)
        assert current["draft_revision"] == before["draft_revision"] + 2
        assert loads(current["draft_fields_json"], {})["stage"] == value
        assert loads(current["draft_fields_json"], {})["source"] == "LOCAL"
        assert defect_fields.basis_of(current)["base"]["stage"] == value
        assert [c["path"] for c in defect_fields.local_changes(current)] == ["/source"]
        assert edit(web, pid, row, [set_field("stage", "stale")], draft_revision=str(before["draft_revision"])).status_code == 409
        assert act(web, pid, row["id"], "sync").status_code == 200
        read_job(web, hub_body(stage=value, source="one"))
        matches = db.hub_defect(row["id"])
        assert loads(matches["sync_json"], {})["matches"]
        assert matches["draft_revision"] == current["draft_revision"]
        assert matches["draft_fields_json"] == current["draft_fields_json"]
        page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
        assert "совпадают с принятой версией в приложении (проверено" in page
        assert f'id="hub-sync-apply-form-{row["id"]}"' not in page
        assert f'id="hub-sync-cancel-form-{row["id"]}"' not in page
    assert not ops(db, "defect_update")


@pytest.mark.parametrize("change", ["same_path", "revision", "basis", "targets"])
def test_sync_conflicts_and_races_leave_all_state_untouched(web, change):
    pid = project(web)
    row = imported(web, pid, body=hub_body(stage="DEV"))
    db = web.app.state.db
    if change == "same_path":
        assert edit(web, pid, row, [set_field("stage", "LOCAL")]).status_code == 200
    act(web, pid, row["id"], "sync")
    read_job(web, hub_body(stage="TEST"))
    before = db.hub_defect(row["id"])
    if change == "revision":
        db.hub_defect_update(row["id"], draft_revision=before["draft_revision"] + 1)
    elif change == "basis":
        basis = defect_fields.basis_of(before)
        basis["base"]["stage"] = "RACE"
        db.hub_defect_update(row["id"], draft_fields_basis_json=dumps(basis))
    elif change == "targets":
        db.hub_defect_update(row["id"], targets_json="[]")
    before = db.hub_defect(row["id"])
    events = db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2")
    response = apply_sync(web, pid, row["id"])
    assert response.status_code == 409, response.text
    assert db.hub_defect(row["id"]) == before
    assert db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2") == events


@pytest.mark.parametrize("values", [
    {"stage": "TEST"}, {"dueDate": "2026-11-10T18:02:03.250+02:30"},
    {"isActive": False}, {"settings": {"isInheritedARStatusFromDefect": False}},
    {"externalBugs": [{"link": "https://tracker.example.org/issue/1", "product": ""}, {}]},
])
def test_nontext_put_and_confirmation(web, values):
    pid, row = ready(web)
    db = web.app.state.db
    before = db.hub_ops_list()
    r = edit(web, pid, row, [set_field(k, v) for k, v in values.items()])
    assert r.status_code == 200, r.text
    assert db.hub_ops_list() == before
    put = to_put(web, pid, row)
    assert all(defect_fields.equal(put["body"][k], v) for k, v in values.items())
    assert put["contract_version"] == "defect-fields-v1" and put["app_id"] == 7
    deliver(web, put, 204, text="")
    read_job(web, put["body"])
    current = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done"
    assert all(loads(current["confirmed_object_json"], {})[k] == v for k, v in values.items())
    assert defect_fields.local_changes(current) == []
    assert db.get_review(pid, "510001")["entered_hub"] == 1


@pytest.mark.parametrize("corruption", ["summary", "number", "text", "field", "missing", "bool_type"])
def test_field_only_update_still_requires_text_number_and_exact_fields(web, corruption):
    pid, row = ready(web)
    db = web.app.state.db
    # После первого успешного поколения меняется только срок и boolean.
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    accepted = db.hub_defect(row["id"])
    body = loads(accepted["confirmed_object_json"], {})
    assert edit(web, pid, row, [set_field("dueDate", "2026-12-10T09:00:00Z"), set_field("isActive", True)]).status_code == 200
    put = to_put(web, pid, row, first=body, second=body)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert set(state["changed_roots"]) == {"dueDate", "isActive"}
    deliver(web, put, 204, text="")
    answer = copy.deepcopy(put["body"])
    if corruption == "summary":
        answer["summary"] += " changed"
    elif corruption == "number":
        answer["summary"] = answer["summary"].replace("ID5", "ID6")
    elif corruption == "text":
        answer["description"] = "<p>Другой текст</p>" + answer["description"]
    elif corruption == "field":
        answer["dueDate"] = body["dueDate"]
    elif corruption == "missing":
        answer.pop("dueDate")
    else:
        answer["isActive"] = 1
    read_job(web, answer)
    current = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "unconfirmed"
    assert current["confirmed_object_json"] == accepted["confirmed_object_json"]
    assert current["text_generation"] == accepted["text_generation"]
    assert take(web) is None


def test_done_diff_ignores_intended_fields_but_reports_other_changes(web):
    pid, row = ready(web)
    db = web.app.state.db
    assert edit(web, pid, row, [set_field("stage", "TEST")]).status_code == 200
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, {**put["body"], "status": "Closed"})
    assert phase(db, row["id"]) == "done_diff"
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert "status" in state["diff"] and "stage" not in state["diff"]


@pytest.mark.parametrize("broken", [{"createTs": True}, {"settings": None}, {"priority": "High"},
                                    {"linkedIssues": [{"id": 510001, "type": "SAST", "isDeleted": 1}]}])
def test_invalid_full_dto_readable_but_not_queued_for_put(web, broken):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row, hub_body(**broken))
    assert phase(db, row["id"]) == "refused"
    assert not ops(db, "defect_update")
    assert web.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200


def test_second_read_validates_full_dto_and_preview_signature(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    put_click(web, pid, row)
    read_job(web, hub_body(updateTs=True))
    assert phase(db, row["id"]) == "stale" and not ops(db, "defect_update")


@pytest.mark.parametrize("damage", ["missing_diff", "empty_diff", "bad_path", "wrong_version"])
def test_incomplete_new_attempt_never_falls_back_to_text_only_confirmation(web, damage):
    pid, row = ready(web)
    db = web.app.state.db
    assert edit(web, pid, row, [set_field("stage", "TEST")]).status_code == 200
    put = to_put(web, pid, row)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    if damage == "missing_diff":
        state.pop("field_diff")
    elif damage == "empty_diff":
        state["field_diff"], state["changed_roots"] = [], []
    elif damage == "bad_path":
        state["field_diff"] = [{}]
    else:
        state["contract_version"] = "unknown"
    db.hub_defect_update(row["id"], update_json=dumps(state))
    deliver(web, put, 204, text="")
    read_job(web, put["body"])
    assert phase(db, row["id"]) == "unconfirmed"
    assert not db.get_review(pid, "510001")["entered_hub"]


def test_unknown_basis_keeps_explicit_removal_until_operator_initializes(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    db.hub_defect_update(row["id"], draft_fields_basis_json="", confirmed_object_json="", draft_fields_json="{}")
    assert edit(web, pid, row, [{"path": "/tool", "op": "remove"}, set_field("stage", "LOCAL")]).status_code == 200
    current = db.hub_defect(row["id"])
    before = db.hub_ops_list()
    seen = loads(current["import_json"], {})
    response = web.client.post(f"/projects/{pid}/defects/{row['id']}/basis", headers=ORIGIN, data={
        "draft_revision": str(current["draft_revision"]), "source": "observation",
        "shown": defect_references.signature(seen)})
    assert response.status_code == 200, response.text
    after = db.hub_defect(row["id"])
    assert after["confirmed_object_json"] == "" and after["draft_revision"] == current["draft_revision"] + 1
    assert loads(after["draft_fields_json"], {})["stage"] == "LOCAL"
    assert "tool" not in loads(after["draft_fields_json"], {})
    assert defect_fields.basis_of(after)["known"] and db.hub_ops_list() == before


@pytest.mark.parametrize("changes", [{}, [set_field("stage", None)], [set_field("settings", {"unknown": 1})],
                                     [set_field("externalBugs", [{"extension": 1}])], [set_field("priorityId", True)]])
def test_invalid_edit_atomic_and_preserves_input(web, changes):
    pid, row = ready(web)
    db = web.app.state.db
    before, history, queue = db.hub_defect(row["id"]), db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2"), db.hub_ops_list()
    response = edit(web, pid, row, changes, command_text="Не потерять этот текст")
    assert response.status_code == 422 and "Не потерять этот текст" in response.text
    assert db.hub_defect(row["id"]) == before
    assert db._all("SELECT * FROM hub_defect_history ORDER BY 1, 2") == history and db.hub_ops_list() == queue


@pytest.mark.parametrize("change", ["remove_local", "remove_unexported", "add_unexported", "unchanged_unexported"])
def test_repeat_sync_of_accepted_links_matches_without_removing_local_targets(web, change):
    pid = project(web)
    db = web.app.state.db
    links = [(510001, "SAST")]
    if change == "remove_local":
        links.append((510002, "SAST"))
    elif change in ("remove_unexported", "unchanged_unexported"):
        links.append((999001, "SAST"))
    remote = hub_body(links=links)
    row = imported(web, pid, body=remote)
    if change.startswith("remove"):
        remote["linkedIssues"].pop()
    elif change == "add_unexported":
        remote["linkedIssues"].append({"id": 999001, "type": "SAST"})
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, remote)
    before = db.hub_defect(row["id"])
    if change != "unchanged_unexported":
        card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
        # итог сверки с «Применить» – вверху карточки, не в свёрнутом «Подробнее»
        assert f'id="hub-sync-apply-form-{row["id"]}"' in card.split('id="defect-more"', 1)[0]
        assert apply_sync(web, pid, row["id"]).status_code == 200
        accepted = db.hub_defect(row["id"])
        # «источник истины Hub»: отвязанная в Hub цель уходит из состава (пометка «выбыла из дефекта»)
        expected = [t["hub_id"] for t in loads(row["targets_json"], []) if not (change == "remove_local" and t["hub_id"] == "510002")]
        assert [t["hub_id"] for t in loads(accepted["targets_json"], [])] == expected
        assert loads(accepted["confirmed_object_json"], {}) == remote
        before = accepted
        assert act(web, pid, row["id"], "sync").status_code == 200
        read_job(web, remote)
    after = db.hub_defect(row["id"])
    assert loads(after["sync_json"], {})["matches"]
    assert after["targets_json"] == before["targets_json"]
    assert after["draft_revision"] == before["draft_revision"]
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert "совпадают с принятой версией в приложении" in page
    assert f'id="hub-sync-apply-form-{row["id"]}"' not in page


def test_sca_not_ready_card_points_to_finding_card_and_shows_refusal_once(web):
    """Отказ сборки текста SCA показывается один раз и говорит, где его снять."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=hub_body(links=((73001, "SCA_S"), (73002, "SCA_S")), summary="ID5 - example-parser (SCA)"))
    url = f"/projects/{pid}/defects/{row['id']}"
    page = web.client.get(url)
    assert page.status_code == 200
    blocked = page.text.split('id="defect-generate-blocked"', 1)[1].split("</p>", 1)[0]
    anchor = db.get_finding_by_hub_id(pid, "73001")
    assert f'href="/projects/{pid}/sca/findings/{anchor["id"]}#sca-set-title"' in blocked
    assert "Дефект по шаблону команды" in blocked
    assert 'Собрать текст из решений' in page.text and "disabled>Собрать текст из решений" in page.text
    assert f'data-canonical-url="{url}"' in page.text
    refusal = blocked.split("недоступны: ", 1)[1].split(" Исправьте", 1)[0]
    response = web.client.post(url + "/text-from-decisions", headers=ORIGIN,
                               data={"draft_revision": str(db.hub_defect(row["id"])["draft_revision"])})
    assert response.status_code == 409
    top = response.text.split('id="defect-more"', 1)[0]
    assert top.count(refusal) == 1, "отказ показан один раз – подсказкой с адресом карточки находки"
    assert 'class="flash flash-err"' not in response.text


def test_unknown_basis_has_accept_button_at_the_top(web):
    """Отказ «Push в Hub» про неизвестную основу полей не отсылает к кнопке в свёрнутом «Подробнее»: кнопка вверху."""
    pid, row = ready(web, build=False)
    db = web.app.state.db
    db.hub_defect_update(row["id"], draft_fields_basis_json="", confirmed_object_json="", draft_fields_json="{}")
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    top = page.split('id="defect-more"', 1)[0]
    assert 'id="defect-basis-top"' in top and 'id="defect-basis-accept"' in top and "Принять поля из Hub" in top
    current = db.hub_defect(row["id"])
    response = web.client.post(f"/projects/{pid}/defects/{row['id']}/basis", headers=ORIGIN, data={
        "draft_revision": str(current["draft_revision"]), "source": "observation",
        "shown": defect_references.signature(loads(current["import_json"], {}))})
    assert response.status_code == 200, response.text
    assert 'id="defect-basis-top"' not in web.client.get(f"/projects/{pid}/defects/{row['id']}").text
