"""Круг 2: справочный выбор при изменении Hub до первого чтения, предпросмотр и очередь PUT."""

import copy

import pytest

from app import defect_fields as fields, defect_references as refs, hub_defects
from app.db import dumps, loads
from test_defect_dev1b import edit, set_field
from test_defect_references import ANSWERS, finish_load, start_load
from test_hub_defect_update import hub_body, note, ops, phase, put_click, read_job, ready, take, to_preview
from test_web import ORIGIN, web  # noqa: F401


def selected_case(web, kind):
    pid, row = ready(web)
    db = web.app.state.db
    if kind == "structureUnits":
        base = hub_body(structureUnitId=11)
        selected = {"structureUnitId": 11, "appStructureUnit": {"id": "11", "name": "Unit"}}
        fresh = hub_body(structureUnitId=22, appStructureUnit={"id": "22", "name": "Other"})
        changes = [set_field("appStructureUnit", selected["appStructureUnit"])]
    else:
        base = hub_body(releaseObject={"id": "21"})
        selected = {"releaseObject": {"id": "21", "name": "Release"}}
        fresh = hub_body(releaseObject={"id": "22", "name": "Other"})
        changes = [set_field("releaseObject/name", "Release")]
    db.hub_defect_update(row["id"], confirmed_object_json=dumps(base),
                         draft_fields_json=dumps(fields.fields_of(base)),
                         draft_fields_basis_json=dumps(fields.new_basis(base, "test")))
    url, load, data = start_load(web, pid, row)
    assert web.client.post(url + "/references/load", headers=ORIGIN, data=data).status_code == 200
    finish_load(web, pid)
    response = edit(web, pid, row, changes, reference_load=str(load["id"]))
    assert response.status_code == 200, response.text
    return pid, db.hub_defect(row["id"]), fresh, selected


@pytest.mark.parametrize("kind", ["structureUnits", "releaseObjects"])
def test_round2_selected_variant_survives_hub_change_before_first_read(web, kind):
    pid, row, fresh, selected = selected_case(web, kind)
    db = web.app.state.db
    before = copy.deepcopy(fresh)
    to_preview(web, pid, row, fresh)
    assert phase(db, row["id"]) == "preview", note(db, row["id"])
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert {k: state["candidate"][k] for k in selected} == selected
    assert state["first"] == fresh == before
    assert not ops(db, "defect_update") and take(web) is None
    assert put_click(web, pid, row).status_code == 200
    read_job(web, fresh)
    queued = ops(db, "defect_update")
    assert len(queued) == 1
    put = take(web)
    assert put is not None and put["method"] == "PUT" and put["path"] == "/defects/777"
    assert put["body"] == state["candidate"]
    assert {k: put["body"][k] for k in selected} == selected
    assert db.hub_defect(row["id"])["draft_fields_json"] == row["draft_fields_json"]
    assert take(web) is None


@pytest.mark.parametrize("kind", ["structureUnits", "releaseObjects"])
@pytest.mark.parametrize("boundary", ["preview", "transaction"])
@pytest.mark.parametrize("corruption", ["mixed_pair", "unlisted_choice"])
def test_round2_candidate_checked_against_saved_choice_before_preview_and_queue(web, monkeypatch, kind, boundary, corruption):
    pid, row, fresh, _ = selected_case(web, kind)
    db = web.app.state.db
    build = fields.candidate

    if corruption == "mixed_pair":
        # Имитируется прежняя сборка: ID свежего Hub и имя локального выбора.
        def mixed_candidate(fresh, row, summary, description):
            body, _, local = build(fresh, row, summary, description)
            if kind == "structureUnits":
                body["structureUnitId"] = fresh["structureUnitId"]
            else:
                body["releaseObject"]["id"] = fresh["releaseObject"]["id"]
            return body, fields.diff(fresh, body), local
        monkeypatch.setattr(fields, "candidate", mixed_candidate)
    else:
        # Тело согласовано с черновиком, но такого варианта нет в сохранённом справочнике.
        draft = loads(row["draft_fields_json"], {})
        if kind == "structureUnits":
            draft.update(structureUnitId=33, appStructureUnit={"id": "33", "name": "Unlisted"})
        else:
            draft["releaseObject"] = {"id": "33", "name": "Unlisted"}
        db.hub_defect_update(row["id"], draft_fields_json=dumps(draft))
        row = db.hub_defect(row["id"])
    if boundary == "transaction":
        # Сохранённый предпросмотр старой реализации. Вторая граница обязана отказать самостоятельно.
        with monkeypatch.context() as legacy:
            legacy.setattr(refs, "check_candidate", lambda *args: None)
            to_preview(web, pid, row, fresh)
        assert phase(db, row["id"]) == "preview"
        assert put_click(web, pid, row).status_code == 200
        checks = []
        check = refs.check_candidate

        def checked_in_transaction(c, current, body):
            checks.append(c.in_transaction)
            return check(c, current, body)
        monkeypatch.setattr(refs, "check_candidate", checked_in_transaction)
        read_job(web, fresh)
    else:
        to_preview(web, pid, row, fresh)
    assert phase(db, row["id"]) == ("refused" if boundary == "preview" else "stale")
    message = note(db, row["id"])
    assert ("/structureUnitId" if kind == "structureUnits" else "/releaseObject") in message
    assert ("выбранным справочным вариантом" if corruption == "mixed_pair" else "сохранённого справочника") in message
    after = db.hub_defect(row["id"])
    for key in ("draft_fields_json", "draft_fields_basis_json", "draft_revision", "confirmed_object_json"):
        assert after[key] == row[key]
    assert not ops(db, "defect_update") and take(web) is None
    if boundary == "transaction":
        assert checks == [True]


def test_round2_new_selection_records_one_source_for_both_structure_fields(web):
    pid, row, _, _ = selected_case(web, "structureUnits")
    db = web.app.state.db
    url, load, data = start_load(web, pid, row)
    assert web.client.post(url + "/references/load", headers=ORIGIN, data=data).status_code == 200
    answers = copy.deepcopy(ANSWERS)
    answers[1][0]["name"] = answers[2]["structureUnits"][0]["name"] = "Renamed"
    finish_load(web, pid, answers)
    assert edit(web, pid, row, [set_field("appStructureUnit/name", "Renamed")],
                reference_load=str(load["id"])).status_code == 200
    current = db.hub_defect(row["id"])
    sources = fields.basis_of(current)["references"]
    assert sources["structureUnitId"] == sources["appStructureUnit"]
    assert sources["structureUnitId"]["load_id"] == load["id"]


@pytest.mark.parametrize("kind", ["structureUnits", "releaseObjects"])
def test_round2_explicit_group_removal_does_not_inherit_new_hub_value(web, kind):
    pid, row, fresh, selected = selected_case(web, kind)
    assert edit(web, pid, row, [{"path": "/" + root, "op": "remove"} for root in selected]).status_code == 200
    to_preview(web, pid, row, fresh)
    db = web.app.state.db
    assert phase(db, row["id"]) == "preview", note(db, row["id"])
    assert put_click(web, pid, row).status_code == 200
    read_job(web, fresh)
    put = take(web)
    assert put is not None and put["method"] == "PUT"
    assert not set(selected).intersection(put["body"])
