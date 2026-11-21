"""Три справочных GET: независимый контекст, явное подтверждение, сохранённые результаты."""

import copy
import json
from types import SimpleNamespace

import pytest

from app import defect_references as refs, hub_ops
from app.db import loads
from app.defect_dto import DEFECT_CONTRACT
from test_defect_fields import dto
from test_hub_defect_import import deliver, imported, project, take
from test_hub_status_routes import HUB
from test_hub_worker import hw
from test_web import ORIGIN, web  # noqa: F401

ANSWERS = [
    {"statuses": ["Open"], "priorities": ["High", "Low"]},
    [{"id": 11, "name": "Unit"}],
    {"structureUnits": [{"id": "11", "name": "Unit"}], "releaseObjects": [{"id": "21", "name": "Release"}]},
]


@pytest.mark.parametrize("req,app_id,purpose,valid", [
    ({"method": "GET", "path": "/defects/serviceInfo"}, 7, "defect_reference", True),
    ({"method": "GET", "path": "/application/7/structureUnits"}, 7, "defect_reference", True),
    ({"method": "GET", "path": "/releaseObject/filters?appId=7"}, 7, "defect_reference", True),
    ({"method": "GET", "path": "/application/8/structureUnits"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/releaseObject/filters?appId=8"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/releaseObject/filters"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/releaseObject/filters?appId=7&appId=7"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/releaseObject/filters?appId=7&extra=1"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/releaseObject/filters?appId=true"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/defects/777"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/application/7/structureUnits"}, 7, "read", False),
    ({"method": "GET", "path": "/releaseObject/filters?appId=7"}, 7, "probe", False),
    ({"method": "POST", "path": "/defects/serviceInfo"}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/defects/serviceInfo", "body": {}}, 7, "defect_reference", False),
    ({"method": "GET", "path": "/defects/serviceInfo"}, None, "defect_reference", False),
    ({"method": "GET", "path": "/defects/serviceInfo"}, "7", "defect_reference", False),
    ({"method": "GET", "path": "/defects/serviceInfo"}, True, "defect_reference", False),
    ({"method": "PUT", "path": "/defects/777", "body": dto(), "contract_version": DEFECT_CONTRACT}, 7, "defect_update", True),
    ({"method": "PUT", "path": "/defects/778", "body": dto(), "contract_version": DEFECT_CONTRACT}, 7, "defect_update", False),
    ({"method": "PUT", "path": "/defects/777", "body": dto(), "contract_version": DEFECT_CONTRACT}, 8, "defect_update", False),
])
def test_operation_contract_on_both_sides(req, app_id, purpose, valid):
    job = {**req, "app_id": app_id, "purpose": purpose, "hub_url": HUB}
    if valid:
        hub_ops.check_operation(purpose, req, app_id)
        hw.check_job(job, HUB)
    else:
        with pytest.raises(ValueError):
            hub_ops.check_operation(purpose, req, app_id)
        with pytest.raises(hw.Refused):
            hw.check_job(job, HUB)


def start_load(web, pid, row):
    url = f"/projects/{pid}/defects/{row['id']}"
    page = web.client.post(url + "/references/prepare", headers=ORIGIN)
    assert page.status_code == 200, page.text
    found = web.app.state.db._one("SELECT * FROM hub_defect_reference_loads ORDER BY id DESC LIMIT 1")
    data = {"load_id": str(found["id"]), "shown": refs.signature(loads(found["load_json"], {})), "action": "confirm"}
    return url, found, data


def finish_load(web, pid, answers=ANSWERS):
    jobs = []
    for body in answers:
        job = take(web)
        assert job is not None
        jobs.append(job)
        deliver(web, job, body=body)
        refs.sync(web.app.state.db, pid)
    return jobs


def test_actual_jobs_carry_saved_app_context_and_refusal_never_contacts_hub(web):
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    old_ops = db.hub_ops_list()
    url, load, data = start_load(web, pid, row)
    assert db.hub_ops_list() == old_ops
    response = web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    assert response.status_code == 200, response.text
    job = take(web)
    op = db.hub_op(job["op_id"])
    assert job["app_id"] == op["app_id"] == 7
    hw.check_job(job, HUB)
    rejected = []
    def no_http(*args):
        pytest.fail("HTTP к Hub при отказе исполнителя")
    def delivered(attempt, payload, **kwargs):
        rejected.append(payload)
        return "ok"
    for invalid in ({k: v for k, v in job.items() if k != "app_id"}, {**job, "app_id": None},
                    {**job, "path": "/application/8/structureUnits"},
                    {**job, "path": "/releaseObject/filters?appId=8"}):
        hw.run_job(SimpleNamespace(request=no_http), SimpleNamespace(deliver=delivered), invalid, HUB)
    assert len(rejected) == 4 and all(p["not_sent"] for p in rejected)
    deliver(web, job, body=ANSWERS[0])
    finish_load(web, pid, ANSWERS[1:])
    refs.sync(db, pid)
    stored = db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (load["id"],))
    assert stored["state"] == "done"
    projection = loads(stored["load_json"], {})["projection"]
    assert projection["structureUnits"] == [{"structureUnitId": 11, "appStructureUnit": {"id": "11", "name": "Unit"}}]
    before = db.hub_ops_list()
    for _ in range(2):
        refs.sync(db, pid)
        web.client.get(url)
    assert db.hub_ops_list() == before and take(web) is None


def test_cancel_and_changed_target_enqueue_nothing(web):
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    before = db.hub_ops_list()
    url, _, data = start_load(web, pid, row)
    assert web.client.post(url + "/references/load", headers=ORIGIN, data={**data, "action": "cancel"}).status_code == 200
    assert db.hub_ops_list() == before
    url, _, data = start_load(web, pid, row)
    with db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = 8 WHERE id = ?", (pid,))
    assert web.client.post(url + "/references/load", headers=ORIGIN, data=data).status_code == 409
    assert db.hub_ops_list() == before


def test_failed_partial_load_retains_previous_snapshot_and_duplicate_delivery(web):
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    url, first, data = start_load(web, pid, row)
    web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    jobs = finish_load(web, pid)
    saved = db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (first["id"],))
    deliver(web, jobs[-1], body=ANSWERS[-1])
    refs.sync(db, pid)
    assert db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (first["id"],)) == saved
    url, second, data = start_load(web, pid, row)
    web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    deliver(web, take(web), status=503, text="error")
    refs.sync(db, pid)
    partial = db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (second["id"],))
    assert partial["state"] == "loading" and len(loads(partial["load_json"], {})["results"]) == 1
    finish_load(web, pid, ANSWERS[1:])
    assert db._one("SELECT state FROM hub_defect_reference_loads WHERE id = ?", (second["id"],))["state"] == "failed"
    assert db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (first["id"],)) == saved
    assert f'name="reference_load" value="{first["id"]}"' in web.client.get(url).text
    assert take(web) is None


@pytest.mark.parametrize("kind", ["duplicate", "mismatch", "missing", "same_name_other_id"])
def test_no_ambiguous_structure_choices(kind):
    answers = copy.deepcopy(ANSWERS)
    if kind == "duplicate":
        answers[1].append({"id": 11, "name": "Unit"})
    elif kind == "mismatch":
        answers[2]["structureUnits"][0]["name"] = "Other"
    elif kind == "missing":
        answers[2]["structureUnits"] = []
    else:
        answers[2]["structureUnits"][0]["id"] = "12"
    assert refs.projection(answers)["structureUnits"] == []


def test_reference_response_json_is_not_silently_coerced():
    answers = copy.deepcopy(ANSWERS)
    answers[1][0]["id"] = "11"
    with pytest.raises(ValueError):
        refs.projection(answers)
    assert json.loads(json.dumps(ANSWERS)) == ANSWERS


def test_error_form_keeps_variants_from_its_own_reference_load(web):
    pid = project(web)
    row = imported(web, pid)
    url, first, data = start_load(web, pid, row)
    web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    finish_load(web, pid)
    _, _, data = start_load(web, pid, row)
    web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    newer = copy.deepcopy(ANSWERS)
    newer[2]["releaseObjects"] = [{"id": "22", "name": "Different"}]
    finish_load(web, pid, newer)
    form = {"draft_revision": str(row["draft_revision"]), "summary": row["draft_summary"], "command_text": row["draft_command_text"],
            "reference_load": str(first["id"]), "f_releaseObject_mode": "set", "f_releaseObject_value": "0",
            "f_dueDate_mode": "set", "f_dueDate_value": "wrong date"}
    page = web.client.post(url + "/fields", headers=ORIGIN, data=form)
    assert page.status_code == 422
    import re
    options = re.search(r'<select name="f_releaseObject_value">(.*?)</select>', page.text, re.S).group(1)
    assert "Release" in options and "Different" not in options and "wrong date" in page.text
    form["f_dueDate_value"] = "2026-12-01T09:00:00Z"
    assert web.client.post(url + "/fields", headers=ORIGIN, data=form).status_code == 200
    assert loads(web.app.state.db.hub_defect(row["id"])["draft_fields_json"], {})["releaseObject"] == ANSWERS[2]["releaseObjects"][0]


def test_truncated_reference_json_never_becomes_a_choice(web):
    pid = project(web)
    row = imported(web, pid)
    db = web.app.state.db
    url, load, data = start_load(web, pid, row)
    web.client.post(url + "/references/load", headers=ORIGIN, data=data)
    job = take(web)
    deliver(web, job, body=ANSWERS[0])
    with db._tx() as c:
        result = loads(db.hub_op(job["op_id"])["result_json"], {})
        result["truncated"] = True
        c.execute("UPDATE hub_ops SET result_json = ? WHERE id = ?", (json.dumps(result), job["op_id"]))
    finish_load(web, pid, ANSWERS[1:])
    found = db._one("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (load["id"],))
    assert found["state"] == "failed" and "projection" not in loads(found["load_json"], {})
    assert take(web) is None
