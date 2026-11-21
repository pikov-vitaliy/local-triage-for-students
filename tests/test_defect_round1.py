"""Регрессии круга 1: расширения свежего DTO, приоритет и приложение подтверждения."""

import copy
import json

import pytest

from app import defect_fields as fields
from app import hub_defects
from test_defect import save_sast
from test_defect_dev1b import edit
from test_defect_fields import dto
from test_hub_defect_guard import created, link_fields
from test_hub_defect_update import hub_body, ops, put_click, read_job, ready, take, to_preview as update_preview
from test_hub_defects import FIX, REASON, create, hub_job, no_job, pair_project, sast_ready, to_preview, verify
from test_hub_status_routes import AS_JSON
from test_web import web  # noqa: F401


@pytest.mark.parametrize("root,base_value,local_value", [
    ("settings", {"isInheritedARStatusFromDefect": False}, fields.MISSING),
    ("releaseObject", {"id": "1"}, fields.MISSING),
    ("appStructureUnit", {"id": "1"}, fields.MISSING),
    ("externalBugs", [{"product": "one", "link": "old"}], [{"product": "one", "link": "new"}]),
    ("externalBugs", [{"product": "one"}], fields.MISSING),
    ("externalBugs", [{"product": "one"}], []),
])
def test_round1_candidate_rejects_loss_of_fresh_extensions(root, base_value, local_value):
    base = dto(**{root: base_value})
    draft = fields.fields_of(base)
    if local_value is fields.MISSING:
        draft.pop(root)
    else:
        draft[root] = local_value
    row = {"hub_defect_id": "777", "app_id": 7, "draft_fields_json": json.dumps(draft),
           "draft_fields_basis_json": json.dumps(fields.new_basis(base, "test"))}
    fresh = copy.deepcopy(base)
    container = fresh[root][0] if isinstance(fresh[root], list) else fresh[root]
    container["extension"] = {"nested": [None, False, 0, "", {"value": "точно\nкак есть"}]}
    before = copy.deepcopy(fresh)
    with pytest.raises(fields.FieldError, match="расширение"):
        fields.candidate(fresh, row, base["summary"], "text")
    assert fields.equal(fresh, before)


@pytest.mark.parametrize("identity", [{"priorityId": 10}, {"rank": 1}, {"priorityId": 10, "rank": 1}])
def test_round1_candidate_rechecks_priority_identity(identity):
    base = dto(priority={"name": "Low"})
    draft = fields.edit(fields.fields_of(base), [{"path": "/priority/name", "op": "set", "value": "High"}],
                        {"priorities": ["High"]})
    row = {"hub_defect_id": "777", "app_id": 7, "draft_fields_json": json.dumps(draft),
           "draft_fields_basis_json": json.dumps(fields.new_basis(base, "test"))}
    fresh = copy.deepcopy(base)
    if "rank" in identity:
        fresh["priority"]["rank"] = identity["rank"]
    if "priorityId" in identity:
        fresh["priorityId"] = identity["priorityId"]
    with pytest.raises(fields.FieldError, match="соответствия"):
        fields.candidate(fresh, row, base["summary"], "text")


@pytest.mark.parametrize("boundary", ["preview", "second_read"])
def test_round1_fresh_extension_prevents_put_queue(web, monkeypatch, boundary):
    pid, row = ready(web)
    assert edit(web, pid, row, [{"path": "/settings", "op": "remove"}]).status_code == 200
    before = web.app.state.db.hub_defect(row["id"])
    fresh = hub_body(settings={"extension": {"nested": [False, None]}})
    if boundary == "second_read":
        # Сохранённый предпросмотр прежней реализации: второе чтение обязано проверить его заново.
        with monkeypatch.context() as old_preview:
            old_preview.setattr(fields, "_extensions_unchanged", lambda *args, **kwargs: None)
            update_preview(web, pid, row, fresh)
        assert put_click(web, pid, row).status_code == 200
        read_job(web, fresh)
    else:
        update_preview(web, pid, row, fresh)
    after = web.app.state.db.hub_defect(row["id"])
    assert hub_defects.update_state(after)["phase"] == ("stale" if boundary == "second_read" else "refused")
    assert after["draft_fields_json"] == before["draft_fields_json"]
    assert not ops(web.app.state.db, "defect_update")
    assert take(web) is None


@pytest.mark.parametrize("app_id", [8, None, "missing", True])
@pytest.mark.parametrize("flow", ["create", "auto_link", "recover", "link"])
def test_round1_confirmation_requires_operation_app(web, app_id, flow):
    db = web.app.state.db
    if flow == "link":
        pid = pair_project(web)
        url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
        parent = created(web, pid, url)
        sibling, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
        response = web.client.post(sibling + "/hub-defect-link", headers=AS_JSON,
                                   data=link_fields(web.client.get(sibling).text))
        assert response.status_code == 200
        row = db.hub_defect(response.json()["defect_id"])
        hub_job(web)
        correct = dict(json.loads(parent["confirmed_object_json"]), appId=7,
                       linkedIssues=[{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}])
        target = "510005"
    else:
        pid, url = sast_ready(web)
        row = to_preview(web, pid, url)
        assert create(web, pid, row["id"]).status_code == 200
        post = hub_job(web, status=503 if flow == "recover" else 200, body={"id": 555})
        correct = dict(post["body"], id=555, appId=7, linkedIssues=[{"id": 510001, "type": "SAST"}])
        target = "510001"
        if flow == "recover":
            assert verify(web, pid, row["id"]).status_code == 200
            hub_job(web, body={"filteredEntities": [{"id": 555, "summary": correct["summary"]}], "totalEntitiesCount": 1})
    observed = copy.deepcopy(correct)
    if flow == "auto_link":
        observed["linkedIssues"] = []
    if app_id == "missing":
        observed.pop("appId")
    else:
        observed["appId"] = app_id
    writes = [o for o in db.hub_ops_list() if o["purpose"] in ("defect_create", "defect_link")]
    hub_job(web, body=observed, raw=True)
    after = db.hub_defect(row["id"])
    assert after["state"] == "unknown" and "appId" in after["error"]
    assert after["confirm_op_id"] is None and not after["confirmed_object_json"]
    assert not db.get_review(pid, target)["entered_hub"]
    assert db.defect_number(pid, "sast:" + target) is None
    assert len([o for o in db.hub_ops_list() if o["purpose"] in ("defect_create", "defect_link")]) == len(writes)
    no_job(web)
    assert verify(web, pid, row["id"]).status_code == 200
    assert hub_job(web, body=correct, raw=True)["method"] == "GET"
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, target)["entered_hub"]
    no_job(web)
