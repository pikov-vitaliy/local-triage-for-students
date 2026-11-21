"""Точный состав создания и привязки; полный каталог без скрытых строк. Данные выдуманы."""

from copy import deepcopy
import re

import pytest

from app import hub_defects
from app.db import loads
from test_defect import save_sast
from test_hub_defect_guard import created, link_fields
from test_hub_defects import FIX, REASON, create, hub_job, no_job, pair_project, sast_ready, to_preview, verify
from test_hub_status_routes import AS_JSON
from test_web import web  # noqa: F401


@pytest.mark.parametrize("unknown", [False, True])
@pytest.mark.parametrize("change", ["extra", "wrong_type", "missing"])
def test_aud06_create_and_recovery_require_exact_composition(web, unknown, change):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    post = hub_job(web, status=503 if unknown else 200, body={"id": 555})
    # Ответ строится из действительно отправленного POST, не из текущего состояния БД.
    remote = deepcopy(post["body"])
    remote["id"] = 555
    if change == "extra":
        remote["linkedIssues"].append({"id": 999, "type": "SAST"})
    elif change == "wrong_type":
        remote["linkedIssues"][0]["type"] = "SCA_S"
    else:
        remote["linkedIssues"] = []
    if unknown:
        assert verify(web, pid, row["id"]).status_code == 200
        hub_job(web, body={"filteredEntities": [{"id": 555, "summary": post["body"]["summary"]}], "totalEntitiesCount": 1})
    hub_job(web, body=remote, raw=True)
    if change == "missing" and not unknown:
        hub_job(web)  # предусмотренная первая привязка, без повторного создания
        hub_job(web, body=remote, raw=True)
    after = db.hub_defect(row["id"])
    assert after["state"] != "done"
    assert not db.get_review(pid, "510001")["entered_hub"]
    if change != "missing":
        assert after["state"] == "unconfirmed"
        diff = loads(after["verify_json"], {})["composition"]
        assert diff["extra"]
        assert bool(diff["missing"]) is (change == "wrong_type")
        assert "Лишние связи" in hub_defects.view(after)["text"]
        assert verify(web, pid, row["id"]).status_code == 200
        correct = dict(post["body"], id=555)
        read = hub_job(web, body=correct, raw=True)
        assert read["method"] == "GET" and db.hub_defect(row["id"])["state"] == "done"
        before = db.get_review(pid, "510001")
        hub_defects._on_read(db, db.hub_defect(row["id"]), db.hub_op(read["op_id"]))
        assert db.get_review(pid, "510001") == before
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1
    no_job(web)


@pytest.mark.parametrize("change", ["none", "extra", "missing_previous", "missing_new"])
def test_aud06_link_keeps_previous_and_requires_exact_union(web, change):
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    parent = created(web, pid, url)
    sibling, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    response = web.client.post(sibling + "/hub-defect-link", headers=AS_JSON,
                               data=link_fields(web.client.get(sibling).text))
    assert response.status_code == 200, response.text
    row_id = response.json()["defect_id"]
    link = hub_job(web)
    assert link["method"] == "POST" and link["path"].endswith("/link")
    remote = loads(parent["confirmed_object_json"], {})
    remote["linkedIssues"].append({"id": 510005, "type": "SAST"})
    if change == "extra":
        remote["linkedIssues"].append({"id": 999, "type": "SAST"})
    elif change == "missing_previous":
        remote["linkedIssues"].pop(0)
    elif change == "missing_new":
        remote["linkedIssues"].pop()
    hub_job(web, body=remote, raw=True)
    assert (db.hub_defect(row_id)["state"] == "done") is (change == "none")
    assert bool(db.get_review(pid, "510005")["entered_hub"]) is (change == "none")
    assert db.get_review(pid, "510001")["entered_hub"]
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1
    no_job(web)


def seed_catalog(db, pid, count=501):
    with db._tx() as c:
        c.executemany("INSERT INTO hub_defects(project_id,kind,state,summary,created_at,updated_at)"
                      " VALUES (?,'SAST','mismatch',?,'','')", [(pid, f"Демо {i:04d}") for i in range(count)])


def test_aud04_catalog_pages_and_search_have_exact_count(web):
    db = web.app.state.db
    pid = db.create_project("Демо каталога")
    seed_catalog(db, pid)
    base = f"/projects/{pid}/defects"
    seen = []
    for page in range(1, 12):
        response = web.client.get(base, params={"page": page, "page_size": 50})  # с 0.9.26.dev4 по умолчанию 200
        assert response.status_code == 200
        assert "Всего: 501." in response.text
        seen.extend(re.findall(r'<tr data-defect-id="(\d+)"', response.text))
    assert len(seen) == len(set(seen)) == 501
    assert "Демо 0000" in web.client.get(base, params={"page": 11, "page_size": 50}).text
    found = web.client.get(base, params={"q": "0000"}).text
    assert "Всего: 1." in found and "Демо 0000" in found
    found = web.client.get(base, params={"q": "Демо", "page": 2}).text
    assert 'page=3&amp;q=' in found and "Всего: 501." in found
    assert not db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
