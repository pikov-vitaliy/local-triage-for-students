"""Круг 1 dev2: применение, последующая отправка и поиск на выдуманных данных."""

from copy import deepcopy
from datetime import date, timedelta
from hashlib import sha256
from html import unescape
from pathlib import Path
import re

import pytest

from app import defect_drafts, defect_fields, hub_pull as pull, hub_sync as sync, hub_sync_compare as compare
from app.db import SCHEMA_VERSION, loads
from test_defect import save_sast
from test_defect_references import start_load, finish_load
from test_hub_composition_audit import seed_catalog
from test_hub_defect_guard import created, link_fields
from test_hub_defect_import import deliver, take
from test_hub_defect_update import hub_body, ready, to_put, phase
from test_hub_defects import FIX, REASON, hub_job, no_job, pair_project, sast_ready
from test_hub_pull import PullHub, accept, read
from test_hub_status_routes import AS_JSON, HUB, decide, project, run_worker, sast, send
from test_hub_sync import run, store  # noqa: F401
from test_web import web  # noqa: F401


def project_hub(db, pid, bodies=()):
    hub = PullHub(count=0, defects=False)
    hub.issues = {int(r["hub_id"]): {"id": int(r["hub_id"]), "appId": 7, "status": "Open",
                                   "currentBranch": "main", "issueBranchBriefData": []}
                  for r in db._all("SELECT * FROM findings WHERE project_id=?", (pid,))}
    hub.defects = {b["id"]: deepcopy(b) for b in bodies}
    return hub


def restore_first(db, pid, kind):
    pending = db._one("SELECT * FROM hub_sync_pending WHERE entity_kind=? ORDER BY id DESC LIMIT 1", (kind,))
    assert pending
    target = {"project_id": pid, "hub_url": HUB, "app_id": 7}
    ctx = pull.pending_context(db, target, pending["id"])
    pull.restore(db, target, pending["id"], ctx["confirmation"])
    return pending


def test_a1_apply_then_recompare_keeps_current_observations(store):
    db, _ = store
    rid = read(store, PullHub())
    accept(db, rid)
    ops = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    applications = db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2")
    compare.recompare(db, rid)
    assert all("stale" not in loads(i["diff_json"], {})["groups"] for i in db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2"))
    assert sync.passport(run(db, rid))["matches_snapshot"]
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == ops
    assert db._all("SELECT * FROM hub_sync_applications ORDER BY 1, 2") == applications


@pytest.mark.parametrize("column,value", [("accepted_epoch", 99), ("accepted_hash", "changed")])
def test_a1_other_acceptance_still_invalidates_observation(store, column, value):
    db, _ = store
    rid = read(store, PullHub())
    accept(db, rid)
    with db._tx() as c:
        c.execute(f"UPDATE hub_entity_versions SET {column}=?", (value,))
    compare.recompare(db, rid)
    assert all("stale" in loads(i["diff_json"], {})["groups"] for i in db._all("SELECT * FROM hub_sync_items ORDER BY 1, 2"))


def test_b1_create_apply_edit_update_without_reconfirming_review(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url, defect_id=777)
    review = db.get_review(pid, "510001")
    body = hub_body(summary=row["summary"], description=row["body_html"])
    hub = project_hub(db, pid, [body])
    rid = read((db, pid), hub)
    ops = db._all("SELECT * FROM hub_ops ORDER BY 1, 2")
    accept(db, rid)
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == ops
    assert db.get_review(pid, "510001") == review
    row = db.hub_defect(row["id"])
    saved = defect_drafts.save(db, row, row["draft_revision"], summary=row["summary"] + " уточнён",
                               command=row["command_text"] + "\n2) Дополнение команды.")
    put = to_put(web, pid, saved, first=body)
    assert put["body"]["summary"] == saved["draft_summary"]
    assert "Дополнение команды." in put["body"]["description"]
    deliver(web, put, 204, text="")
    confirmation = take(web)
    assert confirmation["method"] == "GET"
    deliver(web, confirmation, body=put["body"])
    assert phase(db, row["id"]) == "done"
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_update"]) == 1
    no_job(web)


@pytest.mark.parametrize("status", ["False Positive", "Accepted risk"])
def test_b1_conflicting_hub_decision_archives_already_sent_operator_decision(web, status):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    hub = project_hub(db, pid, [loads(row["confirmed_object_json"], {})])
    hub.manual[510001] = {"issueId": 510001, "issueType": "SAST", "status": status,
                         "reason": "Решение Hub", "expiredAt": None}
    hub.issues[510001]["status"] = status
    rid = read((db, pid), hub)
    accept(db, rid)
    assert db.get_review(pid, "510001")["decision_origin"] == "hub_sync"
    # dev15 (план п. 1.3): решение Hub заменяет «Подтверждаю дефект» – вывод оператора в истории (`saved`), не
    # «ждёт отправки» и не отличие
    saved = db._all("SELECT * FROM hub_sync_pending WHERE entity_kind='issue'")
    assert [r["state"] for r in saved] == ["saved"]
    assert loads(saved[0]["payload_json"], {})["local"]["review"]["final_verdict"] == "true_positive"
    before = db._one("SELECT before_json FROM hub_sync_applications WHERE run_id=? AND entity_kind='issue'"
                     " AND entity_key='SAST:510001'", (rid,))
    assert loads(before["before_json"], {})["local"]["review"]["final_verdict"] == "true_positive"


def test_b1_create_after_apply_keeps_operator_confirmation(web):
    from test_hub_defects import to_preview, create
    pid, url = sast_ready(web)
    db = web.app.state.db
    before = db.get_review(pid, "510001")
    accept(db, read((db, pid), project_hub(db, pid)))
    assert db.get_review(pid, "510001") == before
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    post = hub_job(web, body={"id": 777})
    hub_job(web, body={**post["body"], "id": 777}, raw=True)
    assert db.hub_defect(row["id"])["state"] == "done"
    no_job(web)


@pytest.mark.parametrize("extra_link", [False, True])
def test_a2_create_apply_changed_block_then_link(web, extra_link):
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = created(web, pid, url)
    sibling, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    body = loads(row["confirmed_object_json"], {})
    # в Hub блок изменился (dev30: созданное описание уже несёт блок заготовки – он заменяется новым)
    head = body["description"].split("\n<p>Информация об объекте сканирования:")[0]
    body["description"] = head + "\n<p>Информация об объекте сканирования:</p><p>Новый блок Hub</p>"
    assert "Новый блок Hub" in body["description"]
    hub = project_hub(db, pid, [body])
    accept(db, read((db, pid), hub))
    response = web.client.post(sibling + "/hub-defect-link", headers=AS_JSON,
                               data=link_fields(web.client.get(sibling).text))
    assert response.status_code == 200, response.text
    link = hub_job(web)
    assert link["method"] == "POST" and link["path"].endswith("/link")
    body["linkedIssues"].append({"id": 510005, "type": "SAST"})
    if extra_link:
        body["linkedIssues"].append({"id": 999, "type": "SAST"})
    hub_job(web, body=body, raw=True)
    result = db.hub_defect(response.json()["defect_id"])
    assert result["body_html"] == body["description"]
    assert result["state"] == ("unconfirmed" if extra_link else "done"), result["error"]
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_link"]) == 1
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1
    no_job(web)


@pytest.mark.parametrize("field,value", [("releaseObject", {"id": "21", "name": "Release"}),
                                         ("structureUnitId", 11)])
def test_a3_reference_restore_keeps_new_base_and_prepares_put(web, field, value):
    pid, row = ready(web)
    db = web.app.state.db
    url, load, data = start_load(web, pid, row)
    assert web.client.post(url + "/references/load", headers=AS_JSON, data=data).status_code == 200
    finish_load(web, pid)
    row = db.hub_defect(row["id"])
    operations = [{"op": "set", "path": "/" + field, "value": value}]
    if field == "structureUnitId":
        operations.append({"op": "set", "path": "/appStructureUnit", "value": {"id": "11", "name": "Unit"}})
    saved = defect_drafts.save(db, row, row["draft_revision"], summary=row["draft_summary"],
                               command=row["draft_command_text"], operations=operations, reference_load=load["id"])
    body = hub_body(dueDate="2027-01-01T00:00:00Z")
    accept(db, read((db, pid), project_hub(db, pid, [body])))
    restore_first(db, pid, "defect")
    restored = db.hub_defect(row["id"])
    assert defect_fields.basis_of(restored)["base"] == defect_fields.fields_of(body)
    assert defect_fields.basis_of(restored)["references"] == defect_fields.basis_of(saved)["references"]
    put = to_put(web, pid, restored, first=body)
    assert put["body"][field] == value


def test_a4_failed_status_intent_restores_expiry_and_form(web):
    pid = project(web, [sast("1")])
    db = web.app.state.db
    decide(web, pid, "1")
    expiry = (date.today() + timedelta(days=60)).isoformat()
    response = send(web, pid, "1", extra={"expires": expiry})
    assert response.status_code == 200, response.text
    job = run_worker(web, status=400, body={"message": "Отказ"})
    assert job["body"]["expiredAt"] == expiry + "T00:00:00Z"
    assert db.get_review(pid, "1")["desired_hub_expired_at"] is None
    accept(db, read((db, pid), project_hub(db, pid)))
    # в Hub решения нет: решение оператора не затирается и не требует восстановления
    review = db.get_review(pid, "1")
    assert review["decision_origin"] != "hub_sync" and review["final_verdict"]


def test_b2_catalog_levels_follow_new_and_updated_accepted_version(web):
    db = web.app.state.db
    pid = project(web, [])
    hub = PullHub()
    for priority, severity in [("High", "Medium"), ("Low", "Critical")]:
        hub.defects[77]["priority"]["name"] = priority
        hub.defects[77]["severity"]["name"] = severity
        accept(db, read((db, pid), hub))
        page = web.client.get(f"/projects/{pid}/defects").text
        assert f'<td data-label="Приоритет">{priority}</td>' in page
        assert f'<td data-label="Серьёзность">{severity}</td>' in page


@pytest.mark.skipif("## [0.9.25.dev1]" not in (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(encoding="utf-8"),
                    reason="история выпусков до публичного снимка в него не входит")
def test_b3_dev1_upgrade_instructions_match_schema_and_worker():
    root = Path(__file__).resolve().parents[1]
    digest = sha256((root / "deploy/hub-worker/hub_worker.py").read_bytes()).hexdigest()
    for file in ("README.md", "CHANGELOG.md"):
        text = (root / file).read_text(encoding="utf-8").split("## [0.9.25.dev1]")[0]
        assert f"схема {SCHEMA_VERSION}" in text.lower()
        assert "31 до 32" in text and "замените исполнитель" in text.lower()
        assert digest in text
        assert "Исполнитель не менялся" not in text and "Схема 31 и протокол 2 сохранены" not in text
    assert digest in (root / "deploy/hub-worker/README.md").read_text(encoding="utf-8")


def test_b4_sync_search_covers_entire_result_and_pagination(web):
    db = web.app.state.db
    pid = project(web, [])
    rid = read((db, pid), PullHub(count=120, defects=False))
    url = f"/projects/{pid}/hub-sync/{rid}"
    found = web.client.get(url, params={"q": "SAST:99"}).text
    assert re.findall(r'data-sync-item="([^"]+)"', found) == ["issue:SAST:99"]
    first = web.client.get(url, params={"q": "SAST:"}).text
    assert 'id="hub-sync-query" name="q" value="SAST:"' in first
    next_url = unescape(re.search(r'href="([^"]+)">Следующая страница', first)[1])
    assert "q=SAST%3A" in next_url
    second = web.client.get(next_url).text
    first_ids = set(re.findall(r'data-sync-item="([^"]+)"', first))
    second_ids = set(re.findall(r'data-sync-item="([^"]+)"', second))
    assert len(first_ids) == len(second_ids) == 50 and first_ids.isdisjoint(second_ids)
    assert "Найдено: 0." in web.client.get(url, params={"q": "missing"}).text


def test_b5_catalog_search_normalizes_unicode_for_rows_and_count(web):
    db = web.app.state.db
    pid = project(web, [])
    seed_catalog(db, pid, count=60)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET summary='ДЕМО Е\u0308лка' WHERE project_id=?", (pid,))
    for query in ("демо ёлка", "ДеМо ЁЛКА", "демо е\u0308лка"):
        assert db.hub_defects_total(pid, query) == 60
        assert len(db.hub_defects(pid, limit=50, offset=50, query=query)) == 10


def test_b6_catalog_card_returns_to_same_page_and_query(web):
    db = web.app.state.db
    pid = project(web, [])
    seed_catalog(db, pid, count=60)
    base = f"/projects/{pid}/defects"
    listing = web.client.get(base, params={"q": "демо", "page": 2, "page_size": 50}).text  # по умолчанию 200
    card_url = unescape(re.search(r'<td data-label="Заголовок"[^>]*><a href="([^"]+)"', listing)[1])
    assert "page=2" in card_url and "q=" in card_url and "page_size=50" in card_url
    card = web.client.get(card_url).text
    back = unescape(re.search(r'<a href="([^"]+)">Дефекты</a>', card)[1])
    assert "page=2" in back and "q=" in back
    returned = web.client.get(back).text
    assert re.findall(r'data-defect-id="(\d+)"', listing) == re.findall(r'data-defect-id="(\d+)"', returned)
    assert 'value="демо"' in returned
