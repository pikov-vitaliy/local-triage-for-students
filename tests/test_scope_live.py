"""Бэклог 104: охват разбора «Живые в Hub» по умолчанию. Класс находки – по действующему статусу Hub: Fixed – исправлено,
False Positive и Accepted risk – закрыто решением, пустой и прочие – живая (подписи hub_status_map не участвуют). Очередь и
исключённые охватом – одним чтением в транзакции создания прогона, исключённые – в паспорте прогона. Данные выдуманы."""

from __future__ import annotations

import pytest

from app import db as db_module
from app.db import EmptyQueue
from app.hub_sync_compare import DECISION_STATUSES
from test_finding_status_now import accept_state
from test_hub_status_routes import project, sast
from test_web import ORIGIN, web  # noqa: F401

STATES = {"101": "Fixed", "102": "False Positive", "103": "Accepted risk", "104": "Open", "105": "Confirmed", "106": ""}


def seeded(web) -> int:
    pid = project(web, [sast(h) for h in ("101", "102", "103", "104", "105", "106", "107")])
    for hub_id, status in STATES.items():
        accept_state(web, pid, hub_id, status)
    return pid


def test_closed_statuses_match_hub_decision_statuses():
    assert tuple(s.lower() for s in DECISION_STATUSES) == db_module.HUB_CLOSED_DECISION_STATUSES


def test_queue_for_four_scopes_and_counts(web):  # noqa: F811
    pid = seeded(web)
    db = web.app.state.db
    every = db.sast_queue(pid, "all")
    live = [h for h in every if h in ("104", "105", "106", "107")]
    assert db.sast_queue(pid, "live") == live and set(live) == {"104", "105", "106", "107"}
    assert every[:4] == live and set(every[4:]) == {"101", "102", "103"}, "в охвате «все» сначала живые"
    assert db.sast_queue(pid, "selected", ["101", "104"]) and set(db.sast_queue(pid, "selected", ["101", "104"])) == {"101", "104"}
    assert db.sast_hub_classes(pid) == {"sast_live": 4, "sast_fixed": 1, "sast_closed": 2}
    with db._tx() as c:
        ids, excluded = db.sast_queue_in(c, pid, "live")
    assert ids == live and excluded == {"fixed": 1, "closed": 2}
    with db._tx() as c:
        assert db.sast_queue_in(c, pid, "all")[1] == {}


def test_create_run_writes_queue_and_excluded_from_one_read(web, monkeypatch):  # noqa: F811
    pid = seeded(web)
    db = web.app.state.db
    run_id = db.create_run(pid, "qwen2.5-coder:14b", "live", "sast-v6", [], queue_scope="live")
    items = [r["hub_id"] for r in db._all("SELECT hub_id FROM run_items WHERE run_id = ? ORDER BY seq", (run_id,))]
    assert set(items) == {"104", "105", "106", "107"} and db.get_run(run_id)["total"] == 4
    assert db.run_excluded(run_id) == {"fixed": 1, "closed": 2}
    # паспорт и очередь – из одного результата: подмена статуса после чтения внутри транзакции их не расходит
    real = db.sast_queue_in

    def queue_then_flip(c, project_id, scope, hub_ids=()):
        result = real(c, project_id, scope, hub_ids)
        c.execute("UPDATE hub_issue_states SET confirmed_json = ? WHERE project_id = ? AND issue_id = '104'",
                  ('{"detail": {"status": "Fixed"}}', project_id))
        return result

    monkeypatch.setattr(db, "sast_queue_in", queue_then_flip)
    with db._tx() as c:
        c.execute("UPDATE runs SET state = 'stopped' WHERE id = ?", (run_id,))
    second = db.create_run(pid, "qwen2.5-coder:14b", "live", "sast-v6", [], queue_scope="live")
    assert db.get_run(second)["total"] == 4 and db.run_excluded(second) == {"fixed": 1, "closed": 2}


def test_empty_queue_creates_nothing(web):  # noqa: F811
    pid = project(web, [sast("201")])
    accept_state(web, pid, "201", "Fixed")
    db = web.app.state.db
    before = db._one("SELECT COUNT(*) AS n FROM runs")["n"]
    with pytest.raises(EmptyQueue):
        db.create_run(pid, "qwen2.5-coder:14b", "live", "sast-v6", [], queue_scope="live")
    assert db._one("SELECT COUNT(*) AS n FROM runs")["n"] == before
    r = web.client.post(f"/projects/{pid}/runs", data={"model": "qwen2.5-coder:14b"}, headers=ORIGIN)
    assert r.status_code == 400 and "Нет находок SAST для выбранного охвата" in r.text


def test_project_form_defaults_to_live_and_run_page_names_excluded(web):  # noqa: F811
    pid = seeded(web)
    page = web.client.get(f"/projects/{pid}").text
    assert 'value="live" checked' in page and "Живые в Hub (4)" in page
    assert "включая исправленные и закрытые в Hub (7; исправлено – 1, закрыто решением – 2)" in page
    r = web.client.post(f"/projects/{pid}/runs", data={"model": "qwen2.5-coder:14b"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    run_id = int(r.headers["location"].rsplit("/", 1)[1])
    db = web.app.state.db
    assert db.get_run(run_id)["scope"] == "live"
    run_page = web.client.get(f"/runs/{run_id}").text
    assert "охват: живые в Hub" in run_page and "Исправлено в Hub – 1, закрыто решением – 2: не разбиралось." in run_page
    # прогон «все SAST»: статус Hub не отбирал – строки нет
    r = web.client.post(f"/projects/{pid}/runs", data={"model": "qwen2.5-coder:14b", "scope": "all"}, headers=ORIGIN,
                        follow_redirects=False)
    if r.status_code == 303:
        other = int(r.headers["location"].rsplit("/", 1)[1])
        assert db.run_excluded(other) == {} and 'id="run-excluded"' not in web.client.get(f"/runs/{other}").text
    with db._tx() as c:  # прогон до 0.10.0.dev18 (охват «все SAST», ключа нет): сведений нет
        c.execute("UPDATE runs SET scope = 'all' WHERE id = ?", (run_id,))
        c.execute("UPDATE run_journal SET payload_json = (payload_json::jsonb - 'excluded')::text WHERE run_id = ?", (run_id,))
    assert "Исправленные и закрытые в Hub: сведений нет." in web.client.get(f"/runs/{run_id}").text


def test_form_keeps_live_when_nothing_is_live(web):  # noqa: F811
    pid = project(web, [sast("301"), sast("302")])
    accept_state(web, pid, "301", "Fixed")
    accept_state(web, pid, "302", "False Positive")
    page = web.client.get(f"/projects/{pid}").text
    assert 'value="live" checked>' in page and 'value="all">' in page and "Живые в Hub (0)" in page
