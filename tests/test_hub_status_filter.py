"""Отбор по действующему статусу совпадает с карточкой; данные выдуманы."""

import time
import json

import pytest

from app.db import _CURRENT_HUB_STATUS_SQL, dumps
from app.models import Finding
from app.routes.hub_status_routes import status_now_in
from test_hub_status_routes import HUB, project
from test_web import web  # noqa: F401


@pytest.mark.parametrize("origin", [None, "sync", "status_confirmation", "broken_confirmation"])
@pytest.mark.parametrize("kind,typ", [("SAST", "SAST"), ("SCA", "SCA_S"), ("SCA-license", "SCA_L")])
def test_filter_matches_card(web, origin, kind, typ):
    db = web.app.state.db
    pid = project(web, [Finding(hub_id="00101", kind=kind, status="Open")])
    with db._tx() as c:
        op_id = c.execute("INSERT INTO hub_ops(project_id, hub_url, app_id, purpose, state, request_json, targets_json, op_key, created_at, updated_at)"
                          " VALUES (?, ?, 7, 'status', 'done', ?, ?, 'test-status', '2026-11-06', '2026-11-06') RETURNING id",
                          (pid, HUB, dumps({"body": {"status": "False Positive"}}), dumps([{"hub_id": "00101"}]))).fetchone()[0]
        c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json, confirmed_presence)"
                  " VALUES (?, ?, 7, ?, '101', ?, 'present')", (pid, HUB, typ, dumps({"detail": {"status": "Fixed"}})))
        if origin:
            source = {"origin": "status_confirmation" if origin == "broken_confirmation" else origin,
                      "op_id": -1 if origin == "broken_confirmation" else op_id}
            c.execute("INSERT INTO hub_entity_versions(project_id, hub_url, app_id, entity_kind, entity_key, accepted_source_json)"
                      " VALUES (?, ?, 7, 'issue', ?, ?)", (pid, HUB, typ + ":101", dumps(source)))
    expected = {None: "False Positive", "sync": "Fixed", "status_confirmation": "False Positive",
                "broken_confirmation": "Open"}[origin]
    actual = db.on_connection(lambda c: status_now_in(c, pid, "00101", kind, "Open", HUB, 7))
    assert actual["status"] == expected
    assert expected in db.finding_statuses(pid)
    assert len(db.finding_descriptors(pid, {"hub_status": expected})) == 1
    assert len(db.finding_descriptors(pid, {"hub_status": "Unused"})) == 0
    db.update_project(pid, hub_app_id=8)
    assert db.finding_statuses(pid) == ["Open"]
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": "https://other.example.org"})
    assert db.finding_statuses(pid) == ["Open"]


def test_filter_plan_on_large_synthetic_project(web):
    db = web.app.state.db
    pid = project(web, [Finding(hub_id=str(100000 + n), kind="SAST", status="Open") for n in range(2000)])
    with db._tx() as c:
        c.execute("INSERT INTO hub_entity_versions(project_id, hub_url, app_id, entity_kind, entity_key, accepted_source_json)"
                  " SELECT project_id, ?, 7, 'issue', 'SAST:' || hub_id, ? FROM findings WHERE project_id = ?",
                  (HUB, dumps({"origin": "sync"}), pid))
        c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json, confirmed_presence)"
                  " SELECT project_id, ?, 7, 'SAST', hub_id, ?, 'present' FROM findings WHERE project_id = ?",
                  (HUB, dumps({"detail": {"status": "Fixed"}}), pid))
        for table in ("findings", "hub_entity_versions", "hub_issue_states"):
            c.execute(f"ANALYZE {table}")
        plan = c.execute(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT f.id FROM findings f"
                         f" WHERE f.project_id = ? AND {_CURRENT_HUB_STATUS_SQL} = ?", (pid, "Fixed")).fetchone()[0]
    plan = json.loads(plan)
    assert plan[0]["Plan"]["Actual Rows"] == 2000
    print("Hub status SQL plan:", dumps(plan))


def test_values_and_filter_without_versions_and_long_history_are_fast(web):
    """Находки без принятой версии и длинная история записей статуса: последняя запись не ищется разбором JSON на каждую находку."""
    db = web.app.state.db
    pid = project(web, [Finding(hub_id=str(200000 + n), kind="SAST", status="Open") for n in range(2000)])
    with db._tx() as c:
        for n in range(2000):
            c.execute("INSERT INTO hub_ops(project_id, hub_url, app_id, purpose, state, request_json, targets_json, op_key, created_at, updated_at)"
                      " VALUES (?, ?, 7, 'status', 'done', ?, ?, ?, '2026-11-06', '2026-11-06')",
                      (pid, HUB, dumps({"body": {"status": "Fixed"}}), dumps([{"hub_id": str(200000 + n)}]), f"k{n}"))
        c.execute("ANALYZE hub_ops")
        c.execute("ANALYZE findings")
    started = time.monotonic()
    assert db.finding_statuses(pid) == ["Fixed", "Open"]
    took = time.monotonic() - started
    print("finding_statuses, с:", round(took, 2))
    assert took < 2, took
    started = time.monotonic()
    rows = db._all(f"SELECT f.id FROM findings f WHERE f.project_id = ? AND {_CURRENT_HUB_STATUS_SQL} = ?", (pid, "Fixed"))
    took = time.monotonic() - started
    print("отбор, с:", round(took, 2))
    assert len(rows) == 2000
    assert took < 15, took
