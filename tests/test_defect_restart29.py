"""Настоящее повторное открытие тестовой базы: миграция и восстановление физических попыток."""


import pytest

from test_hub_defect_import import deliver, tab
from test_hub_defect_update import act, app_session, hub_body, phase, read_job, ready, to_put


@pytest.mark.parametrize("origin", ["app", "import"])
@pytest.mark.parametrize("state", ["unknown", "unconfirmed"])
def test_restart_preserves_attempt_and_recovers_by_explicit_read(tmp_path, monkeypatch, origin, state):
    with app_session(tmp_path, monkeypatch) as first:
        pid, row = ready(first)
        db = first.app.state.db
        db.hub_defect_update(row["id"], origin=origin)
        put = to_put(first, pid, row)
        deliver(first, put, 0 if state == "unknown" else 204, text="", error="TimeoutError" if state == "unknown" else "")
        if state == "unconfirmed":
            read_job(first, hub_body())
        before = db.hub_defect(row["id"])
        ops = db.hub_ops_list()
    with app_session(tmp_path, monkeypatch) as second:
        db = second.app.state.db
        assert phase(db, row["id"]) == state
        assert db.hub_defect(row["id"])["update_json"] == before["update_json"]
        tab(second, pid)
        assert second.client.get(f"/projects/{pid}/defects/{row['id']}").status_code == 200
        assert db.hub_ops_list() == ops
        action = "update-verify" if state == "unknown" else "update-reread"
        assert act(second, pid, row["id"], action).status_code == 200
        read_job(second, put["body"])
        assert phase(db, row["id"]) == "done"
        assert db.get_review(pid, "510001")["entered_hub"]
        assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_update"]) == 1
