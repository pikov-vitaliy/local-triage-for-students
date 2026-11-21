"""Ревью кода 0.10.0.dev15, круг 5 (Kimi high 0/2/0): последний прогон со сравнением находится и за 50 прерванными."""
from app import hub_state
from app.db import dumps
from test_hub_status_routes import HUB, decide, project, sast
from test_sync_golden_path import LiveHub, synchronize
from test_web import web  # noqa: F401


def test_sca_overview_without_hub_read_renders_badges(web):
    """Финальный прогон dev15: в проекте, где Hub не читался, значок обзора SCA строил запасную ссылку в макросе без
    переменной проекта – страница (и по семействам) падала с ошибкой 500. Цель ссылки даёт модуль страниц."""
    import re
    from test_defect_links import seed
    db = web.app.state.db
    pid = seed(web)
    db.save_review(pid, "910202", decision="agree", final_verdict="false_positive", final_comment="Не применимо.",
                   reviewed=True)
    for url in (f"/projects/{pid}/sca", f"/projects/{pid}/sca?group_by=family"):
        page = web.client.get(url)
        assert page.status_code == 200, (url, page.status_code)
    page = web.client.get(f"/projects/{pid}/sca").text
    assert re.search(rf'class="badge badge-warn hub-state" href="/projects/{pid}#step-hub"', page), "значок «не отправлено»"


def test_compared_run_is_found_behind_many_unfinished_runs(web):
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    decide(web, pid, "1")
    with db._tx() as c:
        for _ in range(51):  # прогоны, остановленные до сравнения
            c.execute("INSERT INTO hub_defect_sync_runs(project_id,hub_url,app_id,state,run_json,result_json,created_at,"
                      "closed_at) VALUES (?,?,?,?,?,?,?,?)",
                      (pid, HUB, 7, "stopped", dumps({"comparison_complete": False}), "{}",
                       "2026-11-08T12:00:00+00:00", "2026-11-08T12:00:01+00:00"))
    found = hub_state.project_states(db, db.get_project(pid), HUB)
    assert found["run"]["id"] == row["id"], (found["run"] and found["run"]["id"], row["id"])
    assert not found["summary"]["never"] and found["by_hub_id"]["1"]["read"] is None
    assert found["by_hub_id"]["1"]["delivery"]["state"] == "unsent"
