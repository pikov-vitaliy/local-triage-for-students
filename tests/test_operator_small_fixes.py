"""Мелочи оператора (план dev7, раздел 5). Данные выдуманы, сети нет."""

from __future__ import annotations

from pathlib import Path

from app import sca_text
from app.triage import TriageError
from test_hub_status_routes import decide, fid, project, sast
from test_web import ORIGIN, web  # noqa: F401


def test_review_date_is_of_the_last_check(web):
    pid = project(web, [sast("101")])
    db = web.app.state.db
    decide(web, pid, "101")
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed_at = '2026-10-21T10:00:00+00:00' WHERE project_id = ? AND hub_id = '101'", (pid,))
    decide(web, pid, "101")
    assert str(db.get_review(pid, "101")["reviewed_at"]).startswith("2026-10-21"), "сохранение без правок дату не трогает"
    db.save_review(pid, "101", decision="agree", final_verdict="false_positive", final_comment=db.get_review(pid, "101")["final_comment"],
                   reviewed=True, recheck=True)
    assert not str(db.get_review(pid, "101")["reviewed_at"]).startswith("2026-10-21"), "«Сохранить» оператора – новая проверка"
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed_at = '2026-10-21T10:00:00+00:00' WHERE project_id = ? AND hub_id = '101'", (pid,))
    decide(web, pid, "101", comment="Константа, внешнего ввода нет: проверено ещё раз.")
    assert not str(db.get_review(pid, "101")["reviewed_at"]).startswith("2026-10-21"), "правка решения – новая проверка"


def test_review_date_stays_when_only_kind_of_decision_changes(web):
    """Подготовка дефекта из выбранных переводит «Согласен» в «Не согласен» с тем же выводом: это не новая проверка."""
    pid = project(web, [sast("101")])
    db = web.app.state.db
    decide(web, pid, "101", verdict="true_positive", decision="agree")
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed_at = '2026-10-21T10:00:00+00:00' WHERE project_id = ? AND hub_id = '101'", (pid,))
    decide(web, pid, "101", verdict="true_positive", decision="disagree")
    assert str(db.get_review(pid, "101")["reviewed_at"]).startswith("2026-10-21")
    decide(web, pid, "101", verdict="false_positive", decision="disagree")
    assert not str(db.get_review(pid, "101")["reviewed_at"]).startswith("2026-10-21"), "другой итог – новая проверка"


def test_defects_total_counts_like_the_tab_and_names_attempts(web):
    pid = project(web, [sast("101")])
    db = web.app.state.db
    with db._tx() as c:
        for state, number in (("done", 1), ("failed", 2), ("cancelled", 3)):
            c.execute("INSERT INTO hub_defects(project_id, kind, state, summary, command_text, targets_json, hub_url, number, created_at, updated_at)"
                      " VALUES (?, 'SAST', ?, ?, 't', '[]', 'https://hub.example.org', ?, '2026-11-05', '2026-11-05')",
                      (pid, state, f"ID{number} - попытка", number))
    assert db.hub_defect_count(pid) == 1
    page = web.client.get(f"/projects/{pid}/defects").text
    assert "Всего: 1." in page and 'id="hub-defects-attempts"' in page and ">1</a>, в таблице отмечены отдельно" in page
    only = web.client.get(f"/projects/{pid}/defects?state=failed").text
    assert "Всего: 1." in only and 'id="hub-defects-attempts"' not in only


def test_defect_counts_are_of_defects_not_of_rows(web):
    """Бэклог 106: дефект Hub, представленный двумя строками одной семьи (владелец и строка цепочки замены), –
    один дефект: на вкладке, в «Всего» и на отборах. Страницы таблицы считаются по строкам, неудавшаяся попытка
    той же семьи дефектом не считается."""
    pid = project(web, [sast("101")])
    db = web.app.state.db

    def row(c, state: str, number: int, kind: str = "SAST", owner: int | None = None, origin: str = "app") -> int:
        c.execute("INSERT INTO hub_defects(project_id, kind, state, summary, command_text, targets_json, hub_url, number,"
                  " origin, draft_owner_id, created_at, updated_at)"
                  " VALUES (?, ?, ?, ?, 't', '[]', 'https://hub.example.org', ?, ?, ?, '2026-11-05', '2026-11-05')",
                  (pid, kind, state, f"ID{number} - дефект", number, origin, owner))
        return int(c.execute("SELECT MAX(id) FROM hub_defects WHERE project_id = ?", (pid,)).fetchone()[0])

    with db._tx() as c:
        owner = row(c, "done", 1)
        c.execute("UPDATE hub_defects SET draft_owner_id = id WHERE id = ?", (owner,))
        row(c, "done", 1, owner=owner)      # строка цепочки замены: тот же дефект Hub
        row(c, "failed", 1, owner=owner)    # неудавшаяся попытка той же семьи
        row(c, "done", 2, kind="SCA", origin="import")  # прежняя строка без владельца – сама себе семья
        row(c, "failed", 3)                 # попытка без удавшейся строки – не дефект
    assert db.hub_defect_count(pid) == 2 and db.count_findings(pid)["defects"] == 2
    assert db.hub_defects_total(pid) == 5, "строк в таблице – пять"
    assert db.hub_defect_families(pid, live=True) == 2 and db.hub_defect_families(pid) == 3
    assert db.hub_defect_families(pid, kind="SAST", live=True) == 1 and db.hub_defect_families(pid, state="done") == 2
    assert db.hub_defect_families(pid, state="failed") == 2 and db.hub_defect_families(pid, origin="import", live=True) == 1
    page = web.client.get(f"/projects/{pid}/defects").text
    assert "Всего: 2." in page and ">2</a>, в таблице отмечены отдельно" in page and "Страница 1 из 1." in page
    assert page.count('href="/projects/%d/defects/' % pid) >= 5, "в таблице все пять строк"
    assert "Всего: 1." in web.client.get(f"/projects/{pid}/defects?kind=SAST").text
    assert "Всего: 2." in web.client.get(f"/projects/{pid}/defects?state=done").text
    assert "Всего: 2." in web.client.get(f"/projects/{pid}/defects?state=failed").text
    small = web.client.get(f"/projects/{pid}/defects?page_size=50").text
    assert "Всего: 2." in small and "Страница 1 из 1." in small


def test_sources_are_only_of_the_defect_vulnerabilities():
    evidence = [{"evidence_ref": "e1", "url": "https://vendor.example/advisory/CVE-2099-1", "source_type": "advisory", "level": "primary"},
                {"evidence_ref": "e2", "url": "https://vendor.example/release-notes/7.0", "source_type": "release_notes", "level": "primary"}]
    research = {"evidence": evidence, "package_advice": {"target_version": "7.0", "source_refs": ["e2"]},
                "latest_stable_release": {"version": "7.0", "source_refs": ["e2"]}}

    class Vuln:
        research = [{"source_refs": ["e1"]}]

    assert sca_text.research_sources([Vuln()], research, "7.0") == ["https://vendor.example/advisory/CVE-2099-1"]


def test_maintenance_start_explains_metrics_collector():
    text = Path(__file__).resolve().parents[1].joinpath("start.ps1").read_text(encoding="utf-8")
    assert "Сборщик метрик в режиме обслуживания не запущен" in text and "if ($Maintenance)" in text


def test_busy_new_analysis_gets_plain_answer(web, monkeypatch):
    pid = project(web, [sast("101")])
    db = web.app.state.db
    monkeypatch.setattr(db, "active_runs", lambda project_id: [{"id": 41}])
    runner = web.app.state.runner
    try:
        runner.enqueue(pid, "demo-model", "selected", ["101"], fresh=True, origin="card")
    except TriageError as exc:
        assert "прогон №41" in str(exc) and "по одному" in str(exc)
    else:
        raise AssertionError("разбор при занятой очереди не отклонён")
    answer = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '101')}/reanalyze", headers={**ORIGIN, "Accept": "application/json"}, data={"model": "demo-model"})
    assert answer.status_code == 409 and "по одному" in answer.text, answer.text


def test_paused_run_is_not_called_busy(web, monkeypatch):
    pid = project(web, [sast("101")])
    monkeypatch.setattr(web.app.state.db, "active_runs", lambda project_id: [{"id": 41, "state": "paused"}])
    try:
        web.app.state.runner.enqueue(pid, "demo-model", "selected", ["101"], fresh=True, origin="card")
    except TriageError as exc:
        assert "продолжите или" in str(exc) and "дождитесь" not in str(exc)
    else:
        raise AssertionError("разбор при незавершённом прогоне не отклонён")


def test_decision_refusal_says_where_to_choose():
    from app.routes import sca as route
    try:
        route._normalized_decision("", "true_positive", "")
    except route.ReviewRejected as exc:
        assert "в нижней панели" in str(exc)
    else:
        raise AssertionError("решение без выбора не отклонено")
