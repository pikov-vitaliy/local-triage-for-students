"""Бэклог 123, шаг 2: страница дефектов без обращения к базе на каждую цель. typed_ids и адреса карточек целей –
одним запросом на пачку; результат тот же, что у прежнего пути по одной находке."""

from __future__ import annotations

import json
import re

from app import timing
from app.defect_drafts import typed_ids
from app.routes.hub_defect_routes import _card_url_of, _finding_url
from test_web import prepared, web  # noqa: F401


def test_typed_ids_keep_only_targets_of_the_finding_kind_in_one_query(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    sca, sast = "73001", "510002"
    assert db.get_finding_by_hub_id(pid, sca)["kind"] == "SCA" and db.get_finding_by_hub_id(pid, sast)["kind"] == "SAST"
    targets = [{"hub_id": sca, "issue_type": "SCA_S"}, {"hub_id": sca, "issue_type": "SAST"},
               {"hub_id": sast, "issue_type": "SAST"}, {"hub_id": "999999", "issue_type": "SAST"}, {"issue_type": "SAST"}]
    page = timing.PageTiming()
    token = timing.CURRENT.set(page)
    try:
        got = db.on_connection(lambda c: typed_ids(c, pid, iter(targets)))
    finally:
        timing.CURRENT.reset(token)
    assert got == [sca, sast], "тип связи совпадает с видом находки; чужой тип и неизвестный номер – нет"
    assert sum(c for p, (c, _) in page.places.items() if p.startswith("defect_drafts.typed_ids")) == 1, page.places
    assert db.on_connection(lambda c: typed_ids(c, pid, [])) == []


def test_finding_refs_match_the_one_by_one_card_urls(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    wanted = ["73001", "510002", "nope", ""] + [str(900000 + i) for i in range(1200)]  # больше одной пачки
    refs = db.finding_refs(pid, wanted)
    assert set(refs) == {"73001", "510002"}
    for hub_id in ("73001", "510002", "nope"):
        assert _finding_url(pid, refs.get(hub_id)) == _card_url_of(db, pid, hub_id)
    assert _finding_url(pid, refs["73001"]).startswith(f"/projects/{pid}/sca/findings/")
    assert _finding_url(pid, refs["510002"]).startswith(f"/projects/{pid}/findings/")


# ---------------------------------------------------------------- план медленного обращения

def test_slow_read_gets_its_plan_logged_once_without_values(web, monkeypatch, caplog):  # noqa: F811
    """Обращение дольше порога: план снимается один раз на место вызова, в журнале – узлы и таблицы без условий и
    значений; страница отвечает как обычно, транзакция страницы не портится."""
    pid = prepared(web)
    monkeypatch.setattr(timing, "EXPLAIN_MS", 0)
    monkeypatch.setattr(timing, "_EXPLAINED", set())
    first = web.client.get(f"/projects/{pid}/sca?q=секретное-слово")
    assert first.status_code == 200
    plans = [r.getMessage() for r in caplog.records if r.getMessage().startswith("план медленного обращения")]
    assert plans, caplog.text
    joined = "\n".join(plans)
    assert "секретное" not in joined and "73001" not in joined and "SELECT" not in joined.upper()
    assert any(re.search(r" – \d+ мс, строк \d+×\d+", p) for p in plans), plans
    places = [re.search(r"обращения (.+?) \(\d+ мс; снятие", p).group(1) for p in plans]
    assert len(places) == len(set(places)), "одно место – один план"
    caplog.clear()
    again = web.client.get(f"/projects/{pid}/sca?q=секретное-слово")
    assert again.status_code == 200 and again.text.count("<table") == first.text.count("<table")
    assert not [r for r in caplog.records if r.getMessage().startswith("план медленного обращения")], "повтора нет"


def test_only_plain_reads_are_explained(monkeypatch):
    monkeypatch.setattr(timing, "EXPLAIN_MS", 0)
    monkeypatch.setattr(timing, "_EXPLAINED", set())
    assert timing.explain_wanted("a", "SELECT 1", 1.0)
    assert not timing.explain_wanted("a", "SELECT 1", 1.0), "место уже снималось"
    for i, query in enumerate(("UPDATE reviews SET x = 1", "WITH x AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT 1",
                               "SELECT * FROM t FOR UPDATE", "SELECT pg_advisory_lock(1)", "SELECT nextval('s')",
                               "DELETE FROM t", "  insert into t values (1)")):
        assert not timing.explain_wanted(f"w{i}", query, 1.0), query
    monkeypatch.setattr(timing, "EXPLAIN_MS", 1000)
    assert not timing.explain_wanted("fast", "SELECT 1", 0.5)


def test_plan_summary_names_nodes_and_tables_only():
    plan = [{"Plan": {"Node Type": "Aggregate", "Actual Total Time": 30.0, "Actual Loops": 1, "Actual Rows": 1,
                      "Group Key": ["secret"], "Plans": [
                          {"Node Type": "Seq Scan", "Relation Name": "hub_ops", "Alias": "ho", "Filter": "(x = 'секрет')",
                           "Actual Total Time": 25.0, "Actual Loops": 1, "Actual Rows": 900}]}}]
    line = timing.plan_summary(json.dumps(plan))
    assert line.startswith("Seq Scan hub_ops – 25 мс, строк 900×1; Aggregate – 5 мс")
    assert "секрет" not in line and "secret" not in line


def _plans(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("план медленного обращения")]


def _timed(fn):
    page = timing.PageTiming()
    token = timing.CURRENT.set(page)
    try:
        return fn()
    finally:
        timing.CURRENT.reset(token)


def test_plan_runs_the_query_again_only_in_a_read_only_transaction(web, monkeypatch, caplog):  # noqa: F811
    """Вне транзакции – EXPLAIN ANALYZE в своей транзакции только для чтения с откатом; в транзакции записи – только
    оценка без выполнения; транзакция записи после этого завершается как обычно."""
    pid = prepared(web)
    db = web.app.state.db
    monkeypatch.setattr(timing, "EXPLAIN_MS", 0)
    monkeypatch.setattr(timing, "_EXPLAINED", set())
    rows = _timed(lambda: db._store.read(lambda c: c.execute("SELECT id FROM projects WHERE id = ?", (pid,)).fetchall()))
    assert [r["id"] for r in rows] == [pid]
    assert re.search(r" – \d+ мс, строк \d+×\d+", _plans(caplog)[-1]), _plans(caplog)
    caplog.clear()
    timing._EXPLAINED.clear()  # место вызова из теста – одно («?»): план снимается заново

    def write():
        with db._store.transaction() as c:
            c.execute("UPDATE projects SET name = name WHERE id = ?", (pid,))
            got = c.execute("SELECT id FROM projects WHERE id = ? AND name IS NOT NULL", (pid,)).fetchall()
            c.execute("UPDATE projects SET name = name WHERE id = ?", (pid,))
            return got
    assert [r["id"] for r in _timed(write)] == [pid]
    assert "оценка без выполнения" in _plans(caplog)[-1], _plans(caplog)
    assert db.get_project(pid)["id"] == pid


def test_failed_plan_spoils_neither_the_result_nor_the_transaction(web, monkeypatch, caplog):  # noqa: F811
    """Сбой самого EXPLAIN на сервере (ошибка PostgreSQL, транзакция была бы испорчена без точки сохранения): вне
    транзакции, в транзакции только для чтения и в транзакции записи результат исходного запроса цел, следующий
    запрос на том же соединении работает, транзакция завершается; плана в журнале нет (ревью dev30, круг 2)."""
    from app.storage import postgresql
    pid = prepared(web)
    db = web.app.state.db
    monkeypatch.setattr(timing, "EXPLAIN_MS", 0)
    calls = {"explain": 0}

    class Broken(postgresql.ClientCursor):
        def execute(self, query, params=None, **kwargs):
            if str(query).startswith("EXPLAIN"):
                calls["explain"] += 1
                # настоящая ошибка сервера: такой таблицы нет
                return super().execute("EXPLAIN SELECT * FROM timing_no_such_table", None, **kwargs)
            return super().execute(query, params, **kwargs)
    monkeypatch.setattr(postgresql, "ClientCursor", Broken)

    def read_twice(c):
        first = c.execute("SELECT id FROM projects WHERE id = ?", (pid,)).fetchall()
        second = c.execute("SELECT name FROM projects WHERE id = ?", (pid,)).fetchall()
        return first, second

    def snapshot():
        db._store.enter_snapshot()
        try:
            return db._store.read(read_twice)
        finally:
            db._store.exit_snapshot()

    def write():
        with db._store.transaction() as c:
            got = read_twice(c)
            c.execute("UPDATE projects SET name = name WHERE id = ?", (pid,))
            return got
    for name, case in (("вне транзакции", lambda: db._store.read(read_twice)), ("чтение", snapshot), ("запись", write)):
        timing._EXPLAINED.clear()
        before = calls["explain"]
        first, second = _timed(case)
        assert calls["explain"] > before, f"{name}: EXPLAIN не вызывался"
        assert [r["id"] for r in first] == [pid] and len(second) == 1, name
    assert db.get_project(pid)["id"] == pid
    assert web.client.get(f"/projects/{pid}/sca").status_code == 200
    assert not _plans(caplog)
