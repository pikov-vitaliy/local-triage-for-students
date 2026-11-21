"""Подсказка «Рядом та же категория» (ADR-0095 п. 6): ветки A (тот же файл, ±10 строк) и B (тот же непустой
отпечаток кода в другом месте), объединение без повторов, предел и счётчик, исключение своей группы, текущая выгрузка
и проект, планы запросов и время на большом проекте. Данные выдуманы."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.db import Database
from app.models import Finding
from app.triage import order_findings


def sast(hub_id: str, line: int, file: str = "src/A.java", cwe=("CWE-89",), **fields) -> Finding:
    base = dict(hub_id=hub_id, kind="SAST", rule="Внедрение SQL-кода", file=file, line=line, cwe=list(cwe),
                codebase="billing")
    return Finding(**{**base, **fields})


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "t.db")
    yield database
    database.close()


def ids(rows) -> list[str]:
    return [r["hub_id"] for r in rows]


def set_cmp(db: Database, pid: int, hub_id: str, value: str) -> None:
    with db._tx() as c:
        c.execute("INSERT INTO cases(project_id, hub_id, case_hash, context_json, updated_at, code_cmp)"
                  " VALUES (?, ?, 'h', '{}', '2026-10-23', ?) ON CONFLICT(project_id, hub_id) DO UPDATE SET"
                  " code_cmp = excluded.code_cmp", (pid, hub_id, value))


def test_branch_a_same_file_within_ten_lines(db):
    pid = db.create_project("p")
    rows = [sast("1", 50), sast("2", 60), sast("3", 61), sast("4", 40), sast("5", 50, codebase="billing-2"),
            sast("6", 52, cwe=("CWE-79",)), sast("7", 55, file="src/B.java")]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    found, total = db.near_category(pid, rows[0].to_dict())
    # 60 и 40 – на границе (10 включительно), 61 – нет; 5 – та же группа; 6 – другая категория; 7 – другой файл
    assert sorted(ids(found)) == ["2", "4"] and total == 2
    assert all(r["near"] == 1 and r["same_code"] == 0 for r in found)


def test_branch_b_same_code_elsewhere_and_empty_print_never_matches(db):
    pid = db.create_project("p")
    rows = [sast("1", 50), sast("2", 200, file="src/C.java"), sast("3", 300, file="src/D.java"), sast("4", 55)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    for hub_id, value in (("1", "X"), ("2", "X"), ("3", ""), ("4", "X")):
        set_cmp(db, pid, hub_id, value)
    found, total = db.near_category(pid, rows[0].to_dict(), "X")
    assert sorted(ids(found)) == ["2", "4"] and total == 2, "4 подходит по обеим веткам – один раз"
    both = next(r for r in found if r["hub_id"] == "4")
    assert both["near"] == 1 and both["same_code"] == 1
    assert ids(db.near_category(pid, rows[0].to_dict(), "")[0]) == ["4"], "пустой отпечаток отключает только B"


def test_own_group_missing_and_other_project_are_excluded(db):
    pid, other = db.create_project("p"), db.create_project("q")
    rows = [sast("1", 50), sast("2", 50, codebase="billing-2"), sast("3", 52), sast("4", 53)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    db.save_import(other, "a.xlsx", "xlsx", [], {}, [], order_findings([sast("9", 51)]))
    db.save_import(pid, "b.xlsx", "xlsx", [], {}, [], order_findings(rows[:3]))  # 4 пропала из выгрузки
    found, total = db.near_category(pid, rows[0].to_dict())
    assert ids(found) == ["3"] and total == 1


def test_limit_twenty_and_count_over_the_union(db):
    pid = db.create_project("p")
    rows = [sast("0", 100)] + [sast(f"n{n}", 90 + n) for n in range(0, 21) if 90 + n != 100]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    found, total = db.near_category(pid, rows[0].to_dict())
    assert len(found) == 20 and total == 20, "в пределах ±10: строки 90–110 без своей – 20"
    extra = [sast(f"c{n}", 500 + n, file=f"src/X{n}.java") for n in range(3)]
    db.save_import(pid, "b.xlsx", "xlsx", [], {}, [], order_findings(rows + extra))
    for f in (rows[0], *extra):
        set_cmp(db, pid, f.hub_id, "Y")
    found, total = db.near_category(pid, rows[0].to_dict(), "Y")
    assert len(found) == 20 and total == 23, "показаны 20, «и ещё 3»"


def test_no_hint_for_findings_without_a_group(db):
    pid = db.create_project("p")
    rows = [sast("1", 50), sast("2", 51)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    assert db.near_category(pid, sast("x", None).to_dict()) == ([], 0)
    sca = Finding(hub_id="s", kind="SCA", component="example-parser", version="1.4.2")
    assert db.near_category(pid, sca.to_dict()) == ([], 0)


def test_query_plans_use_the_indexes_and_the_budget_holds(db):
    """20 000 находок SAST, почти все – одна категория и один отпечаток кода (худший случай для счётчика)."""
    pid = db.create_project("p")
    rows = [sast(str(n), n % 4000 + 1, file=f"src/F{n % 5}.java") for n in range(20000)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    with db._tx() as c:
        c.executemany("INSERT INTO cases(project_id, hub_id, case_hash, context_json, updated_at, code_cmp)"
                      " VALUES (?, ?, 'h', '{}', '2026-10-23', 'Z')", [(pid, str(n)) for n in range(20000)])
    with db._tx() as c:
        c.execute("ANALYZE findings")
        c.execute("ANALYZE cases")

    def plan_of(sql: str) -> str:
        return " ".join(str(r["QUERY PLAN"]) for r in db._all("EXPLAIN " + sql))
    plan = plan_of("SELECT f.id FROM findings f WHERE f.project_id = 1 AND f.g2_cat = 'a' AND f.g2_file = 'b'"
                   " AND f.g2_line BETWEEN 1 AND 20")
    assert "findings_by_near2" in plan, plan
    plan_b = plan_of("SELECT c.hub_id FROM cases c WHERE c.project_id = 1 AND c.code_cmp = 'Z' AND c.hub_id = '7'")
    assert "cases" in plan_b and "Seq Scan" not in plan_b, plan_b
    plan_join = plan_of("SELECT f.id FROM cases c JOIN findings f ON f.project_id = c.project_id"
                        " AND f.hub_id = c.hub_id WHERE c.project_id = 1 AND c.code_cmp = 'Z' AND f.g2_cat = 'x'"
                        " AND f.kind = 'SAST' AND f.missing = 0 AND f.group_key2 <> 'k'")
    assert "Index" in plan_join, plan_join
    timings = []
    for _ in range(5):
        started = time.perf_counter()
        found, total = db.near_category(pid, rows[0].to_dict(), "Z")
        timings.append(time.perf_counter() - started)
    assert len(found) == 20 and total > 1000
    # бюджет ADR – 50 мс (замер 23.10 – 29 мс): лучший из пяти замеров, чтобы разовая занятость машины не мешала
    assert min(timings) < 0.05, f"подсказка за {min(timings):.3f} с"
