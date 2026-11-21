"""Ключ группы SAST второй редакции (ADR-0095), часть (а): компоненты и ключ, хранение, шаг схемы 20 с фактом
слияния, правило номеров слившихся групп, подписи решений. Данные выдуманы."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app import db as db_module
from app.db import Database, review_signature
from app.hub_import import group_key, group_key2, group_parts2, near_columns2
from app.models import Finding
from app.routes.findings import merged_number_plan
from app.triage import order_findings


def sast(hub_id: str, **fields) -> Finding:
    base = dict(hub_id=hub_id, kind="SAST", rule="Внедрение SQL-кода", file="src/A.java", line=42, cwe=["CWE-89"],
                codebase="billing")
    return Finding(**{**base, **fields})


# ============================================================================ компоненты и ключ

@pytest.mark.parametrize("path, codebase, expected", [
    ("Billing/src/A.c", "Billing", "src/A.c"),
    ("billing/src/A.c", "Billing", "src/A.c"),
    ("src/Billing/A.c", "Billing", "src/Billing/A.c"),
    ("Billing", "Billing", "Billing"),
    ("core/core/a.c", "core", "core/a.c"),
    ("team/core/a.c", "team/core", "team/core/a.c"),
    ("Billing/src/A.c", "", "Billing/src/A.c"),
])
def test_file2_drops_exactly_one_codebase_prefix(path, codebase, expected):
    assert group_parts2(sast("1", file=path, codebase=codebase))["file2"] == expected


def test_path_case_of_the_rest_is_significant():
    assert group_key2(sast("1", file="src/a.c")) != group_key2(sast("2", file="src/A.c"))


@pytest.mark.parametrize("cwe, expected", [
    (["CWE-89", "CWE-09", "CWE-9"], ["CWE-9", "CWE-89"]),
    (["CWE-564", "CWE-89"], ["CWE-89", "CWE-564"]),
    ([], []),
    (["CWE-89", "OWASP-A03"], ["CWE-89", "OWASP-A03"]),
])
def test_cwe2_is_a_numerically_sorted_set(cwe, expected):
    assert group_parts2(sast("1", cwe=cwe))["cwe2"] == expected


def test_same_line_and_category_across_codebases_is_one_key():
    one = sast("1", file="billing/src/A.java", codebase="billing", cwe=["CWE-564", "CWE-89"])
    two = sast("2", file="src/A.java", codebase="billing-2", cwe=["CWE-89", "CWE-564"])
    assert group_key2(one) == group_key2(two) and group_key(one) != group_key(two)
    assert group_key2(sast("3", cwe=["CWE-89"])) != group_key2(sast("4", cwe=["CWE-89", "CWE-564"]))


def test_separators_inside_components_do_not_break_the_key():
    key = group_key2(sast("1", rule="A|B, C", cwe=["X,Y"]))
    assert json.loads(key) == ["A|B, C", ["X,Y"], "src/A.java", 42]
    assert key != group_key2(sast("2", rule="A|B, C", cwe=["X", "Y"]))


def test_no_group_without_rule_file_or_line_and_other_kinds_keep_the_old_key():
    assert group_key2(sast("1", line=None)) == "" and near_columns2(sast("1", line=None)) == ("", "", None)
    assert group_key2(sast("1", rule="")) == ""
    sca = Finding(hub_id="2", kind="SCA", component="example-parser", version="1.4.2")
    assert group_key2(sca) == group_key(sca)
    assert group_key2(sast("1").to_dict()) == group_key2(sast("1")), "словарь из базы – тоже находка"


# ============================================================================ хранение

def stored(db: Database, pid: int) -> dict[str, tuple]:
    return {r["hub_id"]: (r["group_key2"], r["g2_cat"], r["g2_file"], r["g2_line"], r["data_json"])
            for r in db._all("SELECT * FROM findings WHERE project_id = ?", (pid,))}


def test_stored_columns_equal_computed_after_import_reimport_and_reorder(tmp_path: Path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    rows = [sast("1", file="billing/src/A.java"), sast("2", codebase="billing-2"), sast("3", line=None)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    db.save_import(pid, "b.xlsx", "xlsx", [], {}, [], order_findings(rows[:2]))
    db.reorder_findings(pid, order_findings(rows[:2]))
    for hub_id, (key, cat, file2, line, data) in stored(db, pid).items():
        f = json.loads(data)
        assert (key, cat, file2, line) == (group_key2(f), *near_columns2(f)), hub_id
    assert stored(db, pid)["1"][0] == stored(db, pid)["2"][0], "два пути одной строки – одна группа"
    db.close()


def test_group_consumers_do_not_compare_with_the_old_key():
    text = Path(db_module.__file__).read_text(encoding="utf-8")
    sql = re.findall(r"f\.group_key\s*=|AND group_key\s*=", text)
    assert sql == [], "потребители группы сравнивают только group_key2"
    routes = Path(db_module.__file__).with_name("routes").joinpath("findings.py").read_text(encoding="utf-8")
    assert "from app.hub_import import group_key2 as group_key" in routes


# ============================================================================ шаг 20

def test_migration_keeps_review_signature(tmp_path: Path):
    """Ключи группы в подпись решения не входят: миграция не меняет её и не снимает «Проверено» (ADR-0095 п. 5)."""
    f = sast("1").to_dict()
    assert review_signature(f) == review_signature({**f, "group_key2": "x"}), "подпись – по CASE_KEYS"


# ============================================================================ номера слившихся групп

def members(*pairs, own=None):
    return [{"hub_id": h, "number": n} for h, n in pairs]


def test_merged_plan_keeps_both_historical_numbers():
    group = members(("A", 10), ("B", 20), ("C", None))
    assert merged_number_plan(group, "A", [10, 20], None)[0] == 10, "своё у A"
    assert merged_number_plan(group, "B", [10, 20], None)[0] == 20, "своё у B"
    number, error, warning = merged_number_plan(group, "C", [10, 20], None)
    assert number == 10 and not error and "ID10 (A)" in warning and "ID20 (B)" in warning
    assert merged_number_plan(group, "C", [10, 20], 20)[:2] == (20, "")
    number, error, _ = merged_number_plan(group, "C", [10, 20], 30)
    assert number is None and "ID10, ID20" in error, "номер вне исторических – отказ"


def test_merged_plan_with_one_kept_number_is_the_normal_rule_over_the_full_set():
    group = members(("A", 10), ("B", None))  # держатели 20 ушли в другую подгруппу
    assert merged_number_plan(group, "A", [10, 20], None)[0] == 10
    assert merged_number_plan(group, "B", [10, 20], None)[0] == 10, "одинаково из карточки находки без номера"
    assert merged_number_plan(group, "A", [10, 20], 40)[0] is None, "ранняя ветка «у остальных нет номеров» не действует"
    assert merged_number_plan(members(("A", 30), ("B", None)), "B", [10, 20], None)[0] == 30, "kept пуст, current = {30}"
    assert merged_number_plan(members(("A", None), ("B", None)), "A", [10, 20], 55) == (55, "", ""), "номеров нет"


def test_merged_plan_own_number_outside_history():
    group = members(("A", 10), ("B", 20), ("C", 30))
    number, error, _ = merged_number_plan(group, "C", [10, 20], None)
    assert number == 10 and not error, "своё вне исторических при двух kept – предлагается самый частый из kept"
    assert merged_number_plan(group, "C", [10, 20], 30)[0] is None
    one = members(("A", 10), ("C", 30), ("D", 30))
    assert merged_number_plan(one, "A", [10, 20], None)[0] == 30, "при одном kept – участвует в общей частотности"
