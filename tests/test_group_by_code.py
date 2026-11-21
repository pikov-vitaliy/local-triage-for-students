"""Группа SAST по одинаковому коду (ADR-0092): подгруппа – одинаковый отпечаток сравнения; соседи с другим кодом и
недействующие решения в согласованность не входят; номер дефекта принадлежит подгруппе, где его держит больше
находок."""

from __future__ import annotations

from app import defect
import pytest

from app.routes.findings import (ReviewRejected, current_rows, group_conflict_rows, group_number_plan,
                                 number_rows, same_code, state_print)


def row(hub_id, cmp="A", decision="disagree", verdict="false_positive", comment="Имя таблицы из константы.",
        fix="", number=None, revision=1, missing=0, at="2026-10-01"):
    return {"hub_id": hub_id, "code_cmp": cmp, "decision": decision, "final_verdict": verdict,
            "final_comment": comment, "final_fix": fix, "defect_number": number, "revision": revision,
            "missing": missing, "defect_at": at if number is not None else None, "review_verdict_id": None,
            "case_verdict_id": None, "model_fix": ""}


def test_subgroup_is_the_same_code_print():
    rows = [row("1", "A"), row("2", "B"), row("3", ""), row("4", "A")]
    assert [r["hub_id"] for r in same_code(rows, "A")] == ["1", "4"]
    assert [r["hub_id"] for r in same_code(rows, "")] == ["3"], "без отпечатка – своя подгруппа"


def test_other_code_does_not_block_a_different_decision():
    mine = defect.sast_effective("false_positive", "Значение приводится к числу, инъекция исключена.", "")
    rows = [row("1", "B", verdict="true_positive", comment="Склейка SQL.", fix="Параметризовать запрос.")]
    near = current_rows(same_code(rows, "A"), {})
    assert group_conflict_rows(near, mine) == ""
    same = current_rows(same_code([{**rows[0], "code_cmp": "A"}], "A"), {})
    assert "другое решение" in group_conflict_rows(same, mine)


def test_stale_neighbour_is_skipped_only_if_unchanged_since_assessment():
    mine = defect.sast_effective("false_positive", "Имя таблицы из константы.", "")
    other = row("1", verdict="false_positive", comment="Другое обоснование.")
    printed = state_print(other)
    assert current_rows([other], {"1": ("changed", *printed)}) == [], "оценён недействующим и не менялся"
    with pytest.raises(ReviewRejected):  # оценённое состояние изменилось после оценки – оценка недействительна
        current_rows([{**other, "revision": 2}], {"1": ("changed", *printed)})
    with pytest.raises(ReviewRejected):
        current_rows([{**other, "case_hash": "другой срез"}], {"1": ("ok", *printed)})
    assert current_rows([other], {}) == [other], "появился после оценки – сравнивается"
    assert "другой текст" in group_conflict_rows(current_rows([other], {"1": ("ok", *printed)}), mine)
    assert current_rows([row("2", decision="later")], {}) == []


def test_number_belongs_to_the_subgroup_holding_it_more():
    rows = [row("1", "A", number=7), row("2", "B", number=7), row("3", "B", number=7)]
    mine, foreign = number_rows(rows, "A", None)
    assert foreign == {7} and mine == [], "ID7 держат больше находок с кодом B"
    plan = group_number_plan(mine, None, None)
    assert plan == (None, "", ""), "подгруппе A номер ID7 не предлагается"
    mine_b, foreign_b = number_rows(rows, "B", None)
    assert foreign_b == set() and group_number_plan(mine_b, None, None)[0] == 7


def test_number_tie_goes_to_the_earliest_holder():
    rows = [row("1", "A", number=5, at="2026-10-02"), row("2", "B", number=5, at="2026-10-01")]
    assert number_rows(rows, "A", None)[1] == {5}
    assert number_rows(rows, "B", None)[1] == set()


def test_own_number_owner_does_not_depend_on_the_card():
    """A получила ID7 раньше B: номер принадлежит A, из какой бы карточки ни смотреть."""
    from_a = number_rows([row("b", "B", number=7, at="2026-10-02")], "A", 7, own_at="2026-10-01")[1]
    from_b = number_rows([row("a", "A", number=7, at="2026-10-01")], "B", 7, own_at="2026-10-02")[1]
    assert from_a == set() and from_b == {7}
    assert number_rows([row("2", "A", number=9)], "A", 9, own_at="2026-10-05")[1] == set()


def test_number_owner_is_the_same_from_any_card_on_equal_dates():
    """Равные даты и число держателей: владелец – подгруппа с наименьшим номером находки Hub, из любой карточки."""
    from_a = number_rows([row("b", "B", number=7, at="2026-10-01")], "A", 7, own_at="2026-10-01", own_hub="a")[1]
    from_b = number_rows([row("a", "A", number=7, at="2026-10-01")], "B", 7, own_at="2026-10-01", own_hub="b")[1]
    assert from_a == set() and from_b == {7}
