"""Отпечаток сравнения кода группы SAST (ADR-0092): одинаковый код – одинаковый отпечаток; разный код, другое
положение строки, другой язык – разный; недостоверные случаи – пусто."""

from __future__ import annotations

from app.codecmp import code_cmp
from app.context import CUT_MARK


def ctx(lines, start=1, target=20, language="java", status="ok"):
    return {"status": status, "lines": list(lines), "start_line": start, "target_line": target, "language": language}


FILE = [f"line {n}" for n in range(1, 41)]


def test_same_code_same_print_and_differences_change_it():
    base = code_cmp(ctx(FILE))
    assert base and base == code_cmp(ctx(list(FILE)))
    changed = list(FILE)
    changed[16] = "line 17 changed"  # в окне −15…+5
    assert code_cmp(ctx(changed)) not in ("", base)
    spaces = list(FILE)
    spaces[19] = "line  20"  # пробелы значимы
    assert code_cmp(ctx(spaces)) not in ("", base)
    assert code_cmp(ctx(FILE, language="python")) != base
    outside = list(FILE)
    outside[0] = "far away"  # строка 1 – вне окна 5…25
    assert code_cmp(ctx(outside)) == base


def test_slice_offset_does_not_matter_if_window_is_inside():
    tail = FILE[2:]  # срез с третьей строки файла, окно 5…25 целиком внутри
    assert code_cmp(ctx(tail, start=3, target=20)) == code_cmp(ctx(FILE))


def test_unreliable_cases_are_empty():
    assert code_cmp(None) == "" and code_cmp({}) == ""
    assert code_cmp(ctx(FILE, status="line_only")) == ""
    assert code_cmp(ctx(FILE[10:], start=11, target=20)) == "", "окно сверху обрезано срезом не с начала файла"
    assert code_cmp(ctx(FILE[:22], target=20)) == "", "снизу окна не хватает строк"
    cut = list(FILE)
    cut[19] = "very long" + CUT_MARK
    assert code_cmp(ctx(cut)) == ""
    masked = list(FILE)
    masked[18] = 'password = "<SECRET_a1b2c3>"'
    assert code_cmp(ctx(masked)) == ""
    assert code_cmp(ctx(FILE, target=99)) == ""


def test_window_at_file_start_is_reliable():
    assert code_cmp(ctx(FILE, target=3)) != ""
