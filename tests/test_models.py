"""Модели данных: to_dict и from_dict обратимы, пустые строки кода не теряются."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.models import CodeContext, Finding, ScaAnswer, Verdict  # noqa: E402

LINES = ["", "def get_product(conn, product_id):", "    row = conn.execute(QUERY, (product_id,))", "",
         "    return row", ""]


def test_code_context_round_trip_keeps_blank_lines():
    ctx = CodeContext(status="ok", file="catalog_api/products.py", language="Python", start_line=19, end_line=24,
                      target_line=21, lines=list(LINES), enclosing="def get_product(conn, product_id):",
                      export_line_check="match", masked={"SECRET": 1}, note="")
    back = CodeContext.from_dict(json.loads(json.dumps(ctx.to_dict())))
    assert back == ctx
    assert len(back.lines) == back.end_line - back.start_line + 1
    assert [(n, text) for n, text, target in back.rows() if target] == [(21, LINES[2])]
    assert back.numbered().splitlines()[2].startswith(">>")


def test_code_lines_from_text_and_odd_values():
    assert CodeContext.from_dict({"lines": "a\n\nb"}).lines == ["a", "", "b"]
    assert CodeContext.from_dict({"lines": None}).lines == []
    assert CodeContext.from_dict({}).lines == []
    assert CodeContext.from_dict({"lines": ["x", None, ""]}).lines == ["x", "", ""]


def test_other_lists_still_drop_empty_items():
    f = Finding.from_dict({"hub_id": "1", "kind": "SAST", "cwe": ["CWE-89", "", None], "cve": "CVE-2026-0001, "})
    assert f.cwe == ["CWE-89"] and f.cve == ["CVE-2026-0001"]
    v = Verdict.from_dict({"verdict": "uncertain", "data_flow": ["шаг 1", ""], "evidence_lines": ["3", "x", 5]})
    assert v.data_flow == ["шаг 1"] and v.evidence_lines == [3, 5]


def test_verdict_of_both_prompt_versions():
    v2 = Verdict.from_dict({"verdict": "false_positive", "confidence": "80", "summary": "Ложное.",
                            "explanation": "Значение приводится к числу.", "evidence_lines": [12]})
    assert (v2.what_code_does, v2.why, v2.check_by_eye, v2.terms) == ("", [], [], [])
    v3 = Verdict.from_dict({
        "verdict": "true_positive", "confidence": 90, "summary": "Строка 15 склеивает SQL с вводом.",
        "what_code_does": "Метод ищет счета владельца.",
        "why": "Строка 14: owner приходит из запроса, без проверки.\nСтрока 15: он вставляется в SQL, как есть.",
        "check_by_eye": ["Строка 14: откуда owner", "", "Строка 16: как выполняется запрос"],
        "terms": [{"term": "SQL-инъекция", "meaning": "подмена запроса к базе"}, {"term": "", "meaning": "x"},
                  "мусор"],
    })
    assert v3.why == ["Строка 14: owner приходит из запроса, без проверки.", "Строка 15: он вставляется в SQL, как есть."]
    assert v3.check_by_eye == ["Строка 14: откуда owner", "Строка 16: как выполняется запрос"]
    assert v3.terms == [{"term": "SQL-инъекция", "meaning": "подмена запроса к базе"}]
    assert v3.explanation == "" and v3.evidence_lines == []
    assert Verdict.from_dict(json.loads(json.dumps(v3.to_dict()))) == v3
    assert Verdict.from_dict({"verdict": "uncertain", "terms": {"taint": "данные снаружи"}}).terms == [
        {"term": "taint", "meaning": "данные снаружи"}]
    assert Verdict("uncertain", 50).fix == ""  # поля, кроме вердикта и уверенности, необязательны


def test_sca_answer_normalizes_conclusion_and_ids():
    answer = ScaAnswer.from_dict({"component": "org.example:example-parser", "version": 142,
                                  "conclusion": "обновить", "ids": {"AST-1": "CVE-2026-0001, GHSA-aaaa-bbbb-cccc"},
                                  "links": "https://example.org/a, https://example.org/b"})
    assert answer.version == "142" and answer.conclusion == ""
    assert answer.ids == {"AST-1": ["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"]}
    assert answer.links == ["https://example.org/a", "https://example.org/b"]
    assert ScaAnswer.from_dict({"component": "c", "version": "1", "conclusion": "not_applicable"}).conclusion == (
        "not_applicable")
