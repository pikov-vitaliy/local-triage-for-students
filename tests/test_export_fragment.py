"""Сверка фрагмента выгрузки и совместимость сохранённых срезов (ADR-0076). Данные выдуманные."""

import re

import pytest

from app.context import (EXPORT_LINE_CHECK_VERSION, _same_line, build_context, check_export_fragment,
                         export_fragment_scope, export_fragment_view)
from app.models import CodeContext, Finding, Verdict
from app.prompts import PROMPT_VERSION, _limits, build_ask_messages, build_sast_messages
from app.triage import CONTEXT_CHARS, case_hash
from test_db import load
from test_web import ORIGIN, start_run, wait_run, web  # noqa: F401


def fragment_finding(snippet="log.info(value)"):
    return Finding(hub_id="910001", kind="SAST", codebase="fragment-demo", file="Demo.java", line=10,
                   snippet=snippet, language="Java", rule="Вывод информации", cwe=["CWE-532"])


def fragment_context(positions=(), **kwargs):
    lines = [f"// filler {n}" for n in range(1, 21)]
    for number in positions:
        lines[number - 1] = "    log.info(value); // демонстрация"
    return CodeContext(status="ok", file="Demo.java", language="java", start_line=1, end_line=20,
                       target_line=10, lines=lines, export_line_check="differs", **kwargs)


@pytest.mark.parametrize(("snippet", "line"), [
    ("log.info(value)", "private void run() { log.info(value); }"),
    ("log .\t info ( value )", "  log.info(value);"),
    ('log.info(&quot;a&nbsp;b&quot;)', 'log.info("a b");'),
    ('log.info("a b")', 'log.info(&quot;a b&quot;);'),
    ("\n unrelated();\nlog.info(value)", "log.info(value);"),
    ("someLongMethodName(argument...", "someLongMethodName(argument, other);"),
    ("someLongMethodName(argument…", "someLongMethodName(argument, other);"),
    ("some ( value, x, y, z ) ...", "some(value,x,y,z);"),
])
def test_fragment_normalization_and_containment(snippet, line):
    assert _same_line(snippet, line)


@pytest.mark.parametrize(("positions", "expected"), [
    ([10], ("match", 10)), ([11], ("near", 11)), ([7], ("near", 7)),
    ([5], ("near", 5)), ([15], ("near", 15)), ([7, 11, 14], ("near", 11)),
    ([9, 11], ("near", 11)), ([6, 14], ("near", 14)), ([11, 10], ("match", 10)),
    ([4, 16], ("differs", None)), ([], ("differs", None)),
])
def test_fragment_window(positions, expected, tmp_path):
    f = fragment_finding()
    ctx = fragment_context(positions)
    (tmp_path / f.file).write_text("\n".join(ctx.lines), encoding="utf-8")
    actual = build_context(tmp_path, f)
    assert (actual.export_line_check, actual.export_line_at) == expected
    assert actual.export_line_check_version == EXPORT_LINE_CHECK_VERSION
    assert actual.target_line == f.line
    assert CodeContext.from_dict(actual.to_dict()).export_line_at == expected[1]


@pytest.mark.parametrize("snippet", ["x", "{}", " ; ", "&lt;", "\n x\t\n{}"])
def test_short_fragments_are_neutral(snippet):
    assert check_export_fragment(snippet, [snippet], 10, 10) == ("short_export_line", None)
    assert check_export_fragment(snippet, ["unrelated();"], 10, 10) == ("short_export_line", None)
    assert not _same_line(snippet, snippet)


def test_short_file_line_does_not_match_every_export():
    assert not _same_line("log.info(value);", ";")
    assert not _same_line("method() { value(); }", "}")
    assert check_export_fragment("\n\t", ["value();"], 10, 10) == ("no_export_line", None)


def test_two_export_lines_and_non_one_start():
    # ADR-0082: одна совпавшая строка многострочного фрагмента – совпадение лишь частичное
    assert check_export_fragment("missing();\n log.info(value)", ["other();", "log.info(value);"], 9, 9) == \
        ("partial", 10)
    assert check_export_fragment("other();\n log.info(value)", ["other();", "log.info(value);"], 9, 9) == \
        ("match", 9)
    assert check_export_fragment(";\n missing();", ["other();"], 9, 9) == ("differs", None)


def test_masked_saved_line_is_neutral_and_plain_match_wins():
    ctx = fragment_context()
    ctx.lines[9] = 'log.info("<SECRET_abcdef>");'
    f = fragment_finding('log.info("synthetic-value")')
    view = export_fragment_view(f, ctx)
    assert view.export_line_check == "masked_export_line" and view.export_line_at is None
    ctx.lines[10] = f.snippet
    assert export_fragment_view(f, ctx).export_line_at == 11
    ctx.lines[10] = "other();"
    ctx.lines[9], ctx.lines[19] = ctx.lines[19], ctx.lines[9]
    assert export_fragment_view(f, ctx).export_line_check == "differs"  # маска за окном не мешает


def test_visible_fragment_matches_but_placeholder_does_not():
    lines = ['log.info(value, "<SECRET_abcdef>");']
    assert check_export_fragment("log.info(value", lines, 10, 10, masked=True) == ("match", 10)
    assert check_export_fragment("SECRET", lines, 10, 10, masked=True) == ("masked_export_line", None)


def test_fresh_check_uses_unmasked_file_and_survives_prompt(tmp_path, mask_key):
    f = fragment_finding('password = "synthetic-test-password"')
    ctx = fragment_context()
    ctx.lines[10] = f.snippet
    (tmp_path / f.file).write_text("\n".join(ctx.lines), encoding="utf-8")
    actual = build_context(tmp_path, f, mask_key=mask_key)
    assert actual.export_line_check == "near" and actual.export_line_at == 11
    assert "<SECRET_" in actual.lines[10]
    assert export_fragment_view(f, actual) is actual
    text = build_sast_messages(f, actual, mask_key)[1]["content"]
    assert "на строке 11 (сканер указал строку 10)" in text
    assert "synthetic-test-password" not in text


@pytest.mark.parametrize(("positions", "snippet", "expected"), [
    ([10], "log.info(value)", "match"), ([11], "log.info(value)", "near"),
    ([], "log.info(value)", "differs"), ([], "x", "short_export_line"), ([], "", "no_export_line"),
])
def test_prompt_rechecks_legacy_without_mutation(positions, snippet, expected, mask_key):
    f = fragment_finding(snippet)
    ctx = fragment_context(positions, note="строка в файле не совпадает со строкой из выгрузки: старое предупреждение")
    before, old_hash = ctx.to_dict(), case_hash(f, ctx)
    view = export_fragment_view(f, ctx)
    assert view.export_line_check == expected
    text = build_sast_messages(f, ctx, mask_key)[1]["content"]
    assert PROMPT_VERSION == "sast-v8"
    assert "старое предупреждение" not in text
    assert "код мог измениться" not in text
    assert ctx.to_dict() == before and case_hash(f, ctx) == old_hash
    if expected == "differs":
        assert "сверь, о том ли коде речь" in text
        assert "uncertain" not in " ".join(_limits(view))
    else:
        assert _limits(view) == []
        assert "сверь, о том ли коде речь" not in text
    if expected == "near":
        assert "Фрагмент из выгрузки – на строке 11 (сканер указал строку 10)" in text
        ask = build_ask_messages(f, ctx, Verdict.from_dict({}), "Почему?", mask_key=mask_key)[1]["content"]
        assert "на строке 11 (сканер указал строку 10)" in ask


def seed_legacy(db, positions=(), snippet="log.info(value)"):
    f = fragment_finding(snippet)
    pid = db.create_project("Проверка фрагмента")
    load(db, pid, [f])
    ctx = fragment_context(positions, note="строка в файле не совпадает со строкой из выгрузки: старый текст")
    payload = {**ctx.to_dict(), "max_chars": CONTEXT_CHARS}
    payload.pop("export_line_at")
    payload.pop("export_line_check_version")
    chash = case_hash(f, ctx)
    vid = db.save_verdict(chash, "qwen2.5-coder:14b", "sast-v4", {
        "verdict": "true_positive", "confidence": 85, "summary": "Проверить вывод информации.",
        "hub_comment": "Проверить вывод информации.", "evidence_lines": []}, {})
    assert db.save_case(pid, f.hub_id, chash, payload, vid)
    fid = db.get_finding_by_hub_id(pid, f.hub_id)["id"]
    return pid, fid, f


@pytest.mark.parametrize(("positions", "snippet", "expected"), [
    ([10], "log.info(value)", "match"), ([11], "log.info(value)", "near"),
    ([], "log.info(value)", "differs"), ([], "x", "short_export_line"),
])
def test_card_rechecks_legacy_without_hash_or_database_change(web, positions, snippet, expected):
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, positions, snippet)
    before = db.get_case(pid, f.hub_id)
    response = web.client.get(f"/projects/{pid}/findings/{fid}")
    assert response.status_code == 200
    card = response.text
    assert ('id="export-fragment-differs"' in card) == (expected == "differs")
    assert ('id="export-fragment-near"' in card) == (expected == "near")
    assert 'id="code-changed"' not in card and "старый текст" not in card
    if expected == "near":
        assert '<tr id="L11" class="is-export">' in card
    if expected == "differs":
        assert 'id="trace-export-line"' in card and snippet in card
    assert db.get_case(pid, f.hub_id) == before
    names = ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")
    form = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1) for name in names}
    saved = web.client.post(f"/projects/{pid}/findings/{fid}/review",
                            headers={**ORIGIN, "Accept": "application/json"}, data={
                                **form, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                                "comment": "Подтверждено по сохранённому коду.", "reviewed": "1"})
    assert saved.status_code == 200 and saved.json()["reviewed"] is True
    assert db.get_case(pid, f.hub_id) == before


def test_new_run_uses_rechecked_prompt_but_preserves_stored_hash(web):
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, [11])
    before = db.get_case(pid, f.hub_id)
    run = wait_run(web, start_run(web, pid))
    assert run["state"] == "done"
    text = "\n".join(m["content"] for chat in web.fake.chats() for m in chat["messages"])
    assert "на строке 11 (сканер указал строку 10)" in text
    assert "старый текст" not in text and "код мог измениться" not in text
    after = db.get_case(pid, f.hub_id)
    assert after["case_hash"] == before["case_hash"]
    assert after["context"]["export_line_check"] == "differs"
    assert after["context"].get("export_line_check_version", 0) == 0
    assert after["verdict"]["prompt_version"] == "sast-v8"
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="export-fragment-near"' in card and 'id="code-changed"' not in card

# ---------------------------------------------------------------- ADR-0082: точное, частичное, в комментарии


@pytest.mark.parametrize(("snippet", "lines", "expected"), [
    # фрагмент только в закомментированной строке
    ("strcpy(dst, src);", ["// strcpy(dst, src);"], ("commented", 10)),
    ("strcpy(dst, src);", ["/* strcpy(dst, src); */"], ("commented", 10)),
    ("query(sql)", ["# query(sql)"], ("commented", 10)),
    ("query(sql)", [" * query(sql) – пример из документации"], ("commented", 10)),
    ("query(sql)", ["-- query(sql)"], ("commented", 10)),
    ("render(page)", ["<!-- render(page) -->"], ("commented", 10)),
    # строка кода короче фрагмента и входит в него
    ("dangerous_operation(user_input);", ["user_input"], ("partial", 10)),
    ("/* old */ run(task);", ["run(task);"], ("partial", 10)),
    # многострочный фрагмент совпал не весь
    ("if (is_admin) {\n  delete_record(id);", ["if (is_guest) {", "  delete_record(id);"], ("partial", 11)),
    # точные совпадения остаются совпадениями
    ("if (is_admin) {\n  delete_record(id);", ["if (is_admin) {", "", "  delete_record(id);"], ("match", 10)),
    ("log.info(value)", ["  log.info(value); // комментарий после кода"], ("match", 10)),
    ("#include <stdio.h>", ["#include <stdio.h>"], ("match", 10)),
    ("p = x;", ["*p = x;"], ("match", 10)),
    ("i = count;", ["--i = count;"], ("match", 10)),
    ("# secret-value-placeholder", ["# secret-value-placeholder"], ("match", 10)),
    ("someLongMethodName(argument...", ["someLongMethodName(argument, other);"], ("match", 10)),
])
def test_exact_commented_and_partial(snippet, lines, expected):
    assert check_export_fragment(snippet, lines, 10, 10) == expected


def test_exact_nearby_wins_over_comment_on_scanner_line():
    lines = ["// strcpy(dst, src);", "strcpy(dst, src);"]
    assert check_export_fragment("strcpy(dst, src);", lines, 10, 10) == ("near", 11)
    assert check_export_fragment("strcpy(dst, src);", lines[:1] + ["other();"], 10, 10) == ("commented", 10)


def test_multiline_block_reports_scanner_line_inside_block():
    lines = ["if (is_admin) {", "  delete_record(id);", "}"]
    assert check_export_fragment("if (is_admin) {\n delete_record(id);", lines, 10, 11) == ("match", 11)
    assert check_export_fragment("if (is_admin) {\n delete_record(id);", lines, 10, 13) == ("near", 10)


def test_fragment_scope():
    assert export_fragment_scope("log.info(value);", "  log.info(value);") == "line"
    assert export_fragment_scope("log.info(value)", "  log.info(value); // x") == "part"
    assert export_fragment_scope("a();\nb_call();", "a();") == "lines"


def test_legacy_v1_match_is_refined_only_when_comment_or_partial():
    f = fragment_finding("strcpy(dst, src);")
    ctx = fragment_context([], export_line_check_version=1)
    ctx.lines[9] = "// strcpy(dst, src);"
    legacy = CodeContext.from_dict({**ctx.to_dict(), "export_line_check": "match", "export_line_at": 10})
    view = export_fragment_view(f, legacy)
    assert (view.export_line_check, view.export_line_at) == ("commented", 10)
    assert legacy.export_line_check == "match"  # сохранённый срез не меняется
    differs = CodeContext.from_dict({**ctx.to_dict(), "export_line_check": "differs", "export_line_at": None})
    assert export_fragment_view(f, differs) is differs
    secret = CodeContext.from_dict({**ctx.to_dict(), "export_line_check": "near", "export_line_at": 11})
    secret.lines[9] = 'other("<SECRET_abcdef>");'
    secret.lines[10] = 'strcpy("<SECRET_abcdef>", src);'
    kept = export_fragment_view(fragment_finding('strcpy("synthetic-value", src);'), secret)
    assert (kept.export_line_check, kept.export_line_at) == ("near", 11)  # маскирование не отменяет прежнее


@pytest.mark.parametrize("check", ["commented", "partial"])
def test_unconfirmed_checks_reach_prompt_and_cap_confidence(check, mask_key):
    from app.prompts import DIFFERS_CONFIDENCE_MAX, parse_verdict
    f = fragment_finding("strcpy(dst, src);")
    from dataclasses import replace
    ctx = replace(fragment_context([], export_line_at=10, export_line_check_version=EXPORT_LINE_CHECK_VERSION),
                  export_line_check=check)
    text = build_sast_messages(f, ctx, mask_key)[1]["content"]
    marker = "в комментарии" if check == "commented" else "частично"
    assert f"Фрагмент из выгрузки – {marker} на строке 10 (сканер указал строку 10)" in text
    assert "сверь, о том ли коде речь" in text
    assert "Строка срабатывания в выгрузке:" in text
    verdict = parse_verdict({"verdict": "true_positive", "confidence": 95, "summary": "Пример."}, ctx)
    assert verdict.confidence == DIFFERS_CONFIDENCE_MAX and verdict.verdict == "true_positive"


# ---------------------------------------------------------------- ADR-0082: по итогам ревью 0.8.3


@pytest.mark.parametrize(("snippet", "lines", "language", "expected"), [
    ("strcpy(dst, src);", ["safe(); // strcpy(dst, src);"], "c", ("commented", 10)),  # хвостовой комментарий
    ("*p = x;", ["// *p = x;"], "c", ("commented", 10)),
    ("p = x;", ["* p = x;"], "c", ("match", 10)),  # разыменование, не продолжение комментария
    ("strcpy(dst, src);", ["/* пояснение */ strcpy(dst, src);"], "c", ("match", 10)),
    ("x = a // b", ["x = a // b"], "python", ("match", 10)),  # в Python // – деление
    ("open(path)", ['url = "http://host/"; open(path)'], "java", ("match", 10)),  # // в строке – не комментарий
    ("a();\nb();", ["// a();", "x();"], "c", ("partial", 10)),  # одна строка многострочного – частично
    ("a();\nb();", ["// a();", "// b();"], "c", ("commented", 10)),
    ("query(sql)", ["# query(sql)"], "python", ("commented", 10)),
    ("render(page)", ["<!-- render(page) -->"], "html", ("commented", 10)),
])
def test_comments_by_language(snippet, lines, language, expected):
    assert check_export_fragment(snippet, lines, 10, 10, language=language) == expected


def test_long_block_with_scanner_line_at_its_end():
    lines = [f"step{n}(value);" for n in range(10, 17)]
    assert check_export_fragment("\n".join(lines), lines, 10, 16, language="c") == ("match", 16)


def test_hash_ignores_refined_check_of_unchanged_code(tmp_path):
    f = fragment_finding("strcpy(dst, src);")
    (tmp_path / f.file).write_text("\n".join(["// filler"] * 9 + ["// strcpy(dst, src);"] + ["// filler"] * 10),
                                   encoding="utf-8")
    fresh = build_context(tmp_path, f)
    assert fresh.export_line_check == "commented" and fresh.hash_check == "match"
    legacy = CodeContext.from_dict({**fresh.to_dict(), "export_line_check": "match", "export_line_at": 10,
                                    "export_line_check_version": 1, "hash_check": "", "hash_check_at": None})
    assert case_hash(f, fresh) == case_hash(f, legacy)  # уточнение сверки не меняет отпечаток неизменного кода


def test_legacy_near_on_masked_line_is_not_replaced_by_neighbour_partial():
    ctx = fragment_context([], export_line_check_version=1)
    ctx.lines[10] = 'strcpy("<SECRET_abcdef>", src);'
    ctx.lines[9] = "src"
    legacy = CodeContext.from_dict({**ctx.to_dict(), "export_line_check": "near", "export_line_at": 11})
    view = export_fragment_view(fragment_finding('strcpy("synthetic-value", src);'), legacy)
    assert (view.export_line_check, view.export_line_at) == ("near", 11)


@pytest.mark.parametrize(("snippet", "lines", "language", "masked", "expected"), [
    ("dangerous(user);", ["const re = /https?:\/\//; dangerous(user);"], "javascript", False, ("match", 10)),
    ("--counter;", ["// --counter;"], "c", False, ("commented", 10)),
    ("#define SIZE 4", ["// #define SIZE 4"], "c", False, ("commented", 10)),
    ("# secret-value-placeholder", ["# secret-value-placeholder"], "", False, ("match", 10)),
    ("dangerous(user);", ['safe("<SECRET_abcdef>"); // dangerous(user);'], "c", True, ("commented", 10)),
])
def test_second_review_cases(snippet, lines, language, masked, expected):
    assert check_export_fragment(snippet, lines, 10, 10, masked=masked, language=language) == expected


def test_block_split_by_blank_lines_reaching_scanner_line():
    lines = ["a();"] + [""] * 7 + ["b();"]
    assert check_export_fragment("a();\nb();", lines, 10, 18, language="c") == ("match", 18)


# ---------------------------------------------------------------- ADR-0082: по итогам третьего ревью 0.8.3


@pytest.mark.parametrize(("snippet", "lines", "language", "target", "expected"), [
    # деление после «}», «)» и имени – не литерал регулярного выражения
    ("dangerous(user);", ["x = {a: 1} / 2; // dangerous(user);"], "javascript", 10, ("commented", 10)),
    ("dangerous(user);", ["x = (a) / 2; // dangerous(user);"], "javascript", 10, ("commented", 10)),
    ("dangerous(user);", ["a = b / c; d = e / f; dangerous(user);"], "javascript", 10, ("match", 10)),
    ("dangerous(user);", ["a = b / c; d = e / f; // dangerous(user);"], "typescript", 10, ("commented", 10)),
    # литерал после return, typeof, «=>» и в начале строки
    ("dangerous(user);", [r"if (!ok) return /https?:\/\//; dangerous(user);"], "javascript", 10, ("match", 10)),
    ("dangerous(user);", [r"f = x => /https?:\/\//.test(x); dangerous(user);"], "javascript", 10, ("match", 10)),
    ("dangerous(user);", [r"t = typeof /a\/\//; dangerous(user);"], "javascript", 10, ("match", 10)),
    ("dangerous(user);", ["x = 1", r"  /https?:\/\//.test(x); dangerous(user);"], "javascript", 11, ("match", 11)),
    ("dangerous(user);", [r"/https?:\/\//.test(x); dangerous(user);"], "javascript", 10, ("match", 10)),
    # строка с переносом через «\» в конце строки: «#» и «//» внутри неё не комментарий
    ("dangerous()", ['x = "abc \\', '# not comment" ; dangerous()'], "python", 11, ("match", 11)),
    ("dangerous();", ["x = 'abc \\", "// not comment' ; dangerous();"], "javascript", 11, ("match", 11)),
    ("dangerous()", ['x = "#"; dangerous()'], "python", 10, ("match", 10)),
    ("dangerous()", ['x = "abc"', "# dangerous()"], "python", 11, ("commented", 11)),
    # PHP 8: «#[» – атрибут, «#» без скобки – комментарий
    ("public function dangerous() {}", ["#[Route('/x')] public function dangerous() {}"], "php", 10, ("match", 10)),
    ("dangerous();", ["safe(); # dangerous();"], "php", 10, ("commented", 10)),
])
def test_third_review_lexing(snippet, lines, language, target, expected):
    assert check_export_fragment(snippet, lines, 10, target, language=language) == expected


@pytest.mark.parametrize(("snippet", "expected"), [
    ("someLongMethod(argument...", ("match", 10)),  # видимое начало строки совпало с началом фрагмента
    ('someLongMethod(argument, other, "abcdef...', ("masked_export_line", None)),  # начало заходит в метку
])
def test_masked_line_uses_visible_start_of_cut_fragment(snippet, expected):
    lines = ['someLongMethod(argument, other, "<SECRET_abcdef>");']
    assert check_export_fragment(snippet, lines, 10, 10, masked=True, language="java") == expected


def test_view_of_legacy_v1_keeps_case_hash():
    f = fragment_finding("strcpy(dst, src);")
    ctx = fragment_context([], export_line_check_version=1)
    ctx.lines[9] = "// strcpy(dst, src);"
    legacy = CodeContext.from_dict({**ctx.to_dict(), "export_line_check": "match", "export_line_at": 10})
    view = export_fragment_view(f, legacy)
    assert view.export_line_check == "commented" and view.export_line_check_version == EXPORT_LINE_CHECK_VERSION
    assert case_hash(f, legacy) == case_hash(f, view)
