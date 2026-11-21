"""Фрагмент из выгрузки дальше ±5 строк в показанном коде – только для показа (ADR-0086). Данные выдуманные."""

import re

import pytest

from app.context import EXPORT_LINE_CHECK_VERSION, build_context, export_fragment_shift
from app.models import CodeContext, Finding
from app.prompts import build_sast_messages, request_key
from app.triage import CONTEXT_CHARS, case_hash
from test_db import load
from test_web import ORIGIN, start_run, wait_run, web  # noqa: F401

FRAGMENT = "    log.info(value); // демонстрация"


def shift_finding(line=10, snippet="log.info(value)"):
    return Finding(hub_id="920001", kind="SAST", codebase="shift-demo", file="Shift.java", line=line,
                   snippet=snippet, language="Java", rule="Вывод информации", cwe=["CWE-532"])


def shift_context(positions=(), total=60, comments=(), target=10):
    lines = [f"int filler{n} = {n};" for n in range(1, total + 1)]
    for number in positions:
        lines[number - 1] = FRAGMENT
    for number in comments:
        lines[number - 1] = "// log.info(value);"
    return CodeContext(status="ok", file="Shift.java", language="java", start_line=1, end_line=total,
                       target_line=target, lines=lines, export_line_check="differs",
                       export_line_check_version=EXPORT_LINE_CHECK_VERSION)


@pytest.mark.parametrize(("line", "positions", "comments", "expected"), [
    (10, [34], (), 34),            # сдвиг на +24
    (40, [10], (), 10),            # сдвиг на −30
    (30, [5, 50, 22], (), 22),     # несколько мест – ближайшее к строке сканера
    (30, [18, 42], (), 42),        # при равном расстоянии – ниже, как в окне ±5
    (10, [], (40,), None),         # за окном только в комментарии – не сдвиг
    (10, [], (), None),            # фрагмента нет нигде
])
def test_shift_in_shown_code(line, positions, comments, expected):
    ctx = shift_context(positions, comments=comments, target=line)
    assert export_fragment_shift(shift_finding(line), ctx) == expected


def test_shift_only_for_differs_and_shown_code():
    f = shift_finding()
    ctx = shift_context([34])
    for check in ("match", "near", "commented", "partial", "masked_export_line"):
        assert export_fragment_shift(f, CodeContext(**{**ctx.__dict__, "export_line_check": check})) is None
    assert export_fragment_shift(f, CodeContext(**{**ctx.__dict__, "status": "file_missing"})) is None
    # фрагмент за пределами показанных строк не ищется: показаны строки 1–30
    shown = CodeContext(**{**ctx.__dict__, "lines": ctx.lines[:30], "end_line": 30})
    assert export_fragment_shift(f, shown) is None


def test_shift_multiline_fragment():
    f = shift_finding(snippet="a = read();\nlog.info(a);")
    ctx = shift_context()
    ctx.lines[39], ctx.lines[40] = "a = read();", "log.info(a);"
    assert export_fragment_shift(f, ctx) == 40


def test_strict_shift_rejects_cut_and_exported_comment():
    ctx = shift_context()
    ctx.lines[33] = "someLongMethodName(argument, other, 999);"
    assert export_fragment_shift(shift_finding(snippet="someLongMethodName(argument, other, ..."), ctx) is None
    ctx.lines[33] = "// disabled_call();"
    assert export_fragment_shift(shift_finding(snippet="// disabled_call();"), ctx) is None
    ctx.lines[33], ctx.lines[34] = "a = read();", "log.info(a, b, c, d, e, f, g, h);"
    multi_cut = shift_finding(snippet="a = read();\nlog.info(a, b, c, d, e, f, g, ...")
    assert export_fragment_shift(multi_cut, ctx) is None


def test_shift_multiline_incomplete_and_cut_by_shown_end():
    f = shift_finding(snippet="a = read();\nlog.info(a);")
    ctx = shift_context()
    ctx.lines[39] = "a = read();"  # вторая строка не совпала
    assert export_fragment_shift(f, ctx) is None
    ctx.lines[59] = "a = read();"  # блок начинается на последней показанной строке
    assert export_fragment_shift(f, ctx) is None


def test_shift_masked_value_is_not_evidence():
    ctx = shift_context()
    ctx.lines[33] = "log.info(<SECRET_abcdef>);"
    assert export_fragment_shift(shift_finding(snippet="log.info(token)"), ctx) is None


def test_model_messages_do_not_see_shift(tmp_path):
    """Модель получает прежний контекст: сверка в промпте – differs, о сдвиге ни слова; поиск сдвига не меняет
    контекст, сообщения, ключ запроса и отпечаток случая."""
    f = shift_finding()
    lines = shift_context([34]).lines
    (tmp_path / f.file).write_text("\n".join(lines), encoding="utf-8")
    ctx = build_context(tmp_path, f)
    assert ctx.export_line_check == "differs"
    before = (build_sast_messages(f, ctx), case_hash(f, ctx), ctx.to_dict())
    key = request_key("qwen2.5-coder:14b", before[0])
    assert export_fragment_shift(f, ctx) == 34
    assert (build_sast_messages(f, ctx), case_hash(f, ctx), ctx.to_dict()) == before
    assert request_key("qwen2.5-coder:14b", build_sast_messages(f, ctx)) == key
    text = "\n".join(m["content"] for m in before[0])
    assert "строке 34" not in text and "сдвинут" not in text


def seed_shifted(db):
    f = shift_finding()
    pid = db.create_project("Сдвиг фрагмента")
    load(db, pid, [f])
    ctx = shift_context([34])
    payload = {**ctx.to_dict(), "max_chars": CONTEXT_CHARS}
    chash = case_hash(f, ctx)
    vid = db.save_verdict(chash, "qwen2.5-coder:14b", "sast-v6", {
        "verdict": "true_positive", "confidence": 60, "summary": "Проверить вывод информации.",
        "hub_comment": "Проверить вывод информации.", "evidence_lines": []}, {})
    assert db.save_case(pid, f.hub_id, chash, payload, vid)
    return pid, db.get_finding_by_hub_id(pid, f.hub_id)["id"], f


def test_card_shows_shift_without_database_change(web):
    db = web.app.state.db
    pid, fid, f = seed_shifted(db)
    before = db.get_case(pid, f.hub_id)
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="export-fragment-shifted"' in card and 'id="export-fragment-differs"' not in card
    assert "сдвинут на 24 строки" in card
    assert "Фрагмент из выгрузки – на строке <a href=\"#L34\">34</a>; сканер указал 10." in card
    assert "Вероятно, код в клоне другой версии, чем сканировал Hub." in card
    assert "Модель разбирала код вокруг строки 10: её вердикт может относиться к другому коду." in card
    assert "это должна быть исполняемая строка, а не комментарий или текст в кавычках" in card
    assert '<tr id="L34" class="is-export">' in card and "фрагмент из выгрузки (сдвинут)" in card
    assert db.get_case(pid, f.hub_id) == before
    # «Проверено» ставится, как при differs: решение сохраняется по тем же отпечаткам
    names = ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")
    form = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1) for name in names}
    saved = web.client.post(f"/projects/{pid}/findings/{fid}/review",
                            headers={**ORIGIN, "Accept": "application/json"}, data={
                                **form, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                                "comment": "Подтверждено по сохранённому коду.", "reviewed": "1"})
    assert saved.status_code == 200 and saved.json()["reviewed"] is True
    assert db.get_case(pid, f.hub_id) == before


def test_new_run_keeps_differs_prompt_for_shifted(web):
    db = web.app.state.db
    pid, _, f = seed_shifted(db)
    before = db.get_case(pid, f.hub_id)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    text = "\n".join(m["content"] for chat in web.fake.chats() for m in chat["messages"])
    assert "строке 34" not in text and "сдвинут" not in text
    after = db.get_case(pid, f.hub_id)
    assert after["case_hash"] == before["case_hash"] and after["context"]["export_line_check"] == "differs"


@pytest.mark.parametrize("version", [0, 1])
def test_shift_for_older_snapshots(web, version):
    """Срезы версий 0 и 1: представление пересчитывается, сдвиг ищется так же, отпечаток не меняется."""
    from test_export_fragment import fragment_context, fragment_finding
    db = web.app.state.db
    f = fragment_finding()
    pid = db.create_project(f"Срез v{version}")
    load(db, pid, [f])
    ctx = fragment_context([18])
    payload = {**ctx.to_dict(), "max_chars": CONTEXT_CHARS, "export_line_check_version": version}
    if version == 0:
        payload.pop("export_line_at")
        payload.pop("export_line_check_version")
    chash = case_hash(f, CodeContext.from_dict(payload))
    vid = db.save_verdict(chash, "qwen2.5-coder:14b", "sast-v4", {
        "verdict": "true_positive", "confidence": 60, "summary": "x", "hub_comment": "x", "evidence_lines": []}, {})
    assert db.save_case(pid, f.hub_id, chash, payload, vid)
    fid = db.get_finding_by_hub_id(pid, f.hub_id)["id"]
    before = db.get_case(pid, f.hub_id)
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="export-fragment-shifted"' in card and "сдвинут на 8 строк" in card
    assert 'id="code-changed"' not in card and db.get_case(pid, f.hub_id) == before
