"""Потолок уверенности, когда фрагмент выгрузки не найден в показанном коде (ADR-0080), и блок сверки на карточке.
Данные выдуманные."""

import pytest

from app.models import CodeContext
from app.prompts import DIFFERS_CONFIDENCE_MAX, PROMPT_VERSION, build_sast_messages, parse_verdict
from test_export_fragment import fragment_context, fragment_finding, seed_legacy
from test_web import start_run, wait_run, web  # noqa: F401

ANSWER = {"verdict": "false_positive", "confidence": 95, "summary": "Значение не попадает в журнал."}


def ctx_with(check, status="ok"):
    return CodeContext(status=status, file="Demo.java", language="java", start_line=1, end_line=20,
                       target_line=10, lines=[f"// filler {n}" for n in range(1, 21)], export_line_check=check,
                       export_line_check_version=1)


@pytest.mark.parametrize(("ctx", "confidence"), [
    (ctx_with("differs"), DIFFERS_CONFIDENCE_MAX),
    (ctx_with("match"), 95), (ctx_with("near"), 95), (ctx_with("masked_export_line"), 95),
    (ctx_with("short_export_line"), 95), (ctx_with("differs", status="export_line_only"), 95), (None, 95),
])
def test_cap_only_when_fragment_not_found(ctx, confidence):
    verdict = parse_verdict(ANSWER, ctx)
    assert verdict.verdict == "false_positive", "вердикт не меняется – только уверенность"
    assert verdict.confidence == confidence
    assert verdict.raw["confidence"] == 95, "исходная уверенность остаётся в сыром ответе"
    assert parse_verdict({**ANSWER, "confidence": 40}, ctx).confidence == 40


def test_prompt_text_unchanged_by_cap(mask_key):
    """ADR-0080: промпт не меняется – ответы модели те же, меняется только разбор ответа."""
    text = build_sast_messages(fragment_finding(), fragment_context([]), mask_key)[1]["content"]
    assert PROMPT_VERSION == "sast-v8"  # ADR-0148: v6 и оговорка о метках; потолок уверенности в текст не входит
    assert "не выше" not in text and str(DIFFERS_CONFIDENCE_MAX) not in text


@pytest.mark.parametrize(("positions", "capped"), [([], True), ([10], False), ([11], False)])
def test_run_caps_by_rechecked_view(web, positions, capped):
    """Срез версии 0 хранит прежний differs; потолок – по представлению, которое видела модель."""
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, positions)
    run = wait_run(web, start_run(web, pid))
    assert run["state"] == "done"
    after = db.get_case(pid, f.hub_id)
    assert after["context"]["export_line_check"] == "differs"  # сохранённый срез не переписан
    raw = after["verdict"]["raw"]["confidence"]
    assert raw > DIFFERS_CONFIDENCE_MAX, "ответ фальшивой модели по умолчанию – 80"
    assert after["verdict"]["data"]["confidence"] == (DIFFERS_CONFIDENCE_MAX if capped else raw)
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert ('id="confidence-capped"' in card) == capped
    if capped:
        assert f"модель указала {raw} %" in card


def test_trace_block_shows_export_code_and_verdict(web):
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, [11])
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    for marker in ('id="trace-export"', 'id="trace-code"', 'id="trace-verdict"', 'id="trace-export-line"'):
        assert marker in card
    assert card.index('id="trace"') < card.index('id="code-title"'), "сверка – над кодом"
    assert "log.info(value)" in card[card.index('id="trace-export"'):card.index('id="trace-code"')]
    assert 'href="#L11"' in card
    # старый вердикт sast-v4 – без отметки об ограничении
    assert 'id="confidence-capped"' not in card


def test_trace_without_code_does_not_claim_a_line(web):
    """Нет ни клона, ни строки в выгрузке: блок не утверждает, что модель видела строку (ревью ADR-0080)."""
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, [], snippet="")
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    block = card[card.index('id="trace-code"'):card.index('id="trace-verdict"')]
    assert "одна строка" not in block


def test_trace_has_no_decision_line(web):
    """Решение оператора – в бейдже и панели решения; в блоке сверки его нет (черновик и копирование для Hub)."""
    db = web.app.state.db
    pid, fid, f = seed_legacy(db, [11])
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert "ваше решение" not in card[card.index('id="trace"'):card.index('id="code-title"')]


@pytest.mark.parametrize(("version", "shown"), [("sast-v6", True), ("sast-v8", True), ("sast-v5", False)])
def test_cap_note_follows_stored_answer_version(version, shown):
    """Пояснение «уверенность ограничена» – по версии сохранённого ответа: у sast-v6 оно остаётся и после перехода
    приложения на sast-v8 (ревью Codex, dev20)."""
    from app.routes.findings import capped_confidence
    ctx = fragment_context([])
    assert ctx.export_line_check == "differs"
    verdict = parse_verdict({"verdict": "true_positive", "confidence": 95}, ctx)
    row = {"prompt_version": version, "raw": {"confidence": 95}}
    assert capped_confidence(verdict, row, ctx) is shown


def test_old_version_hint_only_for_versions_without_steps(web):  # noqa: F811
    """Подсказка «без шагов и словарика» – только у версий до sast-v3; у sast-v6 – просто «прежняя версия»."""
    from app.view import TEMPLATES_DIR
    source = (TEMPLATES_DIR / "findings" / "card.html").read_text(encoding="utf-8")
    assert "short_explanation_versions" in source and source.count("без шагов и словарика") == 2
    from app.prompts import SHORT_EXPLANATION_VERSIONS
    assert "sast-v6" not in SHORT_EXPLANATION_VERSIONS and "sast-v2" in SHORT_EXPLANATION_VERSIONS
