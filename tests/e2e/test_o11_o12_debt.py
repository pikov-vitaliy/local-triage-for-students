"""Долг браузерных проверок (О11, О12): прежнее «Подтверждаю дефект» без своей рекомендации – дефект не выдаётся,
пока оператор не допишет рекомендацию; «Взять решение и текст» у соседки без своей рекомендации ничего не дописывает
в поле рекомендации (общего пункта нет, ADR-0092); отказ отметки «Внесено в Hub» из-за комментария модели к другому
вердикту – флажок «Текст проверен» – отметка без пересохранения решения. Данные выдуманы."""

from __future__ import annotations

import re
from db_support import connect_db

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_operator_sast_route import (TRUE_FIX, TRUE_REASON, card_urls, save_tp, seeded,  # noqa: E402
                                      wait_clipboard_contains)
from test_stored_code_snapshots import restart  # noqa: E402


def drop_own_fix(tmp_path, pid: int, server, fake_url: str, repos):
    """Как у решения до 0.9.8: своя рекомендация пуста. Приложение держит базу монопольно – правка между остановкой
    и новым запуском на той же папке данных."""
    stop_app(server.process)
    con = connect_db(tmp_path / "data" / "triage.db")
    with con:
        con.execute("UPDATE reviews SET final_fix = '' WHERE project_id = ?", (pid,))
    con.close()
    return restart(tmp_path, fake_url, repos)


def test_legacy_true_positive_without_fix_asks_for_a_recommendation(browser, tmp_path):
    """О11: решение «Подтверждаю дефект» без своей рекомендации (до 0.9.8) – выдача дефекта отказывает и просит
    рекомендацию; оператор дописывает её, сохраняет – текст дефекта кончается его пунктом."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer("true_positive", evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            context.close()
            server = drop_own_fix(tmp_path, pid, server, fake.url, repos)
            context, page, watch = open_page(browser, server.url)
            page.goto(url)
            expect(page.locator("#fix")).to_have_value("")
            # причина названа в карточке, кнопка дефекта не предлагается
            expect(page.locator("#defect-blocked")).to_contain_text("нет рекомендации")
            expect(page.locator("#copy-defect-bar")).to_be_hidden()
            page.fill("#fix", "Параметризовать запрос.")
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            page.click("#copy-defect-bar")
            body = wait_clipboard_contains(page, "Параметризовать запрос.")
            assert body.rstrip().endswith("1) Параметризовать запрос."), body
            assert "PreparedStatement" not in body, "рекомендация модели в текст не входит"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_take_from_a_sibling_without_own_fix_adds_nothing(browser, tmp_path):
    """О11: у соседки по группе прежнее «Подтверждаю дефект» без своей рекомендации – «Взять решение и текст» берёт
    исход и обоснование, поле рекомендации остаётся пустым (общего пункта нет, рекомендация модели не переносится)."""
    pid, repos = seeded(tmp_path, 2)
    with FakeOllama(default_answer=verdict_answer("true_positive", evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            first, second = card_urls(page, pid)
            page.goto(first)
            save_tp(page, TRUE_REASON, TRUE_FIX)  # решение пока только у первой
            context.close()
            server = drop_own_fix(tmp_path, pid, server, fake.url, repos)
            context, page, watch = open_page(browser, server.url)
            page.goto(second)
            page.locator("#group-siblings").get_by_role("button", name="Взять решение и текст").first.click()
            expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
            expect(page.locator("#comment")).to_have_value(TRUE_REASON)
            expect(page.locator("#fix")).to_have_value("")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_entered_refusal_then_flag_then_mark_without_resaving(browser, tmp_path):
    """О12: решение «Ложное срабатывание» сохранено с комментарием модели, написанным к «истинной», – отметка
    «Внесено в Hub» отказывает и показывает «Текст проверен»; флажок – и отметка ставится без пересохранения."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer("true_positive", evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            model_comment = page.input_value("#comment")
            assert model_comment, "комментарий модели подставлен в поле"
            page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
            page.fill("#comment", model_comment)  # текст модели к «истинной» оставлен как есть
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            revision = page.input_value("#review-revision")
            page.click("#mark-entered")
            expect(page.locator("#comment-confirm-label")).to_be_visible()
            expect(page.locator("#entered-badge")).to_be_hidden()
            page.check("#comment-confirm")
            page.click("#mark-entered")
            expect(page.locator("#entered-badge")).to_be_visible()
            assert page.input_value("#review-revision") == revision, "решение не пересохранялось"
            watch.allowed_errors.append("409")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
