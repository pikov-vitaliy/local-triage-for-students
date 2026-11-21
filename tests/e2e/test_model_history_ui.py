"""Второе мнение в браузере (ADR-0097): после «Пересмотреть вердикт» решение человека,
«Проверено» и выбранный исход остаются; карточка говорит, что разбор новый, и показывает историю разборов с метками.
Демо-данные, поддельная модель."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo, run_triage  # noqa: E402
from fake_ollama import verdict_answer  # noqa: E402
from test_preprod_ui import choose_outcome, outcome_is_chosen  # noqa: E402

pytestmark = pytest.mark.e2e


def test_second_opinion_keeps_the_decision_and_shows_history(ui, app_server):
    page, _ = ui
    pid = create_demo(page)
    run_triage(page, pid)
    page.goto(f"/projects/{pid}/findings/by-id?hub_id=100101")
    old_id = page.locator('input[name="verdict_id"]').input_value()
    page.evaluate("document.activeElement && document.activeElement.blur()")
    choose_outcome(page, True, "true_positive")
    page.fill("#comment", "Подтверждено: значение из запроса попадает в SQL без параметров.")
    page.fill("#fix", "Передавать значение параметром подготовленного запроса.")
    page.click("#save-btn")
    page.wait_for_url(lambda url: "ok=saved" in url)
    expect(page.locator("#reviewed-box")).to_be_checked()
    app_server.fake.answers.append(verdict_answer("false_positive", 70))
    page.click("#reanalyze-box summary")  # шаг 4 «Второе мнение» свёрнут
    page.click("#reanalyze-btn")
    expect(page.locator('input[name="verdict_id"]')).not_to_have_value(old_id, timeout=60000)
    # решение, отметка и исход – прежние; новый разбор расходится – предупреждение
    outcome_is_chosen(page, True, "true_positive")
    expect(page.locator("#reviewed-box")).to_be_checked()
    expect(page.locator("#verdict-changed")).to_contain_text("остаётся в силе")
    expect(page.locator("#verdict-changed")).to_contain_text("расходится с вашим решением")
    history = page.locator("#model-history")
    expect(history.locator("summary").first).to_contain_text("История разборов моделью · 2")
    expect(history.locator("summary").first).to_contain_text("модели расходятся")
    history.locator("summary").first.click()
    expect(history).to_contain_text("показан сейчас")
    expect(history).to_contain_text("по нему принято ваше решение")
    expect(history).to_contain_text("пересмотр из карточки")
    expect(page.locator("#reanalyzed-count")).to_contain_text("Уже пересматривали: 1")
