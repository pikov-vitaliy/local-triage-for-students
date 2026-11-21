"""Ревью 0.9.2 в браузере (демо-данные, поддельная модель): текст для Hub – решение человека (ADR-0088).

R092-03 – короткий текст не копируется без выбранного решения, курсор – на выборе решения;
R092-02 – полный текст дефекта с комментарием модели к другому вердикту требует правки или «Текст проверен»."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import clipboard, create_demo, run_triage  # noqa: E402

pytestmark = pytest.mark.e2e


def blur(page) -> None:
    page.evaluate("document.activeElement && document.activeElement.blur()")


def test_sast_hub_text_needs_operator_decision_and_checked_comment(ui):
    page, watch = ui
    watch.allowed_errors.append("status of 400")  # копирование без решения сервер тоже отклоняет
    watch.allowed_errors.append("status of 409")  # полный текст и отметка h с комментарием к другому вердикту – отказ
    pid = create_demo(page)
    run_triage(page, pid)
    # находка, которую модель считает ложной: её комментарий написан к «ложной»
    page.goto(f"/projects/{pid}/findings?kind=SAST&verdict=false_positive")
    page.locator('table tbody a[href*="/findings/"]').first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))
    model = page.locator("#review-form").get_attribute("data-model-verdict")
    assert model == "false_positive", model
    model_comment = page.locator("#review-form").get_attribute("data-model-comment")
    assert model_comment

    # R092-03: без решения комментарий не копируется, курсор – на выборе решения
    page.evaluate("navigator.clipboard.writeText('прежнее')")
    blur(page)
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("выберите решение")
    assert page.evaluate("document.activeElement.name") == "decision"
    assert clipboard(page) == "прежнее"

    # R092-02: «Подтверждаю дефект» убирает комментарий модели к другому вердикту; оператор вернул его сам
    blur(page)
    page.keyboard.press("y")
    expect(page.locator("#comment")).to_have_value("")
    page.fill("#comment", model_comment)
    page.fill("#fix", "Передавать значение параметром запроса.")
    page.locator("#review-form button[value=save]").click()
    page.wait_for_url(re.compile(r"ok=saved"))
    expect(page.locator("#comment-stale")).to_be_visible()
    expect(page.locator("#copy-defect-bar")).to_be_visible()
    # у подтверждённого дефекта короткого текста нет: предпросмотр и кнопка комментария скрыты
    expect(page.locator("#hub-preview")).to_be_hidden()
    expect(page.locator("#copy-hub")).to_be_hidden()
    blur(page)
    page.keyboard.press("h")
    expect(page.locator("#copy-status")).to_contain_text("Текст проверен")
    expect(page.locator("#entered-badge")).to_be_hidden()
    blur(page)
    page.keyboard.press("f")
    expect(page.locator("#copy-status")).to_contain_text("Текст проверен")
    expect(page.locator("#comment-confirm-label")).to_be_visible()
    assert clipboard(page) == "прежнее", "полный текст с чужим обоснованием не скопирован"
    # «Текст проверен» – осознанное подтверждение: теперь полный текст выдаётся
    page.check("#comment-confirm")
    blur(page)
    page.keyboard.press("f")
    expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
    assert clipboard(page).startswith("После тщательного анализа")
    # смена решения переключателем снимает «Текст проверен»: отметка относилась к прежнему итогу
    expect(page.locator("#comment-confirm")).to_be_checked()
    blur(page)
    page.keyboard.press("l")
    expect(page.locator("#comment-confirm")).not_to_be_checked()
    assert not watch.problems(), watch.problems()
