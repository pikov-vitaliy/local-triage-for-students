"""ADR-0100: карточка SCA без ответа агента – поле комментария пустое, переключение «Своё решение» → «Риск принят» ничего
не подставляет, сохранение без обоснования отклоняется и остаётся на карточке. Данные выдуманы."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402


def test_switching_decisions_without_agent_answer_keeps_the_comment_empty(ui):
    page, _ = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/sca")
    page.click("#sca-continue")
    page.wait_for_url(re.compile(r"/sca/findings/\d+"))
    expect(page.locator("#agent-empty")).to_be_visible()
    expect(page.locator("#comment")).to_have_value("")
    assert "безопасная версия" not in page.content().lower()
    page.locator("label").filter(has=page.locator("input[name=decision][value=disagree]")).click()
    page.select_option("#final-verdict", "false_positive")
    expect(page.locator("#comment")).to_have_value("")
    page.locator("label").filter(has=page.locator("input[name=decision][value=risk_accepted]")).click()
    expect(page.locator("#comment")).to_have_value("")
    page.locator("#review-form button[name=action][value=save]").click()
    # пустое обоснование: сохранение не уходит, поле помечено, в нижней панели – короткая причина
    expect(page.locator("#comment")).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#copy-status")).to_contain_text("обоснование")
    expect(page.locator("#comment")).to_have_value("")
