"""О7 (0.9.9): копирование комментария, написанного моделью к другому вердикту, – явный флажок «Текст проверен» на
странице, а не окно подтверждения браузера. Демо-данные, поддельная модель."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_ANSWERS, clipboard, create_demo  # noqa: E402

pytestmark = pytest.mark.e2e


def test_stale_comment_copy_asks_for_the_flag_not_a_browser_dialog(ui):
    page, watch = ui
    dialogs: list[str] = []
    page.on("dialog", lambda d: dialogs.append(d.message))
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(r"/sca/findings/\d+"))
    original = page.locator("#comment").input_value()
    assert original.strip(), "у демо-ответа агента есть комментарий"
    # своё решение «Ложное срабатывание» с комментарием агента, написанным под «Обновить»
    page.locator("label").filter(has=page.locator("input[name=decision][value=disagree]")).click()
    page.select_option("#final-verdict", "false_positive")
    page.fill("#comment", original)
    expect(page.locator("#comment-stale")).to_be_visible()
    before = clipboard(page)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("отметьте «Текст проверен»")
    expect(page.locator("#comment-confirm")).to_be_focused()
    assert dialogs == [], "окна подтверждения браузера нет"
    assert clipboard(page) == before, "без отметки ничего не скопировано"
    # отметка – и копирование проходит; текст уходит как есть
    page.check("#comment-confirm")
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("скопирован")
    assert original.strip()[:30] in clipboard(page)
    assert dialogs == []
    assert not watch.problems(), watch.problems()
