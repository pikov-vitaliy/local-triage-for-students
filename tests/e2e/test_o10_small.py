"""О10 – мелочи натурного теста: страница папок на 360 px с длинным путём к папке стенда не прокручивается
вбок (НТ14); всплывающие сообщения не закрывают кнопки решения (НТ11). Данные – демонстрационные."""

from __future__ import annotations

import shutil

import pytest

pytest.importorskip("playwright.sync_api")

from e2e_support import (DEMO_REPOS, create_demo, no_horizontal_scroll, open_page, start_app,  # noqa: E402
                         stop_app)
from fake_ollama import FakeOllama  # noqa: E402

LONG = "папка-стенда-с-очень-длинным-названием-без-пробелов-для-проверки-узкого-экрана"


def test_folders_page_with_a_long_path_fits_360(browser, tmp_path):
    root = tmp_path / LONG / (LONG + "-2")
    shutil.copytree(DEMO_REPOS, root)
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url, repos_root=root)
        context, page, watch = open_page(browser, server.url, width=360, height=800)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}/folders")
            wide = page.evaluate("""() => Array.from(document.querySelectorAll('body *')).filter(e => {
              const r = e.getBoundingClientRect(); return r.right > document.documentElement.clientWidth + 1; })
              .slice(0, 8).map(e => e.tagName + '.' + e.className + '#' + e.id + ' ' + Math.round(e.getBoundingClientRect().right))""")
            assert no_horizontal_scroll(page), wide
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_toasts_move_off_the_decision_buttons(browser, tmp_path):
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=1440, height=900)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}/continue")
            page.wait_for_url("**/findings/**")
            # сообщение появилось, пока ряд решения ниже стопки; затем ряд прокручен под неё – стопка уходит
            page.evaluate("window.scrollTo(0, 0)")
            page.locator("body").click(position={"x": 5, "y": 5})
            page.keyboard.press("h")
            page.locator(".toast").first.wait_for()
            page.evaluate("window.scrollBy(0, document.querySelector('fieldset.decision-choice')"
                          ".getBoundingClientRect().top - 40)")
            page.wait_for_timeout(200)
            boxes = page.evaluate("""() => { const t = document.getElementById('toasts').getBoundingClientRect();
              const c = document.querySelector('fieldset.decision-choice').getBoundingClientRect();
              return {overlap: t.height > 0 && t.left < c.right && t.right > c.left && t.top < c.bottom
                      && t.bottom > c.top, height: t.height}; }""")
            assert boxes["height"] > 0, "сообщение не показано"
            assert not boxes["overlap"], boxes
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_escape_returns_focus_to_the_element_that_opened_help(browser, tmp_path):
    """НТ15: справка `?` открыта с конкретной кнопки карточки – после `Esc` фокус снова на ней, а не на body."""
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=1440, height=900)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}/continue")
            page.wait_for_url("**/findings/**")
            page.focus("#save-btn")
            page.keyboard.press("Shift+Slash")
            page.locator("#keys-dialog[open]").wait_for()
            page.keyboard.press("Escape")
            page.locator("#keys-dialog:not([open])").wait_for(state="attached")
            assert page.evaluate("document.activeElement && document.activeElement.id") == "save-btn"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)



def test_false_positive_preview_opens_after_copy(browser, tmp_path):
    """О9: предпросмотр короткого комментария, свёрнутый вручную, раскрывается после копирования ложного
    срабатывания – без перезагрузки карточки."""
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=1440, height=900)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}/continue")
            page.wait_for_url("**/findings/**")
            page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
            page.fill("#comment", "Значение берётся из константы, подстановки нет.")
            page.evaluate("document.getElementById('hub-preview').open = false")
            page.click("#copy-hub-step")
            page.locator("#hub-preview[open]").wait_for()
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)



def test_toasts_follow_a_window_resize(browser, tmp_path):
    """НТ11: сообщение показано на широком окне, затем окно сузили и ряд решения ушёл под стопку – расположение
    пересчитывается при смене размера."""
    with FakeOllama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=1440, height=900)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}/continue")
            page.wait_for_url("**/findings/**")
            page.evaluate("window.scrollBy(0, document.querySelector('fieldset.decision-choice')"
                          ".getBoundingClientRect().top - 300)")
            page.locator("body").click(position={"x": 5, "y": 5})
            page.keyboard.press("h")
            page.locator(".toast").first.wait_for()
            page.set_viewport_size({"width": 1000, "height": 700})  # без прокрутки: пересчёт – от resize
            page.wait_for_timeout(200)
            toast = page.locator(".toast").first
            expect_visible = toast.bounding_box()
            assert expect_visible and expect_visible["height"] > 0, "сообщение есть и после смены размера"
            assert 0 <= expect_visible["y"] and expect_visible["y"] + expect_visible["height"] <= 700, expect_visible
            assert float(page.evaluate("getComputedStyle(document.getElementById('toasts')).opacity")) > 0
            state = page.evaluate("""() => { const box = document.getElementById('toasts'); const t = box.getBoundingClientRect();
              const c = document.querySelector('fieldset.decision-choice').getBoundingClientRect();
              const overlap = t.height > 0 && t.left < c.right && t.right > c.left && t.top < c.bottom && t.bottom > c.top;
              return {overlap, faded: box.classList.contains('toasts-faded'), height: t.height}; }""")
            assert state["height"] > 0 and (not state["overlap"] or state["faded"]), state
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)



def test_lost_connection_is_shown_although_reconnects_keep_failing(browser, tmp_path):
    """НТ16: приложение остановлено во время прогона – переподключения раз в 3 с не отодвигают «Нет связи»: оно видно
    в пределах нескольких секунд от первой ошибки, а не пропадает навсегда."""
    import re as _re

    from playwright.sync_api import expect
    with FakeOllama(delay=5) as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, width=1440, height=900)
        try:
            pid = create_demo(page)
            page.goto(f"/projects/{pid}#step3")
            page.check('input[name="scope"][value="all"]')
            page.get_by_role("button", name="Запустить триаж", exact=True).click()
            page.wait_for_url(_re.compile(r"/runs/\d+$"))
            expect(page.locator("#conn-lost")).to_be_hidden()
            stop_app(server.process)
            expect(page.locator("#conn-lost")).to_be_visible(timeout=12000)
            expect(page.locator("#conn-lost")).to_contain_text("Нет связи с приложением")
        finally:
            context.close()
            stop_app(server.process)
