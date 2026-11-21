"""Бэклог 96 в Chrome: на «Компонентах» без задания блок «Исследование провайдером» виден, в нём подсказка и кнопка «Собрать
задание»; кнопка собирает задание, после чего блок предлагает выбрать профиль. Без ошибок скриптов и консоли."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, no_horizontal_scroll

pytestmark = pytest.mark.e2e


def open_research(page) -> None:
    # панель помнит состояние (data-remember) и может оказаться свёрнутой
    for _ in range(3):
        if page.locator("#component-research .service-body").is_visible():
            return
        page.locator("#component-research > summary").click()
        page.wait_for_timeout(200)


def test_research_block_builds_the_task_without_one(ui):
    page, watch = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/components")
    expect(page.locator("#component-task-title")).to_have_text("Задание исследования")
    open_research(page)
    expect(page.locator("#research-no-task")).to_be_visible()
    page.click("#build-task-research")
    page.wait_for_url(re.compile(r"ok=task"))
    open_research(page)
    expect(page.locator("#research-no-task")).to_have_count(0)
    expect(page.locator("#research-no-profile")).to_be_visible()
    assert no_horizontal_scroll(page)
    assert not watch.problems(), watch.problems()
