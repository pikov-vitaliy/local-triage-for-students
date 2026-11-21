"""Карточка находки в браузере (план dev7, раздел 4): действующий статус Hub в шапке, главная кнопка панели у ложного срабатывания ведёт
к отправке, у статуса «Fixed» формы нет. Данные выдуманы, сеть – только приложение на 127.0.0.1. Снимки пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_finding_status_now import accept_state  # noqa: E402
from test_hub_status_routes import decide, fid, project, sast, sca  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


def shot(page, name: str) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(500)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def test_false_positive_leads_to_send_and_fixed_has_no_form(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    card = f"/projects/{pid}/findings/{fid(web, pid, '101')}"
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(card)
        expect(page.locator("#hub-status-now")).to_contain_text("из выгрузки")
        expect(page.locator(".action-bar")).to_have_attribute("data-stage", "send")
        send = page.locator("#go-send")
        expect(send).to_be_visible()
        expect(send).to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#copy-hub")).not_to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#hub-manual-instr")).to_have_count(0)
        send.click()
        expect(page.locator("#hub-send-form")).to_be_in_viewport()
        no_horizontal_scroll(page)
        shot(page, "s4-send")
        accept_state(web, pid, "101", "Fixed")
        page.goto(card)
        expect(page.locator("#hub-status-now")).to_contain_text("Fixed")
        expect(page.locator("#hub-status-now")).to_contain_text("принятая сверка")
        expect(page.locator("#hub-send-fixed")).to_contain_text("issue was fixed")
        expect(page.locator("#hub-send-form")).to_have_count(0)
        expect(page.locator("#go-send")).to_have_count(0)
        # в Hub менять нечего: копирования и отметки нет, главная кнопка – «Дальше» (dev8)
        expect(page.locator("#copy-hub")).to_be_hidden()
        expect(page.locator("#mark-entered")).to_be_hidden()
        expect(page.locator("#copy-hub-step")).to_have_count(0)
        expect(page.locator(".action-bar")).to_have_attribute("data-stage", "next")
        expect(page.locator("#next-btn")).to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#copy-where")).to_contain_text("менять в Hub нечего")
        page.keyboard.press("c")
        expect(page.locator("#copy-status")).to_have_text("")
        page.keyboard.press("h")
        expect(page.get_by_text("отметка не нужна").first).to_be_visible()
        # другое решение возвращает свои кнопки, ложное срабатывание с правкой – «Сохранить решение»
        page.keyboard.press("y")
        expect(page.locator(".action-bar")).not_to_have_attribute("data-fixed-fp", re.compile(".+"))
        page.keyboard.press("n")
        expect(page.locator("#copy-hub")).to_be_hidden()
        no_horizontal_scroll(page)
        shot(page, "s4-fixed")
        assert watch.page_errors == []
    finally:
        context.close()


def test_sca_send_button_follows_decision(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [sca("50001")])
    decide(web, pid, "50001", decision="disagree")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '50001')}")
        send = page.locator("#go-send")
        expect(send).to_be_visible()
        expect(send).to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#hub-status-now")).to_contain_text("из выгрузки от")
        shot(page, "s4-sca-send")
        page.locator('input[name="decision"][value="later"]').check(force=True)
        expect(send).to_be_hidden()
        page.locator('input[name="decision"][value="disagree"]').check(force=True)
        expect(send).to_be_visible()
        no_horizontal_scroll(page)
        assert watch.page_errors == []
    finally:
        context.close()
