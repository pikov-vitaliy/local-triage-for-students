"""Решение компонента – находкам его версии, в Chrome (0.10.0.dev27, ADR-0153): «Сохранить и применить к находкам» в
форме решения карточки компонента сохраняет решение, записывает его находкам и возвращает на карточку с итогом;
кнопка блока применяет уже сохранённое решение. Без ошибок скриптов и горизонтальной прокрутки."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, no_horizontal_scroll

pytestmark = pytest.mark.e2e

WHY = "Версия затронута публичной уязвимостью; исправление есть в более новой версии."


def open_first_component(page, pid: int) -> None:
    page.goto(f"/projects/{pid}/components")
    page.locator("a[data-row-link]").first.click()
    page.wait_for_url(re.compile(r"/components/[^/?]+"))


def test_save_and_apply_from_the_decision_form(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_component(page, pid)
    expect(page.locator("#component-apply-why")).to_contain_text("Сначала сохраните решение")
    page.select_option('#operator-decision select[name="action"]', "update")
    page.fill('#operator-decision textarea[name="rationale"]', WHY)
    page.fill('#operator-decision input[name="target_version"]', "9.9.9")
    page.click("#save-component-apply")
    page.wait_for_url(re.compile(r"ok=applied.*#component-apply$"))
    expect(page.locator("body")).to_contain_text("Решение записано находкам этой версии")
    expect(page.locator("#component-apply-button")).to_be_visible()
    assert no_horizontal_scroll(page)
    # находка версии получила решение компонента: вывод «обновить» и обоснование
    page.click("#component-apply-defect")
    page.wait_for_url(re.compile(r"/sca/findings/\d+"))
    expect(page.locator("#final-verdict")).to_have_value("true_positive")
    expect(page.locator('#review-form textarea[name="comment"]')).to_have_value(WHY)
    assert not watch.problems(), watch.problems()


def test_apply_button_writes_the_saved_decision(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_component(page, pid)
    page.select_option('#operator-decision select[name="action"]', "update")
    page.fill('#operator-decision textarea[name="rationale"]', WHY)
    page.fill('#operator-decision input[name="target_version"]', "9.9.9")
    page.click("#save-component-decision")
    page.wait_for_url(re.compile(r"ok=decision"))
    expect(page.locator("#component-apply-button")).to_be_visible()
    page.click("#component-apply-button")
    page.wait_for_url(re.compile(r"ok=applied.*#component-apply$"))
    expect(page.locator("body")).to_contain_text("Решение записано находкам этой версии")
    assert no_horizontal_scroll(page)
    assert not watch.problems(), watch.problems()
