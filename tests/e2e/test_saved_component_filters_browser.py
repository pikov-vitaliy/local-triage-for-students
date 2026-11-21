"""Сохранённый рабочий отбор «Компонентов» в браузере (В14, ADR-0110): показать отбор, сохранить под именем,
открыть по ссылке из строки «Сохранённые отборы», удалить. Данные – демонстрационные."""

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402

pytestmark = pytest.mark.e2e


def test_save_open_and_delete_a_component_filter(ui):
    page, _watch = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/components")
    page.locator("#component-status").select_option("unresearched")
    page.get_by_role("button", name="Показать").click()
    page.wait_for_url(re.compile(r"status=unresearched"))

    page.locator("#saved-filter-name").fill("Не исследованы")
    page.get_by_role("button", name="Сохранить отбор").click()
    page.wait_for_url(re.compile(r"ok=filter_saved"))
    chip = page.locator("#saved-filters a.chip", has_text="Не исследованы")
    expect(chip).to_have_attribute("href", f"/projects/{pid}/components?status=unresearched")

    page.goto(f"/projects/{pid}/components")
    expect(page.locator("#component-status")).to_have_value("")
    page.locator("#saved-filters a.chip", has_text="Не исследованы").click()
    page.wait_for_url(re.compile(r"status=unresearched$"))
    expect(page.locator("#component-status")).to_have_value("unresearched")

    page.get_by_role("button", name="Удалить отбор «Не исследованы»").click()
    page.wait_for_url(re.compile(r"ok=filter_deleted"))
    expect(page.locator("#component-status")).to_have_value("unresearched")
    expect(page.locator("#saved-filters a.chip")).to_have_count(0)
