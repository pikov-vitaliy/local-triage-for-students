"""Полоса «идёт получение» исследования компонентов на любой странице: как «ход разбора» у
прогона – текст со строками и ссылка на страницу хода; закончилось – итог в спокойном виде; «Скрыть» – до
следующего получения. Ответ /api/research/active подменяется в браузере – состояние получения выдумано."""

from __future__ import annotations

import json

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

RUNNING = {"run": {"id": 7, "project_id": 3, "state": "running", "state_label": "идёт", "rows_total": 15,
                   "rows_saved": 9, "rows_unchanged": 0, "rows_failed": 0, "rows_unknown": 1},
           "project_name": "Демо", "running": 1, "url": "/projects/3/components/research/7"}


def test_research_bar_shows_progress_link_and_result(ui):
    page, watch = ui
    state = {"body": RUNNING}
    page.route("**/api/research/active*", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(state["body"], ensure_ascii=False)))
    page.goto("/settings")
    bar = page.locator("#active-research-bar")
    expect(bar).to_be_visible()
    link = page.locator("#active-research-link")
    expect(link).to_have_attribute("href", "/projects/3/components/research/7")
    expect(link).to_contain_text("Исследование компонентов №7: идёт")
    expect(link).to_contain_text("сохранено 9 из 15")
    expect(link).to_contain_text("результат неизвестен 1")
    # закончилось – итог, спокойный вид; «Скрыть» – полоса уходит до следующего получения
    state["body"] = {**RUNNING, "run": {**RUNNING["run"], "state": "done", "state_label": "завершено", "rows_saved": 14},
                     "running": 0}
    expect(link).to_contain_text("завершено", timeout=12000)
    expect(bar).to_have_class("active-run-bar active-research-bar is-done")
    page.click("#active-research-dismiss")
    expect(bar).to_be_hidden()
    page.wait_for_timeout(6000)  # следующий опрос (раз в 5 с) того же получения полосу не возвращает
    expect(bar).to_be_hidden()
    assert not watch.problems(), watch.problems()


def test_no_research_no_bar(ui):
    page, watch = ui
    page.goto("/")
    page.wait_for_timeout(1500)
    expect(page.locator("#active-research-bar")).to_be_hidden()
    assert not watch.problems(), watch.problems()
