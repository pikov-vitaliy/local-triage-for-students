"""Таблица групп в браузере (план dev7, раздел 3): столбцы вместо «С решением», решение оператора переводит находку в другой столбец,
на ширине 1600 страница без прокрутки вбок. Данные выдуманы, сеть – только приложение на 127.0.0.1. Снимки пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_defect import save_sast  # noqa: E402
from test_web import prepared, web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600
HEADS = ("В дефекте", "Ложные", "Риск принят", "Подтверждено, без дефекта", "Без решения", "Внесено в Hub")


def shot(page, name: str) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(500)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def bucket_total(page, key: str) -> int:
    cells = page.locator(f'.worklist-groups td[data-bucket="{key}"]')
    return sum(0 if t.strip() == "–" else int(t) for t in cells.all_inner_texts())


def test_columns_follow_operator_decision(browser, stand):  # noqa: F811
    web, url = stand
    pid = prepared(web)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings?kind=SAST&group_by=family")
        table = page.locator(".worklist-groups")
        for head in HEADS:
            expect(table.locator("th", has_text=head)).to_have_count(1)
        expect(table.locator("th", has_text="С решением")).to_have_count(0)
        no_horizontal_scroll(page)
        before = bucket_total(page, "undecided"), bucket_total(page, "no_defect")
        shot(page, "s3-findings-groups")
        save_sast(web, pid, "510001", "disagree", "true_positive", "Данные из запроса попадают в SQL без параметров.")
        page.goto(f"/projects/{pid}/findings?kind=SAST&group_by=family")
        assert (bucket_total(page, "undecided"), bucket_total(page, "no_defect")) == (before[0] - 1, before[1] + 1)
        page.goto(f"/projects/{pid}/sca?group_by=family")
        for head in HEADS:
            expect(page.locator(".worklist-groups th", has_text=head)).to_have_count(1)
        no_horizontal_scroll(page)
        shot(page, "s3-sca-groups")
        assert watch.page_errors == []
    finally:
        context.close()
