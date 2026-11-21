"""Форма решения компонента в браузере: быстрый срок пересмотра и «Заполнить по
исследованию» заполняют поля и черновик вкладки, решение сохраняется. Карточка находки SCA по исследованию
(ADR-0108) отрисовывается сервером и проверяется в tests/test_sca_research_answer.py. Пакеты и идентификаторы
выдуманы."""

from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402
from test_component_research import (VULN_ID, manifest_of, upload_answer, vulnerable_href,  # noqa: E402
                                     write_answer)

pytestmark = pytest.mark.e2e


def test_presets_and_research_draft_fill_the_form(ui, tmp_path: Path):
    page, _watch = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/components")
    page.click("#build-task")
    page.wait_for_url(re.compile(r"ok=task"))
    manifest = manifest_of(page, pid)
    upload_answer(page, pid, write_answer(tmp_path, manifest, "answer.json"))
    page.goto(vulnerable_href(page, pid, manifest["rows"][0]["input_ref"]))

    form = page.locator("#decision-form")
    review = form.locator("#decision-review-at")
    expect(review).to_have_attribute("type", "date")
    form.get_by_role("button", name="+90 дней").click()
    expect(review).to_have_value((date.today() + timedelta(days=90)).isoformat())
    expect(page.locator("#component-draft-status")).to_contain_text("Черновик сохранён")

    # совет исследования в демо-ответе – «рассмотреть принятие риска»: действие «риск принят», цели нет
    page.click("#fill-from-research")
    expect(form.locator("#decision-action")).to_have_value("accept_risk")
    expect(form.locator("#decision-target-version")).to_be_hidden()
    expect(form.locator("#decision-rationale")).to_have_value(re.compile(re.escape(VULN_ID)))
    expect(form.locator("#decision-rationale")).to_have_value(re.compile(r"Совет исследования: рассмотреть принятие риска\."))
    expect(review).to_have_value((date.today() + timedelta(days=90)).isoformat())  # заполненное не трогается
    expect(page.locator("#component-draft-status")).to_contain_text("Пустые поля заполнены по исследованию")
    page.click("#fill-from-research")
    expect(page.locator("#component-draft-status")).to_contain_text("Заполнять нечего")

    page.click("#save-component-decision")
    expect(page.locator("#operator-decision .component-current-decision")).to_contain_text("риск принят")
    expect(page.locator("#operator-decision .component-current-decision")).to_contain_text(VULN_ID)
