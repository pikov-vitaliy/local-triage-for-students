"""Вкладка «Компоненты» в браузере (0.9.26.dev17): значок дефекта у компонента ведёт в карточку дефекта, отбор «Дефект»
оставляет только компоненты в дефекте или без него, счётчик «В дефекте» в сводке. Данные выдуманы; сеть – только
приложение на 127.0.0.1."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import open_page  # noqa: E402
from test_hub_sync_flow import sync_server  # noqa: E402,F401

pytestmark = pytest.mark.e2e


def test_component_defect_badge_filter_and_card(browser, sync_server):
    from app.models import Finding
    from app.sca_contract import input_ref
    from app.triage import order_findings

    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо дефектов компонентов")
    db.update_project(pid, hub_app_id=7)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id="73001", kind="SCA", component="example-parser", version="1.4.2", build_type="pypi",
                cve=["CVE-2099-0001"], cvss=8.1),
        Finding(hub_id="73003", kind="SCA", component="demo-xml", version="2.0.0", build_type="pypi",
                cve=["CVE-2099-0002"], cvss=7.5)]))
    row = db.hub_defect_insert(pid, kind="SCA", number=12, summary="ID12 - example-parser (SCA)", anchor_hub_id="73001",
                               targets=[{"hub_id": "73001", "issue_type": "SCA_S"}], number_keys=[], command_text="Текст",
                               hub_url="https://hub.example.org", app_id=7)
    db.hub_defect_update(row["id"], state="done", hub_defect_id="90092")
    parser, xml = input_ref("pypi", "example-parser", "1.4.2"), input_ref("pypi", "demo-xml", "2.0.0")
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/components")
        rows = page.locator("table.table-components tbody tr")
        expect(rows).to_have_count(2)
        badge = page.locator(f"tr[data-input-ref='{parser}'] a.component-defect")
        expect(badge).to_have_text("дефект ID12 · №90092")
        expect(page.locator(f"tr[data-input-ref='{xml}'] a.component-defect")).to_have_count(0)
        expect(page.locator('a.stat-link[href$="?defect=in"]')).to_contain_text("1")
        # отбор «без дефекта» через «Все фильтры»
        page.locator("#component-filters-more > summary").click()
        page.select_option("#component-defect", "none")
        page.locator("#component-filters button[type=submit]").first.click()
        page.wait_for_url(re.compile(r"defect=none"))
        expect(page.locator("table.table-components tbody tr")).to_have_count(1)
        expect(page.locator(f"tr[data-input-ref='{xml}']")).to_be_visible()
        # счётчик сводки ведёт к отбору «в дефекте», значок – в карточку дефекта
        page.locator('a.stat-link[href$="?defect=in"]').click()
        page.wait_for_url(re.compile(r"defect=in"))
        expect(page.locator("table.table-components tbody tr")).to_have_count(1)
        page.locator(f"tr[data-input-ref='{parser}'] a.component-defect").click()
        page.wait_for_url(re.compile(rf"/projects/{pid}/defects/{row['id']}"))
        expect(page.locator("h1")).to_contain_text("ID12")
        # путь по SCA: группы → версии → карточка – дефект виден на каждом шаге
        page.goto(f"/projects/{pid}/sca?group_by=family")
        groups = page.locator("table.worklist-groups tbody tr")
        expect(groups).to_have_count(2)
        parser_group = groups.filter(has_text="example-parser")
        expect(parser_group.locator("a.component-defect")).to_have_text("дефект ID12 · №90092")
        expect(groups.filter(has_text="demo-xml").locator("td.group-defects")).to_have_text("–")
        page.locator("a.chip", has_text="В дефекте").click()
        page.wait_for_url(re.compile(r"show=in_defect"))
        expect(page.locator("table.worklist-groups tbody tr")).to_have_count(1)  # обзор групп: осталась одна
        page.goto(f"/projects/{pid}/sca?show=in_defect")
        expect(page.locator("table tbody tr[data-component]")).to_have_count(1)
        page.goto(f"/projects/{pid}/sca?group_by=family")
        parser_group.locator("a.rule-link").click()
        page.wait_for_url(re.compile(r"family="))
        version_row = page.locator("tr[data-component='example-parser']")
        expect(version_row.locator("a.component-defect")).to_have_text("дефект ID12 · №90092")
        version_row.locator("a[data-row-link]").click()
        page.wait_for_url(re.compile(r"/sca/findings/\d+"))
        expect(page.locator("#finding-defect-badge")).to_have_text("дефект ID12 · №90092")
        expect(page.locator("#defect-exists")).to_contain_text("Дефект для этой находки уже есть")
        page.locator("#finding-defect-badge").click()
        page.wait_for_url(re.compile(rf"/projects/{pid}/defects/{row['id']}"))
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
