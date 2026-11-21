"""Начало проекта из Hub глазами оператора (0.10.0.dev13, ADR-0140): шаг «Состояние Hub», неверный номер приложения,
«Номер верный, продолжить», «Принять состояние Hub». Синтетический Hub, без реальных данных."""

import pytest
from playwright.sync_api import expect

from test_hub_sync import FakeSyncHub, finish
from test_hub_sync_flow import sync_server  # noqa: F401
from e2e_support import open_page

pytestmark = pytest.mark.e2e


def test_wrong_number_stops_then_operator_confirms_and_accepts(browser, sync_server):
    from app.models import Finding
    from app.triage import order_findings
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо начала проекта")
    db.update_project(pid, hub_app_id=7)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="900001", kind="SAST", application="Демо")]))
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}")
        expect(page.locator("#step-hub-state")).to_contain_text("Состояние Hub ещё не принималось")
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator("#hub-step-note")).to_be_visible()
        expect(page.locator("#hub-import-numbers")).to_have_count(0)
        page.goto(f"/projects/{pid}")
        page.locator("#step-hub-sync").click()
        expect(page.locator("#hub-sync-app-check-note")).to_be_visible()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        first = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        hub = FakeSyncHub(5, 1)
        finish(db, hub, first)
        page.reload()
        check = page.locator("#hub-sync-app-check")
        expect(check).to_contain_text("общих 0 из 1")
        expect(check).to_contain_text("Похоже, номер приложения не тот")
        assert {c["path"].split("?")[0] for c in hub.calls} == {"/issue/v2"}, "дефекты и подробности не читались"
        page.goto(f"/projects/{pid}")
        expect(page.locator("#step-hub-state")).to_contain_text("Номер приложения не совпал с выгрузкой")
        page.goto(f"/projects/{pid}/hub-sync/{first}")
        page.locator("#hub-sync-app-confirm").click()
        expect(page.locator("#hub-sync-app-confirmed")).to_be_visible()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        second = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        assert second != first
        finish(db, hub, second)
        page.reload()
        expect(page.locator("#hub-sync-app-check")).to_contain_text("Номер подтверждён оператором")
        expect(page.locator("#hub-sync-apply")).to_be_visible()
        page.locator('#hub-sync-apply-form input[name="confirm"]').check()
        page.locator("#hub-sync-apply").click()
        expect(page.locator("#hub-sync-applied")).to_contain_text("Состояние Hub принято")
        page.goto(f"/projects/{pid}")
        expect(page.locator("#step-hub-state")).to_contain_text("ринято")
        expect(page.locator("#step-hub-confirmed")).to_be_visible()
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator('[id^="hub-import-origin-"]')).to_have_count(1)
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_link_in_number_field_is_taken_as_number(browser, sync_server):
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо номера ссылкой")
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}")
        expect(page.locator("#step-hub-state")).to_contain_text("Приложение в Hub не указано")
        page.locator("#step-hub a", has_text="параметрах проекта").click()
        expect(page.locator("#project-hub-app-id")).to_be_visible()
        page.fill("#project-hub-app-id", "https://hub.example.org/#/appprofile/31/issues/SAST/5")
        page.locator("#project-hub-app-id").press("Enter")
        page.wait_for_url("**ok=project_saved**")
        expect(page.locator("#project-hub-app-id")).to_have_value("31")
        expect(page.locator("#step-hub-state")).to_contain_text("приложение №31")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
