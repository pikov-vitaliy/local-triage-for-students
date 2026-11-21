"""Обновление текущих справочников не теряет рабочую задачу и решение оператора."""
from urllib.parse import urlencode, urlsplit

import pytest
from playwright.sync_api import expect

from capec_fixtures import CAPEC_XML, capec_zip
from feed_fixtures import CWE_FULL_XML, cwe_zip
from e2e_support import create_demo, no_horizontal_scroll, open_page, start_app, stop_app
from test_operator_cycle import first_component

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("kind", ["cwe", "capec"])
def test_reference_update_missing_id_and_return(ui, tmp_path, kind):
    page, watch = ui
    watch.allowed_errors.append("status of 404")
    pid = create_demo(page)
    address = urlsplit(first_component(page, pid))
    card = address.path + ("?" + address.query if address.query else "")
    queue = page.get_by_role("link", name="К списку", exact=True).get_attribute("href")
    page.select_option("#decision-action", "keep")
    page.fill("#decision-rationale", "Проверено оператором на выдуманных данных.")
    page.click("#save-component-decision")
    expect(page.locator(".component-current-decision")).to_contain_text("Проверено оператором")

    source = CWE_FULL_XML if kind == "cwe" else CAPEC_XML
    path = tmp_path / f"{kind}.zip"

    def upload(xml):
        if kind == "cwe":
            cwe_zip(path, xml)
        else:
            path.write_bytes(capec_zip(xml))
        page.goto("/feeds?" + urlencode({"origin": card}))
        page.set_input_files(f"#feed-{kind}-file", str(path))
        page.locator(f"#feed-{kind} form button[type=submit]").click()
        expect(page.locator("[data-poll]")).to_have_count(0, timeout=30000)

    upload(source)
    target = f"/{kind}/{kind.upper()}-2099?" + urlencode({"origin": card})
    page.goto(target)
    expect(page.locator("h1")).to_contain_text(f"{kind.upper()}-2099")
    expect(page.locator("#task-origin")).to_be_visible()
    updated = source.replace('Name="Improper Neutralization of Demo Input"', 'Name="Updated Demo"').replace('Name="Demo Injection"', 'Name="Updated Demo"')
    upload(updated)
    page.goto(target)
    expect(page.locator("h1")).to_contain_text("Updated Demo")
    upload(updated.replace('ID="2099"', 'ID="2199"'))
    response = page.goto(target)
    assert response.status == 404
    expect(page.locator("#reference-missing")).to_contain_text("9.99")
    expect(page.locator("#task-origin")).to_be_visible()
    expect(page.locator("#task-queue")).to_have_attribute("href", queue)
    no_horizontal_scroll(page)
    page.set_viewport_size({"width": 640, "height": 900})
    no_horizontal_scroll(page)
    page.screenshot(path=str(tmp_path / f"reference-missing-{kind}.png"), full_page=True)
    page.set_viewport_size({"width": 1280, "height": 900})
    page.locator("#task-origin").click()
    expect(page.locator(".component-current-decision")).to_contain_text("Проверено оператором")
    page.goto(target)
    page.get_by_role("link", name="Загрузить каталог", exact=True).click()
    expect(page.locator("#task-origin")).to_be_visible()
    upload(source.replace('Version="9.99"', 'Version="9.98"'))
    expect(page.locator("main")).to_contain_text("старее")
    page.goto(target)
    expect(page.locator("#reference-missing")).to_contain_text("9.99")
    upload(source)
    if kind == "capec":
        page.goto("/capec/CAPEC-2101")
        expect(page.locator("main")).to_contain_text("Deprecated")


def test_empty_catalog_upload_and_invalid_id_keep_operator_context(browser, app_server, tmp_path):
    isolated = tmp_path / "empty-catalog-app"
    isolated.mkdir()
    server = start_app(isolated, app_server.fake.url)
    context, page, watch = open_page(browser, server.url)
    watch.allowed_errors.append("status of 404")
    try:
        pid = create_demo(page)
        origin = f"/projects/{pid}/findings?kind=SAST&severity=high&page_size=25"
        page.goto(origin)
        page.locator(".topbar-actions").get_by_role("link", name="CWE", exact=True).click()
        page.locator("#cwe-empty").get_by_role("link", name="К загрузке каталога", exact=True).click()
        expect(page.locator("#task-origin")).to_be_visible()
        page.locator("#task-origin").click()
        expect(page).to_have_url(server.url + origin)
        for value, reason in (("2099", "not-loaded"), ("not-an-id", "invalid")):
            response = page.goto("/cwe/" + value + "?" + urlencode({"origin": origin}))
            assert response.status == 404
            expect(page.locator(f"#reference-{reason}")).to_be_visible()
            expect(page.locator("#task-origin")).to_have_attribute("href", origin)
        assert not watch.problems()
    finally:
        context.close()
        stop_app(server.process)
