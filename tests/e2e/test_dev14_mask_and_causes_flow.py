"""0.10.0.dev14 в браузере: флажок «Маскировать секреты в коде при показе» в параметрах проекта и карточка находки
(ADR-0141), причины отличий на странице чтения (ADR-0142; отметка «не отправлено» снята с выпуска, бэклог 88). Данные выдуманные:
демо-проект и поддельный Hub."""

import re
from types import SimpleNamespace

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, no_horizontal_scroll, open_page
from test_hub_status_routes import decide, project, sast
from test_hub_sync_flow import sync_server  # noqa: F401
from test_sync_golden_path import LiveHub, groups, synced, synchronize

pytestmark = pytest.mark.e2e

DEMO_SECRET = "Demo-Passw0rd-2026"  # демо-клон billing-core, DatabaseSettings.java, находка 100109


def open_card(page, pid: int, hub_id: str) -> None:
    page.goto(f"/projects/{pid}/findings")
    page.locator("tr", has_text=hub_id).locator("a[href*='/findings/']").first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+"))


def save_mask(page, pid: int, checked: bool) -> None:
    page.goto(f"/projects/{pid}?open=params#params")
    box = page.locator("#project-mask-secrets")
    box.check() if checked else box.uncheck()
    box.locator("xpath=ancestor::form").locator("button[type=submit]").first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}"))


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_mask_flag_toggles_plain_code_in_card(browser, app_server, theme):
    context, page, watch = open_page(browser, app_server.url, width=1600, height=900, theme=theme)
    try:
        pid = create_demo(page)
        # по умолчанию масок нет (слово владельца 21.11.2026): код в карточке как в клоне
        expect(page.locator("#project-meta-mask")).to_contain_text("показ кода без масок")
        expect(page.locator("#project-mask-secrets")).not_to_be_checked()
        open_card(page, pid, "100109")
        plain = page.locator("#code-plain")
        expect(plain).to_be_visible()
        expect(plain).to_contain_text("Текущий файл в клоне, без масок")
        expect(plain).to_contain_text(DEMO_SECRET)
        assert no_horizontal_scroll(page)

        save_mask(page, pid, True)
        expect(page.locator("#project-meta-mask")).to_contain_text("показ кода с масками")
        open_card(page, pid, "100109")
        expect(page.locator("#code-plain")).to_have_count(0)
        assert DEMO_SECRET not in page.content()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_sync_page_names_causes(browser, sync_server, theme):  # noqa: F811
    url, app = sync_server
    db = app.state.db
    holder = SimpleNamespace(app=app)
    pid = project(holder, [sast("1"), sast("2"), sast("3")])
    hub = LiveHub(3)
    hub.issues[3]["status"] = "Fixed"
    hub.issues[3]["issueBranchBriefData"][0]["status"] = "Fixed"
    synchronize(db, pid, hub)
    decide(holder, pid, "1")
    decide(holder, pid, "3")
    row = synced(db, pid, hub)
    found = groups(db, row)
    assert found.get("pending") == ["SAST:1"] and found.get("unsendable") == ["SAST:3"], found

    context, page, watch = open_page(browser, url, width=1600, height=900, theme=theme)
    try:
        page.goto(f"/projects/{pid}")
        expect(page.locator("#step-hub")).to_contain_text("Состояние Hub")
        expect(page.locator("#step-hub-unsent")).to_have_count(0)  # снятая отметка не показывается
        assert no_horizontal_scroll(page)

        page.goto(f"/projects/{pid}/hub-sync/{row['id']}")
        for group, key, text in (("pending", "issue:SAST:1", "в Hub не отправлена"),
                                 ("unsendable", "issue:SAST:3", "В Hub находка исправлена (Fixed)")):
            box = page.locator(f'[data-sync-group="{group}"]')
            if box.get_attribute("open") is None:
                box.locator(":scope > summary").click()
            item = page.locator(f'[data-sync-item="{key}"]')
            item.locator(":scope > summary").click()
            expect(item.locator(".hub-sync-cause").first).to_contain_text(text)

        assert not watch.problems(), watch.problems()
    finally:
        context.close()
