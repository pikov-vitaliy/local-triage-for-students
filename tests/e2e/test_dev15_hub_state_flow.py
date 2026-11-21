"""0.10.0.dev15 в браузере: состояние относительно Hub там, где работает оператор (ADR-0143):
значок и отбор «Синхронизация с Hub» в списке находок, плашка в карточке, строка «Синхронизация с Hub» на обзоре,
список сохранённых правок. Обе темы, без горизонтальной прокрутки. Данные выдуманные: поддельный Hub."""

import re
from types import SimpleNamespace

import pytest
from playwright.sync_api import expect

from app.hub_sync_compare import DELIVERY_LABELS, LABELS
from e2e_support import no_horizontal_scroll, open_page
from test_hub_status_routes import decide, project, sast
from test_hub_sync_flow import sync_server  # noqa: F401
from test_sync_golden_path import LiveHub, synced, synchronize

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_operator_sees_state_relative_to_hub(browser, sync_server, theme):  # noqa: F811
    url, app = sync_server
    db = app.state.db
    holder = SimpleNamespace(app=app)
    pid = project(holder, [sast("1"), sast("2", line=5), sast("3", line=8)])
    hub = LiveHub(3)
    synchronize(db, pid, hub)
    decide(holder, pid, "2")  # решение есть, в Hub не отправлено
    hub.issues[3]["category"] = {"category": "Новое правило", "cwes": [{"id": "CWE-20"}]}  # Hub сменил справку
    synced(db, pid, hub)
    context, page, watch = open_page(browser, url, width=1600, height=900, theme=theme)
    try:
        page.goto(f"/projects/{pid}")
        line = page.locator("#step-hub-sync-line")
        expect(line).to_contain_text("Синхронизация с Hub")
        expect(line).to_contain_text("не отправлено 1")
        assert no_horizontal_scroll(page)

        page.goto(f"/projects/{pid}/findings")
        expect(page.locator("#hub-state-2")).to_have_text(DELIVERY_LABELS["unsent"])
        expect(page.locator("#hub-state-3")).to_have_text(LABELS["observed"])
        expect(page.locator("#hub-state-1")).to_have_count(0)  # совпадает – без значка
        assert no_horizontal_scroll(page)

        page.goto(f"/projects/{pid}/findings?hubsync=unsent")
        expect(page.locator("#hub-state-2")).to_be_visible()
        expect(page.locator("[id^='hub-state-']")).to_have_count(1)

        page.locator("tr", has_text="2").locator("a[href*='/findings/']").first.click()
        page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+"))
        note = page.locator("#hub-state-note")
        expect(note).to_be_visible()
        expect(note).to_contain_text(DELIVERY_LABELS["unsent"])
        page.locator("#hub-state-link").click()
        page.wait_for_url(re.compile(rf"/projects/{pid}/hub-sync/\d+"))
        assert no_horizontal_scroll(page)

        page.goto(f"/projects/{pid}/hub-pending")
        expect(page.locator("#hub-pending-open")).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
