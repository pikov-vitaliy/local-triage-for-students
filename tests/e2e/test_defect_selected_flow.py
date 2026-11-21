"""Выбор списка, подтверждения, создание и принятие состава Hub в браузере. Данные выдуманы."""

from copy import deepcopy
import re

import pytest
from playwright.sync_api import expect

from app import hub_defects
from app.db import loads
from e2e_support import no_horizontal_scroll, open_page
from selected_hub_support import SelectedHub, drain
from test_hub_defects import REASON, FIX
from test_hub_pull import accept, read, finish_pull
from test_hub_sync_flow import sync_server  # noqa: F401

pytestmark = pytest.mark.e2e


def seed(app):
    db = app.state.db
    db.set_settings({"team_name": "Платформа"})
    pid = db.create_project("Демо выбранного состава")
    db.update_project(pid, hub_app_id=7)
    hub = SelectedHub()
    hub.issues[3]["category"] = {"category": "Другая категория", "cwes": [{"id": "CWE-20"}]}
    accept(db, read((db, pid), hub))
    db.save_review(pid, "2", decision="disagree", final_verdict="false_positive", final_comment="Прежний вывод.", reviewed=True)
    return db, pid, hub


@pytest.mark.parametrize("javascript", [True, False])
def test_selected_flow_and_pull(browser, sync_server, javascript):
    base, app = sync_server
    db, pid, hub = seed(app)
    previous = {h: db.get_review(pid, h) for h in ("1", "2", "3")}
    context = browser.new_context(base_url=base, java_script_enabled=javascript, viewport={"width": 1100, "height": 900})
    page = context.new_page()
    page.set_default_timeout(15000)
    try:
        page.goto(f"/projects/{pid}/findings")
        for ident in ("1", "2", "3"):
            page.locator(f'.row-check[value="{ident}"]').check()
        page.get_by_role("button", name="Дефект из выбранных", exact=True).click()
        expect(page.locator("#selected-included")).to_contain_text("1")
        expect(page.locator("#selected-excluded")).to_contain_text("другая категория")
        page.fill("#selected-comment", REASON)
        page.fill("#selected-fix", FIX)
        page.click("#selected-preview")
        expect(page.locator("#selected-replacements")).to_contain_text("Прежний вывод.")
        # в Hub решения нет (To verify) – применение не создаёт решение «принято из Hub»
        expect(page.locator("#selected-replacements summary")).to_contain_text(["ложная"])
        expect(page.locator("#selected-replacements")).not_to_contain_text("false_positive")
        before_ops = db._scalar("SELECT count(*) FROM hub_ops")
        assert db.get_review(pid, "1") == previous["1"]
        page.check("#selected-confirm")
        page.click("#selected-prepare")  # HTML требует отдельное подтверждение перезаписи.
        assert db._scalar("SELECT count(*) FROM hub_ops") == before_ops
        page.check("#selected-overwrite")
        page.click("#selected-prepare")
        page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
        row_id = int(page.url.rsplit("/", 1)[1])
        drain(db, hub, pid)
        if not javascript:
            page.reload()
        expect(page.locator("#hub-defect-preview")).to_be_visible(timeout=30000)
        expect(page.locator("#hub-defect-targets")).to_contain_text("(2)")
        expect(page.locator("#hub-defect-left-out")).to_contain_text("другая категория")
        before_statuses = deepcopy(hub.issues)
        page.click("#hub-defect-create")
        drain(db, hub, pid)
        page.reload()
        expect(page.locator("#hub-defect-status")).to_contain_text("создан")
        assert db.hub_defect(row_id)["state"] == "done"
        assert hub.issues == before_statuses
        assert {t["id"] for t in hub.defects[555]["linkedIssues"]} == {1, 2}
        assert len([r for r in hub.calls if r["method"] == "POST"]) == 1
        assert db.get_review(pid, "3") == previous["3"]
        for ident in ("1", "2"):
            assert db.get_review(pid, ident)["reviewed"] and db.get_review(pid, ident)["entered_hub"]
        # Принятие снятой связи и изменённых полей выполняется отдельным подтверждением.
        hub.defects[555]["linkedIssues"] = hub.defects[555]["linkedIssues"][:1]
        hub.defects[555]["description"] = hub.defects[555]["description"].replace("Параметризовать", "Исправить")
        page.goto(f"/projects/{pid}/defects")
        page.click("#hub-sync-start")
        page.click("#hub-sync-confirm")
        rid = db._scalar("SELECT max(id) FROM hub_defect_sync_runs")
        finish_pull(db, hub, rid)
        if not javascript:
            page.reload()
        expect(page.locator("#hub-sync-apply")).to_be_visible(timeout=30000)
        page.locator('#hub-sync-apply-form input[name="confirm"]').check()
        page.click("#hub-sync-apply")
        expect(page.locator("#hub-sync-applied")).to_contain_text("Состояние Hub принято")
        assert not db.get_review(pid, "2")["entered_hub"] and db.get_review(pid, "2")["reviewed"]
        assert [t["hub_id"] for t in loads(db.hub_defect(row_id)["targets_json"], [])] == ["1"]
        if javascript:
            page.set_viewport_size({"width": 390, "height": 850})
            no_horizontal_scroll(page)
    finally:
        context.close()


def test_extra_blank_refuses_post_and_keeps_preview(browser, sync_server):
    base, app = sync_server
    db, pid, hub = seed(app)
    hub.extra_blank = True
    context, page, watch = open_page(browser, base)
    watch.allowed_errors.append("status of 400")
    try:
        page.goto(f"/projects/{pid}/hub/defect-selected?hub_id=1&hub_id=2")
        page.fill("#selected-comment", REASON)
        page.fill("#selected-fix", FIX)
        page.click("#selected-preview")
        page.check("#selected-overwrite")
        page.check("#selected-confirm")
        page.click("#selected-prepare")
        page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
        row_id = int(page.url.rsplit("/", 1)[1])
        drain(db, hub, pid)
        expect(page.locator("#hub-defect-create")).to_be_visible(timeout=30000)
        page.click("#hub-defect-create")
        expect(page.locator(".flash-err")).to_contain_text("linkedIssues")
        expect(page.locator("#hub-defect-preview")).to_be_visible()
        assert db.hub_defect(row_id)["state"] == "preview"
        assert not any(r["method"] == "POST" for r in hub.calls)
        assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 0
        page.click("#hub-defect-cancel")
        assert db.hub_defect(row_id)["state"] == "cancelled"
        assert db.get_review(pid, "1")["reviewed"]
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


@pytest.mark.parametrize("javascript", [True, False])
def test_lost_create_response_visible_verify_without_second_post(browser, sync_server, javascript):
    base, app = sync_server
    db, pid, hub = seed(app)
    hub.lost_create = True
    context = browser.new_context(base_url=base, java_script_enabled=javascript)
    page = context.new_page()
    page.set_default_timeout(15000)
    try:
        page.goto(f"/projects/{pid}/hub/defect-selected?hub_id=1&hub_id=2")
        page.fill("#selected-comment", REASON)
        page.fill("#selected-fix", FIX)
        page.click("#selected-preview")
        page.check("#selected-overwrite")
        page.check("#selected-confirm")
        page.click("#selected-prepare")
        page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
        card_url = page.url
        row_id = int(card_url.rsplit("/", 1)[1])
        drain(db, hub, pid)
        page.reload()
        page.click("#hub-defect-create")
        drain(db, hub, pid)
        assert db.hub_defect(row_id)["state"] == "unknown"
        assert not db.hub_defect(row_id)["hub_defect_id"]
        assert not hub_defects.view(db.hub_defect(row_id)).get("diff")
        before = db._all("SELECT * FROM hub_ops")
        calls_before = deepcopy(hub.calls)
        page.reload()
        verify = page.get_by_role("button", name="Pull из Hub", exact=True)
        expect(verify).to_be_visible()
        expect(page.locator("#hub-defect-status")).to_contain_text("неизвестен")
        assert db._all("SELECT * FROM hub_ops") == before
        assert hub.calls == calls_before
        verify.click()
        page.wait_for_url(card_url + "?ok=hub_defect_verify_queued")
        new_ops = db._all("SELECT * FROM hub_ops WHERE id > ?", (before[-1]["id"],))
        assert new_ops and all(loads(op["request_json"], {})["method"] == "GET" for op in new_ops)
        drain(db, hub, pid)
        page.reload()
        expect(page.locator("#defect-title")).to_be_visible()
        expect(page.locator("#hub-defect-status")).to_contain_text("сверено чтением")
        # у дефекта всегда есть «Pull из Hub» (0.9.26.dev34): кнопка остаётся и после сверки
        expect(page.get_by_role("button", name="Pull из Hub", exact=True)).to_have_count(1)
        assert db.hub_defect(row_id)["state"] == "done"
        assert db.get_review(pid, "1")["entered_hub"] and db.get_review(pid, "2")["entered_hub"]
        assert len([r for r in hub.calls if r["method"] == "POST"]) == 1
        assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 1
        assert all(r["method"] == "GET" for r in hub.calls[len(calls_before):])
    finally:
        context.close()
