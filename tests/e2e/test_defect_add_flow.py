"""«Добавить в дефект» в браузере (ADR-0136): оператор идёт из карточки находки, выбирает занесённый дефект, видит предпросмотр и подтверждает;
затем «Pull из Hub», «Применить», правка и Push. Hub поддельный, данные выдуманы, сеть – только приложение на 127.0.0.1. Снимки пишутся, если задан
E2E_SHOTS."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_add import OTHER_REASON, created, from_import, in_hub  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_hub_defect_import import deliver, take  # noqa: E402
from test_hub_defect_update import hub_body, phase, read_job, sent_body  # noqa: E402
from test_hub_defects import hub_job  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


def shot(page, name: str) -> None:
    """Обе темы на каждом шаге: без горизонтальной прокрутки; снимок – если задан E2E_SHOTS."""
    folder = os.environ.get("E2E_SHOTS")
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        no_horizontal_scroll(page)
        if folder:
            page.wait_for_timeout(500)
            page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def add_from_card(page, db, pid: int, row: dict, hub_id: str = "510002") -> None:
    page.goto(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, hub_id)['id']}")
    page.locator("#hub-defect-add-link").click()
    page.wait_for_url(re.compile(r"/hub/add-to-defect"))
    page.locator(f'input[name="defect"][value="{row["id"]}"]').check()
    no_horizontal_scroll(page)
    shot(page, "add-choose")
    page.locator("#add-preview").click()
    expect(page.locator("#add-request")).to_contain_text(f"POST /defects/{row['hub_defect_id']}/link")
    expect(page.locator("#add-own-text")).to_contain_text(OTHER_REASON)
    expect(page.locator("#add-request-body")).to_contain_text("groupId")
    no_horizontal_scroll(page)
    shot(page, "add-preview")
    page.locator("#add-confirm").check()
    page.locator("#add-apply").click()
    page.wait_for_url(re.compile(r"ok=defect_add_queued"))


def test_operator_adds_to_imported_defect_pulls_applies_and_pushes(browser, stand):  # noqa: F811
    web, url = stand
    pid, row = from_import(web)
    db = web.app.state.db
    both = hub_body(links=((510001, "SAST"), (510002, "SAST")))
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        add_from_card(page, db, pid, row)
        job = hub_job(web, body={})
        assert job["path"] == "/defects/777/link" and job["body"]["issueIds"] == [510002] and job["body"]["groupId"] is None
        hub_job(web, body=both)
        # карточка дефекта объясняет следующий шаг; правка закрыта до «Применить»
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator("#defect-unmerged")).to_contain_text("510002")
        expect(page.locator("#draft-save")).to_be_disabled()
        no_horizontal_scroll(page)
        shot(page, "add-unmerged")
        page.get_by_role("button", name="Pull из Hub").click()
        page.wait_for_load_state()
        hub_job(web, body=both)
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator(f"#hub-sync-unmerged-{row['id']}")).to_contain_text("внесёт их в состав")
        shot(page, "add-sync-preview")
        page.locator(f"#hub-sync-apply-{row['id']}").click()
        page.wait_for_load_state()
        expect(page.locator("#defect-unmerged")).to_have_count(0)
        owner = db.hub_defect(row["id"])
        assert {t["hub_id"] for t in json.loads(owner["targets_json"])} == {"510001", "510002"}
        # правка и Push: в предпросмотре полный состав
        page.locator("#draft-command-text").fill("Правка после добавления находки: данные попадают в запрос без параметров.")
        page.locator("#draft-save").click()
        page.wait_for_load_state()
        page.locator("#defect-update-prepare").click()
        page.wait_for_load_state()
        hub_job(web, body=both)
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator(f"#hub-update-put-form-{row['id']}")).to_be_visible()
        no_horizontal_scroll(page)
        shot(page, "add-push-preview")
        page.locator(f"#hub-update-put-form-{row['id']} button[type=submit]").first.click()
        page.wait_for_load_state()
        read_job(web, both)
        put = take(web)
        assert put["method"] == "PUT" and {i["id"] for i in put["body"]["linkedIssues"]} == {510001, 510002}
        deliver(web, put, 204, text="")
        read_job(web, sent_body(db, row["id"], links=((510001, "SAST"), (510002, "SAST"))))
        assert phase(db, row["id"]) == "done"
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator("#hub-defect-status")).to_contain_text("Обновлено в Hub")
        shot(page, "add-push-done")
        assert watch.page_errors == []
    finally:
        context.close()


def test_unknown_outcome_is_read_again_from_the_finding_card(browser, stand):  # noqa: F811
    web, url = stand
    pid, row, description = created(web)
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        add_from_card(page, db, pid, row)
        hub_job(web, status=504, error="нет ответа")
        page.goto(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}")
        expect(page.locator("#hub-defect-verify")).to_be_visible()
        shot(page, "add-unknown")
        page.locator("#hub-defect-verify").click()
        expect(page.locator("#hub-defect-status")).to_contain_text("", timeout=5000)
        hub_job(web, body=in_hub(row, description, 510001, 510002))
        page.goto(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}")
        expect(page.locator("#hub-defect-done")).to_contain_text("Находки привязаны")
        assert db.hub_defect_bound(pid, "510002")["state"] == "done"
        assert watch.page_errors == []
    finally:
        context.close()


def test_hub_refusal_is_shown_and_defect_stays_selectable(browser, stand):  # noqa: F811
    web, url = stand
    pid, row, _ = created(web)
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        add_from_card(page, db, pid, row)
        hub_job(web, status=400, error="отказ Hub")
        page.goto(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510002')['id']}")
        expect(page.locator("#hub-defect-status")).to_contain_text("отказ Hub")
        expect(page.locator("#hub-defect-add-link")).to_be_visible()
        shot(page, "add-refused")
        assert watch.page_errors == []
    finally:
        context.close()
