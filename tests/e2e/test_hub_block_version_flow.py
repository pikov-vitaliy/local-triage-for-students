"""Единая версия в блоке Hub (ADR-0132) в браузере: предпросмотр создания показывает замену, «Создать» отправляет целевую версию,
Pull показывает правку блока в Hub, «Применить» её принимает, Push приводит блок занесённого дефекта к целевой версии. Данные
выдуманы, Hub поддельный, сеть – только приложение на 127.0.0.1. Снимки экрана пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_hub_block_version import LINKS, SCA_BLOCK, sca_preview  # noqa: E402
from test_hub_defect_update import hub_body, read_job, sca_ready, sent_body  # noqa: E402
from test_hub_defect_import import deliver, take  # noqa: E402
from test_hub_defects import hub_job  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


@pytest.fixture
def stand(web):  # noqa: F811
    """То же приложение, что у тестового клиента, – на настоящем порту: оператор работает в браузере, поддельный исполнитель – клиентом."""
    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(web.app, log_level="error", access_log=False, lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and time.monotonic() < deadline:
        time.sleep(.05)
    assert server.started
    try:
        yield web, url
    finally:
        server.should_exit = True
        thread.join(20)
        sock.close()


def shot(page, name: str, target=None) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        (target or page).screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), **({} if target else {"full_page": True}))


def test_create_pull_apply_with_target_version(browser, stand):
    web, url = stand
    db = web.app.state.db
    pid, row, target = sca_preview(web)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        version = page.locator("#hub-defect-block-version")
        expect(version).to_contain_text(f"1.1.1 – на {target}, мест: 3")
        expect(page.locator("#hub-defect-block")).to_contain_text(f"Обновление demo до версии {target}")
        expect(page.locator("#hub-defect-block")).not_to_contain_text("1.1.1")
        no_horizontal_scroll(page)
        shot(page, "s1-create-preview")
        page.locator("#hub-defect-create").first.click()
        page.wait_for_load_state()
        job = None
        for _ in range(100):
            job = take(web)
            if job is not None:
                break
            time.sleep(.1)
        assert job is not None and job["method"] == "POST", job
        sent = job["body"]["description"]
        assert f"<td>{target}</td>" in sent and "1.1.1" not in sent
        deliver(web, job, 200, text=json.dumps({"id": 900}))
        hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": sent})
        fresh = db.hub_defect(row["id"])
        assert fresh["state"] == "done", fresh["error"]
        assert json.loads(fresh["blank_json"])["description"] == SCA_BLOCK

        # в Hub поправили версию в блоке вручную: Pull показывает правку, «Применить» принимает, повторный Pull совпадает
        edited = sent.replace(f"Обновление demo до версии {target}", "Обновление demo до версии 7.7.7")
        page.goto(f"/projects/{pid}/defects")
        page.locator("form[id^='hub-sync-form-'] button").click()
        page.wait_for_url(re.compile(r"ok=hub_sync_queued"))
        hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": edited})
        page.goto(f"/projects/{pid}/defects")
        block = page.locator(f"#hub-sync-block-{row['id']}")
        expect(block).to_contain_text(f"− Обновление demo до версии {target}")
        expect(block).to_contain_text("+ Обновление demo до версии 7.7.7")
        no_horizontal_scroll(page)
        shot(page, "s1-pull-preview")
        page.locator("form[id^='hub-sync-apply-form-'] button").click()
        page.wait_for_url(re.compile(r"ok=hub_sync_applied"))
        page.locator("form[id^='hub-sync-form-'] button").click()
        page.wait_for_url(re.compile(r"ok=hub_sync_queued"))
        hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": edited})
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator(f"#hub-sync-matches-{row['id']}")).to_be_visible()
        expect(block).to_have_count(0)
        assert watch.page_errors == []
    finally:
        context.close()


def test_push_brings_block_to_target_version(browser, stand):
    web, url = stand
    db = web.app.state.db
    pid, row, card_url = sca_ready(web)
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    fresh = db.hub_defect(row["id"])
    first = hub_body(links=links, summary=fresh["summary"], description="<p>Прежний текст</p>" + SCA_BLOCK)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator(f"#hub-update-form-{row['id']} button").click()
        page.wait_for_url(re.compile(r"ok=hub_update_queued"))
        read_job(web, first)
        page.goto(f"/projects/{pid}/defects")
        notice = page.locator(f"#hub-update-block-version-{row['id']}")
        expect(notice).to_contain_text("1.1.1 – на ")
        expect(notice).to_contain_text("мест: 3")
        expect(page.locator(f"#hub-update-hint-{row['id']}")).to_contain_text("в нём меняется только версия")
        expect(page.locator("section.hub-update-preview")).to_contain_text("73001 | 1.1.1")
        no_horizontal_scroll(page)
        shot(page, "s1-push-preview")
        page.locator("form[id^='hub-update-put-form-'] button").click()
        page.wait_for_url(re.compile(r"ok=hub_update_put_queued"))
        read_job(web, first)
        put = take(web)
        assert put is not None and put["method"] == "PUT", put
        assert "1.1.1" not in put["body"]["description"]
        deliver(web, put, 204, text="")
        read_job(web, sent_body(db, row["id"], linkedIssues=LINKS))
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator('#hub-defects tr[data-origin="import"]')).to_contain_text("Обновлено в Hub")
        shot(page, "s1-push-done")
        assert watch.page_errors == []
    finally:
        context.close()
