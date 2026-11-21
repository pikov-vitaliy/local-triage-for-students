"""«Где исправлять» в браузере (план dev7, раздел 11): оператор нажимает «Push в Hub» у дефекта без служебного блока, видит раздел
в предпросмотре, запись уходит с ним, в черновике раздел остаётся. Данные выдуманы, Hub поддельный, сеть – только приложение
на 127.0.0.1. Снимки экрана пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

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
from test_defect_where import COMMIT, LINK, accepted_state, with_links  # noqa: E402
from test_hub_blank_update_dev31 import TEXT, blank_job, no_block_row  # noqa: E402
from test_hub_defect_import import deliver, take  # noqa: E402
from test_hub_defect_update import read_job, sent_body  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


@pytest.fixture
def stand(web):  # noqa: F811
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


def shot(page, name: str) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(500)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def wait_job(web):
    for _ in range(100):
        job = take(web)
        if job is not None:
            return job
        time.sleep(.1)
    raise AssertionError("операция не поставлена")


def test_operator_sees_section_in_preview_and_draft(browser, stand):
    web, url = stand
    pid, row = no_block_row(web, TEXT + " Правка.")
    accepted_state(web, pid)
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator(f"#hub-update-form-{row['id']} button").click()
        page.wait_for_url(re.compile(r"ok=hub_update_queued"))
        read_job(web, with_links())
        page.goto(f"/projects/{pid}/defects")
        blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator(f"#hub-update-where-{row['id']}")).to_contain_text("служебного блока Hub у дефекта нет")
        text = page.locator(f"#hub-update-text-{row['id']}")
        expect(text).to_contain_text("Где исправлять:")
        expect(text).to_contain_text(f"Коммит: {COMMIT}")
        expect(text).to_contain_text("Ветка: develop")
        expect(text).to_contain_text("Кодовая база: api")
        no_horizontal_scroll(page)
        shot(page, "s11-push-preview")
        page.locator("form[id^='hub-update-put-form-'] button").click()
        page.wait_for_url(re.compile(r"ok=hub_update_put_queued"))
        read_job(web, with_links())
        page.goto(f"/projects/{pid}/defects")
        put = wait_job(web)
        assert put["method"] == "PUT" and COMMIT in put["body"]["description"], put
        deliver(web, put, 204, text="")
        page.goto(f"/projects/{pid}/defects")
        read_job(web, {**sent_body(db, row["id"]), "linkedIssues": [LINK]})
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        expect(page.locator("#draft-command-text, textarea[name='draft_command_text']").first).to_have_value(re.compile(r"Где исправлять:\nКодовая база: api"))
        no_horizontal_scroll(page)
        shot(page, "s11-card")
        assert watch.page_errors == []
    finally:
        context.close()
