"""После создания и применения оператор обновляет и привязывает дефект без повторного решения."""

import re
import socket
import threading
import time

import pytest
import uvicorn
from playwright.sync_api import expect

from app import hub_defects
from app.db import loads
from e2e_support import open_page
from test_defect import save_sast
from test_hub_defect_guard import created
from test_hub_defect_import import deliver, take
from test_hub_defect_update import hub_body, phase
from test_hub_defects import FIX, REASON, hub_job, pair_project
from test_hub_pull import finish_pull
from test_hub_review_round1 import project_hub
from test_web import web  # noqa: F401

pytestmark = pytest.mark.e2e


@pytest.fixture
def review_server(web):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(web.app, lifespan="off", log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and time.monotonic() < deadline:
        time.sleep(.05)
    assert server.started
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}", web
    finally:
        server.should_exit = True
        thread.join(20)
        sock.close()
        assert not thread.is_alive()


@pytest.mark.parametrize("action", ["update", "link"])
def test_created_sync_apply_then_send_without_new_review(browser, review_server, action):
    url, web = review_server
    pid = pair_project(web)
    db = web.app.state.db
    finding, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = created(web, pid, finding, defect_id=777)
    sibling, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    reviews = [db.get_review(pid, ident) for ident in ("510001", "510005")]
    # описание в Hub – текст команды (строка создания хранит его в command_text, body_html пуст) и блок Hub
    body = hub_body(summary=row["summary"], description=row["body_html"] or hub_defects.command_html(row["command_text"]))
    if action == "link":
        # тело строки создания уже с блоком Hub: Hub заменил его своим, текст команды тот же (две разные границы – «текст не выделен»)
        body["description"] = hub_defects.command_html(row["command_text"]) + "\n<p>Информация об объекте сканирования:</p><p>Новый блок Hub</p>"
    hub = project_hub(db, pid, [body])
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        finish_pull(db, hub, rid)
        expect(page.locator("#hub-sync-apply")).to_be_visible()
        before = db._all("SELECT * FROM hub_ops")
        page.locator('#hub-sync-apply-form input[name="confirm"]').check()
        page.locator("#hub-sync-apply").click()
        expect(page.locator("#hub-sync-applied")).to_be_visible()
        assert db._all("SELECT * FROM hub_ops") == before
        assert [db.get_review(pid, ident) for ident in ("510001", "510005")] == reviews
        if action == "update":
            page.goto(f"/projects/{pid}/defects/{row['id']}")
            page.locator("#draft-summary").fill(row["summary"] + " уточнён")
            page.locator("#draft-command-text").fill(row["command_text"] + "\n2) Дополнение команды.")
            page.locator("#draft-save").click()
            expect(page.locator("#draft-dirty-note")).to_be_hidden()
            page.goto(f"/projects/{pid}/defects")
            page.locator(f"#hub-update-{row['id']}").click()
            page.wait_for_url(re.compile("ok=hub_update_queued"))
            job = take(web)
            assert job["method"] == "GET"
            deliver(web, job, body=body)
            expect(page.locator("section.hub-update-preview")).to_be_visible()
            page.locator(f"#hub-update-put-form-{row['id']} button").click()
            page.wait_for_url(re.compile("ok=hub_update_put_queued"))
            job = take(web)
            assert job["method"] == "GET"
            deliver(web, job, body=body)
            put = take(web)
            assert put["method"] == "PUT" and "Дополнение команды." in put["body"]["description"]
            deliver(web, put, 204, text="")
            job = take(web)
            assert job["method"] == "GET"
            deliver(web, job, body=put["body"])
            expect(page.locator(f'#hub-defects tr[data-defect-id="{row["id"]}"]')).to_contain_text("Обновлено в Hub")
            assert phase(db, row["id"]) == "done"
        else:
            page.goto(sibling)
            page.locator("#hub-defect-link-form button").click()
            expect(page.locator("#hub-defect-status")).to_contain_text("Привязываю")
            link = hub_job(web)
            assert link["method"] == "POST" and link["path"].endswith("/link")
            body["linkedIssues"].append({"id": 510005, "type": "SAST"})
            hub_job(web, body=body, raw=True)
            expect(page.locator("#entered-badge")).to_be_visible()
            linked = db.hub_defects(pid)[0]
            assert linked["state"] == "done" and "Новый блок Hub" in linked["body_html"]
            assert loads(linked["blank_json"], {})["expected_previous_links"] == [[510001, "SAST"]]
        assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
