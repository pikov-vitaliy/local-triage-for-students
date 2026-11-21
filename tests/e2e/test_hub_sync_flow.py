"""Общий обход: подтверждение, ход, остановка, продолжение и сохранённые расхождения."""

import socket
import threading
import time

import pytest
import uvicorn
from playwright.sync_api import expect

from app.config import Settings
from app.main import create_app
from e2e_support import DEMO_REPOS, make_fake_ollama, open_page
from test_hub_sync import FakeSyncHub, finish, step

pytestmark = pytest.mark.e2e


def test_sync_apply_then_second_sync_matches(browser, sync_server):
    from app.db import loads
    from test_hub_pull import PullHub, finish_pull

    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо принятия Hub")
    db.update_project(pid, hub_app_id=7)
    hub = PullHub()
    hub.decision(1)
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
        expect(page.locator("#hub-sync-applied")).to_contain_text("Состояние Hub принято")
        expect(page.locator("#hub-sync-matches")).to_contain_text("база совпадает с Hub")
        assert db._all("SELECT * FROM hub_ops") == before
        fid = db._scalar("SELECT id FROM findings WHERE project_id=?", (pid,))
        page.goto(f"/projects/{pid}/findings/{fid}")
        expect(page.locator("#hub-accepted-state")).to_contain_text("Основание Hub")
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        second = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        assert second != rid
        finish_pull(db, hub, second)
        expect(page.locator("#hub-sync-matches")).to_contain_text("база совпадает с Hub")
        assert all(loads(op["request_json"], {})["method"] == "GET" for op in db._all("SELECT * FROM hub_ops"))
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_catalog_pages_search_and_readonly_hub_block(browser, sync_server):
    from app.db import dumps, loads
    from app import hub_sync as sync, hub_sync_compare as compare
    from test_hub_composition_audit import seed_catalog
    from test_hub_sync_analyst import defect_store

    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо страниц")
    seed_catalog(db, pid)
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator("#hub-defects-total")).to_contain_text("Всего: 501")
        expect(page.locator("#hub-defects tbody > tr")).to_have_count(200)  # с 0.9.26.dev4 по умолчанию 200
        page.goto(f"/projects/{pid}/defects?page_size=50")
        expect(page.locator("#hub-defects tbody > tr")).to_have_count(50)
        page.get_by_label("Поиск по заголовку или номеру Hub").fill("демо")
        page.get_by_role("button", name="Найти", exact=True).click()
        page.get_by_role("link", name="Следующая страница", exact=True).click()
        expect(page.locator("#hub-defects-total")).to_contain_text("Страница 2 из 11")
        expect(page.get_by_label("Поиск по заголовку или номеру Hub")).to_have_value("демо")
        before = page.locator('#hub-defects tbody > tr').first.get_attribute('data-defect-id')
        page.locator('#hub-defects td[data-label="Заголовок"] a').first.click()
        page.locator('nav.crumbs').get_by_role('link', name='Дефекты', exact=True).click()
        expect(page.locator("#hub-defects-total")).to_contain_text("Страница 2 из 11")
        expect(page.get_by_label("Поиск по заголовку или номеру Hub")).to_have_value("демо")
        assert page.locator('#hub-defects tbody > tr').first.get_attribute('data-defect-id') == before
        page.get_by_label("Поиск по заголовку или номеру Hub").fill("0000")
        page.get_by_role("button", name="Найти", exact=True).click()
        expect(page.locator("#hub-defects-total")).to_contain_text("Всего: 1")
        expect(page.locator("#hub-defects")).to_contain_text("Демо 0000")

        pid = db.create_project("Демо блока Hub")
        db.update_project(pid, hub_app_id=7)
        rid = sync.start(db, pid, "https://hub.example.org", 7)
        finish(db, FakeSyncHub(), rid)
        _, body = defect_store((db, pid))
        body["description"] = body["description"].replace("строка 10", "строка 20")
        with db._tx() as c:
            c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json) VALUES (?,'defect','77',?)",
                      (rid, dumps({"brief": {"id": 77}, "detail": body})))
            compare.compare_in(c, sync.run_in(c, rid))
        page.goto(f"/projects/{pid}/hub-sync/{rid}")
        group = page.locator('[data-sync-group="changed"]')
        group.locator(":scope > summary").click()
        item = page.locator('[data-sync-item="defect:77"]')
        item.locator(":scope > summary").click()
        expect(item.locator(".hub-sync-fields")).to_contain_text("Блок Hub (только чтение)")
        expect(item.locator(".hub-sync-fields")).to_contain_text("строка 10")
        expect(item.locator(".hub-sync-fields")).to_contain_text("строка 20")
        expect(item.locator("textarea,input")).to_have_count(0)
        assert all(loads(op["request_json"], {})["method"] == "GET" for op in db._all("SELECT * FROM hub_ops"))
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


@pytest.fixture
def sync_server(tmp_path):
    with make_fake_ollama() as fake:
        app = create_app(Settings(data_dir=tmp_path / "data", repos_root=DEMO_REPOS, ollama_url=fake.url,
                                  hub_url="https://hub.example.org", osv_url=""))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        try:
            yield url, app
        finally:
            server.should_exit = True
            thread.join(20)
            sock.close()
            assert not thread.is_alive()


def test_hub_sync_confirmation_progress_stop_resume_diffs_and_matches(browser, sync_server):
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо синхронизации")
    db.update_project(pid, hub_app_id=7)
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        expect(page.locator("#hub-sync-confirm")).to_be_visible()
        assert not db._all("SELECT * FROM hub_ops")
        page.get_by_role("link", name="Отменить", exact=True).click()
        assert not db._all("SELECT * FROM hub_ops")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
        hub = FakeSyncHub(3)
        step(db, hub); step(db, hub); step(db, hub)
        expect(page.locator("#hub-sync-progress-label")).to_contain_text("Находки в списке: 3 / 3")
        page.locator("#hub-sync-stop").click()
        expect(page.locator("#hub-sync-state")).to_have_text("Остановлено")
        saved = len(hub.calls)
        page.reload()
        assert len(hub.calls) == saved
        page.locator("#hub-sync-continue").click()
        expect(page.get_by_role("heading", name="Оставшиеся и повторяемые запросы", exact=False)).to_be_visible()
        page.locator("#hub-sync-confirm").click()
        finish(db, hub, rid)
        expect(page.locator('[data-sync-group="new"]')).to_be_visible()
        expect(page.locator("#hub-sync-apply")).to_be_visible()
        assert not db._all("SELECT * FROM hub_sync_applications")
        page.reload()
        expect(page.locator('[data-sync-group="new"]')).to_be_visible()
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        expect(page.locator("#hub-sync-previous")).to_contain_text("Есть завершённый прогон")
        expect(page.locator("#hub-sync-previous")).to_contain_text("Новые в Hub: 3")
        expect(page.locator("#hub-sync-confirm")).to_have_text("Начать новое чтение")
        assert len(hub.calls) == saved + 5
        previous = rid
        page.locator("#hub-sync-confirm").click()
        rid = db._one("SELECT MAX(id) AS id FROM hub_defect_sync_runs")["id"]
        assert rid != previous
        finish(db, FakeSyncHub(), rid)
        expect(page.locator("#hub-sync-matches")).to_contain_text("Принятая база совпадает")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_old_protocol_worker_has_update_instruction(browser, sync_server):
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо старого исполнителя")
    db.update_project(pid, hub_app_id=7)
    app.state.hub_workers["old"] = {"seen_mono": time.monotonic(), "hub_url": "https://hub.example.org",
                                    "sync_protocol": 1}
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        expect(page.locator("#hub-sync-worker")).to_contain_text("протокол устарел: обновите исполнитель")
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-worker")).to_contain_text("обновите исполнитель")
        page.locator("#hub-sync-worker-help summary").click()
        expect(page.locator("#hub-sync-worker-help")).to_contain_text("замените hub_worker.py")
        page.get_by_role("link", name="Инструкция установки и обновления исполнителя").click()
        page.locator("#hub-worker-instructions summary").click()
        expect(page.locator("#hub-worker-instructions")).to_contain_text("сохранив свой hub_worker.conf")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_running_checks_and_readable_issue_comparison(browser, sync_server):
    from app.models import Finding
    from app.triage import order_findings
    from test_hub_sync import VariedSyncHub
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо сравнения")
    db.update_project(pid, hub_app_id=7)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    db.save_review(pid, "1", decision="agree", final_verdict="false_positive", final_comment="Локальный комментарий", reviewed=True)
    finding = db._one("SELECT id FROM findings WHERE project_id=?", (pid,))
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-verification")).to_contain_text("страницы 0")
        rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
        hub = VariedSyncHub(4)
        hub.issues[0]["branch"] = "release"
        step(db, hub)
        expect(page.locator("#hub-sync-verification")).to_contain_text("страницы 1")
        expect(page.locator("#hub-sync-branches")).to_contain_text("release")
        step(db, hub)
        step(db, hub, status=503, body={})
        expect(page.locator("#hub-sync-verification")).to_contain_text("исключения ответов: 1")
        expect(page.locator("#hub-sync-stop")).to_be_visible()
        finish(db, hub, rid)
        expect(page.locator("#hub-sync-stop")).to_have_count(0)
        # Без принятой базы прежний комментарий не доказывает неотправленную правку.
        expect(page.locator('[data-sync-group="pending"]')).to_have_count(0)
        page.locator('[data-sync-group="unknown_base"] > summary').click()
        item = page.locator('[data-sync-group="unknown_base"] > details').first
        item.locator(":scope > summary").click()
        expect(item.locator(".hub-sync-fields")).to_be_visible()
        expect(item.locator(".hub-sync-fields")).to_contain_text("Основание")
        expect(item.locator(".hub-sync-fields")).to_contain_text("Локальный комментарий")
        link = item.get_by_role("link", name="Открыть карточку находки")
        expect(link).to_have_attribute("href", f"/projects/{pid}/findings/{finding['id']}")
        expect(item).to_contain_text("состояние Hub становится принятой базой")
        expect(page.locator("#hub-sync-apply")).to_be_visible()
        assert not db._all("SELECT * FROM hub_sync_applications")
        link.click()
        expect(page).to_have_url(f"{url}/projects/{pid}/findings/{finding['id']}")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


@pytest.mark.parametrize("case", ["capped", "total_changed", "object_exception"])
def test_measured_sync_outcome_in_browser(browser, sync_server, case):
    from app import hub_sync
    from test_hub_sync_measured import MeasuredHub
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо проверки чтения")
    db.update_project(pid, hub_app_id=7)
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        expect(page.get_by_text("Ветки: как в Hub по умолчанию", exact=False)).to_be_visible()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
        hub = MeasuredHub(cap=2 if case != "object_exception" else 100)
        step(db, hub)
        if case == "total_changed":
            hub.issues.pop()
        elif case == "object_exception":
            step(db, hub)
            step(db, hub, body=[])
        finish(db, hub, rid)
        expect(page.locator("#hub-sync-verification")).to_contain_text("Проверка на ходу")
        expect(page.locator("#hub-sync-stop")).to_have_count(0)
        expect(page.locator("#hub-sync-branches")).to_contain_text("как в Hub по умолчанию")
        expect(page.locator("#hub-sync-matches")).to_have_count(0)
        if case == "capped":
            expect(page.locator("#hub-sync-verification")).to_contain_text("находки 3 / 3, дефекты 5 / 5")
            expect(page.locator("#hub-sync-verification")).to_contain_text("перечитывания с меньшим шагом 2")
            expect(page.locator("#hub-sync-branches")).to_contain_text("main, release")
        else:
            expect(page.get_by_text("Чтение неполное:", exact=False).first).to_be_visible()
            if case == "object_exception":
                expect(page.locator('[data-sync-group="incomplete"]')).to_be_visible()
                expect(page.locator("#hub-sync-continue")).to_be_visible()
                data = hub_sync.passport(db._one("SELECT * FROM hub_defect_sync_runs"))
                assert data["comparison_complete"] and data["exceptions"] == 1
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_type_collision_has_no_link_to_other_finding(browser, sync_server):
    from app.models import Finding
    from app.triage import order_findings
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо коллизии")
    db.update_project(pid, hub_app_id=7)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([Finding(hub_id="1", kind="SAST")]))
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
        hub = FakeSyncHub(1)
        hub.issues[0]["type"] = "SCA_S"
        finish(db, hub, rid)
        # коллизия типа: общих находок с выгрузкой нет – оператор подтверждает номер (ADR-0140)
        page.reload()
        page.locator("#hub-sync-app-confirm").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        finish(db, hub, rid)
        page.reload()
        page.locator('[data-sync-group="unmapped"] > summary').click()
        item = page.locator('[data-sync-group="unmapped"] > details')
        expect(item).to_have_count(1)
        item.locator(":scope > summary").click()
        expect(item).to_contain_text("Сопоставленной карточки нет.")
        expect(item.get_by_role("link", name="Открыть карточку находки")).to_have_count(0)
        expect(item).not_to_contain_text("проверить и сохранить локальное решение")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_new_read_removes_continue_from_stopped_history(browser, sync_server):
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо закрытого чтения")
    db.update_project(pid, hub_app_id=7)
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._one("SELECT id FROM hub_defect_sync_runs")["id"]
        hub = FakeSyncHub(1)
        step(db, hub)
        step(db, hub)
        page.locator("#hub-sync-stop").click()
        expect(page.locator("#hub-sync-continue")).to_be_visible()
        old_url = page.url
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        expect(page.locator("#hub-sync-confirm")).to_have_text("Начать новое чтение")
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        assert db._one("SELECT id FROM hub_defect_sync_runs WHERE closed_at IS NULL")["id"] != rid
        before = db._all("SELECT * FROM hub_ops ORDER BY id")
        page.goto(old_url)
        expect(page.locator("#hub-sync-state")).to_have_text("Запуск закрыт")
        expect(page.locator("#hub-sync-continue")).to_have_count(0)
        assert db._all("SELECT * FROM hub_ops ORDER BY id") == before
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_large_sync_groups_pagination_and_deferred_raw(browser, sync_server):
    from test_hub_sync_dev2 import seed_large_run
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо большого результата")
    db.update_project(pid, hub_app_id=7)
    rid, _ = seed_large_run(db, pid)
    before = db._all("SELECT * FROM hub_ops")
    context, page, watch = open_page(browser, url)
    raw_requests = []
    page.on("request", lambda request: raw_requests.append(request.url) if "/raw?" in request.url else None)
    try:
        response = page.goto(f"/projects/{pid}/hub-sync/{rid}")
        assert len(response.body()) < 200_000
        groups = page.locator("details[data-sync-group]")
        expect(groups).to_have_count(1)
        assert groups.evaluate_all("nodes => nodes.every(node => !node.open)")
        group = page.locator('[data-sync-group="incomplete"]')
        group.locator(":scope > summary").click()
        expect(group.locator(":scope > details")).to_have_count(50)
        expect(group).to_contain_text("Показано 50 из 2000")
        keys = page.locator('[data-sync-item]').evaluate_all("nodes => nodes.map(node => node.dataset.syncItem)")
        assert len(keys) == len(set(keys)) == 50
        assert raw_requests == []
        item = group.locator(":scope > details").first
        item.locator(":scope > summary").click()
        raw = item.locator("details[data-sync-raw]")
        assert raw_requests == []
        raw.locator("summary").click()
        expect(raw.locator("[data-sync-raw-status]")).to_have_text("Сохранённые данные загружены.")
        expect(raw.locator("[data-sync-raw-content]")).to_contain_text("сохранённый-текст")
        assert len(raw_requests) == 1
        raw.locator("summary").click()
        raw.locator("summary").click()
        assert len(raw_requests) == 1
        group.get_by_role("link", name="Следующая страница", exact=True).click()
        expect(group).to_contain_text("Страница 2 из 40")
        expect(group.locator(":scope > details").first.locator(":scope > summary")).to_have_text("Находка SAST:0051")
        group.get_by_role("link", name="Предыдущая страница", exact=True).click()
        expect(group).to_contain_text("Страница 1 из 40")
        page.locator('#hub-sync-query').fill('SAST:1999')
        page.locator('#hub-sync-search button').click()
        expect(page.locator('#hub-sync-search-count')).to_have_text('Найдено: 1.')
        expect(page.locator('[data-sync-item]')).to_have_count(1)
        expect(page.locator('[data-sync-item]')).to_have_attribute('data-sync-item', 'issue:SAST:1999')
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert db._all("SELECT * FROM hub_ops") == before
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_saved_empty_manual_recompare_from_page(browser, sync_server):
    from test_hub_sync_dev2 import OLD_ADAPTER, deliver_text, waiting_manual
    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо сохранённого пустого статуса")
    db.update_project(pid, hub_app_id=7)
    rid = waiting_manual((db, pid), OLD_ADAPTER)
    deliver_text(db, "")
    before = db._all("SELECT * FROM hub_ops")
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/hub-sync/{rid}")
        expect(page.locator("#hub-sync-incomplete")).to_contain_text("исключений ответов 1")
        page.get_by_role("button", name="Пересчитать расхождения", exact=True).click()
        expect(page.locator("#hub-sync-incomplete")).to_have_count(0)
        expect(page.locator('[data-sync-group="incomplete"]')).to_have_count(0)
        expect(page.locator("#hub-sync-progress-label")).to_contain_text("Основания и риски: 1 / 1")
        expect(page.locator("#hub-sync-continue")).to_have_count(0)
        assert db._all("SELECT * FROM hub_ops") == before
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
