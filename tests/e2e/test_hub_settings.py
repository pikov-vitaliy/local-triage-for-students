"""Запись в Hub через исполнителя (ADR-0114) в браузере: раздел «AppSec.Hub» в настройках – адрес Hub, ключ,
состояние исполнителя, «Проверить связь» с поддельным исполнителем в потоке теста (он ходит к приложению так же, как
настоящий: ключ в заголовке, Origin – адрес приложения); номер приложения Hub в параметрах проекта; вёрстка 360 px.
Hub и учётные данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
import urllib.request

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import worker_key  # noqa: E402
from e2e_support import create_demo, no_horizontal_scroll, open_page  # noqa: E402

pytestmark = pytest.mark.e2e

HUB = "https://hub.example.org"
PRINCIPAL = {"name": "user1", "firstName": "Иван", "lastName": "Тестов", "roles": ["DEVELOPER", "MANAGER"]}


def worker_call(base: str, key: str, method: str, path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Accept": "application/json", "Content-Type": "application/json",
                                          "Origin": base, "X-Hub-Worker-Key": key})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fake_worker(base: str, key: str, stop: threading.Event, done: list) -> None:
    """Поддельный исполнитель: приветствие, долгий опрос, ответ Hub на GET /auth/user – тело PrincipalDto."""
    worker_call(base, key, "POST", "/api/hub/worker/hello",
                {"worker_id": "e2e-1", "hub_url": HUB, "hub_user": "Иван Тестов", "hub_login": "user1",
                 "roles": PRINCIPAL["roles"], "version": "e2e"})
    query = urllib.parse.urlencode({"worker_id": "e2e-1", "hub_url": HUB, "wait": 2})
    while not stop.is_set():
        job = worker_call(base, key, "GET", f"/api/hub/jobs?{query}").get("job")
        if not job:
            continue
        assert job["method"] == "GET" and job["path"] == "/auth/user"
        done.append(worker_call(base, key, "POST", f"/api/hub/jobs/{job['attempt_id']}/result",
                                {"lease_token": job["lease_token"], "worker_id": "e2e-1", "status": 200,
                                 "headers": {"content-type": "application/json"},
                                 "body_text": json.dumps(PRINCIPAL, ensure_ascii=False), "took_ms": 12}))
        return


def test_hub_section_probe_with_fake_worker(ui, app_server):
    page, _ = ui
    page.goto("/settings#hub")
    section = page.locator("#hub")
    expect(section.locator("h2")).to_contain_text("AppSec.Hub")
    key = page.locator("#hub-key").inner_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", key)
    assert key == worker_key(app_server)
    expect(page.locator("#hub-worker-state")).to_contain_text("не на связи")
    # адрес Hub сохраняется общей кнопкой раздела
    page.fill("#hub-url", HUB)
    page.locator("#hub-url-save").click()
    page.wait_for_url(re.compile(r"/settings\?ok=settings_saved"))
    expect(page.locator("#hub-url")).to_have_value(HUB)
    expect(page.locator("#hub-probe-button")).to_be_enabled()
    # «Проверить связь»: пока исполнителя нет – ждём его; поддельный исполнитель отвечает – имя и роли
    page.locator("#hub-probe-button").click()
    expect(page.locator("#hub-probe-status")).to_contain_text("Ждём исполнителя")
    stop, done = threading.Event(), []
    thread = threading.Thread(target=fake_worker, args=(app_server.url, key, stop, done), daemon=True)
    thread.start()
    try:
        expect(page.locator("#hub-probe-status")).to_contain_text("вошли как Иван Тестов (user1)", timeout=20000)
        expect(page.locator("#hub-probe-status")).to_contain_text("DEVELOPER, MANAGER")
    finally:
        stop.set()
        thread.join(timeout=30)
    assert done and done[0]["outcome"] == "accepted" and done[0]["state"] == "done"
    page.reload()
    expect(page.locator("#hub-worker-state")).to_contain_text("на связи")
    expect(page.locator("#hub-worker-state")).to_contain_text("вошёл в Hub как Иван Тестов (user1)")
    # повторная проверка ставится снова; исполнителя уже нет – ждём его
    page.locator("#hub-probe-button").click()
    expect(page.locator("#hub-probe-status")).to_contain_text("Ждём исполнителя")


def test_hub_key_rotate_asks_and_changes_key(ui, app_server):
    page, _ = ui
    page.goto("/settings#hub")
    old = page.locator("#hub-key").inner_text().strip()
    asked = []
    page.on("dialog", lambda dialog: asked.append(dialog.message))  # подтверждение принимает open_page
    page.locator("#hub-key-rotate").click()
    page.wait_for_url(re.compile(r"/settings\?ok=hub_key_rotated"))
    expect(page.locator(".flash-ok")).to_contain_text("Выпущен новый ключ исполнителя")
    new = page.locator("#hub-key").inner_text().strip()
    assert new != old and new == worker_key(app_server)
    assert asked and "Прежний сразу перестанет действовать" in asked[0]


def test_project_hub_app_id_saved(ui):
    page, _ = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}#params")
    page.locator("#params > summary").click()
    page.fill("#project-hub-app-id", "4242")
    page.locator("#params button[type=submit]", has_text="Сохранить параметры").click()
    page.wait_for_url(re.compile(rf"/projects/{pid}\?ok=project_saved"))
    page.locator("#params > summary").click()
    expect(page.locator("#project-hub-app-id")).to_have_value("4242")


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_hub_section_fits_360(browser, app_server, theme):
    context, page, watch = open_page(browser, app_server.url, width=360, height=800, theme=theme)
    try:
        page.goto("/settings#hub")
        expect(page.locator("#hub")).to_be_visible()
        assert no_horizontal_scroll(page)
        assert not watch.problems()
    finally:
        context.close()
