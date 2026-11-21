"""«Push в Hub» (ADR-0125) в браузере: дефект №777, занесённый из Hub, с находкой, по которой сохранено
«Подтверждаю дефект»; во вкладке «Дефекты» – «Подготовить обновление»: поддельный исполнитель отвечает на чтение –
вкладка сама перезагружается и показывает предпросмотр (новый заголовок и текст по решению); «Push в Hub» –
исполнитель отвечает на второе чтение, на `PUT /defects/777` (204 без тела) и на подтверждающее чтение – строка
«Обновлено в Hub», в карточке находки – отметка «дефект создан в Hub». Подготовка, поставленная до перезапуска
приложения, доводится после него. Запись с неизвестным исходом (5xx) – «Сверить»: чтение показывает отправленное –
«Обновлено в Hub». Тело `PUT` – прочитанный объект, где заменены только заголовок и описание; блок Hub – байт в байт.
Hub, номера и учётные данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import open_fields, DEMO_REPOS, create_demo, make_fake_ollama, open_page, run_triage, start_app, stop_app  # noqa: E402
from test_hub_defect_card import save_true_positive  # noqa: E402
from test_hub_defect_import_flow import import_number  # noqa: E402
from test_hub_status_card import APP_ID, open_first_sast, set_hub, start_worker  # noqa: E402
from test_stored_code_snapshots import restart  # noqa: E402

pytestmark = pytest.mark.e2e

OLD_SUMMARY = "ID5 - SQL injection (SAST)"
BLOCK = "<p>Информация об объекте сканирования:</p><p>файл, строка, ветка</p>"
DESCRIPTION = "<p>Старый текст команды прежнего формата.</p>" + BLOCK


def defect(links: list[str], summary: str = OLD_SUMMARY, description: str = DESCRIPTION, **extra) -> dict:
    """Дефект №777 в поддельном Hub (поля – как у ответа интерфейса Hub, значения выдуманы)."""
    return {"id": 777, "appId": int(APP_ID), "summary": summary, "description": description,
            "linkedIssues": [{"id": int(i), "type": "SAST"} for i in links], "author": {"login": "user1"},
            "createTs": "2026-10-27T12:00:00Z", "updateTs": "2026-10-28T12:00:00Z", "priorityId": 2, "severityId": 3, "settings": {}, "priority": {"name": "High"}, "severity": {"name": "High"},
            "status": "Open", **extra}


def hub_for(links: list[str], seen: dict, put_status: int = 204):
    """Ответы поддельного Hub: чтение `GET /defects/777` – прежний дефект или, после записи, отправленное; `PUT` –
    put_status без тела; тело записи – в seen["put"]."""
    def answer(job: dict) -> tuple[int, str]:
        if job["method"] == "PUT":
            assert job["path"] == "/defects/777", job
            seen.setdefault("put", []).append(job["body"])
            return put_status, ""
        assert job["method"] == "GET" and job["path"] == "/defects/777", job
        if seen.get("put") and seen.get("applied", True):
            body = seen["put"][-1]
            return 200, json.dumps({**body, "updateTs": "2026-10-29T12:00:00Z"}, ensure_ascii=False)
        return 200, json.dumps(defect(links), ensure_ascii=False)
    return answer


def run_worker(server, answers: list, until):
    stop, jobs, thread = start_worker(server, answers)
    try:
        until()
    finally:
        stop.set()
        thread.join(timeout=30)
    return jobs


def test_prepare_preview_update_confirm_restart_and_verify(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        seen: dict = {}
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            run_triage(page, pid)
            open_first_sast(page, pid)
            card = page.url.split("?")[0].split("#")[0]
            hub_id = page.locator("#route-id").inner_text().strip()
            save_true_positive(page)
            expect(page.locator("#entered-badge")).to_be_hidden()
            # занесение дефекта из Hub
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            run_worker(server, [hub_for([hub_id], seen)], lambda: expect(
                page.locator("form[id^='hub-import-accept-form-'] button")).to_be_visible(timeout=30000))
            page.locator("form[id^='hub-import-accept-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_import_done"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_have_attribute("data-state", "done")
            # ADR-0126: оператор явно собирает и сохраняет черновик до подготовки обновления.
            row.locator('td[data-label="Заголовок"] a').click()
            page.get_by_role("button", name="Собрать текст из решений").click()
            page.goto(f"/projects/{pid}/defects")
            row = page.locator('#hub-defects tr[data-origin="import"]')
            # «Подготовить обновление» → предпросмотр
            row.locator("form[id^='hub-update-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_queued"))
            expect(row).to_contain_text("читаю дефект №777")
            run_worker(server, [hub_for([hub_id], seen)], lambda: expect(
                page.locator("section.hub-update-preview")).to_be_visible(timeout=30000))
            preview = page.locator("section.hub-update-preview")
            expect(preview.locator("[id^='hub-update-old-summary-']")).to_have_text(OLD_SUMMARY)
            expect(preview.locator("[id^='hub-update-summary-']")).to_contain_text("ID5 - ")
            expect(preview.locator("pre[id^=hub-update-text-]")).to_contain_text("Обоснование:")
            expect(preview.locator("pre[id^=hub-update-text-]")).to_contain_text("PreparedStatement")
            new_summary = preview.locator("[id^='hub-update-summary-']").inner_text().strip()
            assert new_summary != OLD_SUMMARY and new_summary.endswith("(SAST)")
            # «Push в Hub» → второе чтение, PUT, подтверждающее чтение
            preview.locator("form[id^='hub-update-put-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_put_queued"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            jobs = run_worker(server, [hub_for([hub_id], seen)] * 3,
                              lambda: expect(row).to_contain_text("Обновлено в Hub", timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777"), ("PUT", "/defects/777"),
                                                                ("GET", "/defects/777")]
            put = seen["put"][0]
            before = defect([hub_id])
            assert {k: v for k, v in put.items() if k not in ("summary", "description")} == {
                k: v for k, v in before.items() if k not in ("summary", "description")}
            assert put["summary"] == new_summary and put["description"].endswith(BLOCK), "dev30: блок Hub сохраняется"
            assert "Старый текст команды" not in put["description"]
            expect(page.locator("section.hub-update-preview")).to_have_count(0)
            page.goto(card)
            expect(page.locator("#entered-badge")).to_be_visible()
            # Новое изменение, затем подготовка до перезапуска: пустой diff теперь не создаёт предпросмотр.
            page.goto(f"/projects/{pid}/defects")
            page.locator('#hub-defects tr[data-origin="import"] td[data-label="Заголовок"] a').click()
            open_fields(page); page.locator('#f-stage-value').fill('TEST')
            page.locator('#draft-save').click()
            page.goto(f"/projects/{pid}/defects")
            page.locator('#hub-defects tr[data-origin="import"] form[id^="hub-update-form-"] button').click()
            page.wait_for_url(re.compile(r"ok=hub_update_queued"))
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
        server = restart(tmp_path, fake.url, DEMO_REPOS)  # папка данных та же: замок отпускается, когда устареет
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f"/projects/{pid}/defects")
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_contain_text("читаю дефект №777")
            seen["applied"] = True
            run_worker(server, [hub_for([hub_id], seen)], lambda: expect(
                page.locator("section.hub-update-preview")).to_be_visible(timeout=30000))
            # запись с неизвестным исходом (503) → «Сверить» → в Hub отправленное
            page.locator("section.hub-update-preview form[id^='hub-update-put-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_put_queued"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            jobs = run_worker(server, [hub_for([hub_id], seen, put_status=503)] * 2,
                              lambda: expect(row.locator("form[id^='hub-update-verify-form-'] button")).to_be_visible(
                                  timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777"), ("PUT", "/defects/777")]
            expect(row).to_contain_text("Результат обновления неизвестен")
            row.locator("form[id^='hub-update-verify-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_verify_queued"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            jobs = run_worker(server, [hub_for([hub_id], seen)],
                              lambda: expect(row).to_contain_text("Обновлено в Hub", timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777")]
            assert len(seen["put"]) == 2, "PUT не повторяется: «Сверить» – только чтение"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_release_number_of_a_false_positive_in_the_card(browser, tmp_path):
    """«Снять номер» (ADR-0125, круг 5): у находки сохранили номер при «Подтверждаю дефект», затем решение сменили на
    «Ложное срабатывание» – в шаге 6 видна кнопка «Снять номер ID<n>»; нажатие снимает номер, кнопка пропадает."""
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            run_triage(page, pid)
            open_first_sast(page, pid)
            save_true_positive(page)
            page.fill("#defect-number", "7")
            page.click("#copy-defect-title")
            expect(page.locator("#defect-status")).not_to_be_empty(timeout=30000)
            page.reload()
            expect(page.locator("#defect-number-hint")).to_contain_text("Номер сохранён")
            page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
            page.fill("#comment", "Значение не из запроса пользователя.")
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            button = page.locator("#defect-number-release")
            expect(button).to_be_visible()
            expect(button).to_have_text("Снять номер ID7")
            button.click()
            page.wait_for_url(re.compile(r"ok=defect_number_released(?:&|#|$)"))
            expect(page.locator("p.flash-ok")).to_contain_text("Номер дефекта снят: находка – ложное срабатывание")
            expect(page.locator("#defect-number-release")).to_have_count(0)
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
