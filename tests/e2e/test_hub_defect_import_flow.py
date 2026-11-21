"""«Занести из Hub» и «Pull из Hub» (ADR-0124) в браузере: адрес Hub и номер приложения заданы, во вкладке «Дефекты»
номер дефекта Hub – «Занести из Hub»; поддельный исполнитель в потоке теста отвечает на чтение `GET /defects/{id}` –
вкладка сама перезагружается и показывает предпросмотр (заголовок, номер ID, текст команды, находки); «Отменить» –
строки нет; занесение заново – «Занести»: строка «создан» с пометкой «занесён из Hub», карточка находки – «Дефект №…
(ID<n>), занесён из Hub»; «Pull из Hub» – предпросмотр добавления, «Применить» – находка добавлена. Чтение,
поставленное до перезапуска приложения, доводится после него. Только чтения: исполнитель получает лишь
`GET /defects/{id}`. Hub, номера и учётные данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_REPOS, create_demo, make_fake_ollama, open_page, start_app, stop_app  # noqa: E402
from test_hub_status_card import APP_ID, set_hub, start_worker  # noqa: E402
from test_stored_code_snapshots import restart  # noqa: E402

pytestmark = pytest.mark.e2e

DESCRIPTION = ("<p>После анализа команда Платформа приняла решение.<br><br>Обоснование:<br>owner из запроса "
               "подставляется в SQL-запрос.<br><br>Рекомендация:<br>1) Параметризовать запрос.</p>"
               "<p>Информация об объекте сканирования:</p><p>файл, строка, ветка</p>")


def sast_ids(page, pid: int, count: int = 2) -> list[tuple[str, str]]:
    """(номер находки Hub, адрес карточки) первых находок SAST демо-проекта – из списка и полосы шагов карточки."""
    page.goto(f"/projects/{pid}/findings?kind=SAST")
    links = page.locator('table tbody a[href*="/findings/"]')
    urls: list[str] = []
    for i in range(links.count()):
        href = (links.nth(i).get_attribute("href") or "").split("?")[0].split("#")[0]
        if href and href not in urls:
            urls.append(href)
        if len(urls) == count:
            break
    out = []
    for url in urls:
        page.goto(url)
        out.append((page.locator("#route-id").inner_text().strip(), url))
    return out


def defect_answer(defect_id: int, links: list[str], summary: str = "ID5 - Внедрение SQL-кода (SAST)"):
    """Ответ поддельного Hub на чтение дефекта: только `GET /defects/{defect_id}`."""
    def answer(job: dict) -> tuple[int, str]:
        assert job["method"] == "GET" and job["path"] == f"/defects/{defect_id}", job
        return 200, json.dumps({"id": defect_id, "appId": int(APP_ID), "summary": summary, "description": DESCRIPTION,
                                "linkedIssues": [{"id": int(i), "type": "SAST"} for i in links]}, ensure_ascii=False)
    return answer


def import_number(page, number: str) -> None:
    """Подготовка: строка «занесён из Hub» прежним путём. Формы номеров на вкладке нет с 0.10.0.dev13 (дефекты Hub заносит
    синхронизация), маршрут остаётся для прежних строк – браузер отправляет ту же форму со страницы вкладки."""
    page.evaluate("""number => {
        const form = document.createElement('form');
        form.method = 'post';
        form.action = location.pathname.replace(/\\/$/, '') + '/import';
        const field = document.createElement('input');
        field.type = 'hidden'; field.name = 'numbers'; field.value = number;
        form.appendChild(field); document.body.appendChild(form); form.submit();
    }""", number)
    page.wait_for_url(re.compile(r"/defects\?ok=hub_import_queued"))


def test_import_cancel_accept_sync_and_restart(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            (first, first_url), (second, _) = sast_ids(page, pid)
            page.goto(f"/projects/{pid}/defects")
            expect(page.locator("#hub-import-form")).to_have_count(0)  # формы номеров нет с 0.10.0.dev13
            # занесение – предпросмотр – «Отменить»
            import_number(page, "777")
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_have_attribute("data-state", "import_reading")
            stop, jobs, thread = start_worker(server, [defect_answer(777, [first])])
            try:
                expect(page.locator("section.hub-import-preview")).to_be_visible(timeout=30000)  # вкладка обновилась
            finally:
                stop.set()
                thread.join(timeout=30)
            preview = page.locator("section.hub-import-preview")
            expect(preview).to_contain_text("ID5 - Внедрение SQL-кода (SAST)")
            expect(preview.locator("pre.hub-text")).to_contain_text("Рекомендация:")
            expect(preview.locator("[id^='hub-import-accepted-']")).to_contain_text(first)
            preview.locator("form[id^='hub-import-cancel-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_import_cancelled"))
            expect(page.locator("section.hub-import-preview")).to_have_count(0)
            expect(page.locator('#hub-defects tr[data-origin="import"]')).to_have_count(0)
            # занесение заново – «Занести»
            import_number(page, "777")
            stop, jobs2, thread = start_worker(server, [defect_answer(777, [first])])
            try:
                expect(page.locator("form[id^='hub-import-accept-form-'] button")).to_be_visible(timeout=30000)
            finally:
                stop.set()
                thread.join(timeout=30)
            page.locator("form[id^='hub-import-accept-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_import_done"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_have_attribute("data-state", "done")
            expect(row).to_contain_text("занесён из Hub")
            expect(row).to_contain_text("ID5")
            expect(row.locator(f'a[href="{first_url}"]')).to_be_visible()
            expect(row.locator("[id^='hub-defect-recheck-']")).to_have_count(0)
            page.goto(first_url)
            expect(page.locator("#hub-defect-done")).to_contain_text("№777")
            expect(page.locator("#hub-defect-done")).to_contain_text("ID5")
            expect(page.locator("#hub-defect-done")).to_contain_text("занесён из Hub")
            expect(page.locator("#entered-badge")).to_be_hidden()  # отметки «Внесено в Hub» занесение не ставит
            # «Pull из Hub» – предпросмотр добавления, «Применить»
            page.goto(f"/projects/{pid}/defects")
            page.locator("form[id^='hub-sync-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_sync_queued"))
            stop, jobs3, thread = start_worker(server, [defect_answer(777, [first, second])])
            try:
                expect(page.locator("section.hub-sync-preview")).to_be_visible(timeout=30000)
            finally:
                stop.set()
                thread.join(timeout=30)
            expect(page.locator("[id^='hub-sync-added-']")).to_contain_text(second)
            page.locator("form[id^='hub-sync-apply-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_sync_applied"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_have_attribute("data-state", "done")
            expect(row).to_contain_text(second)
            expect(page.locator("section.hub-sync-preview")).to_have_count(0)
            # чтение, поставленное до перезапуска, – доводится после него
            import_number(page, "778")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
        for got in (jobs, jobs2, jobs3):
            assert [(j["method"], j["path"]) for j in got] == [("GET", "/defects/777")], got
        server = restart(tmp_path, fake.url, DEMO_REPOS)  # папка данных та же: замок отпускается, когда устареет
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f"/projects/{pid}/defects")
            expect(page.locator('#hub-defects tr[data-origin="import"][data-state="import_reading"]')).to_have_count(1)
            stop, jobs4, thread = start_worker(server, [defect_answer(778, [], summary="ID6 - Без находок (SAST)")])
            try:
                expect(page.locator("section.hub-import-preview")).to_be_visible(timeout=30000)
            finally:
                stop.set()
                thread.join(timeout=30)
            assert [(j["method"], j["path"]) for j in jobs4] == [("GET", "/defects/778")]
            expect(page.locator("section.hub-import-preview")).to_contain_text("ID6 - Без находок (SAST)")
            expect(page.locator('#hub-defects tr[data-origin="import"][data-state="done"]')).to_have_count(1)
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
