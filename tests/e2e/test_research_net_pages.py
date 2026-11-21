"""Страницы исследования провайдером в Chrome (B4): блок на «Компонентах», предпросмотр с согласием, страница хода
получения обновляется без перезагрузки – без ошибок скриптов и консоли, без горизонтальной прокрутки. Поддельный
сервер API чат-завершений на этом компьютере."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, no_horizontal_scroll
from fake_chat_api import FakeChatApi

pytestmark = pytest.mark.e2e


def test_research_pages_work_without_script_errors(ui):
    page, watch = ui
    pid = create_demo(page)
    with FakeChatApi(models=["flash-model"]) as fake:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Исследователь e2e")
        page.check('input[name="kind"][value="chat_completions"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', fake.url)
        page.fill('input[name="default_model"]', "flash-model")
        page.locator("#provider-chat > summary").click()
        page.check('input[name="search_on"]')
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        page.goto(f"/projects/{pid}/components")
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        page.locator("#component-research > summary").click()
        value = page.locator("#research-provider option", has_text="Исследователь e2e").get_attribute("value")
        page.select_option("#research-provider", value)
        page.wait_for_url(re.compile(r"ok=research_provider_saved"))
        # панель помнит состояние (data-remember) и может оказаться свёрнутой: раскрываем, пока кнопка не видна
        for _ in range(3):
            if page.locator("#research-preview").is_visible():
                break
            page.locator("#component-research > summary").click()
            page.wait_for_timeout(200)
        expect(page.locator("#research-preview")).to_be_visible()
        page.select_option('#research-preview-form select[name="selection"]', "all")
        page.click("#research-preview")
        page.wait_for_url(re.compile(r"/components/research/preview$"))
        expect(page.locator("#research-first")).to_contain_text("cutoff_date")
        expect(page.locator("#research-start")).to_be_visible()
        assert no_horizontal_scroll(page)
        # строки задания демо – сервер отвечает «не JSON»: получение завершится с «не получена», страница хода жива
        fake.default_answer = "это не JSON"
        page.check("#research-confirm")
        page.click("#research-start")
        page.wait_for_url(re.compile(r"/components/research/\d+$"))
        # страница, открытая во время получения, один раз перезагружается по его концу – ждём кнопку доисследования
        expect(page.locator("#research-requeue")).to_be_visible(timeout=60000)
        expect(page.locator("#run-state")).to_have_text("завершено")
        expect(page.locator("#research-rows [data-state]").first).to_have_text("не получена")
        page.wait_for_load_state()
        assert no_horizontal_scroll(page)
        assert not watch.problems(), watch.problems()


def test_stopped_run_page_resumes_polling_after_resume_in_another_tab(ui, browser):
    """П. 26 (ревью 0.9.17): страница остановленного получения после «Продолжить» из другой вкладки при возврате во
    вкладку снова опрашивает сервер – состояние доходит до «завершено», прежняя причина остановки скрыта."""
    import time
    page, watch = ui
    pid = create_demo(page)
    with FakeChatApi(models=["flash-model"]) as fake:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Исследователь e2e 2")
        page.check('input[name="kind"][value="chat_completions"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', fake.url)
        page.fill('input[name="default_model"]', "flash-model")
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        page.goto(f"/projects/{pid}/components")
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        page.locator("#component-research > summary").click()
        value = page.locator("#research-provider option", has_text="Исследователь e2e 2").get_attribute("value")
        page.select_option("#research-provider", value)
        page.wait_for_url(re.compile(r"ok=research_provider_saved"))
        for _ in range(3):
            if page.locator("#research-preview").is_visible():
                break
            page.locator("#component-research > summary").click()
            page.wait_for_timeout(200)
        page.select_option('#research-preview-form select[name="selection"]', "all")
        page.click("#research-preview")
        page.wait_for_url(re.compile(r"/components/research/preview$"))

        import threading
        hold, release = threading.Event(), threading.Event()

        def slow(_body):
            # до «Продолжить» – медленные ходы (есть время нажать «Остановить»); после него (hold) каждый ход ждёт
            # барьера release: получение не может завершиться, пока вкладка не увидела «идёт» и не восстановила опрос
            if hold.is_set():
                release.wait(60)
            else:
                time.sleep(2.0)
            return "это не JSON"
        fake.default_answer = slow
        try:
            page.check("#research-confirm")
            page.click("#research-start")
            page.wait_for_url(re.compile(r"/components/research/\d+$"))
            run_url = page.url
            page.click("#research-stop")
            page.wait_for_url(re.compile(r"/components/research/\d+"))
            expect(page.locator("#run-state")).to_have_text("остановлено", timeout=30000)
            expect(page.locator("#run-reason")).to_be_visible()
            # опрос этой вкладки уже увидел остановку и снял таймер (data-polling – наблюдаемое состояние опроса)
            expect(page.locator("#research-run[data-polling='0']")).to_have_count(1, timeout=15000)
            hold.set()
            other = page.context.new_page()
            other.goto(run_url)
            other.click("#research-resume")
            other.wait_for_url(re.compile(r"/components/research/\d+"))
            other.close()
            # возврат во вкладку: один опрос по visibilitychange показывает «идёт» и восстанавливает таймер; «завершено»
            # приходит уже следующими периодическими опросами, без нового события видимости
            page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
            expect(page.locator("#run-state")).to_have_text("идёт", timeout=15000)
            expect(page.locator("#research-run[data-polling='1']")).to_have_count(1), "таймер опроса восстановлен"
            expect(page.locator("#run-reason")).to_be_hidden()
            # следующий периодический опрос (без нового события видимости) должен сам дойти до сервера: ждём его запрос
            before = len([u for u in watch.requests if u.endswith("/status")])
            for _ in range(150):
                if len([u for u in watch.requests if u.endswith("/status")]) > before:
                    break
                page.wait_for_timeout(100)
            assert len([u for u in watch.requests if u.endswith("/status")]) > before, "периодический опрос не возобновился"
            release.set()  # барьер снят – получение завершается, страница видит это очередным опросом
            expect(page.locator("#run-state")).to_have_text("завершено", timeout=120000)
            expect(page.locator("#research-run[data-polling='0']")).to_have_count(1, timeout=15000)
            assert not watch.problems(), watch.problems()
        finally:
            release.set()  # барьер снимается и при падении проверки: ходы модели не ждут 60 с


def test_marked_components_go_to_the_research_preview(ui):
    """0.10.0.dev24: галочки в таблице компонентов и кнопка «Исследовать отмеченные провайдером» – в предпросмотре
    только отмеченные строки; выбор «без дефекта» есть в списке. Без ошибок скриптов и горизонтальной прокрутки."""
    page, watch = ui
    pid = create_demo(page)
    with FakeChatApi(models=["flash-model"]) as fake:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Исследователь отметок e2e")
        page.check('input[name="kind"][value="chat_completions"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', fake.url)
        page.fill('input[name="default_model"]', "flash-model")
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        page.goto(f"/projects/{pid}/components")
        expect(page.locator("#research-picked")).to_have_count(0)  # без задания и профиля отметок нет
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        page.locator("#component-research > summary").click()
        value = page.locator("#research-provider option", has_text="Исследователь отметок e2e").get_attribute("value")
        page.select_option("#research-provider", value)
        page.wait_for_url(re.compile(r"ok=research_provider_saved"))
        expect(page.locator('#research-preview-form select[name="selection"] option[value="no_defect"]')).to_have_count(1)
        boxes = page.locator('#batch-selection input[name="input_ref"]')
        assert boxes.count() >= 2
        boxes.nth(0).check()
        boxes.nth(1).check()
        assert no_horizontal_scroll(page)
        page.click("#research-picked")
        page.wait_for_url(re.compile(r"/components/research/preview$"))
        expect(page.locator("#rows-title")).to_have_text(re.compile(r"отмеченные в таблице \(2\)"))
        expect(page.locator('#research-consent input[name="input_ref"]')).to_have_count(2)
        expect(page.locator("#research-start")).to_be_visible()
        assert no_horizontal_scroll(page)
        assert fake.chats() == []
        assert not watch.problems(), watch.problems()


def test_component_card_button_opens_the_preview_of_one_row(ui):
    """0.10.0.dev26: кнопка «Исследовать провайдером – предпросмотр» в карточке компонента ведёт к предпросмотру одной
    строки. Без ошибок скриптов и горизонтальной прокрутки."""
    page, watch = ui
    pid = create_demo(page)
    with FakeChatApi(models=["flash-model"]) as fake:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Исследователь карточки e2e")
        page.check('input[name="kind"][value="chat_completions"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', fake.url)
        page.fill('input[name="default_model"]', "flash-model")
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        page.goto(f"/projects/{pid}/components")
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        page.locator("#component-research > summary").click()
        value = page.locator("#research-provider option", has_text="Исследователь карточки e2e").get_attribute("value")
        page.select_option("#research-provider", value)
        page.wait_for_url(re.compile(r"ok=research_provider_saved"))
        page.locator("a[data-row-link]").first.click()
        page.wait_for_url(re.compile(r"/components/[^/?]+"))
        expect(page.locator("#research-one")).to_be_visible()
        assert no_horizontal_scroll(page)
        page.click("#research-one")
        page.wait_for_url(re.compile(r"/components/research/preview$"))
        expect(page.locator("#rows-title")).to_have_text(re.compile(r"отмеченные в таблице \(1\)"))
        expect(page.locator('#research-consent input[name="input_ref"]')).to_have_count(1)
        assert fake.chats() == []
        assert not watch.problems(), watch.problems()
