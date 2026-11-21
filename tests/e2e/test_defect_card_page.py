"""Карточка дефекта: заголовок вкладки, сборка, ручная правка, сохранение, PUT через поддельного исполнителя."""

import re

import pytest
from playwright.sync_api import expect

from e2e_support import open_fields, create_demo, make_fake_ollama, open_page, run_triage, start_app, stop_app
from test_hub_defect_card import save_true_positive
from test_hub_defect_import_flow import import_number
from test_hub_defect_import_flow import sast_ids
from test_hub_defect_update_flow import defect, hub_for, run_worker
from test_hub_status_card import open_first_sast, set_hub

pytestmark = pytest.mark.e2e


def test_unsaved_defect_fields_warn_on_leave_reload_and_action(browser, tmp_path):
    """AUD-03: настоящий beforeunload Chrome, отмена действия и сохранение без лишнего диалога."""
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url, accept_dialogs=False)
        dialogs = []
        allow = False

        def respond(dialog):
            dialogs.append(dialog.type)
            dialog.accept() if allow else dialog.dismiss()

        page.on("dialog", respond)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            hub_id, _ = sast_ids(page, pid, 1)[0]
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            run_worker(server, [hub_for([hub_id], {})], lambda: expect(
                page.locator('form[id^=hub-import-accept-form-] button')).to_be_visible(timeout=30000))
            page.locator('form[id^=hub-import-accept-form-] button').click()
            page.wait_for_url(re.compile('ok=hub_import_done'))
            page.locator('td[data-label="Заголовок"] a').click()
            card_url = page.url
            original = page.locator('#draft-command-text').input_value()
            page.locator('#draft-command-text').fill(original + ' Несохранённый ввод.')
            page.get_by_role('link', name='Дефекты', exact=True).first.click(no_wait_after=True)
            expect(page.locator('#draft-command-text')).to_have_value(original + ' Несохранённый ввод.')
            assert dialogs == ['beforeunload'] and page.url == card_url
            page.locator('#defect-update-prepare').click()
            assert dialogs == ['beforeunload', 'confirm']
            expect(page.locator('#draft-dirty-note')).to_be_visible()
            # Уход подтверждён оператором: reload предупреждает и возвращает сохранённый текст.
            allow = True
            page.reload()
            assert dialogs[-1] == 'beforeunload' and len(dialogs) == 3
            expect(page.locator('#draft-command-text')).to_have_value(original)
            # Нетекстовые поля также защищены; успешный POST сохранения не предупреждает.
            allow = False
            open_fields(page); page.locator('#f-stage-value').fill('LOCAL')
            # находка принятого из Hub дефекта получает решение «из Hub» без обоснования оператора (dev23, 01.11):
            # сборка текста недоступна, карточка называет причину
            expect(page.get_by_role('button', name='Собрать текст из решений')).to_be_disabled()
            expect(page.locator('#defect-generate-blocked')).to_contain_text('решение принято из Hub')
            page.locator('#defect-update-prepare').click()
            assert dialogs[-1] == 'confirm' and len(dialogs) == 4
            with page.expect_navigation():
                page.locator('#draft-save').click()
            expect(page.locator('#f-stage-value')).to_have_value('LOCAL')
            expect(page.locator('#draft-dirty-note')).to_be_hidden()
            page.reload()
            assert len(dialogs) == 4
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_defect_card_edit_and_update(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        seen = {}
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            run_triage(page, pid)
            open_first_sast(page, pid)
            hub_id = page.locator("#route-id").inner_text().strip()
            save_true_positive(page)
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            run_worker(server, [hub_for([hub_id], seen)], lambda: expect(
                page.locator("form[id^='hub-import-accept-form-'] button")).to_be_visible(timeout=30000))
            page.locator("form[id^='hub-import-accept-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_import_done"))
            page.locator('#hub-defects td[data-label="Заголовок"] a').click()
            page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
            page.get_by_role("button", name="Собрать текст из решений").click()
            expect(page.locator("#draft-command-text")).to_contain_text("Обоснование:")
            command = page.locator("#draft-command-text").input_value().replace("Обоснование:", "Обоснование:\nДополнение оператора.")
            summary = "ID5 - Ручной заголовок (SAST)"
            page.locator("#draft-summary").fill(summary)
            page.locator("#draft-command-text").fill(command)
            page.get_by_role("button", name="Сохранить черновик").click()
            expect(page.locator("#draft-command-text")).to_have_value(command)
            page.locator('#defect-update-prepare').click()
            run_worker(server, [hub_for([hub_id], seen)], lambda: expect(
                page.locator("section.hub-update-preview")).to_be_visible(timeout=30000))
            page.get_by_role("button", name="Push в Hub", exact=True).click()
            jobs = run_worker(server, [hub_for([hub_id], seen)] * 3, lambda: expect(
                page.locator("#hub-defect-status")).to_contain_text("Обновлено в Hub", timeout=30000))
            assert [j["method"] for j in jobs] == ["GET", "PUT", "GET"]
            assert len(seen["put"]) == 1
            put = seen["put"][0]
            assert put["summary"] == summary and "Дополнение оператора." in put["description"]
            # dev30: блок Hub из описания сохраняется следом за новым текстом
            hub_description = defect([hub_id])["description"]
            at = hub_description.find("Информация об объекте сканирования")
            assert at > 0 and put["description"].endswith(hub_description[hub_description.rfind("<", 0, at):]), put["description"]
            assert {k: v for k, v in put.items() if k not in ("summary", "description")} == {
                k: v for k, v in defect([hub_id]).items() if k not in ("summary", "description")}
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
