"""Dev1b: реальные формы, явная загрузка справочников и сверка без пустого предпросмотра."""

import json
import re

import pytest
from playwright.sync_api import expect

from e2e_support import open_more, open_fields, create_demo, make_fake_ollama, open_page, start_app, stop_app
from test_hub_defect_import_flow import import_number, sast_ids
from test_hub_defect_update_flow import defect, run_worker
from test_hub_status_card import APP_ID, set_hub, start_worker
from test_sca_table import make_project

pytestmark = pytest.mark.e2e


def test_dev1b_conflict_versions_still_saves_and_generates_locally(browser, tmp_path):
    from hub_fixtures import SCA_ROWS, make_hub_xlsx
    report = make_hub_xlsx(tmp_path / "versions.xlsx", sast=[], sca=[SCA_ROWS[0], {**SCA_ROWS[1], "Component version": "2.0.0"}])
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = make_project(page, report)
            set_hub(page, pid)
            body = defect([], summary="ID5 - example-parser (SCA)", linkedIssues=[
                {"id": 73001, "type": "SCA_S"}, {"id": 73002, "type": "SCA_S"}])
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            jobs = run_worker(server, [lambda job: (200, json.dumps(body))], lambda: expect(
                page.locator('form[id^=hub-import-accept-form-] button')).to_be_visible(timeout=30000))
            assert len(jobs) == 1
            page.locator('form[id^=hub-import-accept-form-] button').click()
            page.wait_for_url(re.compile('ok=hub_import_done'))
            page.locator('td[data-label="Заголовок"] a').click()
            explanation = page.locator('#defect-conflict-explanation')
            expect(explanation).to_contain_text('1.4.2')
            expect(explanation).to_contain_text('2.0.0')
            expect(explanation).to_contain_text('В Hub уберите из связи')
            expect(page.locator('#defect-update-prepare')).to_have_count(0)
            page.locator('#draft-command-text').fill('Локальная правка при конфликте')
            open_fields(page); page.locator('#f-stage-value').fill('LOCAL')
            page.locator('#draft-save').click()
            expect(page.locator('#draft-command-text')).to_have_value('Локальная правка при конфликте')
            page.get_by_role('button', name='Собрать текст из решений').click()
            expect(page.locator('#draft-command-text')).to_have_value(re.compile(r'1\.4\.2[\s\S]+2\.0\.0'))
            expect(page.locator('#f-stage-value')).to_have_value('LOCAL')
            expect(explanation).to_be_visible()
            expect(page.get_by_role('button', name='Push в Hub', exact=True)).to_have_count(0)
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_dev1b_fields_references_and_no_difference_sync(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            hub_id, _ = sast_ids(page, pid, 1)[0]
            body = defect([hub_id], stage="DEV", externalBugs=[{"product": "first", "extension": 4}, {"product": "second"}])
            def answer(job):
                assert job["method"] == "GET" and job["path"] == "/defects/777"
                return 200, json.dumps(body)
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            run_worker(server, [answer], lambda: expect(page.locator("form[id^=hub-import-accept-form-] button")).to_be_visible(timeout=30000))
            page.locator("form[id^=hub-import-accept-form-] button").click()
            page.wait_for_url(re.compile("ok=hub_import_done"))
            page.locator('td[data-label="Заголовок"] a').click()
            card = page.url
            # Форма изменения значений; отсутствие, false и пустая строка не смешиваются.
            open_fields(page); page.locator('#f-source-value').fill('локально')
            open_fields(page); page.locator('#f-dueDate-value').fill('2026-11-10T18:02:03.250+02:30')
            open_fields(page); page.locator('[name=f_isActive_value]').select_option('false')
            open_fields(page); page.locator('[name=setting_isInheritedARStatusFromDefect]').select_option('false')
            open_fields(page); page.locator('.external-bug').last.locator('[data-bug-action=up]').click()
            page.locator('#draft-save').click()
            expect(page.locator('#f-source-value')).to_have_value('локально')
            expect(page.locator('#f-dueDate-value')).to_have_value('2026-11-10T18:02:03.250+02:30')
            expect(page.locator('.external-bug').first.locator('input[name$=_product_value]')).to_have_value('second')
            expect(page.locator('[name=f_isActive_value]')).to_have_value('false')
            open_fields(page); assert json.loads(page.locator('[data-defect-field=isActive] > p.small code').inner_text()) == {"isActive": False}
            # Подтверждение справочников: отмена не создаёт операций, повторное открытие тоже.
            open_more(page); page.get_by_role('button', name='Загрузить справочники').click()
            expect(page.get_by_text('Подтверждение поставит ровно три чтения исполнителю.')).to_be_visible()
            page.get_by_role('button', name='Отменить', exact=True).click()
            page.get_by_role('link', name='Вернуться к черновику').click()
            open_more(page); page.get_by_role('button', name='Загрузить справочники').click()
            page.get_by_role('button', name='Подтвердить загрузку').click()
            bodies = [{"priorities": ["High", "Low"], "statuses": ["Open"]}, [{"id": 11, "name": "Unit"}],
                      {"structureUnits": [{"id": "11", "name": "Unit"}], "releaseObjects": [{"id": "21", "name": "Release"}]}]
            stop, jobs, thread = start_worker(server, [lambda job, b=b: (200, json.dumps(b)) for b in bodies])
            try:
                thread.join(timeout=30)
                assert not thread.is_alive() and len(jobs) == 3
            finally:
                stop.set()
                thread.join(timeout=5)
            assert [j['path'] for j in jobs] == ['/defects/serviceInfo', f'/application/{APP_ID}/structureUnits', f'/releaseObject/filters?appId={APP_ID}']
            assert all(j['app_id'] == int(APP_ID) and j['purpose'] == 'defect_reference' for j in jobs)
            page.reload()
            expect(page.get_by_text('Проверенные варианты')).to_be_visible()
            page.get_by_role('link', name='Вернуться к черновику').click()
            open_fields(page); page.locator('[name=f_structureUnitId_mode]').select_option('set')
            open_fields(page); page.locator('[name=f_structureUnitId_value]').select_option('0')
            open_fields(page); page.locator('[name=f_releaseObject_mode]').select_option('set')
            open_fields(page); page.locator('[name=f_releaseObject_value]').select_option('0')
            page.locator('#draft-save').click()
            expect(page.locator('[data-defect-field=structureUnitId]')).to_contain_text('Unit')
            # Локальная правка не создаёт расхождения Hub с принятой базой.
            page.goto(f"/projects/{pid}/defects")
            page.locator('form[id^=hub-sync-form-] button').click()
            run_worker(server, [answer], lambda: expect(page.locator('[id^=hub-sync-matches-]')).to_be_visible(timeout=30000))
            expect(page.locator('section.hub-sync-preview')).to_have_count(0)
            # Изменился только stage: предпросмотр содержит только этот путь, применение сохраняет source.
            body['stage'] = 'TEST'
            page.locator('form[id^=hub-sync-form-] button').click()
            run_worker(server, [answer], lambda: expect(page.locator('section.hub-sync-preview')).to_be_visible(timeout=30000))
            preview = page.locator('section.hub-sync-preview')
            expect(preview).to_contain_text('/stage')
            expect(preview.locator('[id^=hub-sync-text-]')).to_have_count(0)
            page.locator('form[id^=hub-sync-apply-form-] button').click()
            page.wait_for_url(re.compile('ok=hub_sync_applied'))
            page.locator('form[id^=hub-sync-form-] button').click()
            run_worker(server, [answer], lambda: expect(page.locator('[id^=hub-sync-matches-]')).to_be_visible(timeout=30000))
            expect(page.locator('form[id^=hub-sync-apply-form-]')).to_have_count(0)
            expect(page.locator('form[id^=hub-sync-cancel-form-]')).to_have_count(0)
            # Принятая связь вне выгрузки не вызывает повторного окна; её исчезновение также принимается один раз.
            for remove in (False, True):
                if remove:
                    body['linkedIssues'].pop()
                else:
                    body['linkedIssues'].append({'id': 999001, 'type': 'SAST'})
                page.locator('form[id^=hub-sync-form-] button').click()
                run_worker(server, [answer], lambda: expect(page.locator('section.hub-sync-preview')).to_be_visible(timeout=30000))
                expect(page.locator('section.hub-sync-preview')).to_contain_text('999001')
                page.locator('form[id^=hub-sync-apply-form-] button').click()
                page.wait_for_url(re.compile('ok=hub_sync_applied'))
                page.locator('form[id^=hub-sync-form-] button').click()
                run_worker(server, [answer], lambda: expect(page.locator('[id^=hub-sync-matches-]')).to_be_visible(timeout=30000))
                expect(page.locator('section.hub-sync-preview')).to_have_count(0)
            page.goto(card)
            expect(page.locator('#f-stage-value')).to_have_value('TEST')
            expect(page.locator('#f-source-value')).to_have_value('локально')
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
