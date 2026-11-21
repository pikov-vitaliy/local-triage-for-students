"""Круг 1: присутствие свойств, старая вкладка и принятое предупреждение о номере."""

import json
import re

import pytest
from playwright.sync_api import expect

from e2e_support import open_fields, create_demo, make_fake_ollama, open_page, run_triage, start_app, stop_app
from test_hub_defect_card import save_true_positive
from test_hub_defect_import_flow import import_number, sast_ids
from test_hub_defect_update_flow import defect, run_worker
from test_hub_status_card import open_first_sast, set_hub

pytestmark = pytest.mark.e2e


def import_card(page, server, pid, body):
    page.goto(f"/projects/{pid}/defects")
    expect(page.get_by_text('Остальные поля доступны только для чтения.', exact=False)).to_have_count(0)
    expect(page.get_by_text('Связанные справочные значения можно менять только при наличии проверенного соответствия.',
                            exact=False)).to_be_visible()
    import_number(page, "777")
    run_worker(server, [lambda job: (200, json.dumps(body))], lambda: expect(
        page.locator('form[id^=hub-import-accept-form-] button')).to_be_visible(timeout=30000))
    page.locator('form[id^=hub-import-accept-form-] button').click()
    page.wait_for_url(re.compile('ok=hub_import_done'))
    page.locator('td[data-label="Заголовок"] a').click()


def test_round1_external_presence_false_and_put(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            run_triage(page, pid)
            open_first_sast(page, pid)
            hub_id = page.locator('#route-id').inner_text().strip()
            save_true_positive(page)
            body = defect([hub_id], isActive=True, externalBugs=[{"product": "one", "link": "old", "extension": {"x": False}}])
            import_card(page, server, pid, body)
            page.get_by_role('button', name='Собрать текст из решений').click()
            open_fields(page); page.locator('[name=bug_0_link_mode]').select_option('remove')
            open_fields(page); page.locator('[name=f_isActive_value]').select_option('false')
            page.locator('#draft-save').click()
            page.reload()
            expect(page.locator('[name=f_isActive_value]')).to_have_value('false')
            open_fields(page)
            active = json.loads(page.locator('[data-defect-field=isActive] > p.small code').inner_text())
            assert 'isActive' in active and active['isActive'] is False
            bugs = json.loads(page.locator('[data-defect-field=externalBugs] > p.small code').inner_text())['externalBugs']
            assert bugs == [{"product": "one", "extension": {"x": False}}]
            sent = []

            def answer(job):
                if job['method'] == 'PUT':
                    sent.append(job['body'])
                    return 204, ''
                assert job['method'] == 'GET'
                return 200, json.dumps(sent[-1] if sent else body)

            page.goto(f"/projects/{pid}/defects")
            page.locator('form[id^=hub-update-form-] button').click()
            run_worker(server, [answer], lambda: expect(page.locator('section.hub-update-preview')).to_be_visible(timeout=30000))
            page.locator('form[id^=hub-update-put-form-] button').click()
            jobs = run_worker(server, [answer] * 3, lambda: expect(
                page.locator('#hub-defects tr[data-origin=import]')).to_contain_text('Обновлено в Hub', timeout=30000))
            assert [j['method'] for j in jobs] == ['GET', 'PUT', 'GET']
            assert len(sent) == 1 and 'isActive' in sent[0] and sent[0]['isActive'] is False
            assert sent[0]['externalBugs'] == bugs
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_round1_stale_external_rows_never_adopt_new_revision(browser, tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            hub_id, _ = sast_ids(page, pid, 1)[0]
            body = defect([hub_id], externalBugs=[{'product': 'A', 'link': 'a'}, {'product': 'B', 'link': 'b'}])
            import_card(page, server, pid, body)
            card = page.url
            revision = page.locator('#defect-draft-form [name=draft_revision]').input_value()
            other = context.new_page()
            other.goto(card)
            open_fields(other)
            other.locator('.external-bug').last.locator('[data-bug-action=up]').click()
            other.locator('#draft-save').click()
            expect(other.locator('.external-bug').first.locator('input[name$=_product_value]')).to_have_value('B')
            open_fields(page); page.locator('[name=bug_0_link_value]').fill('new-a')
            watch.allowed_errors.append('409 (Conflict)')
            for _ in range(2):
                with page.expect_response(lambda r: r.request.method == 'POST' and r.url.endswith('/fields')) as response:
                    page.locator('#draft-save').click()
                assert response.value.status == 409
                expect(page.locator('#defect-draft-form [name=draft_revision]')).to_have_value(revision)
                expect(page.locator('[name=bug_0_link_value]')).to_have_value('new-a')
            other.reload()
            open_fields(other)
            bugs = json.loads(other.locator('[data-defect-field=externalBugs] > p.small code').inner_text())['externalBugs']
            assert bugs == [{'product': 'B', 'link': 'b'}, {'product': 'A', 'link': 'a'}]
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


@pytest.mark.parametrize('summary', ['Без номера (SAST)', 'ID5 и ID6 (SAST)'])
def test_round1_accepted_number_warning_does_not_repeat_preview(browser, tmp_path, summary):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            hub_id, _ = sast_ids(page, pid, 1)[0]
            body = defect([hub_id], summary=summary, stage='DEV')
            import_card(page, server, pid, body)
            card = page.url
            body['stage'] = 'TEST'
            page.goto(f"/projects/{pid}/defects")
            page.locator('form[id^=hub-sync-form-] button').click()
            answer = lambda job: (200, json.dumps(body))
            run_worker(server, [answer], lambda: expect(page.locator('section.hub-sync-preview')).to_be_visible(timeout=30000))
            page.locator('form[id^=hub-sync-apply-form-] button').click()
            page.wait_for_url(re.compile('ok=hub_sync_applied'))
            page.locator('form[id^=hub-sync-form-] button').click()
            run_worker(server, [answer], lambda: expect(page.locator('[id^=hub-sync-matches-]')).to_be_visible(timeout=30000))
            expect(page.locator('section.hub-sync-preview')).to_have_count(0)
            page.goto(card)
            expect(page.locator('#draft-save')).to_be_enabled()
            open_fields(page); page.locator('#f-source-value').fill('LOCAL')
            page.locator('#draft-save').click()
            expect(page.locator('#f-source-value')).to_have_value('LOCAL')
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
