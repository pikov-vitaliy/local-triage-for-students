"""Операторский цикл в браузере: черновик, справочник, независимые вкладки и сохранение."""
import re
import time
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

pytest.importorskip('playwright.sync_api')
from playwright.sync_api import expect
from e2e_support import create_demo, no_horizontal_scroll

pytestmark = pytest.mark.e2e


def first_component(page, pid):
    page.goto(f'/projects/{pid}/components?sort=name_desc&page_size=25')
    page.locator('a[data-row-link]').first.click()
    page.wait_for_url(re.compile(r'/components/[^/?]+\?'))
    return page.url


def test_operator_cycle_draft_survives_reload_and_reference_return(ui):
    page, _ = ui
    pid = create_demo(page)
    card = first_component(page, pid)
    queue = page.get_by_role('link', name='К списку', exact=True).get_attribute('href')
    page.select_option('#decision-action', 'keep')
    page.fill('#decision-rationale', 'Черновик: сверить условия использования.')
    page.reload()
    expect(page.locator('#decision-rationale')).to_have_value('Черновик: сверить условия использования.')
    expect(page.locator('#component-draft-status')).to_contain_text('не сохранён')
    page.locator('.topbar-actions').get_by_role('link', name='CWE', exact=True).click()
    expect(page.locator('#task-context')).to_be_visible()
    page.locator('#task-origin').click()
    page.wait_for_url(re.compile(r'/components/[^/?]+\?'))
    assert unquote(urlsplit(page.url).path) == unquote(urlsplit(card).path)
    assert parse_qs(urlsplit(page.url).query) == parse_qs(urlsplit(card).query)
    expect(page.locator('#decision-rationale')).to_have_value('Черновик: сверить условия использования.')
    page.click('#save-component-decision')
    expect(page.locator('.component-current-decision')).to_contain_text('Черновик: сверить условия использования.')
    page.reload()
    expect(page.locator('#component-draft-status')).not_to_contain_text('восстановлен')
    page.get_by_role('link', name='К списку', exact=True).click()
    expect(page).to_have_url(re.compile(re.escape(queue) + '$'))
    assert 'sort=name_desc' in page.url


def test_operator_cycle_tabs_keep_independent_drafts_and_warn_on_new_revision(ui):
    page, _ = ui
    pid = create_demo(page)
    card = first_component(page, pid)
    page.select_option('#decision-action', 'keep')
    page.fill('#decision-rationale', 'Первая вкладка: ещё исследую.')
    other = page.context.new_page()
    try:
        other.goto(card)
        other.select_option('#decision-action', 'investigate')
        other.fill('#decision-rationale', 'Вторая вкладка: дополнительные сведения.')
        other.reload()
        expect(other.locator('#decision-rationale')).to_have_value('Вторая вкладка: дополнительные сведения.')
        page.reload()
        expect(page.locator('#decision-rationale')).to_have_value('Первая вкладка: ещё исследую.')
        other.click('#save-component-decision')
        expect(other.locator('.component-current-decision')).to_contain_text('Вторая вкладка')
        page.reload()
        expect(page.locator('#decision-rationale')).to_have_value('Первая вкладка: ещё исследую.')
        expect(page.locator('#component-draft-check')).to_be_visible()
        expect(page.locator('#save-component-decision')).to_be_disabled()
        page.reload()
        expect(page.locator('#component-draft-check')).to_be_visible()
        expect(page.locator('#save-component-decision')).to_be_disabled()
        page.check('#component-draft-confirm')
        expect(page.locator('#save-component-decision')).to_be_enabled()
        page.click('#discard-component-draft')
        expect(page.locator('#decision-rationale')).to_have_value('Вторая вкладка: дополнительные сведения.')
    finally:
        other.close()


def test_operator_cycle_late_edit_is_kept_after_save_response(ui):
    page, _ = ui
    pid = create_demo(page)
    first_component(page, pid)
    page.select_option('#decision-action', 'keep')
    page.fill('#decision-rationale', 'Отправленное обоснование.')

    def reply_after_edit(route):
        response = route.fetch()
        page.fill('#decision-rationale', 'Новая правка, пока сохранялось.')
        route.fulfill(response=response)

    pattern = re.compile(r'/components/[^/]+/decision(?:\?|$)')
    page.route(pattern, reply_after_edit)
    page.click('#save-component-decision')
    expect(page.locator('#component-draft-status')).to_contain_text('новые правки')
    page.unroute(pattern, reply_after_edit)
    page.reload()
    expect(page.locator('#decision-rationale')).to_have_value('Новая правка, пока сохранялось.')
    expect(page.locator('.component-current-decision')).to_contain_text('Отправленное обоснование.')
    for width in (1440, 390):
        page.set_viewport_size({'width': width, 'height': 950})
        no_horizontal_scroll(page)


def test_operator_cycle_reference_chain_and_returned_row(ui, tmp_path):
    from feed_fixtures import CWE_FULL_XML
    from test_feeds import cwe_zip
    from capec_fixtures import capec_zip
    page, _ = ui
    pid = create_demo(page)
    xml = CWE_FULL_XML.replace('ID="2099"', 'ID="89"', 1).replace('CAPEC_ID="209"', 'CAPEC_ID="2099"')
    uploads = [('cwe', cwe_zip(tmp_path / 'cwe.zip', xml).read_bytes()), ('capec', capec_zip())]
    for kind, payload in uploads:
        endpoint = urlsplit(page.url)
        result = page.request.post(f'/feeds/{kind}', headers={'Origin': endpoint.scheme + '://' + endpoint.netloc}, multipart={'file': {
            'name': kind + '.zip', 'mimeType': 'application/zip', 'buffer': payload}})
        assert result.ok
        for _ in range(100):
            job = page.request.get('/feeds/job').json()
            if job['done']:
                assert job['state'] == 'done'; break
            time.sleep(.05)
        else:
            raise AssertionError('Фид не загрузился')
    queue = f'/projects/{pid}/findings?kind=SAST&sort=severity_asc&page_size=25'
    page.goto(queue)
    row = page.locator('tbody tr').filter(has_text='CWE-89').first
    row.locator('a[href*="/findings/"]').first.click()
    source_path = urlsplit(page.url).path
    page.fill('#comment', 'Черновик находки: сверить условия.')
    page.reload()
    expect(page.locator('#comment')).to_have_value('Черновик находки: сверить условия.')
    page.locator("#cwe-info summary").click()  # справка по классу слабости в шаге 3 свёрнута
    page.locator('#cwe-info a[href*="/cwe/CWE-89"]').first.click()
    page.locator('a[href*="/capec/CAPEC-2099"]').first.click()
    page.locator('a[href*="/capec/CAPEC-2100"]').first.click()
    expect(page.locator('#task-context')).to_be_visible()
    page.click('#task-origin')
    assert urlsplit(page.url).path == source_path
    expect(page.locator('#comment')).to_have_value('Черновик находки: сверить условия.')
    page.get_by_role('link', name='К списку находок', exact=False).click()
    expect(page.locator('tr.is-returned')).to_have_count(1)
    assert 'sort=severity_asc' in page.url


def test_operator_cycle_return_links_work_without_javascript(browser, app_server):
    context = browser.new_context(base_url=app_server.url, java_script_enabled=False)
    try:
        page = context.new_page()
        pid = create_demo(page)
        source = first_component(page, pid)
        page.locator('.topbar-actions').get_by_role('link', name='CWE', exact=True).click()
        expect(page.locator('#task-context')).to_be_visible()
        page.click('#task-origin')
        assert unquote(urlsplit(page.url).path) == unquote(urlsplit(source).path)
        page.get_by_role('link', name='К списку', exact=True).click()
        assert parse_qs(urlsplit(page.url).query)['sort'] == ['name_desc']
    finally:
        context.close()
