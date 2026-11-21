"""Импорт CAPEC и работа с каталогом в настоящем браузере."""
import pytest
from playwright.sync_api import expect
from capec_fixtures import capec_zip, CAPEC_XML
from e2e_support import no_horizontal_scroll, create_demo

pytestmark=pytest.mark.e2e


def test_capec_upload_catalog_and_return(ui,tmp_path):
    page,_=ui
    file=tmp_path/'capec.zip';file.write_bytes(capec_zip())
    page.goto('/feeds')
    page.set_input_files('#feed-capec-file',str(file))
    page.locator('#feed-capec form button[type=submit]').click()
    expect(page.locator('#feed-capec-records')).to_have_text('6',timeout=30000)
    page.goto('/capec?q=CWE-2099')
    expect(page.locator('.worklist-pager')).to_have_count(2)
    page.get_by_role('link',name='CAPEC-2099 · Demo Injection',exact=True).click()
    expect(page.locator('h1')).to_contain_text('CAPEC-2099')
    expect(page.locator('main')).to_contain_text('Observe a test.')
    page.get_by_role('link',name='Назад к результатам',exact=True).click()
    assert 'q=CWE-2099' in page.url
    for width in (390,1440):
        page.set_viewport_size({'width':width,'height':900})
        assert no_horizontal_scroll(page)
    page.goto('/capec?kind=view')
    page.get_by_role('link',name='CAPEC-1000 · Demo Graph',exact=True).click()
    expect(page.locator('main')).to_contain_text('Demo graph view.')
    page.goto('/capec?view=1000')
    expect(page.locator('table tbody')).to_contain_text('Demo Injection')


def test_capec_context_preserves_unsaved_operator_comment(ui, tmp_path):
    page, _ = ui
    file = tmp_path/'capec.zip'
    file.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"','CWE_ID="89"')))
    page.goto('/feeds')
    page.set_input_files('#feed-capec-file',str(file))
    page.locator('#feed-capec form button[type=submit]').click()
    expect(page.locator('#feed-capec-records')).to_have_text('6',timeout=30000)
    pid = create_demo(page)
    page.goto(f'/projects/{pid}/findings?kind=SAST')
    page.locator('table tbody a[href*="/findings/"]').first.click()
    page.locator('#comment').fill('Несохранённый рабочий комментарий оператора')
    page.locator('.capec-context summary').click()
    page.locator('.capec-context a[href^="/capec/CAPEC-2099"]').click()
    expect(page.locator('h1')).to_contain_text('CAPEC-2099')
    page.locator('#task-origin').click()
    expect(page.locator('#comment')).to_have_value('Несохранённый рабочий комментарий оператора')


def test_project_capec_count_opens_visible_source_findings(ui, tmp_path):
    from urllib.parse import parse_qs, urlsplit
    page, _ = ui
    file = tmp_path/'capec.zip'
    file.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"', 'CWE_ID="89"')))
    page.goto('/feeds')
    page.set_input_files('#feed-capec-file', str(file))
    page.locator('#feed-capec form button[type=submit]').click()
    expect(page.locator('#feed-capec-records')).to_have_text('6', timeout=30000)
    pid = create_demo(page)
    page.goto('/')
    page.locator(f'a[href="/projects/{pid}"]').first.click()
    page.get_by_role('link', name='Сценарии CAPEC по находкам проекта', exact=True).click()
    row = page.locator('table tbody tr').filter(has_text='CAPEC-2099')
    count = int(row.locator('td').last.inner_text())
    assert count > 0
    row.locator('td').last.get_by_role('link').click()
    assert parse_qs(urlsplit(page.url).query).get('scenario') == ['CAPEC-2099']
    assert urlsplit(page.url).fragment == 'source-findings'
    heading = page.locator('#source-findings h2')
    expect(heading).to_have_text(f'Исходные находки · CAPEC-2099 · {count}')
    expect(heading).to_be_in_viewport()
    expect(page.locator('#source-findings li')).to_have_count(count)
    for width in (390, 1440):
        page.set_viewport_size({'width': width, 'height': 900})
        assert no_horizontal_scroll(page)
    page.locator('#clear-scenario').click()
    expect(page.locator('#source-findings')).to_have_count(0)
    expect(page.locator('table tbody')).to_contain_text('CAPEC-2099')

    page.goto('/capec?kind=view')
    page.get_by_role('link', name='CAPEC-1000 · Demo Graph', exact=True).click()
    page.get_by_role('link', name='Открыть состав представления', exact=True).click()
    assert parse_qs(urlsplit(page.url).query).get('view') == ['CAPEC-1000']
    expect(page.locator('table tbody')).to_contain_text('Demo Injection')
    expect(page.locator('table tbody')).not_to_contain_text('Retired Demo')


def _capec_shot(page, name):
    import os
    from pathlib import Path
    folder = os.environ.get('E2E_SHOTS')
    if not folder:
        return
    for theme in ('light', 'dark'):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(300)
        page.screenshot(path=str(Path(folder) / f'{name}-{theme}.png'), full_page=False)


def test_project_capec_page_looks_like_the_application(ui, tmp_path):
    """Фильтры, страница и таблица CAPEC – в оформлении приложения: вкладки проекта, основные поля в ряд,
    остальное – «Все фильтры», сортировка заголовками."""
    from urllib.parse import parse_qs, urlsplit
    page, _ = ui
    file = tmp_path/'capec.zip'
    file.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"', 'CWE_ID="89"')))
    page.goto('/feeds')
    page.set_input_files('#feed-capec-file', str(file))
    page.locator('#feed-capec form button[type=submit]').click()
    expect(page.locator('#feed-capec-records')).to_have_text('6', timeout=30000)
    pid = create_demo(page)
    page.set_viewport_size({'width': 1600, 'height': 900})
    page.goto(f'/projects/{pid}/capec')
    expect(page.get_by_role('link', name='Находки').first).to_be_visible()
    expect(page.locator('.crumb-project')).to_be_visible()
    more = page.locator('#capec-filters-more')
    expect(more).not_to_have_attribute('open', '')
    expect(page.locator('select[name=abstraction]')).to_be_hidden()
    expect(page.locator('input[name=q]')).to_be_visible()
    boxes = [page.locator(f'#capec-filters [name={name}]').bounding_box() for name in ('q', 'kind', 'severity', 'cwe')]
    assert max(b['y'] for b in boxes) - min(b['y'] for b in boxes) <= 2 and max(b['height'] for b in boxes) - min(b['height'] for b in boxes) <= 2, boxes
    assert no_horizontal_scroll(page)
    _capec_shot(page, 'capec-closed')
    more.locator('summary').click()
    expect(page.locator('select[name=abstraction]')).to_be_visible()
    expect(page.locator('select[name=finding_kind]')).to_be_visible()
    _capec_shot(page, 'capec-open')
    page.locator('select[name=abstraction]').select_option(index=1)
    page.locator('#capec-filters button[type=submit]').click()
    expect(page.locator('#capec-filters-more')).to_have_attribute('open', '')
    expect(page.locator('#capec-filters-more summary')).to_contain_text('выбрано 1')
    expect(page.get_by_role('link', name='Сбросить', exact=True)).to_be_visible()
    page.get_by_role('link', name='Сбросить', exact=True).click()
    page.locator('th a.table-sort', has_text='Name').click()
    assert parse_qs(urlsplit(page.url).query).get('sort') == ['name_desc']
    page.locator('#capec-filters [name=q]').fill('Demo')
    page.locator('#capec-filters button[type=submit]').click()
    assert parse_qs(urlsplit(page.url).query).get('sort') == ['name_desc'], 'отбор не сбрасывает сортировку'
    page.set_viewport_size({'width': 390, 'height': 900})
    assert no_horizontal_scroll(page)
    # заголовки таблицы на узком экране скрыты: сортировка – в «Все фильтры»
    page.locator('#capec-filters-more summary').click()
    page.locator('select[name=sort]').select_option('severity_desc')
    page.locator('#capec-filters button[type=submit]').click()
    assert parse_qs(urlsplit(page.url).query).get('sort') == ['severity_desc']

