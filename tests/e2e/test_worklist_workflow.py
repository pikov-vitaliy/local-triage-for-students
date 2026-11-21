"""Рабочие таблицы в браузере: страницы, группы, отдельные версии и общее решение."""
import re
import pytest
from playwright.sync_api import expect
from hub_fixtures import make_hub_xlsx, SAST_ROWS, SCA_ROWS
from feed_fixtures import CWE_FULL_XML, cwe_zip
from e2e_support import no_horizontal_scroll

pytestmark=pytest.mark.e2e


def table_project(page, app_server, tmp_path):
    response=page.request.post('/projects',form={'name':'Рабочие таблицы Demo'},
                               headers={'Origin':app_server.url},max_redirects=0)
    assert response.status == 303
    pid=int(response.headers['location'].split('/')[2].split('?')[0])
    sast=[{**SAST_ROWS[0],'Issue id':str(91000+i),'Category':'Demo rule '+str(i%3),
           'Severity':'Critical' if i==60 else 'Low'} for i in range(61)]
    sca=[{**SCA_ROWS[0],'Issue id':str(92000+i),'Component name':'org.demo:library',
          'Component version':f'1.{i}.0'} for i in range(55)]
    path=make_hub_xlsx(tmp_path/'tables.xlsx',sast=sast,sca=sca,practices='auto',severities='auto')
    response=page.request.post(f'/projects/{pid}/import',headers={'Origin':app_server.url},max_redirects=0,
        multipart={'file':{'name':path.name,'mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':path.read_bytes()}})
    assert response.status == 303, response.text()
    return pid


def test_operator_tables_navigation_grouping_and_batch(ui,app_server,tmp_path):
    page,_=ui
    pid=table_project(page,app_server,tmp_path)
    # Критичность сортируется по всей выборке: критичная запись была за первой страницей.
    page.goto(f'/projects/{pid}/findings?kind=SAST&sort=severity_desc&page_size=50')
    expect(page.locator('.worklist-pager')).to_have_count(2)
    expect(page.locator('table.table-findings tbody tr').first).to_contain_text('91060')
    expect(page.locator('.worklist-pager').first).to_contain_text('Страница 1 из 2')
    page.locator('.worklist-pager').first.get_by_role('link',name='Страница 2',exact=True).click()
    expect(page.locator('.worklist-pager').first).to_contain_text('Страница 2 из 2')
    # Размер сбрасывает страницу, сортировка и отбор сохраняются.
    top=page.locator('.worklist-pager').first
    top.get_by_label('Записей или групп на странице').select_option('25')
    top.get_by_role('button',name='Применить размер').click()
    expect(page).to_have_url(re.compile('page=1'))
    assert 'kind=SAST' in page.url and 'sort=severity_desc' in page.url
    # Обзор групп не склеивает строки.
    page.locator('.worklist-controls').get_by_role('link',name=re.compile('Группы')).click()
    expect(page.locator('.worklist-groups tbody tr')).to_have_count(3)
    page.locator('.worklist-groups tbody tr').first.get_by_role('link',name=re.compile('Открыть')).click()
    expect(page.locator('table.table-findings tbody tr')).to_have_count(21)
    # Семейство компонентов имеет 55 версий с отдельной пагинацией и явным выбором.
    page.goto(f'/projects/{pid}/components?group_by=family&page_size=50')
    expect(page.locator('.worklist-groups tbody tr')).to_have_count(1)
    expect(page.locator('.worklist-groups tbody')).to_contain_text('55')
    page.locator('.worklist-groups').get_by_role('link',name='Открыть 55').click()
    expect(page.locator('.table-components tbody tr')).to_have_count(50)
    selected=page.locator('.table-components input[name=input_ref]')
    selected.nth(0).check();selected.nth(1).check()
    page.get_by_role('button',name='Общее решение для выбранных версий').click()
    expect(page.locator('h1')).to_have_text('Решение по выбранным версиям')
    # заголовки столбцов – scope="col" (KIMI-13)
    expect(page.locator('table th[scope="col"]')).to_have_count(4)
    expect(page.locator('th:not([scope="col"])')).to_have_count(0)
    expect(page.locator('table tbody tr')).to_have_count(2)
    page.locator('[name=action]').select_option('update')
    page.locator('[name=target_version]').fill('9.0.99')
    page.locator('[name=action]').select_option('replace')
    page.locator('[name=replacement_name]').fill('demo-replacement')
    expect(page.locator('[name=target_version]')).to_be_hidden()
    page.locator('[name=action]').select_option('update')
    expect(page.locator('[name=target_version]')).to_have_value('9.0.99')
    page.locator('[name=action]').select_option('keep')
    expect(page.locator('[name=target_version]')).to_be_hidden()
    page.locator('[name=rationale]').fill('Проверена применимость к выбранным версиям Demo')
    page.locator('[name=confirm]').check()
    page.get_by_role('button',name='Применить к 2 версиям').click()
    expect(page.locator('.table-components tbody')).to_contain_text('Проверена применимость')
    href=page.locator('.table-components [data-row-link]').first.get_attribute('href')
    page.goto(href)
    expect(page.locator('#decision-target-version')).to_have_value('')
    expect(page.locator('#decision-replacement-name')).to_have_value('')
    expect(page.get_by_role('navigation',name='Версии компонента')).to_be_visible()
    page.get_by_role('link',name='К списку',exact=True).click()
    assert 'family=' in page.url
    # Существующий CVSS-отбор совместим с группами SCA.
    page.goto(f'/projects/{pid}/sca?group_by=family&cvss_min=7&sort=cvss_desc&page_size=50')
    expect(page.locator('.worklist-groups tbody tr')).to_have_count(1)
    page.locator('.worklist-groups').get_by_role('link',name='Открыть 55').click()
    assert 'cvss_min=7' in page.url and 'sort=cvss_desc' in page.url
    expect(page.locator('#sca-table tbody tr')).to_have_count(50)
    for width in (1440,390):
        page.set_viewport_size({'width':width,'height':900})
        assert no_horizontal_scroll(page)


def test_cwe_sort_and_combined_filters(ui,tmp_path):
    page,_=ui
    page.goto('/feeds')
    page.set_input_files('#feed-cwe-file',str(cwe_zip(tmp_path/'cwe.zip',CWE_FULL_XML)))
    page.locator('#feed-cwe form button[type=submit]').click()
    expect(page.locator('#feed-cwe-records')).to_have_text('6',timeout=30000)
    page.goto('/cwe')
    page.get_by_role('columnheader',name=re.compile('ID')).get_by_role('link').click()
    expect(page.locator('table tbody tr').first).to_contain_text('CWE-3000')
    page.select_option('#cwe-kind','weakness')
    page.locator('select[name=abstraction]').select_option('Class')
    page.locator('select[name=status]').select_option('Draft')
    page.fill('#cwe-q','Demo')
    page.locator('#cwe-filters button[type=submit]').click()
    expect(page.locator('table tbody tr')).to_have_count(4)
    assert all(x in page.url for x in ('kind=weakness','abstraction=Class','status=Draft','sort=id_desc'))
    for width in (1440,390):
        page.set_viewport_size({'width':width,'height':900})
        assert no_horizontal_scroll(page)


def test_component_service_anchor_reveals_saved_closed_panel(ui,app_server,tmp_path):
    page,_=ui
    pid=table_project(page,app_server,tmp_path)
    page.goto(f'/projects/{pid}/components')
    panel=page.locator('#component-task')
    if panel.evaluate('el=>el.open'):
        panel.locator('summary').first.click()
    expect(panel).not_to_have_attribute('open','')
    # Это переход в пределах документа, загрузки страницы и повторной инициализации нет.
    page.goto(f'/projects/{pid}/components#component-task')
    expect(panel).to_have_attribute('open','')
    panel.locator('summary').first.click()
    page.goto(f'/projects/{pid}/components#component-task-title')
    expect(panel).to_have_attribute('open','')
