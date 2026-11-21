"""Оператор открывает паспорт прогона, отбирает историю и выгружает статистику."""
import json
import pytest
from playwright.sync_api import expect
from e2e_support import create_demo, run_triage, no_horizontal_scroll

pytestmark = pytest.mark.e2e


def test_journal_run_snapshot_filter_export_and_small_screen(ui, tmp_path):
    page, _ = ui
    pid = create_demo(page)
    rid = run_triage(page, pid)
    page.get_by_role('link', name='Журнал', exact=True).click()
    expect(page.get_by_role('heading', name='Журнал прогонов')).to_be_visible()
    page.locator('select[name=project]').select_option(str(pid))
    page.get_by_role('button', name='Применить', exact=True).click()
    expect(page.locator('.journal-table tbody tr')).to_have_count(1)
    # заголовки столбцов связаны с ячейками для вспомогательных технологий (KIMI-13)
    expect(page.locator('.journal-table th[scope="col"]')).to_have_count(6)
    expect(page.locator('th:not([scope="col"])')).to_have_count(0)
    page.locator(f'a[href^="/journal/{rid}?"]').click()
    expect(page.get_by_role('heading', name='Что исследовалось')).to_be_visible()
    expect(page.get_by_role('heading', name='Паспорт окружения')).to_be_visible()
    expect(page.locator('th:not([scope="col"])')).to_have_count(0)
    expect(page.locator('.journal-environment')).to_contain_text('Промпт', ignore_case=True)
    for width in (390, 1440):
        page.set_viewport_size({'width': width, 'height': 1000})
        assert no_horizontal_scroll(page)
    page.get_by_role('link', name='← Журнал прогонов').click()
    page.locator('select[name=project]').select_option(str(pid))
    page.get_by_role('button', name='Применить', exact=True).click()
    with page.expect_download() as downloaded:
        page.get_by_role('link', name='Скачать JSON').click()
    path = tmp_path / 'journal.json'
    downloaded.value.save_as(path)
    data = json.loads(path.read_text(encoding='utf-8'))
    assert [x['run']['id'] for x in data['runs']] == [rid]
    assert data['runs'][0]['snapshot']['queue']['kinds'] == {'SAST': data['runs'][0]['run']['total']}
