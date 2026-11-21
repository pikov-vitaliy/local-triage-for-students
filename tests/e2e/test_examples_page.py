"""Страница «Примеры», справка и тема по времени суток в настоящем браузере (ADR-0156, ADR-0157)."""
import pytest
from e2e_support import no_horizontal_scroll
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_examples_page_lists_catalog_and_start_panel(ui):
    page, _ = ui
    page.goto('/examples')
    expect(page.locator('h1')).to_have_text('Учебные примеры')
    expect(page.locator('#start')).to_contain_text('Начало работы')
    expect(page.locator('#ex-juice-shop')).to_contain_text('OWASP Juice Shop')
    expect(page.locator('#ex-crapi')).to_contain_text('Кодовые базы')
    expect(page.locator('#ex-demo-library')).to_contain_text('Поставляется с приложением')
    for width in (390, 1440):
        page.set_viewport_size({'width': width, 'height': 900})
        assert no_horizontal_scroll(page)


def test_presets_open_prefilled_profile_form(ui):
    page, _ = ui
    page.goto('/settings/providers/new?preset=deepseek')
    expect(page.locator('input[name=base_url]')).to_have_value('https://api.deepseek.com')
    expect(page.locator('#provider-notice')).to_contain_text('вставьте свой ключ API')


def test_help_opens_in_a_new_tab_with_glossary(ui):
    page, _ = ui
    page.goto('/examples')
    with page.context.expect_page() as info:
        page.locator('a.topnav-link[href="/help"]').click()
    help_page = info.value
    help_page.wait_for_load_state()
    expect(help_page.locator('#help-glossary')).to_contain_text('Ложное срабатывание')
    help_page.close()


def test_theme_follows_clock_and_manual_choice_is_kept(ui):
    page, _ = ui
    page.goto('/examples')
    page.evaluate("() => localStorage.removeItem('local-triage-theme')")
    page.reload()
    hour = page.evaluate('() => new Date().getHours()')
    expected = 'dark' if hour >= 20 or hour < 7 else 'light'
    assert page.evaluate("() => document.documentElement.getAttribute('data-theme')") == expected
    page.locator('#theme-toggle').click()
    flipped = 'light' if expected == 'dark' else 'dark'
    page.reload()
    assert page.evaluate("() => document.documentElement.getAttribute('data-theme')") == flipped
    stored = page.evaluate("() => JSON.parse(localStorage.getItem('local-triage-theme'))")
    assert stored['theme'] == flipped and stored['until'] > page.evaluate('() => Date.now()')


def test_demo_library_created_from_catalog_then_opened(ui):
    page, _ = ui
    page.goto('/examples')
    card = page.locator('#ex-demo-library')
    if card.get_by_role('button', name='Создать проект').count():
        card.get_by_role('button', name='Создать проект').click()
        page.wait_for_url('**/projects/*')
        expect(page.locator('h1')).to_contain_text('Демо')
    page.goto('/examples')
    expect(page.locator('#ex-demo-library')).to_contain_text('Открыть проект')


def test_demo_library_from_catalog_is_triaged_with_fake_model(ui):
    """План стенда, сборка Б: проект из записи Demo Library каталога и разбор поддельной Ollama."""
    from e2e_support import run_triage

    page, _ = ui
    page.goto('/examples')
    card = page.locator('#ex-demo-library')
    if card.get_by_role('button', name='Создать проект').count():
        card.get_by_role('button', name='Создать проект').click()
        page.wait_for_url('**/projects/*')
    else:
        card.get_by_role('link', name='Открыть проект').click()
    project_id = int(page.url.split('/projects/')[1].split('?')[0].split('#')[0])
    run_triage(page, project_id)
    expect(page.locator('#run-state')).to_have_class(__import__('re').compile(r'\bstate-done\b'))
