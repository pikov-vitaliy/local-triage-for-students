"""Регрессии аудита: клавиши, отметки времени и комментарий SCA."""
import re
import pytest
from playwright.sync_api import expect
from e2e_support import create_demo, DEMO_ANSWERS
pytestmark=pytest.mark.e2e

def test_help_opens_when_hotkeys_disabled(ui):
    page,_=ui;page.goto('/settings');page.wait_for_load_state('networkidle')
    page.evaluate("localStorage.setItem('local-triage-keys','off');document.activeElement.blur()")
    page.keyboard.press('Shift+/')
    expect(page.locator('#keys-dialog')).to_be_visible()

def test_enter_settings_shows_visible_busy_indicator(ui):
    page,_=ui;page.goto('/settings');page.wait_for_load_state('networkidle')
    # Отмена после штатного обработчика busy на document оставляет страницу для проверки индикатора.
    page.evaluate("document.addEventListener('submit', e => e.preventDefault())")
    page.locator('input[name=ollama_url]').press('Enter')
    button=page.locator('.settings-form button[aria-busy=true]:visible')
    expect(button).to_have_count(1);expect(button).to_contain_text('Сохраняю')

def test_sca_comment_confirmation_and_time_elements(ui):
    page,_=ui;pid=create_demo(page)
    page.goto(f'/projects/{pid}/sca#answers');page.set_input_files('#answers-file',str(DEMO_ANSWERS));page.click('#answers-submit')
    page.wait_for_url(re.compile('ok=sca_answers'));page.click('#sca-continue')
    page.wait_for_url(re.compile(r'/sca/findings/\d+'))
    original=page.locator('#comment').input_value()
    page.locator('label').filter(has=page.locator('input[name=decision][value=disagree]')).click();page.select_option('#final-verdict','false_positive')
    page.fill('#comment',original)
    expect(page.locator('#comment-stale')).to_be_visible();expect(page.locator('#comment-confirm')).to_be_visible()
    page.fill('#comment','Решение оператора по проверенному контексту')
    page.click('#copy-hub');expect(page.locator('#copy-status')).to_contain_text('текст скопирован')
    expect(page.locator('#copied-at time[datetime]')).to_have_count(1)
    page.click('#mark-entered');expect(page.locator('#entered-badge')).to_be_visible()
    expect(page.locator('#entered-at time[datetime]')).to_have_count(1)
