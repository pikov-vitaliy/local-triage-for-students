"""Приёмка управления очередью и конфиденциальности на выдуманном исходнике."""
from __future__ import annotations

import hashlib
import json
import re
from db_support import connect_db
import time

import pytest
from playwright.sync_api import expect

from app.db import Database
from app.models import Finding
from e2e_support import open_page, run_triage, start_app, stop_app, wait_run_done
from fake_ollama import FakeOllama, verdict_answer
from test_db import load

pytestmark = pytest.mark.e2e

MARKER = 'PRIVACY_SYNTHETIC_CODE_2099'
SECRET = 'night-test-not-a-real-api-secret-2099'


def seeded_app(tmp_path, count=1):
    repos = tmp_path/'repos'
    repos.mkdir()
    source = repos/'demo.py'
    source.write_text(f'''# {MARKER}
def demo(value):
    api_key = "{SECRET}"
    return value
''', encoding='utf-8')
    db = Database(tmp_path/'data'/'triage.db')
    pid = db.create_project('Выдуманный проект приёмки')
    rows = [Finding(hub_id=str(990000+i), kind='SAST', rule=f'Проверка входа {i}', cwe=['CWE-20'],
                    codebase='demo', file='demo.py', line=4, snippet='    return value',
                    severity='high', language='Python') for i in range(count)]
    load(db, pid, rows)
    db.set_codebase_folder(pid, 'demo', '.', True)
    db.close()
    return pid, repos, source


def test_operator_privacy_code_is_masked_and_model_markup_never_runs(browser, tmp_path):
    pid, repos, source = seeded_app(tmp_path)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    payload = '<img src="https://privacy.example.invalid/code" onerror="window.nightLeak=true">'
    answer = verdict_answer(what_code_does=payload, why=[payload], evidence_lines=[4])
    with FakeOllama(default_answer=answer) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            sent = fake.chats()
            assert len(sent) == 1
            body = json.dumps(sent[0], ensure_ascii=False)
            assert MARKER in body and SECRET not in body
            assert not {'tools', 'functions', 'tool_choice'} & sent[0].keys()
            page.goto(f'/projects/{pid}/findings')
            page.locator('table tbody a[href*="/findings/"]').first.click()
            expect(page.locator('.verdict-panel')).to_contain_text(payload)
            expect(page.locator('.verdict-panel img,.verdict-panel script')).to_have_count(0)
            assert page.evaluate('window.nightLeak') is None
            response = page.request.get(page.url)
            assert "connect-src 'self'" in response.headers['content-security-policy']
            assert response.headers['cache-control'] == 'no-store'
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
        # SQLite этого тестового экземпляра держит EXCLUSIVE: читать файл можно после его остановки.
        with connect_db(server.data_dir/'triage.db') as db:
            saved = db.execute('SELECT context_json FROM cases').fetchone()[0]
        assert MARKER in saved and SECRET not in saved
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert MARKER not in server.log.read_text(encoding='utf-8', errors='replace')
    assert SECRET not in server.log.read_text(encoding='utf-8', errors='replace')


def test_operator_can_pause_resume_stop_and_finish_remaining_items(browser, tmp_path):
    pid, repos, _ = seeded_app(tmp_path, count=12)
    with FakeOllama(delay=0.25, default_answer=verdict_answer(evidence_lines=[4])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f'/projects/{pid}#step3')
            page.get_by_role('button', name='Запустить триаж', exact=True).click()
            page.wait_for_url(re.compile(r'/runs/\d+$'))
            run_url = page.url
            page.get_by_role('button', name='Пауза', exact=True).click()
            expect(page.locator('#run-state')).to_have_class(re.compile(r'\bstate-paused\b'), timeout=15000)
            paused = page.request.get(run_url+'/status').json()['run']
            assert paused['done'] < paused['total']
            time.sleep(0.5)
            assert page.request.get(run_url+'/status').json()['run']['done'] == paused['done']
            page.reload()
            expect(page.get_by_role('button', name='Продолжить', exact=True)).to_be_visible()
            page.get_by_role('button', name='Продолжить', exact=True).click()
            page.get_by_role('button', name='Стоп', exact=True).click()
            expect(page.locator('#run-state')).to_have_class(re.compile(r'\bstate-stopped\b'), timeout=15000)
            stopped = page.request.get(run_url+'/status').json()['run']
            assert paused['done'] <= stopped['done'] < stopped['total']
            fake.delay = 0
            page.get_by_role('link', name='Новый прогон', exact=True).click()
            page.get_by_role('button', name='Запустить триаж', exact=True).click()
            page.wait_for_url(re.compile(r'/runs/\d+$'))
            assert page.url != run_url
            wait_run_done(page)
            finished = page.request.get(page.url+'/status').json()['run']
            assert finished['done'] == 12 and finished['failed'] == 0
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_operator_mouse_decisions_survive_reopening(browser, tmp_path):
    pid, repos, _ = seeded_app(tmp_path)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[4])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            page.goto(f'/projects/{pid}/findings')
            page.locator('table tbody a[href*="/findings/"]').first.click()
            # три решения карточки SAST (ADR-0089): ложное срабатывание, подтверждённый дефект, отложить
            for decision in ('false_positive', 'true_positive', 'later'):
                # Оператор нажимает видимую подпись; сам input перекрыт оформлением label.
                radio = page.locator(f'input[name="decision"][value="{decision}"]')
                page.locator('label').filter(has=radio).click()
                comment = f'Обоснование выдуманной проверки: {decision}'
                page.fill('#comment', comment)
                if decision == 'true_positive':
                    page.fill('#fix', 'Проверять значение перед использованием.')
                page.locator('#review-form button[name="action"][value="save"]').click()
                page.reload()
                expect(page.locator(f'input[name="decision"][value="{decision}"]')).to_be_checked()
                expect(page.locator('#comment')).to_have_value(comment)
                if decision == 'true_positive':
                    expect(page.locator('#fix')).to_have_value('Проверять значение перед использованием.')
            expect(page.locator('#final-verdict')).to_have_count(0)
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def seeded_group(tmp_path):
    """Выдуманный проект, где две находки стоят на одной строке в одной категории: в Hub это один дефект."""
    repos = tmp_path/'repos'
    repos.mkdir()
    (repos/'demo.py').write_text(f'''# {MARKER}
def demo(value):
    api_key = "{SECRET}"
    return value
''', encoding='utf-8')
    db = Database(tmp_path/'data'/'triage.db')
    pid = db.create_project('Выдуманный проект группы')
    rows = [Finding(hub_id=str(991000+i), kind='SAST', rule='Проверка входа', cwe=['CWE-20'], codebase='demo',
                    file='demo.py', line=4, snippet='    return value', severity='high', language='Python')
            for i in range(2)]
    load(db, pid, rows)
    db.set_codebase_folder(pid, 'demo', '.', True)
    db.close()
    return pid, repos


def test_group_sibling_decision_and_text_can_be_taken(browser, tmp_path):
    """Находки той же строки и категории: карточка показывает соседку, а кнопка «Взять решение и текст» переносит
    её решение, обоснование и рекомендацию (ADR-0089)."""
    pid, repos = seeded_group(tmp_path)
    reason = 'Значение приходит из запроса и без проверки доходит до вызова.'
    fix = 'Проверять значение перед использованием.'
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[4])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            page.goto(f'/projects/{pid}/findings')
            rows = page.locator('table tbody tr')  # в строке несколько ссылок на находку: берём по одной со строки
            first_url = rows.nth(0).locator('a[href*="/findings/"]').first.get_attribute('href')
            second_url = rows.nth(1).locator('a[href*="/findings/"]').first.get_attribute('href')
            assert first_url != second_url, (first_url, second_url)
            page.goto(first_url)
            expect(page.locator('#group-siblings')).to_be_visible()
            page.locator('label').filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
            expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
            page.fill('#comment', reason)
            page.fill('#fix', fix)
            page.locator('#review-form button[name="action"][value="save"]').click()
            page.wait_for_url(re.compile(r'ok=saved'))
            expect(page.locator('#defect-panel')).to_be_visible()
            # текст дефекта: после копирования тела – отметка «скопировано» и акцент на «Отметить: внесено в Hub»
            page.click('#copy-defect-bar')
            expect(page.locator('#defect-status')).to_contain_text('скопирован')
            expect(page.locator('#copied-at')).to_contain_text('Скопировано для Hub')
            expect(page.locator('#mark-entered')).to_be_visible()
            # у соседки видно решение и кнопка переноса
            page.goto(second_url)
            group = page.locator('#group-siblings')
            expect(group.locator('li').first).to_contain_text('дефект')
            group.get_by_role('button', name='Взять решение и текст').first.click()
            expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
            expect(page.locator('#comment')).to_have_value(reason)
            expect(page.locator('#fix')).to_have_value(fix)
            page.locator('#review-form button[name="action"][value="save"]').click()
            page.wait_for_url(re.compile(r'ok=saved'))
            expect(page.locator('#defect-panel')).to_be_visible()
            # тот же текст – дефект выдаётся под тем же номером
            expect(page.locator('#defect-number')).to_have_value('1')
            page.click('#copy-defect-bar')
            expect(page.locator('#defect-status')).to_contain_text('скопирован')
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
