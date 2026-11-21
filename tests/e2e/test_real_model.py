"""Необязательная проверка в браузере с настоящей моделью в Ollama этого компьютера: демо-проект, разбор двух
находок SAST, карточка с объяснением модели и вопрос к модели. Запуск: scripts/run-e2e.ps1 -RealModel
(или `pytest tests/e2e --e2e --real-model gpt-oss:20b`). Нет Ollama или модели – проверка пропускается."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo, open_page, wait_run_done  # noqa: E402

pytestmark = [pytest.mark.e2e, pytest.mark.real_model]

# Истинная (внедрение SQL через склейку строки) и ложная (параметризованный запрос) – см. examples/demo/README.md
FINDINGS = ("100101", "100111")


def test_real_model_explains_and_answers(browser, real_app_server, real_model):
    context, page, watch = open_page(browser, real_app_server.url)
    try:
        pid = create_demo(page)
        page.goto(f"/projects/{pid}/findings?kind=SAST")
        for hub_id in FINDINGS:
            page.check(f'input.row-check[value="{hub_id}"]')
        expect(page.locator("#selected-bar")).to_be_visible()
        page.select_option('#selected-bar select[name="model"]', real_model)
        page.click("#run-selected")
        page.wait_for_url(re.compile(r"/runs/\d+$"))
        wait_run_done(page, timeout_ms=600_000)
        expect(page.locator("#progress-text")).to_contain_text("Обработано 2 из 2")

        page.goto(f"/projects/{pid}/findings?kind=SAST")
        page.locator("table.table-findings tbody tr", has_text=FINDINGS[0]).locator("a").first.click()
        page.wait_for_url(re.compile(r"/findings/\d+"))
        expect(page.locator(".verdict-big")).to_be_visible()
        expect(page.locator(".verdict-panel")).to_contain_text("Что делает код")
        expect(page.locator(".verdict-panel")).to_contain_text("Почему такой вердикт")
        expect(page.locator("#check-by-eye li").first).to_be_visible()
        expect(page.locator(".model-meta")).to_contain_text("ток/с")

        page.locator("#ask summary").click()  # «Вопросы к модели» в необязательном шаге 4 свёрнуты
        page.fill("#ask-question", "Что нужно поменять в этом методе, чтобы запрос стал безопасным?")
        page.click("#ask-btn")
        page.wait_for_url(re.compile(r"ok=(asked|ask_failed)"), timeout=600_000)
        answer = page.locator("#qa-list li.qa-item").last
        expect(answer).not_to_have_class(re.compile(r"\bis-error\b"))
        expect(answer.locator(".qa-a")).not_to_be_empty()
        expect(answer.locator(".qa-meta")).to_contain_text("ток/с")
        journal=page.request.get(f'{real_app_server.url}/journal/export.json?project={pid}').json()
        entry=journal['runs'][0]
        assert entry['new_answers']==2 and entry['run']['failed']==0
        assert entry['snapshot']['queue']['kinds']=={'SAST':2}
        assert len(entry['snapshot']['environments'][0]['data']['model']['digest'])==64
        assert len(entry['context_sha256'])==64
        page.goto(f"{real_app_server.url}/journal/{entry['run']['id']}")
        expect(page.get_by_role('heading',name='Паспорт окружения')).to_be_visible()
        problems = watch.problems()
    finally:
        context.close()
    assert not problems, "\n".join(problems)
