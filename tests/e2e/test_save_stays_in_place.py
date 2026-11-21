"""Сохранение решения не перебрасывает к началу карточки (У1): пустая рекомендация у «Подтверждаю
дефект» останавливается у поля без запроса и без прокрутки; после сохранения карточка открывается на шаге «Перенос
в Hub». Подсказка у поля говорит о кнопке «Взять пункты» только тогда, когда кнопка есть (У2). Данные выдуманы."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_operator_sast_route import TRUE_FIX, TRUE_REASON, card_urls, seeded  # noqa: E402
from test_recommendation_words_only import MARKER_POINTS, MARKERS  # noqa: E402

CODE_ONLY_FIX = "```python\nquery = 'SELECT ' + escape(value)\n```"


def choose_tp(page) -> None:
    page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()


def test_empty_recommendation_stops_at_the_field_and_save_opens_next_step(browser, tmp_path):
    pid, repos = seeded(tmp_path, 1)
    answer = verdict_answer("true_positive", evidence_lines=[2], fix=CODE_ONLY_FIX)
    with FakeOllama(default_answer=answer) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            # у модели только пример кода: кнопки нет, и подсказка о ней не говорит
            expect(page.locator("#take-model-fix")).to_have_count(0)
            assert "только пример кода" in page.locator("#review-form").get_attribute("data-need-fix")
            choose_tp(page)
            page.fill("#comment", TRUE_REASON)
            page.locator("#save-btn").scroll_into_view_if_needed()
            before = page.evaluate("window.scrollY")
            requests = []
            page.on("request", lambda r: requests.append(r.url) if r.method == "POST" else None)
            page.click("#save-btn")
            expect(page.locator("#fix-error")).to_contain_text("только пример кода")
            assert not [u for u in requests if u.endswith("/review") or "/review?" in u], "запрос не уходил"
            assert "/review" not in page.url and "ok=saved" not in page.url
            assert abs(page.evaluate("window.scrollY") - before) < 400, "карточка не прыгнула к началу"
            page.fill("#fix", TRUE_FIX)
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved.*#step-6$"))
            expect(page.locator("#step-6")).to_be_in_viewport()
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_points_of_the_model_are_offered_by_the_hint(browser, tmp_path):
    pid, repos = seeded(tmp_path, 1)
    answer = verdict_answer("true_positive", evidence_lines=[2], fix="1) Передавать значение параметром.")
    with FakeOllama(default_answer=answer) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            expect(page.locator("#take-model-fix")).to_have_count(1)
            assert "Взять пункты из рекомендации модели" in page.locator("#review-form").get_attribute("data-need-fix")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_recommendation_preview_and_code_warning(browser, tmp_path):
    """У5: под полем видно, какие пункты уйдут в Hub; строки кода без ограды – предупреждение, код в ограде в
    пункты не попадает."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer("true_positive", evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            choose_tp(page)
            page.fill("#fix", "1) Передавать значение параметром.\n```\nps.setString(1, v);\n```")
            expect(page.locator("#fix-preview")).to_have_text("В Hub уйдут пункты: 1) Передавать значение параметром.")
            expect(page.locator("#fix-code-warn")).to_be_hidden()
            page.fill("#fix", "String sql = \"SELECT\" + value;")
            expect(page.locator("#fix-code-warn")).to_be_visible()
            # маркер пункта – то же правило, что на сервере (tests/test_recommendation_words_only.py, MARKERS)
            page.fill("#fix", MARKERS)
            expect(page.locator("#fix-preview")).to_have_text(
                "В Hub уйдут пункты: " + " ".join(f"{n}) {p}" for n, p in enumerate(MARKER_POINTS, 1)))
            # слова пункта – как написаны (ADR-0149); один пустой тег пунктом не считается, как на сервере
            page.fill("#fix", "1) Экранируйте <b>вывод</b>.")
            expect(page.locator("#fix-preview")).to_have_text("В Hub уйдут пункты: 1) Экранируйте <b>вывод</b>.")
            page.fill("#fix", "<b></b>")
            expect(page.locator("#fix-preview")).to_be_hidden()
            # отступ строки в 1–3 пробела – перед номером пункта, как в тексте дефекта (defect._point, ревью круга 5)
            page.fill("#fix", "Экранируйте вывод.\n  - Используйте параметры.")
            expect(page.locator("#fix-preview")).to_be_visible()
            assert page.locator("#fix-preview").evaluate("e => e.textContent") == (
                "В Hub уйдут пункты:\n1) Экранируйте вывод.\n  2) Используйте параметры.")
            # пункт – на своей строке, отступ виден (ревью круга 6)
            assert page.locator("#fix-preview").evaluate("e => getComputedStyle(e).whiteSpace") == "pre-wrap"
            # пустой тег рядом с пунктом пунктом не считается, как на сервере (ревью круга 6)
            page.fill("#fix", "<b></b>\nПараметризовать запрос.")
            assert page.locator("#fix-preview").evaluate("e => e.textContent") == (
                "В Hub уйдут пункты:\n1) Параметризовать запрос.")
            # признаки кода – по тексту пункта без тегов (ревью круга 7, Kimi круга 7)
            page.fill("#fix", "return <b>value</b>;")
            expect(page.locator("#fix-code-warn")).to_be_visible()
            page.fill("#fix", "<b>Параметризовать запрос.</b>")
            expect(page.locator("#fix-code-warn")).to_be_hidden()
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
