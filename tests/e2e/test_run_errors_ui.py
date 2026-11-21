"""Страница прогона в браузере: ошибки списком и группами, «Повторить ошибочные» по сохранённым срезам без
клона, кнопка разбора находок вне управления прогоном и цвет строки «Последние данные модели»."""

from __future__ import annotations

import re
import shutil
import time

import pytest
from playwright.sync_api import expect

from e2e_support import (DEMO_REPOS, create_demo, e2e_reply, make_fake_ollama, open_page, run_triage, start_app,
                         stop_app, wait_run_done)

pytestmark = pytest.mark.e2e


def test_run_errors_block_and_review_button(ui, app_server):
    page, _ = ui
    pid = create_demo(page)
    original = app_server.fake.default_answer

    def answer(body):
        text = "\n".join(str(m.get("content") or "") for m in body.get("messages") or [])
        return "это не JSON" if "Подделка серверных запросов" in text else e2e_reply(body)

    app_server.fake.default_answer = answer
    try:
        page.goto(f"/projects/{pid}#step3")
        page.check('input[name="fresh"]')
        page.get_by_role("button", name="Запустить триаж", exact=True).click()
        page.wait_for_url(re.compile(r"/runs/\d+$"))
        run_id = int(re.search(r"/runs/(\d+)", page.url).group(1))
        wait_run_done(page)
    finally:
        app_server.fake.default_answer = original
    # Блок ошибок виден и раскрывается в список находок с короткими причинами
    expect(page.locator("#run-errors")).to_be_visible()
    total = int(page.locator("#errors-total").inner_text())
    assert total > 0
    page.locator("#run-errors summary").first.click()
    format_group = page.locator('[data-error-group="format"]')
    expect(format_group).to_be_visible()
    expect(format_group).to_contain_text("ответ не по формату")
    expect(format_group.locator(".error-item a").first).to_be_visible()
    # В ленте – короткая метка, полный текст только в подсказке
    error_badge = page.locator("#feed .badge.item-error").first
    expect(error_badge).to_have_text("ошибка формата")
    assert "Модель дважды ответила не по формату" in (error_badge.get_attribute("title") or "")
    assert page.locator("#last-error").count() == 0
    # Ссылка разбора находок – вне управления прогоном и не называется «Продолжить разбор»
    review = page.locator("#review-findings")
    expect(review).to_be_visible()
    expect(review).to_have_text("Разбирать находки")
    assert page.locator("#run-actions #review-findings").count() == 0
    assert "Продолжить разбор" not in page.locator("#run-actions").inner_text()
    # Кнопка повтора видна, число совпадает с числом ошибок
    retry = page.locator("#retry-errors-button")
    expect(retry).to_be_visible()
    expect(retry).to_contain_text(f"({total})")
    # Повтор создаёт новый прогон selected; эта же модель отвечает уже правильно
    app_server.fake.answers = []
    retry.click()
    page.wait_for_url(re.compile(r"/runs/\d+$"))
    new_id = int(re.search(r"/runs/(\d+)", page.url).group(1))
    assert new_id != run_id
    wait_run_done(page)
    expect(page.locator(".page-head")).to_contain_text("охват: выбранные")
    expect(page.locator(".page-head")).to_contain_text(f"находок {total}")
    expect(page.locator("#run-errors")).to_be_hidden()


def test_retry_errors_works_without_clones(tmp_path_factory, browser):
    tmp = tmp_path_factory.mktemp("run-errors-no-clone")
    repos = tmp / "repos"
    repos.mkdir()
    for name in ("billing-core", "catalog-api"):
        shutil.copytree(DEMO_REPOS / name, repos / name)
    fake = make_fake_ollama()
    server = start_app(tmp, fake.url, repos_root=repos)
    context = None
    try:
        context, page, _ = open_page(browser, server.url)
        pid = create_demo(page)
        original = fake.default_answer
        fake.default_answer = "это не JSON"
        try:
            run_id = run_triage(page, pid)
        finally:
            fake.default_answer = original
        total = int(page.locator("#errors-total").inner_text())
        assert total > 0
        # Клоны удалены после прогона: срезы остались в базе, повтор идёт без клонов
        shutil.rmtree(repos / "billing-core")
        shutil.rmtree(repos / "catalog-api")
        fake.answers = []
        page.locator("#retry-errors-button").click()
        page.wait_for_url(re.compile(r"/runs/\d+$"))
        new_id = int(re.search(r"/runs/(\d+)", page.url).group(1))
        assert new_id != run_id
        wait_run_done(page)
        expect(page.locator(".page-head")).to_contain_text("охват: выбранные")
        expect(page.locator(".page-head")).to_contain_text(f"находок {total}")
        expect(page.locator("#run-errors")).to_be_hidden()
    finally:
        if context is not None:
            context.close()
        stop_app(server.process)
        fake.close()


def test_model_activity_is_warned_only_after_silence(ui):
    page, watch = ui
    pid = create_demo(page)
    run_id = run_triage(page, pid)
    state = page.request.get(f"/runs/{run_id}/status").json()
    state["run"]["state"] = "running"
    state["run"]["state_label"] = "идёт"
    state["run"]["failed"] = 3
    now = time.time()
    state["current"] = {"phase": "generating", "phase_label": "модель формирует ответ", "seconds": 1,
                        "last_model_event_at": now}
    mock = {"state": state}

    def status(route):
        route.fulfill(json=mock["state"])

    watch.allowed_errors.append("net::ERR_FAILED")  # поток событий не нужен: состояние подменяет status
    page.route(f"**/runs/{run_id}/status", status)
    page.route(f"**/runs/{run_id}/events", lambda route: route.abort())
    page.reload()
    expect(page.locator("#obs-health")).to_contain_text("Последние данные модели")
    expect(page.locator("#obs-health")).not_to_have_class(re.compile(r"\btext-warn\b"))
    # То же состояние, но данные модели были 200 с назад – порог 180 с, цвет предупреждающий
    state["current"]["last_model_event_at"] = now - 200
    expect(page.locator("#obs-health")).to_have_class(re.compile(r"\btext-warn\b"), timeout=10000)
    expect(page.locator("#obs-health")).to_contain_text("Долго нет новых данных модели")
