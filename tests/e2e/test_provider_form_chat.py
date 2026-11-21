"""Форма профиля API чат-завершений коротко (разделы «Основное» и «Дополнительно»): формат,
рассуждение, пределы и поиск свёрнуты; вместо галочки «по умолчанию для разбора кода» – пояснение; галочка поиска без
путей сохраняет стандартные; «Проверить» показывает модели сервера. Сервер – поддельный, на этом компьютере."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from fake_chat_api import FakeChatApi

pytestmark = pytest.mark.e2e


def test_chat_profile_form_is_short_and_search_takes_standard_paths(ui):
    page, watch = ui
    with FakeChatApi(models=["flash-model"]) as fake:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Чат e2e")
        page.check('input[name="kind"][value="chat_completions"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', fake.url)
        advanced = page.locator("#provider-chat")
        expect(advanced).to_be_visible()
        expect(page.locator('select[name="response_mode"]')).to_be_hidden()  # свёрнуто
        expect(page.locator(".provider-code-default")).to_be_hidden()
        expect(page.locator("#provider-code-default-note")).to_be_visible()
        page.click("#provider-check")
        expect(page.locator("#provider-status")).to_contain_text("моделей: 1")
        page.locator("#provider-chat > summary").click()
        page.check('input[name="search_on"]')
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        page.get_by_role("link", name="Изменить").last.click()
        page.locator("#provider-chat > summary").click()
        expect(page.locator('input[name="search_path"]')).to_have_value("/v1/tools/search")
        expect(page.locator('input[name="fetch_path"]')).to_have_value("/v1/tools/fetch")
        assert not watch.problems(), watch.problems()


def test_messages_kind_shows_its_own_response_format_and_hides_thinking(ui):
    """0.9.14: у Anthropic Messages API свой список формата ответа; поля рассуждения чат-завершений скрыты (рассуждение
    не передаётся), вместо галочки умолчания – пояснение; обратное переключение возвращает поля чат-завершений."""
    page, watch = ui
    page.goto("/settings/providers/new")
    page.check('input[name="kind"][value="messages"]')
    page.locator("#provider-chat > summary").click()
    expect(page.locator('select[name="messages_response_mode"]')).to_be_visible()
    expect(page.locator('select[name="response_mode"]')).to_be_hidden()
    expect(page.locator('select[name="thinking"]')).to_be_hidden()
    expect(page.locator('select[name="effort"]')).to_be_hidden()
    expect(page.locator(".provider-code-default")).to_be_hidden()
    expect(page.locator("#provider-code-default-note")).to_be_visible()
    expect(page.locator('select[name="think"]')).to_be_hidden()  # раздел Ollama
    page.check('input[name="kind"][value="chat_completions"]')
    expect(page.locator('select[name="response_mode"]')).to_be_visible()
    expect(page.locator('select[name="thinking"]')).to_be_visible()
    expect(page.locator('select[name="messages_response_mode"]')).to_be_hidden()
    assert not watch.problems(), watch.problems()
