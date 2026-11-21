"""«Параметры проекта» в браузере: выбор другого профиля сразу показывает модели его сервера,
до «Сохранить параметры»; профиль проекта при этом не меняется. Второй сервер Ollama – поддельный, на этом
компьютере."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402

pytestmark = pytest.mark.e2e


def test_choosing_a_profile_shows_its_models_before_saving(ui):
    page, watch = ui
    with FakeOllama(models=["second-server-model:7b"]) as second:
        page.goto("/settings/providers/new")
        page.fill('input[name="name"]', "Второй сервер e2e")
        page.check('input[name="kind"][value="ollama"]')
        page.check('input[name="trust"][value="local"]')
        page.fill('input[name="base_url"]', second.url)
        page.click("#provider-save")
        page.wait_for_url(re.compile(r"/settings/providers\?ok="))
        pid = create_demo(page)
        page.goto(f"/projects/{pid}")
        page.locator("#params > summary").click()
        model = page.locator("#project-model")
        expect(model.locator("option", has_text="second-server-model")).to_have_count(0)
        chosen = page.locator("#project-provider option", has_text="Второй сервер e2e").get_attribute("value")
        page.locator("#project-provider").select_option(chosen)
        expect(model.locator("option", has_text="second-server-model")).to_have_count(1)
        expect(page.locator("#project-model-status")).to_contain_text("Модели – с сервера профиля «Второй сервер e2e»")
        page.reload()
        page.evaluate("document.getElementById('params').open = true")  # раздел мог запомниться открытым
        expect(page.locator("#project-provider")).to_have_value("")

        # пока список грузится, «Сохранить параметры» недоступна: новый профиль со старым списком не сохраняется
        held = []
        page.route("**/models.json*", lambda route: held.append(route))
        save = page.get_by_role("button", name="Сохранить параметры")
        page.locator("#project-provider").select_option(chosen)
        expect(save).to_be_disabled()
        for _ in range(50):
            if held:
                break
            page.wait_for_timeout(100)
        assert held, "запрос списка не перехвачен"
        held.pop().continue_()
        expect(save).to_be_enabled()
        expect(model.locator("option", has_text="second-server-model")).to_have_count(1)

        # ошибка загрузки – профиль и список прежние, кнопка доступна
        watch.allowed_errors.append("status of 500")  # ниже ответ сервера подменён ошибкой намеренно
        page.unroute("**/models.json*")
        page.route("**/models.json*", lambda route: route.fulfill(status=500, content_type="application/json",
                                                                 body='{"detail": "Сбой для проверки."}'))
        page.locator("#project-provider").select_option("")
        expect(page.locator("#project-model-status")).to_contain_text("Профиль оставлен прежним")
        expect(page.locator("#project-provider")).to_have_value(chosen)
        expect(save).to_be_enabled()
        page.unroute("**/models.json*")
