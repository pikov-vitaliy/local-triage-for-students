"""Операторские регрессии: применимые поля, сохранность ввода и точные ошибки формы."""

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402

pytestmark = pytest.mark.e2e


def test_decision_action_fields_and_validation_recovery(ui, tmp_path):
    page, watch = ui
    watch.allowed_errors.append("status of 422")  # ниже намеренно отправляется несуществующая дата
    pid = create_demo(page)
    expect(page.locator("#step2")).to_contain_text("Демонстрационные репозитории")
    expect(page.locator("#step2")).to_contain_text("start.ps1 -ReposRoot")
    page.goto(f"/projects/{pid}/components")
    href = page.locator(".table-components a[data-row-link]").first.get_attribute("href")
    page.goto(href)
    action = page.locator("#decision-action")
    target = page.locator("#decision-target-version")
    replacement = page.locator("#decision-replacement-name")
    expect(target).to_be_hidden()
    action.select_option("update")
    target.fill("2.3.9")
    page.locator("#decision-rationale").fill("Проверка переходов действий")
    action.select_option("accept_risk")
    expect(target).to_be_hidden()
    action.select_option("update")
    expect(target).to_have_value("2.3.9")
    action.select_option("replace")
    replacement.fill("demo-replacement")
    page.locator("#decision-replacement-version").fill("4.0.0")
    expect(target).to_be_hidden()
    action.select_option("update")
    expect(replacement).to_be_hidden()
    action.select_option("replace")
    expect(replacement).to_have_value("demo-replacement")
    action.select_option("update")
    # Формально подходящая строка даты, но не существующий календарный день: отказ сервера, не браузера. Поле – type=date,
    # и такой день браузер ввести не даст; здесь – браузер без календаря, поле текстовое.
    page.locator("#decision-review-at").evaluate("el => { el.type = 'text'; }")
    page.locator("#decision-review-at").fill("2099-02-31")
    with page.expect_response(lambda r: r.request.method == "POST" and r.url.split("?")[0].endswith("/decision")) as result:
        page.locator("#save-component-decision").click()
    assert result.value.status == 422
    expect(page.locator("#decision-error")).to_contain_text("Дата пересмотра")
    expect(page.locator("#decision-error")).not_to_contain_text("Обновите страницу")
    expect(page.locator("#decision-review-at")).to_be_focused()
    expect(page.locator("#decision-review-at")).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#decision-rationale")).to_have_value("Проверка переходов действий")
    page.locator("#decision-review-at").fill("2099-02-28")
    page.locator("#save-component-decision").click()
    page.wait_for_url(re.compile("ok=decision"))
    expect(page.locator(".component-current-decision")).to_contain_text("2.3.9")
    expect(page.locator("#decision-replacement-name")).to_have_value("")
    action.select_option("accept_risk")
    page.locator("#save-component-decision").click()
    page.wait_for_url(re.compile("ok=decision"))
    # URL уже мог содержать ok=decision: ждём ответ и перерисовку по сохранённому действию.
    expect(page.locator(".component-current-decision .badge")).to_contain_text("риск принят")
    expect(page.locator(".component-current-decision")).not_to_contain_text("целевая версия")
    page.reload()
    expect(page.locator("#decision-target-version")).to_have_value("")
    expect(page.locator(".component-history")).to_contain_text("2.3.9")
    page.locator("#operator-decision").scroll_into_view_if_needed()
    page.screenshot(path=str(tmp_path / "decision-fixed.png"))
