"""Уточнение по ГОСТ Р КАПО в браузере (ADR-0145): у нового решения «обновить» – «актуальна» по умолчанию, подстановка повторяется
при возврате к итогу «Подтверждено», а явный выбор оператора – в том числе пустой «по выводу» – переживает перезагрузку
страницы (черновик восстанавливается без подстановки; ревью Codex 08.11)."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo  # noqa: E402
from test_scroll_and_decision_ergonomics import blur, open_first_sca  # noqa: E402

pytestmark = pytest.mark.e2e


def test_kapo_default_actual_and_explicit_empty_survives_reload(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_sca(page, pid)
    kapo = page.locator("#kapo-state")
    # первая находка демо – совет «обновить»: «актуальна» выбрана сразу
    blur(page)
    page.keyboard.press("a")
    assert page.locator("#final-verdict").input_value() == "true_positive"
    expect(kapo).to_have_value("actual")
    # «Риск принят» – «актуальна» недопустима, выбор обязателен; возврат к «обновить» подставляет «актуальна» снова
    page.locator("input[name=decision][value=risk_accepted]").focus()
    page.keyboard.press("Space")
    expect(kapo).to_have_value("")
    blur(page)
    page.keyboard.press("a")
    expect(kapo).to_have_value("actual")
    # явный пустой выбор («по выводу») переживает перезагрузку: черновик восстанавливается без подстановки
    page.select_option("#kapo-state", "")
    page.wait_for_timeout(600)
    page.reload()
    expect(page.locator("#final-verdict")).to_have_value("true_positive")
    expect(kapo).to_have_value("")
    expect(page.locator("#kapo-state option[value='']")).to_have_text("по выводу (сейчас: анализ не завершён)")
    # умолчание после перезагрузки живо: смена итога «Риск принят» → «обновить» снова подставляет «актуальна» (ревью круга 2)
    page.locator("input[name=decision][value=risk_accepted]").focus()
    page.keyboard.press("Space")
    expect(kapo).to_have_value("")
    blur(page)
    page.keyboard.press("a")
    expect(kapo).to_have_value("actual")
    assert not watch.problems(), watch.problems()


def test_kapo_choice_returns_with_outcome_but_cleared_stays_empty(ui):
    """Выбор уточнения у итога возвращается, когда оператор переключил итог и вернулся; очищенный выбор не
    возвращается (исправление 09.11 и ревью Codex, круг 2)."""
    page, watch = ui
    pid = create_demo(page)
    open_first_sca(page, pid)
    kapo = page.locator("#kapo-state")
    risk = page.locator("input[name=decision][value=risk_accepted]")
    later = page.locator("input[name=decision][value=later]")

    def pick(radio):
        radio.focus()
        page.keyboard.press("Space")
    pick(risk)
    page.select_option("#kapo-state", "not_actual")
    pick(later)
    pick(risk)
    expect(kapo).to_have_value("not_actual")
    page.select_option("#kapo-state", "")
    pick(later)
    pick(risk)
    expect(kapo).to_have_value("")
    assert not watch.problems(), watch.problems()
