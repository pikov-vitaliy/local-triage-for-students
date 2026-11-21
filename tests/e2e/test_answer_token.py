"""Карточка SCA в браузере: новый ответ агента не превращается в проверенное согласие, пока человек его не увидел.

Итоговая проверка LTA-002: после смены ответа форма не получает его номер молча; копирование отложено до обновления
карточки, введённый вариант решения переживает обновление, а после обновления виден полный новый ответ."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_ANSWERS, clipboard, create_demo  # noqa: E402

pytestmark = pytest.mark.e2e

NEW_TEXT = "ДРУГАЯ-РЕКОМЕНДАЦИЯ-ИЗ-НОВОГО-ОТВЕТА"


def second_answers(tmp_path: Path) -> Path:
    """Ответ B: тот же вывод update по той же библиотеке, но другая рекомендованная версия и пояснение."""
    data = json.loads(DEMO_ANSWERS.read_text(encoding="utf-8"))
    first = data["components"][0]
    first["recommended_version"] = "2.9.9"
    first["explanation"] = NEW_TEXT
    path = tmp_path / "answers-b.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def open_first_card(page, pid: int) -> None:
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))


def upload_b(page, pid: int, answers: Path) -> None:
    other = page.context.new_page()
    try:
        other.goto(f"/projects/{pid}/sca#answers")
        other.click("details.answers-upload > summary")  # ответы уже загружены: форма загрузки свёрнута
        other.set_input_files("#answers-file", str(answers))
        other.click("#answers-submit")
        other.wait_for_url(re.compile(r"ok=sca_answers"))
    finally:
        other.close()


def test_new_answer_blocks_copying_keeps_the_draft_and_shows_the_new_answer(ui, tmp_path: Path):
    page, watch = ui
    watch.allowed_errors.append("status of 409")  # отказ по устаревшему ответу – 409, так и задумано
    pid = create_demo(page)
    open_first_card(page, pid)
    token_before = page.locator('input[name="answer_id"]').input_value()
    assert NEW_TEXT not in page.content()
    # человек начинает решение: согласен с агентом и дописывает комментарий
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("d")  # «Ложное срабатывание»: у «Обновить» короткого текста нет (0.9.8), копирование – здесь
    page.select_option("#final-verdict", "false_positive")
    page.fill("#comment", "Уязвимая функция разбора в продукте не вызывается. ДОПИСАНО-ЧЕЛОВЕКОМ")

    upload_b(page, pid, second_answers(tmp_path))  # в другой вкладке приходит ответ B

    page.click("#copy-hub")  # сервер видит устаревший токен ответа
    expect(page.locator("#copy-status")).to_contain_text("новый ответ")
    expect(page.locator("#reload-card")).to_be_visible()
    expect(page.locator("#copy-hub")).to_be_disabled()
    assert page.locator('input[name="answer_id"]').input_value() == token_before, "токен ответа форме не подменяется"
    assert "ДОПИСАНО-ЧЕЛОВЕКОМ" not in clipboard(page), "текст не скопирован"

    page.click("#reload-card")  # обновить карточку: черновик сохраняется на время обновления
    expect(page.locator("#copy-status")).to_contain_text("Карточка обновлена")
    expect(page.locator("#comment")).to_have_value(re.compile("ДОПИСАНО-ЧЕЛОВЕКОМ"))
    assert NEW_TEXT in page.content(), "после обновления виден полный новый ответ"
    assert page.locator('input[name="answer_id"]').input_value() != token_before
    expect(page.locator("#reviewed-box")).not_to_be_checked()

    # человек увидел ответ B, отметил «Проверено» и копирует: теперь это согласие с тем ответом, который он видел
    page.select_option("#final-verdict", "false_positive")  # вывод восстановлен из черновика; кнопка – по нему
    page.check("#reviewed-box")
    page.click("#copy-hub")
    expect(page.locator("#mark-entered")).to_be_visible()
    assert "ДОПИСАНО-ЧЕЛОВЕКОМ" in clipboard(page)
    # согласие с увиденным ответом B: «Согласен» сохраняется по новому номеру ответа и становится проверенным
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("a")
    expect(page.locator('input[name="decision"][value="agree"]')).to_be_checked()
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=sca_(?:saved|all_reviewed|no_other)"))
    expect(page.locator("#reviewed-badge")).to_be_visible()
    assert NEW_TEXT in page.content() and page.locator('input[name="answer_id"]').input_value() != token_before


def test_server_reports_a_moved_answer_and_the_form_keeps_its_token(ui):
    """Защита в браузере не зависит от того, как именно сервер сообщил о смене ответа: ответ сохранения с answer_moved и
    токеном нового ответа не подменяет токен формы и отключает копирование до обновления."""
    page, _ = ui
    pid = create_demo(page)
    open_first_card(page, pid)
    token_before = page.locator('input[name="answer_id"]').input_value()

    def moved(route):
        response = route.fetch()
        body = response.json()
        body.update({"answer_moved": True, "answer_id": "999999", "current_answer_id": "999999",
                     "notice": "Пока решение сохранялось, пришёл новый ответ агента."})
        route.fulfill(response=response, json=body)

    page.route(re.compile(r"/sca/findings/\d+/review(?:\?.*)?$"), moved)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("d")  # копирование – у «Ложное срабатывание» (0.9.8)
    page.select_option("#final-verdict", "false_positive")
    page.fill("#comment", "Уязвимая функция разбора в продукте не вызывается.")
    page.click("#copy-hub")
    expect(page.locator("#reload-card")).to_be_visible()
    expect(page.locator("#copy-hub")).to_be_disabled()
    assert page.locator('input[name="answer_id"]').input_value() == token_before, "999999 в форму не попадает"
