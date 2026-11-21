"""Сценарии оператора с текстами для Hub в браузере (демо-данные, поддельная модель): какая кнопка что кладёт в буфер,
где это видно и что подсказывает карточка. Кнопки подписаны однозначно: короткий текст – в комментарий к смене
статуса, полный текст дефекта – в описание дефекта; полный текст копируется и кнопкой внизу, и в разделе дефекта."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_SCA_EXPLANATION, save_sca_decision, sca_set_text_ready, DEMO_ANSWERS, clipboard, create_demo, run_triage  # noqa: E402

pytestmark = pytest.mark.e2e


def blur(page) -> None:
    page.evaluate("document.activeElement && document.activeElement.blur()")


def labels_are_unambiguous(page) -> None:
    """Кнопки копирования различимы по названию: доступные имена не совпадают и говорят, куда вставлять."""
    short = page.get_by_role("button", name=re.compile(r"^Скопировать короткий текст для Hub"))
    expect(short).to_have_count(1)
    expect(short).to_have_attribute("title", re.compile("комментарий к смене статуса"))
    expect(page.get_by_role("button", name=re.compile(r"^Скопировать для Hub"))).to_have_count(0)


def sast_labels_are_unambiguous(page) -> None:
    """Карточка SAST (ADR-0089): копируются комментарий ложного срабатывания и текст дефекта."""
    comment = page.get_by_role("button", name=re.compile(r"^Скопировать комментарий для Hub"))
    expect(comment).to_have_count(1)
    expect(comment).to_have_attribute("title", re.compile("Ложное срабатывание"))
    expect(page.get_by_role("button", name=re.compile(r"^Скопировать короткий текст для Hub"))).to_have_count(0)


def open_sast_with_verdict(page, pid: int, verdict: str = "true_positive") -> None:
    """Первая находка SAST, которой модель дала нужный вердикт (отбор списка)."""
    page.goto(f"/projects/{pid}/findings?kind=SAST&verdict={verdict}")
    page.locator('table tbody a[href*="/findings/"]').first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))


FALSE_REASON = "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."
TRUE_REASON = "Значение приходит из запроса пользователя и без проверки попадает в SQL."



def wait_clipboard(page, expected: str, attempts: int = 50) -> bool:
    """Буфер обмена получил ожидаемый текст: запись идёт после ответа сервера, ждём её, а не прежнее содержимое."""
    for _ in range(attempts):
        if clipboard(page) == expected:
            return True
        page.wait_for_timeout(100)
    return False

def test_sast_operator_copies_comment_and_defect_text(ui):
    """Два решения SAST (ADR-0089): ложное срабатывание – комментарий кнопкой «c», подтверждённый дефект –
    сохранить решение и скопировать текст дефекта."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_sast_with_verdict(page, pid)
    sast_labels_are_unambiguous(page)
    # до решения дефекта нет: ни раздела, ни кнопки текста дефекта внизу
    expect(page.locator("#defect-panel")).to_be_hidden()
    expect(page.locator("#copy-defect-bar")).to_be_hidden()
    expect(page.locator("#copy-where")).to_contain_text("Выберите решение")

    # 1. Ложное срабатывание: поля рекомендации нет, копируется комментарий оператора
    blur(page)
    page.keyboard.press("n")
    expect(page.locator("#fix-field")).to_be_hidden()
    expect(page.locator("#copy-hub")).to_be_visible()
    page.fill("#comment", FALSE_REASON)
    blur(page)
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("комментарий скопирован")
    assert clipboard(page) == FALSE_REASON, "в Hub уходит обоснование оператора, без «Статус: …»"
    expect(page.locator("#defect-panel")).to_be_hidden()
    expect(page.locator("#copy-defect-bar")).to_be_hidden()
    # выбранное решение отмечено не только цветом
    assert "✓" in page.evaluate(
        "getComputedStyle(document.querySelector('.segmented label:has(input:checked)'), '::before').content")

    # 1б. Отметка «скопировано» (/copied) задержалась: кнопка копирования её не ждёт
    held = []
    page.route("**/copied*", lambda route: held.append(route))
    page.evaluate("navigator.clipboard.writeText('прежнее содержимое буфера')")
    with page.expect_request("**/copied*"):
        page.click("#copy-hub")
    for _ in range(50):  # обработчик перехвата вызывается асинхронно: дождаться его
        if held:
            break
        page.wait_for_timeout(100)
    assert held, "отметка «скопировано» перехвачена и ещё не ответила"
    expect(page.locator("#copy-hub")).to_be_enabled()  # кнопка не ждёт ответа на /copied
    assert clipboard(page) == FALSE_REASON, "буфер записан до ответа на /copied"
    for route in held:
        route.continue_()
    page.unroute("**/copied*")

    # 2. Подтверждаю дефект: появляется пустое поле рекомендации (ADR-0092 – модель его не заполняет), пункты
    # модели переносит кнопка; комментарий не копируется
    fix_box = page.locator("#fix")
    expect(page.locator("#fix-field")).to_be_hidden()
    expect(fix_box).to_have_value("")
    blur(page)
    page.keyboard.press("y")
    expect(page.locator("#fix-field")).to_be_visible()
    expect(fix_box).to_have_value("")
    take = page.locator("#take-model-fix")
    if take.count():
        take.click()
        expect(fix_box).not_to_have_value("")
        assert "```" not in fix_box.input_value(), "пример кода модели в пункты не переносится"
    expect(page.locator("#copy-hub")).to_be_hidden()
    expect(page.locator("#hub-preview")).to_be_hidden()
    page.fill("#comment", TRUE_REASON)
    page.fill("#fix", "Передавать значение параметром запроса.\nПроверить такие же места в этом классе.")
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=saved"))

    # 3. Текст дефекта – кнопкой внизу, клавишей f и кнопкой в разделе дефекта; заголовок – отдельно
    expect(page.locator("#defect-panel")).to_be_visible()
    bar = page.locator("#copy-defect-bar")
    expect(bar).to_be_visible()
    expect(bar).to_have_text(re.compile(r"Скопировать текст дефекта"))
    expect(page.locator("#copy-where")).to_contain_text("в описание дефекта в Hub")
    bar.click()
    expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
    full = clipboard(page)
    assert full.startswith("После тщательного анализа уязвимости")
    assert f"\nОбоснование:\n{TRUE_REASON}\n" in full
    assert full.endswith("Рекомендация:\n1) Передавать значение параметром запроса.\n"
                         "2) Проверить такие же места в этом классе.")
    for absent in ("Требуется от разработчика", "ГОСТ", "Справочно", "Итог:"):
        assert absent not in full, absent
    blur(page)
    page.evaluate("navigator.clipboard.writeText('до клавиши f')")
    with page.expect_response(re.compile(r"/defect")):
        page.keyboard.press("f")
    assert wait_clipboard(page, full), "клавиша f заново выдала и скопировала текст"
    expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
    page.evaluate("navigator.clipboard.writeText('до кнопки раздела')")
    with page.expect_response(re.compile(r"/defect")):
        page.click("#copy-defect-body")
    assert wait_clipboard(page, full), "кнопка раздела заново выдала и скопировала текст"
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
    page.click("#copy-defect-title")
    expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
    assert re.fullmatch(r"ID\d+ - .+ \(SAST\)", clipboard(page))

    # 4. Несохранённая правка: текст дефекта не копируется, и это сказано рядом с нижней кнопкой
    in_buffer = clipboard(page)
    page.fill("#comment", "Подтверждено: другое обоснование.")
    expect(page.locator("#copy-where")).to_contain_text("сохраните решение")
    blur(page)
    page.keyboard.press("f")
    expect(page.locator("#copy-status")).to_contain_text("Сначала сохраните решение")
    assert clipboard(page) == in_buffer, "буфер не тронут"
    # «Внесено в Hub» при несохранённой правке не ставится: отметка – о сохранённом тексте
    page.click("#mark-entered")
    expect(page.locator("#copy-status")).to_contain_text("Решение изменено, но не сохранено")
    expect(page.locator("#entered-badge")).to_be_hidden()

    # 5. «Отложить»: в Hub ничего не переносится – кнопка комментария скрыта
    blur(page)
    page.keyboard.press("l")
    expect(page.locator("#copy-hub")).to_be_hidden()
    expect(page.locator("#fix-field")).to_be_hidden()

    # 6. Справка по клавишам называет обе кнопки
    blur(page)
    page.keyboard.press("?")
    help_box = page.locator("dialog[open]")
    expect(help_box).to_contain_text("скопировать комментарий для Hub")
    expect(help_box).to_contain_text("скопировать текст дефекта")
    page.keyboard.press("Escape")
    assert not watch.problems(), watch.problems()


def test_sast_true_positive_needs_own_recommendation(ui):
    """«Подтверждаю дефект» без своей рекомендации не сохраняется (ADR-0092): причина на экране, поле пустое и
    модель его не заполняет; со своей рекомендацией решение сохраняется."""
    page, watch = ui
    watch.allowed_errors.append("status of 400")  # отказ сохранения без рекомендации – так и задумано
    pid = create_demo(page)
    run_triage(page, pid)
    open_sast_with_verdict(page, pid)
    blur(page)
    page.keyboard.press("y")
    page.fill("#comment", TRUE_REASON)
    page.fill("#fix", "")
    page.get_by_role("button", name="Сохранить", exact=True).click()
    expect(page.locator("body")).to_contain_text("Напишите рекомендацию")
    expect(page.locator("#fix")).to_have_value("")
    page.fill("#fix", "Передавать значение параметром запроса.")
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=saved"))
    expect(page.locator("#fix")).to_have_value("Передавать значение параметром запроса.")
    assert not watch.problems(), watch.problems()


def test_sca_operator_copies_short_and_full_texts(ui):
    """Карточка SCA (0.9.8, ADR-0091 п. 3): короткий текст – только обоснование у «Ложное срабатывание» и «Риск
    принят»; у «Обновить» кнопки короткого текста нет, полный текст дефекта – по тексту набора."""
    page, watch = ui
    pid = create_demo(page)
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))
    expect(page.locator("#copy-defect-bar")).to_be_hidden()
    blur(page)
    page.keyboard.press("d")
    page.select_option("#final-verdict", "false_positive")
    reason = "Уязвимая функция разбора XML в продукте не вызывается: документы приходят только из своей базы."
    page.fill("#comment", reason)
    labels_are_unambiguous(page)
    blur(page)
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("скопирован")
    # карточка SCA без маршрута шагов: после копирования главная – «Отметить», как до 0.9.7
    expect(page.locator("#mark-entered")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(page.locator("#copy-hub")).not_to_have_class(re.compile(r"\bbtn-primary\b"))
    short = clipboard(page)
    assert reason in short and not short.startswith("Статус:"), short
    # «Обновить»: короткого текста нет, дефект – после текста набора
    blur(page)
    page.keyboard.press("a")
    expect(page.locator("#copy-hub")).to_be_hidden()
    save_sca_decision(page)
    expect(page.locator("#copy-defect-bar")).to_be_hidden()
    sca_set_text_ready(page, DEMO_SCA_EXPLANATION)
    expect(page.locator("#copy-defect-bar")).to_be_visible()
    page.click("#copy-defect-bar")
    expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
    full = clipboard(page)
    assert full.startswith("Описание\n"), full
    assert "Обновление org.example.thirdparty:example-xml-parser до версии 2.3.9" in full and full != short
    assert not watch.problems(), watch.problems()
