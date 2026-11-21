"""Эргономика 0.9.2 в браузере (демо-данные, поддельная модель): курсор остаётся на выборе решения, к незаполненному
полю он переходит при сохранении; надпись о несохранённых правках; подписи «ложное срабатывание», уточнения ГОСТ Р КАПО
и отметки «Внесено в Hub»; кнопка «Наверх»; закреплённая полоска отборов и заголовки столбцов в
списках; нижняя панель на узком экране."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_ANSWERS, clipboard, create_demo, run_triage  # noqa: E402

pytestmark = pytest.mark.e2e


def active(page) -> str:
    return page.evaluate("(() => { const el = document.activeElement;"
                         " return el ? (el.id || (el.name + ':' + el.value)) : ''; })()")


def blur(page) -> None:
    page.evaluate("document.activeElement && document.activeElement.blur()")


def open_first_sast(page, pid: int) -> None:
    run_triage(page, pid)
    page.goto(f"/projects/{pid}/continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))


def open_first_sca(page, pid: int) -> None:
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))


def test_sast_cursor_stays_on_choice_and_save_points_to_missing_field(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_sast(page, pid)
    url = page.url
    note = page.locator("#dirty-note")
    expect(note).to_be_hidden()

    # стрелками по переключателю: решения SAST идут по порядку и не уводят курсор в поле (ADR-0089)
    page.locator("input[name=decision][value=false_positive]").focus()
    page.keyboard.press("ArrowRight")
    assert active(page) == "decision:true_positive"
    page.keyboard.press("ArrowRight")
    assert active(page) == "decision:later"
    page.keyboard.press("ArrowLeft")
    assert active(page) == "decision:true_positive"
    expect(note).to_be_visible()
    expect(note).to_have_text("Есть несохранённые изменения")

    # «Подтверждаю дефект» без обоснования: сохранение не уходит, курсор – в комментарий, причина видна в панели
    page.fill("#comment", "")
    page.fill("#fix", "Передавать значение параметром запроса.")
    page.locator("#review-form button[value=save]").click()
    assert active(page) == "comment"
    expect(page.locator("#copy-status")).to_contain_text("Не сохранено: нужен комментарий")
    expect(page.locator("#comment-error")).to_contain_text("обоснование дефекта")
    expect(page.locator("#comment")).to_have_attribute("aria-invalid", "true")
    assert "comment-error" in (page.locator("#comment").get_attribute("aria-describedby") or "")
    assert page.url == url

    # «Ложное срабатывание» без обоснования: то же при копировании комментария – буфер не тронут
    page.locator(".segmented label:has(input[value=false_positive])").click()
    page.fill("#comment", "")
    expect(page.locator("#fix-field")).to_be_hidden()
    page.evaluate("navigator.clipboard.writeText('прежнее')")
    blur(page)
    page.keyboard.press("c")
    assert active(page) == "comment"
    expect(page.locator("#comment-error")).to_contain_text("почему срабатывание ложное")
    assert clipboard(page) == "прежнее"

    # заполнено – копирование сохраняет: надпись о несохранённом гаснет, отметка названа точно
    page.fill("#comment", "Значение берётся из константы.")
    expect(page.locator("#comment-error")).to_be_hidden()  # исправлено – ошибка гаснет сразу
    expect(page.locator("#copy-status")).not_to_contain_text("Не сохранено")
    blur(page)
    page.keyboard.press("c")
    expect(page.locator("#copy-status")).to_contain_text("комментарий скопирован")
    assert clipboard(page) == "Значение берётся из константы."
    expect(note).to_be_hidden()
    mark = page.locator("#mark-entered")
    expect(mark).to_contain_text("Отметить: статус и комментарий внесены в Hub")  # надпись кнопки после копирования возвращает скрипт
    mark.click()
    expect(page.locator("#entered-note")).to_contain_text("Внесено в Hub")
    expect(page.locator("#entered-at")).to_contain_text("Внесено в Hub")
    assert not watch.problems(), watch.problems()


def test_sca_labels_and_kapo_choice(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_sca(page, pid)
    url = page.url
    option = page.locator("#final-verdict option[value=false_positive]")
    expect(option).to_contain_text("ложное срабатывание (компонент или уязвимость определены ошибочно)")
    empty = page.locator("#kapo-state option[value='']")

    # «Согласен с агентом» по выводу «обновить»: пустой вариант называет, что за ним стоит
    blur(page)
    page.keyboard.press("a")
    assert page.locator("#final-verdict").input_value() == "true_positive", "первая находка демо – «обновить»"
    expect(empty).to_have_text("по выводу (сейчас: анализ не завершён)")

    # «Риск принят»: состояние выбрать обязательно – без него курсор уходит в список уточнения
    page.locator("input[name=decision][value=risk_accepted]").focus()
    page.keyboard.press("Space")
    assert active(page) == "decision:risk_accepted"
    expect(empty).to_have_text("выберите состояние…")
    page.fill("#comment", "Риск принят: уязвимая функция не вызывается, пересмотреть при обновлении библиотеки.")
    page.select_option("#kapo-state", "")
    page.locator("#review-form button[value=save]").click()
    assert active(page) == "kapo-state"
    expect(page.locator("#copy-status")).to_contain_text("уточните состояние по ГОСТ Р КАПО")
    expect(page.locator("#kapo-state-error")).to_contain_text("уточните по ГОСТ Р КАПО")
    assert page.url == url
    page.select_option("#kapo-state", "not_actual")
    page.locator("#review-form button[value=save]").click()
    page.wait_for_url(re.compile(r"ok=sca_saved"))
    assert not watch.problems(), watch.problems()


def test_findings_list_strip_headers_and_to_top(ui):
    page, watch = ui
    pid = create_demo(page)
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 1280, "height": 420})
    page.goto(f"/projects/{pid}/findings")
    strip = page.locator("nav.presets[data-sticky-strip]")
    to_top = page.locator("#to-top")
    expect(to_top).to_be_hidden()
    expect(strip.locator(".strip-filters")).to_be_hidden()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "нет горизонтальной прокрутки"

    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_function("() => window.scrollY > window.innerHeight * 1.5")
    expect(strip).to_have_class(re.compile(r"\bis-stuck\b"))
    expect(strip.locator(".strip-filters")).to_be_visible()
    expect(to_top).to_be_visible()
    # полоска у верхнего края, заголовки столбцов сразу под ней
    box = strip.bounding_box()
    assert box and abs(box["y"]) < 1
    head = page.locator(".table-findings thead th").first.bounding_box()
    assert head and abs(head["y"] - box["height"]) < 2, (head, box)
    # строка под курсором j не прячется под полоской и заголовками
    blur(page)
    for _ in range(6):
        page.keyboard.press("j")
    page.wait_for_function("""() => { const row = document.querySelector('.table-findings tr.is-cursor');
        const strip = document.querySelector('nav.presets').getBoundingClientRect();
        const head = document.querySelector('.table-findings thead').getBoundingClientRect();
        return row && row.getBoundingClientRect().top >= strip.height + head.height - 1
          && row.getBoundingClientRect().bottom <= window.innerHeight; }""")

    # «Все фильтры» в полоске: к панели фильтров, панель раскрыта, курсор – на её видимом заголовке
    strip.locator(".strip-filters").click()
    expect(page.locator("#findings-filters")).to_have_attribute("open", "")
    assert page.evaluate("document.activeElement.tagName") == "SUMMARY"
    expect(page.locator("#findings-filters > summary")).to_be_in_viewport(ratio=1)

    # кнопка «Наверх»
    page.evaluate("document.querySelector('#findings-filters').open = false")
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    expect(to_top).to_be_visible()
    to_top.click()
    page.wait_for_function("() => window.scrollY === 0")
    expect(to_top).to_be_hidden()
    assert active(page) == "main"
    assert not watch.problems(), watch.problems()


def test_headers_stick_only_when_table_fits(ui):
    page, watch = ui
    pid = create_demo(page)
    page.emulate_media(reduced_motion="reduce")
    # 960 px: таблица демо шире контейнера – заголовки не закрепляются, остаётся прокрутка таблицы вбок
    page.set_viewport_size({"width": 960, "height": 420})
    page.goto(f"/projects/{pid}/findings")
    page.wait_for_function("() => !document.querySelector('.table-findings').parentNode.classList.contains('head-sticky')")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    # 1024 px: помещается – заголовки закреплены под полоской. Сначала – класс закрепления (его ставит обработчик
    # изменения размера), потом прокрутка к середине таблицы, а не к низу страницы (бэклог 113): закреплённый заголовок
    # держится, пока таблица на экране, а у низа страницы под полоской и заголовками оставалось 11 px таблицы. В полном
    # прогоне подвал выше на 20 px (предыдущая проверка настроила сервер моделей в сети организации – текст подвала
    # длиннее), и заголовок по правилам sticky уходил вверх вместе с концом таблицы. Пока ждём, прокрутка повторяется
    page.set_viewport_size({"width": 1024, "height": 420})
    page.wait_for_function("() => document.querySelector('.table-findings').parentNode.classList.contains('head-sticky')")
    middle = """() => { const t = document.querySelector('.table-findings').getBoundingClientRect();
        window.scrollTo(0, window.scrollY + t.top + t.height / 2 - window.innerHeight / 2); }"""
    page.evaluate(middle)
    page.wait_for_function("""() => { const s = document.querySelector('nav.presets').getBoundingClientRect();
        const h = document.querySelector('.table-findings thead th').getBoundingClientRect();
        if (Math.abs(s.top) < 1 && Math.abs(h.top - s.height) < 2) return true;
        const t = document.querySelector('.table-findings').getBoundingClientRect();
        window.scrollTo(0, window.scrollY + t.top + t.height / 2 - window.innerHeight / 2);
        return false; }""", polling=200)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    # сужение до карточек – заголовки не закрепляются, расширение – снова закреплены
    page.set_viewport_size({"width": 700, "height": 420})
    page.wait_for_function("() => !document.querySelector('.table-findings').parentNode.classList.contains('head-sticky')")
    page.set_viewport_size({"width": 1100, "height": 420})
    page.wait_for_function("() => document.querySelector('.table-findings').parentNode.classList.contains('head-sticky')")
    # обзор групп с разбивкой находок по столбцам (план dev7, раздел 3) помещается от 1100 px: заголовки закреплены; уже – прокрутка таблицы
    page.set_viewport_size({"width": 1100, "height": 420})
    page.goto(f"/projects/{pid}/findings?group_by=family")
    page.wait_for_function("() => document.querySelector('.worklist-groups').parentNode.classList.contains('head-sticky')")
    assert page.evaluate("getComputedStyle(document.querySelector('.worklist-groups thead th')).position") == "sticky"
    assert not watch.problems(), watch.problems()


def test_sca_list_strip(ui):
    page, watch = ui
    pid = create_demo(page)
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 1280, "height": 420})
    page.goto(f"/projects/{pid}/sca")
    strip = page.locator("#components nav.chips[data-sticky-strip]")
    page.evaluate("window.scrollTo(0, document.querySelector('#sca-table').getBoundingClientRect().top + window.scrollY)")
    expect(strip).to_have_class(re.compile(r"\bis-stuck\b"))
    button = strip.locator(".strip-filters")
    expect(button).to_be_visible()
    button.click()
    expect(page.locator("#sca-filters")).to_have_attribute("open", "")
    expect(page.locator("#sca-filters > summary")).to_be_in_viewport(ratio=1)
    assert page.evaluate("document.activeElement.tagName") == "SUMMARY"
    # заголовок фильтров не под закреплённой полоской
    page.wait_for_function("""() => { const s = document.querySelector('#components nav.chips').getBoundingClientRect();
        const f = document.querySelector('#sca-filters > summary').getBoundingClientRect(); return f.top >= s.bottom - 1; }""")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not watch.problems(), watch.problems()


def test_narrow_card_bar_and_to_top_above_it(ui):
    page, watch = ui
    pid = create_demo(page)
    open_first_sast(page, pid)
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 390, "height": 760})
    page.reload()
    bar = page.locator(".action-bar")
    box = bar.bounding_box()
    assert box and box["height"] <= 760 * 0.5 + 1, box
    to_top = page.locator("#to-top")
    # середина длинной карточки: панель внизу экрана, «Наверх» – над ней и на экране
    page.evaluate("window.scrollTo(0, window.innerHeight * 2)")
    expect(to_top).to_be_visible()
    expect(to_top).to_be_in_viewport()
    page.wait_for_function("""() => { const b = document.querySelector('.action-bar').getBoundingClientRect();
        const t = document.querySelector('#to-top').getBoundingClientRect(); return t.bottom <= b.top + 1; }""")
    # конец страницы: подвал виден и не пересекается с панелью, «Наверх» не уходит за экран
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_function("""() => { const b = document.querySelector('.action-bar').getBoundingClientRect();
        const f = document.querySelector('.footer p').getBoundingClientRect();
        return f.top >= b.bottom - 1 || f.bottom <= b.top + 1; }""")
    expect(page.locator(".footer p").first).to_be_in_viewport()
    expect(page.locator("#build-info")).to_be_in_viewport()  # плашка сборки видна и над нижней панелью
    expect(to_top).to_be_in_viewport()
    # ошибка обязательного поля видна в панели, даже если панель прокручена
    page.locator(".segmented label:has(input[value=false_positive])").click()
    page.fill("#comment", "")
    bar.evaluate("el => { el.scrollTop = el.scrollHeight; }")
    page.locator("#review-form button[value=save]").click()
    expect(page.locator("#copy-status")).to_contain_text("нужен комментарий")
    expect(page.locator("#copy-status")).to_be_in_viewport(ratio=1)
    expect(page.locator("#dirty-note")).to_be_visible()  # отказ сохранения правку не снимает
    # подробная ошибка у поля целиком над нижней панелью
    page.wait_for_function("""() => { const b = document.querySelector('.action-bar').getBoundingClientRect();
        const e = document.querySelector('#comment-error').getBoundingClientRect();
        return e.height > 0 && e.top >= 0 && e.bottom <= b.top + 1; }""")
    # пробелы – не обоснование: ошибка и aria-invalid остаются
    page.locator("#comment").press_sequentially("  ")
    expect(page.locator("#comment-error")).to_be_visible()
    expect(page.locator("#comment")).to_have_attribute("aria-invalid", "true")
    # панель прокручена к кнопкам – надпись о несохранённом по-прежнему видна внутри панели
    bar.evaluate("el => { el.scrollTop = el.scrollHeight; }")
    page.wait_for_function("""() => { const b = document.querySelector('.action-bar').getBoundingClientRect();
        const d = document.querySelector('#dirty-note').getBoundingClientRect();
        return d.height > 0 && d.top >= b.top - 1 && d.bottom <= b.bottom + 1; }""")
    # после копирования в конце страницы подтверждение в строке панели видно
    page.fill("#comment", "Значение берётся из заранее заданной строки, подстановки извне нет.")
    page.click("#copy-hub")
    expect(page.locator("#copy-status")).to_contain_text("комментарий скопирован")
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    expect(page.locator("#copy-status")).to_be_in_viewport(ratio=1)
    assert not watch.problems(), watch.problems()
