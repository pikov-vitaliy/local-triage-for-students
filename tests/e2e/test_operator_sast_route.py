"""Маршрут оператора по карточке SAST (шаги 1–7, 0.9.7) в браузере: главная кнопка нижней панели по этапу, галочки
шагов 5 и 6 по сохранённому, «Отложить» без шага 6, сворачивание кода как предпочтение оператора, группа той же
строки и категории, прежнее решение «Риск принят», отказ буфера обмена. Демо-данные и поддельная модель."""

from __future__ import annotations

import os
import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from app.db import Database  # noqa: E402
from app.models import Finding  # noqa: E402
from e2e_support import clipboard, create_demo, open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_db import load  # noqa: E402

pytestmark = pytest.mark.e2e

FALSE_REASON = "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."
TRUE_REASON = "Значение приходит из запроса пользователя и без проверки попадает в SQL."
TRUE_FIX = "Передавать значение параметром подготовленного запроса."
TEAM_PHRASE = "приняла решение присвоить данной уязвимости категорию True Positive"


def blur(page) -> None:
    page.evaluate("document.activeElement && document.activeElement.blur()")


def stage(page):
    return expect(page.locator(".action-bar"))


def step(page, n: int):
    return page.locator(f"#route .route-step[data-step='{n}']")


def open_first_sast(page, pid: int) -> None:
    page.goto(f"/projects/{pid}/findings?kind=SAST")
    page.locator('table tbody a[href*="/findings/"]').first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))


def wait_clipboard_contains(page, part: str, attempts: int = 50) -> str:
    text = ""
    for _ in range(attempts):
        text = clipboard(page)
        if part in text:
            return text
        page.wait_for_timeout(100)
    return text


def test_false_positive_route_by_keyboard(ui):
    """Ложное срабатывание: n → комментарий → c (копирование) → h (внесено в Hub) → Ctrl+Enter. Главная кнопка
    переходит «скопировать» → «отметить» → «дальше», галочки шагов 5 и 6 ставятся по сохранённому."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_first_sast(page, pid)
    stage(page).to_have_attribute("data-stage", "")
    expect(page.locator("#copy-where")).to_contain_text("Выберите решение")
    blur(page)
    page.keyboard.press("n")
    stage(page).to_have_attribute("data-stage", "copy")
    expect(page.locator("#copy-hub")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(page.locator("#copy-where")).to_contain_text("при смене статуса")
    expect(step(page, 5)).not_to_have_class(re.compile(r"\bis-done\b"))
    page.fill("#comment", FALSE_REASON)
    blur(page)
    page.keyboard.press("c")
    assert FALSE_REASON in wait_clipboard_contains(page, FALSE_REASON)
    expect(page.locator("#copied-at")).to_contain_text("Скопировано для Hub")
    stage(page).to_have_attribute("data-stage", "mark")
    expect(page.locator("#mark-entered")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(step(page, 5)).to_have_class(re.compile(r"\bis-done\b"))  # копирование сохраняет решение
    blur(page)
    page.keyboard.press("h")
    expect(page.locator("#entered-badge")).to_be_visible()
    stage(page).to_have_attribute("data-stage", "next")
    expect(page.locator("#next-btn")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(step(page, 6)).to_have_class(re.compile(r"\bis-done\b"))
    first = page.url
    page.keyboard.press("Control+Enter")
    page.wait_for_url(lambda url: url.split("?")[0] != first.split("?")[0])
    assert not watch.problems(), watch.problems()


def test_true_positive_route_save_copy_enter(ui):
    """Подтверждённый дефект: y → обоснование и рекомендация → «Сохранить решение» внизу → «Скопировать текст
    дефекта» → «Отметить: внесено в Hub» → «Дальше». Правка после сохранения возвращает этап к сохранению."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_first_sast(page, pid)
    blur(page)
    page.keyboard.press("y")
    stage(page).to_have_attribute("data-stage", "save")
    expect(page.locator("#save-bar")).to_be_visible()
    expect(page.locator("#save-bar")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(page.locator("#copy-where")).to_contain_text("сохраните решение")
    page.fill("#comment", TRUE_REASON)
    page.fill("#fix", TRUE_FIX)
    page.click("#save-bar")
    page.wait_for_url(re.compile(r"ok=saved"))
    expect(page.locator("#defect-panel")).to_be_visible()
    # О2: заголовок → текст → отметка; кнопка заголовка в панели – только на своём этапе
    stage(page).to_have_attribute("data-stage", "title")
    expect(page.locator("#copy-title-bar")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(page.locator("#save-bar")).to_be_hidden()
    expect(step(page, 5)).to_have_class(re.compile(r"\bis-done\b"))
    expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
    page.click("#copy-title-bar")
    assert re.fullmatch(r"ID\d+ - .+ \(SAST\)", wait_clipboard_contains(page, "(SAST)"))
    stage(page).to_have_attribute("data-stage", "defect")
    expect(page.locator("#copy-title-bar")).to_be_hidden()
    expect(page.locator("#copy-defect-bar")).to_have_class(re.compile(r"\bbtn-primary\b"))
    expect(page.locator("#copy-defect-bar")).to_be_focused()
    page.click("#copy-defect-bar")
    body = wait_clipboard_contains(page, TRUE_REASON)  # буфер общий между проверками: ждать свой текст, не общую фразу
    assert TEAM_PHRASE in body and TRUE_REASON in body and TRUE_FIX in body, body
    stage(page).to_have_attribute("data-stage", "mark")
    page.click("#mark-entered")
    expect(page.locator("#entered-badge")).to_be_visible()
    stage(page).to_have_attribute("data-stage", "next")
    expect(step(page, 6)).to_have_class(re.compile(r"\bis-done\b"))
    # правка после внесения: в Hub уйдёт новый текст – сначала сохранить
    page.fill("#fix", TRUE_FIX + " Проверить остальные вызовы.")
    stage(page).to_have_attribute("data-stage", "save")
    expect(page.locator("#copy-where")).to_contain_text("сохраните решение")
    assert not watch.problems(), watch.problems()


def test_later_marks_step_six_not_applicable(ui):
    """«Отложить»: в Hub ничего не переносится – шаг 6 «не применяется», главная кнопка – «Дальше»."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_first_sast(page, pid)
    blur(page)
    page.keyboard.press("l")
    stage(page).to_have_attribute("data-stage", "next")
    expect(page.locator("#copy-where")).to_contain_text("Решение изменено")  # «Отложить» ещё не сохранено
    expect(step(page, 6)).to_have_class(re.compile(r"\bis-na\b"))
    page.click("#save-btn")
    page.wait_for_url(re.compile(r"ok=saved"))
    expect(page.locator("#copy-where")).to_contain_text("ничего не переносится")
    expect(step(page, 6)).to_have_class(re.compile(r"\bis-na\b"))
    expect(page.locator("#mark-entered")).to_be_hidden()
    stage(page).to_have_attribute("data-stage", "next")
    assert not watch.problems(), watch.problems()


def test_code_fold_is_operator_preference_and_line_link_reveals(ui):
    """«Свернуть код» запоминается только по нажатию; переход к строке раскрывает код и предпочтение не меняет."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_first_sast(page, pid)
    expect(page.locator("#code-body")).to_be_visible()
    page.click("#code-toggle")
    expect(page.locator("#code-body")).to_be_hidden()
    expect(page.locator("#code-toggle")).to_have_attribute("aria-expanded", "false")
    page.reload()
    expect(page.locator("#code-body")).to_be_hidden()
    link = page.locator("#trace a[href^='#L']").first
    target = link.get_attribute("href")
    link.click()
    expect(page.locator("#code-body")).to_be_visible()
    expect(page.locator(f"tr{target}")).to_be_visible()
    page.goto(page.url.split("#")[0])  # та же карточка без адреса строки: предпочтение прежнее – свёрнуто
    expect(page.locator("#code-body")).to_be_hidden()
    page.click("#code-toggle")
    expect(page.locator("#code-body")).to_be_visible()
    page.reload()
    expect(page.locator("#code-body")).to_be_visible()
    assert not watch.problems(), watch.problems()


def seeded(tmp_path, count: int, legacy: bool = False):
    """Выдуманный проект: count находок на одной строке в одной категории; legacy – у первой прежнее решение
    «Риск принят» (до 0.9.6)."""
    repos = tmp_path / "repos"
    repos.mkdir()
    (repos / "demo.py").write_text("def demo(value):\n    query = 'SELECT ' + value\n    return query\n",
                                   encoding="utf-8")
    db = Database(tmp_path / "data" / "triage.db")
    pid = db.create_project("Выдуманный проект маршрута")
    rows = [Finding(hub_id=str(993000 + i), kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo",
                    file="demo.py", line=2, snippet="    query = 'SELECT ' + value", severity="high",
                    language="Python") for i in range(count)]
    load(db, pid, rows)
    db.set_codebase_folder(pid, "demo", ".", True)
    if legacy:
        db.save_review(pid, "993000", decision="risk_accepted", final_verdict="", final_comment="Риск принят.",
                       reviewed=False)
    db.close()
    return pid, repos


def card_urls(page, pid: int) -> list[str]:
    page.goto(f"/projects/{pid}/findings")
    rows = page.locator("table tbody tr")
    return [rows.nth(i).locator('a[href*="/findings/"]').first.get_attribute("href") for i in range(rows.count())]


def save_tp(page, reason: str, fix: str) -> None:
    page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
    page.fill("#comment", reason)
    page.fill("#fix", fix)
    page.click("#save-btn")
    page.wait_for_url(re.compile(r"ok=saved"))


def test_group_take_all_and_refusal_on_different_text(browser, tmp_path):
    """Группа из трёх находок: две с одним решением и текстом – у третьей кнопка «Взять решение и текст у всех»;
    другой текст у третьей – дефект не готовится, приложение называет расхождение."""
    pid, repos = seeded(tmp_path, 3)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            first, second, third = card_urls(page, pid)
            page.goto(first)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            page.goto(second)
            expect(page.locator("#group-take-all")).to_have_count(0)  # у третьей решения нет: «у всех» не сказать
            # номер находки в закреплённой полосе – копируется щелчком (бэклог 31)
            page.evaluate("navigator.clipboard.writeText('до номера')")
            page.click("#route-id")
            assert clipboard(page) == "993001"
            expect(page.locator("#take-note")).to_be_hidden()
            page.locator("#group-siblings").get_by_role("button", name="Взять решение и текст").first.click()
            # подставлено, но не сохранено: подсказка и подсвеченная «Сохранить» (бэклог 32)
            expect(page.locator("#take-note")).to_have_text("Решение подставлено – сохраните")
            expect(page.locator("#save-btn")).to_have_class(re.compile(r"\bis-attention\b"))
            # отменённая отправка (обоснование стёрто – поле обязательно) подсказку не снимает
            page.fill("#comment", "   ")
            before_cancel = page.url
            page.click("#save-btn")
            expect(page.locator("#take-note")).to_be_visible()
            assert page.url == before_cancel
            page.fill("#comment", TRUE_REASON)
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            expect(page.locator("#take-note")).to_be_hidden()
            expect(page.locator("#save-btn")).not_to_have_class(re.compile(r"\bis-attention\b"))
            page.goto(third)
            take_all = page.locator("#group-take-all")
            expect(take_all).to_be_visible()
            take_all.click()
            expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
            expect(page.locator("#comment")).to_have_value(TRUE_REASON)
            expect(page.locator("#fix")).to_have_value(TRUE_FIX)
            # другой текст: решение сохраняется, но выдать дефект группы приложение отказывает и называет расхождение
            page.fill("#comment", TRUE_REASON + " Проверено на стенде.")
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            watch.allowed_errors.append("status of 409")  # отказ выдачи дефекта – ожидаемый ответ
            page.evaluate("navigator.clipboard.writeText('до отказа')")
            page.click("#copy-defect-bar")
            expect(page.locator("#defect-status")).to_contain_text("решение и текст должны совпадать")
            expect(page.locator("#defect-status")).to_contain_text("другой текст")
            assert clipboard(page) == "до отказа"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_taken_decision_saved_by_copy_clears_the_hint(browser, tmp_path):
    """«Взять решение и текст» у соседа с «Ложным срабатыванием», затем «Скопировать комментарий для Hub»:
    копирование сохраняет решение без отправки формы – подсказка «сохраните» и подсветка снимаются (ревью Codex)."""
    pid, repos = seeded(tmp_path, 2)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            first, second = card_urls(page, pid)
            page.goto(first)
            page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
            page.fill("#comment", FALSE_REASON)
            page.click("#save-btn")
            page.wait_for_url(re.compile(r"ok=saved"))
            page.goto(second)
            page.locator("#group-siblings").get_by_role("button", name="Взять решение и текст").first.click()
            expect(page.locator("#take-note")).to_be_visible()
            expect(page.locator("#comment")).to_have_value(FALSE_REASON)
            page.click("#copy-hub")
            expect(page.locator("#copied-at")).to_contain_text("Скопировано для Hub")
            expect(page.locator("#take-note")).to_be_hidden()
            expect(page.locator("#save-btn")).not_to_have_class(re.compile(r"\bis-attention\b"))
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_legacy_risk_accepted_and_clipboard_refusal(browser, tmp_path):
    """Прежнее решение «Риск принят» показано и просит выбрать заново; без доступа к буферу обмена текст дефекта
    выделяется для ручного копирования, а отметка ставится кнопкой «Скопировал текст дефекта вручную»."""
    pid, repos = seeded(tmp_path, 1, legacy=True)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            expect(page.locator("#legacy-outcome")).to_be_visible()
            expect(page.locator("#legacy-outcome")).to_contain_text("риск принят")
            expect(page.locator("input[name=decision]:checked")).to_have_count(0)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            expect(page.locator("#legacy-outcome")).to_have_count(0)
            # буфер обмена недоступен: запись отклоняется
            # строка-функция вызывается самим evaluate: подмена – внутри обёртки
            # и запасной путь execCommand – тоже без результата
            page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));"
                          " document.execCommand = () => false; }")
            page.click("#copy-defect-bar")
            expect(page.locator("#defect-copied-manually")).to_be_visible()
            selected = page.evaluate("String(window.getSelection())")
            assert TEAM_PHRASE in selected, selected
            page.click("#defect-copied-manually")
            expect(page.locator("#defect-status")).to_contain_text("вручную")
            expect(page.locator("#copied-at")).to_contain_text("Скопировано для Hub")
            watch.allowed_errors.append("denied")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_route_current_step_follows_scroll(ui):
    """Оглавление шагов прилипает к верху и отмечает текущий шаг по прокрутке."""
    page, watch = ui
    pid = create_demo(page)
    run_triage(page, pid)
    open_first_sast(page, pid)
    current = page.locator("#route .route-link[aria-current='step']")
    expect(current).to_have_count(1)
    # шаг из середины (у нижних шагов в конце страницы текущим считается последний)
    page.evaluate("() => window.scrollTo(0, document.getElementById('step-3').getBoundingClientRect().top"
                  " + window.scrollY - document.getElementById('route').offsetHeight - 8)")
    expect(current).to_have_attribute("href", "#step-3")
    expect(page.locator("#route")).to_have_class(re.compile(r"\bis-stuck\b"))
    assert page.evaluate("document.getElementById('route').getBoundingClientRect().top") <= 1
    page.evaluate("() => window.scrollTo(0, 0)")
    expect(current).to_have_attribute("href", "#trace")
    assert not watch.problems(), watch.problems()


def test_stage_after_reload_and_changed_text_after_entered(browser, tmp_path):
    """Этап после перезагрузки: у дефекта прежняя отметка «скопировано» не пропускает копирование текста дефекта
    (до 0.9.6 она могла относиться к короткому тексту). Отметка «Внесено в Hub» по прежнему тексту (сменилось
    название команды) возвращает маршрут к копированию и подтверждению."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            page.click("#copy-defect-bar")
            assert TEAM_PHRASE in wait_clipboard_contains(page, TEAM_PHRASE)
            stage(page).to_have_attribute("data-stage", "mark")
            page.reload()
            expect(page.locator("#copied-at")).to_contain_text("Скопировано для Hub")
            stage(page).to_have_attribute("data-stage", "title")  # после перезагрузки маршрут – с заголовка
            page.click("#copy-title-bar")
            stage(page).to_have_attribute("data-stage", "defect")  # копирование текста дефекта не пропускается
            page.click("#copy-defect-bar")
            stage(page).to_have_attribute("data-stage", "mark")
            page.click("#mark-entered")
            stage(page).to_have_attribute("data-stage", "next")
            expect(step(page, 6)).to_have_class(re.compile(r"\bis-done\b"))
            # название команды сменилось в другой вкладке, карточка открыта: новый текст дефекта – отметка по прежнему
            other = context.new_page()
            other.goto("/settings")
            other.fill("#team-name", "Команда платёжного сервиса")
            other.locator('.settings-form button.btn-primary[value="save"]').click()
            other.wait_for_load_state()
            other.close()
            # заголовок сообщает, что отметка – по другому тексту; тело ещё не скопировано
            page.click("#copy-defect-title")
            expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
            stage(page).to_have_attribute("data-stage", "defect")
            expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
            page.click("#copy-defect-bar")
            assert "Команда платёжного сервиса" in wait_clipboard_contains(page, "Команда платёжного сервиса")
            stage(page).to_have_attribute("data-stage", "mark")
            expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
            expect(page.locator("#mark-entered")).to_be_focused()
            page.click("#mark-entered")
            stage(page).to_have_attribute("data-stage", "next")
            # отметку сняли в другой вкладке: выдача заголовка сообщает это, перенос снова не завершён
            other = context.new_page()
            other.goto(url)
            other.locator("#entered-form button[name='entered'][value='0'], button#unmark-entered").first.click()
            other.wait_for_load_state()
            other.close()
            page.click("#copy-defect-title")
            expect(page.locator("#entered-badge")).to_be_hidden()
            # тот же текст уже скопирован на этой странице – этап «отметить», а не «дальше»
            stage(page).to_have_attribute("data-stage", "mark")
            expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
            # после перезагрузки – предупреждение «текст изменился» и тот же маршрут
            page.goto("/settings")
            page.fill("#team-name", "Команда биллинга")
            page.locator('.settings-form button.btn-primary[value="save"]').click()
            page.wait_for_load_state()
            page.goto(url)
            page.click("#copy-defect-bar")
            assert "Команда биллинга" in wait_clipboard_contains(page, "Команда биллинга")
            page.click("#mark-entered")
            page.goto("/settings")
            page.fill("#team-name", "Команда платёжного сервиса")
            page.locator('.settings-form button.btn-primary[value="save"]').click()
            page.wait_for_load_state()
            page.goto(url)
            expect(page.locator("#entered-changed")).to_be_visible()
            stage(page).to_have_attribute("data-stage", "title")
            expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
            page.click("#copy-defect-bar")  # текст раньше заголовка – сразу к отметке (О2)
            assert "Команда платёжного сервиса" in wait_clipboard_contains(page, "Команда платёжного сервиса")
            stage(page).to_have_attribute("data-stage", "mark")
            page.click("#mark-entered")
            expect(page.locator("#entered-changed")).to_be_hidden()
            stage(page).to_have_attribute("data-stage", "next")
            expect(step(page, 6)).to_have_class(re.compile(r"\bis-done\b"))
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_unmarked_elsewhere_then_body_with_clipboard_refusal(browser, tmp_path):
    """Отметку «Внесено в Hub» сняли в другой вкладке, затем в открытой карточке запросили текст дефекта, а буфер
    обмена отказал: отметка исчезает, этап – копирование, шаг 6 не завершён, доступно ручное копирование."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            page.click("#copy-defect-bar")
            assert TEAM_PHRASE in wait_clipboard_contains(page, TEAM_PHRASE)
            stage(page).to_have_attribute("data-stage", "mark")  # буфер общий между проверками: ждать завершения копирования
            page.click("#mark-entered")
            stage(page).to_have_attribute("data-stage", "next")
            other = context.new_page()
            other.goto(url)
            other.click("#unmark-entered")
            other.wait_for_load_state()
            other.close()
            page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));"
                          " document.execCommand = () => false; }")
            page.click("#copy-defect-bar")
            expect(page.locator("#defect-copied-manually")).to_be_visible()
            expect(page.locator("#entered-badge")).to_be_hidden()
            stage(page).to_have_attribute("data-stage", "defect")
            expect(step(page, 6)).not_to_have_class(re.compile(r"\bis-done\b"))
            page.click("#defect-copied-manually")
            stage(page).to_have_attribute("data-stage", "mark")
            watch.allowed_errors.append("denied")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


@pytest.mark.parametrize("change", ["comment", "later"])
def test_conflict_from_another_tab_makes_reload_the_main_action(browser, tmp_path, change):
    """Решение изменили в другой вкладке (другое обоснование или вовсе «Отложить»): выдача дефекта по прежней
    редакции отклоняется, главная кнопка – «Обновить карточку»; после обновления маршрут продолжается."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            other = context.new_page()
            other.goto(url)
            if change == "later":
                other.locator("label").filter(has=other.locator('input[name="decision"][value="later"]')).click()
            else:
                other.fill("#comment", TRUE_REASON + " Проверено ещё раз.")
            other.click("#save-btn")
            other.wait_for_url(re.compile(r"ok=saved"))
            other.close()
            watch.allowed_errors.append("status of 409")
            page.click("#copy-defect-bar")
            expect(page.locator("#reload-card")).to_be_visible()
            stage(page).to_have_attribute("data-stage", "reload")
            expect(page.locator("#reload-card")).to_have_class(re.compile(r"\bbtn-primary\b"))
            expect(page.locator("#copy-defect-bar")).not_to_have_class(re.compile(r"\bbtn-primary\b"))
            page.click("#reload-card")
            page.wait_for_load_state()
            # обновлённая карточка – с черновиком оператора поверх нового решения (механизм черновика прежний):
            # этап – сохранить своё или взять пришедшее
            expect(page.locator("#reload-card")).to_have_count(0)
            stage(page).to_have_attribute("data-stage", re.compile(r"^(save|defect)$"))
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_low_screen_keeps_save_refusal_in_view(browser, tmp_path):
    """Низкий экран: карточка после отказа сохранения (решение изменили в другой вкладке) открывается на решении
    (У1: «Сохранить» не перебрасывает наверх) – черновик оператора на виду, причина отказа –
    всплывающим сообщением; до 0.9.10 карточка оставалась вверху у плашки отказа."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url, width=1280, height=620)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            assert page.evaluate("window.scrollY") > 0  # обычное открытие на низком экране – к строке срабатывания
            page.evaluate("() => window.scrollTo(0, 0)")
            other = context.new_page()
            other.goto(url)
            save_tp(other, TRUE_REASON, TRUE_FIX)
            other.close()
            watch.allowed_errors.append("status of 409")
            page.locator("label").filter(has=page.locator('input[name="decision"][value="later"]')).click()
            page.click("#save-btn")
            expect(page.locator(".flash-err")).to_have_count(1)
            expect(page.locator("#decision")).to_be_in_viewport()
            expect(page.locator(".toast-err .toast-text")).to_contain_text(
                page.locator(".flash-err").first.text_content().strip()[:40])
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


@pytest.mark.parametrize("size", [(1280, 620), (1440, 900), (1536, 864)])
def test_first_screen_shows_trace_verdict_and_target_line(browser, app_server, size):
    """Основные экраны операторов: на первом экране – сверка, вердикт и не меньше трёх строк кода со строкой
    срабатывания между верхом окна кода и нижней панелью; горизонтальной прокрутки нет."""
    width, height = size
    context, page, watch = open_page(browser, app_server.url, width=width, height=height)
    try:
        pid = create_demo(page)
        run_triage(page, pid)
        open_first_sast(page, pid)
        page.goto(page.url.split("#")[0])
        page.wait_for_timeout(300)
        geometry = page.evaluate("""() => {
          const bar = document.querySelector('.action-bar').getBoundingClientRect();
          const code = document.getElementById('code').getBoundingClientRect();
          const top = Math.max(code.top, 0), bottom = Math.min(code.bottom, bar.top);
          const rows = [...document.querySelectorAll('#code tr')].filter(r => {
            const b = r.getBoundingClientRect(); return b.top >= top - 1 && b.bottom <= bottom + 1; });
          const target = document.querySelector('#code tr.is-target').getBoundingClientRect();
          const seen = el => { const b = el.getBoundingClientRect(); return b.top >= 0 && b.top < bar.top; };
          return { rows: rows.length, targetIn: target.top >= top - 1 && target.bottom <= bottom + 1,
                   trace: seen(document.getElementById('trace')), verdict: seen(document.querySelector('.verdict-big')),
                   wide: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1 };
        }""")
        assert geometry["targetIn"] and geometry["rows"] >= 3, geometry
        assert geometry["trace"] and geometry["verdict"] and not geometry["wide"], geometry
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_title_copied_then_number_changed_brings_back_the_title_stage(browser, tmp_path):
    """О2: заголовок скопирован, номер дефекта сменили, затем скопировали текст – в Hub остался прежний заголовок,
    поэтому следующий этап – снова «Скопировать заголовок», а не отметка."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            stage(page).to_have_attribute("data-stage", "title")
            page.click("#copy-title-bar")
            stage(page).to_have_attribute("data-stage", "defect")
            page.fill("#defect-number", "77")
            page.click("#copy-defect-bar")
            assert TRUE_REASON in wait_clipboard_contains(page, TRUE_REASON)
            stage(page).to_have_attribute("data-stage", "title")
            page.click("#copy-title-bar")
            assert "ID77" in wait_clipboard_contains(page, "ID77")
            stage(page).to_have_attribute("data-stage", "mark")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_title_number_back_to_the_copied_one_is_not_stale(browser, tmp_path):
    """О2: заголовок скопирован с номером N, номер сменили и вернули (N → 77 → N) – в Hub лежит заголовок с N, поэтому
    после копирования текста этап – отметка, а не повтор заголовка."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            page.click("#copy-title-bar")
            stage(page).to_have_attribute("data-stage", "defect")
            first = page.input_value("#defect-number")
            assert first and first != "77"
            page.fill("#defect-number", "77")
            page.click("#copy-defect-bar")
            assert TRUE_REASON in wait_clipboard_contains(page, TRUE_REASON)
            stage(page).to_have_attribute("data-stage", "title")
            page.evaluate("navigator.clipboard.writeText('перед возвратом номера')")
            page.fill("#defect-number", first)
            page.click("#copy-defect-bar")
            assert TRUE_REASON in wait_clipboard_contains(page, TRUE_REASON)
            stage(page).to_have_attribute("data-stage", "mark")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_manual_title_copy_after_clipboard_refusal_advances_the_route(browser, tmp_path):
    """О2: буфер отказал при копировании заголовка – заголовок выделен; Ctrl+C по нему подтверждает заголовок, и
    маршрут переходит к копированию текста дефекта."""
    pid, repos = seeded(tmp_path, 1)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_triage(page, pid)
            (url,) = card_urls(page, pid)
            page.goto(url)
            save_tp(page, TRUE_REASON, TRUE_FIX)
            stage(page).to_have_attribute("data-stage", "title")
            page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('denied'));"
                          " document.execCommand = () => false; }")
            page.click("#copy-title-bar")
            expect(page.locator("#defect-status")).to_contain_text("Ctrl+C")
            assert "ID" in page.evaluate("String(window.getSelection())")
            stage(page).to_have_attribute("data-stage", "title")
            # часть заголовка – не подтверждение: этап остаётся «Скопировать заголовок»
            page.evaluate("""() => { const box = document.getElementById('defect-title-text');
              const range = document.createRange(); range.setStart(box.firstChild, 0); range.setEnd(box.firstChild, 3);
              const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); }""")
            page.keyboard.press("Control+c")
            page.wait_for_timeout(300)
            stage(page).to_have_attribute("data-stage", "title")
            page.evaluate("""() => { const box = document.getElementById('defect-title-text');
              const range = document.createRange(); range.selectNodeContents(box);
              const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); }""")
            page.keyboard.press("Control+c")
            stage(page).to_have_attribute("data-stage", "defect")
            expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
            watch.allowed_errors.append("denied")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


@pytest.mark.parametrize("size", [(1600, 790), (1280, 620)])
def test_code_stays_beside_the_model_reasoning(browser, app_server, size):
    """Код шага 3 – в левой колонке под сверкой, рядом с разбором модели; при прокрутке
    длинного разбора код остаётся на экране (закреплён), щелчок по «строка N» в разборе показывает строку в окне кода и не
    сдвигает страницу."""
    width, height = size
    context, page, watch = open_page(browser, app_server.url, width=width, height=height)
    try:
        pid = create_demo(page)
        run_triage(page, pid)
        open_first_sast(page, pid)
        page.goto(page.url.split("#")[0])
        details = page.locator("#verdict-more")
        if details.count() and not details.evaluate("el => el.open"):
            details.locator("summary").click()
        box = page.evaluate("""() => {
          const r = id => document.getElementById(id).getBoundingClientRect();
          return { code: r('step-3'), verdict: r('step-2'), trace: r('trace') };
        }""")
        assert box["code"]["right"] <= box["verdict"]["left"] + 1, box
        assert abs(box["code"]["left"] - box["trace"]["left"]) <= 1 and box["code"]["top"] >= box["trace"]["bottom"], box
        # длинный разбор (как у настоящей модели): правая колонка втрое выше окна
        page.evaluate("""() => { const pad = document.createElement('div'); pad.id = 'tall-reasoning';
          pad.style.height = (window.innerHeight * 3) + 'px'; document.getElementById('step-2').appendChild(pad); }""")
        route_h = page.evaluate("document.getElementById('route').offsetHeight")
        for part in (0.25, 0.5):
            page.evaluate(f"""() => {{ const v = document.getElementById('step-2');
              const top = v.getBoundingClientRect().top + window.scrollY;
              window.scrollTo(0, top + v.offsetHeight * {part} - window.innerHeight / 2); }}""")
            page.wait_for_timeout(150)
            top = page.evaluate("document.getElementById('step-3').getBoundingClientRect().top")
            assert route_h - 1 <= top <= route_h + 40, (part, top, route_h)
        # у конца разбора код уходит вверх вместе с ним и не выходит за низ правой колонки
        page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(150)
        assert page.evaluate("document.getElementById('step-3').getBoundingClientRect().bottom"
                             " <= document.getElementById('step-2').getBoundingClientRect().bottom + 1")
        page.evaluate("() => { const v = document.getElementById('step-2');"
                      " window.scrollTo(0, v.getBoundingClientRect().top + window.scrollY + v.offsetHeight * 0.4); }")
        page.wait_for_timeout(150)
        # «строка N» из разбора при закреплённом коде: подсвечена именно её строка, она видна, страница не сдвигается
        link = page.locator("#step-2 a.line-ref").first
        expect(link).to_have_count(1)
        n = link.evaluate("el => el.getAttribute('data-line') || el.getAttribute('href').replace('#L', '')")
        page.evaluate("""() => { const pad = document.getElementById('tall-reasoning'); pad.remove();
          const more = document.getElementById('verdict-more'); more.insertBefore(pad, more.children[1]); }""")
        link.scroll_into_view_if_needed()  # человек щёлкает видимую ссылку; Playwright прокрутил бы к ней сам
        page.wait_for_timeout(150)
        top = page.evaluate("document.querySelector('#step-3 .code').getBoundingClientRect().top")
        assert top <= height * 0.6, top  # код закреплён у верха окна
        before = page.evaluate("window.scrollY")
        link.click()
        page.wait_for_timeout(700)
        assert abs(page.evaluate("window.scrollY") - before) <= 2
        seen = page.evaluate(f"""() => {{ const row = document.getElementById('L{n}');
          const c = document.querySelector('#step-3 .code').getBoundingClientRect();
          const bar = document.querySelector('.action-bar').getBoundingClientRect().top;
          const b = row.getBoundingClientRect();
          return {{ok: row.classList.contains('is-flash') && b.top >= c.top - 1 && b.bottom <= c.bottom + 1
                      && b.top >= 0 && b.bottom <= bar + 1, row: [b.top, b.bottom], box: [c.top, c.bottom], bar}}; }}""")
        assert seen["ok"], (seen, width)
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")
        shots = os.environ.get("E2E_SHOTS")  # снимок для глаз разработчика, по желанию
        if shots:
            page.screenshot(path=os.path.join(shots, f"card-layout-{width}.png"))
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
