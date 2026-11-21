"""Этап 3 в браузере на демо-данных и поддельной модели: статусы Hub по-русски, «Риск принят» только
с обоснованием, «Дефект для Hub» – копирование заголовка и текста (SAST и SCA), страница «Справочники» с загрузкой
выдуманного фида и сведения БДУ ФСТЭК России и CWE в карточках."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_SCA_EXPLANATION, save_sca_decision, sca_set_text_ready, DEMO_ANSWERS, clipboard, create_demo, run_triage  # noqa: E402
from feed_fixtures import bdu_zip, cwe_zip  # noqa: E402

pytestmark = pytest.mark.e2e


def open_first_sast(page, pid: int) -> None:
    run_triage(page, pid)
    page.goto(f"/projects/{pid}/continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))


def save_review(page) -> None:
    page.locator("#review-form button[value=save]").click()
    page.wait_for_url(re.compile(r"ok=saved"))


def test_statuses_two_outcomes_and_sast_defect(ui):
    """Два решения SAST (ADR-0089): ложное срабатывание – комментарий, подтверждённый дефект – заголовок и текст."""
    page, watch = ui
    # обязательное обоснование сервер проверяет сам (400) – браузер пишет это в консоль, так и задумано
    watch.allowed_errors.append("status of 400")
    pid = create_demo(page)
    open_first_sast(page, pid)
    legend = page.locator("#status-legend")
    expect(legend).to_contain_text("«Ложное срабатывание» – в Hub статус «Ложное срабатывание»")
    expect(legend).to_contain_text("«Подтверждаю дефект» – в Hub")
    expect(legend).not_to_contain_text("Риск принят")
    expect(page.locator("#defect-panel")).to_be_hidden()
    expect(page.locator('input[name="decision"][value="risk_accepted"]')).to_have_count(0)

    # Ложное срабатывание (клавиша n): курсор остаётся на выборе; без обоснования не сохраняется
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("n")
    expect(page.locator('input[name="decision"][value="false_positive"]')).to_be_checked()
    expect(page.locator("#comment")).not_to_be_focused()
    page.fill("#comment", "")
    page.click("#copy-hub")
    expect(page.locator("#copy-status")).to_contain_text("нужен комментарий")
    expect(page.locator("#comment")).to_be_focused()
    page.fill("#comment", "Значение берётся из заранее заданной строки, подстановки извне нет.")
    page.click("#copy-hub")
    expect(page.locator("#copy-status")).to_contain_text("комментарий скопирован")
    assert clipboard(page) == "Значение берётся из заранее заданной строки, подстановки извне нет."
    expect(page.locator("#defect-panel")).to_be_hidden()  # для ложного срабатывания дефект не готовится

    # Подтверждаю дефект: после сохранения появляется «Дефект для Hub», заголовок и текст копируются
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("y")
    expect(page.locator('input[name="decision"][value="true_positive"]')).to_be_checked()
    expect(page.locator("#copy-hub")).to_be_hidden()
    page.fill("#comment", "Значение из запроса попадает в SQL без параметров.")
    page.fill("#fix", "Передавать значение параметром запроса.")
    save_review(page)
    expect(page.locator("#defect-panel")).to_be_visible()
    expect(page.locator("#defect-number")).to_have_value("1")
    page.click("#copy-defect-title")
    expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
    assert re.fullmatch(r"ID1 - .+ \(SAST\)", clipboard(page))
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
    body = clipboard(page)
    assert body.startswith("После тщательного анализа уязвимости команда Платформа приняла решение присвоить данной "
                           "уязвимости категорию True Positive.\n\nОбоснование:\n")
    assert "\nОбоснование:\nЗначение из запроса попадает в SQL без параметров.\n" in body
    assert body.endswith("Рекомендация:\n1) Передавать значение параметром запроса.")
    # пока решение не сохранено, дефект не копируется
    page.fill("#comment", "Другой текст.")
    page.click("#copy-defect-title")
    expect(page.locator("#defect-status")).to_contain_text("Сначала сохраните решение")
    # ссылка на строку, которой нет в показанном коде: дефект – только после отметки «Предупреждения проверены»
    watch.allowed_errors.append("status of 409")
    page.fill("#comment", "Значение попадает в запрос (строка 999999).")
    save_review(page)
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("999999")
    expect(page.locator("#defect-confirm-row")).to_be_visible()
    page.check("#defect-confirm")
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
    assert "строка 999999" in clipboard(page)


def test_feeds_upload_and_sca_defect_with_bdu(ui, tmp_path: Path):
    page, _ = ui
    # Страница «Справочники»: выдуманные фиды того же формата
    page.goto("/feeds")
    expect(page.locator("main")).to_contain_text("БДУ ФСТЭК России")
    page.set_input_files("#feed-bdu-file", str(bdu_zip(tmp_path / "vulxml.zip")))
    page.locator("#feed-bdu form button[type=submit]").click()
    page.wait_for_url(re.compile(r"/feeds"))
    expect(page.locator("#feed-bdu-records")).to_have_text("2", timeout=30000)  # страница обновится сама
    expect(page.locator("main")).not_to_contain_text("Файл получен. Идёт разбор")
    page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_latest.xml.zip")))
    page.locator("#feed-cwe form button[type=submit]").click()
    expect(page.locator("#feed-cwe-records")).to_have_text("3", timeout=30000)
    expect(page.locator("#feed-job")).to_contain_text("Готово: Каталог CWE загружен")
    expect(page.locator("#feed-cwe-state")).to_contain_text("Загружен и работает")

    # Ошибка фоновой загрузки тоже убирает прежнее сообщение о ходе работы; старый справочник остаётся.
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    page.set_input_files("#feed-bdu-file", str(bad))
    page.locator("#feed-bdu form button[type=submit]").click()
    expect(page.locator("#feed-job")).to_contain_text("не архив ZIP", timeout=30000)
    expect(page.locator("main")).not_to_contain_text("Файл получен. Идёт разбор")
    expect(page.locator("#feed-bdu-records")).to_have_text("2")

    pid = create_demo(page)
    page.goto(f"/projects/{pid}/sca#answers")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    page.click("#sca-continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))
    # Карточка SCA обогащена записями БДУ по CVE (CVE-2099-10002 – из ответа агента для AST-2026-000101)
    expect(page.locator("#bdu-records")).to_contain_text("BDU:2099-00001")
    expect(page.locator("#bdu-records")).to_contain_text("Способ устранения")
    expect(page.locator("#defect-panel")).to_be_hidden()
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("a")
    save_sca_decision(page)  # пакетное решение (0.9.8): обе находки версии получают «Обновить» и входят в набор
    expect(page.locator("#copy-hub")).to_be_hidden()  # у «Обновить» короткого текста нет (ADR-0091 п. 3)
    expect(page.locator("#sca-set-members")).to_contain_text("200201, 200202")
    # заготовка Объяснения – из БДУ по CVE; оператор проверяет её и сохраняет текст набора
    expect(page.locator("#package-explanation")).to_have_value(re.compile("CVE-2099-10002: "))
    sca_set_text_ready(page, DEMO_SCA_EXPLANATION)
    expect(page.locator("#defect-panel")).to_be_visible()
    page.click("#copy-defect-title")
    expect(page.locator("#defect-status")).to_contain_text("Заголовок дефекта скопирован")
    assert clipboard(page) == "ID1 - org.example.thirdparty:example-xml-parser | Component version: 2.3.1 (SCA)"
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
    body = clipboard(page)
    assert body.startswith("Описание\n"), body
    assert "CVE-2099-10002 (https://nvd.nist.gov/vuln/detail/CVE-2099-10002)" in body
    assert "CVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)" in body
    assert "\nОбъяснение\nCVE-2099-10002: Парсер по умолчанию" in body
    assert "\nРекомендации\nОбновление org.example.thirdparty:example-xml-parser до версии 2.3.9\n" in body
    assert "\nИсточники\nhttps://nvd.nist.gov/vuln/detail/" in body
    for banned in ("Заключение", "Сводка", "200201", "----------"):  # шаблон команды, без прежнего формата
        assert banned not in body, banned
    # текст набора один на версию компонента: из карточки второй находки – тот же дефект
    page.locator("#siblings a").first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))
    expect(page.locator("#defect-panel")).to_be_visible()
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
    assert clipboard(page) == body

    # Карточка SAST: класс уязвимости из каталога CWE
    open_first_sast(page, pid)
    expect(page.locator("#cwe-info")).to_be_visible()


def test_hub_report_with_hyperlink_formulas_imports(ui, tmp_path: Path):
    """Настоящая выгрузка Hub хранит номер находки, систему и AST-идентификатор формулами HYPERLINK: она принимается,
    а книга с другой формулой в колонке номера отклоняется понятным сообщением."""
    from test_hub_hyperlinks import SAST_PART, _real_like, link_cell, put

    page, watch = ui
    watch.allowed_errors.append("status of 400")  # отказ по формуле – ответ 400, так и задумано
    page.goto("/")
    page.fill('#new-project input[name="name"]', "Ссылки HYPERLINK")
    page.locator("#new-project").get_by_role("button", name="Создать", exact=True).click()
    page.wait_for_url(re.compile(r"/projects/\d+\?ok=created"))
    pid = int(re.search(r"/projects/(\d+)", page.url).group(1))

    bad = _real_like(tmp_path / "bad")
    put(bad, SAST_PART, {"A2": link_cell("A2", "510001", formula='HYPERLINK("https://hub.example.org/1",A1)')})
    page.set_input_files("input[type=file][name=file]", str(bad))
    page.get_by_role("button", name="Загрузить", exact=True).click()
    expect(page.locator("main")).to_contain_text("формулы в колонках")
    expect(page.locator("main")).to_contain_text("Формулы HYPERLINK")

    good = _real_like(tmp_path / "good")
    page.goto(f"/projects/{pid}")
    page.set_input_files("input[type=file][name=file]", str(good))
    page.get_by_role("button", name="Загрузить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=imported"))
    page.goto(f"/projects/{pid}/findings")
    expect(page.locator("table.table-findings tbody tr")).to_have_count(8)
    expect(page.locator("table.table-findings")).to_contain_text("510001")


def test_hub_report_with_shared_string_values_imports(ui, tmp_path: Path):
    """Настоящие полные выгрузки Hub хранят значение формулы HYPERLINK индексом общей строки (t="s"): такая книга
    принимается, а книга, где текст общей строки расходится с текстом ссылки, отклоняется понятным сообщением."""
    from test_hub_shared_formulas import shared_book, simple

    page, watch = ui
    watch.allowed_errors.append("status of 400")
    page.goto("/")
    page.fill('#new-project input[name="name"]', "Общие строки")
    page.locator("#new-project").get_by_role("button", name="Создать", exact=True).click()
    page.wait_for_url(re.compile(r"/projects/\d+\?ok=created"))
    pid = int(re.search(r"/projects/(\d+)", page.url).group(1))

    bad = shared_book(tmp_path / "bad", item=lambda text: simple(text + "X"))
    page.set_input_files("input[type=file][name=file]", str(bad))
    page.get_by_role("button", name="Загрузить", exact=True).click()
    expect(page.locator("main")).to_contain_text("формулы в колонках")

    good = shared_book(tmp_path / "good")
    page.goto(f"/projects/{pid}")
    page.set_input_files("input[type=file][name=file]", str(good))
    page.get_by_role("button", name="Загрузить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=imported"))
    page.goto(f"/projects/{pid}/findings")
    expect(page.locator("table.table-findings tbody tr")).to_have_count(8)
    expect(page.locator("table.table-findings")).to_contain_text("510001")


def test_defect_text_blocked_after_the_finding_changed(ui):
    """LTA-001 в браузере: после повторного импорта с изменённой находкой карточка говорит, что дефект не готовится,
    и копирование текста дефекта отказывает."""
    from e2e_support import DEMO_REPORT_V2, finding_id_from

    page, watch = ui
    watch.allowed_errors.append("status of 409")  # отказ выдать устаревший текст – ответ 409, так и задумано
    pid = create_demo(page)
    open_first_sast(page, pid)
    # находка 100105 меняется во второй выгрузке: решение по ней должно перестать давать текст дефекта
    page.goto(f"/projects/{pid}/findings")
    page.get_by_role("link", name="100105").click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))
    fid = finding_id_from(page.url)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("y")
    page.fill("#comment", "Значение из запроса попадает в разметку.")
    page.fill("#fix", "Экранировать значение перед выводом.")
    save_review(page)
    expect(page.locator("#defect-panel")).to_be_visible()
    page.click("#copy-defect-body")
    expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")

    page.goto(f"/projects/{pid}#step1")
    page.locator("details.reupload summary").click()
    page.set_input_files("details.reupload input[type=file]", str(DEMO_REPORT_V2))
    page.locator("details.reupload").get_by_role("button", name="Загрузить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=imported"))

    page.goto(f"/projects/{pid}/findings/{fid}")
    expect(page.locator("#defect-blocked")).to_contain_text("Дефект для Hub не готовится")
    expect(page.locator("#defect-panel")).to_be_hidden()
    page.goto(f"/projects/{pid}/findings/{fid}")
    status = page.evaluate("""async () => {
        const body = new URLSearchParams({number: "", confirm: "1"});
        const r = await fetch(window.location.pathname + "/defect", {method: "POST", body,
            headers: {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}});
        const data = await r.json();
        return [r.status, data.detail || ""];
    }""")
    assert status[0] == 409 and "прежней версии находки" in status[1], status


def test_copy_button_does_not_copy_without_the_servers_permission(ui):
    """LTA-001: ответ сервера без copy_allowed (находка исчезла, ответ повреждён) в буфер не копируется."""
    page, _ = ui
    pid = create_demo(page)
    open_first_sast(page, pid)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("n")
    page.fill("#comment", "Значение берётся из константы.")
    page.evaluate("navigator.clipboard.writeText('БУФЕР-ДО')")
    page.route("**/review", lambda route: route.fulfill(
        status=200, content_type="application/json", body='{"ok": true, "hub_text": "ЧУЖОЙ-ТЕКСТ"}'))
    page.click("#copy-hub")
    expect(page.locator("#copy-status")).to_contain_text("не скопирован")
    assert clipboard(page) == "БУФЕР-ДО"
