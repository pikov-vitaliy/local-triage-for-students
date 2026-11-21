"""Сквозной сценарий в браузере на демо-данных и поддельной модели: демо-проект → находки → триаж → карточка →
согласие → «Проверено» → «Скопировать для Hub» → «Внесено в Hub» → вопрос к модели → SCA: переход в «Компоненты»
и комплект задания вместо прежнего пакета (прежние адреса 410) → прежний импорт ответов → карточка SCA →
повторный импорт сохраняет решения и отметки."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import DEMO_SCA_EXPLANATION, save_sca_decision, sca_set_text_ready, DEMO_ANSWERS, DEMO_REPORT_V2, clipboard, create_demo, finding_id_from, run_triage  # noqa: E402

pytestmark = pytest.mark.e2e

# В комплекте задания не должно быть ничего, кроме библиотек, версий и идентификаторов уязвимостей
NOT_IN_PACKAGE = ("billing-core", "catalog-api", "Catalog_API", "notify-gateway", ".java", "src/main", "catalog_api",
                  "100101", "200201", "200202", "200203", "200204")


def test_demo_project_from_triage_to_reimport(ui, tmp_path: Path):
    page, watch = ui
    pid = create_demo(page)
    expect(page.locator(".flash-ok")).to_contain_text("Демо-проект создан")
    expect(page.locator("#step2")).to_contain_text("billing-core")

    # Находки: 15 SAST, вкладки проекта, отбор «Непроверенные»
    page.get_by_role("link", name=re.compile(r"^Находки")).first.click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/findings$"))
    expect(page.locator("nav.tabs a[aria-current=page]")).to_contain_text("Находки")
    expect(page.locator("table.table-findings tbody tr")).to_have_count(21)
    # Фильтры чипами: «Вид: SAST», «Проверено: нет»; кодовая база – списком, отбор применяется сразу
    page.locator("details.filters-more summary").click()  # подробные фильтры свёрнуты, пока ничего не выбрано
    page.locator(".filter-group", has=page.locator("#filter-kind")).get_by_role(
        "link", name="SAST", exact=True).click()
    expect(page).to_have_url(re.compile(r"\?kind=SAST$"))
    page.locator(".filter-group", has=page.locator("#filter-reviewed")).get_by_role(
        "link", name="нет", exact=True).click()
    expect(page).to_have_url(re.compile(r"\?kind=SAST&reviewed=no$"))
    expect(page.locator("table.table-findings tbody tr")).to_have_count(15)
    page.select_option("#filter-cb", "billing-core")
    expect(page).to_have_url(re.compile(r"cb=billing-core"))
    expect(page.locator("table.table-findings tbody tr")).to_have_count(9)
    page.get_by_role("link", name="Сбросить фильтры").click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/findings$"))

    # Триаж всех SAST поддельной моделью
    run_triage(page, pid)
    expect(page.locator("#progress-text")).to_contain_text("Обработано 15 из 15")

    # Карточка первой непроверенной: объяснение для человека, ссылки на строки, чек-лист, словарик
    page.goto(f"/projects/{pid}/continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))
    fid = finding_id_from(page.url)
    expect(page.locator(".verdict-big")).to_be_visible()
    expect(page.locator(".verdict-panel")).to_contain_text("Что делает код")
    expect(page.locator(".verdict-panel")).to_contain_text("Почему такой вердикт")
    expect(page.locator("#check-by-eye li")).to_have_count(2)
    page.locator("#verdict-more summary").click()  # подробности разбора свёрнуты
    ref = page.locator(".verdict-panel a.line-ref").first
    line = re.search(r"\d+", ref.inner_text()).group(0)
    ref.click()
    expect(page.locator(f"tr#L{line}")).to_have_class(re.compile(r"\bis-flash\b"))
    page.locator("#glossary summary").click()
    expect(page.locator("#glossary dl.terms")).to_contain_text("срабатывание")
    # длинный термин-код не сжимает пояснение в столбик по букве
    widths = page.evaluate("""() => {
      const dl = document.querySelector('#glossary dl.terms');
      dl.querySelector('dt').innerHTML = '<code>' + 'req.body.email.'.repeat(12) + '</code>';
      return [dl.querySelector('dd').getBoundingClientRect().width, dl.getBoundingClientRect().width];
    }""")
    assert widths[1] > 0 and widths[0] >= widths[1] * 0.45, widths

    # Ложное срабатывание (n), «Проверено» (v снимает и ставит), копирование (c), «Внесено в Hub» (h)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("n")
    expect(page.locator('input[name="decision"][value="false_positive"]')).to_be_checked()
    expect(page.locator("#reviewed-box")).to_be_checked()
    page.keyboard.press("v")
    expect(page.locator("#reviewed-box")).not_to_be_checked()
    expect(page.locator("#unreviewed-note")).to_be_visible()
    page.keyboard.press("v")
    expect(page.locator("#reviewed-box")).to_be_checked()
    page.fill("#comment", "Значение берётся из заранее заданной строки.")
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("c")
    expect(page.locator("#mark-entered")).to_be_visible()
    expect(page.locator("#reviewed-badge")).to_be_visible()
    copied = clipboard(page)
    assert copied.strip() == (page.locator("#hub-text").text_content() or "").strip()  # блок свёрнут
    assert copied == "Значение берётся из заранее заданной строки.", copied
    expect(page.locator("#mark-entered")).to_be_focused()
    page.keyboard.press("h")
    expect(page.locator("#entered-badge")).to_be_visible()
    expect(page.locator("#entered-note")).to_be_visible()
    expect(page.locator("#mark-entered")).to_be_hidden()
    expect(page.locator("#next-btn")).to_be_focused()

    # После перезагрузки отметки на месте; «Скопировать для Hub» сам «Внесено» не ставил – это сделала клавиша h
    page.reload()
    expect(page.locator("#entered-badge")).to_be_visible()
    expect(page.locator("#reviewed-badge")).to_be_visible()

    # Вопрос к модели: ответ появляется в карточке и остаётся у находки
    page.locator("#ask summary").click()  # «Вопросы к модели» в необязательном шаге 4 свёрнуты
    page.fill("#ask-question", "А если значение приходит из сессии, а не из запроса?")
    page.click("#ask-btn")
    page.wait_for_url(re.compile(r"ok=asked"))
    answer = page.locator("#qa-list li.qa-item").last
    expect(answer).to_contain_text("А если значение приходит из сессии")
    expect(answer.locator(".qa-a")).to_contain_text("проверки всё равно нет")
    expect(answer.locator(".qa-meta")).to_contain_text("ток/с")

    # Список: отбор «Внесено в Hub: да» – ровно эта находка
    page.goto(f"/projects/{pid}/findings?entered=yes")
    rows = page.locator("table.table-findings tbody tr")
    expect(rows).to_have_count(1)
    expect(rows.first.locator("a").first).to_have_attribute("href", re.compile(rf"/findings/{fid}\b"))

    # SCA: прежняя таблица библиотек и переход в новый раздел «Компоненты»
    page.goto(f"/projects/{pid}")
    page.locator("nav.tabs").get_by_role("link", name=re.compile(r"^SCA")).click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/sca$"))
    expect(page.locator("#component-research")).to_contain_text("Исследование компонентов")
    # Прежний исходящий пакет отменён: его адреса отвечают 410, комплект задания собирается в новом разделе
    for suffix in ("package.zip", "components.csv", "components.json"):
        response = page.request.get(f"/projects/{pid}/sca/{suffix}")
        assert response.status == 410, suffix
    page.locator("#component-research").get_by_role("link", name=re.compile("компоненты", re.IGNORECASE)).click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/components$"))
    page.click("#build-task")
    page.wait_for_url(re.compile(r"ok=task"))
    with page.expect_download() as download:
        page.click("#download-task")
    kit = tmp_path / "sca-components.zip"
    download.value.save_as(kit)
    with zipfile.ZipFile(kit) as archive:
        assert sorted(archive.namelist()) == ["answer.schema.json", "answer.template.json", "components.json",
                                              "manifest.json", "task.md", "validate.py"]
        for name in archive.namelist():
            text = archive.read(name).decode("utf-8")
            assert not any(word in text for word in NOT_IN_PACKAGE), (name, text)

    # Прежний импорт ответов первой версии продолжает работать
    page.goto(f"/projects/{pid}/sca")
    page.set_input_files("#answers-file", str(DEMO_ANSWERS))
    expect(page.locator(".dropzone-file").first).to_contain_text("sca-answers.json")
    page.click("#answers-submit")
    page.wait_for_url(re.compile(r"ok=sca_answers"))
    expect(page.locator(".flash-ok")).to_contain_text("Ответы сохранены: 3")
    expect(page.locator("#sca-table")).to_contain_text("обновить")

    # Карточка SCA: согласен с агентом (a), копирование (c), «Внесено в Hub» (h)
    page.click("#sca-continue")
    page.wait_for_url(re.compile(rf"/projects/{pid}/sca/findings/\d+(?:\?.*)?$"))
    sca_fid = finding_id_from(page.url)
    expect(page.locator("#agent-conclusion")).to_contain_text("обновить")
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("a")
    expect(page.locator('input[name="decision"][value="agree"]')).to_be_checked()
    save_sca_decision(page)
    expect(page.locator("#copy-hub")).to_be_hidden()  # у «Обновить» короткого текста нет: дефект – по тексту набора
    sca_set_text_ready(page, DEMO_SCA_EXPLANATION)
    expect(page.locator("#copy-defect-bar")).to_be_visible()
    page.click("#copy-defect-bar")
    expect(page.locator("#copy-status")).to_contain_text("Полный текст дефекта скопирован")
    sca_text = clipboard(page)
    assert "Обновление" in sca_text and "2.3.9" in sca_text, sca_text
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("h")  # «Дефект создан в Hub» – по тексту набора
    expect(page.locator("#entered-badge")).to_be_visible()

    # Повторный импорт: вторая демо-выгрузка из репозитория – без 100115, с новой 100116, у 100105 другая строка
    page.goto(f"/projects/{pid}#step1")
    page.locator("details.reupload summary").click()
    page.set_input_files("details.reupload input[type=file]", str(DEMO_REPORT_V2))
    page.locator("details.reupload").get_by_role("button", name="Загрузить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=imported"))
    summary = page.locator("#step1")
    expect(summary).to_contain_text("новых 1")
    expect(summary).to_contain_text("исчезло 1")
    expect(summary).to_contain_text("изменилось 1")
    expect(page.locator(".review-summary")).to_contain_text("Нет в новой выгрузке")

    # Решения и отметки по совпадающим ID сохранились – и у SAST, и у SCA
    page.goto(f"/projects/{pid}/findings/{fid}")
    expect(page.locator("#reviewed-badge")).to_be_visible()
    expect(page.locator("#entered-badge")).to_be_visible()
    expect(page.locator('input[name="decision"][value="false_positive"]')).to_be_checked()
    page.goto(f"/projects/{pid}/sca/findings/{sca_fid}")
    expect(page.locator("#reviewed-badge")).to_be_visible()
    expect(page.locator("#entered-badge")).to_be_visible()

    # Исчезнувшая находка – с пометкой, новая – в списке
    page.goto(f"/projects/{pid}/findings?missing=yes")
    missing = page.locator("table.table-findings tbody tr")
    expect(missing).to_have_count(1)
    expect(missing.first).to_contain_text("100115")
    expect(missing.first).to_contain_text("нет в выгрузке")
    page.goto(f"/projects/{pid}/findings?kind=SAST&reviewed=no")
    expect(page.locator("table.table-findings")).to_contain_text("100116")
    assert not watch.problems(), watch.problems()
