"""Таблица SCA в браузере: компактная строка и раскрытие длинных списков, отбор по оценке чипами и границами,
числовая сортировка по заголовку CVSS, сброс – на настольной ширине и на 390 px, в обеих темах.

Данные – таблица .csv с длинными перечнями (десять идентификаторов, двенадцать CWE, шесть находок) и оценками
разных версий: так проверяется, что раскрытие не теряет ссылки, а версия берётся из отчёта.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page, project_id_from  # noqa: E402

pytestmark = pytest.mark.e2e

COLUMNS = ["Issue id", "Application", "Type", "Component name", "Component version", "CVSS score", "CVE id",
           "Codebase", "CWE ID", "CVSS vector"]
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
LONG_IDS = ", ".join(f"CVE-2099-{n:05d}" for n in range(70010, 70030))
LONG_CWES = ", ".join(str(200 + n) for n in range(12))


def write_report(path: Path) -> Path:
    """Таблица выгрузки: длинная библиотека со многими находками и три коротких с разными баллами."""
    lines = [";".join(COLUMNS)]
    rows = [[f"900{n:02d}", "Demo Library", "maven", "lib-long", "1.0.0", f"{7 + n / 2:.1f}", LONG_IDS,
             "core-a" if n != 3 else "core-b", LONG_CWES, V31] for n in range(6)]
    rows += [
        ["91001", "Demo Library", "maven", "lib-seven", "2.0.0", "7.0", "CVE-2099-91001", "core-a", "611", V31],
        ["91002", "Demo Library", "maven", "lib-low", "3.0.0", "3.9", "CVE-2099-91002", "core-b", "1333", V40],
        ["91003", "Demo Library", "maven", "lib-none", "4.0.0", "-", "CVE-2099-91003", "core-b", "20", "-"],
        ["91004", "Demo Library", "maven", "lib-mid", "5.0.0", "6.9", "CVE-2099-91004", "core-a", "89", V40],
        # балл без вектора и без колонки с версией: версия остаётся неизвестной
        ["91005", "Demo Library", "maven", "lib-plain", "6.0.0", "6.0", "CVE-2099-91005", "core-b", "89", "-"]]
    lines += [";".join(row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def make_project(page, report: Path) -> int:
    """Новый проект с загруженной таблицей."""
    page.goto("/")
    page.fill("form.inline-form input[name=name]", "Отбор по оценке")
    page.click("form.inline-form button[type=submit]")
    page.wait_for_url(re.compile(r"/projects/\d+"))
    pid = project_id_from(page.url)
    page.set_input_files("#step1 input[type=file]", str(report))
    page.click("#step1 form.upload-form button[type=submit]")
    page.wait_for_url(re.compile(r"ok=imported"))
    return pid


def rows(page) -> "list[str]":
    return page.eval_on_selector_all("#sca-table tbody tr", "rows => rows.map(r => r.dataset.component)")


def row_scores(page) -> "list[str]":
    return page.eval_on_selector_all(
        "#sca-table tbody tr", "rows => rows.map(r => (r.querySelector('.cvss') || {}).textContent || '-')")


def test_sca_table_stays_compact_and_opens_full_lists(ui, tmp_path: Path):
    page, watch = ui
    pid = make_project(page, write_report(tmp_path / "cvss.csv"))
    page.goto(f"/projects/{pid}/sca")
    expect(page.locator("#sca-table tbody tr")).to_have_count(6)

    # закрытая строка длинной библиотеки не растянута: всё лишнее под раскрытием
    row = page.locator('#sca-table tbody tr[data-component="lib-long"]')
    expect(row.locator("td[data-label='Уязвимости'] .compact-preview .mono")).to_have_count(2)
    expect(row.locator("details.compact")).to_have_count(3)
    expect(row).to_contain_text("Показать все 20")
    height_closed = row.evaluate("r => r.getBoundingClientRect().height")
    assert height_closed < 320, height_closed

    # раскрытие с клавиатуры: подпись раскрывает список, все ссылки и идентификаторы на месте
    summary = row.locator("td[data-label='Уязвимости'] summary")
    summary.focus()
    page.keyboard.press("Enter")
    expect(summary.locator("xpath=..")).to_have_attribute("open", "")
    # раскрытый список – весь перечень, а сокращённая строка над ним скрыта; номера не переносятся
    expect(row.locator("td[data-label='Уязвимости'] .compact-preview")).to_be_hidden()
    expect(row.locator("td[data-label='Уязвимости'] .compact-list li")).to_have_count(20)
    first = row.locator("td[data-label='Уязвимости'] .compact-list li .mono").first
    assert first.evaluate("el => getComputedStyle(el).whiteSpace") == "nowrap"
    for n in range(20):
        expect(row).to_contain_text(f"CVE-2099-{70010 + n:05d}")
    height_open = row.evaluate("r => r.getBoundingClientRect().height")
    assert height_open < 900, height_open      # длинный список прокручивается, а не растягивает строку на экран
    assert row.locator("td[data-label='Уязвимости'] .compact-list").evaluate(
        "el => el.scrollHeight > el.clientHeight")     # у раскрытого списка своя прокрутка

    # ссылки на находки не потеряны: они внутри раскрытия
    row.locator("td[data-label='Находки'] summary").click()
    expect(row.locator("td[data-label='Находки'] .compact-list a")).to_have_count(6)   # все, основная – первой
    expect(row.locator("td[data-label='Находки'] .compact-preview")).to_be_hidden()
    assert row.locator("[data-row-link]").get_attribute("href").startswith(f"/projects/{pid}/sca/findings/")

    # отбор по оценке: «строго больше 7» – организационное правило, 7,0 в него не входит
    page.locator("#sca-filters summary").click()
    page.locator(".filter-group", has=page.locator("#filter-cvss")).get_by_role(
        "link", name=re.compile("^Строго больше 7")).click()
    expect(page).to_have_url(re.compile(r"cvss=above7"))
    expect(page.locator("#sca-table tbody tr")).to_have_count(1)
    expect(page.locator("#sca-shown-count")).to_contain_text("Отобрано 1 из 6")
    page.get_by_role("link", name=re.compile("^7 и выше")).click()
    expect(page.locator("#sca-table tbody tr")).to_have_count(2)

    # свои границы: обе границы входят в отбор, одна граница – без ограничения с другой стороны
    page.fill("#cvss-min", "7")
    page.click("#sca-range-form button[type=submit]")
    expect(page).to_have_url(re.compile(r"cvss_min=7"))
    expect(page.locator("#sca-table tbody tr")).to_have_count(2)
    page.fill("#cvss-max", "9")
    page.click("#sca-range-form button[type=submit]")
    expect(page.locator("#sca-table tbody tr")).to_have_count(1)
    assert row_scores(page) == ["7,0"]

    # граница вне 0…10 приходит из адреса, введённого руками: сервер обязан ответить понятно, а не отфильтровать молча
    # (браузер такое значение в поле типа number и не отправит – это его штатная проверка)
    page.goto(f"/projects/{pid}/sca?cvss_min=11")
    expect(page.locator("#cvss-errors")).to_be_visible()
    expect(page.locator("#cvss-errors")).to_contain_text("от 0 до 10")
    expect(page.locator("#sca-table tbody tr")).to_have_count(6)
    expect(page.locator("#cvss-min")).to_have_value("11")
    # перевёрнутые границы – тоже ошибка, а не пустой список без объяснения
    page.fill("#cvss-min", "9")
    page.fill("#cvss-max", "7")
    page.click("#sca-range-form button[type=submit]")
    expect(page.locator("#cvss-errors")).to_contain_text("больше")
    expect(page.locator("#sca-table tbody tr")).to_have_count(6)
    page.click("#sca-reset")
    expect(page.locator("#sca-table tbody tr")).to_have_count(6)

    # версия оценки: под 3,1 остаются только библиотеки с оценкой 3,1, под «версия не указана» – своя
    page.locator("#sca-filters summary").click()
    page.select_option("#cvss-version", "3.1")
    expect(page).to_have_url(re.compile(r"cvss_version=3.1"))
    expect(page.locator("#sca-table tbody tr")).to_have_count(2)
    page.select_option("#cvss-version", "4.0")
    expect(page.locator("#sca-table tbody tr")).to_have_count(2)
    page.select_option("#cvss-version", "?")
    expect(page.locator("#sca-table tbody tr")).to_have_count(1)

    # числовая сортировка по заголовку: сначала по убыванию, затем по возрастанию, без оценки – в конце
    page.click("#sca-reset")   # сброс закрывает панель и снимает сортировку
    expect(page.locator("#sca-table tbody tr")).to_have_count(6)
    page.locator("#sca-sort-cvss").click()
    expect(page).to_have_url(re.compile(r"sort=cvss_desc"))
    expect(page.locator("th.col-cvss")).to_have_attribute("aria-sort", "descending")
    descending = row_scores(page)
    assert descending[-1] == "-"
    assert descending[:-1] == sorted(descending[:-1], key=lambda value: float(value.replace(",", ".")), reverse=True)
    page.locator("#sca-sort-cvss").click()
    expect(page).to_have_url(re.compile(r"sort=cvss_asc"))
    expect(page.locator("th.col-cvss")).to_have_attribute("aria-sort", "ascending")
    ascending = row_scores(page)
    assert ascending[-1] == "-"
    assert ascending[:-1] == sorted(ascending[:-1], key=lambda value: float(value.replace(",", ".")))
    assert descending == list(reversed(ascending[:-1])) + ["-"]

    # сортировка не теряет отбор: отбор по баллу сохранился, адрес хранит оба параметра
    page.locator("#sca-filters summary").click()
    page.locator(".filter-group", has=page.locator("#filter-cvss")).get_by_role(
        "link", name=re.compile("^Строго больше 7")).click()
    expect(page).to_have_url(re.compile(r"sort=cvss_asc"))
    expect(page.locator("#sca-table tbody tr")).to_have_count(1)
    page.locator("#sca-sort-cvss").click()
    expect(page).to_have_url(re.compile(r"cvss=above7"))
    expect(page).to_have_url(re.compile(r"sort=cvss_desc"))
    expect(page.locator("th.col-cvss")).to_have_attribute("aria-sort", "descending")
    assert not watch.problems(), watch.problems()


def test_sca_table_on_narrow_screen_and_dark_theme(browser, app_server, tmp_path: Path):
    report = write_report(tmp_path / "cvss.csv")
    problems: list[str] = []
    for width, theme in ((390, "light"), (390, "dark"), (360, "light"), (1440, "dark")):
        context, page, watch = open_page(browser, app_server.url, width=width, height=800, theme=theme)
        try:
            pid = make_project(page, report)
            page.goto(f"/projects/{pid}/sca?cvss=from7&sort=cvss_desc")
            expect(page.locator("#sca-table tbody tr")).to_have_count(2)
            row = page.locator('#sca-table tbody tr[data-component="lib-long"]')
            assert row.evaluate("r => r.getBoundingClientRect().height") < 700
            row.locator("td[data-label='Находки'] summary").click()
            expect(row.locator("td[data-label='Находки'] .compact-list a")).to_have_count(6)
            if not no_horizontal_scroll(page):
                problems.append(f"{width} px, {theme}: раскрытый список, ширина страницы "
                                f"{page.evaluate('document.documentElement.scrollWidth')} px")
            # категории первого столбца разделены: экосистема, CWE и кодовые базы не склеены в одно слово
            first = page.locator('#sca-table tbody tr[data-component="lib-seven"] '
                                 "td[data-label='Библиотека']").inner_text()
            if not re.search(r"\d+ · core-a", first):
                problems.append(f"{width} px, {theme}: первый столбец «{first.strip()}»")
            # панель отбора открыта (в адресе есть выбор), границы заполнены – худший случай по ширине
            expect(page.locator("#sca-filters")).to_have_attribute("open", "")
            page.fill("#cvss-min", "7")
            page.fill("#cvss-max", "9.5")
            page.wait_for_timeout(100)
            if not no_horizontal_scroll(page):
                problems.append(f"{width} px, {theme}: панель отбора, ширина страницы "
                                f"{page.evaluate('document.documentElement.scrollWidth')} px")
            problems += [f"{width} px, {theme}: {p}" for p in watch.problems()]
        finally:
            context.close()
    assert not problems, "\n".join(problems)