"""Страница SCA: отбор по оценке CVSS и числовая сортировка, компактные строки таблицы.

Проверки идут через настоящий разбор выгрузки: книга тестовой выгрузки (tests/hub_fixtures.py) указаний версии
оценки не содержит, а таблица со своими колонками позволяет принести вектор и версию оценки – так проверяется,
что версия берётся из сохранённых сведений, а не угадывается.
"""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qsl

from hub_fixtures import APP
from test_web import ORIGIN, create_project, prepared, web  # noqa: F401

COLUMNS = ["Issue id", "Application", "Type", "Component name", "Component version", "CVSS score", "CVE id",
           "Codebase", "CWE ID", "CVSS vector", "CVSS version"]
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


def upload_table(web, pid: int, rows, name: str = "cvss.csv"):
    """Выгрузка таблицей с произвольными колонками."""
    lines = [";".join(COLUMNS)]
    for row in rows:
        lines.append(";".join(str(row.get(column, "-")) for column in COLUMNS))
    data = ("\n".join(lines) + "\n").encode("utf-8")
    r = web.client.post(f"/projects/{pid}/import", headers=ORIGIN, follow_redirects=False,
                        files={"file": (name, data, "text/csv")})
    assert r.status_code == 303, r.text
    return r


def row(issue: str, component: str, score: str, *, cve: str = "", cwes: str = "", codebases: str = "",
        vector: str = "", version: str = "", fixed: str = "") -> dict:
    return {"Issue id": issue, "Application": APP, "Type": "maven", "Component name": component,
            "Component version": "1.0.0", "CVSS score": score, "CVE id": cve or f"CVE-2099-{issue}",
            "Codebase": codebases, "CWE ID": cwes, "CVSS vector": vector, "CVSS version": version,
            "Non-vulnerable versions": fixed}


def libraries(page: str) -> list[str]:
    return re.findall(r'data-component="([^"]+)"', page)


def scores(page: str) -> list[str]:
    return re.findall(r'class="cvss cvss-[a-z]+" title="CVSS [0-9,]+">([0-9,]+)</span>', page)


def text(page: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))


def hrefs(page: str) -> list[str]:
    return [html.unescape(href) for href in re.findall(r'href="([^"]+)"', page)]


def sca_links(page: str, pid: int) -> list[dict[str, str]]:
    """Параметры всех ссылок таблицы и панели отбора: [{cvss: …, sort: …}], без учёта порядка."""
    found = []
    for href in hrefs(page):
        path, _, _query = href.partition("#")
        if path.partition("?")[0] == f"/projects/{pid}/sca":
            found.append(dict(parse_qsl(path.partition("?")[2])))
    return found


def sca_page(web, pid: int, query: str = "") -> str:
    r = web.client.get(f"/projects/{pid}/sca{query}")
    assert r.status_code == 200, r.text
    return r.text


def test_cvss_presets_narrow_by_band(web):
    pid = prepared(web)  # 9,8 и 8,9, версия оценки в книге не указана
    page = sca_page(web, pid)
    assert scores(page) == ["9,8", "8,9"] and libraries(page) == ["example-parser", "demo-xml"]
    assert libraries(sca_page(web, pid, "?cvss=critical")) == ["example-parser"]
    assert scores(sca_page(web, pid, "?cvss=critical")) == ["9,8"]
    assert libraries(sca_page(web, pid, "?cvss=high")) == ["demo-xml"]
    assert "Под этот отбор ничего не попало" in sca_page(web, pid, "?cvss=low")
    assert len(libraries(sca_page(web, pid, "?cvss=from7"))) == 2


def test_cvss_strictly_above_seven_is_not_seven_and_above(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73101", "lib-seven", "7.0"), row("73102", "lib-above", "7.1"),
                            row("73103", "lib-max", "10")])
    assert libraries(sca_page(web, pid, "?cvss=above7")) == ["lib-max", "lib-above"]  # без сортировки – порядок отчёта
    assert libraries(sca_page(web, pid, "?cvss=from7")) == ["lib-max", "lib-above", "lib-seven"]
    assert libraries(sca_page(web, pid, "?cvss=high")) == ["lib-above", "lib-seven"]  # 7,0 входит в «Высокий»
    assert libraries(sca_page(web, pid, "?cvss=above7&sort=cvss_asc")) == ["lib-above", "lib-max"]


def test_cvss_zero_is_not_missing_score(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73201", "lib-zero", "0"), row("73202", "lib-none", "-")])
    assert scores(sca_page(web, pid, "?cvss=zero")) == ["0,0"]
    assert libraries(sca_page(web, pid, "?cvss=zero")) == ["lib-zero"]
    assert libraries(sca_page(web, pid, "?cvss=no_score")) == ["lib-none"]
    assert libraries(sca_page(web, pid, "?cvss=low")) == []


def test_cvss_band_edges(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73301", "lib-zero", "0"), row("73302", "lib-low-top", "3.9"),
                            row("73303", "lib-mid-low", "4"), row("73304", "lib-mid-top", "6.9"),
                            row("73305", "lib-high-low", "7"), row("73306", "lib-high-top", "8.9"),
                            row("73307", "lib-crit-low", "9"), row("73308", "lib-crit-top", "10")])
    assert libraries(sca_page(web, pid, "?cvss=low")) == ["lib-low-top"]
    assert libraries(sca_page(web, pid, "?cvss=medium")) == ["lib-mid-top", "lib-mid-low"]
    assert libraries(sca_page(web, pid, "?cvss=high")) == ["lib-high-top", "lib-high-low"]
    assert libraries(sca_page(web, pid, "?cvss=critical")) == ["lib-crit-top", "lib-crit-low"]
    assert libraries(sca_page(web, pid, "?cvss_min=3.9&cvss_max=7")) == ["lib-high-low", "lib-mid-top",
                                                                           "lib-mid-low", "lib-low-top"]
    assert libraries(sca_page(web, pid, "?cvss_min=7")) == ["lib-crit-top", "lib-crit-low",
                                                             "lib-high-top", "lib-high-low"]
    assert libraries(sca_page(web, pid, "?cvss_max=0")) == ["lib-zero"]


def test_cvss_bounds_come_from_the_address(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73401", "lib-high", "9.8"), row("73402", "lib-mid", "6.9"),
                            row("73403", "lib-low", "3.9")])
    assert libraries(sca_page(web, pid, "?cvss_min=8&cvss_max=10")) == ["lib-high"]
    assert libraries(sca_page(web, pid, "?cvss_min=6,9&cvss_max=9,8")) == ["lib-high", "lib-mid"]
    assert libraries(sca_page(web, pid, "?cvss_max=3.9")) == ["lib-low"]
    assert 'value="3.9"' in sca_page(web, pid, "?cvss_max=3.9")
    assert "Отобрано 1 из 3" in text(sca_page(web, pid, "?cvss_max=3.9"))


def test_cvss_bad_value_is_reported_and_not_applied(web):
    pid = prepared(web)
    for query, piece in (("?cvss_min=abc", "числом от 0 до 10"), ("?cvss_min=nan", "числом от 0 до 10"),
                         ("?cvss_min=inf", "числом от 0 до 10"), ("?cvss_min=11", "от 0 до 10"),
                         ("?cvss_max=-1", "от 0 до 10"), ("?cvss_min=9&cvss_max=7", "больше"),
                         ("?cvss_min=abc&cvss_max=9", "числом от 0 до 10"),
                         ("?cvss_max=abc&cvss_min=7", "числом от 0 до 10"),
                         ("?cvss=нет", "неизвестен"), ("?sort=cvss_sideways", "Сортировка"),
                         ("?cvss_version=5.0", "неизвестна")):
        page = sca_page(web, pid, query)
        assert 'role="alert"' in page and piece in text(page), query
        assert "не применён" in text(page) and len(libraries(page)) == 2, query
    assert 'value="abc"' in sca_page(web, pid, "?cvss_min=abc")  # значение осталось в поле, его можно исправить
    assert 'value="9"' in sca_page(web, pid, "?cvss_min=9&cvss_max=7")


def test_bad_value_does_not_apply_half_of_the_range(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73411", "lib-nine", "9.8"), row("73412", "lib-six", "6.9")])
    # неверная нижняя граница при верной верхней: 9,8 не отбрасывается, а половина 0…9 молча не применяется
    page = sca_page(web, pid, "?cvss_min=abc&cvss_max=9")
    assert 'role="alert"' in page
    assert libraries(page) == ["lib-nine", "lib-six"]
    assert libraries(sca_page(web, pid, "?cvss_max=9")) == ["lib-six"]   # без ошибки верхняя граница работает
    # сообщение не обещает «показаны все», когда другие отборы продолжают действовать
    urgent = sca_page(web, pid, "?show=urgent&cvss_min=abc")
    assert "продолжают действовать" in text(urgent) and libraries(urgent) == ["lib-nine"]
    assert "список показан без изменений" not in text(urgent)


def test_comma_in_the_address_stays_in_the_form(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73421", "lib-high", "9.8"), row("73422", "lib-six", "6.9")])
    page = sca_page(web, pid, "?cvss_min=6,9")
    # запятая – то же число, что и точка: поле типа number не показывает запятую, значение не должно пропасть
    assert 'value="6.9"' in page and libraries(page) == ["lib-high", "lib-six"]


def test_cvss_sort_is_numeric_and_keeps_the_filter(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73501", "lib-nine", "9.8"), row("73502", "lib-seven", "7.0"),
                            row("73503", "lib-none", "-"), row("73504", "lib-three", "3.5")])
    # порядок отчёта: срочные (CVSS не ниже 9) и по убыванию балла; явная сортировка числовая и в обе стороны
    assert libraries(sca_page(web, pid)) == ["lib-nine", "lib-seven", "lib-three", "lib-none"]
    assert libraries(sca_page(web, pid, "?sort=cvss_asc")) == ["lib-three", "lib-seven", "lib-nine", "lib-none"]
    assert scores(sca_page(web, pid, "?sort=cvss_asc")) == ["3,5", "7,0", "9,8"]
    assert libraries(sca_page(web, pid, "?sort=cvss_desc")) == ["lib-nine", "lib-seven", "lib-three", "lib-none"]
    assert 'aria-sort="ascending"' in sca_page(web, pid, "?sort=cvss_asc")
    assert 'aria-sort="descending"' in sca_page(web, pid, "?sort=cvss_desc")
    assert 'aria-sort="none"' in sca_page(web, pid)
    # отбор и сортировка не теряют друг друга: каждая ссылка меняет только свой параметр
    links = sca_links(sca_page(web, pid, "?cvss=from7&sort=cvss_asc"), pid)
    assert {"cvss": "from7", "sort": "cvss_desc"} in links      # заголовок CVSS меняет направление
    assert {"cvss": "high", "sort": "cvss_asc"} in links        # чип диапазона сохраняет сортировку
    assert {"show": "urgent", "cvss": "from7", "sort": "cvss_asc"} in links   # чип готового отбора
    assert {"cvss": "from7", "sort": "cvss_asc"} in links        # сортировка сохраняет отбор по баллу
    assert {"cvss": "from7"} in links                  # «как в отчёте» снимает сортировку, отбор оставляет
    assert {} in links                                                 # сброс всего отбора
    assert libraries(sca_page(web, pid, "?cvss=from7&sort=cvss_asc")) == ["lib-seven", "lib-nine"]


def test_cvss_version_is_taken_from_the_report(web):
    pid = create_project(web.client)
    upload_table(web, pid, [
        row("73601", "lib-31", "9.8", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        row("73602", "lib-31", "5.0", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
        row("73603", "lib-40", "8.0", vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
        row("73604", "lib-20", "4.0", vector="AV:N/AC:L/Au:N/C:P/I:P/A:P"),
        row("73605", "lib-plain", "7.5")])
    page = sca_page(web, pid)
    for label in ("CVSS 3.1", "CVSS 4.0", "CVSS 2.0", "версия не указана"):
        assert label in page, label
    # 9,8 и 5,0 у одной библиотеки: под выбранной версией остаются только её оценки
    assert libraries(sca_page(web, pid, "?cvss_version=3.1")) == ["lib-31"]
    assert scores(sca_page(web, pid, "?cvss_version=3.1")) == ["9,8"]
    assert libraries(sca_page(web, pid, "?cvss_version=4.0")) == ["lib-40"]
    assert scores(sca_page(web, pid, "?cvss_version=4.0")) == ["8,0"]  # 5,0 – это 3,1, не 4,0
    assert libraries(sca_page(web, pid, "?cvss_version=2.0")) == ["lib-20"]
    assert 'title="Оценка CVSS 3.1: 9,8"' in sca_page(web, pid, "?cvss_version=3.1")
    assert 'title="Оценка CVSS 2.0: 4,0"' in sca_page(web, pid, "?cvss_version=2.0")
    # оценка без указания версии остаётся отдельным отбором и не смешивается с известными версиями
    assert libraries(sca_page(web, pid, "?cvss_version=?")) == ["lib-plain"]
    assert scores(sca_page(web, pid, "?cvss_version=?")) == ["7,5"]
    assert len(libraries(sca_page(web, pid))) == 4      # без выбора версии видны все библиотеки


def test_cvss_scale_of_version_2_is_not_the_scale_of_3(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73701", "lib-20", "10", vector="AV:N/AC:L/Au:N/C:C/I:C/A:C"),
                            row("73702", "lib-31", "0")])
    page = sca_page(web, pid, "?cvss_version=2.0")
    assert "Диапазоны шкалы – CVSS 2.0" in text(page)
    assert "Критический" not in page and "Нулевой" not in page
    assert "высокий 7–10" in text(page)          # у второй версии верх границы 10, а не 8,9
    assert "низкий 0–3,9" in text(page)         # ноль входит в низкий
    assert "7–8,9" not in text(page)
    assert libraries(page) == ["lib-20"]
    assert libraries(sca_page(web, pid, "?cvss_version=2.0&cvss=high")) == ["lib-20"]
    assert libraries(sca_page(web, pid, "?cvss_version=2.0&cvss=low")) == []
    assert "не применим к CVSS 2.0" in text(sca_page(web, pid, "?cvss_version=2.0&cvss=critical"))
    assert "Критический" in sca_page(web, pid)  # под шкалой 3.x и 4.0 он есть


def test_counters_follow_the_chosen_version(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73721", "lib-31", "9.8", vector=V31), row("73722", "lib-40", "8.0", vector=V40),
                            row("73723", "lib-plain", "6.0")])
    page = sca_page(web, pid, "?cvss_version=3.1")
    panel = page[page.index('id="sca-filters"'):page.index('id="sca-table"')]
    shown = libraries(page)
    # «Все» и «из N» считают реальную выборку версии, а не все библиотеки проекта
    assert shown == ["lib-31"]
    assert f"Отобрано {len(shown)} из {len(shown)}" in text(page)
    assert re.search(r'Все <span class="chip-count">1</span>', panel), panel
    assert len(libraries(sca_page(web, pid))) == 3      # без выбора версии видны все библиотеки


def test_score_cell_signs_the_version_honestly(web):
    pid = create_project(web.client)
    upload_table(web, pid, [row("73731", "lib-mixed", "9.8", vector=V31), row("73732", "lib-mixed", "5.0", vector=V40),
                            row("73733", "lib-plain", "6.0")])
    plain = sca_page(web, pid)
    assert 'title="Оценка CVSS' not in plain            # без выбора версии подписи нет: балл из всех версий
    assert "наибольший балл среди находок библиотеки" in text(plain)
    assert 'title="Оценка CVSS 3.1: 9,8"' in sca_page(web, pid, "?cvss_version=3.1")
    unknown = sca_page(web, pid, "?cvss_version=?")
    assert 'title="Оценка без указания версии: 6,0"' in unknown
    assert "Оценка CVSS ?:" not in unknown
    assert "наибольший балл среди находок библиотеки: без указания версии" in text(unknown)
    # раскрытие с версиями – блок, а не строка: блок внутри строки в разметке недопустим
    cell = re.search(r'<td data-label="CVSS".*?</td>', plain, re.S).group(0)
    assert cell.startswith('<td data-label="CVSS" class="num"><div class="cvss-cell"')
    assert "<details class=\"compact\">" in cell
    assert "<span class=\"cvss-cell\"" not in plain


def test_cvss_cell_breaks_the_package_down_by_version(web):
    pid = create_project(web.client)
    upload_table(web, pid, [
        row("73801", "lib-mixed", "9.8", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        row("73802", "lib-mixed", "5.0", vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"),
        row("73803", "lib-mixed", "2.0")])
    page = sca_page(web, pid)
    assert "версии: 3" in page
    assert "9,8 – CVSS 3.1" in text(page) and "5,0 – CVSS 4.0" in text(page)
    assert "2,0 – версия не указана" in text(page)
    assert scores(page) == ["9,8"]  # в ячейке виден максимум, остальное – под раскрытием


def test_rows_stay_compact_and_keep_every_link(web):
    pid = create_project(web.client)
    ids = ", ".join(f"CVE-2099-{n:05d}" for n in range(73810, 73820))
    cwes = ", ".join(str(100 + n) for n in range(12))
    rows = [row(f"739{n:02d}", "lib-long", f"{1 + n / 2:.1f}", cve=ids, cwes=cwes, codebases="core-a",
                vector=V31) for n in range(6)]
    rows[3]["Codebase"] = "core-b"
    upload_table(web, pid, rows)
    page = sca_page(web, pid)
    body = page[page.index('id="sca-table"'):page.index("</table>")]
    # видимая часть строки короткая: по два идентификатора, три CWE и две кодовые базы
    assert body.count('<details class="compact">') == 3  # идентификаторы, CWE, находки
    ids_cell = body[body.index('data-label="Уязвимости"'):body.index('data-label="Версия исправления (Hub)"')]
    assert len(re.findall(r'class="mono nowrap">CVE-2099-', ids_cell.split("<details")[0])) == 2
    assert "Показать все 10" in ids_cell
    assert "Показать все CWE 12" in body                                        # CWE
    cwe_list = body[body.index("Показать все CWE 12"):]
    cwe_list = cwe_list[:cwe_list.index("</ul>")]
    assert cwe_list.count("<li") == 12                                  # раскрытие – весь перечень, не остаток
    assert "Показать все 6" in body                                     # находки
    for n in range(10):
        assert f"CVE-2099-{73810 + n:05d}" in body
    findings_cell = body[body.index('data-label="Находки"'):]
    assert len(set(re.findall(r"/sca/findings/\d+", findings_cell))) == 6  # ссылка на каждую находку (основная – и в строке, и в раскрытии)
    assert 'data-row-link href="/projects/%d/sca/findings/' % pid in body  # переход в карточку на месте
    assert "6 находок · проверено 0" in text(body)
    assert "core-a · core-b" in text(body)
    assert "lib-long" in text(body) and "@1.0.0" in text(body)


def first_column(page: str, component: str) -> str:
    """Первый столбец строки библиотеки как видимый текст."""
    return text(first_column_html(page, component))


def first_column_html(page: str, component: str) -> str:
    body = page[page.index("<tbody>"):page.index("</table>")]
    row = [part for part in body.split('<tr data-component="')[1:] if part.startswith(f'{component}"')][0]
    return row[row.index('data-label="Библиотека"'):row.index('data-label="CVSS"')]


def test_categories_of_the_first_column_are_separated(web):
    pid = create_project(web.client)
    upload_table(web, pid, [
        row("74001", "lib-one", "9.8", cwes="CWE-770", codebases="demo-data", vector=V31),
        row("74002", "lib-two", "7.0", cwes="CWE-79, CWE-89, CWE-20, CWE-22", codebases="web-core"),
        row("74003", "lib-three", "6.0"),
        row("74004", "lib-four", "5.0", codebases="core-a"),
        row("74005", "lib-five", "4.0", cwes="CWE-79", codebases="a-b, c-d")])
    page = sca_page(web, pid)
    one, two = first_column(page, "lib-one"), first_column(page, "lib-two")
    # категории первого столбца не слипаются: между экосистемой, CWE и кодовыми базами есть разделитель
    assert "maven · CWE-770 · demo-data" in one
    assert "maven · CWE-79 · CWE-89 · CWE-20" in two          # превью трёх CWE подряд
    assert "maven · core-a" in first_column(page, "lib-four")       # без CWE разделитель тоже на месте
    assert "maven · CWE-79 · a-b, c-d" in first_column(page, "lib-five")
    assert "maven" in first_column(page, "lib-three")               # только экосистема
    for glued in ("CWE-770demo-data", "CWE-20CWE-22", "demo-datacore-a", "mavencore-a"):
        assert glued not in text(page), glued
    # раскрытый перечень CWE стоит с новой строки: перед кодовыми базами точки быть не должно
    column = first_column_html(page, "lib-two")
    tail = column[column.index("</details>") + len("</details>"):]
    before_codes = tail[:tail.index('<div class="compact-preview inline">web-core')]
    assert before_codes.strip() == "", before_codes


def test_counter_and_panel_state(web):
    pid = prepared(web)
    assert 'id="sca-shown-count"' not in sca_page(web, pid)
    assert "Отобрано 2 из 2" in text(sca_page(web, pid, "?cvss=from7"))
    assert "Отобрано 1 из 2" in text(sca_page(web, pid, "?cvss=critical"))
    assert "Отобрано 0 из 2" in text(sca_page(web, pid, "?cvss=low&sort=cvss_asc"))
    page = sca_page(web, pid, "?cvss=critical&sort=cvss_asc")
    assert 'id="sca-filters" open' in page
    assert "выбрано 1" in text(page)      # сортировка – не отбор, в счётчик выбранных не входит


def test_filter_works_without_javascript(web):
    pid = prepared(web)
    page = sca_page(web, pid)
    form = page[page.index('id="sca-range-form"'):page.index('id="sca-version-form"')]
    assert 'method="get"' in form and 'name="cvss_min"' in form and 'name="cvss_max"' in form
    assert "<button type=\"submit\"" in form and "no-js-only" not in form
    assert "autocomplete" not in form
    version_form = page[page.index('id="sca-version-form"'):page.index('id="filter-sort"')]
    assert 'name="cvss_version"' in version_form and 'name="cvss_min" value=""' not in version_form
    assert re.search(r'<option value="\?"[^>]*selected', sca_page(web, pid, "?cvss_version=?"))