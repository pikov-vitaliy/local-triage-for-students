"""Справочник CWE в браузере: список с поиском и фильтром, карточка класса с примерами кода и связями, переходы
из карточек находок и таблицы SCA, вёрстка без горизонтальной прокрутки в светлой и тёмной темах.

Каталог загружается выдуманным файлом того же формата (tests/feed_fixtures.py): настоящий архив MITRE в проверках
не участвует, как и раньше для страницы «Справочники».
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo, no_horizontal_scroll, open_page  # noqa: E402
from feed_fixtures import CWE_FULL_XML, CWE_XML, bdu_zip, cwe_zip  # noqa: E402

pytestmark = pytest.mark.e2e


def test_cwe_list_search_filter_and_card(ui, tmp_path: Path):
    page, watch = ui
    watch.allowed_errors.append("status of 404")  # проверка несуществующего номера класса – так и задумано
    # Список: загрузка каталога через страницу «Справочники», затем сам справочник
    page.goto("/feeds")
    page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML)))
    page.locator("#feed-cwe form button[type=submit]").click()
    expect(page.locator("#feed-cwe-records")).to_have_text("6", timeout=30000)

    page.goto("/cwe")
    expect(page.locator("h1")).to_contain_text("Справочник CWE")
    expect(page.locator('.topnav-link[href="/cwe"]')).to_have_attribute("aria-current", "page")
    expect(page.locator("table tbody tr")).to_have_count(6)
    expect(page.locator("main")).to_contain_text("Weaknesses")
    expect(page.locator("main")).to_contain_text("9.99")

    # Поиск по названию и по номеру, фильтр вида записи
    page.fill("#cwe-q", "parent class")
    page.locator("#cwe-filters button[type=submit]").click()
    expect(page).to_have_url(re.compile(r"/cwe\?q="))
    expect(page.locator("table tbody tr")).to_have_count(1)
    expect(page.locator("table tbody")).to_contain_text("Demo Parent Class")
    page.fill("#cwe-q", "3000")
    page.locator("#cwe-filters button[type=submit]").click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    page.get_by_role("link", name="Сбросить", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(6)
    page.locator("#cwe-kind").select_option("category")
    page.locator("#cwe-filters button[type=submit]").click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    expect(page.locator("table tbody")).to_contain_text("Demo Category")
    page.locator("#cwe-kind").select_option("")
    page.locator("#cwe-filters button[type=submit]").click()

    # Карточка класса: разделы, примеры кода, связи переходами внутри приложения
    page.locator("table tbody tr", has_text="Demo Input").locator("a.break").click()
    expect(page).to_have_url(re.compile(r"/cwe/CWE-2099$"))
    expect(page.locator("h1")).to_contain_text("CWE-2099")
    expect(page.locator("h1")).to_contain_text("Improper Neutralization of Demo Input")
    for header in ("Description", "Extended Description", "Alternate Terms", "Relationships",
                   "Detection Methods", "Potential Mitigations", "Common Consequences", "Demonstrative Examples",
                   "Observed Examples", "Taxonomy Mappings", "Notes", "References"):
        expect(page.get_by_role("heading", name=header, exact=True)).to_be_visible()
    bad = page.locator(".cwe-code-err").first
    expect(bad.locator(".cwe-code-cap")).to_contain_text("Bad")
    expect(bad.locator("code")).to_contain_text("value = demo_input()")
    expect(page.locator(".cwe-code-ok").first.locator(".cwe-code-cap")).to_contain_text("Good")
    expect(page.locator("#cwe-links-title ~ .grid-2, .cwe-links").first).to_be_visible()
    page.locator('.cwe-link-list a[href="/cwe/CWE-2098"]').first.click()
    expect(page).to_have_url(re.compile(r"/cwe/CWE-2098$"))
    expect(page.locator("h1")).to_contain_text("Demo Parent Class")
    page.locator("nav.crumbs").get_by_role("link", name="Проекты", exact=True).click()
    page.goto("/cwe/CWE-9999")
    expect(page.locator("main")).to_contain_text("Такого класса в каталоге нет")

    # Внешняя ссылка из справочника ссылок открывается в новой вкладке, адрес в приложении не меняется
    page.goto("/cwe/CWE-2099")
    expect(page.locator('#cwe-refs a[href="https://example.org/ref1"]')).to_have_attribute(
        "rel", "noopener noreferrer")
    expect(page.locator("main")).to_contain_text("условиям использования CWE")
    assert not watch.problems()


def test_cwe_links_from_findings_and_sca(ui, tmp_path: Path):
    page, watch = ui
    # демонстрационная выгрузка содержит CWE-89 и CWE-1333: каталог с этими номерами нужен для проверки переходов
    page.goto("/feeds")
    page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_demo.zip", CWE_XML)))
    page.locator("#feed-cwe form button[type=submit]").click()
    expect(page.locator("#feed-cwe-records")).to_have_text("3", timeout=30000)
    pid = create_demo(page)
    # Карточка находки SAST: номер CWE ведёт в справочник
    page.goto(f"/projects/{pid}/findings?kind=SAST")
    page.locator("table.table-findings tbody tr td.col-id a").first.click()
    expect(page).to_have_url(re.compile(r"/findings/\d+"))
    card = page.locator("#cwe-info")
    expect(card).to_be_visible()
    card.locator("summary").click()  # справка по классу слабости в шаге 3 свёрнута
    card.locator('a[href^="/cwe/CWE-"]').first.click()
    expect(page).to_have_url(re.compile(r"/cwe/CWE-\d+(?:\?.*)?$"))
    expect(page.locator("h1")).to_contain_text("CWE-")
    # из карточки класса – назад к находке и к списку классов
    expect(page.locator('.cwe-link-list a[href^="/cwe/CWE-"]').first).to_be_visible()
    page.go_back()
    expect(page).to_have_url(re.compile(r"/findings/\d+"))
    expect(page.locator("#cwe-info")).to_be_visible()
    page.goto("/cwe")
    expect(page.locator("table tbody tr").first).to_be_visible()

    # Таблица SCA: перечень CWE в первой колонке и переход из карточки SCA
    page.goto(f"/projects/{pid}/sca")
    expect(page.locator('.compact-preview a[href^="/cwe/CWE-1333?"]').first).to_be_visible()
    page.locator('.compact-preview a[href^="/cwe/CWE-1333?"]').first.click()
    expect(page).to_have_url(re.compile(r"/cwe/CWE-1333(?:\?.*)?$"))
    expect(page.locator("h1")).to_contain_text("CWE-1333")
    page.goto(f"/projects/{pid}/sca")
    row = page.locator("table.table-sca tbody tr").filter(
        has=page.locator('.compact-preview a[href^="/cwe/CWE-1333?"]')).first
    row.locator("a[data-row-link]").click()
    expect(page).to_have_url(re.compile(r"/sca/findings/\d+(?:\?.*)?$"))
    expect(page.locator('#cwe-info a[href^="/cwe/CWE-"]').first).to_be_visible()
    # каталог для следующих проверок снова полный: в нём есть класс с примерами и наблюдаемыми примерами
    page.goto("/feeds")
    page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_full.zip", CWE_FULL_XML)))
    page.locator("#feed-cwe form button[type=submit]").click()
    expect(page.locator("#feed-cwe-records")).to_have_text("6", timeout=30000)
    assert not watch.problems()


def test_bdu_page_from_observed_example(ui, tmp_path: Path):
    page, watch = ui
    watch.allowed_errors.append("status of 404")  # класс из записи БДУ в этом каталоге отсутствует
    page.goto("/feeds")
    page.set_input_files("#feed-bdu-file", str(bdu_zip(tmp_path / "vulxml.zip")))
    page.locator("#feed-bdu form button[type=submit]").click()
    expect(page.locator("#feed-bdu-records")).to_have_text("2", timeout=30000)
    page.goto("/cwe/CWE-2099")
    expect(page.locator("#cwe-observed")).to_contain_text("CVE-2099-10001")
    page.locator('#cwe-observed a[href="/bdu/CVE-2099-10001"]').click()
    expect(page).to_have_url(re.compile(r"/bdu/CVE-2099-10001$"))
    expect(page.locator("h1")).to_contain_text("CVE-2099-10001")
    expect(page.locator("main")).to_contain_text("Как устранить")
    # класс CWE в записи БДУ – переходом в справочник; класса в выгруженном каталоге нет, поэтому 404 с подсказкой
    page.locator('.dot-list a[href^="/cwe/CWE-"]').first.click()
    expect(page).to_have_url(re.compile(r"/cwe/CWE-\d+(?:\?.*)?$"))
    expect(page.locator("main")).to_contain_text("Такого класса в каталоге нет")
    assert not watch.problems()


def test_cwe_pages_layout(browser, app_server, tmp_path: Path):
    """Список, карточка и страница БДУ: без горизонтальной прокрутки на 1440 и 360 px в обеих темах. Справочники
    загружаются здесь же: тест не зависит от того, запускались ли до него соседние (загрузка повторяемая)."""
    context, page, _ = open_page(browser, app_server.url)
    try:
        page.goto("/feeds")
        page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML)))
        page.locator("#feed-cwe form button[type=submit]").click()
        expect(page.locator("#feed-cwe-records")).to_have_text("6", timeout=30000)
        page.goto("/feeds")
        page.set_input_files("#feed-bdu-file", str(bdu_zip(tmp_path / "vulxml.zip")))
        page.locator("#feed-bdu form button[type=submit]").click()
        expect(page.locator("#feed-bdu-records")).to_have_text("2", timeout=30000)
    finally:
        context.close()
    problems = []
    for width, theme in ((1440, "light"), (1440, "dark"), (360, "light"), (360, "dark")):
        context, page, watch = open_page(browser, app_server.url, width=width, height=800, theme=theme)
        try:
            for url in ("/cwe", "/cwe?q=demo", "/cwe?kind=category", "/cwe/CWE-2099", "/bdu/CVE-2099-10001"):
                page.goto(url)
                if not no_horizontal_scroll(page):
                    problems.append(f"{width} px, {theme}: {url} – ширина страницы "
                                    f"{page.evaluate('document.documentElement.scrollWidth')}")
            problems += [f"{width} px, {theme}: {p}" for p in watch.problems()]
        finally:
            context.close()
    assert not problems, "\n".join(problems)


def test_cwe_filters_look_like_the_application(ui, tmp_path):
    """Поля фильтра и кнопки одним рядом, одной высоты, без дублирующих чипов."""
    import os
    from pathlib import Path as _Path
    page, _ = ui
    page.goto("/feeds")
    page.set_input_files("#feed-cwe-file", str(cwe_zip(tmp_path / "cwec_latest.xml.zip", CWE_FULL_XML)))
    page.locator("#feed-cwe form button[type=submit]").click()
    expect(page.locator("#feed-cwe-records")).to_have_text("6", timeout=30000)
    page.set_viewport_size({"width": 1600, "height": 900})
    page.goto("/cwe")
    expect(page.locator("#cwe-filters .chip")).to_have_count(0)
    boxes = [page.locator(f"#cwe-filters [name={name}]").bounding_box() for name in ("q", "abstraction", "status", "kind")]
    boxes.append(page.locator("#cwe-filters button[type=submit]").bounding_box())
    assert max(b["y"] for b in boxes) - min(b["y"] for b in boxes) <= 2, boxes
    assert max(b["height"] for b in boxes) - min(b["height"] for b in boxes) <= 2, boxes
    folder = os.environ.get("E2E_SHOTS")
    for theme in ("light", "dark") if folder else ():
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(300)
        page.screenshot(path=str(_Path(folder) / f"cwe-{theme}.png"))
    page.locator("#cwe-kind").select_option("weakness")
    page.locator("#cwe-filters button[type=submit]").click()
    reset = page.get_by_role("link", name="Сбросить", exact=True)
    # число сводки – отбор таблицы
    page.locator("a.stat-filter", has_text="Categories").click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    expect(page.locator("#cwe-kind")).to_have_value("category")
    expect(page.locator("a.stat-filter", has_text="Categories")).to_have_attribute("aria-current", "true")
    expect(reset).to_be_visible()
    # кнопки – одним рядом и при средней ширине окна
    page.set_viewport_size({"width": 1333, "height": 900})
    assert abs(page.locator("#cwe-filters button[type=submit]").bounding_box()["y"] - reset.bounding_box()["y"]) < 12
    reset.click()
    expect(page).to_have_url(re.compile(r"/cwe$"))

