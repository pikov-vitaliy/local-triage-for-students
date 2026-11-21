"""Страницы в браузере: настройки и проверка Ollama, обзор папок и параметры проекта, «Продолжить», архив
и удаление, справка по клавишам и тема, вёрстка без горизонтальной прокрутки до 360 px в обеих темах."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import (create_demo, finding_id_from, no_horizontal_scroll, open_page,  # noqa: E402
                         project_id_from, run_triage)

pytestmark = pytest.mark.e2e


def test_settings_check_ollama_and_save(ui, app_server):
    page, _ = ui
    page.goto("/settings")
    expect(page.locator("h1")).to_have_text("Настройки")
    expect(page.locator("main")).to_contain_text("буква в букву")
    expect(page.locator("main")).not_to_contain_text("HUB_STATUS_MAP")
    # Чужой хост не проверяется и не сохраняется: запрос туда не уходит
    page.fill('input[name="ollama_url"]', "http://ollama.example.com:11434")
    page.get_by_role("button", name="Проверить", exact=True).click()
    expect(page.locator("#ollama_url-error")).to_be_visible()
    # Введённый, ещё не сохранённый адрес проверяется: версия и модели
    page.fill('input[name="ollama_url"]', app_server.fake.url)
    page.get_by_role("button", name="Проверить", exact=True).click()
    expect(page.locator("#ollama-status")).to_contain_text("Ollama 0.40.4")
    expect(page.locator("#ollama-models")).to_contain_text("qwen2.5-coder:14b")
    expect(page.locator("#ollama-models")).not_to_contain_text("cloud")
    expect(page.locator('select[name="default_model"]')).to_have_value("gpt-oss:20b")
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"/settings\?ok=settings_saved"))
    expect(page.locator(".flash-ok")).to_contain_text("Настройки сохранены")
    expect(page.locator('input[name="status_true_positive"]')).to_have_value("Подтверждено")
    expect(page.locator('input[name="status_risk_accepted"]')).to_have_value("Риск принят")
    expect(page.locator('input[name="sca_urgent_cvss"]')).to_have_value("9,0")
    expect(page.locator("main")).to_contain_text("Корень папок с репозиториями")


def test_folder_browser_params_and_continue(ui):
    page, _ = ui
    pid = create_demo(page)
    # Обзор папок: только внутри корня, клон кодовой базы папкой проекта не выбирается
    page.get_by_role("link", name="Выбрать папку…", exact=True).click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/folders"))
    listing = page.locator(".folder-list")
    expect(listing).to_contain_text("billing-core")
    expect(listing).to_contain_text("catalog-api")
    expect(listing.locator(".badge-accent")).to_have_count(2)  # кодовые базы из выгрузки
    page.locator("a.folder", has_text="billing-core").click()
    expect(page.locator(".browser-actions")).to_contain_text("Это клон одной кодовой базы")
    expect(page.get_by_role("button", name="Выбрать эту папку", exact=True)).to_have_count(0)
    page.locator("a.folder-up").click()
    expect(page.locator(".browser-actions")).to_contain_text("Найдено здесь по именам: 2 из 3")
    page.get_by_role("button", name="Выбрать эту папку", exact=True).click()
    page.wait_for_url(re.compile(rf"/projects/{pid}\?ok=repos"))
    # Параметры проекта: название и модель
    page.locator("#params summary").click()
    page.fill('#params input[name="name"]', "Демо – проверка параметров")
    page.select_option('#params select[name="model"]', "qwen2.5-coder:14b")  # не модель по умолчанию
    page.get_by_role("button", name="Сохранить параметры", exact=True).click()
    page.wait_for_url(re.compile(r"ok=project_saved"))
    expect(page.locator("h1")).to_have_text("Демо – проверка параметров")
    expect(page.locator(".project-meta")).to_contain_text("qwen2.5-coder:14b")
    expect(page.locator("#model-select")).to_have_value("qwen2.5-coder:14b")
    # «Продолжить» в списке проектов ведёт к первой непроверенной находке
    page.goto("/")
    page.locator(f"#project-{pid}").get_by_role("link", name="Продолжить", exact=True).click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))
    expect(page.locator(".finding-id")).to_be_visible()


def test_archive_restore_and_delete(ui):
    page, _ = ui
    page.goto("/")
    page.fill('#new-project input[name="name"]', "Временный проект")
    page.locator("#new-project").get_by_role("button", name="Создать", exact=True).click()
    page.wait_for_url(re.compile(r"/projects/\d+\?ok=created"))
    pid = project_id_from(page.url)
    expect(page.locator("#step1")).to_contain_text("Отчёт AppSec.Hub")
    page.goto("/")
    # «В архив» переспрашивает – диалог подтверждается
    page.locator(f"#project-{pid}").get_by_role("button", name="В архив", exact=True).click()
    page.wait_for_url(re.compile(r"ok=project_archived"))
    expect(page.locator(f"#project-{pid}")).to_have_count(0)
    page.goto("/projects/archive")
    page.locator(f"#project-{pid}").get_by_role("button", name="Вернуть", exact=True).click()
    page.wait_for_url(re.compile(r"ok=project_restored"))
    expect(page.locator(f"#project-{pid}")).to_be_visible()
    page.locator(f"#project-{pid}").get_by_role("link", name="Удалить…", exact=True).click()
    expect(page.locator("h1")).to_contain_text("Удалить проект «Временный проект»?")
    page.get_by_role("button", name="Удалить навсегда", exact=True).click()
    page.wait_for_url(re.compile(r"ok=project_deleted"))
    expect(page.locator(f"#project-{pid}")).to_have_count(0)


def test_keys_help_and_theme_choice(ui):
    page, _ = ui
    page.goto("/")
    page.keyboard.press("Shift+Slash")
    expect(page.locator("#keys-dialog")).to_be_visible()
    expect(page.locator("#keys-dialog")).to_contain_text("отметить «Внесено в Hub»")
    page.keyboard.press("Escape")
    expect(page.locator("#keys-dialog")).to_be_hidden()
    before = page.evaluate("document.documentElement.getAttribute('data-theme')")  # по времени суток
    flipped = "light" if before == "dark" else "dark"
    page.click("#theme-toggle")
    assert page.evaluate("document.documentElement.getAttribute('data-theme')") == flipped
    page.reload()
    assert page.evaluate("document.documentElement.getAttribute('data-theme')") == flipped
    expect(page.locator("#theme-toggle")).to_have_attribute("data-mode", flipped)


def test_pages_fit_narrow_screens_in_both_themes(browser, app_server):
    context, page, watch = open_page(browser, app_server.url)
    try:
        pid = create_demo(page)
        run_id = run_triage(page, pid)
        page.goto(f"/projects/{pid}/continue")
        page.wait_for_url(re.compile(r"/findings/\d+(?:\?.*)?$"))
        card = finding_id_from(page.url)
        page.goto(f"/projects/{pid}/sca")
        sca_card = int(re.search(r"/sca/findings/(\d+)", page.locator("#sca-continue").get_attribute("href")).group(1))
        page.click("#component-research a[href$='/components']")
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        component_card = page.locator("table.table-components tbody tr a[data-row-link]").first.get_attribute("href")
    finally:
        context.close()
    pages = ["/", "/projects/archive", "/settings", f"/projects/{pid}", f"/projects/{pid}/findings",
             f"/projects/{pid}/findings/{card}", f"/projects/{pid}/sca", f"/projects/{pid}/sca/findings/{sca_card}",
             f"/projects/{pid}/components", component_card, f"/projects/{pid}/folders", f"/projects/{pid}/delete",
             f"/runs/{run_id}"]
    problems = []
    for width, theme in ((360, "light"), (360, "dark"), (1440, "light")):
        context, page, watch = open_page(browser, app_server.url, width=width, height=800, theme=theme)
        try:
            for url in pages:
                page.goto(url)
                if not no_horizontal_scroll(page):
                    wide = page.evaluate("document.documentElement.scrollWidth")
                    problems.append(f"{width} px, {theme}: {url} – ширина страницы {wide}")
            problems += [f"{width} px, {theme}: {p}" for p in watch.problems()]
        finally:
            context.close()
    assert not problems, "\n".join(problems)
