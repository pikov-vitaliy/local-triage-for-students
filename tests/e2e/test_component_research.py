"""Полный цикл исследования компонентов в браузере на демо-выгрузке и поддельной модели.

Демо-проект → раздел «Компоненты» → сборка задания → скачивание комплекта → ответ агента по действующему
контракту → импорт → публичная уязвимость, версии и поддержка → решение оператора → та же уязвимость после
«принятия риска» → новое исследование делает решение устаревшим → ответ с ошибкой формата не пишет ни одной
строки → решение по устаревшей странице не принимается молча.

Все пакеты и идентификаторы уязвимостей выдуманы: демо-выгрузка даёт example-parser и demo-xml, ответ агента
ссылается на CVE-2099-10001. Реальных названий библиотек и уязвимостей в проверке нет.
"""

from __future__ import annotations

import json
import re
import zipfile
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from component_research_fixtures import complete_research_row

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import Page, expect  # noqa: E402

from e2e_support import create_demo, no_horizontal_scroll, open_page  # noqa: E402

pytestmark = pytest.mark.e2e

VULN_ID = "CVE-2099-10001"
ADVISORY_URL = "https://advisories.example.invalid/demo/CVE-2099-10001.json"
FIXED_VERSION = "2.3.9"  # текущая демо-версия 2.3.1 должна входить в выдуманный диапазон
LATEST_VERSION = "9.0.99"
CARD = r"/projects/\d+/components/maven:[0-9a-f]{16}"

#: в комплекте задания не должно быть ни кода, ни путей, ни названий кодовых баз, ни номеров находок выгрузки.
#: Слово «AST» в task.md есть – там запрет на внутренние номера, поэтому проверяются номера вида AST-2026-000101.
NOT_IN_KIT = ("billing-core", "catalog-api", "notify-gateway", ".java", "src/main", "catalog_api",
              "73001", "73002", "73003", "Demo Library")
AST_NUMBER = re.compile(r"AST-\d{4}")


def answer_document(manifest: dict[str, Any], *, changed: bool = False, again: bool = False,
                    broken: bool = False) -> dict[str, Any]:
    """Ответ агента по контракту из манифеста: охват с целью проверки, точным запросом и ссылкой на источник.

    changed и again – два последовательных исследования с уточнённым описанием находки: второе нужно, чтобы
    отпечаток ответа действительно сменился, иначе сервер честно скажет, что новой ревизии нет;
    broken – подмена версии, которую отклоняет валидатор целиком, а не частично."""
    today = date.today()
    description = ("Обход проверки значения из внешнего источника" if not changed and not again else
                   "Уточнённые условия применения уязвимости" if not again else
                   "Уточнённые условия применения уязвимости: проверено из второй вкладки")
    rows = []
    for index, source in enumerate(manifest["rows"]):
        vulnerable = index == 0
        rows.append({
            "input_ref": source["input_ref"], "ecosystem": source["ecosystem"],
            "component": source["component"],
            "current_version": "0.0.0-подмена" if broken and vulnerable else source["version"],
            "identity_resolution": {"state": "resolved", "coordinates": source["component"], "candidates": [],
                                    "note": "Координаты совпали с записью реестра", "source_refs": ["ev-1"]},
            "latest_stable_release": {"version": LATEST_VERSION, "released_at": (today - timedelta(days=17)).isoformat(),
                                      "note": "Стабильный релиз по записи реестра", "source_refs": ["ev-1"]},
            "update_status": "update_available" if source['ecosystem'] in ('maven', 'npm') else 'unknown',
            "support_status": {"state": "eol", "scope": "oss", "as_of": today.isoformat(),
                               "note": "Открытая поддержка ветки объявлена завершённой", "source_refs": ["ev-1"]},
            "public_findings": ([{"id": VULN_ID, "aliases": ["GHSA-2099-0000-0001"], "applies": "yes",
                                  "description": description,
                                  "ranges": [{"introduced": "1.4.0", "fixed": FIXED_VERSION}],
                                  "conditions": "Затронута только описанная конфигурация разбора",
                                  "fixed_versions": [FIXED_VERSION],
                                  "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                           "version": "3.1"},
                                  "source_refs": ["ev-1"]}] if vulnerable else []),
            "research_coverage": [
                {"source": "Реестр пакетов", "purpose": "release", "checked_at": today.isoformat(), "status": "ok",
                 "complete": True, "note": "Запись о релизе и датах выхода",
                 "query": {"ecosystem": source["ecosystem"], "coordinates": source["component"],
                           "version": source["version"]},
                 "source_refs": ["ev-1"]},
                {"source": "Бюллетени уязвимостей", "purpose": "vulnerabilities", "checked_at": today.isoformat(),
                 "status": "ok", "complete": True, "note": "Запрос по координатам и версии",
                 "query": {"ecosystem": source["ecosystem"], "coordinates": source["component"],
                           "version": source["version"]},
                 "source_refs": ["ev-1"]},
            ],
            "package_advice": {"action": "accept_risk" if vulnerable else "no_action",
                               "target_version": None,
                               "compatibility_notes": "Применимость к этой версии не проверена в приложении",
                               "remaining_risks": ["Нужна проверка в приложении"] if vulnerable else []},
            "evidence": [{"evidence_ref": "ev-1", "url": ADVISORY_URL, "checked_at": today.isoformat(),
                          "source_type": "advisory", "justification": "Запись бюллетеня о пакете и версии",
                          "quote": f"{VULN_ID}: уязвимость в диапазоне версий", "level": "primary"}],
            "gaps": ([] if source['ecosystem'] in ('maven', 'npm') else [
                {'code': 'VERSION_UNKNOWN', 'text': 'Порядок версий этой экосистемы не проверяется данным MVP'}]),
            "package_status": "vulnerable" if vulnerable else "no_known_vulnerabilities",
        })
    rows = [complete_research_row(item) for item in rows]
    return {"contract": manifest["answer_contract"], "task_id": manifest["task_id"],
            "manifest_sha256": manifest["manifest_sha256"], "validator_version": manifest["validator_version"],
            "generated_at": f"{today.isoformat()}T10:00:00Z", "row_count": len(rows), "rows": rows}


def write_answer(tmp_path: Path, manifest: dict[str, Any], name: str, **kwargs) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(answer_document(manifest, **kwargs), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def manifest_of(page: Page, pid: int) -> dict[str, Any]:
    """Манифест действующего задания: по нему собирается корректный ответ агента."""
    response = page.request.get(f"/projects/{pid}/components/task.json")
    assert response.status == 200, response.text()
    return response.json()


def upload_answer(page: Page, pid: int, path: Path) -> None:
    """Загрузка ответа с новой ревизией: «не изменился» – это другой исход, и такой ответ проверке не годится."""
    page.goto(f"/projects/{pid}/components")
    if not page.locator("#component-answers").evaluate("el => el.open"):
        page.locator("#component-answers > summary").click()
    page.set_input_files("#component-answer-file", str(path))
    page.click("#upload-component-answer")
    page.wait_for_url(re.compile(r"ok=answers&"))
    expect(page.locator(".flash-ok")).to_contain_text("Ответ сохранён")


def wide_elements(page: Page, limit: int = 5) -> list[str]:
    """Элементы, которые шире окна: без их адреса сообщение «страница не помещается» бесполезно.

    Внутренние прокручиваемые полосы (вкладки проекта) не считаются: там прокрутка положена по проекту."""
    width = page.evaluate("document.documentElement.clientWidth")
    return page.evaluate(
        """(limit) => {
             const scrolls = (node) => {
               for (let p = node.parentElement; p && p !== document.body; p = p.parentElement) {
                 const over = getComputedStyle(p).overflowX;
                 if (over === 'auto' || over === 'scroll') return true;
               }
               return false;
             };
             return [...document.querySelectorAll('body *')]
               .filter((node) => node.getBoundingClientRect().right > limit + 1 && !scrolls(node))
               .slice(0, 8)
               .map((node) => node.tagName.toLowerCase() + '.' + String(node.className || '').split(' ')[0]);
           }""",
        width)


def first_card_href(page: Page, pid: int) -> str:
    page.goto(f"/projects/{pid}/components")
    href = page.locator("table.table-components tbody tr a[data-row-link]").first.get_attribute("href")
    assert href and re.search(CARD, href), href
    return href


def vulnerable_href(page: Page, pid: int, input_ref: str) -> str:
    """Ссылка на строку, по которой в ответе есть находка: карточка нужна именно та, где видны факты и решение."""
    page.goto(f"/projects/{pid}/components")
    row = page.locator(f"table.table-components tbody tr[data-input-ref='{input_ref}']")
    href = row.locator("a[data-row-link]").get_attribute("href")
    assert href and re.search(CARD, href), href
    return href


def test_component_research_cycle(ui, tmp_path: Path):
    page, watch = ui
    pid = create_demo(page)

    # Состав виден уже до сборки задания; просмотр страницы не создаёт сохранённого манифеста.
    page.goto(f"/projects/{pid}/sca")
    expect(page.locator("#component-research")).to_contain_text("Исследование компонентов")
    page.locator("#component-research").get_by_role("link", name=re.compile("компоненты", re.IGNORECASE)).click()
    expect(page).to_have_url(re.compile(rf"/projects/{pid}/components$"))
    expect(page.locator("table.table-components tbody tr")).to_have_count(3)
    expect(page.locator("table.table-components tbody tr").first).to_contain_text("не исследован")
    assert page.request.get(f"/projects/{pid}/components/task.json").status == 404

    # Сборка задания; повторная сборка того же состава ничего не пересоздаёт
    page.click("#build-task")
    page.wait_for_url(re.compile(r"ok=task"))
    expect(page.locator(".flash-ok")).to_contain_text("Задание собрано")
    manifest = manifest_of(page, pid)
    rows = page.locator("table.table-components tbody tr")
    expect(rows).to_have_count(manifest["row_count"])
    expect(rows.first).to_contain_text("не исследован")
    page.click("#build-task")
    page.wait_for_url(re.compile(r"ok=task_same"))
    expect(page.locator(".flash-ok")).to_contain_text("Состав не изменился")

    # Комплект задания: координаты, версии и проверяющая программа – без кода и номеров выгрузки
    with page.expect_download() as download:
        page.click("#download-task")
    kit = tmp_path / "sca-components.zip"
    download.value.save_as(kit)
    with zipfile.ZipFile(kit) as archive:
        assert sorted(archive.namelist()) == ["answer.schema.json", "answer.template.json", "components.json",
                                              "manifest.json", "task.md", "validate.py"]
        for name in archive.namelist():
            text = archive.read(name).decode("utf-8")
            assert not any(word in text for word in NOT_IN_KIT), (name, text[:400])
            assert not AST_NUMBER.search(text), (name, AST_NUMBER.search(text).group(0))
        assert manifest["manifest_sha256"] in archive.read("manifest.json").decode("utf-8")

    # Ответ агента, собранный по манифесту, принимается целиком
    upload_answer(page, pid, write_answer(tmp_path, manifest, "answer.json"))
    expect(page.locator("table.table-components tbody tr").first).to_contain_text("уязвим")

    # Карточка: публичная уязвимость, версии и поддержка, охват с целью проверки и ссылками на источник
    href = vulnerable_href(page, pid, manifest["rows"][0]["input_ref"])
    page.goto(href)
    expect(page.locator("#public-findings")).to_contain_text(VULN_ID)
    expect(page.locator("#public-findings")).to_contain_text("относится к этой версии")
    expect(page.locator("#component-facts")).to_contain_text(LATEST_VERSION)
    expect(page.locator("#component-facts")).to_contain_text("открытая поддержка")
    coverage = page.locator("#research-coverage")
    expect(coverage).to_contain_text("уязвимости")
    expect(coverage).to_contain_text("релиз")
    expect(coverage).to_contain_text("ev-1")
    expect(page.locator("#component-advice")).to_contain_text("рассмотреть принятие риска")
    expect(page.locator("#component-advice")).not_to_contain_text("риск принят")  # риск принимает оператор

    # Решение оператора «принять риск» с причиной: уязвимость при этом никуда не девается
    page.select_option("#decision-action", "accept_risk")
    page.fill("#decision-rationale", "Внешний вызов недоступен в этом приложении")
    page.click("#save-component-decision")
    page.wait_for_url(re.compile(r"ok=decision"))
    expect(page.locator(".flash-ok")).to_contain_text("Решение сохранено")
    expect(page.locator("#operator-decision")).to_contain_text("Внешний вызов недоступен в этом приложении")
    expect(page.locator("#public-findings")).to_contain_text(VULN_ID)

    # Новое исследование меняет описание находки: решение остаётся, но требует пересмотра
    upload_answer(page, pid, write_answer(tmp_path, manifest, "answer-changed.json", changed=True))
    page.goto(href)
    expect(page.locator("#public-findings")).to_contain_text("Уточнённые условия применения уязвимости")
    expect(page.locator("#operator-decision")).to_contain_text("требует пересмотра")
    expect(page.locator("#public-findings")).to_contain_text(VULN_ID)

    # Ответ с подменой версии отклоняется целиком: ни одна строка не сохраняется
    page.goto(f"/projects/{pid}/components")
    before = re.sub(r"\s+", "", page.locator("section[aria-label='Сводка исследования компонентов']").inner_text())
    watch.allowed_errors.append("422")  # отказ по существу – ожидаемый ответ, а не сбой страницы
    if not page.locator("#component-answers").evaluate("el => el.open"):
        page.locator("#component-answers > summary").click()
    page.set_input_files("#component-answer-file", str(write_answer(tmp_path, manifest, "answer-broken.json",
                                                                   broken=True)))
    # Другая вкладка могла запомнить закрытие: ошибка должна раскрыться независимо от этого значения.
    page.evaluate("pid => localStorage.setItem('local-triage-open:component-answers-' + pid, '0')", pid)
    page.click("#upload-component-answer")
    expect(page.locator("#answer-error-report")).to_be_visible()
    expect(page.locator("#answer-error-report")).to_contain_text("SCA-C002")
    expect(page.locator("#answer-error-report")).to_contain_text("0.0.0-подмена")
    page.goto(f"/projects/{pid}/components")
    after = re.sub(r"\s+", "", page.locator("section[aria-label='Сводка исследования компонентов']").inner_text())
    assert after == before, (before, after)

    # Решение, отправленное со страницы, открытой до нового исследования, молча не принимается.
    # Вторая вкладка нужна по существу: первая остаётся открытой с прежними фактами и своим черновиком.
    stale = page.context.new_page()
    incoming = page.context.new_page()
    try:
        stale.goto(href)
        seen_sig = stale.locator("input[name=expected_research_sig]").input_value()
        seen_revision = stale.locator("input[name=expected_research_revision]").input_value()
        stale.select_option("#decision-action", "update")
        stale.fill("#decision-target-version", LATEST_VERSION)
        stale.fill("#decision-rationale", "Черновик решения по старым фактам")
        upload_answer(incoming, pid, write_answer(tmp_path, manifest, "answer-again.json", again=True))
        stale.click("#save-component-decision")
        expect(stale.locator("#decision-error")).to_be_visible()
        expect(stale.locator("#decision-rationale")).to_have_value("Черновик решения по старым фактам")
        expect(stale.locator("input[name=expected_research_sig]")).to_have_value(seen_sig)
        expect(stale.locator("input[name=expected_research_revision]")).to_have_value(seen_revision)
        stale.goto(href)
        expect(stale.locator("#operator-decision")).to_contain_text("Внешний вызов недоступен")
    finally:
        stale.close()
        incoming.close()

    assert not watch.problems(), watch.problems()


def test_component_pages_fit_narrow_screens(browser, app_server):
    """Список и карточка компонентов не разъезжаются на узких экранах и в тёмной теме."""
    context, page, _ = open_page(browser, app_server.url)
    try:
        pid = create_demo(page)
        page.goto(f"/projects/{pid}/components")
        page.click("#build-task")
        page.wait_for_url(re.compile(r"ok=task"))
        href = first_card_href(page, pid)
    finally:
        context.close()
    problems = []
    for width, theme in ((390, "light"), (390, "dark"), (1440, "light")):
        context, page, watch = open_page(browser, app_server.url, width=width, height=800, theme=theme)
        try:
            # «Компоненты» дважды: со свёрнутыми и с раскрытыми «Все фильтры» (подписи select, CVSS в одну строку)
            for url in (f"/projects/{pid}/components", f"/projects/{pid}/components?support=unknown", href,
                        f"/projects/{pid}/components?group_by=family", f"/projects/{pid}/sca",
                        f"/projects/{pid}/sca?group_by=family"):
                page.goto(url)
                if "support=" in url:
                    assert page.locator("#component-filters-more").evaluate("d => d.open")
                if not no_horizontal_scroll(page):
                    wide = page.evaluate("document.documentElement.scrollWidth")
                    problems.append(f"{width} px, {theme}: {url} – ширина страницы {wide}; шире окна: "
                                    + ", ".join(wide_elements(page)))
            problems += [f"{width} px, {theme}: {p}" for p in watch.problems()]
        finally:
            context.close()
    assert not problems, "\n".join(problems)
