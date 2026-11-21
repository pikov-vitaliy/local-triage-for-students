"""Интерфейс исследования компонентов: список, карточка, формы, ошибки и история решений.

Проверки идут через настоящие маршруты и базу во временной папке. Данные выдуманные; прежние ответы SCA здесь не
используются и не изменяются.

Все пакеты и идентификаторы уязвимостей в фикстурах выдуманы: example-parser, demo-xml, CVE-2099-10001. Реальное
имя библиотеки с выдуманными фактами выдавало бы фикстуру за эталон проверки настоящей уязвимости.
"""

from __future__ import annotations

import json
import re

from component_research_fixtures import complete_research_row

from app.sca_contract import ANSWER_CONTRACT, VALIDATOR_VERSION
from hub_fixtures import SCA_ROWS, make_hub_xlsx
from test_web import ORIGIN, create_project, upload, web  # noqa: F401

VULN_ID = "CVE-2099-10001"          # выдуманный идентификатор: 2099 не существует как год выпуска
FIXED_VERSION = "1.4.9"              # версия из фикстуры выгрузки, в ответе агента – как релиз
LATEST_VERSION = "9.0.99"            # тоже выдуманная: в выгрузке такой версии нет
ADVISORY_URL = "https://advisories.example.invalid/demo/CVE-2099-10001.json"


def project_with_components(web, *, rows=None) -> int:
    pid = create_project(web.client)
    report = make_hub_xlsx(web.tmp / "components.xlsx", sast=(), sca=SCA_ROWS if rows is None else rows)
    assert upload(web.client, pid, report).status_code == 303
    return pid


def build_task(web, pid: int) -> dict:
    response = web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303, response.text
    return web.client.get(f"/projects/{pid}/components/task.json").json()


def answer_document(manifest: dict) -> dict:
    """Ответ агента по действующему контракту: у охвата обязательны цель проверки, точный запрос и ссылки на
    источник – без записи об уязвимостях пакет не может считаться чистым."""
    rows = []
    for index, source in enumerate(manifest["rows"]):
        vulnerable = index == 0
        rows.append({
            "input_ref": source["input_ref"], "ecosystem": source["ecosystem"],
            "component": source["component"], "current_version": source["version"],
            "identity_resolution": {"state": "resolved", "coordinates": source["component"], "candidates": [],
                                    "note": "Координаты совпали с записью реестра", "source_refs": ["ev-1"]},
            "latest_stable_release": {"version": LATEST_VERSION, "released_at": "2026-09-30",
                                      "note": "Стабильный релиз по записи реестра", "source_refs": ["ev-1"]},
            "update_status": "update_available",
            "support_status": {"state": "eol", "scope": "oss", "as_of": "2026-10-01",
                               "note": "Открытая поддержка ветки объявлена завершённой", "source_refs": ["ev-1"]},
            "public_findings": ([{"id": VULN_ID, "aliases": ["GHSA-2099-0000-0001"], "applies": "yes",
                                  "description": "Обход проверки значения из внешнего источника",
                                  "ranges": [{"introduced": "1.4.0", "fixed": FIXED_VERSION}],
                                  "conditions": "Затронута только описанная конфигурация разбора",
                                  "fixed_versions": [FIXED_VERSION],
                                  "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                           "version": "3.1"},
                                  "source_refs": ["ev-1"]}] if vulnerable else []),
            "research_coverage": [
                {"source": "Реестр пакетов", "purpose": "release", "checked_at": "2026-10-16", "status": "ok",
                 "complete": True, "note": "Запись о релизе и датах выхода",
                 "query": {"ecosystem": source["ecosystem"], "coordinates": source["component"],
                           "version": source["version"]},
                 "source_refs": ["ev-1"]},
                {"source": "Бюллетени уязвимостей", "purpose": "vulnerabilities", "checked_at": "2026-10-16",
                 "status": "ok", "complete": True, "note": "Запрос по координатам и версии",
                 "query": {"ecosystem": source["ecosystem"], "coordinates": source["component"],
                           "version": source["version"]},
                 "source_refs": ["ev-1"]},
            ],
            "package_advice": {"action": "update" if vulnerable else "no_action",
                               "target_version": FIXED_VERSION if vulnerable else None,
                               "compatibility_notes": "Проверить совместимость" if vulnerable else "Обновлений нет",
                               "remaining_risks": ["Нужна проверка в приложении"] if vulnerable else []},
            "evidence": [{"evidence_ref": "ev-1", "url": ADVISORY_URL, "checked_at": "2026-10-16",
                          "source_type": "advisory", "justification": "Запись бюллетеня о пакете и версии",
                          "quote": f"{VULN_ID}: уязвимость в диапазоне версий", "level": "primary"}],
            "gaps": [], "package_status": "vulnerable" if vulnerable else "no_known_vulnerabilities",
        })
    rows = [complete_research_row(item) for item in rows]
    return {"contract": ANSWER_CONTRACT, "task_id": manifest["task_id"],
            "manifest_sha256": manifest["manifest_sha256"], "validator_version": VALIDATOR_VERSION,
            "generated_at": "2026-10-17T10:00:00Z", "row_count": len(rows), "rows": rows}


def upload_answer(web, pid: int, document: dict):
    return web.client.post(f"/projects/{pid}/components/answers", headers=ORIGIN, follow_redirects=False,
                           files={"file": ("answer.json", json.dumps(document, ensure_ascii=False).encode("utf-8"),
                                           "application/json")})


def expect_accepted(web, pid: int, document: dict):
    """Ответ должен быть принят. При отказе показываем протокол валидатора из ответа 422: иначе непонятно,
    какое поле виновато."""
    response = upload_answer(web, pid, document)
    if response.status_code != 303:
        errors = re.findall(r'<span class="badge badge-err">([^<]+)</span> <span class="mono break">([^<]+)</span>'
                            r'<p>([^<]*)</p>', response.text)
        raise AssertionError(f"ответ отклонён: {response.status_code}; " + "; ".join(
            f"{code} {path}: {message}" for code, path, message in errors))
    return response


def decide(web, pid: int, input_ref: str, **fields):
    """Отправка решения так, как это делает форма на странице: вместе с отпечатками показанных фактов.

    Явно переданные значения всегда выигрывают – так проверяется и решение по устаревшей странице."""
    data = {"action": "keep", "rationale": "Проверено в выпуске"}
    if "expected_research_sig" not in fields:
        page = web.client.get(f"/projects/{pid}/components/{input_ref}").text
        for name in ("revision", "expected_input_sig", "expected_research_sig", "expected_research_revision"):
            value = hidden(page, name)
            if value is not None:
                data[name] = value
    data.update(fields)
    return web.client.post(f"/projects/{pid}/components/{input_ref}/decision", data=data, headers=ORIGIN,
                           follow_redirects=False)


def hidden(html: str, name: str) -> str | None:
    """Значение скрытого поля формы или None: так видно, какие отпечатки страница собирается отправить."""
    found = re.search(rf'<input[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"', html)
    return found.group(1) if found else None


def section(html: str, section_id: str) -> str:
    match = re.search(rf'<section[^>]*id="{re.escape(section_id)}"[^>]*>.*?</section>', html, re.S)
    assert match, f"нет раздела {section_id}"
    return match.group(0)


def test_component_list_shows_facts_research_and_operator_decision(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    input_ref = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, input_ref, action="accept_risk", rationale="Функция недоступна извне").status_code == 303

    response = web.client.get(f"/projects/{pid}/components")
    assert response.status_code == 200
    html = response.text
    for needle in (
        'aria-current="page">Компоненты', f'action="/projects/{pid}/components/task"',
        f'href="/projects/{pid}/components/task/{manifest["task_id"]}.zip"',
        f'action="/projects/{pid}/components/answers"', 'id="component-answer-file"', 'name="text"',
        f'href="/projects/{pid}/components/report?format=md"', 'id="component-filters"',
        'name="status"', 'name="decision"', 'name="ecosystem"', 'name="q"',
        'data-label="Текущая версия"', 'data-label="Актуальный стабильный релиз"',
        'data-label="Поддержка"', 'data-label="Публичные уязвимости"', 'data-label="Исследование"',
        'data-label="Решение человека"', "открытая поддержка", "поддержка закончилась",
        LATEST_VERSION, "риск принят", "Функция недоступна извне",
    ):
        assert needle in html, needle
    assert "открытая лицензия" not in html
    assert f'href="/projects/{pid}/components/{input_ref}?back=' in html
    table = section(html, "component-list")
    assert 'применимых: <strong>1</strong>' in table and "публичных находок: 1" in table
    assert "проверено источников: 3 из 3" in table


def test_component_detail_separates_public_facts_advice_and_decision(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    document = answer_document(manifest)
    document["rows"][0]["package_advice"] = {"action": "accept_risk", "target_version": None,
                                               "compatibility_notes": "Сначала проверить условия",
                                               "remaining_risks": ["Эксплуатируемость не оценивалась"]}
    expect_accepted(web, pid, document)
    input_ref = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, input_ref, action="accept_risk", rationale="Внешний вызов невозможен").status_code == 303

    response = web.client.get(f"/projects/{pid}/components/{input_ref}")
    assert response.status_code == 200
    html = response.text
    for needle in (
        VULN_ID, "GHSA-2099-0000-0001", "CVSS 3.1", "cvss-critical",
        "Текущая версия", "Актуальный стабильный релиз", "Советуемая версия",
        "Координаты совпали с записью реестра", "открытая поддержка",
        "относится к этой версии", "Затронута только описанная конфигурация разбора",
        "Применимость к версии не доказывает эксплуатируемость",
        "Это рекомендация агента, а не решение человека", "Ошибки и ограничения источников",
        'target="_blank" rel="noreferrer"',
    ):
        assert needle in html, needle
    advice = section(html, "component-advice")
    assert "рассмотреть принятие риска" in advice
    assert "риск принят" not in advice
    assert "Эксплуатируемость не оценивалась" in advice
    findings = section(html, "public-findings")
    assert VULN_ID in findings
    decision = section(html, "operator-decision")
    assert "риск принят" in decision and "Внешний вызов невозможен" in decision


def test_coverage_shows_purpose_query_and_source_links(web):
    """Охват показывает, что именно и по какой версии проверяли: без этого «уязвимостей не найдено» не видно,
    откуда оно взялось. Пустая цель проверки у старых ответов остаётся видимой как «не указана»."""
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    document = answer_document(manifest)
    # Неполный протокол теперь отклоняется до записи, а не маскируется общим статусом.
    broken = json.loads(json.dumps(document))
    broken["rows"][1]["research_coverage"][0].pop("purpose")
    assert upload_answer(web, pid, broken).status_code == 422
    assert web.app.state.db.research(pid) == {}
    expect_accepted(web, pid, document)
    row = manifest["rows"][0]
    vulnerable = web.client.get(f"/projects/{pid}/components/{row['input_ref']}").text
    coverage = section(vulnerable, "research-coverage")
    assert "уязвимости" in coverage and "релиз" in coverage
    assert f'{row["component"]}@{row["version"]}' in coverage
    assert "ev-1" in coverage


def test_import_error_report_is_complete_and_nothing_is_saved(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    document = answer_document(manifest)
    document["rows"][0]["current_version"] = "0.0.0-подмена"
    response = upload_answer(web, pid, document)
    assert response.status_code == 422
    html = response.text
    assert "Ответ не принят." in html and "SCA-C002" in html
    assert "rows[0].current_version" in html and "0.0.0-подмена" in html
    assert 'id="answer-error-report"' in html
    assert web.app.state.db.research(pid) == {}


def test_decision_form_keeps_draft_on_validation_error_and_conflict(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    input_ref = manifest["rows"][0]["input_ref"]
    invalid = decide(web, pid, input_ref, action="update", rationale="Черновик обновления",
                     target_version=FIXED_VERSION, review_at="17.10.2026")
    assert invalid.status_code == 422
    html = invalid.text
    assert 'id="decision-rationale"' in html and "Черновик обновления" in html
    assert f'id="decision-target-version" value="{FIXED_VERSION}"' in html
    assert 'id="decision-review-at" value="17.10.2026"' in html
    # неверная дата – в текстовом поле: в поле type=date браузер показал бы его пустым (ревью Codex, круг 20)
    assert '<input type="text" name="review_at" id="decision-review-at" value="17.10.2026"' in html
    assert 'name="revision" value="0"' in html
    replacement = re.search(r'<input[^>]*id="decision-replacement-version"[^>]*>', html).group(0)
    assert "required" not in replacement
    assert "Введённые значения остались в форме" in html

    assert decide(web, pid, input_ref, action="keep", rationale="Прежнее решение").status_code == 303
    conflict = decide(web, pid, input_ref, action="update", rationale="Черновик из старой вкладки",
                      target_version="9.0.100", revision=0)
    assert conflict.status_code == 409
    assert "Черновик из старой вкладки" in conflict.text
    assert 'id="decision-target-version" value="9.0.100"' in conflict.text
    assert "Страница устарела" in conflict.text and "История решений" in conflict.text
    assert "Прежнее решение" in conflict.text


def test_new_research_marks_decision_stale_without_hiding_cve(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    document = answer_document(manifest)
    expect_accepted(web, pid, document)
    input_ref = manifest["rows"][0]["input_ref"]
    assert decide(web, pid, input_ref, action="accept_risk", rationale="Риск на текущей ревизии").status_code == 303
    changed = answer_document(manifest)
    changed["rows"][0]["public_findings"][0]["description"] = "Уточнённые условия применения уязвимости"
    expect_accepted(web, pid, changed)

    page = web.client.get(f"/projects/{pid}/components/{input_ref}")
    assert page.status_code == 200
    assert "Уточнённые условия применения уязвимости" in page.text
    assert VULN_ID in page.text and "требует пересмотра" in page.text
    assert "исследование обновилось после решения" in page.text
    assert "Риск на текущей ревизии" in page.text


def test_decision_form_carries_seen_facts_and_keeps_them_after_conflict(web):
    """Отпечатки показанных фактов едут вместе с формой и после отказа не подменяются свежими: иначе решение,
    выбранное по старым данным, сохранилось бы молча под новыми."""
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    input_ref = manifest["rows"][0]["input_ref"]

    page = web.client.get(f"/projects/{pid}/components/{input_ref}").text
    seen = {name: hidden(page, name) for name in ("expected_input_sig", "expected_research_sig",
                                                 "expected_research_revision", "revision")}
    assert seen["expected_input_sig"], "нет отпечатка строки задания"
    assert seen["expected_research_sig"], "нет отпечатка ответа агента"
    assert seen["expected_research_revision"] == "1", seen

    accepted = decide(web, pid, input_ref, action="accept_risk", rationale="Риск принят на показанной ревизии",
                      **seen)
    assert accepted.status_code == 303, accepted.text

    # Новое исследование приходит, пока форма человека – со старыми отпечатками
    changed = answer_document(manifest)
    changed["rows"][0]["public_findings"][0]["description"] = "Условия применения уточнены после решения"
    expect_accepted(web, pid, changed)
    refused = decide(web, pid, input_ref, action="keep", rationale="Черновик по старым фактам", **seen)
    assert refused.status_code == 409, refused.text
    for name, value in seen.items():
        assert hidden(refused.text, name) == value, (name, hidden(refused.text, name), value)
    assert "Черновик по старым фактам" in refused.text

    # Свежая страница показывает новые отпечатки: только с ними решение сохраняется
    fresh = web.client.get(f"/projects/{pid}/components/{input_ref}").text
    current = {name: hidden(fresh, name) for name in seen}
    assert current["expected_research_sig"] != seen["expected_research_sig"]
    assert current["expected_research_revision"] == "2", current
    assert decide(web, pid, input_ref, action="investigate", rationale="Проверю на новой ревизии",
                  **current).status_code == 303


def test_unknown_identity_and_source_error_are_not_rendered_as_clean(web):
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    document = answer_document(manifest)
    row = document["rows"][1]
    row["identity_resolution"] = {"state": "unresolved", "coordinates": "", "candidates": [],
                                  "note": "Не удалось подтвердить координаты", "source_refs": ["ev-1"]}
    row["research_coverage"] = [{"source": "Бюллетени уязвимостей", "purpose": "vulnerabilities",
                                 "checked_at": "2026-10-16", "status": "error",
                                 "complete": False, "note": "Источник недоступен",
                                 "query": {"ecosystem": row["ecosystem"], "coordinates": row["component"],
                                           "version": row["current_version"]},
                                 "source_refs": ["ev-1"]}]
    row["latest_stable_release"].update(version=None, released_at="", source_refs=[])
    row["update_status"] = "unknown"
    row["support_status"].update(state="unknown", scope="unknown", source_refs=[])
    row["package_status"] = "identity_unresolved"
    row["package_advice"] = {"action": "needs_identity", "target_version": None,
                             "compatibility_notes": "Сначала нужны координаты", "remaining_risks": []}
    row["gaps"] = [{"code": "SOURCE_UNAVAILABLE", "text": "Ответ источника не получен"}]
    expect_accepted(web, pid, document)

    page = web.client.get(f"/projects/{pid}/components/{row['input_ref']}")
    assert page.status_code == 200
    for needle in ("идентичность не подтверждена", "не разрешена", "Не удалось подтвердить координаты",
                   "Источник недоступен", "Ошибки и ограничения источников", "Ответ источника не получен"):
        assert needle in page.text, needle
    assert "уязвимостей не найдено" not in section(page.text, "public-findings")


def test_long_component_list_has_pagination_filters_and_compact_rows(web):
    rows = []
    for index in range(55):
        source = dict(SCA_ROWS[index % len(SCA_ROWS)])
        source["Issue id"] = str(900000 + index)
        source["Component name"] = f"org.example:component-{index:02d}-with-a-long-descriptive-name"
        source["Component version"] = "1.0.0"
        rows.append(source)
    pid = project_with_components(web, rows=rows)
    build_task(web, pid)

    whole = web.client.get(f"/projects/{pid}/components")
    assert whole.status_code == 200 and len(re.findall(r'<tr[^>]*data-input-ref=', whole.text)) == 55, "по умолчанию 200"
    first = web.client.get(f"/projects/{pid}/components?page_size=50")
    assert first.status_code == 200
    assert len(re.findall(r'<tr[^>]*data-input-ref=', first.text)) == 50
    assert "Страница 1 из 2" in first.text and 'rel="next"' in first.text
    second = web.client.get(f"/projects/{pid}/components?page=2&page_size=50")
    assert len(re.findall(r'<tr[^>]*data-input-ref=', second.text)) == 5
    assert "Страница 2 из 2" in second.text and 'rel="prev"' in second.text
    filtered = web.client.get(f"/projects/{pid}/components?q=component-54")
    assert len(re.findall(r'<tr[^>]*data-input-ref=', filtered.text)) == 1
    assert "component-54-with-a-long-descriptive-name" in filtered.text
    # строка без ответа агента: «не исследован», а не вывод об отсутствии уязвимостей. Смотрим таблицу строк,
    # а не весь блок: в фильтре состояний та же подпись стоит как вариант отбора.
    table = re.search(r'<table[^>]*table-components.*?</table>', filtered.text, re.S).group(0)
    assert "не исследован" in table and "уязвимостей не найдено" not in table
