"""Замечания оператора в браузере (план dev9, часть 2). Данные выдуманы, Hub поддельный или не вызывается, сеть – только
приложение на 127.0.0.1. Снимки пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from app.models import Finding  # noqa: E402
from app.routes import findings as card_routes  # noqa: E402
from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from fake_ollama import verdict_answer  # noqa: E402
from test_component_research_ui import FIXED_VERSION, answer_document, build_task, expect_accepted, project_with_components  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_dev9_operator_notes import FP_TEXT  # noqa: E402
from test_finding_status_now import accept_state  # noqa: E402
from test_findings_ui import analysed  # noqa: E402
from test_hub_defect_update import FIX, REASON, hub_settings, prepared, ready, save_sast  # noqa: E402
from test_hub_status_routes import decide, fid, project, sast, sca  # noqa: E402
from test_sca_update_comment import _agent_answer  # noqa: E402
from test_web import start_run, wait_run, web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


def shot(page, name: str, full: bool = True) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(300)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=full)


def test_badge_of_test_code_in_card_and_list(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [Finding(hub_id="101", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo",
                                file="src/test/demo.py", line=2, snippet="x = 1", severity="high"),
                        Finding(hub_id="102", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo",
                                file="contest/demo.py", line=2, snippet="x = 1", severity="high")])
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '101')}")
        expect(page.locator(".finding-tags .test-code-badge")).to_have_text("тестовый код")
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '102')}")
        expect(page.locator(".test-code-badge")).to_have_count(0)
        page.goto(f"/projects/{pid}/findings")
        expect(page.locator(f"#finding-{fid(web, pid, '101')} .test-code-badge")).to_be_visible()
        expect(page.locator(f"#finding-{fid(web, pid, '102')} .test-code-badge")).to_have_count(0)
        no_horizontal_scroll(page)
        shot(page, "p8-list", full=False)
        assert watch.page_errors == []
    finally:
        context.close()


def test_fixed_hint_asks_to_save_only_with_unsaved_edit(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    accept_state(web, pid, "101", "Fixed")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '101')}")
        hint = page.locator("#copy-where")
        expect(hint).to_contain_text("менять в Hub нечего")
        expect(hint).not_to_contain_text("сохраните")
        page.fill("#comment", "Имя таблицы задано константой, поэтому внедрение исключено.")
        expect(hint).to_contain_text("менять в Hub нечего – сохраните решение")
        assert watch.page_errors == []
    finally:
        context.close()


def test_reviewed_mark_is_explained_and_warning_stands_by_save(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [sast("101"), sca("50001")])
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '101')}")
        expect(page.locator("#reviewed-hint")).to_have_text("отметка ставится при выборе решения")
        warn = page.locator("#unreviewed-warn")
        expect(warn).to_be_hidden()
        page.locator('input[name="decision"][value="false_positive"]').check(force=True)
        expect(page.locator("#reviewed-box")).to_be_checked()
        expect(warn).to_be_hidden()
        page.locator("#reviewed-box").uncheck(force=True)
        expect(warn).to_have_text("Без отметки «Проверено» находка останется непроверенной")
        expect(page.locator("#unreviewed-note")).to_be_visible()
        save, plate = page.locator("#save-btn").bounding_box(), warn.bounding_box()
        assert abs(save["y"] - plate["y"]) < 40 and plate["x"] > save["x"], (save, plate)
        page.locator("#decision").scroll_into_view_if_needed()
        no_horizontal_scroll(page)
        shot(page, "p7-sast", full=False)
        # «Отложить» – решение и есть «вернуться позже»: предупреждения нет, мягкая подпись осталась
        page.locator('input[name="decision"][value="later"]').check(force=True)
        expect(warn).to_be_hidden()
        expect(page.locator("#unreviewed-note")).to_contain_text("Отложено")
        # карточка SCA: то же предупреждение рядом с «Сохранить», подпись – у отметки в нижней панели
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '50001')}")
        expect(page.locator("#reviewed-hint")).to_have_text("ставится при выборе решения")
        page.locator('input[name="decision"][value="disagree"]').check(force=True)
        expect(page.locator("#reviewed-box")).to_be_checked()
        page.locator("#reviewed-box").uncheck(force=True)
        expect(page.locator("#unreviewed-warn")).to_be_visible()
        no_horizontal_scroll(page)
        shot(page, "p7-sca", full=False)
        assert watch.page_errors == []
    finally:
        context.close()


def test_push_is_main_button_only_with_unsent_edit(browser, stand):  # noqa: F811
    web, url = stand
    pid, row = ready(web, build=False)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/defects/{row['id']}")
        push = page.locator("#defect-update-prepare")
        expect(push).to_be_visible()
        expect(push).not_to_have_class(re.compile(r"btn-primary"))
        shot(page, "p10-no-edit", full=False)
        page.fill("#draft-summary", "ID5 - Ручная правка (SAST)")
        page.click("#draft-save")
        expect(push).to_have_class(re.compile(r"btn-primary"))
        shot(page, "p10-edit", full=False)
        no_horizontal_scroll(page)
        assert watch.page_errors == []
    finally:
        context.close()


def test_model_text_about_false_positive_stays_out_of_defect(browser, stand):  # noqa: F811
    """Вердикт модели «истинная», а её текст начинается с «Ложное срабатывание»: при «Подтверждаю дефект» он не подставляется, при «Ложное
    срабатывание» подставляется; решение и текст дальше не спорят."""
    web, url = stand
    pid = analysed(web, verdict_answer("true_positive", 85, hub_comment=FP_TEXT))
    card = f"/projects/{pid}/findings/{fid(web, pid, '510001')}"
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(card)
        comment = page.locator("#comment")
        expect(comment).to_have_value("")
        expect(page.locator("#comment-stale")).to_be_hidden()
        page.locator('input[name="decision"][value="true_positive"]').check(force=True)
        expect(comment).to_have_value("")
        page.locator('input[name="decision"][value="false_positive"]').check(force=True)
        expect(comment).to_have_value(FP_TEXT)
        expect(page.locator("#comment-stale")).to_be_hidden()
        page.locator('input[name="decision"][value="true_positive"]').check(force=True)
        expect(comment).to_have_value("")
        assert watch.page_errors == []
    finally:
        context.close()


def test_hidden_target_line_note_in_verdict_panel(browser, stand, monkeypatch):  # noqa: F811
    web, url = stand
    pid = analysed(web)
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    stored = dict(case["context"])
    stored["lines"] = [("<SECRET_abc123>" if stored["start_line"] + k == stored["target_line"] else line)
                       for k, line in enumerate(stored["lines"])]
    assert db.save_case(pid, "510001", case["case_hash"], stored, case["verdict_id"])
    monkeypatch.setattr(card_routes, "is_credential_finding", lambda rule, cwe: True)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '510001')}")
        expect(page.locator("#step-2 #target-line-hidden")).to_contain_text("вердикт модели по такой находке ненадёжен")
        no_horizontal_scroll(page)
        shot(page, "p2-hidden-line", full=False)
        assert watch.page_errors == []
    finally:
        context.close()


def test_status_term_like_last_time_only_by_press(browser, stand):  # noqa: F811
    """Поле срока без умолчания; «как в прошлый раз» появляется после отправки и подставляет дату только по нажатию; подпись одна."""
    web, url = stand
    pid = project(web, [sast("101"), sast("102", line=3)])
    decide(web, pid, "101")
    decide(web, pid, "102")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000, timezone_id="Etc/GMT-3")
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '101')}")
        last = page.locator("#hub-send-last")
        expect(last).to_be_hidden()
        expect(page.locator("#hub-send-expires")).to_have_value("")
        expect(page.locator("#hub-send-hint")).not_to_contain_text("UTC")
        page.locator("#hub-send [data-date-value]", has_text="+90 дней").click()
        chosen = page.locator("#hub-send-expires").input_value()
        preview = page.locator("#hub-send-until-preview")
        expect(preview).to_have_text(re.compile(r"^до \d\d\.\d\d\.\d{4}, 02:59 по вашему времени$"))
        page.locator("#hub-send-button").click()
        expect(page.locator("#hub-send-status")).to_contain_text("В очереди")
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '102')}")
        expect(page.locator("#hub-send-expires")).to_have_value("")
        expect(preview).to_be_hidden()
        expect(last).to_be_visible()
        no_horizontal_scroll(page)
        page.locator("#hub-send").scroll_into_view_if_needed()
        shot(page, "p9-last", full=False)
        last.click()
        expect(page.locator("#hub-send-expires")).to_have_value(chosen)
        expect(preview).to_contain_text("по вашему времени")
        # дата вне допустимых – кнопки нет
        page.evaluate("localStorage.setItem('local-triage-hub-expires', '2000-01-01')")
        page.reload()
        expect(page.locator("#hub-send-expires")).to_have_value("")
        expect(last).to_be_hidden()
        assert watch.page_errors == []
    finally:
        context.close()


def visible_above_bar(page, selector: str) -> None:
    """Блок виден на экране и его начало не закрыто нижней панелью и закреплённым оглавлением."""
    box = page.locator(selector).bounding_box()
    bar = page.locator(".action-bar").bounding_box()
    route = page.locator("#route").bounding_box() if page.locator("#route").count() else None
    assert box and bar and box["y"] < bar["y"] - 20, (box, bar)
    assert box["y"] >= (route["y"] + route["height"] if route and route["y"] <= 0.5 else 0) - 1, (box, route)


def test_create_is_main_button_with_hub_and_copy_is_secondary(browser, stand):  # noqa: F811
    web, url = stand
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '510001')}")
        bar = page.locator(".action-bar")
        expect(bar).to_have_attribute("data-stage", "create")
        go = page.locator("#go-create")
        expect(go).to_be_visible()
        expect(go).to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#copy-defect-bar")).to_be_visible()
        expect(page.locator("#copy-defect-bar")).not_to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#copy-title-bar")).to_be_hidden()
        expect(page.locator("#mark-entered")).to_be_hidden()
        expect(page.locator("#defect-panel")).not_to_contain_text("Создайте дефект в Hub вручную")
        no_horizontal_scroll(page)
        go.click()
        expect(page.locator("#hub-defect-button")).to_be_in_viewport()
        visible_above_bar(page, "#hub-defect")
        shot(page, "p3-create", full=False)
        # правка возвращает к сохранению
        page.fill("#comment", REASON + " Уточнение.")
        expect(bar).to_have_attribute("data-stage", "save")
        expect(go).to_be_hidden()
        assert watch.page_errors == []
    finally:
        context.close()


def test_without_hub_route_of_copying_stays(browser, stand):  # noqa: F811
    web, url = stand
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings/{fid(web, pid, '510001')}")
        expect(page.locator(".action-bar")).to_have_attribute("data-stage", "title")
        expect(page.locator("#go-create")).to_have_count(0)
        expect(page.locator("#defect-panel")).to_contain_text("Создайте дефект в Hub вручную")
        assert watch.page_errors == []
    finally:
        context.close()


def test_filter_open_no_decision_model_verdict(browser, stand):  # noqa: F811
    """Подбор оператора «открытая, без решения, вердикт модели» – кнопками «Все фильтры», без правки адреса."""
    web, url = stand
    pid = analysed(web, verdict_answer("true_positive", 85))
    db = web.app.state.db
    sast_ids = [row["hub_id"] for row in db.list_findings(pid, kind="SAST")[0]]
    with db._tx() as c:
        for n, hub_id in enumerate(sast_ids):
            row = c.execute("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = ?", (pid, hub_id)).fetchone()
            data = json.loads(row[0])
            data["status"] = "Open" if n < 2 else "Fixed"
            c.execute("UPDATE findings SET data_json = ? WHERE project_id = ? AND hub_id = ?",
                      (json.dumps(data, ensure_ascii=False), pid, hub_id))
    decided, free = sast_ids[0], sast_ids[1]
    db.save_review(pid, decided, decision="disagree", final_verdict="false_positive", final_comment="Текст.", reviewed=True)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings")
        page.locator("#findings-filters > summary").click()
        panel = page.locator("#findings-filters")
        panel.locator('nav[aria-labelledby="filter-hub_status"] a', has_text="Open").click()
        panel = page.locator("#findings-filters")
        expect(panel).to_have_attribute("open", "")
        panel.locator('nav[aria-labelledby="filter-decision"] a', has_text="нет решения").click()
        page.locator('#findings-filters nav[aria-labelledby="filter-verdict"] a', has_text="истинная").click()
        assert "hub_status=Open" in page.url and "decision=none" in page.url and "verdict=true_positive" in page.url, page.url
        rows = page.locator("table.table-findings tbody tr")
        expect(rows).to_have_count(1)
        expect(rows.first.locator(".col-id a")).to_have_text(free)
        no_horizontal_scroll(page)
        shot(page, "p11-filters", full=False)
        # чужой вердикт – пусто, с понятной подписью
        page.locator('#findings-filters nav[aria-labelledby="filter-verdict"] a', has_text="ложная").click()
        expect(page.get_by_text("Под фильтр ничего не попало.")).to_be_visible()
        assert watch.page_errors == []
    finally:
        context.close()


def test_sca_comment_takes_defect_target_and_note_stands_by_conclusion(browser, stand):  # noqa: F811
    web, url = stand
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    _agent_answer(web, pid, "99.9.9")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '73001')}")
        expect(page.locator("#final-verdict")).to_have_value("true_positive")
        comment = page.locator("#comment").input_value()
        assert f"до {FIXED_VERSION}." in comment and "99.9.9" not in comment, comment
        note = page.locator("#target-note")
        expect(note).to_have_text(f"Совет агента – 99.9.9, исследование – {FIXED_VERSION}: в дефект уйдёт {FIXED_VERSION}")
        page.locator("#final-verdict").scroll_into_view_if_needed()
        no_horizontal_scroll(page)
        shot(page, "p4-note", full=False)
        page.locator("#final-verdict").select_option("false_positive")
        expect(note).to_be_hidden()
        page.locator("#final-verdict").select_option("true_positive")
        expect(note).to_be_visible()
        assert watch.page_errors == []
    finally:
        context.close()


def test_sca_path_create_block_in_panel_and_each_step_opens_next(browser, stand):  # noqa: F811
    """«Создать дефект в Hub» – внутри панели; «Сохранить» ведёт к дефекту по шаблону, «Утвердить текст» – к созданию; блок виден и не закрыт панелью."""
    web, url = stand
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    hub_settings(web, pid)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '73001')}")
        expect(page.locator(".panel #hub-defect")).to_have_count(1)
        expect(page.locator("#hub-defect-not-ready")).to_be_visible()
        page.locator("#final-verdict").select_option("true_positive")
        expect(page.locator('input[name="decision"][value="disagree"]')).to_be_checked()
        page.get_by_role("button", name="Сохранить", exact=True).click()
        page.wait_for_url(re.compile(r"ok=sca_saved.*#sca-set$"))
        expect(page.locator("#package-explanation")).to_be_in_viewport()
        visible_above_bar(page, "#sca-set")
        no_horizontal_scroll(page)
        shot(page, "p5-after-save", full=False)
        expect(page.locator(".toast").first).to_contain_text("Решение сохранено")
        # условие не выполнено – к перечню условий, а не вниз. Короткая строка объяснения – уже предупреждение, не запрет
        # (ADR-0152); запретом остаётся пустое Объяснение
        page.fill("#package-explanation", "")
        page.click("#package-text-save")
        page.wait_for_url(re.compile(r"ok=sca_text_saved.*#sca-set-problems$"))
        visible_above_bar(page, "#sca-set-problems")
        shot(page, "p5-problems", full=False)
        # текст готов – сразу к созданию
        explanation = page.locator("#package-explanation")
        vulns = page.locator("#sca-set-vulns .item-title").all_inner_texts()
        explanation.fill("\n".join(f"{v}: подгрузка внешних сущностей при разборе документа позволяет прочитать файл сервера." for v in vulns))
        for box in ("#package-version-checked", "#package-residual-checked", "#package-text-checked"):
            if page.locator(box).count():
                page.check(box)
        page.click("#package-text-save")
        page.wait_for_url(re.compile(r"ok=sca_text_saved.*#hub-defect-section$"))
        expect(page.locator("#sca-set-problems")).to_have_count(0)
        expect(page.locator("#hub-defect-button")).to_be_in_viewport()
        visible_above_bar(page, "#hub-defect-section")
        go = page.locator("#go-create")
        expect(go).to_be_visible()
        expect(go).to_have_class(re.compile(r"btn-primary"))
        expect(page.locator("#mark-entered")).to_be_hidden()
        expect(page.locator("#defect-panel")).not_to_contain_text("Создайте дефект в Hub вручную")
        expect(page.locator("#sca-set")).not_to_contain_text("отметив их галочками")
        no_horizontal_scroll(page)
        shot(page, "p5-after-text", full=False)
        # другой итог: этапа «создание» нет, отметку он не скрывает; вернули «обновить» – этап снова тот же
        page.locator("#final-verdict").select_option("false_positive")
        expect(go).to_be_hidden()
        expect(page.locator(".action-bar")).not_to_have_attribute("data-stage", "create")
        page.locator("#final-verdict").select_option("true_positive")
        expect(go).to_be_visible()
        expect(page.locator(".action-bar")).to_have_attribute("data-stage", "create")
        page.reload()  # выбор итога не сохранён: дальше – сохранённое решение
        expect(go).to_be_visible()
        # буфер обмена отказал: подсказка без несуществующей кнопки, отметка доступна
        page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('нет')); document.execCommand = () => false; }")
        page.click("#copy-defect-bar")
        expect(page.locator("#defect-status")).to_contain_text("Не скопировано")
        expect(page.locator("#defect-status")).not_to_contain_text("Скопировал текст дефекта вручную")
        expect(page.locator("#mark-entered")).to_be_visible()
        page.reload()
        expect(go).to_be_visible()
        # копирование – ручной путь: отметка снова доступна
        page.click("#copy-defect-bar")
        expect(page.locator("#defect-status")).to_contain_text("скопирован")
        expect(page.locator("#mark-entered")).to_be_visible()
        assert watch.page_errors == []
    finally:
        context.close()
