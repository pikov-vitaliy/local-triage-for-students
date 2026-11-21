"""Этап 3: статусы Hub по-русски и «Риск принят», обновление базы до схемы 3, отметка «Внесено в Hub» с отпечатком
текста, ответы агентов SCA – охват, неполный ответ, смена ответа после решения."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import DEFAULT_STATUS_MAP
from app.db import hub_verdict
from app.models import ScaAnswer
from app.prompts import hub_text, hub_text_v2
from test_sca import AS_JSON, answer, answers_json, form_fields, post_answers, sca_card
from test_web import shown_hash, ORIGIN, hidden_fields, prepared, start_run, wait_run, web  # noqa: F401

# ============================================================================ обновление базы со схемы 2


# ============================================================================ «Риск принят»

def test_hub_verdict_and_sast_text_is_the_operator_reason():
    """Пара «решение + итог» не менялась, а текст SAST с 0.9.6 – только обоснование оператора (ADR-0089): статус
    выбирается в Hub списком. Прежний формат остаётся в hub_text_v2 – по нему узнаются старые отметки."""
    from app.models import Finding

    f = Finding(hub_id="1", kind="SAST", rule="Внедрение SQL-кода")
    assert hub_verdict("risk_accepted", "true_positive") == "risk_accepted"
    assert hub_verdict("later", "true_positive") == "uncertain"
    for outcome in ("true_positive", "false_positive", "uncertain", "risk_accepted"):
        assert hub_text(f, outcome, "Вход ограничен константой.", DEFAULT_STATUS_MAP) == "Вход ограничен константой."
    # третья категория ГОСТ Р 71207-2024 (п. 5.5) – «Риск принят»
    old = hub_text_v2(f, "risk_accepted", "Риск принят до выпуска 2.0.", DEFAULT_STATUS_MAP)
    assert old.startswith("Статус: Риск принят\nКомментарий: Подтверждена ошибка в программе: Внедрение SQL-кода; "
                          "исправление кода не требуется")
    assert "(ГОСТ Р 71207-2024, п. 5.5)" in old and old.endswith("\nОбоснование: Риск принят до выпуска 2.0.")


def test_sast_risk_accepted_is_refused(web):
    """С 0.9.6 у SAST два решения (ADR-0089): «Риск принят» в карточке не предлагается и не сохраняется – ни через
    скрипт, ни обычной формой. Прежнее такое решение карточка показывает и просит выбрать заново."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    card = web.client.get(url).text
    assert 'value="risk_accepted" form="review-form"' not in card and 'id="final-verdict"' not in card
    fields = {**hidden_fields(card), "review_revision": "0"}
    r = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **fields, "decision": "risk_accepted", "final_verdict": "true_positive",
        "comment": "Риск принят владельцем продукта до выпуска 2.0.", "action": "copy"})
    assert r.status_code == 400 and "два решения" in r.json()["detail"], r.text
    assert db.get_review(pid, "510001") is None
    # без скрипта – карточка с тем же отказом
    r = web.client.post(f"{url}/review", headers=ORIGIN, data={
        **fields, "decision": "risk_accepted", "final_verdict": "true_positive",
        "comment": "Риск принят владельцем продукта до выпуска 2.0.", "action": "save"})
    assert r.status_code == 400 and "два решения" in r.text
    assert db.get_review(pid, "510001") is None
    # прежнее решение из базы: карточка просит выбрать заново, список по-прежнему его находит
    db.save_review(pid, "510001", decision="risk_accepted", final_verdict="", final_comment="До выпуска 2.0.",
                   reviewed=True)
    card = web.client.get(url).text
    assert 'id="legacy-outcome"' in card and "Выберите решение заново" in card
    listing = web.client.get(f"/projects/{pid}/findings?decision=risk_accepted").text
    assert "510001" in listing and "риск принят" in listing


def test_entered_mark_remembers_text_and_ignores_status_rename(web):
    """Отметка «Внесено в Hub» помнит отпечаток текста. У ложного срабатывания в Hub уходит обоснование оператора
    (ADR-0089), поэтому переименование статуса в настройках текст не меняет."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    fields = {**hidden_fields(web.client.get(url).text), "review_revision": "0"}
    saved = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **fields, "decision": "false_positive", "final_verdict": "", "comment": "Параметр приводится к числу.",
        "reviewed": "1", "action": "copy"}).json()
    marked = web.client.post(f"{url}/entered", headers={**ORIGIN, "Accept": "application/json"},
                             data={"entered": "1", "review_revision": str(saved["revision"]),
                                   "text_hash": shown_hash(web.client, url)}).json()
    assert marked["ok"] and marked["entered"]
    review = db.get_review(pid, "510001")
    assert review["entered_text_hash"]
    assert 'id="entered-changed"' not in web.client.get(url).text
    # статусы Hub сменились в настройках: комментарий оператора от этого не меняется
    db.set_settings({"hub_status_map": {**DEFAULT_STATUS_MAP, "false_positive": "Ложное"}})
    assert 'id="entered-changed"' not in web.client.get(url).text
    # а правка обоснования текст меняет: отметка снимается сама
    again = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **hidden_fields(web.client.get(url).text), "review_revision": str(review["revision"]),
        "decision": "false_positive", "final_verdict": "", "comment": "Параметр приводится к числу в конструкторе.",
        "reviewed": "1", "action": "save"})
    assert again.status_code == 200 and db.get_review(pid, "510001")["entered_hub"] == 0
    # снятая отметка – сверять нечего
    web.client.post(f"{url}/entered", headers={**ORIGIN, "Accept": "application/json"}, data={"entered": "0"})
    assert db.get_review(pid, "510001")["entered_text_hash"] == ""
    assert 'id="entered-changed"' not in web.client.get(url).text


def test_entered_mark_on_a_defect_follows_the_team_name(web):
    """У подтверждённого дефекта отметка «Внесено в Hub» считается по телу дефекта: сменилось название команды –
    в Hub уже другой текст, карточка это показывает (ADR-0089)."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    fields = {**hidden_fields(web.client.get(url).text), "review_revision": "0"}
    saved = web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **fields, "decision": "true_positive", "final_verdict": "",
        "comment": "Значение из запроса попадает в SQL без параметров.", "fix": "Параметризовать запрос.",
        "reviewed": "1", "action": "save"}).json()
    body = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"}).json()["body"]
    assert "команда Платформа" in body
    marked = web.client.post(f"{url}/entered", headers={**ORIGIN, "Accept": "application/json"},
                             data={"entered": "1", "review_revision": str(saved["revision"]),
                                   "text_hash": shown_hash(web.client, url)}).json()
    assert marked["ok"] and marked["entered"]
    assert 'id="entered-changed"' not in web.client.get(url).text
    db.set_settings({"team_name": "Безопасная разработка"})
    assert 'id="entered-changed"' in web.client.get(url).text


# ============================================================================ SCA: ответы агентов

def test_sca_risk_accepted_needs_reason_and_entered_hash(web):
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73003")
    url = f"/projects/{pid}/sca/findings/{fid}"
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "risk_accepted", "final_verdict": "true_positive", "action": "copy"})
    assert r.status_code == 400 and "обоснованием" in r.json()["detail"]
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "risk_accepted", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Библиотека в закрытом контуре, обновление в следующем выпуске.", "action": "copy"})
    # «Риск принят» по SCA – с уточнением по ГОСТ Р КАПО: неактуальна или нейтрализована, иначе не сохраняется
    assert r.status_code == 400 and "ГОСТ Р КАПО" in r.json()["detail"]
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "risk_accepted", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Библиотека в закрытом контуре, обновление в следующем выпуске.", "action": "copy",
        "kapo_state": "neutralized"})
    # короткий текст 0.9.8 – только обоснование оператора; уточнение по ГОСТ Р КАПО – внутреннее поле (ADR-0091 п. 3)
    assert r.status_code == 200
    assert r.json()["hub_text"] == "demo-xml 2.0.0: Библиотека в закрытом контуре, обновление в следующем выпуске."
    assert r.json()["kapo_state"] == "neutralized"
    marked = web.client.post(f"{url}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": str(web.app.state.db.get_review(pid, "73003")["revision"])}).json()
    assert marked["entered"] and web.app.state.db.get_review(pid, "73003")["entered_text_hash"]


def test_sca_answer_scope_new_vulnerability_disables_agree(web):
    pid = prepared(web)
    item = answer("example-parser", "1.4.2", vulnerabilities=["AST-2026-000101"])
    assert post_answers(web, pid, answers_json(item)).status_code == 303
    [stored] = web.app.state.db.sca_answers(pid, "example-parser", "1.4.2")
    assert stored["vulnerabilities"] == ["AST-2026-000101"]
    # 73001 – AST-2026-000101 в охвате ответа: «Согласен с агентом» доступно
    _, card = sca_card(web, pid, "73001")
    assert 'data-model-verdict="true_positive"' in card and 'id="answer-stale"' not in card
    # 73002 – CVE-2099-10001 агент не исследовал: ответ не про неё
    fid, card = sca_card(web, pid, "73002")
    assert 'id="answer-stale"' in card and "CVE-2099-10001" in card
    assert 'data-model-verdict=""' in card and 'value="agree" form="review-form" disabled' in card
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "action": "copy"})
    assert r.status_code == 400
    page = web.client.get(f"/projects/{pid}/sca").text
    assert "ответ не про CVE-2099-10001" in page


def test_sca_answer_without_scope_takes_current_ids(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    [stored] = web.app.state.db.sca_answers(pid, "example-parser", "1.4.2")
    assert sorted(stored["vulnerabilities"]) == ["AST-2026-000101", "CVE-2099-10001"]


def test_incomplete_answer_keeps_complete_one(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    # незаполненная заготовка того же источника не затирает полный ответ
    blank = {"component": "example-parser", "version": "1.4.2", "conclusion": "", "recommended_version": "",
             "explanation": "", "links": []}
    r = post_answers(web, pid, answers_json(blank))
    assert r.status_code == 200 and "прежний полный ответ этого источника оставлен" in r.text
    [stored] = web.app.state.db.sca_answers(pid, "example-parser", "1.4.2")
    assert (stored["conclusion"], stored["recommended_version"]) == ("update", "1.4.9")
    # «обновить» без версии – тоже неполный
    r = post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", recommended_version="")))
    assert "оставлен" in r.text
    # полный ответ другого вывода заменяет
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion="not_applicable",
                                                      recommended_version=""))).status_code == 303
    [stored] = web.app.state.db.sca_answers(pid, "example-parser", "1.4.2")
    assert stored["conclusion"] == "not_applicable"


def test_changed_answer_returns_agreement_to_review(web):
    pid = prepared(web)
    db = web.app.state.db
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Обновить до 1.4.9.", "action": "save"})
    assert r.status_code == 200 and r.json()["reviewed"]
    assert db.get_review(pid, "73001")["answer_sig"]
    # тот же ответ ещё раз – решение остаётся проверенным
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    assert db.get_review(pid, "73001")["reviewed"] == 1
    # вывод сменился: решение «Согласен» возвращается на проверку, само решение остаётся
    r = post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion="not_applicable",
                                                   recommended_version="", explanation="Версия не затронута.")))
    assert r.status_code == 200 and "снята отметка «Проверено»" in r.text
    review = db.get_review(pid, "73001")
    assert (review["reviewed"], review["decision"]) == (0, "agree")
    assert 'id="answer-changed"' in sca_card(web, pid, "73001")[1]


def test_answer_model_complete_and_signature():
    full = ScaAnswer("a", "1", "2", "update", "Исправлено.", vulnerabilities=["CVE-2099-1"])
    assert full.complete()
    assert not ScaAnswer("a", "1", "", "update", "Исправлено.").complete()
    assert not ScaAnswer("a", "1", "", "", "Исправлено.").complete()
    assert not ScaAnswer("a", "1", "", "unclear", " ").complete()
    assert full.signature() == ScaAnswer("a", "1", "2", "update", "Другое пояснение.",
                                         vulnerabilities=["CVE-2099-1"]).signature()
    assert full.signature() != ScaAnswer("a", "1", "3", "update", "Исправлено.",
                                         vulnerabilities=["CVE-2099-1"]).signature()


# ============================================================================ проверки в браузере: итог запуска

def test_e2e_run_without_executed_checks_is_a_failure(monkeypatch):
    """Замечание 9: с --e2e ни одной выполненной проверки в браузере (браузера нет, всё пропущено) – ошибка, а не
    «Проверки в браузере прошли»."""
    import importlib.util
    import sys
    from types import SimpleNamespace

    e2e_dir = Path(__file__).resolve().parent / "e2e"
    monkeypatch.syspath_prepend(str(e2e_dir))
    spec = importlib.util.spec_from_file_location("e2e_conftest_probe", e2e_dir / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules.pop("e2e_conftest_probe", None)

    def session(e2e: bool, status: int = 0):
        config = SimpleNamespace(getoption=lambda name: e2e,
                                 pluginmanager=SimpleNamespace(get_plugin=lambda name: None))
        return SimpleNamespace(config=config, exitstatus=status)

    skipped_all = session(True)
    module.pytest_sessionfinish(skipped_all, 0)
    assert skipped_all.exitstatus == pytest.ExitCode.TESTS_FAILED
    plain = session(False)
    module.pytest_sessionfinish(plain, 0)
    assert plain.exitstatus == 0  # без --e2e пропуск проверок в браузере – норма
    module.pytest_runtest_logreport(SimpleNamespace(when="call", passed=True, keywords={"e2e": 1}))
    ran = session(True)
    module.pytest_sessionfinish(ran, 0)
    assert ran.exitstatus == 0
    text = (e2e_dir / "conftest.py").read_text(encoding="utf-8")
    assert "pytest.skip(" not in text  # нет браузера, порта, Ollama или модели – ошибка, а не пропуск


# ============================================================================ ссылки на строки и пределы SCA

def test_line_refs_outside_slice_are_marked():
    from app.view import missing_line_refs, model_text

    shown = {10, 11, 12}
    html = str(model_text("См. строка 11 и строка 999999.", shown))
    assert '<a class="line-ref" href="#L11">строка 11</a>' in html
    assert '<span class="line-ref-missing" title="Строки 999999 нет в показанном коде' in html
    assert 'href="#L999999"' not in html
    assert missing_line_refs("строка 11, строка 40, line 41", shown) == [40, 41]
    assert missing_line_refs("строка 40", None) == []
    assert str(model_text("строка 5")) == "строка 5"  # без среза номера не сверяются


def test_card_warns_about_comment_lines_outside_slice(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    url = f"/projects/{pid}/findings/{fid}"
    fields = {**hidden_fields(web.client.get(url).text), "review_revision": "0"}
    web.client.post(f"{url}/review", headers={**ORIGIN, "Accept": "application/json"}, data={
        **fields, "decision": "disagree", "final_verdict": "false_positive", "action": "save",
        "comment": "Значение проверено, строка 999999."})
    card = web.client.get(url).text
    assert 'id="comment-lines"' in card and "999999" in card


def test_pasted_sca_text_has_the_same_limit_as_file(web, monkeypatch):
    from app import sca as sca_module

    pid = prepared(web)
    monkeypatch.setattr(sca_module, "MAX_ANSWER_BYTES", 1000)
    big = "x" * 1500
    r = post_answers(web, pid, big)  # multipart: текстовое поле
    assert r.status_code == 400 and "больше" in r.text
    r = web.client.post(f"/projects/{pid}/sca/answers", headers=ORIGIN, data={"answers": big})  # urlencoded
    assert r.status_code == 400 and "больше" in r.text
    r = web.client.post(f"/projects/{pid}/sca/answers", headers=ORIGIN, data={"answers": "x" * 5000})
    assert r.status_code == 400 and "больше" in r.text  # отказ ещё до разбора тела


def test_sca_page_shows_package_composition_and_exclusions(web):
    pid = prepared(web)
    web.app.state.db.set_settings({"sca_internal_prefixes": ["demo-"]})
    page = web.client.get(f"/projects/{pid}/sca").text
    assert 'id="package-excluded"' in page and "demo-xml@2.0.0" in page and "внутренний компонент" in page
    assert 'id="package-rows"' in page and "example-parser@1.4.2" in page
    # прежний экспорт состава больше не выдаётся: задание собирается в новом разделе «Компоненты»
    retired = web.client.get(f"/projects/{pid}/sca/components.csv")
    assert retired.status_code == 410 and f"/projects/{pid}/components" in retired.text
    assert "AST-" not in retired.text
    assert web.client.post(f"/projects/{pid}/components/task", headers=ORIGIN,
                           follow_redirects=False).status_code == 303
    manifest = web.client.get(f"/projects/{pid}/components/task.json").json()
    assert [row["component"] for row in manifest["rows"]] == ["example-parser"]
