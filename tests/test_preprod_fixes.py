"""Предбоевая проверка 18.10.2026: исправления блокирующих замечаний (документ «Предбоевая проверка», пункты Б1–Б10,
ADR-0073). Данные выдуманные (tests/hub_fixtures.py), модель – поддельная (tests/fake_ollama.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from hub_fixtures import SAST_ROWS, make_hub_xlsx  # noqa: E402
from test_code_snapshots import (MODEL, analysed, cases, decide, remove_clone, reviewed, sync, upload,  # noqa: E402,F401
                                 web, wait_run)
from test_web import ORIGIN, prepared  # noqa: E402


# ============================================================================ Б1: долговечность записи

def test_main_database_syncs_every_commit():
    """Подтверждённая транзакция на диске до ответа: это настройка сервера базы – в поставке не ослаблена (тестовый
    контейнер работает в памяти и в расчёт не идёт)."""
    compose = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(encoding="utf-8")
    assert "synchronous_commit" not in compose and "fsync" not in compose


# ============================================================================ Б5: кэш не заменяет второе мнение

def test_ordinary_run_keeps_second_opinion_of_other_model(web):
    pid = analysed(web)  # модель MODEL дала вердикт V1
    db = web.app.state.db
    first = db.get_case(pid, "510001")["verdict_id"]
    other = "llama3.1:8b"
    web.fake.models.append({**web.fake.models[0], "name": other, "model": other})
    second = web.app.state.runner.enqueue(pid, other, "selected", ["510001"], fresh=True)  # «Пересмотреть вердикт»
    assert wait_run(web, second)["state"] == "done"
    v2 = db.get_case(pid, "510001")["verdict_id"]
    assert v2 != first
    decide(web, pid, "510001")
    assert reviewed(web, pid, "510001") == 1
    again = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=False)  # обычный прогон первой моделью
    assert wait_run(web, again)["state"] == "done"
    assert db.get_case(pid, "510001")["verdict_id"] == v2
    assert reviewed(web, pid, "510001") == 1


# ============================================================================ Б6: повторная выгрузка

def test_empty_export_is_not_applied_silently(web):
    pid = prepared(web)
    before = web.app.state.db.count_findings(pid)
    r = upload(web.client, pid, make_hub_xlsx(web.tmp / "empty.xlsx", sast=(), sca=()))
    assert r.status_code == 409 and "нет ни одной находки" in r.text
    assert web.app.state.db.count_findings(pid) == before


def test_new_findings_of_removed_clone_need_new_project(web):
    pid = analysed(web)
    remove_clone(web)
    sync(web, pid)
    assert web.app.state.db.detached_codebases(pid) == {"billing-core"}
    rows = [dict(SAST_ROWS[0], **{"Issue id": "519999", "Line number": "40"}), *SAST_ROWS]
    r = upload(web.client, pid, make_hub_xlsx(web.tmp / "next.xlsx", sast=rows))
    assert "создайте новый проект" in r.text
    assert web.app.state.db.get_finding_by_hub_id(pid, "519999") is None


# ============================================================================ полнота срезов и причины

def test_missing_file_is_complete_and_explained(web):
    from test_code_snapshots import card_url

    pid = prepared(web)
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN)
    assert page.status_code == 200
    assert web.app.state.db.get_case(pid, "510002")["context"]["reason"] == "missing"
    assert 'id="snapshots-ready"' in page.text
    assert "файла нет в клоне – разбор по строке из выгрузки: 2" in page.text
    card = web.client.get(card_url(web, pid, "510002")).text
    assert 'id="code-reason"' in card and "Файла нет в клоне." in card


def test_ambiguous_file_blocks_ready_and_lists_finding(web):
    from test_code_snapshots import clone

    pid = prepared(web)
    for folder in ("one", "two"):
        path = clone(web) / folder / "src/Renderer.java"
        path.parent.mkdir(parents=True)
        path.write_text("// строка\n" * 100, encoding="utf-8")
    rows = [dict(row, **{"File": "build/pipeline/src/Renderer.java"})
            if row["Issue id"] == "510002" else row for row in SAST_ROWS]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "ambiguous.xlsx", sast=rows)).status_code == 303
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
    db = web.app.state.db
    assert db.get_case(pid, "510002")["context"]["reason"] == "ambiguous"
    assert 'id="snapshots-ready"' not in page and 'id="snapshots-incomplete"' in page
    assert "510002" in page and "несколько подходящих файлов" in page
    assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == 1
    assert db.incomplete_snapshots(pid) == [{"hub_id": "510002", "codebase": "billing-core",
                                           "file": "build/pipeline/src/Renderer.java", "reason": "ambiguous"}]


def test_large_file_blocks_ready(web):
    from test_code_snapshots import INVOICE, clone

    pid = prepared(web)
    (clone(web) / INVOICE).write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
    assert web.app.state.db.get_case(pid, "510001")["context"]["reason"] == "too_large"
    assert 'id="snapshots-ready"' not in page and 'id="snapshots-incomplete"' in page
    assert "больше 2 МБ" in page
    assert 'id="save-snapshots"' not in page


def test_line_out_of_range_never_promises_snapshot_upgrade(web):
    from test_code_snapshots import INVOICE, card_url, clone

    pid = prepared(web)
    (clone(web) / INVOICE).write_text("// короткий файл\n", encoding="utf-8")
    for _ in range(2):
        page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
        assert web.app.state.db.get_case(pid, "510001")["context"]["reason"] == "line_out_of_range"
        assert 'id="save-snapshots"' not in page and 'id="snapshots-ready"' not in page
        assert 'id="snapshots-incomplete"' in page
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-reason"' in card and "клон, похоже, не на коммите скана" in card


def test_detached_clone_note_states_actual_reason(web):
    from test_code_snapshots import card_url

    pid = prepared(web)
    web.app.state.db.set_detached(pid, ["billing-core"])
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-reason"' in card and "клон отвязан: код берётся из срезов в базе" in card
    assert "папка репозитория для кодовой базы не задана" not in card


def test_reason_does_not_change_existing_case_hash(web):
    from app.context import build_context
    from app.models import CodeContext, Finding
    from app.triage import case_hash
    from test_code_snapshots import clone

    pid = prepared(web)
    f = Finding.from_dict(web.app.state.db.case_input(pid, "510001")["data"])
    ctx = build_context(clone(web), f, mask_key=bytes(range(32)))
    new_hash = "dcca24eb8e37221af6fd4b8930796125e88838020b14cfb5ce8a03b8ad1216f7"
    assert case_hash(f, ctx) == new_hash  # новый срез: в отпечаток входит export_line_at
    legacy = {k: v for k, v in ctx.to_dict().items()
              if k not in ("export_line_at", "export_line_check_version", "reason")}
    old_hash = "d58d132aed1dfc6ef469bb0ed2c21082527be245b84ab7600c9986221b186c9e"
    assert case_hash(f, CodeContext.from_dict(legacy)) == old_hash, "прежний вид среза даёт прежний хэш"
    ctx.reason = "missing"
    assert case_hash(f, ctx) == new_hash


def test_context_fallback_reasons_cover_missing_empty_binary_and_read_errors(tmp_path, monkeypatch):
    from app import context
    from app.models import Finding

    f = Finding(hub_id="1", kind="SAST", file="sample.py", line=50, snippet="print(value)")
    assert context.build_context(None, f, no_repo_note="клон отвязан").reason == "no_repo"
    assert "клон отвязан" in context.build_context(None, f, no_repo_note="клон отвязан").note
    assert context.build_context(tmp_path / "absent", f).reason == "no_repo"
    assert context.build_context(tmp_path, f).reason == "missing"
    assert context.build_context(tmp_path, Finding(hub_id="2", kind="SAST")).reason == "missing"
    path = tmp_path / f.file
    path.write_bytes(b"")
    assert context.build_context(tmp_path, f).reason == "empty"  # пустой файл при указанной строке
    path.write_bytes(b"\x00\x01\x02")
    assert context.build_context(tmp_path, f).reason == "binary"

    for error in (OSError("нет доступа"), context._ReadRefused("file_missing", "файл не прочитан")):
        def refuse(*args):
            raise error

        monkeypatch.setattr(context, "_read_inside", refuse)
        assert context.build_context(tmp_path, f).reason == "unreadable"


def test_unfinished_clone_walk_is_ambiguous(tmp_path, monkeypatch):
    from app import context
    from app.models import Finding

    monkeypatch.setattr(context, "_file_index", lambda root: ({}, False))
    ctx = context.build_context(tmp_path, Finding(hub_id="1", kind="SAST", file="build/src/Missing.py"))
    assert ctx.reason == "ambiguous" and "обход клона не завершён" in ctx.note


def test_snapshot_counts_and_candidates_use_reason_even_without_export_line(web):
    from app.models import CodeContext, Finding
    from app.triage import case_hash

    pid = prepared(web)
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN)
    db = web.app.state.db
    f = Finding.from_dict(db.case_input(pid, "510001")["data"])
    ctx = CodeContext.from_dict(db.get_case(pid, f.hub_id)["context"])
    for reason in ("missing", "no_repo", "empty", "ambiguous", "unreadable", "too_large", "binary",
                   "line_out_of_range", ""):
        for lines in (["print(value)"], []):
            ctx.status, ctx.reason, ctx.lines = "export_line_only", reason, lines
            payload = ctx.to_dict()
            if not reason:
                payload.pop("reason")  # реальный формат среза прежней версии
            assert db.save_case(pid, f.hub_id, case_hash(f, ctx), payload, None)
            # клон сопоставлен и на месте – no_repo тут устаревший, срез неполный (ADR-0075)
            incomplete = reason not in ("missing", "empty")
            assert db.snapshot_counts(pid)["billing-core"]["incomplete"] == int(incomplete)
            assert len(db.incomplete_snapshots(pid)) == int(incomplete)
            candidates = dict(db.snapshot_candidates(pid))
            assert (f.hub_id in candidates) == (reason in ("missing", "no_repo", "unreadable", ""))
    ctx.status = "ok"
    assert db.save_case(pid, f.hub_id, case_hash(f, ctx), ctx.to_dict(), None)
    assert db.incomplete_snapshots(pid) == []


def test_legacy_snapshot_with_unreadable_file_does_not_repeat_upgrade_promise(web):
    from app import context
    from test_code_snapshots import clone, INVOICE

    pid = prepared(web)
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN)
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    legacy = {**case["context"], "status": "export_line_only", "lines": ["// строка выгрузки"]}
    legacy.pop("reason")
    assert db.save_case(pid, "510001", "legacy", legacy, None)
    path = clone(web) / INVOICE
    path.write_bytes(b"x" * (context.MAX_FILE_BYTES + 1))
    assert context.file_presence(clone(web), INVOICE) == "found"
    for _ in range(2):
        page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
        assert 'id="save-snapshots"' not in page
        assert 'id="snapshots-incomplete"' in page and "сохранён прежней версией" in page
        assert db.get_case(pid, "510001")["case_hash"] == "legacy"


def test_unreadable_snapshot_can_upgrade_after_read_access_returns(web, monkeypatch):
    from app import context

    pid = prepared(web)
    original = context._read_inside

    def refuse(*args):
        raise OSError("нет доступа")

    monkeypatch.setattr(context, "_read_inside", refuse)
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
    assert web.app.state.db.get_case(pid, "510001")["context"]["reason"] == "unreadable"
    assert 'id="save-snapshots"' not in page
    again = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
    assert 'id="save-snapshots"' not in again
    monkeypatch.setattr(context, "_read_inside", original)
    assert 'id="save-snapshots"' in web.client.get(f"/projects/{pid}").text
    page = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN).text
    assert 'id="snapshots-ready"' in page and 'id="save-snapshots"' not in page
    assert web.app.state.db.get_case(pid, "510001")["context"]["reason"] == ""


def test_incomplete_snapshots_limit_order_and_current_export(web):
    from test_code_snapshots import INVOICE, clone

    pid = prepared(web)
    rows = [dict(SAST_ROWS[0], **{"Issue id": str(520000 + i)}) for i in range(55)]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "many.xlsx", sast=[*rows, *SAST_ROWS])).status_code == 303
    (clone(web) / INVOICE).write_text("// короткий файл\n", encoding="utf-8")
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN)
    db = web.app.state.db
    expected = db._all("SELECT hub_id FROM findings WHERE project_id = ? AND kind = 'SAST'"
                       " AND hub_id <> '510002' AND hub_id <> '510003' AND hub_id <> '510004' ORDER BY pos", (pid,))
    assert [r["hub_id"] for r in db.incomplete_snapshots(pid)] == [r["hub_id"] for r in expected[:50]]
    assert len(db.incomplete_snapshots(pid, limit=100)) == 56
    assert db.incomplete_snapshots(pid, limit=0) == []
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "current.xlsx")).status_code == 303
    assert [r["hub_id"] for r in db.incomplete_snapshots(pid)] == ["510001"]


def test_detached_clone_reason_reaches_current_code_and_runner(web):
    from app.triage import current_code

    pid = prepared(web)
    db = web.app.state.db
    db.set_detached(pid, ["billing-core"])
    _, ctx, _ = current_code(web.settings, db.case_input(pid, "510001"), web.app.state.mask_key)
    assert ctx.reason == "no_repo" and "клон отвязан" in ctx.note
    run = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    assert wait_run(web, run)["state"] == "done"
    saved = db.get_case(pid, "510001")["context"]
    assert saved["reason"] == "no_repo" and "клон отвязан" in saved["note"]
    assert db.get_case(pid, "510001")["verdict_id"] is not None


# ============================================================================ Пакет 3

"""Регрессии интерфейса решений: подтверждения, черновики сервера, вердикты и переходы по ID."""

import re

import pytest

from app.hub_import import parse_workbook
from app.models import Finding
from app.routes.findings import line_warnings
from app.routes.sca import decision_state
from app.triage import order_findings
from fake_ollama import verdict_answer
from hub_fixtures import INVOICE, make_hub_xlsx
from test_code_snapshots import analysed, card_url, cases, clone, decide, form_of, web  # noqa: F401
from test_sca import form_fields, sca_card
from test_web import ORIGIN, prepared

AS_JSON = {**ORIGIN, "Accept": "application/json"}


def test_project_folder_reset_requires_confirmation(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    db = web.app.state.db
    before = cases(web, pid)
    (web.tmp / "repos" / "other").mkdir()
    url = f"/projects/{pid}/repos"
    blocked = web.client.post(url, data={"repos_dir": "other"}, headers=ORIGIN, follow_redirects=False)
    assert blocked.status_code == 409
    assert f"срезов кода: {len(before)}; отметок «Проверено»: 1" in blocked.text
    assert "единственная копия кода" in blocked.text
    assert cases(web, pid) == before
    assert db.get_project(pid)["repos_dir"] == "team"
    assert db.get_review(pid, "510001")["reviewed"] == 1
    saved = web.client.post(url, data={"repos_dir": "other", "confirm_reset": "1"},
                            headers=ORIGIN, follow_redirects=False)
    assert saved.status_code == 303
    assert db.get_project(pid)["repos_dir"] == "other"
    assert not cases(web, pid)
    assert db.get_review(pid, "510001")["reviewed"] == 0


def test_codebase_reset_is_atomic_and_counts_only_changed_folders(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    db = web.app.state.db
    before = cases(web, pid)
    mapping = db.get_codebase_map(pid)
    expected = db.case_reset_counts(pid)["billing-core"]
    data = {"cb-1": "billing-core", "folder-1": "Catalog_API", "cb-2": "catalog-api", "folder-2": "Catalog_API"}
    url = f"/projects/{pid}/codebases"
    response = web.client.post(url, data=data, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 409
    assert f"срезов кода: {expected['cases']}; отметок «Проверено»: 1" in response.text
    assert cases(web, pid) == before and db.get_codebase_map(pid) == mapping
    response = web.client.post(url, data={**data, "confirm_reset": "1"}, headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303
    assert db.get_codebase_map(pid)["billing-core"]["folder"] == "Catalog_API"
    assert db.get_case(pid, "510001") is None
    assert db.get_case(pid, "510004") is not None


def test_missing_findings_still_require_reset_confirmation(web):
    pid = analysed(web)
    db = web.app.state.db
    db.save_import(pid, "empty.xlsx", "hub", [], {}, [], [])
    before = cases(web, pid)
    response = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": ""},
                               headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 409 and cases(web, pid) == before
    assert f"срезов кода: {len(before)}; отметок «Проверено»: 0" in response.text


def test_unchanged_folder_does_not_need_confirmation(web):
    pid = analysed(web)
    before = cases(web, pid)
    response = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"},
                               headers=ORIGIN, follow_redirects=False)
    assert response.status_code == 303 and cases(web, pid) == before


@pytest.mark.parametrize("json_response", [False, True])
def test_disagree_requires_final_verdict_and_keeps_draft(web, json_response):
    pid = prepared(web)
    url = card_url(web, pid, "510001")
    response = web.client.post(url + "/review", headers=AS_JSON if json_response else ORIGIN, data={
        **form_of(web.client.get(url).text), "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "",
        "comment": "Мой несохранённый комментарий", "reviewed": "1"})
    assert response.status_code == 400
    assert "Выберите итоговый вердикт" in response.text
    assert web.app.state.db.get_review(pid, "510001") is None
    if not json_response:
        assert "Мой несохранённый комментарий" in response.text and 'data-draft="1"' in response.text


@pytest.mark.parametrize("verdict", ["", "true_positive"])
def test_sca_empty_decision_does_not_save(web, verdict):
    pid = prepared(web)
    fid, html = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    response = web.client.post(url + "/review", headers=ORIGIN, data={
        **form_fields(html), "fix": "Параметризовать запрос.", "decision": "", "final_verdict": verdict, "comment": "Мой вывод"})
    assert response.status_code == 400 and "Выберите решение" in response.text
    db = web.app.state.db
    row = db.get_finding_by_hub_id(pid, "73002")
    assert db.get_review(pid, "73002") is None
    assert decision_state(Finding.from_dict(row["data"]), db.get_review(pid, "73002"), None, row)[0] == "none"
    assert 'value="disagree" checked' not in response.text


def test_sca_own_decision_and_legacy_record(web):
    pid = prepared(web)
    db = web.app.state.db
    fid, html = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    response = web.client.post(url + "/review", headers=AS_JSON, data={
        **form_fields(html), "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive", "comment": "Обновить"})
    assert response.status_code == 200
    assert db.get_review(pid, "73002")["decision"] == "disagree"
    db.save_review(pid, "73002", decision="", final_verdict="true_positive", final_comment="Старое решение",
                   reviewed=False, verdict_id=None)
    html = web.client.get(url).text
    assert re.search(r'value="disagree"[^>]*checked', html)
    # «Обновить» без готового дефекта набора: отметка «дефект создан в Hub» скрыта – сервер её всё равно отклонит
    # (ревью шага 6 выпуска 0.9.11)
    assert re.search(r'id="mark-entered"[^>]*hidden', html)
    row = db.get_finding_by_hub_id(pid, "73002")
    assert decision_state(Finding.from_dict(row["data"]), db.get_review(pid, "73002"), None, row)[0] == "ok"


def test_agree_uses_new_model_verdict_and_checks_what_was_shown(web):
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, "510001")
    decide(web, pid, "510001", decision="agree", verdict="false_positive")
    old_form = form_of(web.client.get(url).text)
    case = db.get_case(pid, "510001")
    verdict_id = db.save_verdict(case["case_hash"], "qwen2.5-coder:14b", "sast-v4",
                                 verdict_answer("true_positive"), {})
    db.save_case(pid, "510001", case["case_hash"], case["context"], verdict_id)
    current = web.client.get(url).text
    # у SAST решение показывается кнопкой исхода, и это исход человека: новый ответ модели его не переворачивает
    # (ADR-0097, прежде форма показывала исход нового вердикта); прямая отправка «Согласен» ниже – совместимость
    assert 'value="false_positive" form="review-form" checked' in current
    assert 'value="true_positive" form="review-form" checked' not in current
    stale = web.client.post(url + "/review", headers=AS_JSON, data={**old_form, "fix": "Параметризовать запрос.", "decision": "agree"})
    assert stale.status_code == 409
    response = web.client.post(url + "/review", headers=AS_JSON, data={
        **form_of(current), "fix": "Параметризовать запрос.", "decision": "agree", "final_verdict": "false_positive", "comment": "Согласен"})
    assert response.status_code == 200 and response.json()["final_verdict"] == "true_positive"


def test_stale_code_blocks_agreement_but_allows_own_reviewed_decision(web):
    """«Согласен» с ответом о прежнем срезе не сохраняется; своё решение – с отметкой «Проверено» (ADR-0147)."""
    pid = analysed(web)
    db = web.app.state.db
    file = clone(web) / INVOICE
    file.write_text(file.read_text(encoding="utf-8").replace("owner", "account"), encoding="utf-8")
    url = card_url(web, pid, "510001")
    form = form_of(web.client.get(url).text)
    response = web.client.post(url + "/review", headers=AS_JSON, data={
        **form, "fix": "Параметризовать запрос.", "decision": "agree", "final_verdict": "false_positive", "reviewed": "1"})
    assert response.status_code == 409 and "Код изменился после разбора" in response.text
    assert db.get_review(pid, "510001") is None
    response = web.client.post(url + "/review", headers=AS_JSON, data={
        **form, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive", "comment": "Проверено по текущему коду.",
        "reviewed": "1"})
    assert response.status_code == 200 and response.json()["reviewed"]


@pytest.mark.parametrize("hub_id,section", [("510001", "findings"), ("73002", "sca/findings")])
@pytest.mark.parametrize("missing", [False, True])
def test_by_id_finds_current_and_missing_findings(web, hub_id, section, missing):
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, hub_id)["id"]
    if missing:
        db.save_import(pid, "empty.xlsx", "hub", [], {}, [], [])
    response = web.client.get(f"/projects/{pid}/findings/by-id", params={"hub_id": f" {hub_id} "},
                              follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/projects/{pid}/{section}/{fid}"


def test_by_id_not_found_returns_list(web):
    pid = prepared(web)
    response = web.client.get(f"/projects/{pid}/findings/by-id?hub_id=unknown")
    assert response.status_code == 200 and "Находка с таким ID не найдена" in response.text
    assert 'id="hub-id"' in response.text


def test_reimport_shifted_rows_is_unchanged(web):
    pid = prepared(web)
    db = web.app.state.db
    result = parse_workbook(make_hub_xlsx(web.tmp / "shifted.xlsx"))
    rows = order_findings(result.findings, web.settings.sca_urgent_cvss)
    for row in rows:
        row["data"]["sheet"] = "Другой лист"
        row["data"]["row"] = int(row["data"].get("row") or 0) + 10
    stats = db.save_import(pid, "shifted.xlsx", result.format, result.sheets, result.summary, [], rows)
    assert stats["updated"] == 0 and stats["unchanged"] == len(rows)
    row = next(row for row in rows if row["kind"] == "SCA")
    row["data"]["version"] = "99.0"
    stats = db.save_import(pid, "changed.xlsx", result.format, result.sheets, result.summary, [], rows)
    assert stats["updated"] == 1


@pytest.mark.parametrize("kind", ["SCA-license", "DAST"])
def test_continue_reaches_licenses_and_dast(web, kind):
    pid = prepared(web)
    db = web.app.state.db
    finding = Finding(hub_id="900001", kind=kind)
    db.save_import(pid, "next.xlsx", "hub", [], {}, [], order_findings([finding], 7))
    response = web.client.get(f"/projects/{pid}/continue", follow_redirects=False)
    fid = db.get_finding_by_hub_id(pid, finding.hub_id)["id"]
    assert response.headers["location"] == f"/projects/{pid}/findings/{fid}"


def test_group_count_and_reason_grammar(web):
    pid = prepared(web)
    html = web.client.get(f"/projects/{pid}/findings?group_by=family").text
    assert re.search(r"Показано групп: [1-9]\d* из [1-9]\d*", html)
    assert line_warnings("строка 99", "строка 99", {1}) == [
        "Обоснование ссылается на строки, которых нет в показанном коде: 99. Сверьте с кодом.",
        "Рекомендации модели ссылаются на строки, которых нет в показанном коде: 99. Сверьте с кодом."]
