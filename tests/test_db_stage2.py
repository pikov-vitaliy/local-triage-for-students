"""Хранилище этапа 2: обновление базы этапа 1 без потери данных, настройки, проекты (модель, архив, удаление,
ход разбора, последняя активность), находки «нет в новой выгрузке», отметки «Проверено» и «Внесено в Hub»,
защита решения от перезаписи из устаревшей вкладки, вопросы к модели, компоненты SCA и ответы внешних агентов,
соответствие AST → CVE, принятая команда прогона и неполные замеры."""

from __future__ import annotations

from db_support import connect_db
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app.db import (QUESTION_INTERRUPTED, STOPPED_NOTE, Database, ProjectBusy, StaleReview,  # noqa: E402
                    review_signature)
from app.models import Finding, ScaAnswer  # noqa: E402
from app.triage import order_findings, reorder_project  # noqa: E402

JAVA_FILE = "src/main/java/org/example/billing/InvoiceDao.java"


def sast(hub_id: str, *, line: int = 10, severity: str = "high", codebase: str = "billing-core") -> Finding:
    return Finding(hub_id=hub_id, kind="SAST", rule="Внедрение SQL-кода", cwe=["CWE-89"], file=JAVA_FILE, line=line,
                   severity=severity, codebase=codebase, snippet="String sql = base + owner;", language="Java",
                   sheet="SAST", row=line)


def sca(hub_id: str, component: str = "org.example:example-parser", version: str = "1.4.2", cvss: float = 9.8,
        vuln: str = "AST-2026-0001", cve: str = "", fixed: str = "1.4.9", codebase: str = "billing-core") -> Finding:
    return Finding(hub_id=hub_id, kind="SCA", component=component, version=version, cvss=cvss,
                   policy_severity="Critical", codebase=codebase, vuln_ids=[vuln], cve=[cve] if cve else [],
                   fixed_version=fixed, cwe=["CWE-502"], build_type="maven", sheet="SCA Security", row=int(cvss * 10))


def load(db: Database, project_id: int, findings: list[Finding], sca_cvss: float = 9.0) -> dict:
    return db.save_import(project_id, "report.xlsx", "hub", [], {}, [], order_findings(findings, sca_cvss))


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "data" / "triage.db")
    yield database
    database.close()


def verdict(value: str = "false_positive") -> dict:
    return {"verdict": value, "confidence": 70, "summary": "s", "explanation": "e", "data_flow": [],
            "evidence_lines": [10], "fix": "", "hub_comment": "c", "cwe_fit": "да", "raw": {}}


# ============================================================================ обновление базы этапа 1

STAGE1_DATA = """
INSERT INTO meta(key, value) VALUES ('schema_version', '1'), ('rev:1:billing-core', 'aaaaaaaa');
INSERT INTO projects(id, name, repos_dir, created_at, updated_at)
     VALUES (1, 'Demo Library', 'team', '2026-10-01T10:00:00+00:00', '2026-10-01T10:00:00+00:00');
INSERT INTO imports(id, project_id, filename, format, total, created_at)
     VALUES (1, 1, 'demo-hub-report.xlsx', 'hub', 2, '2026-10-01T10:00:00+00:00');
INSERT INTO findings(id, project_id, hub_id, import_id, pos, kind, severity, codebase, group_key, data_json)
     VALUES (1, 1, '100101', 1, 0, 'SAST', 'high', 'billing-core', 'g1',
             '{"hub_id": "100101", "kind": "SAST", "codebase": "billing-core", "line": 58}'),
            (2, 1, '100102', 1, 1, 'SAST', 'low', 'billing-core', 'g2',
             '{"hub_id": "100102", "kind": "SAST", "codebase": "billing-core", "line": 70}');
INSERT INTO codebase_map(project_id, codebase, folder, manual, updated_at)
     VALUES (1, 'billing-core', 'billing-core', 0, '2026-10-01T10:00:00+00:00');
INSERT INTO verdicts(id, case_hash, model, prompt_version, verdict, confidence, data_json, created_at)
     VALUES (1, 'h1', 'qwen2.5-coder:14b', 'sast-v2', 'false_positive', 80, '{"verdict": "false_positive"}',
             '2026-10-01T11:00:00+00:00');
INSERT INTO cases(project_id, hub_id, case_hash, context_json, verdict_id, updated_at)
     VALUES (1, '100101', 'h1', '{"status": "ok"}', 1, '2026-10-01T11:00:00+00:00');
INSERT INTO reviews(project_id, hub_id, decision, final_verdict, final_comment, reviewed, reviewed_at, copied_at,
                    verdict_id, finding_sig, revision, updated_at)
     VALUES (1, '100101', 'agree', 'false_positive', 'Значение приводится к числу.', 1,
             '2026-10-02T09:00:00+00:00', '2026-10-02T09:01:00+00:00', 1, 'sig', 3, '2026-10-02T09:01:00+00:00');
INSERT INTO runs(id, project_id, state, scope, model, prompt_version, total, done, created_at, updated_at)
     VALUES (1, 1, 'done', 'all', 'qwen2.5-coder:14b', 'sast-v2', 2, 2, '2026-10-01T11:00:00+00:00',
             '2026-10-03T08:00:00+00:00');
INSERT INTO run_items(run_id, seq, hub_id, state, case_hash, verdict_id) VALUES (1, 0, '100101', 'done', 'h1', 1);
"""


def layout(path: Path) -> dict:
    """Раскладка базы: таблицы с колонками (имя, тип, NOT NULL, значение по умолчанию, ключ), внешние ключи,
    индексы с колонками."""
    conn = connect_db(path)
    try:
        tables = sorted(r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
        indexes = sorted((r[0], r[1]) for r in conn.execute(
            "SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"))
        return {
            "tables": tables,
            "columns": {t: [tuple(r[1:]) for r in conn.execute(f"PRAGMA table_info({t})")] for t in tables},
            "foreign_keys": {t: sorted(tuple(r[2:]) for r in conn.execute(f"PRAGMA foreign_key_list({t})"))
                             for t in tables},
            "indexes": {name: [r[2] for r in conn.execute(f"PRAGMA index_info({name})")] for name, _ in indexes},
        }
    finally:
        conn.close()


# ============================================================================ настройки

def test_settings_are_seeded_once_and_saved(db: Database):
    defaults = {"ollama_url": "http://127.0.0.1:11434", "default_model": "qwen2.5-coder:14b",
                "hub_status_map": {"true_positive": "Confirmed", "false_positive": "False Positive",
                                   "uncertain": "To verify"}, "sca_urgent_cvss": 9.0}
    assert db.get_settings() == {}
    assert db.seed_settings(defaults) == defaults
    db.set_settings({"default_model": "gpt-oss:20b", "sca_urgent_cvss": 7.5})
    # повторный первый запуск с другими значениями окружения сохранённое не меняет
    stored = db.seed_settings({**defaults, "ollama_url": "http://host.docker.internal:11434", "new_key": 1})
    assert stored["default_model"] == "gpt-oss:20b" and stored["sca_urgent_cvss"] == 7.5
    assert stored["ollama_url"] == "http://127.0.0.1:11434" and stored["new_key"] == 1
    db._conn.execute("UPDATE settings SET value_json = '{испорчено' WHERE key = 'new_key'")
    assert "new_key" not in db.get_settings()


# ============================================================================ проекты

def test_project_model_archive_and_activity(db: Database):
    first = db.create_project("Первый", model="gpt-oss:20b")
    second = db.create_project("Второй")
    assert db.get_project(first)["model"] == "gpt-oss:20b" and db.get_project(second)["model"] == ""
    db._conn.execute("UPDATE projects SET last_activity = '2026-01-01T00:00:00+00:00'")
    load(db, first, [sast("A")])  # работа с проектом поднимает его наверх списка
    assert [p["id"] for p in db.list_projects()] == [first, second]
    db._conn.execute("UPDATE projects SET last_activity = '2026-01-01T00:00:00+00:00' WHERE id = ?", (first,))
    load(db, second, [sast("B")])
    db.save_review(second, "B", decision="later", final_verdict="", final_comment="", reviewed=False)
    assert [p["id"] for p in db.list_projects()] == [second, first]
    assert db.update_project(first, name="Первый, октябрь", model="")
    assert (db.get_project(first)["name"], db.get_project(first)["model"]) == ("Первый, октябрь", "")
    assert not db.update_project(999, name="нет")
    assert db.set_project_archived(second, True) and db.get_project(second)["archived_at"]
    assert [p["id"] for p in db.list_projects()] == [first]
    assert [p["id"] for p in db.list_projects(archived=True)] == [second]
    assert {p["id"] for p in db.list_projects(archived=None)} == {first, second}
    assert db.set_project_archived(second, False) and db.get_project(second)["archived_at"] is None


def test_project_progress_counts_current_findings(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12), sca("S1"), sca("S2", vuln="AST-2026-0002")])
    db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    db.mark_entered(pid, "A")
    db.save_review(pid, "S1", decision="disagree", final_verdict="true_positive", final_comment="", reviewed=True)
    db.mark_entered(pid, "S1")
    [project] = db.list_projects()
    assert (project["sast"], project["reviewed"], project["entered"]) == (2, 1, 1)
    assert (project["sca"], project["sca_reviewed"], project["sca_entered"], project["missing"]) == (2, 1, 1, 0)
    load(db, pid, [sast("B", line=12), sca("S1"), sca("S2", vuln="AST-2026-0002")])  # A пропала из выгрузки
    [project] = db.list_projects()
    assert (project["sast"], project["reviewed"], project["entered"], project["missing"]) == (1, 0, 0, 1)
    stats = db.review_stats(pid)
    assert (stats["sast"], stats["reviewed"], stats["sca"], stats["sca_reviewed"], stats["missing"]) == (1, 0, 2, 1, 1)


def test_delete_project_removes_its_data_and_only_its_verdicts(db: Database):
    keep, gone = db.create_project("остаётся"), db.create_project("удаляется")
    for pid in (keep, gone):
        load(db, pid, [sast("A")])
        db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
        db.sync_revisions(pid, {"billing-core": "a" * 40})
    shared = db.save_verdict("h-shared", "m", "v", verdict(), {})
    own = db.save_verdict("h-own", "m", "v", verdict(), {})
    db.save_case(keep, "A", "h-shared", {}, shared)
    db.save_case(gone, "A", "h-shared", {}, shared)
    run_id = db.create_run(gone, "m", "all", "v", ["A"])
    item = db.next_pending_item(run_id)
    db.finish_item(run_id, item["id"], "done", case_hash="h-own", verdict_id=own, seconds=1.0, model_call=True)
    db.save_review(gone, "A", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    db.add_question(gone, "A", "Почему ложная?", "m", verdict_id=own)
    db.save_sca_answers(gone, "агент", [{"component": "c", "version": "1"}])
    db._conn.execute("INSERT INTO meta(key, value) VALUES (?, '{}'), (?, '{}')",
                     (f"notice:{gone}", f"codechange:{gone}"))
    other = db.create_run(gone, "m", "all", "v", ["A"])
    db.set_run_state(other, "running")
    with pytest.raises(ProjectBusy):  # идёт прогон – сначала остановить
        db.delete_project(gone)
    db.set_run_state(other, "stopped")
    assert db.delete_project(gone) and not db.delete_project(gone)
    assert db.get_project(gone) is None and db.get_run(run_id) is None
    for table in ("findings", "cases", "reviews", "imports", "codebase_map", "runs", "questions", "sca_answers"):
        assert db._scalar(f"SELECT COUNT(*) FROM {table} WHERE project_id = ?", (gone,)) == 0, table
    assert db._scalar("SELECT COUNT(*) FROM run_items WHERE run_id IN (?, ?)", (run_id, other)) == 0
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key LIKE ? OR key IN (?, ?)",
                      (f"rev:{gone}:%", f"notice:{gone}", f"codechange:{gone}")) == 0
    assert db.get_verdict(own) is None  # ответ только этого проекта удалён
    assert db.get_verdict(shared) is not None and db.get_case(keep, "A")["verdict_id"] == shared
    assert db.revisions(keep) == {"billing-core": "a" * 40}


# ============================================================================ находки «нет в новой выгрузке»

def test_missing_findings_are_kept_marked_and_skipped_by_work_queues(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", severity="critical"), sast("B", line=12), sast("C", line=14, severity="low")])
    stats = load(db, pid, [sast("A", severity="critical"), sast("C", line=14, severity="low")])
    assert (stats["removed"], stats["missing"], stats["returned"]) == (1, 1, 0)
    rows, total = db.list_findings(pid)
    assert [r["hub_id"] for r in rows] == ["A", "C", "B"] and total == 3 and rows[2]["missing"] == 1
    assert [r["hub_id"] for r in db.list_findings(pid, missing="yes")[0]] == ["B"]
    assert [r["hub_id"] for r in db.list_findings(pid, missing="no")[0]] == ["A", "C"]
    assert db.sast_queue(pid, "all") == ["A", "C"] and db.sast_queue(pid, "selected", ["B"]) == []
    ids = {r["hub_id"]: r["id"] for r in rows}
    assert db.neighbor_unreviewed(pid, rows[1]["pos"], "next", wrap=False) is None  # B не предлагается
    assert db.neighbor_unreviewed(pid, -1, "next", filters={"missing": "yes"}) == ids["B"]
    assert db.count_unreviewed(pid) == (2, 0)
    assert db.count_findings(pid)["sast"] == 2 and db.codebase_counts(pid)[0]["total"] == 2
    stats = load(db, pid, [sast("B", line=12), sast("A", severity="critical")])
    assert (stats["removed"], stats["missing"], stats["returned"]) == (1, 1, 1)
    assert [r["hub_id"] for r in db.list_findings(pid)[0]] == ["A", "B", "C"]


def test_missing_finding_keeps_review_and_reopens_on_return_after_folder_change(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    db.save_review(pid, "B", decision="disagree", final_verdict="true_positive", final_comment="", reviewed=True)
    load(db, pid, [sast("A")])
    # смена папки не считает пропавшую находку: она сверится по версии, когда вернётся
    assert db.set_codebase_folder(pid, "billing-core", "fork", manual=True) == 0
    assert db.get_review(pid, "B")["reviewed"] == 1
    stats = load(db, pid, [sast("A"), sast("B", line=12)])
    assert stats["reopened"] == 1 and db.get_review(pid, "B")["reviewed"] == 0


def test_reorder_after_threshold_change(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sca("S-low", cvss=7.5, vuln="AST-1"), sca("S-high", cvss=9.8, vuln="AST-2"), sast("A")],
         sca_cvss=9.0)
    rows = {r["hub_id"]: r for r in db.list_findings(pid)[0]}
    assert (rows["S-low"]["urgent"], rows["S-high"]["urgent"]) == (0, 1)
    assert reorder_project(db, pid, 7.0) >= 1
    rows = db.list_findings(pid)[0]
    assert [r["hub_id"] for r in rows] == ["A", "S-high", "S-low"] and rows[2]["urgent"] == 1
    assert reorder_project(db, pid, 7.0) == 0  # ничего не изменилось


# ============================================================================ решение и отметки

def test_revision_guard_refuses_save_from_stale_tab(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    version = db.review_version(pid, "A")
    tab = {"version": version, "verdict_id": None, "revision": 0}  # две вкладки открыли находку без решения
    first = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="первая",
                           reviewed=True, expect=tab)
    with pytest.raises(StaleReview) as info:  # вторая вкладка не затирает решение первой
        db.save_review(pid, "A", decision="disagree", final_verdict="false_positive", final_comment="вторая",
                       reviewed=True, expect=tab)
    assert info.value.reason == "revision"
    assert db.get_review(pid, "A")["final_comment"] == "первая"
    second = db.save_review(pid, "A", decision="disagree", final_verdict="false_positive", final_comment="вторая",
                            reviewed=True, expect={**tab, "revision": first["revision"]})
    assert second["revision"] == first["revision"] + 1
    with pytest.raises(StaleReview) as info:  # отметка «Проверено» из устаревшей вкладки – тоже
        db.set_reviewed(pid, "A", False, expect={**tab, "revision": first["revision"]})
    assert info.value.reason == "revision"
    load(db, pid, [sast("A", line=11)])
    with pytest.raises(StaleReview) as info:
        db.save_review(pid, "A", decision="later", final_verdict="", final_comment="", reviewed=False,
                       expect={**tab, "revision": second["revision"]})
    assert info.value.reason == "source"


def test_entered_mark_follows_hub_text_and_keeps_revision(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    review = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="c",
                            reviewed=True)
    marked = db.mark_entered(pid, "A", revision=review["revision"])
    assert marked["entered_hub"] == 1 and marked["entered_hub_at"] and marked["revision"] == review["revision"]
    assert db.mark_entered(pid, "A", revision=review["revision"] + 5) is None  # решение с тех пор менялось
    same = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="c",
                          reviewed=False)
    assert same["entered_hub"] == 1  # текст для Hub тот же
    other = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="другой",
                           reviewed=True)
    assert (other["entered_hub"], other["entered_hub_at"]) == (0, None)  # в Hub теперь другой текст
    assert db.mark_copied(pid, "A", other["revision"]) and db.get_review(pid, "A")["entered_hub"] == 0
    assert db.mark_entered(pid, "B")["entered_hub"] == 1  # без решения – отметка всё равно ставится
    assert db.mark_entered(pid, "B", False)["entered_hub_at"] is None
    assert db.mark_entered(pid, "нет такой") is None
    assert [r["hub_id"] for r in db.list_findings(pid, entered="no")[0]] == ["A", "B"]
    db.mark_entered(pid, "A")
    assert [r["hub_id"] for r in db.list_findings(pid, entered="yes")[0]] == ["A"]


def test_set_reviewed_keeps_decision_and_refuses_later(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    review = db.set_reviewed(pid, "A", True, code_hash="c" * 64, code_chars=14000)
    assert (review["reviewed"], review["decision"], review["revision"], review["code_hash"]) == (1, "", 1, "c" * 64)
    assert review["finding_sig"] == review_signature(db.get_finding_by_hub_id(pid, "A")["data"])
    db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="ок", reviewed=True)
    off = db.set_reviewed(pid, "A", False)
    assert (off["reviewed"], off["reviewed_at"], off["decision"], off["final_comment"]) == (0, None, "agree", "ок")
    assert off["code_hash"] == "c" * 64  # отпечаток не задан – прежний
    db.save_review(pid, "B", decision="later", final_verdict="", final_comment="", reviewed=False)
    with pytest.raises(ValueError, match="Отложенная"):
        db.set_reviewed(pid, "B", True)


def test_sca_review_signature_follows_component_not_code_folder(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sca("S1")])
    db.save_review(pid, "S1", decision="disagree", final_verdict="true_positive", final_comment="", reviewed=True)
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    assert load(db, pid, [sca("S1")])["reopened"] == 0  # папка с кодом для SCA не важна
    assert load(db, pid, [sca("S1", version="1.4.3")])["reopened"] == 1  # другая версия компонента


def test_reviewed_code_hash_reopens_when_first_slice_differs(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    db.set_reviewed(pid, "A", True, code_hash="old", code_chars=14000)
    db.set_reviewed(pid, "B", True, code_hash="same", code_chars=14000)
    assert db.save_case(pid, "A", "new", {"max_chars": 14000}, None)  # код изменился после отметки человека
    assert db.save_case(pid, "B", "same", {"max_chars": 14000}, None)
    assert db.get_review(pid, "A")["reviewed"] == 0 and db.get_review(pid, "B")["reviewed"] == 1
    assert db.code_change_notice(pid)["reopened"] == 1


# ============================================================================ вопросы к модели

def test_questions_history_and_restart(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    vid = db.save_verdict("h", "m", "v", verdict(), {})
    first = db.add_question(pid, "A", "Откуда берётся owner?", "qwen2.5-coder:14b", case_hash="h", verdict_id=vid)
    second = db.add_question(pid, "A", "А если owner пустой?", "qwen2.5-coder:14b")
    assert db.next_pending_question()["id"] == first
    assert db.finish_question(first, answer="Из параметра запроса, строка 15.", answer_data={"lines": [15]},
                              stats={"eval_tps": 80.5})
    assert not db.finish_question(first, answer="повтор")  # ответ уже есть
    history = db.list_questions(pid, "A")
    assert [q["id"] for q in history] == [first, second]
    assert (history[0]["state"], history[0]["answer"], history[0]["stats"]["eval_tps"]) == (
        "done", "Из параметра запроса, строка 15.", 80.5)
    assert history[0]["answer_data"] == {"lines": [15]} and history[0]["verdict_id"] == vid
    db.recover_interrupted()  # перезапуск: вопрос без ответа закрывается с пояснением
    assert (db.get_question(second)["state"], db.get_question(second)["error"]) == ("error", QUESTION_INTERRUPTED)
    assert db.next_pending_question() is None
    third = db.add_question(pid, "A", "?", "m")
    assert db.finish_question(third, error="Ollama не отвечает.") and db.get_question(third)["state"] == "error"


# ============================================================================ SCA

def test_sca_components_group_by_component_and_version(db: Database):
    pid = db.create_project("p")
    load(db, pid, [
        sca("S1", vuln="AST-1", cvss=9.8, cve="CVE-2026-0001"),
        sca("S2", vuln="AST-2", cvss=7.5, codebase="catalog-api"),
        sca("S3", component="org.example:example-json", version="2.0.0", cvss=5.0, vuln="AST-3", fixed=""),
        sast("A"),
    ])
    db.save_review(pid, "S1", decision="disagree", final_verdict="true_positive", final_comment="", reviewed=True)
    db.mark_entered(pid, "S2")
    parser, json_lib = db.sca_components(pid)
    assert (parser["component"], parser["version"], parser["findings"]) == ("org.example:example-parser", "1.4.2", 2)
    assert parser["cvss"] == 9.8 and parser["urgent"] and parser["vuln_ids"] == ["AST-1", "AST-2"]
    assert parser["cve"] == ["CVE-2026-0001"] and parser["fixed_versions"] == ["1.4.9"]
    assert parser["codebases"] == ["billing-core", "catalog-api"] and parser["cwe"] == ["CWE-502"]
    assert (parser["reviewed"], parser["entered"], parser["build_types"]) == (1, 1, ["maven"])
    assert sorted(parser["hub_ids"]) == ["S1", "S2"] and len(parser["finding_ids"]) == 2
    assert (json_lib["component"], json_lib["fixed_versions"], json_lib["urgent"]) == (
        "org.example:example-json", [], False)


def test_sca_answers_by_source_and_ast_map(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sca("S1")])
    answer = {"component": "org.example:example-parser", "version": "1.4.2", "recommended_version": "1.4.9",
              "conclusion": "update", "explanation": "Уязвимость исправлена в 1.4.9.",
              "ids": {"AST-2026-0001": ["CVE-2026-0001"]}, "links": ["https://example.org/advisory"]}
    assert db.save_sca_answers(pid, "Агент 1", [answer, {"component": ""}])["saved"] == 1
    assert db.save_sca_answers(pid, "Агент 2", [ScaAnswer.from_dict({**answer, "conclusion": "можно"})])["saved"] == 1
    assert db.save_sca_answers(pid, "Агент 1", [{**answer, "recommended_version": "1.5.0"}])["saved"] == 1  # замена
    answers = db.sca_answers(pid, "org.example:example-parser", "1.4.2")
    assert sorted((a["source"], a["recommended_version"], a["conclusion"]) for a in answers) == [
        ("Агент 1", "1.5.0", "update"), ("Агент 2", "1.4.9", "")]  # неизвестный вывод – пусто
    latest = db.latest_sca_answers(pid)[("maven", "org.example:example-parser", "1.4.2")]
    assert latest["source"] == "Агент 1" and latest["ids"] == {"AST-2026-0001": ["CVE-2026-0001"]}
    assert latest["links"] == ["https://example.org/advisory"]
    assert db.save_ast_map([("AST-2026-0001", "CVE-2026-0001"), ("AST-2026-0001", "GHSA-xxxx-yyyy-zzzz"),
                            ("AST-2026-0001", "CVE-2026-0001"), ("", "CVE-1")], source="поставщик") == 2
    assert db.ast_map(["AST-2026-0001", "AST-нет"]) == {"AST-2026-0001": ["CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz"]}
    assert db.ast_map() == db.ast_map(["AST-2026-0001"])


# ============================================================================ прогоны

def test_accepted_stop_survives_restart(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    stopped, paused, running = (db.create_run(pid, "m", "all", "v", ["A"]) for _ in range(3))
    for run_id in (stopped, paused, running):
        db.set_run_state(run_id, "running")
    assert db.set_run_control(stopped, "stop") and db.set_run_control(paused, "pause")
    assert not db.set_run_control(db.create_run(pid, "m", "all", "v", ["A"]), "stop")  # прогон не идёт
    with pytest.raises(ValueError):
        db.set_run_control(stopped, "restart")
    assert db.recover_interrupted() == 4
    run = db.get_run(stopped)
    assert (run["state"], run["control"], run["last_error"]) == ("stopped", "", STOPPED_NOTE) and run["finished_at"]
    assert db.get_run(paused)["state"] == "paused" and db.get_run(paused)["control"] == ""
    assert db.get_run(running)["state"] == "paused"


def test_state_change_clears_accepted_command(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    run_id = db.create_run(pid, "m", "all", "v", ["A"])
    db.set_run_state(run_id, "running")
    db.set_run_control(run_id, "pause")
    db.set_run_state(run_id, "paused", only_from=("running",))
    assert db.get_run(run_id)["control"] == ""


def test_failed_answer_measures_and_partial_stats(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    run_id = db.create_run(pid, "m", "all", "v", ["A", "B"])
    first = db.next_pending_item(run_id)
    db.finish_item(run_id, first["id"], "error", error="не по формату", seconds=3.0, eval_tps=50.0,
                   output_tokens=150, eval_seconds=3.0, model_call=True)
    second = db.next_pending_item(run_id)
    db.finish_item(run_id, second["id"], "error", error="сбой связи", seconds=1.0, model_call=True,
                   stats_partial=True)
    run = db.get_run(run_id)
    assert (run["output_tokens"], run["eval_seconds"], run["partial_stats"], run["failed"]) == (150, 3.0, 1, 2)
    assert [item["stats_partial"] for item in db.recent_items(run_id)] == [1, 0]


def test_request_key_cache(db: Database):
    old = db.save_verdict("h", "m", "v", verdict("false_positive"), {}, request_key="r1")
    new = db.save_verdict("h", "m", "v", verdict("true_positive"), {}, request_key="r1")
    assert db.find_verdict_by_request("r1")["id"] == new and old != new
    assert db.find_verdict_by_request("r2") is None and db.find_verdict_by_request("") is None
