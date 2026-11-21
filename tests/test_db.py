"""Хранилище: схема и журнал, повторная загрузка выгрузки без потери решений, отбор находок, кэш вердиктов,
прогоны и их счётчики, восстановление после перезапуска, одновременный доступ из нескольких потоков."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db import INTERRUPTED_NOTE, Database, StaleReview, finding_version, review_signature  # noqa: E402
from app.models import Finding  # noqa: E402
from app.triage import order_findings  # noqa: E402

JAVA_FILE = "src/main/java/org/example/billing/InvoiceDao.java"


def sast(hub_id: str, *, line: int = 10, severity: str = "high", codebase: str = "billing-core",
         status: str = "To verify", rule: str = "Внедрение SQL-кода", file: str = JAVA_FILE) -> Finding:
    return Finding(hub_id=hub_id, kind="SAST", rule=rule, cwe=["CWE-89"], file=file, line=line, severity=severity,
                   codebase=codebase, status=status, snippet="String sql = base + owner;", language="Java")


def sca(hub_id: str, cvss: float = 9.8) -> Finding:
    return Finding(hub_id=hub_id, kind="SCA", component="example-parser", version="1.4.2", cvss=cvss,
                   policy_severity="Critical", codebase="billing-core")


def load(db: Database, project_id: int, findings: list[Finding], filename: str = "report.xlsx") -> dict:
    sheets = [{"name": "SAST", "rows": len(findings), "skipped": False, "reason": ""}]
    return db.save_import(project_id, filename, "hub", sheets, {"total": len(findings)}, ["предупреждение"],
                          order_findings(findings))


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "data" / "triage.db")
    yield database
    database.close()


def verdict(value: str = "false_positive", confidence: int = 70) -> dict:
    return {"verdict": value, "confidence": confidence, "summary": "s", "explanation": "e", "data_flow": [],
            "evidence_lines": [10], "fix": "", "hub_comment": "c", "cwe_fit": "да", "raw": {"verdict": value}}


def test_newer_schema_is_refused(tmp_path: Path):
    path = tmp_path / "triage.db"
    database = Database(path)
    database._conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    database.close()
    with pytest.raises(RuntimeError, match="более новой версией"):
        Database(path)


def test_projects_and_latest_import(db: Database):
    pid = db.create_project("  Demo Library  ")
    assert db.get_project(pid)["name"] == "Demo Library"
    load(db, pid, [sast("A"), sast("B", line=20), sca("S1")], filename="hub.xlsx")
    db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    [project] = db.list_projects()
    assert (project["findings"], project["sast"], project["reviewed"]) == (3, 2, 1)
    assert project["last_run_state"] is None
    imp = db.latest_import(pid)
    assert imp["filename"] == "hub.xlsx" and imp["total"] == 3
    assert imp["sheets"][0]["name"] == "SAST" and imp["warnings"] == ["предупреждение"]
    assert imp["stats"] == {"new": 3, "updated": 0, "unchanged": 0, "removed": 0, "returned": 0, "missing": 0,
                            "reopened": 0}
    db.set_repos_dir(pid, "team/demo")
    assert db.get_project(pid)["repos_dir"] == "team/demo"


def test_reimport_keeps_reviews_ids_and_unchanged_cases(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", line=10), sast("B", line=20), sast("C", line=30)])
    a_id = db.get_finding_by_hub_id(pid, "A")["id"]
    vid = db.save_verdict("hash-a", "m", "sast-v1", verdict(), {"eval_tps": 50.0})
    db.save_case(pid, "A", "hash-a", {"status": "ok"}, vid)
    db.save_case(pid, "B", "hash-b", {"status": "ok"}, vid)
    db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="ok", reviewed=True)
    db.save_review(pid, "B", decision="agree", final_verdict="false_positive", final_comment="ok", reviewed=True)

    # A: сменился только статус в Hub; B: другая строка; C исчезла; D новая. «Изменилось» – только то, от чего
    # зависит решение (предбоевая проверка 18.10.2026): статус в Hub и место на листе изменением не считаются
    stats = load(db, pid, [sast("A", line=10, status="False Positive"), sast("B", line=21), sast("D", line=40)])
    assert (stats["new"], stats["updated"], stats["unchanged"], stats["removed"]) == (1, 1, 1, 1)
    assert stats["reopened"] == 1
    assert db.get_finding_by_hub_id(pid, "A")["id"] == a_id
    assert db.get_finding_by_hub_id(pid, "A")["data"]["status"] == "False Positive"
    assert db.get_case(pid, "A")["verdict"]["verdict"] == "false_positive"
    assert db.get_case(pid, "B") is None
    gone = db.get_finding_by_hub_id(pid, "C")  # пропавшая находка остаётся с пометкой «нет в новой выгрузке»
    assert (gone["missing"], bool(gone["missing_since"])) == (1, True) and stats["missing"] == 1
    assert [r["hub_id"] for r in db.list_findings(pid)[0]][-1] == "C"  # после найденных
    assert db.count_findings(pid)["total"] == 3 and db.count_findings(pid)["missing"] == 1
    assert db.get_review(pid, "A")["reviewed"] == 1
    review_b = db.get_review(pid, "B")  # код или место изменились – проверить заново, решение сохранено
    assert (review_b["reviewed"], review_b["reviewed_at"], review_b["decision"]) == (0, None, "agree")

    # решение по находке, которая пропала из выгрузки и вернулась, не теряется
    db.save_review(pid, "D", decision="later", final_verdict="", final_comment="", reviewed=True)
    load(db, pid, [sast("A", line=10)])
    stats = load(db, pid, [sast("A", line=10), sast("D", line=40)])
    assert db.get_review(pid, "D")["decision"] == "later" and db.get_review(pid, "D")["reviewed"] == 1
    assert stats["reopened"] == 0 and stats["returned"] == 1
    back = db.get_finding_by_hub_id(pid, "D")
    assert (back["missing"], back["missing_since"]) == (0, None)
    # вернулась другой (другая строка) – проверить заново
    load(db, pid, [sast("A", line=10)])
    stats = load(db, pid, [sast("A", line=10), sast("D", line=41)])
    assert stats["reopened"] == 1 and db.get_review(pid, "D")["reviewed"] == 0


def test_repeated_hub_id_in_one_import_keeps_first(db: Database):
    pid = db.create_project("p")
    stats = load(db, pid, [sast("A", line=10), sast("A", line=99)])
    assert stats["total"] == 1
    assert db.get_finding_by_hub_id(pid, "A")["data"]["line"] == 10


def test_list_findings_order_and_filters(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sca("S1"), sast("B", severity="low", line=11, codebase="catalog-api"),
                   sast("A", severity="critical", line=12)])
    rows, total = db.list_findings(pid)
    assert total == 3
    assert [r["hub_id"] for r in rows] == ["A", "B", "S1"]  # SAST впереди, срочная и критичная первой
    assert db.list_findings(pid, kind="SCA")[1] == 1
    assert [r["hub_id"] for r in db.list_findings(pid, codebase="catalog-api")[0]] == ["B"]
    assert [r["hub_id"] for r in db.list_findings(pid, urgent=True)[0]] == ["A", "S1"]

    vid = db.save_verdict("h", "m", "v", verdict("true_positive", 90), {})
    db.save_case(pid, "A", "h", {}, vid)
    rows, _ = db.list_findings(pid, verdict="true_positive")
    assert [r["hub_id"] for r in rows] == ["A"] and rows[0]["model_confidence"] == 90
    assert [r["hub_id"] for r in db.list_findings(pid, verdict="none")[0]] == ["B", "S1"]

    db.save_review(pid, "B", decision="disagree", final_verdict="true_positive", final_comment="", reviewed=True)
    assert [r["hub_id"] for r in db.list_findings(pid, decision="disagree")[0]] == ["B"]
    assert [r["hub_id"] for r in db.list_findings(pid, decision="none")[0]] == ["A", "S1"]
    assert [r["hub_id"] for r in db.list_findings(pid, reviewed="yes")[0]] == ["B"]
    assert [r["hub_id"] for r in db.list_findings(pid, reviewed="no")[0]] == ["A", "S1"]

    rows, total = db.list_findings(pid, limit=1, offset=1)
    assert total == 3 and [r["hub_id"] for r in rows] == ["B"]
    counts = {c["codebase"]: (c["total"], c["sast"], c["sca"]) for c in db.codebase_counts(pid)}
    assert counts == {"billing-core": (2, 1, 1), "catalog-api": (1, 1, 0)}


def test_neighbor_unreviewed_skips_reviewed_and_wraps(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("F0", line=1, severity="critical"), sast("F1", line=2, severity="high"),
                   sast("F2", line=3, severity="medium"), sca("S")])
    ids = {r["hub_id"]: r["id"] for r in db.list_findings(pid)[0]}
    pos = {r["hub_id"]: r["pos"] for r in db.list_findings(pid)[0]}
    db.save_review(pid, "F1", decision="agree", final_verdict="", final_comment="", reviewed=True)
    assert db.neighbor_unreviewed(pid, pos["F0"], "next") == ids["F2"]
    assert db.neighbor_unreviewed(pid, pos["F2"], "next") == ids["F0"]  # по кругу, SCA не в счёт
    assert db.neighbor_unreviewed(pid, pos["F0"], "prev") == ids["F2"]
    assert db.neighbor_unreviewed(pid, -1, "next") == ids["F0"]
    for hub_id in ("F0", "F2"):
        db.save_review(pid, hub_id, decision="agree", final_verdict="", final_comment="", reviewed=True)
    assert db.neighbor_unreviewed(pid, pos["F0"], "next") is None


def test_verdicts_are_immutable_and_cache_takes_latest(db: Database):
    first = db.save_verdict("h", "qwen2.5-coder:14b", "sast-v1", verdict("false_positive"), {"eval_tps": 80.0})
    again = db.save_verdict("h", "qwen2.5-coder:14b", "sast-v1", verdict("true_positive"), {"eval_tps": 81.0})
    assert first != again
    assert db.get_verdict(first)["verdict"] == "false_positive"  # прежний ответ не переписан
    stored = db.find_verdict("h", "qwen2.5-coder:14b", "sast-v1")
    assert stored["id"] == again and stored["verdict"] == "true_positive" and stored["stats"]["eval_tps"] == 81.0
    assert "raw" not in stored["data"] and stored["raw"] == {"verdict": "true_positive"}
    assert db.find_verdict("h", "gpt-oss:20b", "sast-v1") is None
    assert db.find_verdict("h", "qwen2.5-coder:14b", "sast-v2") is None


def test_save_case_keeps_verdict_only_for_same_hash(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    vid = db.save_verdict("h1", "m", "v", verdict(), {})
    db.save_case(pid, "A", "h1", {"status": "ok"}, vid)
    db.save_case(pid, "A", "h1", {"status": "ok", "note": "снова"}, None)
    case = db.get_case(pid, "A")
    assert case["verdict_id"] == vid and case["context"]["note"] == "снова"
    db.save_case(pid, "A", "h2", {"status": "no_repo"}, None)
    assert db.get_case(pid, "A")["verdict"] is None


def test_changing_folders_drops_cases_of_affected_findings(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", codebase="billing-core"), sast("K", line=11, codebase="catalog-api")])
    vid = db.save_verdict("h", "m", "v", verdict(), {})
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    db.set_codebase_folder(pid, "catalog-api", "catalog-api", manual=False)
    for hub_id in ("A", "K"):
        db.save_case(pid, hub_id, "h", {}, vid)
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=True)  # та же папка – ничего не меняется
    assert db.get_case(pid, "A") is not None
    db.set_codebase_folder(pid, "billing-core", "billing-core-fork", manual=True)
    assert db.get_case(pid, "A") is None and db.get_case(pid, "K") is not None
    db.set_repos_dir(pid, "")  # та же папка проекта
    assert db.get_case(pid, "K") is not None
    db.set_repos_dir(pid, "team")
    assert db.get_case(pid, "K") is None


def test_changing_folders_clears_reviewed_of_affected_findings(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", codebase="billing-core"), sast("B", line=12, codebase="billing-core"),
                   sast("K", line=11, codebase="catalog-api"), sast("N", line=13, codebase="notify-gateway")])
    assert db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False) == 0
    assert db.set_codebase_folder(pid, "catalog-api", "catalog-api", manual=False) == 0
    for hub_id in ("A", "B", "K", "N"):
        db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="ложное",
                       reviewed=hub_id != "B")
    assert db.set_codebase_folder(pid, "billing-core", "billing-core", manual=True) == 0  # та же папка
    assert db.set_codebase_folder(pid, "billing-core", "billing-core-fork", manual=True) == 1  # B не был проверен
    a, k = db.get_review(pid, "A"), db.get_review(pid, "K")
    assert (a["reviewed"], a["reviewed_at"], a["decision"], a["final_comment"]) == (0, None, "disagree", "ложное")
    assert k["reviewed"] == 1
    # смена папки проекта: у кодовых баз с выбранной папкой; у notify-gateway папки нет – код тот же
    assert db.set_repos_dir(pid, "") == 0
    assert db.set_repos_dir(pid, "team") == 1
    assert db.get_review(pid, "K")["reviewed"] == 0 and db.get_review(pid, "N")["reviewed"] == 1


def test_review_version_covers_code_folder(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12)])
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    shown_a = {"version": db.review_version(pid, "A"), "verdict_id": None}
    shown_b = {"version": db.review_version(pid, "B"), "verdict_id": None}
    db.save_review(pid, "B", decision="disagree", final_verdict="false_positive", final_comment="", reviewed=True,
                   expect=shown_b)
    load(db, pid, [sast("A")])  # B пропала из выгрузки
    db.set_codebase_folder(pid, "billing-core", "billing-core-fork", manual=True)  # в другой вкладке сменили клон
    assert db.review_version(pid, "A") != shown_a["version"]
    with pytest.raises(StaleReview):  # карточка, открытая до смены клона, «Проверено» не вернёт
        db.save_review(pid, "A", decision="disagree", final_verdict="false_positive", final_comment="",
                       reviewed=True, expect=shown_a)
    stats = load(db, pid, [sast("A"), sast("B", line=12)])  # B вернулась с теми же полями, но клон уже другой
    assert stats["reopened"] == 1 and db.get_review(pid, "B")["reviewed"] == 0


def test_copy_mark_follows_hub_status_with_later(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    first = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="c",
                           reviewed=True)
    assert db.mark_copied(pid, "A", first["revision"])
    later = db.save_review(pid, "A", decision="later", final_verdict="true_positive", final_comment="c",
                           reviewed=False)
    assert later["copied_at"] is None  # скопирован был Confirmed, теперь текст с To verify
    assert db.mark_copied(pid, "A", later["revision"])
    back = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="c",
                          reviewed=True)
    assert back["copied_at"] is None  # обратный переход – снова другой текст
    assert db.mark_copied(pid, "A", back["revision"])
    same = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="c",
                          reviewed=False)
    assert same["copied_at"] is not None  # сменилась только отметка «проверено» – текст для Hub тот же


def test_revision_change_resets_cases_and_reviews(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A"), sast("B", line=12), sast("K", line=11, codebase="catalog-api")])
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    db.set_codebase_folder(pid, "catalog-api", "catalog-api", manual=False)
    first = {"billing-core": "a" * 40, "catalog-api": ""}  # catalog-api – не клон git
    assert db.sync_revisions(pid, first) == {"changed": [], "reopened": 0}  # первая ревизия только запоминается
    assert db.revisions(pid) == first
    vid = db.save_verdict("h", "m", "v", verdict(), {})
    for hub_id in ("A", "B", "K"):
        db.save_case(pid, hub_id, "h", {}, vid)
        db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="",
                       reviewed=True, verdict_id=vid, expect={"version": db.review_version(pid, hub_id),
                                                              "verdict_id": vid})
    shown_a = db.review_version(pid, "A")
    load(db, pid, [sast("A"), sast("K", line=11, codebase="catalog-api")])  # B пропала из выгрузки
    assert db.sync_revisions(pid, first)["changed"] == []
    result = db.sync_revisions(pid, {"billing-core": "b" * 40, "catalog-api": ""})  # git pull в billing-core
    assert result == {"changed": ["billing-core"], "reopened": 1}
    assert db.get_case(pid, "A") is None and db.get_case(pid, "K") is not None
    assert db.get_review(pid, "A")["reviewed"] == 0 and db.get_review(pid, "K")["reviewed"] == 1
    assert db.review_version(pid, "A") != shown_a
    assert db.revision_notice(pid) == {"codebases": ["billing-core"], "reopened": 1,
                                       "at": db.revision_notice(pid)["at"]}
    stats = load(db, pid, [sast("A"), sast("B", line=12), sast("K", line=11, codebase="catalog-api")])
    assert stats["reopened"] == 1 and db.get_review(pid, "B")["reviewed"] == 0  # вернулась, а клон уже другой
    db.clear_revision_notice(pid)
    assert db.revision_notice(pid) is None
    db.set_codebase_folder(pid, "billing-core", "billing-core-fork", manual=True)  # ревизия прежней папки забыта
    assert "billing-core" not in db.revisions(pid)
    assert db.sync_revisions(pid, {"billing-core": "c" * 40})["changed"] == []


def test_save_case_refuses_stale_source(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", line=10)])
    db.set_codebase_folder(pid, "billing-core", "billing-core", manual=False)
    source = db.case_input(pid, "A")
    assert source["folder"] == "billing-core" and source["repos_dir"] == ""
    assert db.save_case(pid, "A", "h1", {"n": 1}, None, source)
    load(db, pid, [sast("A", line=11)])  # находку заменила новая выгрузка
    assert not db.save_case(pid, "A", "h1", {"n": 2}, None, source)
    assert db.get_case(pid, "A") is None
    source = db.case_input(pid, "A")
    db.set_codebase_folder(pid, "billing-core", "other", manual=True)
    assert not db.save_case(pid, "A", "h1", {"n": 3}, None, source)
    source = db.case_input(pid, "A")
    load(db, pid, [])  # находки нет в новой выгрузке: ответ, полученный до этого, не привязывается
    assert db.case_input(pid, "A")["missing"] is True
    assert not db.save_case(pid, "A", "h1", {"n": 4}, None, source)
    assert db.case_input(pid, "B") is None


def test_eta_groups_are_per_codebase(db: Database):
    pid = db.create_project("p")
    # одно правило, файл и строка, но разные кодовые базы – код разный, вызов модели нужен для каждой
    load(db, pid, [sast("A", codebase="billing-core"), sast("B", codebase="billing-core-fork")])
    run_id = db.create_run(pid, "m", "all", "v", ["A", "B"])
    assert db.pending_model_groups(run_id) == (2, 2)
    item = db.next_pending_item(run_id)
    db.finish_item(run_id, item["id"], "done", case_hash="h", seconds=1.0, model_call=True)
    assert db.pending_model_groups(run_id) == (1, 1)
    assert db.case_done_in_run(run_id, "h") and not db.case_done_in_run(run_id, "other")


def test_review_semantics_and_validation(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    first = db.save_review(pid, "A", decision="agree", final_verdict="true_positive", final_comment="c", reviewed=True)
    assert first["reviewed_at"] and first["copied_at"] is None and first["revision"] == 1
    assert db.mark_copied(pid, "A", first["revision"])
    # тот же текст для Hub (сменилась только отметка «проверено») – отметка о копировании остаётся
    second = db.save_review(pid, "A", decision="agree", final_verdict="true_positive", final_comment="c",
                            reviewed=False)
    assert second["revision"] == 2 and second["copied_at"] and second["reviewed_at"] is None
    third = db.save_review(pid, "A", decision="agree", final_verdict="true_positive", final_comment="c",
                           reviewed=True)
    assert third["reviewed_at"] and third["copied_at"] == second["copied_at"]
    # другой комментарий – текст для Hub другой, скопированным он ещё не был
    fourth = db.save_review(pid, "A", decision="later", final_verdict="", final_comment="другое", reviewed=False)
    assert fourth["copied_at"] is None and fourth["revision"] == 4
    assert db.mark_copied(pid, "A", third["revision"]) is None  # скопирован текст прежней редакции
    assert db.mark_copied(pid, "A", fourth["revision"]) and db.mark_copied(pid, "нет решения", 1) is None
    with pytest.raises(ValueError):
        db.mark_copied(pid, "A", 0)
    with pytest.raises(ValueError):
        db.save_review(pid, "A", decision="maybe", final_verdict="", final_comment="", reviewed=False)
    with pytest.raises(ValueError):
        db.save_review(pid, "A", decision="agree", final_verdict="yes", final_comment="", reviewed=False)


def test_review_from_stale_page_is_refused(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", line=10)])
    data = db.get_finding_by_hub_id(pid, "A")["data"]
    shown = {"version": finding_version(data), "verdict_id": None}
    review = db.save_review(pid, "A", decision="disagree", final_verdict="true_positive", final_comment="",
                            reviewed=True, expect=shown)
    assert review["finding_sig"] == review_signature(data)
    vid = db.save_verdict("h", "m", "v", verdict(), {})
    db.save_case(pid, "A", "h", {}, vid)  # пока страница была открыта, появился вердикт модели
    with pytest.raises(StaleReview):
        db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="",
                       reviewed=True, expect=shown)
    shown = {"version": finding_version(data), "verdict_id": vid}
    db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True,
                   verdict_id=vid, expect=shown)
    load(db, pid, [sast("A", line=11)])  # новая выгрузка: другая строка
    with pytest.raises(StaleReview):
        db.save_review(pid, "A", decision="agree", final_verdict="false_positive", final_comment="",
                       reviewed=True, expect=shown)
    assert db.get_review(pid, "A")["reviewed"] == 0  # снято при загрузке и не возвращено устаревшей страницей


def test_sast_queue_scopes(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A", severity="high", line=1), sast("B", severity="low", line=2),
                   sast("C", severity="critical", line=3), sca("S")])
    assert db.sast_queue(pid, "all") == ["C", "A", "B"]
    assert db.sast_queue(pid, "urgent") == ["C", "A"]
    assert db.sast_queue(pid, "selected", ["B", "C", "S", "нет такой"]) == ["C", "B"]
    with pytest.raises(ValueError):
        db.sast_queue(pid, "everything")


def test_run_lifecycle_and_counters(db: Database):
    pid = db.create_project("p")
    # A и B – дубли (одно правило, файл и строка), C – отдельная находка
    load(db, pid, [sast("A", line=10), sast("B", line=10, severity="medium"), sast("C", line=30)])
    run_id = db.create_run(pid, "qwen2.5-coder:14b", "all", "sast-v1", db.sast_queue(pid, "all"))
    run = db.get_run(run_id)
    assert (run["state"], run["total"], run["done"]) == ("queued", 3, 0)
    assert db.next_queued_run()["id"] == run_id
    assert [r["id"] for r in db.active_runs(pid)] == [run_id]
    assert db.set_run_state(run_id, "running", only_from=("queued",))
    assert not db.set_run_state(run_id, "running", only_from=("queued",))
    assert db.get_run(run_id)["started_at"]
    assert db.pending_model_groups(run_id) == (3, 2)

    vid = db.save_verdict("h", "qwen2.5-coder:14b", "sast-v1", verdict(), {})
    item = db.next_pending_item(run_id)
    assert item["hub_id"] == "A"
    db.finish_item(run_id, item["id"], "done", case_hash="h", verdict_id=vid, seconds=2.0, eval_tps=50.0,
                   output_tokens=100, eval_seconds=2.0, model_call=True)
    db.finish_item(run_id, item["id"], "done", case_hash="h", verdict_id=vid, seconds=2.0, eval_tps=50.0,
                   output_tokens=100, eval_seconds=2.0, model_call=True)  # повтор не считается дважды
    assert db.pending_model_groups(run_id) == (2, 1)  # дубль B возьмёт готовый вердикт
    item = db.next_pending_item(run_id)
    db.finish_item(run_id, item["id"], "cached", case_hash="h", verdict_id=vid, seconds=0.01)
    item = db.next_pending_item(run_id)
    db.finish_item(run_id, item["id"], "error", error="модель ответила не по формату", seconds=1.0)
    assert db.next_pending_item(run_id) is None

    run = db.get_run(run_id)
    assert (run["done"], run["failed"], run["cached"], run["model_calls"]) == (3, 1, 1, 1)
    assert run["model_seconds"] == pytest.approx(2.0) and run["last_tps"] == pytest.approx(50.0)
    assert run["output_tokens"] == 100 and run["last_error"] == "модель ответила не по формату"
    recent = db.recent_items(run_id)
    assert [r["hub_id"] for r in recent] == ["C", "B", "A"]
    assert recent[2]["verdict"] == "false_positive" and recent[2]["finding_id"]
    assert recent[0]["rule"] == "Внедрение SQL-кода" and recent[0]["line"] == 30
    assert db.set_run_state(run_id, "done", only_from=("running",))
    assert db.get_run(run_id)["finished_at"] and db.active_runs(pid) == []
    with pytest.raises(ValueError):
        db.set_run_state(run_id, "finished")
    with pytest.raises(ValueError):
        db.finish_item(run_id, item["id"], "pending")


def test_recover_interrupted_runs(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast("A")])
    ids = [db.create_run(pid, "m", "all", "sast-v1", ["A"]) for _ in range(4)]
    db.set_run_state(ids[0], "running")
    db.set_run_state(ids[2], "paused", last_error="")
    db.set_run_state(ids[3], "done")
    assert db.recover_interrupted() == 2
    states = [db.get_run(i)["state"] for i in ids]
    assert states == ["paused", "paused", "paused", "done"]
    assert db.get_run(ids[0])["last_error"] == INTERRUPTED_NOTE
    assert db.get_run(ids[2])["last_error"] == ""


def test_concurrent_writes_from_threads(db: Database):
    pid = db.create_project("p")
    load(db, pid, [sast(f"F{i}", line=i + 1) for i in range(60)])
    errors: list[BaseException] = []

    def worker(start: int) -> None:
        try:
            for i in range(start, 60, 6):
                db.save_review(pid, f"F{i}", decision="agree", final_verdict="false_positive",
                               final_comment=f"поток {start}", reviewed=True)
                db.list_findings(pid, reviewed="yes")
                db.review_stats(pid)
        except BaseException as e:  # noqa: BLE001 – ошибка любого потока валит тест
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors
    stats = db.review_stats(pid)
    assert (stats["sast"], stats["reviewed"], stats["agree"]) == (60, 60, 60)


def test_project_list_counts_from_one_snapshot():
    """Счётчики главной – три запроса: запись, подтверждённая между ними, не даёт числа, которого не было ни до неё, ни после."""
    import psycopg
    from db_support import empty_database
    target = empty_database()
    db = Database(target)
    other = psycopg.connect(target, autocommit=True)
    try:
        pid = db.create_project("Проект")
        import_id = other.execute("INSERT INTO imports(project_id, filename, format, total, created_at) VALUES (%s, 'f', 'x', 0, 't') RETURNING id", (pid,)).fetchone()[0]

        def add(number):
            other.execute("INSERT INTO findings(project_id, hub_id, import_id, pos, kind, data_json) VALUES (%s, %s, %s, %s, 'SAST', '{}')", (pid, str(number), import_id, number))

        add(1)
        real = db._store.read

        def between(fn, **kwargs):
            def wrapped(conn):
                inner = conn.execute
                calls = []

                class Spy:
                    def execute(self, *args, **options):
                        calls.append(args)
                        if len(calls) == 2:
                            add(2)
                        return inner(*args, **options)

                return fn(Spy())
            return real(wrapped, **kwargs)

        db._store.read = between
        during = db.list_projects()[0]
        db._store.read = real
        assert during["findings"] == 1, "запись после начала чтения в счётчики этого показа не попала"
        assert db.list_projects()[0]["findings"] == 2
    finally:
        other.close()
        db.close()

