"""Исследование компонентов SCA: сборка задания, комплект для агента, сохранение ответов и решений, отчёты.

Проверяем то, на чём держится сценарий: строка задания не меняется от переимпорта выгрузки, комплект не уносит
код, названия кодовых баз и номера находок, прежние ревизии исследования не переписываются, решение человека
не меняет факты и защищено от сохранения по устаревшей странице.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from component_research_fixtures import complete_research_row

from app import sca_research as research
from app.db import Database, DecisionStale
from app.hub_import import parse_workbook
from app.sca_contract import ANSWER_CONTRACT, VALIDATOR_VERSION
from app.triage import order_findings
from hub_fixtures import SCA_BASE, make_hub_xlsx
from test_repo_hygiene import FSTEC_BARE, LONG_DASH

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = research.CONTRACT
AST_ID = "AST-2026-000101"
HUB_ID = "73001"
CODEBASE = "billing-core"
APP_NAME = "Demo Library"

#: Выгрузка Hub с теми же тремя пакетами, что и PACKAGES: хранилище проверяет состав по находкам, поэтому
#: база под задание наполняется настоящей выгрузкой, а не пустым проектом.
HUB_ROWS = [{"Issue id": "73001", "CVSS score": "9.8", "Component name": "org.example:example-parser",
             "Component version": "9.0.83", "CVE id": AST_ID, "Non-vulnerable versions": "1.4.9"},
            {"Issue id": "73002", "CVSS score": "8.2", "Component name": "example-parser",
             "Component version": "9.0.83", "CVE id": "CVE-2099-10001", "Non-vulnerable versions": "1.4.9"},
            {"Issue id": "73003", "CVSS score": "7.5", "Type": "npm", "Component name": "@example/parser",
             "Component version": "7.23.2", "CVE id": "AST-2026-000103", "Non-vulnerable versions": "7.23.5",
             "Codebase": "catalog-api", "Path": "catalog-api > @example/parser"}]


def hub_export(path: Path, rows: list[dict] | None = None) -> Path:
    """Выгрузка Hub с указанными находками SCA."""
    return make_hub_xlsx(path, sast=(), sca=[dict(SCA_BASE, **row) for row in (rows or HUB_ROWS)])


def load_export(db: Database, project_id: int, path: Path, name: str = "") -> dict:
    """Загрузить выгрузку в базу тем же путём, что приложение: разбор файла и сохранение находок."""
    parsed = parse_workbook(path)
    return db.save_import(project_id, name or path.name, parsed.format, parsed.sheets, parsed.summary,
                          parsed.warnings, order_findings(parsed.findings))


def composition_of(db: Database, project_id: int) -> tuple[list[dict], str]:
    """Текущий состав проекта и его отпечаток – так их считает страница перед сборкой задания."""
    rows, _ = research.task_rows(db.sca_components(project_id),
                                 db.get_settings().get("sca_internal_prefixes", ()) or (), db.sca_confirmed(project_id))
    return rows, research.sha256(research.composition(rows))


def component(name: str, version: str, *, ecosystem: str = "maven", fixed=("1.4.9",), findings: int = 2,
              codebases=(CODEBASE,)) -> dict:
    """Пакет в виде Database.sca_components."""
    return {"ecosystem": ecosystem, "component": name, "version": version, "findings": findings,
            "hub_ids": [HUB_ID], "finding_ids": [1], "cvss": 9.8, "urgent": True, "cve": ["CVE-2099-10001"],
            "vuln_ids": [AST_ID], "fixed_versions": list(fixed), "cwe": ["CWE-611"],
            "codebases": list(codebases), "build_types": [ecosystem], "dep_paths": ["core > app"],
            "reviewed": 0, "entered": 0}


PACKAGES = [component("org.example:example-parser", "9.0.83"),
            component("example-parser", "9.0.83"),
            component("@example/parser", "7.23.2", ecosystem="npm", fixed=("7.23.5",), codebases=("catalog-api",))]


def task_of(rows: list[dict], task_id: str = "t-20261017-ab12cd") -> dict:
    return {"task_id": task_id, "manifest_sha256": research.sha256(research.composition(rows)),
            "row_count": len(rows), "ecosystems": sorted({row["ecosystem"] for row in rows})}


def kit_rows(rows: list[dict]) -> list[dict]:
    return [research.row_text(item) for item in rows]


# ============================================================== строки задания

def test_task_rows_are_stable_and_keep_coordinates_untouched():
    rows, excluded = research.task_rows(PACKAGES)
    assert excluded == []
    assert [row["name"] for row in rows] == [item["component"] for item in PACKAGES]
    assert [row["identity_kind"] for row in rows] == ["coordinates", "short_name", "registry_name"]
    # область npm часть имени, а не часть версии
    assert rows[2]["name"] == "@example/parser" and rows[2]["version"] == "7.23.2"
    # подсказка из выгрузки сохраняется и помечена, но вывод агента не ею ограничен
    assert rows[0]["hub_fix_candidate"] == "1.4.9"
    assert rows[0]["finding_count"] == 2 and rows[0]["codebase_count"] == 1
    # тот же пакет из другой экосистемы – другая строка
    other = research.input_ref("pypi", "example-parser", "9.0.83")
    assert other != rows[1]["input_ref"] and other.startswith("pypi:")


def test_input_ref_does_not_change_from_new_findings_or_row_numbers():
    """Переимпорт с другими номерами строк выгрузки не должен обесценивать исследование и решение человека."""
    first, _ = research.task_rows(PACKAGES)
    again, _ = research.task_rows([dict(item, hub_ids=["99999"], finding_ids=[7], findings=5) for item in PACKAGES])
    assert [row["input_ref"] for row in first] == [row["input_ref"] for row in again]
    assert [row["input_sig"] for row in first] == [row["input_sig"] for row in again]
    changed, _ = research.task_rows([component("org.example:example-parser", "9.0.84")])
    assert changed[0]["input_ref"] != first[0]["input_ref"]


def test_composition_fingerprint_changes_only_with_the_composition():
    rows, _ = research.task_rows(PACKAGES)
    assert research.sha256(research.composition(rows)) == research.sha256(research.composition(rows))
    other, _ = research.task_rows(PACKAGES[:2])
    assert research.sha256(research.composition(other)) != research.sha256(research.composition(rows))


def test_internal_and_doubtful_names_stay_out_of_the_task():
    rows, excluded = research.task_rows([component("billing-core", "1.0.0"),
                                         component("core/billing", "0.0.1"),
                                         component("org.example:lib", "2.0.0")],
                                        prefixes=("billing-",))
    assert [row["name"] for row in rows] == ["org.example:lib"]
    assert [item["doubtful"] for item in excluded] == [False, True]
    # подтверждённое человеком сомнительное имя в задание попадает
    rows, excluded = research.task_rows([component("core/billing", "0.0.1")], confirmed={"core/billing@0.0.1"})
    assert [row["name"] for row in rows] == ["core/billing"] and excluded == []


# ============================================================== комплект для агента

def test_kit_has_six_files_and_nothing_local():
    rows, _ = research.task_rows(PACKAGES)
    archive = zipfile.ZipFile(io.BytesIO(research.kit(task_of(rows), rows, "2026-10-17T19:00:00+00:00")))
    assert sorted(archive.namelist()) == ["answer.schema.json", "answer.template.json", "components.json",
                                          "manifest.json", "task.md", "validate.py"]
    # валидатор в комплекте – тот же файл, что проверяет приложение
    assert archive.read("validate.py") == (ROOT / "app" / "sca_contract.py").read_bytes()
    everything = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
    for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID, APP_NAME, "core > app", "CWE-611"):
        assert secret not in everything, secret


def test_manifest_publishes_contract_validator_limits_and_rows():
    rows, _ = research.task_rows(PACKAGES)
    manifest = research.manifest(task_of(rows), rows, "2026-10-17T19:00:00+00:00")
    assert manifest["contract"] == CONTRACT and manifest["answer_contract"] == ANSWER_CONTRACT
    assert manifest["validator_version"] == VALIDATOR_VERSION
    assert manifest["validator_sha256"] == research.validator_sha256()
    assert manifest["manifest_sha256"] == research.sha256(research.composition(rows))
    assert manifest["row_count"] == 3 and [row["input_ref"] for row in manifest["rows"]] == \
        [row["input_ref"] for row in rows]
    assert manifest["limits"]["findings_per_row"] >= 100 and manifest["freshness"]["as_of"]
    # строки манифеста достаточно, чтобы командная проверка нашла подмену координат и версии
    assert set(manifest["rows"][0]) == {"input_ref", "ecosystem", "component", "version", "identity_kind",
                                        "vulnerability_ids"}
    assert manifest["rows"][0]["identity_kind"] in ("coordinates", "short_name", "registry_name")


def test_components_doc_is_the_only_table_of_rows():
    rows, _ = research.task_rows(PACKAGES)
    doc = research.components_doc(task_of(rows), rows, "2026-10-17T19:00:00+00:00")
    assert set(doc["rows"][0]) == {"input_ref", "ecosystem", "component", "version", "identity_kind",
                                   "hub_fix_candidate", "vulnerability_ids"}
    assert doc["row_count"] == 3 and doc["task_id"] == "t-20261017-ab12cd"


def test_answer_template_is_the_contract_itself():
    rows, _ = research.task_rows(PACKAGES)
    template = research.answer_template(task_of(rows), rows)
    assert template["contract"] == ANSWER_CONTRACT and template["row_count"] == 3
    assert [item["input_ref"] for item in template["rows"]] == [row["input_ref"] for row in rows]
    # входные поля заготовки совпадают с заданием: агент их не переписывает, а подмену заметно
    assert [(item["ecosystem"], item["component"], item["current_version"]) for item in template["rows"]] == \
        [(row["ecosystem"], row["name"], row["version"]) for row in rows]
    assert all(item["package_status"] == "incomplete" for item in template["rows"])


def test_task_text_states_the_rules_the_agent_must_follow():
    rows, _ = research.task_rows(PACKAGES)
    text = research.task_text(task_of(rows), rows)
    for needle in ("python validate.py --manifest manifest.json --answer answer.json", "Окончание поддержки (EOL)",
                   "не отменяет", "Последний стабильный релиз и минимальное исправление", "Не угадывайте groupId",
                   "не выдумывайте", "AST-…", "БДУ ФСТЭК России", "Maven Central", "hub_fix_candidate",
                   "должны совпадать с заданием", "Не обещайте, что последний релиз полностью безопасен"):
        assert needle in text, needle
    assert "Строк в задании: 3" in text
    assert LONG_DASH not in text
    assert not FSTEC_BARE.search(text)  # регулятор пишется полностью: правило общее с проверкой текстов репозитория
    for secret in (CODEBASE, HUB_ID, AST_ID):
        assert secret not in text, secret


def test_schema_doc_is_the_contract_of_the_validator():
    schema = research.schema_doc()
    assert schema["x-contract"] == ANSWER_CONTRACT and schema["properties"]["rows"]["items"]


# ============================================================== ответ агента

def answer_for(rows: list[dict]) -> dict:
    """Принятый ответ по трём строкам задания: одна уязвимость, полный охват у первых двух, пробел у третьей."""
    payload = []
    for index, row in enumerate(rows):
        vulnerable = index == 0
        evidence = [{"evidence_ref": "ev-1", "url": "https://advisories.example.invalid/CVE-2099-10001",
                     "checked_at": "2026-10-16", "source_type": "advisory", "justification": "Запись OSV",
                     "quote": "CVE-2099-10001", "level": "primary"}]
        payload.append({
            "input_ref": row["input_ref"], "ecosystem": row["ecosystem"], "component": row["name"],
            "current_version": row["version"],
            "identity_resolution": {"state": "resolved", "coordinates": row["name"], "candidates": [],
                                    "note": "", "source_refs": ["ev-1"]},
            "latest_stable_release": {"version": "11.0.22", "released_at": "2026-09-30", "note": "",
                                      "source_refs": ["ev-1"]},
            "update_status": "update_available",
            "support_status": {"state": "eol", "scope": "oss", "as_of": "2026-10-01", "note": "Ветка закрыта",
                               "source_refs": ["ev-1"]},
            "public_findings": ([{"id": "CVE-2099-10001", "aliases": ["GHSA-4r9m-6cqx-x5h2"], "applies": "yes",
                                  "description": "Обход аутентификации", "ranges": [{"introduced": "9.0.0.M1",
                                                                                     "fixed": "9.0.99"}],
                                  "conditions": "", "fixed_versions": ["9.0.99"],
                                  "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N", "version": "3.1"},
                                  "source_refs": ["ev-1"]}] if vulnerable else []),
            "research_coverage": [{"source": "OSV", "purpose": "vulnerabilities",
                                   "query": {"ecosystem": row["ecosystem"], "coordinates": row["name"],
                                             "version": row["version"]},
                                   "source_refs": ["ev-1"], "checked_at": "2026-10-16", "status": "ok",
                                   "complete": True, "note": ""}],
            "package_advice": {"action": "update" if vulnerable else "no_action",
                               "target_version": "9.0.99" if vulnerable else None,
                               "compatibility_notes": "" if vulnerable else "Обновлений нет",
                               "remaining_risks": []},
            "evidence": evidence, "gaps": [],
            "package_status": "vulnerable" if vulnerable else "no_known_vulnerabilities",
        })
    payload = [complete_research_row(item) for item in payload]
    return {"contract": ANSWER_CONTRACT, "task_id": "t-20261017-ab12cd",
            "manifest_sha256": research.sha256(research.composition(rows)), "validator_version": VALIDATOR_VERSION,
            "generated_at": "2026-10-17T10:00:00Z", "row_count": len(rows), "rows": payload}


def test_accepted_answer_gives_rows_for_storage():
    rows, _ = research.task_rows(PACKAGES)
    task = task_of(rows)
    text = json.dumps(answer_for(rows), ensure_ascii=False)
    report = research.check_answer(text, task, rows)
    assert report.ok, report.errors[:3]
    results = research.research_results(report.answer, rows)
    assert len(results) == 3
    first = results[0]
    assert (first["status"], first["findings_total"], first["applicable"], first["evidence_count"]) == \
        ("vulnerable", 1, 1, 2)
    assert results[1]["status"] == "no_known_vulnerabilities" and results[1]["applicable"] == 0
    assert all(item["input_sig"] == next(row["input_sig"] for row in rows if row["input_ref"] == item["input_ref"])
               for item in results)


def test_answer_from_another_task_is_rejected():
    rows, _ = research.task_rows(PACKAGES)
    other = task_of(rows, "t-20261017-ffff")
    report = research.check_answer(json.dumps(answer_for(rows), ensure_ascii=False), other, rows)
    assert not report.ok and "SCA-T002" in report.codes()


def test_row_view_and_status_note_explain_the_verdict():
    rows, _ = research.task_rows(PACKAGES)
    results = {item["input_ref"]: item for item in research.research_results(answer_for(rows), rows)}
    view = research.row_view(rows[0], results[rows[0]["input_ref"]], None, "current")
    assert view["status"] == "vulnerable" and view["applicable"] == 1 and view["coverage"]["complete"]
    assert "применимых уязвимостей: 1" in view["status_note"]
    assert view["decision"] is None and not view["decision_stale"]
    assert view["findings"][0]["applies_label"] == "относится к этой версии"
    assert view["findings"][0]["sources"][0]["level_label"] == "первоисточник"
    clean = research.row_view(rows[1], results[rows[1]["input_ref"]], None, "current")
    assert "уязвимостей не найдено" in clean["status_note"]
    empty = research.row_view(rows[2], None, None, "superseded")
    assert empty["status"] == "" and empty["task_stale"] and not empty["researched"]
    assert empty["status_label"] == "не исследован"


def test_filters_and_summaries():
    rows, _ = research.task_rows(PACKAGES)
    results = {item["input_ref"]: item for item in research.research_results(answer_for(rows), rows)}
    views = [research.row_view(row, results.get(row["input_ref"]), None, "current") for row in rows]
    counts = research.summaries(views)
    assert counts == {"total": 3, "vulnerable": 1, "no_known_vulnerabilities": 2, "incomplete": 0,
                      "identity_unresolved": 0, "unresearched": 0, "decided": 0, "stale": 0,
                      "with_gaps": 0, "support_unknown": 0, "in_defect": 0}
    assert [row["name"] for row in research.filter_rows(views, {"status": "vulnerable"})] == [rows[0]["name"]]
    assert len(research.filter_rows(views, {"q": "EXAMPLE/parser".casefold()})) == 1
    assert len(research.filter_rows(views, {"ecosystem": "npm"})) == 1
    assert research.filter_rows(views, {"status": "unresearched"}) == []
    assert research.filter_rows(views, {"decision": "unset"}) == views


# ============================================================== решение человека

@pytest.mark.parametrize("form, want", [
    ({}, "Выберите"),
    ({"action": "keep"}, "Напишите причину"),
    ({"action": "update", "rationale": "Патч есть"}, "версию, на которую переходим"),
    ({"action": "replace", "rationale": "Проект заброшен"}, "заменяющего пакета"),
    ({"action": "keep", "rationale": "л" * (research.RATIONALE_CHARS + 1)}, "длиннее"),
    ({"action": "keep", "rationale": "ок", "review_at": "17.10.2026"}, "ГГГГ-ММ-ДД"),
])
def test_decision_rules(form: dict, want: str):
    assert want in research.check_decision(form)


@pytest.mark.parametrize("action, extra", [
    ("update", {"target_version": "9.0.99"}), ("keep", {}), ("accept_risk", {}),
    ("replace", {"replacement_name": "example-parser", "replacement_version": "11.0.22"}),
    ("investigate", {}), ("remove", {}),
])
def test_valid_decisions_are_accepted(action: str, extra: dict):
    assert research.check_decision({"action": action, "rationale": "Проверено в выпуске", **extra}) == ""


def test_decision_form_keeps_entered_values_on_reject():
    form = {"action": "update", "rationale": "Патч", "target_version": "9.0.99", "review_at": "2026-11-01"}
    assert research.decision_form(form, 3) == {"action": "update", "rationale": "Патч", "target_version": "9.0.99",
                                               "replacement_name": "", "replacement_version": "", "review_at": "2026-11-01",
                                               "revision": 3, "expected_input_sig": "", "expected_research_sig": "",
                                               "expected_research_revision": 0}
    # отпечатки увиденного подставляются только если форма их не принесла
    fresh = research.decision_form(form, 0, input_sig="sig-строки", research_sig="sig-ответа", research_revision=2)
    assert (fresh["expected_input_sig"], fresh["expected_research_sig"], fresh["expected_research_revision"]) == \
        ("sig-строки", "sig-ответа", 2)
    assert fresh["revision"] == 0


# ============================================================== отчёты

def test_report_holds_public_facts_and_decision_and_nothing_local():
    rows, _ = research.task_rows(PACKAGES)
    results = {item["input_ref"]: item for item in research.research_results(answer_for(rows), rows)}
    views = [research.row_view(row, results.get(row["input_ref"]), None, "current") for row in rows]
    decision = {"id": 1, "input_ref": rows[0]["input_ref"], "action": "update", "action_label": "обновить",
                "rationale": "Обновление в ветке 9.0.x", "target_version": "9.0.99", "replacement_name": "",
                "replacement_version": "", "review_at": "", "decided_at": "2026-10-17T19:41:03+03:00",
                "revision": 1, "research_sig": views[0]["answer_sig"], "input_sig": rows[0]["input_sig"],
                "state": "current", "superseded_at": None}
    views[0]["decision"] = research.decision_view(decision)
    views[0]["decided"] = True
    document = research.report(project={"id": 1, "name": APP_NAME}, task=task_of(rows), rows=views,
                               generated_at="2026-10-17T20:00:00+00:00")
    assert document["contract"] == "local-triage/sca-report/2"
    assert len(document["components"]) == 3  # неисследованные строки в отчёт не идут
    body = json.dumps(document, ensure_ascii=False)
    for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID):
        assert secret not in body, secret
    first = document["components"][0]
    assert first["status"] == "vulnerable" and first["public_findings"][0]["id"] == "CVE-2099-10001"
    assert first["decision"]["action"] == "update" and first["decision"]["rationale"]
    assert first["identity"]["coordinates"] == rows[0]["name"]
    assert first["research_coverage"][0]["source"] == "OSV"
    text = research.report_text(document)
    assert "org.example:example-parser" in text and "Обновление в ветке 9.0.x" in text
    for secret in (CODEBASE, HUB_ID, AST_ID):
        assert secret not in text, secret


def test_agent_can_work_with_the_kit_alone_and_the_app_agrees(tmp_path: Path):
    """Комплект самодостаточен: распакованный агентом и заполненный по заготовке ответ проходит его же
    validate.py и принимается приложением тем же кодом."""
    rows, _ = research.task_rows(PACKAGES)
    task = task_of(rows)
    with zipfile.ZipFile(io.BytesIO(research.kit(task, rows, "2026-10-17T19:00:00+00:00"))) as archive:
        archive.extractall(tmp_path)
    answer = json.loads((tmp_path / "answer.template.json").read_text(encoding="utf-8"))
    filled = research.research_results(answer, rows)
    assert len(filled) == 3 and filled[0]["status"] == "incomplete"
    for index, (item, source) in enumerate(zip(answer["rows"], rows)):
        item["identity_resolution"].update(state="resolved", coordinates=item["component"], source_refs=["ev-1"])
        item["latest_stable_release"].update(version="11.0.22", released_at="2026-09-30", source_refs=["ev-1"])
        item["support_status"].update(state="eol", scope="oss", as_of="2026-10-01", source_refs=["ev-1"])
        item["update_status"] = "update_available"
        item["public_findings"] = ([{"id": "CVE-2099-10001", "aliases": [], "applies": "yes",
                                    "description": "Обход аутентификации", "ranges": [], "conditions": "",
                                    "fixed_versions": ["9.0.99"], "cvss": None, "source_refs": ["ev-1"]}]
                                  if index == 0 else [])
        item["research_coverage"] = [{"source": "OSV", "purpose": "vulnerabilities",
                                      "query": {"ecosystem": source["ecosystem"], "coordinates": source["name"],
                                                "version": source["version"]}, "source_refs": ["ev-1"],
                                      "checked_at": "2026-10-16", "status": "ok", "complete": True, "note": ""}]
        item["package_advice"].update(action="update" if index == 0 else "no_action",
                                      target_version="9.0.99" if index == 0 else None)
        item["evidence"] = [{"evidence_ref": "ev-1", "url": "https://advisories.example.invalid/CVE-2099-10001",
                             "checked_at": "2026-10-16", "source_type": "advisory",
                             "justification": "Запись OSV", "quote": "CVE-2099-10001", "level": "primary"}]
        item["gaps"] = []
        item["package_status"] = "vulnerable" if index == 0 else "no_known_vulnerabilities"
        complete_research_row(item)
    (tmp_path / "answer.json").write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")
    run = subprocess.run([sys.executable, str(tmp_path / "validate.py"), "--manifest",
                          str(tmp_path / "manifest.json"), "--answer", str(tmp_path / "answer.json")],
                         capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    report = research.check_answer((tmp_path / "answer.json").read_text(encoding="utf-8"), task, rows)
    assert report.ok and report.summary == {"vulnerable": 1, "no_known_vulnerabilities": 2}


# ============================================================== хранение

@pytest.fixture
def stored(tmp_path: Path):
    """База с проектом, настоящей выгрузкой и заданием по трём строкам её состава."""
    db = Database(tmp_path / "triage.db")
    pid = db.create_project(APP_NAME)
    loaded = load_export(db, pid, hub_export(tmp_path / "hub.xlsx"))
    rows, digest = composition_of(db, pid)
    task = db.insert_task(pid, int(loaded["import_id"]), "t-20261017-ab12cd", rows, ["maven", "npm"], digest,
                          "components-sha", CONTRACT, ANSWER_CONTRACT, VALIDATOR_VERSION)
    return db, pid, task, rows


def test_task_rows_are_saved_and_the_task_is_current(stored):
    db, pid, task, rows = stored
    assert task["state"] == "current" and task["row_count"] == 3
    assert [row["name"] for row in rows] == [item["component"] for item in PACKAGES]
    saved = db.task_rows(task["id"])
    assert [row["input_ref"] for row in saved] == [row["input_ref"] for row in rows]
    assert [row["identity_kind"] for row in saved] == ["coordinates", "short_name", "registry_name"]
    assert db.task(pid, "t-20261017-ab12cd")["row_count"] == 3 and db.task(pid, "нет") is None
    assert db.task_row(pid, rows[0]["input_ref"])["name"] == rows[0]["name"]


def test_new_composition_supersedes_the_previous_task(stored, tmp_path: Path):
    """Новый состав выгрузки вытесняет прежнее задание; строка, ушедшая из выгрузки, остаётся в базе."""
    db, pid, task, rows = stored
    # в выгрузке остались только пакеты maven: третья строка из состава ушла
    left = [row for row in HUB_ROWS if row["Issue id"] != "73003"]
    loaded = load_export(db, pid, hub_export(tmp_path / "less.xlsx", left))
    other, digest = composition_of(db, pid)
    assert len(other) == 2 and other != rows
    db.insert_task(pid, int(loaded["import_id"]), "t-20261017-second", other, ["maven"], digest, "sha-c", CONTRACT,
                   ANSWER_CONTRACT, VALIDATOR_VERSION)
    assert db.task(pid, "t-20261017-ab12cd")["state"] == "superseded"
    assert db.task(pid, "t-20261017-ab12cd")["superseded_at"]
    assert db.task(pid, "t-20261017-second")["state"] == "current"
    assert [item["task_id"] for item in db.tasks(pid)] == ["t-20261017-second", "t-20261017-ab12cd"]
    # строка, ушедшая из состава, остаётся в базе, но в действующем задании её нет
    assert db.task_row(pid, rows[2]["input_ref"]) is None
    assert len(db.task_rows(db.task(pid, "t-20261017-ab12cd")["id"])) == 3


def test_research_revisions_are_immutable_and_reimport_is_idempotent(stored):
    db, pid, task, rows = stored
    results = research.research_results(answer_for(rows), rows)
    first = db.save_research(pid, task["id"], results)
    assert first["saved"] == 3 and first["unchanged"] == 0
    again = db.save_research(pid, task["id"], results)
    assert again["saved"] == 0 and again["unchanged"] == 3 and again["revisions"] == first["revisions"]
    changed = research.research_results(answer_for(rows), rows)
    changed[0]["answer_sig"] = "b" * 64
    third = db.save_research(pid, task["id"], changed)
    assert third["saved"] == 1 and third["revisions"][rows[0]["input_ref"]] == 2
    # прежняя ревизия никуда не делась
    history = db.research_history(pid, rows[0]["input_ref"])
    assert [item["revision"] for item in history] == [2, 1]
    assert db.research_row(pid, rows[0]["input_ref"])["payload"]["package_status"] == "vulnerable"


def test_decision_history_cas_and_staleness(stored):
    db, pid, task, rows = stored
    db.save_research(pid, task["id"], research.research_results(answer_for(rows), rows))
    current = db.research_row(pid, rows[0]["input_ref"])
    seen = (current["answer_sig"], int(current["revision"]))  # что человек видел на странице
    decision = db.save_decision(pid, rows[0]["input_ref"], "update", "Патч в ветке", "9.0.99", "", "", "",
                                rows[0]["input_sig"], current["answer_sig"], 0, *seen)
    assert decision["revision"] == 1 and decision["state"] == "current"
    assert db.decision(pid, rows[0]["input_ref"])["action"] == "update"
    # решение с устаревшей страницы не пишется
    with pytest.raises(DecisionStale):
        db.save_decision(pid, rows[0]["input_ref"], "keep", "Передумал", "", "", "", "", rows[0]["input_sig"],
                         current["answer_sig"], 0, *seen)
    assert db.decision(pid, rows[0]["input_ref"])["action"] == "update"
    again = db.save_decision(pid, rows[0]["input_ref"], "accept_risk", "Обновление в следующем окне", "", "", "", "",
                             rows[0]["input_sig"], current["answer_sig"], 1, *seen)
    assert again["revision"] == 2
    history = db.decision_history(pid, rows[0]["input_ref"])
    assert [item["revision"] for item in history] == [2, 1]
    assert history[1]["state"] == "superseded" and history[1]["superseded_at"]
    # решение, привязанное к ответу агента, без отпечатков увиденного не принимается
    with pytest.raises(DecisionStale):
        db.save_decision(pid, rows[1]["input_ref"], "keep", "По памяти", "", "", "", "", "", "", 0)
    # а решение по строке без ответа агента сохраняется (проверено в тестах адресов)


def test_project_delete_removes_research_and_decisions(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    pid = db.create_project(APP_NAME)
    loaded = load_export(db, pid, hub_export(tmp_path / "hub.xlsx"))
    rows, digest = composition_of(db, pid)
    task = db.insert_task(pid, int(loaded["import_id"]), "t-1", rows, ["maven", "npm"], digest, "sha-c", CONTRACT,
                          ANSWER_CONTRACT, VALIDATOR_VERSION)
    db.save_research(pid, task["id"], research.research_results(answer_for(rows), rows))
    seen = db.research_row(pid, rows[0]["input_ref"])
    db.save_decision(pid, rows[0]["input_ref"], "keep", "Пока оставить", "", "", "", "", rows[0]["input_sig"], "",
                     0, seen["answer_sig"], int(seen["revision"]))
    assert db.delete_project(pid) is True
    assert db.current_task(pid) is None and db.research(pid) == {} and db.decisions(pid) == {}
