"""Контракт второй версии ответа агента по исследованию компонентов SCA: одно описание полей, схема из него,
проверки приложения и командная проверка из комплекта задания.

Контракт общий для приложения и внешнего агента: тот же файл копируется в комплект как validate.py, поэтому
проверяем, что он не зависит от приложения, выдаёт полный отчёт об ошибках полей и отказывает там, где ответ
нельзя принимать (подмена строк, несуществующие ссылки на доказательства, будущие даты, внутренние номера,
превышение пределов без обрезки).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from component_research_fixtures import complete_research_row

from app import sca_contract as sc

ROOT = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 17)
TOMCAT = ("maven", "org.example:example-parser", "9.0.83")
BABEL = ("npm", "@example/parser", "7.23.2")
ROWS = [dict(zip(("input_ref", "ecosystem", "component", "version", "identity_kind"),
                (sc.input_ref(*TOMCAT), *TOMCAT, "coordinates"))),
        dict(zip(("input_ref", "ecosystem", "component", "version", "identity_kind"),
                (sc.input_ref(*BABEL), *BABEL, "registry_name")))]
TASK = {"task_id": "t-20261017-ab12cd", "manifest_sha256": "a" * 64, "row_count": len(ROWS), "rows": ROWS}

EVIDENCE = [
    {"evidence_ref": "ev-1", "url": "https://advisories.example.invalid/CVE-2099-10001", "checked_at": "2026-10-16",
     "source_type": "advisory", "justification": "Запись об уязвимости в OSV", "quote": "CVE-2099-10001",
     "level": "primary"},
    {"evidence_ref": "ev-2", "url": "https://example.invalid/support", "checked_at": "2026-10-16",
     "source_type": "policy", "justification": "Политика поддержки веток Example Parser", "quote": "9.0.x EOL",
     "level": "primary"},
]


def coverage_row(index: int = 0, **fields) -> dict:
    """Запись охвата: сказано, что искали уязвимости, для каких координат и по какому источнику."""
    source = ROWS[index]
    base = {"source": "OSV", "purpose": "vulnerabilities",
            "query": {"ecosystem": source["ecosystem"], "coordinates": source["component"],
                      "version": source["version"]},
            "source_refs": ["ev-1"], "checked_at": "2026-10-16", "status": "ok", "complete": True, "note": ""}
    return {**base, **fields}


def row(index: int = 0, **fields) -> dict:
    """Правильная строка ответа по строке задания: подтверждённая идентичность, одна применимая находка,
    источники с цитатами, решение «обновить»."""
    src = ROWS[index]
    base = {
        "input_ref": src["input_ref"], "ecosystem": src["ecosystem"], "component": src["component"],
        "current_version": src["version"],
        "identity_resolution": {"state": "resolved", "coordinates": src["component"], "candidates": [],
                                "note": "", "source_refs": ["ev-1"]},
        "latest_stable_release": {"version": "11.0.22", "released_at": "2026-09-30", "note": "",
                                  "source_refs": ["ev-1"]},
        "update_status": "update_available",
        "support_status": {"state": "eol", "scope": "oss", "as_of": "2026-10-01",
                           "note": "Ветка 9.0.x больше не поддерживается", "source_refs": ["ev-2"]},
        "public_findings": [{"id": "CVE-2099-10001", "aliases": ["GHSA-4r9m-6cqx-x5h2"], "applies": "yes",
                             "description": "Обход аутентификации при частичной загрузке сессии",
                             "ranges": [{"introduced": "9.0.0.M1" if index == 0 else "0", "fixed": "9.0.99"}], "conditions": "",
                             "fixed_versions": ["9.0.99"],
                             "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                      "version": "3.1"},
                             "source_refs": ["ev-1"]}],
        "research_coverage": [coverage_row(index, note="Проверено по идентификатору"),
                              {"source": "NVD", "checked_at": "2026-10-16", "status": "error", "complete": False,
                               "note": "Ответ 403"}],
        "package_advice": {"action": "update", "target_version": "9.0.99",
                           "compatibility_notes": "Проверить совместимость приложения с Jakarta Servlet 6",
                           "remaining_risks": ["Ветка 9.0.x вне поддержки"]},
        "evidence": [dict(item) for item in EVIDENCE],
        "gaps": [{"code": "SOURCE_BLOCKED", "text": "Проверка NVD не завершена: ответ 403"}],
        "package_status": "vulnerable",
    }
    return {**complete_research_row(base), **fields}


def answer(*rows: dict, **fields) -> dict:
    return {"contract": sc.ANSWER_CONTRACT, "task_id": TASK["task_id"],
            "manifest_sha256": TASK["manifest_sha256"], "validator_version": sc.VALIDATOR_VERSION,
            "generated_at": "2026-10-17T09:00:00Z", "row_count": len(rows),
            "rows": [dict(item) for item in rows], **fields}


def check(payload, **kwargs) -> sc.Report:
    return sc.validate_answer(json.dumps(payload, ensure_ascii=False), TASK, today=TODAY, **kwargs)


def paths(report: sc.Report) -> list[str]:
    return [error["path"] for error in report.errors]


def codes(report: sc.Report) -> list[str]:
    return [error["code"] for error in report.errors]


# ============================================================== описание, схема и совпадение с проверками

def test_schema_is_built_from_the_same_description_as_the_validator():
    schema = sc.schema()
    properties = schema["properties"]
    assert properties["contract"]["enum"] == [sc.ANSWER_CONTRACT]
    assert properties["task_id"]["maxLength"] == sc.LIMITS["id_chars"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"contract", "task_id", "manifest_sha256", "validator_version", "rows",
                                       "row_count"}
    # каждое поле описания попало в схему с теми же границами, перечислениями и необязательностью
    for name, field in sc._ANSWER_SPEC.items():
        assert properties[name] == field.schema(), name
    row = properties["rows"]["items"]
    # обязательны все поля строки, кроме расширения 2.1 «проверка версий» (ADR-0094)
    assert row == sc.ROW_SCHEMA and set(row["required"]) == set(row["properties"]) - {"version_checks"}
    # пределы публикуются в схеме: агент узнаёт о них до ответа, а не после отказа
    assert schema["x-limits"] == sc.LIMITS and schema["x-validator"] == sc.VALIDATOR_VERSION
    assert sc.LIMITS["evidence_per_row"] >= 100 and sc.LIMITS["answer_bytes"] >= 8 * 1024 * 1024


def test_schema_matches_module_enums_and_status_logic():
    assert tuple(sc.ROW_SCHEMA["properties"]["package_status"]["enum"]) == sc.PACKAGE_STATUSES
    assert set(sc.ADVICE_ACTIONS) >= {"update", "keep", "replace", "remove", "accept_risk", "needs_identity"}
    assert sc.row_status(row()) == "vulnerable"
    clean = row(public_findings=[], package_advice={"action": "no_action", "target_version": "",
                                                    "compatibility_notes": "Обновлений нет",
                                                    "remaining_risks": []},
                update_status="up_to_date", gaps=[], research_coverage=[coverage_row()],
                latest_stable_release={"version": "9.0.83", "released_at": "",
                                       "note": "", "source_refs": ["ev-1"]},
                package_status="no_known_vulnerabilities")
    assert sc.row_status(clean) == "no_known_vulnerabilities"
    # неполный охват не делает результат чистым
    partial = row(public_findings=[], research_coverage=[coverage_row(source="NVD", status="error",
                                                                          complete=False, note="403")],
                  package_status="incomplete")
    assert sc.row_status(partial) == "incomplete"
    assert sc.row_status(row(identity_resolution={"state": "ambiguous", "coordinates": "", "candidates": ["a"],
                                                  "note": "", "source_refs": ["ev-1"]})) == "identity_unresolved"


def test_contract_module_is_standalone_and_runnable_as_validate_py():
    """Комплект отдаётся внешнему агенту: файл обязан работать без приложения, только на стандартной библиотеке."""
    source = (ROOT / "app" / "sca_contract.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+(fastapi|starlette|requests|pydantic|app\.)", source, re.M)
    assert "def main(" in source and sc.__file__.endswith("sca_contract.py")


# ============================================================== правильный ответ

def test_valid_answer_passes_and_keeps_its_hash():
    payload = answer(row(), row(1))
    report = check(payload)
    assert report.ok, report.errors
    assert report.answer_bytes == len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    assert report.answer_sha256 == sc.sha256(sc.canonical(payload))
    assert report.summary == {"vulnerable": 2}
    assert sc.row_status(payload["rows"][1]) == "vulnerable"


def test_bytes_and_unicode_do_not_change_the_result():
    text = json.dumps(answer(row(), row(1)), ensure_ascii=False)
    for raw in (text.encode("utf-8"), text.encode("utf-8-sig")):
        assert sc.validate_answer(raw, TASK, today=TODAY).ok
    assert not sc.validate_answer(text.encode("utf-16"), TASK, today=TODAY).ok


def test_template_is_the_same_contract_and_valid_after_fill():
    template = sc.template(TASK, ROWS)
    assert template["contract"] == sc.ANSWER_CONTRACT and template["row_count"] == len(ROWS)
    assert [item["input_ref"] for item in template["rows"]] == [item["input_ref"] for item in ROWS]
    for item, source in zip(template["rows"], ROWS):
        # входные поля уже стоят из задания: их не нужно переписывать, и подмена заметна проверке
        assert (item["ecosystem"], item["component"], item["current_version"]) == \
            (source["ecosystem"], source["component"], source["version"])
        assert item["package_status"] == "incomplete" and item["public_findings"] == []
        assert sc.row_status(item) == "incomplete", "пустая заготовка не должна считаться чистым результатом"
    filled = answer(row(), row(1))
    filled["task_id"] = template["task_id"]
    filled["manifest_sha256"] = template["manifest_sha256"]
    assert check(filled).ok


# ============================================================== техника: JSON, пределы, глубина

def test_rejects_unparsable_json_and_reports_the_reason():
    report = sc.validate_answer("{", TASK, today=TODAY)
    assert codes(report) == ["SCA-M001"] and not report.ok
    assert not sc.validate_answer("", TASK, today=TODAY).ok


def test_rejects_nan_infinity_and_duplicate_keys():
    text = json.dumps(answer(row()), ensure_ascii=False)
    for literal in ("NaN", "Infinity", "-Infinity"):
        broken = text.replace('"generated_at": "2026-10-17T09:00:00Z"', f'"generated_at": {literal}')
        report = sc.validate_answer(broken, TASK, today=TODAY)
        assert not report.ok and codes(report)[0] == "SCA-M001", literal
    duplicated = text.replace('"generated_at": "2026-10-17T09:00:00Z",',
                              '"generated_at": "2026-10-17T09:00:00Z", "generated_at": "2026-10-16T09:00:00Z",', 1)
    report = sc.validate_answer(duplicated, TASK, today=TODAY)
    assert not report.ok and "повтор" in report.errors[0]["message"].lower()
    # число вне диапазона разбора JSON (1e999) тоже не число ответа
    overflow = text.replace('"score": 9.8', '"score": 1e999')
    report = sc.validate_answer(overflow, TASK, today=TODAY)
    assert not report.ok and "SCA-M" in codes(report)[0]


def test_rejects_unknown_fields_and_missing_fields():
    payload = answer(row(), row(1))
    payload["rows"][0]["ast_ids"] = ["AST-2026-000101"]
    report = check(payload)
    assert not report.ok and "SCA-M003" in codes(report) and "rows[0].ast_ids" in paths(report)
    missing = answer(row(), row(1))
    del missing["rows"][0]["update_status"]
    report = check(missing)
    assert not report.ok and "SCA-M004" in codes(report) and "rows[0].update_status" in paths(report)


def test_rejects_wrong_type_and_unknown_enum_values():
    report = check(answer(row(identity_resolution=[]), row(1)))
    assert "SCA-M005" in codes(report)
    report = check(answer(row(update_status="maybe"), row(1)))
    assert "SCA-M005" in codes(report) and "rows[0].update_status" in paths(report)
    report = check(answer(row(public_findings=[{"id": "CVE-2025-1", "applies": "yes"}]), row(1)))
    assert "SCA-M003" in codes(report) or "SCA-M004" in codes(report)


def test_limits_are_reported_without_truncation():
    too_big = answer(row(evidence=[{**item, "justification": "л" * (sc.LIMITS["text_chars"] + 1)}
                                   for item in EVIDENCE]), row(1))
    report = check(too_big)
    assert not report.ok and "SCA-M002" in codes(report)
    assert "rows[0].evidence[0].justification" in " ".join(paths(report))
    payload = sc.canonical(answer(row(), row(1))).decode("utf-8")
    padded = payload.replace('"note":""', '"note":"%s"' % ("л" * (sc.LIMITS["answer_bytes"] // 2)))
    report = sc.validate_answer(padded, TASK, today=TODAY)
    assert not report.ok and "SCA-M002" in codes(report)
    # слишком много находок у томата – норма контракта, а не отказ
    base = row(public_findings=[], update_status="up_to_date", gaps=[], research_coverage=[coverage_row()],
               latest_stable_release={"version": "9.0.83", "released_at": "", "note": "", "source_refs": ["ev-1"]},
               package_advice={"action": "no_action", "target_version": "", "compatibility_notes": "Обновлений нет",
                               "remaining_risks": []}, package_status="no_known_vulnerabilities")
    big = answer({**base, "public_findings": [{"id": f"CVE-2025-{n:04d}", "aliases": [], "applies": "no",
                                               "description": "Не относится к этой версии", "ranges": [],
                                               "conditions": None, "fixed_versions": [], "cvss": None,
                                               "source_refs": ["ev-1"]}
                                              for n in range(sc.LIMITS["findings_per_row"])]}, row(1))
    assert check(big).ok, check(big).errors[:3]


def test_reports_every_bad_field_with_its_path():
    payload = answer(row(public_findings=[{"id": "", "aliases": [], "applies": "yes", "description": "",
                                           "ranges": [], "conditions": "", "fixed_versions": [],
                                           "cvss": {"score": 42.0}, "source_refs": ["ev-9"]}]),
                     row(1, package_status="vulnerable"))
    report = check(payload)
    assert len(report.errors) >= 3
    assert {"rows[0].public_findings[0].id", "rows[0].public_findings[0].source_refs"} <= set(paths(report))
    assert all(error["message"] for error in report.errors)


# ============================================================== соответствие сохранённому заданию

def test_rejects_task_substitution_manifest_and_row_swap():
    report = check(answer(row(), row(1), contract="local-triage/sca-answers/1"))
    assert "SCA-T002" in codes(report)
    report = check(answer(row(), row(1), manifest_sha256="b" * 64))
    assert "SCA-C004" in codes(report) and "manifest_sha256" in paths(report)
    report = check(answer(row(), row(1), task_id="t-20261017-ffff"))
    assert "SCA-T002" in codes(report)
    # та же строка задания, но подставлены чужие координаты или версия
    report = check(answer(row(component="org.apache.ivy:ivy"), row(1)))
    assert "SCA-C002" in codes(report)
    report = check(answer(row(current_version="9.0.84"), row(1)))
    assert "SCA-C002" in codes(report)
    report = check(answer(row(ecosystem="npm"), row(1)))
    assert "SCA-C002" in codes(report)


def test_rejects_unknown_duplicate_and_missing_rows():
    alien = row(input_ref=sc.input_ref("pypi", "demo", "1.0"), ecosystem="pypi", component="demo",
                current_version="1.0")
    report = check(answer(row(), alien))
    assert "SCA-C001" in codes(report)
    report = check(answer(row(), row()))
    assert "SCA-C003" in codes(report) and "rows[1].input_ref" in " ".join(paths(report))
    report = check(answer(row()))
    assert "SCA-C003" in codes(report)
    report = check(answer(row(), row(1), row_count=5))
    assert "SCA-C003" in codes(report) or "SCA-M005" in codes(report)


# ============================================================== факты: доказательства, даты, AST, статусы

def test_rejects_evidence_refs_that_do_not_exist():
    report = check(answer(row(identity_resolution={"state": "resolved", "coordinates": TOMCAT[1],
                                                  "candidates": [], "note": "", "source_refs": ["ev-404"]}),
                         row(1)))
    assert "SCA-E001" in codes(report) and "rows[0].identity_resolution.source_refs" in " ".join(paths(report))
    duplicated = row()
    duplicated["evidence"] = [dict(EVIDENCE[0]), dict(EVIDENCE[0])]
    report = check(answer(duplicated, row(1)))
    assert "SCA-E001" in codes(report)
    # находка без источников – не подтверждённый публичный факт
    report = check(answer(row(public_findings=[{**row()["public_findings"][0], "source_refs": []}]), row(1)))
    assert "SCA-E001" in codes(report)


def test_rejects_future_dates():
    report = check(answer(row(research_coverage=[coverage_row(checked_at="2027-01-05")]), row(1)))
    assert "SCA-D001" in codes(report) and "rows[0].research_coverage[0].checked_at" in " ".join(paths(report))
    report = check(answer(row(), row(1), generated_at="2026-12-01T00:00:00Z"))
    assert "SCA-D001" in codes(report)
    # вчерашний день и сегодняшний – норма
    assert check(answer(row(), row(1))).ok


def test_rejects_internal_ast_numbers_and_unknown_urls():
    report = check(answer(row(public_findings=[{**row()["public_findings"][0],
                                                "aliases": ["AST-2026-000101"]}]), row(1)))
    assert "SCA-A001" in codes(report)
    report = check(answer(row(evidence=[{**EVIDENCE[0], "url": "file:///etc/passwd"}]), row(1)))
    assert "SCA-M005" in codes(report) and "url" in " ".join(paths(report))
    # публичные идентификаторы, оценки и CWE пропускаются
    assert check(answer(row(public_findings=[{**row()["public_findings"][0],
                                              "aliases": ["GHSA-4r9m-6cqx-x5h2"]}]), row(1))).ok


def test_status_is_computed_not_declared():
    forged = row(package_status="no_known_vulnerabilities")
    report = check(answer(forged, row(1)))
    assert "SCA-T001" in codes(report)
    # пустой результат при ошибке источника не становится чистым
    partial = row(public_findings=[], research_coverage=[{"source": "NVD", "checked_at": "2026-10-16",
                                                           "status": "error", "complete": False, "note": "403"}],
                  package_status="no_known_vulnerabilities",
                  package_advice={"action": "no_action", "target_version": "", "compatibility_notes": "",
                                  "remaining_risks": []},
                  update_status="up_to_date",
                  latest_stable_release={"version": "9.0.83", "released_at": "", "note": "",
                                         "source_refs": ["ev-1"]})
    report = check(answer(partial, row(1)))
    assert "SCA-T001" in codes(report) and sc.row_status(partial) == "incomplete"
    # применимая находка важнее ошибки другого источника: уязвимо с неполным охватом
    assert sc.row_status(row()) == "vulnerable"


def test_rejects_obvious_contradictions():
    report = check(answer(row(update_status="up_to_date",
                              latest_stable_release={"version": "11.0.22", "released_at": "", "note": "",
                                                    "source_refs": ["ev-1"]}), row(1)))
    assert "SCA-L001" in codes(report)
    report = check(answer(row(identity_resolution={"state": "unresolved", "coordinates": TOMCAT[1],
                                                  "candidates": [], "note": "", "source_refs": ["ev-1"]}), row(1)))
    assert "SCA-L001" in codes(report)
    report = check(answer(row(package_advice={"action": "update", "target_version": "", "compatibility_notes": "",
                                              "remaining_risks": []}), row(1)))
    assert "SCA-L001" in codes(report) or "SCA-M004" in codes(report)
    # применимая уязвимость и «оставить без действия» без объяснения – противоречие
    report = check(answer(row(package_advice={"action": "keep", "target_version": "",
                                              "compatibility_notes": "", "remaining_risks": []}), row(1)))
    assert "SCA-L001" in codes(report)


def test_advice_without_action_requires_an_explanation():
    justified = row(package_advice={"action": "keep", "target_version": "",
                                   "compatibility_notes": "Патч 9.0.99 ломает Jakarta Servlet 6",
                                   "remaining_risks": ["Уязвимость останется"]})
    assert check(answer(justified, row(1))).ok


# ============================================================== командная проверка из комплекта

def test_cli_exit_codes_report_and_technical_error(tmp_path: Path):
    manifest = {"contract": sc.TASK_CONTRACT, "manifest_sha256": TASK["manifest_sha256"],
                "row_count": TASK["row_count"], "rows": ROWS}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    good = tmp_path / "answer.json"
    good.write_text(json.dumps(answer(row(), row(1)), ensure_ascii=False), encoding="utf-8")
    report_file = tmp_path / "report.json"
    run = subprocess.run([sys.executable, str(ROOT / "app" / "sca_contract.py"), "--manifest",
                          str(tmp_path / "manifest.json"), "--answer", str(good), "--report", str(report_file)],
                         capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 0, run.stderr
    assert json.loads(report_file.read_text(encoding="utf-8"))["ok"] is True

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(answer(row(), row(1), manifest_sha256="c" * 64), ensure_ascii=False),
                   encoding="utf-8")
    run = subprocess.run([sys.executable, str(ROOT / "app" / "sca_contract.py"), "--manifest",
                          str(tmp_path / "manifest.json"), "--answer", str(bad)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 2
    assert "SCA-C004" in run.stdout

    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    run = subprocess.run([sys.executable, str(ROOT / "app" / "sca_contract.py"), "--manifest",
                          str(tmp_path / "manifest.json"), "--answer", str(tmp_path / "broken.json")],
                         capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 2

    run = subprocess.run([sys.executable, str(ROOT / "app" / "sca_contract.py"), "--manifest",
                          str(tmp_path / "manifest.json"), "--answer", str(tmp_path / "absent.json")],
                         capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 3


@pytest.mark.parametrize("payload, message", [("", "пуст"), ("[]", "объект")])
def test_cli_reports_contract_errors_with_exit_code_two(tmp_path: Path, payload: str, message: str):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"manifest_sha256": "a" * 64, "rows": []}), encoding="utf-8")
    answer_file = tmp_path / "answer.json"
    answer_file.write_text(payload, encoding="utf-8")
    run = subprocess.run([sys.executable, str(ROOT / "app" / "sca_contract.py"), "--manifest", str(manifest),
                          "--answer", str(answer_file)], capture_output=True, text=True, encoding="utf-8",
                         timeout=60)
    assert run.returncode == 2
    assert message in (run.stdout + run.stderr).lower()


def test_sha256_and_canonical_json_are_stable():
    assert sc.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert sc.sha256(b"abc") == sc.sha256("abc".encode("utf-8"))
    assert sc.input_ref(*TOMCAT) == sc.input_ref(*TOMCAT)
    assert sc.input_ref(*TOMCAT) != sc.input_ref(*BABEL)
    assert re.fullmatch(r"[a-z][a-z0-9]*:[0-9a-f]{16}", sc.input_ref(*BABEL))
