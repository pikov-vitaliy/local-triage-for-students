"""Проверка цели с остаточной уязвимостью (ADR-0094 Р1): статус исправления по классу уязвимости, запрет цели не
новее текущей, находки проверки цели, отрицательные случаи. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

import copy

from app import sca_text as t

EVIDENCE = [
    {"evidence_ref": "adv", "url": "https://github.com/example/driver/security/advisories/GHSA-nnnn-oooo-ffff",
     "source_type": "advisory", "level": "primary", "quote": "No patched versions", "checked_at": "2026-10-20"},
    {"evidence_ref": "reg", "url": "https://repo.example/driver/1.5.0", "source_type": "registry", "level": "primary"},
]


def finding(vuln_id, ranges, fixed_versions=(), aliases=(), **extra):
    return {"id": vuln_id, "aliases": list(aliases), "applies": "yes", "description": "Описание.", "conditions": None,
            "ranges": ranges, "fixed_versions": list(fixed_versions), "source_refs": ["adv"], **extra}


def research(*findings, latest="1.5.0", target="1.5.0", complete=True, checks=()):
    return {"public_findings": list(findings), "evidence": copy.deepcopy(EVIDENCE),
            "package_advice": {"action": "update", "target_version": target, "source_refs": ["reg"]},
            "latest_stable_release": {"version": latest, "source_refs": ["reg"]},
            "research_coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": complete}],
            "version_checks": list(checks)}


FIXED = finding("CVE-2099-1001", [{"introduced": "1.0.0", "fixed": "1.2.5"}], ["1.2.5"])
NOFIX = finding("GHSA-nnnn-oooo-ffff", [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}])


def test_residual_without_fix_does_not_block_the_target():
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, NOFIX), "2026-10-22")
    assert check.state == "verified", check
    assert [r["id"] for r in check.residual] == ["GHSA-nnnn-oooo-ffff"]
    assert check.residual[0]["status"] == "fix_not_found", "ответ без fix_status – «не установлено в охвате»"


def test_no_fix_published_with_proof():
    proven = finding("GHSA-nnnn-oooo-ffff", [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                     fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]})
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, proven), "2026-10-22")
    assert check.state == "verified" and check.residual[0]["status"] == "no_fix_published"
    assert check.residual[0]["scope"] == "package" and check.residual[0]["date"] == "2026-10-20"


def test_fixable_above_target_blocks():
    later = finding("CVE-2099-1002", [{"introduced": "1.4.0", "fixed": "1.6.0"}], ["1.6.0"])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, NOFIX, later), "2026-10-22")
    assert check.state == "affected" and check.affected == ["CVE-2099-1002"]


def test_fix_unknown_blocks():
    unknown = finding("CVE-2099-1003", [{"introduced": "1.4.0", "fixed": None, "last_affected": "1.5.0"}])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, unknown, latest="1.6.0"), "2026-10-22")
    assert check.state == "affected", "наибольшая стабильная вне диапазона – исправление неизвестно"


def test_conflicting_records_of_one_class_block():
    cve = finding("CVE-2099-1004", [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                  fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]})
    ghsa = finding("GHSA-cccc-dddd-eeee", [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0"],
                   aliases=["CVE-2099-1004"])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, cve, ghsa, latest="1.6.0"), "2026-10-22")
    assert check.state == "affected", "исправление в 1.6.0 перекрывает «исправления нет» той же уязвимости"


def test_target_not_newer_is_forbidden():
    for target in ("1.2.0", "1.1.0"):
        check = t.check_version("maven", "1.2.0", target, research(FIXED), "2026-10-22")
        assert check.state == "not_newer", target


def test_finding_only_in_target_check_blocks():
    target_check = {"role": "target", "version": "1.5.0", "coverage": [],
                    "findings": [{"id": "CVE-2099-1005", "aliases": [], "ranges": [{"introduced": "1.5.0", "fixed": "1.5.1"}],
                                  "fixed_versions": ["1.5.1"], "source_refs": ["adv"]}]}
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, checks=[target_check], latest="1.5.1"),
                            "2026-10-22")
    assert check.state == "affected" and check.affected == ["CVE-2099-1005"]


def test_residual_kept_when_target_unverified():
    incomplete = research(FIXED, NOFIX, complete=False)
    unpublished = research(FIXED, NOFIX)  # версия известна, но публикация цели ничем не подтверждена
    unpublished["latest_stable_release"]["source_refs"] = []
    unpublished["package_advice"]["source_refs"] = []
    for name, data in (("неполный охват", incomplete), ("публикация не подтверждена", unpublished)):
        check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
        assert check.state == "unverified", name
        assert [r["id"] for r in check.residual] == ["GHSA-nnnn-oooo-ffff"], "остаточная видна и при «не проверена»"


def test_unknown_range_of_another_vulnerability_keeps_unverified():
    odd = finding("CVE-2099-1006", [{"introduced": "1.0.0-vendor", "fixed": "1.2.9-vendor"}])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, NOFIX, odd), "2026-10-22")
    assert check.state in ("unverified", "affected") and check.state != "verified"


# ============================================================================ Р1 в сборке дефекта

import pytest  # noqa: E402
from pathlib import Path  # noqa: E402

from app.db import Database, ScaSnapshot  # noqa: E402
from app.feeds import FeedStore  # noqa: E402
from app.models import Finding  # noqa: E402
from app.routes import sca as sca_routes  # noqa: E402
from test_db_stage2 import load, sca  # noqa: E402


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "triage.db")
    store = FeedStore(tmp_path / "feeds.db")
    pid = db.create_project("Проект")
    load(db, pid, [sca("1", version="1.2.0", vuln="CVE-2099-1001", fixed="1.2.5")])
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    payload = research(FIXED, finding("GHSA-nnnn-oooo-ffff", [{"introduced": "0", "fixed": None,
                                                                "last_affected": "1.5.0"}],
                                      cvss={"score": 3.1, "vector": None, "version": "3.1"}))
    monkeypatch.setattr(ScaSnapshot, "research", property(
        lambda self: {"payload": payload, "observed_at": "2026-10-22", "revision": 1}))
    yield db, store, pid
    store.close()
    db.close()


def defect(db, store, pid, record):
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "1")["data"])
    return sca_routes.sca_defect(db, store, pid, f, db.get_review(pid, "1"), override=record)


EXPLANATION = ("CVE-2099-1001: Уязвимость разбора позволяет выполнить код при подстановке параметров.\n"
               "GHSA-nnnn-oooo-ffff: Разбор файла сертификата без ограничения размера ведёт к отказу в обслуживании.")


def test_residual_needs_the_operator_mark_and_is_named_in_recommendations(env):
    db, store, pid = env
    record = {"target_basis": "manual", "target_version": "1.5.0", "explanation": EXPLANATION,
              "recommendation_note": "Перед обновлением проверить совместимость с Java 17."}
    first = defect(db, store, pid, record)
    assert first["state"] == "text" and "Остаточный риск проверил" in first["hint"], first["hint"]
    assert [r["id"] for r in first["residual"]] == ["GHSA-nnnn-oooo-ffff"]
    done = defect(db, store, pid, {**record, "residual_checked_sig": first["residual_confirm_sig"]})
    assert done["ready"], done["hint"]
    recommendations = done["body"].split("Рекомендации\n", 1)[1].split("\n\nИсточники", 1)[0].split("\n")
    assert recommendations == [
        "Исправление не установлено в исследованном охвате на 2026-10-22: GHSA-nnnn-oooo-ffff (низкая) – "
        "обновление до 1.5.0 её не закрывает.",
        "Перед обновлением проверить совместимость с Java 17.",
        "Обновление org.example:example-parser до версии 1.5.0"]
    # смена тела (другое добавление) снимает отметку остаточного риска
    other = defect(db, store, pid, {**record, "recommendation_note": "Иное условие.",
                                    "residual_checked_sig": first["residual_confirm_sig"]})
    assert not other["ready"] and "Остаточный риск проверил" in other["hint"]


def test_target_not_newer_cannot_be_confirmed(env):
    db, store, pid = env
    record = {"target_basis": "manual", "target_version": "1.1.0", "explanation": EXPLANATION}
    first = defect(db, store, pid, record)
    assert not first["ready"] and "не новее текущей" in first["hint"]
    second = defect(db, store, pid, {**record, "version_checked_sig": first.get("version_confirm_sig", "")})
    assert not second["ready"] and "не новее текущей" in second["hint"]


# ============================================================================ Р2.7: пояснение о версии Hub

def checks(target_findings=(), complete=True, hub_findings=None):
    cov = [{"purpose": "vulnerabilities", "status": "ok", "complete": complete}]
    medium = finding("CVE-2099-2001", [{"introduced": "1.4.0", "fixed": "1.5.0"}], ["1.5.0"],
                     cvss={"score": 5.9, "vector": None, "version": "3.1"})
    return [{"role": "target", "version": "1.5.0", "coverage": cov, "findings": list(target_findings)},
            {"role": "hub", "version": "1.4.2", "coverage": cov,
             "findings": [medium] if hub_findings is None else list(hub_findings)}]


def test_hub_note_names_only_what_is_proven_not_to_affect_the_target():
    data = research(FIXED, checks=checks())
    assert t.hub_note("maven", ["1.4.2", "1.4.2"], "1.5.0", data) == (
        "Версия 1.4.2, указанная в Hub, затронута CVE-2099-2001 (средняя); по исследованным диапазонам версия 1.5.0 "
        "не затронута.")
    assert t.hub_note("maven", ["1.4.2"], "1.5.0", research(FIXED, checks=checks(complete=False))) == "", \
        "охват цели неполный – не доказано"
    hits_target = finding("CVE-2099-2001", [{"introduced": "1.5.0", "fixed": "1.5.1"}])
    assert t.hub_note("maven", ["1.4.2"], "1.5.0", research(FIXED, checks=checks([hits_target]))) == "", \
        "запись класса в проверке цели затрагивает цель – строки нет"
    assert t.hub_note("maven", ["1.4.2"], "1.5.0", research(FIXED)) == "", "ответ 2.0 без проверки версий"
    assert t.hub_note("maven", ["1.4.9"], "1.5.0", data) == "", "проверки точно этой версии Hub нет"
