"""Диапазон «от начала без верхней границы» (BUG-02 ревью 24.10, валидатор 2.1.1): introduced="0" без fixed
и last_affected затрагивает все версии – ответ с applies=yes принимается, остаточный риск цели не исчезает; пустой
и несравнимый интервал по-прежнему остаются неизвестностью. Пакеты и идентификаторы выдуманы."""

from __future__ import annotations

from app import sca_contract as sc
from app import sca_text as t
from test_sca_research_contract import answer, check, codes, row
from test_sca_residual import FIXED, finding, research

OPEN = [{"introduced": "0", "fixed": None, "last_affected": None}]
NO_FIX = {"status": "no_fix_published", "scope": "package", "source_refs": ["ev-1"]}


def open_row(applies: str = "yes") -> dict:
    base = row(0)
    first = {**base["public_findings"][0], "ranges": OPEN, "fixed_versions": [], "applies": applies,
             "fix_status": NO_FIX}
    return row(0, public_findings=[first])


def test_range_contains_open_interval():
    assert sc.range_contains("maven", "9.0.85", {"introduced": "0"}) is True
    assert sc.range_contains("maven", "9.0.85", OPEN[0]) is True
    assert sc.range_contains("maven", "9.0.85", {"introduced": "0", "fixed": "9.0.80"}) is False
    assert sc.range_contains("maven", "9.0.85", {}) is None, "интервал без границ – неизвестность"
    assert sc.range_contains("maven", "9.0.85", {"introduced": "vendor-x"}) is None, "несравнимая версия"


def test_open_range_with_applies_yes_is_accepted():
    report = check(answer(open_row(), row(1)))
    assert report.ok, report.errors


def test_open_range_contradicts_applies_no():
    report = check(answer(open_row("no"), row(1)))
    assert not report.ok and "SCA-A001" in codes(report)


def test_validator_211_keeps_accepting_210_answers_with_extensions():
    assert sc.VALIDATOR_VERSION == "sca-contract/2.1.1"
    assert "sca-contract/2.1.0" in sc.ACCEPTED_VALIDATORS and "sca-contract/2.1.0" in sc.EXTENSION_VALIDATORS
    report = check(answer(open_row(), row(1), validator_version="sca-contract/2.1.0"))
    assert report.ok, report.errors


def test_open_range_keeps_residual_risk_of_the_target():
    open_vuln = finding("GHSA-oooo-pppp-qqqq", [{"introduced": "0"}],
                        fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]})
    check_ = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, open_vuln), "2026-10-22")
    assert check_.state == "verified", check_
    assert [r["id"] for r in check_.residual] == ["GHSA-oooo-pppp-qqqq"]
