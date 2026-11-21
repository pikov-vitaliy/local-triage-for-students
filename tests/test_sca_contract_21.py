"""Контракт исследования 2.1 (ADR-0094 Р2): проверка версий Hub и цели, статус исправления, оспоренность и позиции
источников; расширения – только при объявленной схеме 2.1.0; прежние схемы 2.0.x принимаются."""

from __future__ import annotations

from app import sca_contract as sc
from test_sca_research_contract import ROWS, answer, check, codes, coverage_row, paths, row


def hub_check(**fields) -> dict:
    version = "9.0.90"
    base = {"role": "hub", "version": version,
            "coverage": [coverage_row(0, query={"ecosystem": "maven", "coordinates": ROWS[0]["component"],
                                                "version": version})],
            "findings": [{"id": "CVE-2099-20001", "aliases": [], "ranges": [{"introduced": "9.0.85", "fixed": "9.0.99"}],
                          "fixed_versions": ["9.0.99"], "cvss": {"score": 5.9, "vector": None, "version": "3.1"},
                          "source_refs": ["ev-1"]}]}
    return {**base, **fields}


def test_answers_of_schema_20_are_still_accepted():
    for declared in ("sca-contract/2.0.2", "sca-contract/2.0.1"):
        report = check(answer(row(0), row(1), validator_version=declared))
        assert report.ok, report.errors


def test_extensions_need_schema_21():
    with_checks = row(0, version_checks=[hub_check()])
    old = check(answer(with_checks, row(1), validator_version="sca-contract/2.0.2"))
    assert not old.ok and "SCA-T002" in codes(old) and "rows[0]" in paths(old)
    assert check(answer(with_checks, row(1))).ok, "при схеме 2.1.0 – принимается"
    finding = dict(row(1)["public_findings"][0], disputed={"by": "vendor", "note": "Производитель оспаривает",
                                                            "source_refs": ["ev-1"]})
    old = check(answer(row(0), row(1, public_findings=[finding]), validator_version="sca-contract/2.0.1"))
    assert not old.ok and any("disputed" in e["message"] for e in old.errors)


def test_unknown_schema_is_refused_without_partial_import():
    report = check(answer(row(0), row(1), validator_version="sca-contract/9.9.9"))
    assert not report.ok and "SCA-T002" in codes(report) or "SCA-M005" in codes(report)


def test_version_checks_keys_and_query_version():
    twice = check(answer(row(0, version_checks=[hub_check(), hub_check()]), row(1)))
    assert not twice.ok and "SCA-M005" in codes(twice)
    wrong = hub_check(coverage=[coverage_row(0)])  # запрос про текущую версию, а проверяется версия Hub
    report = check(answer(row(0, version_checks=[wrong]), row(1)))
    assert not report.ok and any(p.endswith("coverage[0].query.version") for p in paths(report))
    no_source = hub_check(findings=[dict(hub_check()["findings"][0], source_refs=[])])
    report = check(answer(row(0, version_checks=[no_source]), row(1)))
    assert not report.ok and any(p.endswith("findings[0].source_refs") for p in paths(report))


def test_no_fix_published_needs_a_quoted_dated_advisory():
    base = row(0)["public_findings"][0]
    proven = dict(base, fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["ev-1"]})
    assert check(answer(row(0, public_findings=[proven]), row(1))).ok
    weak = dict(base, fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["ev-2"]})
    report = check(answer(row(0, public_findings=[weak]), row(1)))  # ev-2 – политика, не бюллетень
    assert not report.ok and any("исправления нет" in e["message"] for e in report.errors)


def test_schema_publishes_the_extensions():
    props = sc.ROW_SCHEMA["properties"]
    assert "version_checks" in props and "version_checks" not in sc.ROW_SCHEMA["required"]
    finding = props["public_findings"]["items"]["properties"]
    assert {"fix_status", "disputed", "source_positions"} <= set(finding)
    assert sc.VALIDATOR_VERSION == "sca-contract/2.1.1" and sc.VALIDATOR_VERSION in sc.EXTENSION_VALIDATORS
    assert "sca-contract/2.1.0" in sc.EXTENSION_VALIDATORS, "ответы 2.1.0 с расширениями принимаются"


def test_version_check_coverage_and_ranges_follow_the_main_rules():
    bare = hub_check(coverage=[coverage_row(0, query=None, source_refs=[])])
    report = check(answer(row(0, version_checks=[bare]), row(1)))
    assert not report.ok and any(p.endswith("coverage[0].query") for p in paths(report))
    other = hub_check(coverage=[coverage_row(0, query={"ecosystem": "npm", "coordinates": "other:pkg",
                                                       "version": "9.0.90"})])
    report = check(answer(row(0, version_checks=[other]), row(1)))
    assert not report.ok and any("другой экосистеме" in e["message"] or "другой пакет" in e["message"]
                                 for e in report.errors)
    excluded = hub_check(findings=[dict(hub_check()["findings"][0], ranges=[{"introduced": "9.1.0", "fixed": "9.2.0"}])])
    report = check(answer(row(0, version_checks=[excluded]), row(1)))
    assert not report.ok and any("исключают проверяемую версию" in e["message"] for e in report.errors)


def test_new_claims_need_sources_and_branch_needs_a_prefix():
    base = row(0)["public_findings"][0]
    for extra, needle in (
            ({"disputed": {"by": "vendor", "note": "Оспаривает", "source_refs": []}}, "оспоренность без источника"),
            ({"source_positions": [{"source": "NVD", "affects": "no", "ranges": [], "source_refs": []}]},
             "позиция источника без ссылки"),
            ({"fix_status": {"status": "fixed", "scope": "package", "source_refs": []}}, "об исправлении без источника"),
            ({"fix_status": {"status": "no_fix_published", "scope": "branch", "source_refs": ["ev-1"]}},
             "scope=branch требует ветку")):
        report = check(answer(row(0, public_findings=[dict(base, **extra)]), row(1)))
        assert not report.ok and any(needle in e["message"] for e in report.errors), (needle, report.errors)
    branch = dict(base, fix_status={"status": "no_fix_published", "scope": "branch", "branch": "9.0",
                                    "source_refs": ["ev-1"]})
    assert check(answer(row(0, public_findings=[branch]), row(1))).ok
