"""LTA-003: экосистема – часть идентичности пакета SCA.

Замечание аудита 15.10.2026 (реестр – docs/state/audit-2026-10-15.md): два пакета audit-example@1.0.0 из npm и PyPI
сливались в одну группу, а ответ агента для npm без списка уязвимостей получал CVE пакета из PyPI.
"""

from __future__ import annotations

import json
from db_support import connect_db
from pathlib import Path

import pytest

from app import db as db_module, defect, sca
from app.db import Database
from app.ecosystem import AMBIGUOUS, canon_ecosystem
from app.models import Finding, ScaAnswer
from app.triage import order_findings
from legacy_support import rewrite_legacy_signatures

OLD_ANSWERS = """
CREATE TABLE sca_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    component TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL DEFAULT '',
    recommended_version TEXT NOT NULL DEFAULT '', conclusion TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '', ids_json TEXT NOT NULL DEFAULT '{}', links_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, vulns_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (project_id, component, version, source))"""


def sca_finding(hub_id: str, ecosystem: str, cve: str, component: str = "audit-example", version: str = "1.0.0"):
    return Finding(hub_id=hub_id, kind="SCA", component=component, version=version, build_type=ecosystem, cve=[cve],
                   cvss=9.0, severity="critical")


def load(db: Database, pid: int, findings: list[Finding]) -> dict:
    return db.save_import(pid, "audit.csv", "csv", [], {}, [], order_findings(findings))


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


@pytest.fixture
def mixed(db: Database):
    """Проект: audit-example@1.0.0 в npm и в PyPI (разные CVE), lonely@2.0 только в maven."""
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("2", "pypi", "CVE-2099-0002"),
                   sca_finding("3", "maven", "CVE-2099-0003", component="org.example:lonely", version="2.0")])
    return pid


def answers_json(*items) -> str:
    return json.dumps({"components": list(items)})


def item(ecosystem: str | None, conclusion: str = "not_applicable", **extra) -> dict:
    row = {"component": "audit-example", "version": "1.0.0", "conclusion": conclusion,
           "explanation": "Пояснение агента.", **extra}
    if ecosystem is not None:
        row["ecosystem"] = ecosystem
    return row


# ============================================================================ нормализация

@pytest.mark.parametrize("raw, expected", [("npm", "npm"), ("NPM", "npm"), (" yarn ", "npm"), ("pnpm", "npm"),
                                           ("pip", "pypi"), ("PyPI", "pypi"), ("poetry", "pypi"),
                                           ("gradle", "maven"), ("sbt", "maven"), ("maven", "maven"),
                                           ("go", "golang"), ("Cargo", "cargo"), ("rubygems", "gem"),
                                           ("debian", "deb"), ("", ""), (None, ""), ("+npm", ""), ("unknown", ""),
                                           ("maven-plugin", "")])
def test_ecosystem_names_follow_package_url_types(raw, expected):
    assert canon_ecosystem(raw) == expected


# ============================================================================ критерий 1: две группы, разные ключи

def test_same_name_and_version_in_two_ecosystems_are_two_groups(db, mixed):
    groups = {(g["ecosystem"], g["component"], g["version"]): g for g in db.sca_components(mixed)}
    assert ("npm", "audit-example", "1.0.0") in groups and ("pypi", "audit-example", "1.0.0") in groups
    assert groups[("npm", "audit-example", "1.0.0")]["cve"] == ["CVE-2099-0001"]
    assert groups[("pypi", "audit-example", "1.0.0")]["cve"] == ["CVE-2099-0002"]
    assert all(len(g["build_types"]) == 1 for g in groups.values())


def test_synonyms_of_one_registry_stay_one_group(db):
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "pip", "CVE-2099-0001"), sca_finding("2", "pypi", "CVE-2099-0002")])
    [group] = db.sca_components(pid)
    assert group["ecosystem"] == "pypi" and group["findings"] == 2


def test_defect_keys_differ_by_ecosystem():
    npm = defect.defect_key_sca("audit-example", "1.0.0", "npm")
    pypi = defect.defect_key_sca("audit-example", "1.0.0", "pypi")
    assert npm != pypi and defect.defect_key_sca("audit-example", "1.0.0") == 'sca:v3|["","audit-example","1.0.0"]'
    assert npm == 'sca:v3|["npm","audit-example","1.0.0"]' and "sca:audit-example@1.0.0" not in (npm, pypi)
    assert sca._COMPONENT_OK.fullmatch("a|b") is None, "в имени пакета нет «|»: новый ключ не совпадёт со старым"


def test_package_for_agents_has_one_row_per_ecosystem(db, mixed):
    rows = sca.package_rows(db.sca_components(mixed))
    pairs = sorted((r["ecosystem"], r["component"]) for r in rows)
    assert pairs == [("maven", "org.example:lonely"), ("npm", "audit-example"), ("pypi", "audit-example")]
    by_eco = {r["ecosystem"]: r for r in rows}
    assert by_eco["npm"]["vulnerabilities"] == ["CVE-2099-0001"]
    assert by_eco["pypi"]["vulnerabilities"] == ["CVE-2099-0002"]


# ============================================================================ критерий 2: ответ для npm не меняет pypi

def test_answer_for_npm_does_not_reach_pypi_and_gets_only_its_own_cve(db, mixed):
    report = sca.parse_answers(answers_json(item("npm")), db.sca_components(mixed))
    [answer] = report.answers
    assert answer.ecosystem == "npm" and answer.vulnerabilities == ["CVE-2099-0001"], "охват – уязвимости только npm"
    assert db.save_sca_answers(mixed, "агент", report.answers)["saved"] == 1
    assert [a["ecosystem"] for a in db.sca_answers(mixed)] == ["npm"]
    assert db.sca_answers(mixed, "audit-example", "1.0.0", "pypi") == []
    latest = db.latest_sca_answers(mixed)
    assert ("npm", "audit-example", "1.0.0") in latest and ("pypi", "audit-example", "1.0.0") not in latest
    views = {(v["ecosystem"]): v for v in sca.component_views(db.sca_components(mixed), latest, {})
             if v["component"] == "audit-example"}
    assert views["npm"]["answer"] and views["pypi"]["answer"] is None


def test_answers_for_both_ecosystems_are_kept_separately(db, mixed):
    report = sca.parse_answers(answers_json(item("npm", "update", recommended_version="1.1.0"),
                                            item("PyPI", "not_applicable")), db.sca_components(mixed))
    assert sorted(a.ecosystem for a in report.answers) == ["npm", "pypi"]
    db.save_sca_answers(mixed, "агент", report.answers)
    latest = db.latest_sca_answers(mixed)
    assert latest[("npm", "audit-example", "1.0.0")]["conclusion"] == "update"
    assert latest[("pypi", "audit-example", "1.0.0")]["conclusion"] == "not_applicable"


def test_answer_for_an_ecosystem_the_package_does_not_have_is_unknown(db, mixed):
    report = sca.parse_answers(answers_json(item("nuget")), db.sca_components(mixed))
    assert report.answers == [] and report.unknown == ["audit-example@1.0.0"] and report.ambiguous == []


def test_new_answer_for_one_ecosystem_reopens_only_its_agreements(db, mixed):
    base = sca.parse_answers(answers_json(item("npm", "update", recommended_version="1.1.0"),
                                          item("pypi", "not_applicable")), db.sca_components(mixed))
    db.save_sca_answers(mixed, "агент", base.answers)
    for hub_id, eco in (("1", "npm"), ("2", "pypi")):
        answer = next(a for a in base.answers if a.ecosystem == eco)
        db.save_review(mixed, hub_id, decision="agree", final_verdict="true_positive", final_comment="x",
                       reviewed=True, answer_sig=answer.signature())
    changed = sca.parse_answers(answers_json(item("npm", "update", recommended_version="2.0.0")),
                                db.sca_components(mixed))
    assert db.save_sca_answers(mixed, "агент", changed.answers)["reopened"] == 1
    assert db.get_review(mixed, "1")["reviewed"] == 0 and db.get_review(mixed, "2")["reviewed"] == 1


# ============================================================================ критерий 3: старые ответы без экосистемы

def test_answer_without_ecosystem_is_accepted_only_when_the_package_is_unique(db, mixed):
    unique = sca.parse_answers(answers_json({"component": "org.example:lonely", "version": "2.0",
                                              "conclusion": "not_applicable", "explanation": "Нет."}),
                               db.sca_components(mixed))
    assert [a.ecosystem for a in unique.answers] == ["maven"]
    ambiguous = sca.parse_answers(answers_json(item(None)), db.sca_components(mixed))
    assert ambiguous.answers == [] and ambiguous.ambiguous == ["audit-example@1.0.0"]
    assert any("несколько экосистем" in w and "npm" in w and "pypi" in w for w in ambiguous.warnings)
    assert ambiguous.unknown == []


def test_stored_answer_without_ecosystem_is_resolved_or_marked_ambiguous(db, mixed):
    """Сохранение напрямую, без экосистемы: однозначный пакет получает свою, неоднозначный – метку и ни к чему не
    применяется."""
    db.save_sca_answers(mixed, "старый агент", [
        ScaAnswer(component="org.example:lonely", version="2.0", conclusion="update", recommended_version="2.1",
                  explanation="Ответ."),
        ScaAnswer(component="audit-example", version="1.0.0", conclusion="update", recommended_version="1.1.0",
                  explanation="Ответ.")])
    ecosystems = {a["component"]: a["ecosystem"] for a in db.sca_answers(mixed)}
    assert ecosystems == {"org.example:lonely": "maven", "audit-example": AMBIGUOUS}
    for eco in ("npm", "pypi"):
        assert db.sca_answers(mixed, "audit-example", "1.0.0", eco) == []


def test_legacy_answer_does_not_attach_to_a_package_that_appears_later(db):
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001")])
    db.save_sca_answers(pid, "агент", [ScaAnswer(component="audit-example", version="1.0.0", conclusion="update",
                                                 recommended_version="1.1.0", explanation="Ответ.")])
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("2", "pypi", "CVE-2099-0002")])
    assert [a["ecosystem"] for a in db.sca_answers(pid, "audit-example", "1.0.0", "npm")] == ["npm"]
    assert db.sca_answers(pid, "audit-example", "1.0.0", "pypi") == []


# ============================================================================ критерий 4: миграция

def downgrade_to_v8(path: Path, answers: list[tuple], seq: int | None = None) -> None:
    """База схемы 8: прежняя таблица ответов без экосистемы; answers – (проект, имя, версия, источник, вывод)."""
    con = connect_db(path)
    with con:
        con.execute("DROP TABLE sca_answers")
        con.execute(OLD_ANSWERS)
        for pid, component, version, source, conclusion in answers:
            con.execute("INSERT INTO sca_answers(project_id, component, version, source, conclusion, explanation,"
                        " created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'x', '2026-10-15', '2026-10-15')",
                        (pid, component, version, source, conclusion))
        if seq:
            con.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'sca_answers'", (seq,))
        con.execute("UPDATE meta SET value = '8' WHERE key = 'schema_version'")
        con.execute("DELETE FROM meta WHERE key = 'journal_installation'")  # В схеме 8 журнала ещё не было.
        con.execute("DELETE FROM schema_version WHERE version >= 9")
    con.close()
    rewrite_legacy_signatures(path)  # настоящие подписи прежних версий: без экосистемы


def test_migration_is_noop_on_a_new_base_and_repeats_safely(tmp_path: Path):
    path = tmp_path / "triage.db"
    Database(path).close()
    Database(path).close()
    db = Database(path)
    try:
        assert [r["version"] for r in db.schema_log()][-1] == db_module.SCHEMA_VERSION
    finally:
        db.close()


# ============================================================================ карточка и дефект по экосистеме

def test_defect_and_answers_do_not_cross_ecosystems_in_the_cards(db, mixed):
    from app.routes import sca as routes

    f_npm = Finding.from_dict(db.get_finding_by_hub_id(mixed, "1")["data"])
    f_pypi = Finding.from_dict(db.get_finding_by_hub_id(mixed, "2")["data"])
    db.save_sca_answers(mixed, "агент", [ScaAnswer(component="audit-example", version="1.0.0", ecosystem="npm",
                                                   conclusion="update", recommended_version="1.1.0",
                                                   explanation="Только npm.", vulnerabilities=["CVE-2099-0001"])])
    assert routes._latest_answer(db, mixed, f_npm)["conclusion"] == "update"
    assert routes._latest_answer(db, mixed, f_pypi) is None
