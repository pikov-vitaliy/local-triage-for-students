"""Комментарий SCA при выводе «обновить» (план dev7, раздел 6): цель и состав как у дефекта набора. Данные выдуманы."""

from __future__ import annotations

import html
import re

import pytest

from app import sca, sca_text
from app.db import ScaSnapshot, finding_ecosystem
from app.models import Finding
from app.routes import sca as sca_routes
from test_component_research_ui import FIXED_VERSION, answer_document, build_task, expect_accepted, project_with_components
from test_sca import sca_card
from test_web import web  # noqa: F401

PAYLOAD = {"public_findings": [{"id": "CVE-2099-0001", "applies": "yes"}, {"id": "CVE-2099-0002", "applies": "no"},
                               {"id": "CVE-2099-0003", "applies": "yes"}, {"id": "CVE-2099-0004", "applies": "unknown"}]}


def comment(target="2.0.1", payload=PAYLOAD, excluded=(), decisions=()):
    return sca_text.update_comment("demo-lib", target, payload, {"1": ["CVE-2099-0001"]}, {}, decisions, 1, excluded)


def test_names_target_and_applicable_only():
    assert comment() == "Обновить demo-lib до версии 2.0.1. Применимые уязвимости: CVE-2099-0001, CVE-2099-0003."


def test_excluded_from_set_is_not_named():
    assert comment(excluded=[{"id": "CVE-2099-0003", "ids": ["CVE-2099-0003"], "reason": "другой модуль"}]) == (
        "Обновить demo-lib до версии 2.0.1. Применимые уязвимости: CVE-2099-0001.")


@pytest.mark.parametrize("kwargs", [{"target": ""}, {"payload": None}, {"payload": {"public_findings": [{"id": "CVE-2099-0002", "applies": "no"}]}}])
def test_nothing_to_say_gives_nothing(kwargs):
    assert comment(**kwargs) == ""


def test_mapping_joins_classes_so_applicability_decision_holds():
    """Решение «не про продукт» по объединённому классу действует, только если классы строятся с теми же соответствиями."""
    payload = {"public_findings": [{"id": "CVE-2099-0001", "applies": "yes"}, {"id": "CVE-2099-0003", "applies": "yes"}]}
    decisions = [{"vuln_ids": ["AST-1", "CVE-2099-0001"], "decision": "not_product", "research_revision": 1, "ids": ["AST-1", "CVE-2099-0001"]}]
    mapping = {"AST-1": ["CVE-2099-0001"]}
    rep = sca_text.union_classes(sca_text.class_groups([["AST-1"]], mapping, payload))
    assert rep[sca_text._norm("AST-1")] == rep[sca_text._norm("CVE-2099-0001")], "без соответствия класс распался бы"
    text = sca_text.update_comment("demo-lib", "2.0.1", payload, {"1": ["AST-1"]}, {}, decisions, 1, (), mapping)
    assert "CVE-2099-0001" not in text and "CVE-2099-0003" in text, text


@pytest.mark.parametrize("decision,vendor,excluded", [("agree", False, True), ("disagree", False, False),
                                                      ("disagree", True, True)])
def test_update_comment_uses_agreed_legacy_mapping(decision, vendor, excluded):
    f = Finding(hub_id="101", kind="SCA", component="demo-lib", version="1.0", vuln_ids=["AST-1"])
    row = {"id": 1, "hub_id": f.hub_id, "missing": 0, "data": f.to_dict()}
    state = {"own": row, "package": ("", f.component, f.version), "members": [row],
             "reviews": {f.hub_id: {"decision": decision}}, "answers": [{"ids": {"AST-1": ["CVE-2099-0001"]}}],
             "mapping": [("AST-1", "CVE-2099-0001")] if vendor else [],
             "research": {"revision": 1, "payload": PAYLOAD},
             "texts": {0: {"target_basis": "manual", "target_version": "2.0.1"}},
             "applicability": {"AST-1": {"ids": ["AST-1", "CVE-2099-0001"], "decision": "not_product",
                                         "research_revision": 1}}}
    snap = ScaSnapshot(1, f.hub_id, True, state)
    text = sca_routes._update_comment(snap, 1, f)
    assert ("CVE-2099-0001" not in text) is excluded
    assert "CVE-2099-0003" in text


def test_vulnerabilities_of_other_sets_are_not_named():
    """Находки версии разделены на наборы: второй набор со своей уязвимостью, цель своя – в заготовке только свои."""
    payload = {"public_findings": [{"id": "CVE-2099-0001", "applies": "yes"}, {"id": "CVE-2099-0003", "applies": "yes"}]}
    text = sca_text.update_comment("demo-lib", "2.0.1", payload, {"1": ["CVE-2099-0001"]}, {"2": ["CVE-2099-0003"]}, (), 1, ())
    assert "CVE-2099-0001" in text and "CVE-2099-0003" not in text, text
    second = sca_text.update_comment("demo-lib", "3.0.0", payload, {"2": ["CVE-2099-0003"]}, {"1": ["CVE-2099-0001"]}, (), 1, (), default_set=False)
    assert "CVE-2099-0003" in second and "CVE-2099-0001" not in second, second


def shown(page: str) -> str:
    found = re.search(r'data-update-comment="([^"]*)"', page)
    return html.unescape(found.group(1)) if found else ""


def test_card_offers_comment_with_research_target(web):
    pid = project_with_components(web)
    assert shown(sca_card(web, pid, "73001")[1]) == "", "исследования нет – заготовки нет"
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    text = shown(sca_card(web, pid, "73001")[1])
    assert text.startswith("Обновить example-parser до версии ") and "Применимые уязвимости: " in text, text


# ---------------------------------------------------------------------------- заготовка карточки и версия дефекта (план dev9, часть 2, п. 4 и 6)

def _textarea(page: str) -> str:
    return html.unescape(re.search(r'<textarea name="comment" id="comment"[^>]*>(.*?)</textarea>', page, re.S).group(1))


def _agent_answer(web, pid: int, version: str, links=("https://osv.dev/vulnerability/CVE-2099-0001",)) -> None:
    """Ответ внешнего агента по пакету с выводом «обновить» и своей версией."""
    from app.models import ScaAnswer
    db = web.app.state.db
    row = next(r for r in db.list_findings(pid, kind="SCA")[0] if r["hub_id"] == "73001")
    ids = sca.finding_ids(Finding.from_dict(row["data"]))
    data = row["data"]
    db.save_sca_answers(pid, "агент", [ScaAnswer(component=data["component"], version=data["version"], ecosystem=finding_ecosystem(data),
                                        recommended_version=version, conclusion="update", explanation="Пояснение агента.",
                                        links=list(links), vulnerabilities=ids)])


def test_card_comment_names_defect_target_and_note_tells_agent_differs(web):
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    research_target = FIXED_VERSION
    _agent_answer(web, pid, "99.9.9")
    page = sca_card(web, pid, "73001")[1]
    text = _textarea(page)
    assert f"до {research_target}." in text.split("\n")[0] and "99.9.9" not in text, text
    note = re.search(r'id="target-note"[^>]*>([^<]*)<', page).group(1)
    assert note == f"Совет агента – 99.9.9, исследование – {research_target}: в дефект уйдёт {research_target}"


def test_card_without_research_keeps_agent_version_and_no_note(web):
    pid = project_with_components(web)
    _agent_answer(web, pid, "99.9.9")
    page = sca_card(web, pid, "73001")[1]
    assert "до 99.9.9." in _textarea(page) and 'id="target-note"' not in page


@pytest.mark.parametrize("basis, word", [("research", "исследование"), ("component", "решение по компоненту"), ("manual", "указана оператором")])
def test_target_note_names_real_basis(basis, word):
    target = sca_text.Target("4.1.2", basis)
    assert sca_routes._target_note("3.5.14", target) == f"Совет агента – 3.5.14, {word} – 4.1.2: в дефект уйдёт 4.1.2"


@pytest.mark.parametrize("agent, target", [("", sca_text.Target("4.1.2", "research")), ("4.1.2", sca_text.Target("4.1.2", "research")),
                                           ("3.5.14", sca_text.Target("3.5.14", "legacy")), ("3.5.14", sca_text.Target(basis="no_fix")),
                                           ("3.5.14", sca_text.Target(problem="нет цели"))])
def test_no_target_note(agent, target):
    assert sca_routes._target_note(agent, target) == ""


def test_no_note_when_agent_and_research_agree(web):
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    assert 'id="target-note"' not in sca_card(web, pid, "73001")[1]


@pytest.mark.parametrize("url, target, expected", [
    ("https://osv.dev/vulnerability/CVE-2099-0001", "4.1.2", True),
    ("https://github.com/advisories/GHSA-abcd-efgh-ijkl", "4.1.2", True),
    ("https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "", True),
    ("https://central.sonatype.com/artifact/org.example/lib/4.1.2", "4.1.2", True),
    ("https://central.sonatype.com/artifact/org.example/lib/3.5.14", "4.1.2", False),
    ("https://central.sonatype.com/artifact/org.example/lib/4.1.2-rc1", "4.1.2", False),
    ("https://central.sonatype.com/artifact/org.example/lib/14.1.2", "4.1.2", False),
    ("https://central.sonatype.com/artifact/org.example/lib", "4.1.2", False),
    ("https://repo1.maven.org/maven2/org/example/lib/4.1.2/lib-4.1.2.pom", "4.1.2", True),
    ("https://www.npmjs.com/package/lib/v/4.1.2", "4.1.2", True),
    ("https://www.npmjs.com/package/lib/v/3.5.14", "4.1.2", False),
    ("https://pkg.go.dev/example.org/lib@v4.1.2", "4.1.2", True),
    ("https://pypi.org/project/lib/3.5.14/", "", False),
    ("https://pkg.go.dev/example.org/lib@v2.0.0%2Bincompatible", "2.0.0+incompatible", True),
    ("https://pypi.org/project/lib-4.1.2/3.0.0/", "4.1.2", False),
    ("https://pypi.org/project/4.1.2/3.0.0/", "4.1.2", False),
    ("https://pypi.org/project/4.1.2/", "4.1.2", False),
    ("https://test.pypi.org/project/4.1.2/", "4.1.2", False),
    ("https://test.pypi.org/project/lib/4.1.2/", "4.1.2", True),
    ("https://pypi.org/project/lib/4.1.2/", "4.1.2", True),
    ("https://www.nuget.org/packages/Lib/4.1.2", "4.1.2", True),
    ("https://crates.io/crates/lib/4.1.2", "4.1.2", True),
    ("https://pkg.go.dev/example.org/lib@v4.1.2/sub", "4.1.2", True),
    ("https://pkg.go.dev/example.org/4.1.2", "4.1.2", False),
    ("https://repo1.maven.org/maven2/org/example/4.1.2/3.0.0/lib-3.0.0.pom", "4.1.2", False),
    ("https://repo1.maven.org/maven2/org/example/lib/4.1.2/", "4.1.2", True),
])
def test_comment_link_fits(url, target, expected):
    assert sca.comment_link_fits(url, target) is expected


def test_agent_version_without_agreement_is_named_as_advice():
    target = sca_text.Target(version="4.1.2", basis="legacy")
    assert "сейчас не уйдёт" in sca_routes._target_note("4.1.2", target, "disagree", "")
    assert "сейчас не уйдёт" in sca_routes._target_note("4.1.2", target, "agree", ""), "согласие есть, но ответ охватывает не весь набор"
    assert sca_routes._target_note("4.1.2", target, "agree", "4.1.2") == ""
    assert sca_routes._target_note("4.1.2", target, "", "") == "", "свежая карточка без лишней строки"
    assert sca_routes._target_note("4.1.2", target, "agree", "", "no_defect") == "", "цель не считалась: причину называет блок дефекта"
    assert "сейчас не уйдёт" in sca_routes._target_note("4.1.2", target, "agree", "", "text")


def test_suggested_comment_drops_links_of_other_versions():
    f = Finding(hub_id="1", kind="SCA", component="org.example:lib", version="1.0", cve=["CVE-2099-0001"])
    answer = {"conclusion": "update", "recommended_version": "3.5.14", "explanation": "",
              "links": ["https://central.sonatype.com/artifact/org.example/lib/3.5.14",
                        "https://osv.dev/vulnerability/CVE-2099-0001",
                        "https://central.sonatype.com/artifact/org.example/lib/4.1.2",
                        "https://github.com/advisories/GHSA-abcd-efgh-ijkl"]}
    text = sca.suggested_comment(f, answer, {}, target="4.1.2")
    assert "до 4.1.2." in text and "3.5.14" not in text, text
    assert ("Источники: https://osv.dev/vulnerability/CVE-2099-0001, "
            "https://central.sonatype.com/artifact/org.example/lib/4.1.2") in text, text
    assert "до 3.5.14." in sca.suggested_comment(f, answer, {})
    assert "до " not in sca.suggested_comment(f, answer, {}, target="").split("\n")[0]
