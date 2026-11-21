"""LTA-003 (третья проверка): экосистема в привязке решения, единое правило для старых ответов, ключи дефектов, миграция."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import defect
from app.db import Database, finding_version, review_signature
from app.models import Finding, ScaAnswer
from test_audit_lta003 import load, sca_finding
from test_sca import post_answers
from test_web import ORIGIN, create_project, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


def answers_for(*items) -> str:
    return json.dumps({"components": list(items)})


def legacy_item(**extra) -> dict:
    return {"component": "audit-example", "version": "1.0.0", "conclusion": "not_applicable",
            "explanation": "Пояснение агента.", **extra}


# ============================================================================ (а) экосистема в привязке решения

def test_signature_and_form_version_include_the_ecosystem():
    npm, pypi = sca_finding("1", "npm", "CVE-2099-0001").to_dict(), sca_finding("1", "pypi", "CVE-2099-0001").to_dict()
    assert review_signature(npm) != review_signature(pypi)
    assert finding_version(npm) != finding_version(pypi)
    synonym = sca_finding("1", "pip", "CVE-2099-0001").to_dict()
    assert review_signature(synonym) == review_signature(sca_finding("1", "pypi", "CVE-2099-0001").to_dict())


def test_changing_type_with_the_same_hub_id_reopens_the_decision(db):
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001")])
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="Обновить.", reviewed=True)
    assert db.get_review(pid, "1")["reviewed"] == 1
    stats = load(db, pid, [sca_finding("1", "pypi", "CVE-2099-0001")])
    assert stats["reopened"] == 1
    review = db.get_review(pid, "1")
    assert review["reviewed"] == 0 and review["decision"] == "disagree", "решение осталось историей"
    from app.routes.sca import decision_state

    row = db.get_finding_by_hub_id(pid, "1")
    state, _ = decision_state(Finding.from_dict(row["data"]), review, None, row)
    assert state == "changed", "решение принято по другому пакету"


def test_an_unchanged_package_keeps_its_decision(db):
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001")])
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="x", reviewed=True)
    stats = load(db, pid, [sca_finding("1", "yarn", "CVE-2099-0001")])
    assert stats["reopened"] == 0 and db.get_review(pid, "1")["reviewed"] == 1, "yarn и npm – один реестр"


def test_identical_answers_in_two_ecosystems_do_not_bind_the_decision_across_them(db):
    """Ответы двух экосистем совпадают по существу (подпись ответа одна), но решение привязано к пакету подписью находки."""
    pid = db.create_project("p")
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("2", "pypi", "CVE-2099-0001")])
    same = dict(component="audit-example", version="1.0.0", conclusion="update", recommended_version="1.1.0",
                explanation="Один и тот же вывод.", vulnerabilities=["CVE-2099-0001"])
    db.save_sca_answers(pid, "агент", [ScaAnswer(ecosystem="npm", **same), ScaAnswer(ecosystem="pypi", **same)])
    a, b = db.sca_answers(pid, "audit-example", "1.0.0", "npm")[0], db.sca_answers(pid, "audit-example", "1.0.0", "pypi")[0]
    from app.routes.sca import answer_signature

    assert answer_signature(a) == answer_signature(b), "подпись ответа – про содержание, экосистема в ней не нужна"
    db.save_review(pid, "1", decision="agree", final_verdict="true_positive", final_comment="x", reviewed=True,
                   answer_sig=answer_signature(a))
    load(db, pid, [sca_finding("1", "pypi", "CVE-2099-0001"),
                                                      sca_finding("2", "pypi", "CVE-2099-0001")])
    assert db.get_review(pid, "1")["reviewed"] == 0


# ============================================================================ миграция 10: подписи и ключи дефектов

def test_current_key_never_equals_a_historical_key():
    key = defect.defect_key_sca
    assert key("lib", "1", "") == 'sca:v3|["","lib","1"]' and key("lib", "1", "npm") == 'sca:v3|["npm","lib","1"]'
    assert key("lib", "1", "") not in ("sca:lib@1", "sca:|lib@1") and key("lib", "1", "npm") != "sca:npm|lib@1"
    assert len({key("lib", "1", e) for e in ("", "npm", "pypi", "maven")}) == 4


# ============================================================================ (б) старый ответ без экосистемы – единое правило

def test_http_upload_considers_missing_packages_as_candidates(web):  # noqa: F811
    pid = create_project(web.client)
    db = web.app.state.db
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001")])
    load(db, pid, [sca_finding("2", "pypi", "CVE-2099-0002")])
    r = post_answers(web, pid, answers_for(legacy_item()), source="старый агент")
    assert r.status_code == 400 and "несколько экосистем" in r.text, "ничего не сохранено, причина названа"
    stored = db.sca_answers(pid)
    assert stored == [], "кандидатов два (npm пропал, pypi текущий): ответ не приписывается ни одному"


def test_a_single_historical_candidate_is_used_by_all_paths(web, tmp_path: Path):  # noqa: F811
    """Остался только пропавший npm-пакет: ответ без экосистемы относится к нему на всех путях."""
    hpid = create_project(web.client)
    hdb = web.app.state.db
    load(hdb, hpid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("9", "maven", "CVE-2099-0009",
                                                                          component="other", version="1")])
    load(hdb, hpid, [sca_finding("9", "maven", "CVE-2099-0009", component="other",
                                                                    version="1")])
    post_answers(web, hpid, answers_for(legacy_item()), source="агент")
    assert [a["ecosystem"] for a in hdb.sca_answers(hpid, "audit-example")] == ["npm"]
    direct = Database(tmp_path / "d.db")
    try:
        pid = direct.create_project("p")
        load(direct, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("9", "maven", "CVE-2099-0009",
                                                                                component="other", version="1")])
        load(direct, pid, [sca_finding("9", "maven", "CVE-2099-0009",
                                                                        component="other", version="1")])
        direct.save_sca_answers(pid, "агент", [ScaAnswer(component="audit-example", version="1.0.0",
                                                         conclusion="update", recommended_version="1.1.0",
                                                         explanation="Ответ.")])
        assert [a["ecosystem"] for a in direct.sca_answers(pid, "audit-example")] == ["npm"]
    finally:
        direct.close()


# ============================================================================ (г) отказ шагов миграции

# ============================================================================ карточки и страница: экосистемы не смешиваются

def test_pages_and_defects_keep_the_ecosystems_apart(web):  # noqa: F811
    pid = create_project(web.client)
    db = web.app.state.db
    load(db, pid, [sca_finding("1", "npm", "CVE-2099-0001"), sca_finding("2", "pypi", "CVE-2099-0002")])
    db.save_sca_answers(pid, "агент", [
        ScaAnswer(component="audit-example", version="1.0.0", ecosystem="npm", conclusion="update",
                  recommended_version="1.1.0", explanation="ТОЛЬКО-NPM", vulnerabilities=["CVE-2099-0001"]),
        ScaAnswer(component="audit-example", version="1.0.0", ecosystem="pypi", conclusion="not_applicable",
                  explanation="ТОЛЬКО-PYPI", vulnerabilities=["CVE-2099-0002"])])
    page = web.client.get(f"/projects/{pid}/sca").text
    assert page.count("audit-example") >= 2 and "npm" in page and "pypi" in page
    cards = {}
    for hub_id, mine, other in (("1", "ТОЛЬКО-NPM", "ТОЛЬКО-PYPI"), ("2", "ТОЛЬКО-PYPI", "ТОЛЬКО-NPM")):
        row = db.get_finding_by_hub_id(pid, hub_id)
        url = f"/projects/{pid}/sca/findings/{row['id']}"
        text = web.client.get(url).text
        assert mine in text and other not in text, hub_id
        cards[hub_id] = url
    # дефекты: решения по каждому пакету дают свои номера и свои тексты
    from test_sca import form_fields

    numbers = {}
    for hub_id, url in cards.items():
        r = web.client.post(f"{url}/review", headers=AS_JSON, data={
            **form_fields(web.client.get(url).text), "decision": "disagree", "final_verdict": "true_positive",
            "comment": f"Решение {hub_id}.", "reviewed": "1", "action": "save"})
        assert r.status_code == 200, r.text
        from test_sca import sca_text_ready
        sca_text_ready(web, url)  # текст набора дефекта (ADR-0091)
        d = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})
        assert d.status_code == 200, d.text
        numbers[hub_id] = d.json()["number"]
        # уязвимости в тексте – только своего пакета: npm – CVE-2099-0001, pypi – CVE-2099-0002
        mine_cve, other_cve = ("CVE-2099-0001", "CVE-2099-0002") if hub_id == "1" else ("CVE-2099-0002",
                                                                                         "CVE-2099-0001")
        assert mine_cve in d.json()["body"]
        assert other_cve not in d.json()["body"], "в дефект входят находки только своего пакета"
    assert numbers["1"] != numbers["2"]
    assert db.defect_number(pid, defect.defect_key_sca("audit-example", "1.0.0", "npm")) == numbers["1"]
    assert db.defect_number(pid, defect.defect_key_sca("audit-example", "1.0.0", "pypi")) == numbers["2"]
    # агент отвечает только про npm: pypi остаётся без нового ответа
    post_answers(web, pid, answers_for(legacy_item(ecosystem="npm", conclusion="update", recommended_version="2.0.0")),
                 source="агент")
    assert db.sca_answers(pid, "audit-example", "1.0.0", "pypi")[0]["explanation"] == "ТОЛЬКО-PYPI"
