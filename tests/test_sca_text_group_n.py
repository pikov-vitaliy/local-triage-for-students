"""Группа Н плана 0.9.8: «Источники» – только страницы для человека (Г7), область набора – уязвимости находок других
наборов, «без дефекта» и исторических участников не возвращаются через исследование (Г10), Объяснение на русском –
по каждой строке (Г12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import sca_text as t
from app.db import Database
from app.feeds import FeedStore
from app.models import Finding
from app.routes import sca as sca_routes
from test_db_stage2 import load, sca
from test_web import web  # noqa: F401


def test_g7_only_pages_for_people():
    assert t.human_url("https://github.com/example/parser/security/advisories/GHSA-xxxx-xxxx-xxxx")
    assert t.human_url("https://nvd.nist.gov/vuln/detail/CVE-2099-0001")
    for url in ("https://api.github.com/advisories?ecosystem=maven&affects=x", "https://repo1.maven.org/maven2/a/b/maven-metadata.xml",
                "https://repo1.maven.org/maven2/a/b/1.0/b-1.0.pom", "https://example.org/api/v1/vulns/X",
                "ftp://example.org/x"):
        assert not t.human_url(url), url
    research = {"evidence": [
        {"evidence_ref": "a", "url": "https://github.com/o/p/security/advisories/GHSA-aaaa-bbbb-cccc",
         "source_type": "advisory", "level": "primary"},
        {"evidence_ref": "b", "url": "https://api.github.com/advisories?affects=x", "source_type": "advisory",
         "level": "primary"},
        {"evidence_ref": "c", "url": "https://repo1.maven.org/maven2/o/p/maven-metadata.xml", "source_type": "registry",
         "level": "primary"},
        {"evidence_ref": "d", "url": "https://github.com/o/p/releases/tag/v2", "source_type": "release_notes",
         "level": "primary"}],
        "package_advice": {"target_version": "2.0", "source_refs": ["b", "c", "d"]}}
    vuln = t.Vuln(ids=["CVE-2099-0001"], research=[{"id": "CVE-2099-0001", "source_refs": ["a"]}])
    # ADR-0135: ссылки совета о целевой версии в «Источники» не идут, только ссылки уязвимостей
    assert t.research_sources([vuln], research, "2.0") == ["https://github.com/o/p/security/advisories/GHSA-aaaa-bbbb-cccc"]
    vuln_with_notes = t.Vuln(ids=["CVE-2099-0001"], research=[{"id": "CVE-2099-0001", "source_refs": ["a", "b", "c", "d"]}])
    assert t.research_sources([vuln_with_notes], research, "2.0") == ["https://github.com/o/p/security/advisories/GHSA-aaaa-bbbb-cccc",
                                                                      "https://github.com/o/p/releases/tag/v2"], "страницы для человека"


def test_g12_every_line_must_be_russian():
    vulns = [t.Vuln(ids=["CVE-2099-0001"]), t.Vuln(ids=["CVE-2099-0002"])]
    text = ("CVE-2099-0001: Очень длинное русское объяснение уязвимости компонента, при каких условиях она срабатывает "
            "и что может сделать нарушитель, с подробностями о затронутых версиях и исправлении.\n"
            "CVE-2099-0002: The driver does not check class instantiation when providing plugin classes.")
    assert t.cyrillic_share(text) >= 1 / 3, "по всему тексту английская строка не видна"
    assert t.non_russian_lines(text, vulns) == ["CVE-2099-0002"]


@pytest.fixture
def two_sets(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    store = FeedStore(tmp_path / "feeds.db")
    pid = db.create_project("Проект")
    load(db, pid, [sca("1", vuln="AST-1"), sca("2", vuln="AST-2"), sca("3", vuln="AST-3")])
    for hub_id in ("1", "2", "3"):
        db.save_review(pid, hub_id, decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                       reviewed=True)
    yield db, store, pid
    store.close()
    db.close()


def others_for(monkeypatch, db, store, pid, hub_id) -> dict:
    seen = {}
    real = t.set_vulns

    def spy(members, others, *args, **kwargs):
        seen["members"], seen["others"] = dict(members), dict(others)
        return real(members, others, *args, **kwargs)

    monkeypatch.setattr(sca_routes.sca_text, "set_vulns", spy)
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, hub_id)["data"])
    sca_routes.sca_defect(db, store, pid, f, db.get_review(pid, hub_id))
    return seen


def test_g10_other_set_no_defect_and_historical_members_stay_out(two_sets, monkeypatch):
    db, store, pid = two_sets
    ref = db.sca_snapshot(pid, "1").input_ref
    db.move_sca_member(pid, ref, "2", 1, "", expect={0: 0, 1: 0})
    sets = db.sca_sets(pid, ref)
    db.move_sca_member(pid, ref, "3", None, "Компонент не используется в сборке.",
                       expect={0: sets[0]["revision"]})
    seen = others_for(monkeypatch, db, store, pid, "1")
    assert set(seen["members"]) == {"1"}
    assert seen["others"].get("2") == ["AST-2"], "находка отдельного набора – «другая» со своими идентификаторами"
    assert seen["others"].get("3") == ["AST-3"], "находка «без дефекта» – тоже"
    # находка 2 пропала из выгрузки, её место в наборе 1 сохраняется – уязвимость остаётся «другой» для набора 0
    load(db, pid, [sca("1", vuln="AST-1"), sca("3", vuln="AST-3")])
    seen = others_for(monkeypatch, db, store, pid, "1")
    assert seen["others"].get("2") == ["AST-2"]


def test_g10_shared_vulnerability_enters_both_sets():
    members = {"1": ["CVE-2099-0001"]}
    others = {"2": ["CVE-2099-0001"]}  # та же уязвимость у находки другого набора
    research = [{"id": "CVE-2099-0001", "applies": "yes", "aliases": []},
                {"id": "CVE-2099-0002", "applies": "yes", "aliases": []}]
    in_default = [v.main for v in t.set_vulns(members, others, {}, research, default_set=True)]
    assert "CVE-2099-0001" in in_default, "членство важнее: своя находка связана с уязвимостью"
    in_other = [v.main for v in t.set_vulns(others, members, {}, research, default_set=False)]
    assert in_other == ["CVE-2099-0001"], "в отдельный набор уязвимости только исследования не входят"


def test_g8_sca_comment_counter_and_hint(web):  # noqa: F811
    from test_sca import sca_card
    from test_web import prepared

    pid = prepared(web)
    _, card = sca_card(web, pid, "73002")
    assert 'data-char-count="sca-comment-count"' in card and 'id="sca-comment-count"' in card
    assert "Hub обрезает длинные комментарии" in card and "У «Обновить» короткого текста нет" in card
