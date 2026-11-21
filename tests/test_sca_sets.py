"""Наборы дефекта SCA и текст набора (ADR-0091): пакетное решение одной транзакцией, перенос между наборами с
проверкой редакций, «без дефекта» с обоснованием, выход из набора при смене исхода, текст набора с редакцией."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db import Database, StaleReview
from app.models import Finding
from app.triage import order_findings

REF = "ref-kit-1.2.0"


def sca(hub_id: str) -> Finding:
    return Finding(hub_id=hub_id, kind="SCA", component="example-json-kit", version="1.2.0", build_type="maven",
                   cve=["CVE-2099-10001"], cvss=7.5, severity="critical")


@pytest.fixture()
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    pid = database.create_project("p")
    database.save_import(pid, "x.csv", "csv", [], {}, [], order_findings([sca("1"), sca("2"), sca("3")]))
    yield database, pid
    database.close()


def item(hub_id: str, verdict: str = "true_positive", comment: str = "обновить") -> dict:
    return {"hub_id": hub_id, "decision": "disagree", "final_verdict": verdict, "final_comment": comment,
            "reviewed": True}


def test_batch_saves_all_or_nothing(db):
    database, pid = db
    saved = database.save_reviews(pid, [item("1"), item("2")])
    assert [r["hub_id"] for r in saved] == ["1", "2"]
    assert database.get_review(pid, "1")["final_verdict"] == "true_positive"

    def refuse(_c):
        raise StaleReview("снимок пакета изменился", "snapshot")

    with pytest.raises(StaleReview):
        database.save_reviews(pid, [item("1", "false_positive", "не затронут"), item("3")], check=refuse)
    assert database.get_review(pid, "1")["final_verdict"] == "true_positive", "откат целиком"
    assert database.get_review(pid, "3") is None
    version = database.review_version(pid, "2")
    with pytest.raises(StaleReview) as stale:  # отказ по одной находке (устаревшая редакция) откатывает всё
        database.save_reviews(pid, [item("3"), {**item("2"), "expect": {"version": version, "verdict_id": None,
                                                                         "revision": 99}}])
    assert stale.value.reason == "revision"
    assert database.get_review(pid, "3") is None


def test_move_between_sets_checks_revisions_and_reason(db):
    database, pid = db
    sets = database.sca_sets(pid, REF)
    assert sets == {0: {"revision": 0, "excluded": []}}
    sets = database.move_sca_member(pid, REF, "2", 1, "", expect={0: 0, 1: 0})
    assert sets[0]["revision"] == 1 and sets[1]["revision"] == 1
    assert database.sca_members(pid, REF) == {"2": {"set_no": 1, "no_defect_reason": ""}}
    with pytest.raises(StaleReview):
        database.move_sca_member(pid, REF, "2", 0, "", expect={1: 0})
    with pytest.raises(ValueError):
        database.move_sca_member(pid, REF, "3", None, "  ", expect={})
    with pytest.raises(StaleReview):  # редакции обоих затронутых наборов обязательны
        database.move_sca_member(pid, REF, "3", None, "компонент не используется в сборке", expect={})
    database.move_sca_member(pid, REF, "3", None, "компонент не используется в сборке", expect={0: 1})
    assert database.sca_members(pid, REF)["3"] == {"set_no": None, "no_defect_reason": "компонент не используется "
                                                                                      "в сборке"}
    database.move_sca_member(pid, REF, "2", 0, "", expect={1: 1, 0: 2})
    assert "2" not in database.sca_members(pid, REF), "возврат в набор по умолчанию"


def test_leaving_on_outcome_change(db):
    database, pid = db
    database.move_sca_member(pid, REF, "2", 1, "", expect={0: 0, 1: 0})
    with pytest.raises(StaleReview):  # запись другой версии компонента не трогается
        database.move_sca_member(pid, "ref-other", "2", 0, "", expect={0: 0, 1: 1})
    with database._tx() as c:
        database.sca_leave_sets(c, pid, REF, ["2"], "2026-10-23T00:00:00+00:00")
    assert database.sca_members(pid, REF) == {}
    assert database.sca_sets(pid, REF)[1]["revision"] == 2


def test_package_text_revision(db):
    database, pid = db
    assert database.sca_package_text(pid, REF, 0) is None
    first = database.save_sca_package_text(pid, REF, 0, expect_revision=0, explanation="CVE-2099-10001: текст",
                                           ast={"AST-1": "show"}, target_version="1.2.7", target_basis="research",
                                           version_checked_sig="", text_checked_sig="", text_sig="s1")
    assert first["revision"] == 1 and first["ast"] == {"AST-1": "show"}
    with pytest.raises(StaleReview):
        database.save_sca_package_text(pid, REF, 0, expect_revision=0, explanation="другое", ast={},
                                       target_version="", target_basis="", version_checked_sig="",
                                       text_checked_sig="", text_sig="")
    assert database.sca_package_text(pid, REF, 0)["explanation"] == "CVE-2099-10001: текст"


from test_web import web  # noqa: E402,F401


def test_no_defect_mark_counts_only_for_the_current_component_version(web):  # noqa: F811
    """Ревью круг 7 (номера наборов): пометка «без дефекта» прежней версии после новой выгрузки не действует – находка
    текущей версии из снятия номера не исключается; пометка текущей версии – исключает (ключ набора по умолчанию)."""
    from app.db import finding_ecosystem, loads, now_iso
    from app.defect_drafts import in_some_set
    from app.sca_contract import input_ref
    from test_hub_status_routes import project as status_project, sca

    pid = status_project(web, [sca("50001")])
    db = web.app.state.db
    data = loads(db._one("SELECT data_json FROM findings WHERE project_id=? AND hub_id='50001'", (pid,))["data_json"], {})
    eco = finding_ecosystem(data)
    old = input_ref(eco, data["component"], "1.0.0")
    current = input_ref(eco, data["component"], data["version"])
    with db._tx() as c:
        c.execute("INSERT INTO sca_set_members(project_id,hub_id,input_ref,set_no,updated_at) VALUES (?,?,?,NULL,?)",
                  (pid, "50001", old, now_iso()))
        assert in_some_set(c, pid, ["50001"]) == ["50001"], "пометка прежней версии не действует"
        c.execute("UPDATE sca_set_members SET input_ref=? WHERE project_id=? AND hub_id='50001'", (current, pid))
        assert in_some_set(c, pid, ["50001"]) == [], "пометка текущей версии исключает находку из снятия"
        assert in_some_set(c, pid, ["510001", "нет такой"]) == ["510001", "нет такой"], "не SCA – как раньше"
