"""LTA-002 (третья проверка): ответ после записи решения из одного снимка и транзакционная выдача дефекта SCA."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.models import Finding
from test_audit_lta002 import AS_JSON, Case, answer  # noqa: F401
from test_audit_lta003 import sca_finding  # noqa: F401
from test_sca import form_fields
from test_web import ORIGIN, prepared, web  # noqa: F401


@pytest.fixture
def case(web):  # noqa: F811
    return Case(web)


# ============================================================================ (а) ответ из одного снимка

def test_answer_arriving_between_commit_and_response_is_reflected_consistently(case):
    """Решение по A записано и зафиксировано; до формирования ответа загружается B. Ответ не смешивает состояния:
    «Проверено» снято, редакция и счётчики – после обновления, есть предупреждение и номер текущего ответа."""
    fields = case.fields()
    original = case.db.save_review

    def commit_then_new_answer(*args, **kwargs):
        result = original(*args, **kwargs)  # COMMIT решения по A
        case.put("агент 1", "update", "Ответ B", "99.0.0")  # новый ответ до формирования ответа клиенту
        return result

    with patch.object(case.db, "save_review", side_effect=commit_then_new_answer):
        r = case.agree(fields)
    assert r.status_code == 200, r.text
    body = r.json()
    stored = case.review()
    assert stored["reviewed"] == 0 and stored["revision"] > int(fields["review_revision"])
    assert body["reviewed"] is False and body["revision"] == stored["revision"], "решение – после обновления ответа"
    stats = case.db.review_stats(case.pid)
    assert body["progress"] == {"total": int(stats["sca"]), "reviewed": int(stats["sca_reviewed"])} \
        and body["progress"]["reviewed"] == 0
    latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    # форма остаётся с номером ответа, который видел человек; номер нового ответа сообщается отдельно
    assert body["answer_id"] == fields["answer_id"] and body["answer_id"] != str(latest["id"])
    assert body["answer_moved"] is True and body["current_answer_id"] == str(latest["id"])
    assert body["notice"] and "новый ответ" in body["notice"]
    assert body["defect_ready"] is False


def test_response_without_interference_is_unchanged(case):
    body = case.agree().json()
    assert body["reviewed"] is True and body["notice"] == "" and body["progress"]["reviewed"] == 1
    assert body["answer_id"] == case.fields()["answer_id"]


def test_snapshot_does_not_see_writer_during_its_duration(case):
    """Основание: пока открыт снимок, запись другого потока в него не попадает; запись при этом не ждёт (ADR-0128, п. 6.2)."""
    import threading

    before = case.db._all("SELECT id, data_json FROM findings ORDER BY id")
    with case.db.snapshot():
        first = case.db._all("SELECT * FROM sca_answers ORDER BY id")
        t = threading.Thread(target=case.put, args=("агент 1", "update", "Ответ из потока", "9.9.9"))
        t.start()
        t.join(10)
        assert not t.is_alive(), "запись не ждёт снимок"
        assert case.db._all("SELECT * FROM sca_answers ORDER BY id") == first, "снимок не изменился"
        assert case.db._all("SELECT id, data_json FROM findings ORDER BY id") == before
    assert case.db._all("SELECT * FROM sca_answers ORDER BY id") != first, "после снимка запись видна"


# ============================================================================ (б) выдача дефекта SCA

def decide(case, hub_id: str = "73002"):
    row = case.db.get_finding_by_hub_id(case.pid, hub_id)
    url = f"/projects/{case.pid}/sca/findings/{row['id']}"
    r = case.web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(case.web.client.get(url).text), "decision": "disagree", "final_verdict": "true_positive",
        "comment": "Обновить.", "reviewed": "1", "action": "save"})
    assert r.status_code == 200, r.text
    return url


def issue(case, url: str):
    from test_sca import sca_text_ready
    sca_text_ready(case.web, url)  # текст набора дефекта (ADR-0091)
    return case.web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})


def interleave_number(case, action):
    original = case.db.set_sca_defect_number_checked

    def injected(*args, **kwargs):
        action()
        return original(*args, **kwargs)

    return patch.object(case.db, "set_sca_defect_number_checked", side_effect=injected)


def stored_number(case):
    from app import defect

    return case.db.defect_number(case.pid, defect.defect_key_sca(case.f.component, case.f.version, "maven"))


def test_defect_is_issued_without_interference(case):
    url = decide(case)
    r = issue(case, url)
    assert r.status_code == 200 and r.json()["title"].startswith("ID1 - "), r.text
    assert stored_number(case) == 1


def test_new_answer_between_building_the_text_and_the_number(case):
    url = decide(case)
    with interleave_number(case, lambda: case.put("агент 2", "update", "Ответ B", "99.0.0")):
        r = issue(case, url)
    assert r.status_code == 409 and r.json()["reason"] == "source", r.text
    assert stored_number(case) is None


def test_decision_of_another_member_between_building_the_text_and_the_number(case):
    url = decide(case)

    def change_sibling():
        decide(case, "73001")

    with interleave_number(case, change_sibling):
        r = issue(case, url)
    assert r.status_code == 409 and stored_number(case) is None


def test_finding_replaced_between_building_the_text_and_the_number(case):
    url = decide(case)

    def change(f: Finding):
        if f.hub_id == "73002":
            f.cve = ["CVE-2099-77777"]

    from test_audit_lta001b import reimport

    with interleave_number(case, lambda: reimport(case.web, case.pid, change)):
        r = issue(case, url)
    assert r.status_code == 409 and stored_number(case) is None


def test_group_member_leaves_between_building_the_text_and_the_number(case):
    url = decide(case)
    from test_audit_lta001b import reimport

    with interleave_number(case, lambda: reimport(case.web, case.pid, drop={"73001"})):
        r = issue(case, url)
    assert r.status_code == 409 and stored_number(case) is None


def test_ast_map_between_building_the_text_and_the_number(case):
    url = decide(case)
    with interleave_number(case, lambda: case.db.save_ast_map([("AST-2026-000101", "CVE-2099-55555")], source="x")):
        r = issue(case, url)
    assert r.status_code == 409 and stored_number(case) is None


def test_project_deleted_between_building_the_text_and_the_number(case):
    url = decide(case)
    with interleave_number(case, lambda: case.db.delete_project(case.pid)):
        r = issue(case, url)
    assert r.status_code == 409, "контролируемый отказ, а не ошибка внешнего ключа"


def test_html_form_gets_a_conflict_page(case):
    from test_sca import sca_text_ready
    url = decide(case)
    sca_text_ready(case.web, url)  # текст набора дефекта (ADR-0091)
    with interleave_number(case, lambda: case.put("агент 2", "update", "Ответ B", "99.0.0")):
        r = case.web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "", "confirm": "1"})
    assert r.status_code == 409 and "данные изменились" in r.text
