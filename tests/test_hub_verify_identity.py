"""Сверка «результата неизвестен» (ADR-0115): ответ Hub о статусе другой находки отметку не ставит, чтения круга
различаются номером и типом находки (план 09.11, этап 3). Данные выдуманы."""

from __future__ import annotations

import pytest

from app import hub_status as hs
from test_hub_status_routes import (REASON, decide, fixed_today, project, run_worker, sast, send,  # noqa: F401
                                    verify)
from test_web import web  # noqa: F401

OK = {"status": "False Positive", "reason": "Имя таблицы задано", "expiredAt": "2027-01-01T00:00:00Z"}


def test_answer_about_another_issue_does_not_match():
    target = {"issue_id": "101", "issue_type": "SAST"}
    assert hs.status_matches({**OK, "issueId": 101, "issueType": "SAST"}, "False Positive", "Имя таблицы задано",
                             "2027-01-01T00:00:00Z", target)
    assert not hs.status_matches({**OK, "issueId": 102, "issueType": "SAST"}, "False Positive", "Имя таблицы задано",
                                 "2027-01-01T00:00:00Z", target)
    assert not hs.status_matches({**OK, "issueId": 101, "issueType": "SCA_S"}, "False Positive", "Имя таблицы задано",
                                 "2027-01-01T00:00:00Z", target)
    # ответ без номера или типа, с null или номером-строкой находку не подтверждает (бэклог 118)
    for answer in (OK, {**OK, "issueId": 101}, {**OK, "issueType": "SAST"},
                   {**OK, "issueId": None, "issueType": "SAST"}, {**OK, "issueId": 101, "issueType": None},
                   {**OK, "issueId": "101", "issueType": "SAST"}, {**OK, "issueId": True, "issueType": "SAST"}):
        assert not hs.status_matches(answer, "False Positive", "Имя таблицы задано", "2027-01-01T00:00:00Z", target), answer
    # без цели чтения сверяются только статус, комментарий и срок – как раньше
    assert hs.status_matches(OK, "False Positive", "Имя таблицы задано", "2027-01-01T00:00:00Z")
    # в ручной записи SCA Hub пишет имя листа выгрузки
    assert hs.status_matches({**OK, "issueId": 7, "issueType": "SCA Security"}, "False Positive",
                             "Имя таблицы задано", "2027-01-01T00:00:00Z", {"issue_id": "7", "issue_type": "SCA_S"})


def test_reads_of_a_round_are_told_apart_by_type_and_number():
    """Чтения круга – по типу и номеру: SAST 101 и SCA_S 101 – разные находки (ревью Codex круга 1)."""
    from app import hub_effects
    assert hub_effects._issue_key({"issue_type": "SAST", "issue_id": "101"}) != hub_effects._issue_key(
        {"issue_type": "SCA_S", "issue_id": "101"})
    assert hub_effects._issue_key({"issue_type": "SAST", "issue_id": 101}) == ("SAST", "101")


def test_verify_with_answer_about_another_issue_stays_unknown(web):  # noqa: F811
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=0, error="timeout")
    verify(web, pid, answer["op_id"])
    run_worker(web, body={"issueId": 999, "issueType": "SAST", "status": "False Positive", "reason": REASON,
                          "expiredAt": "2027-01-26T00:00:00Z"})
    op = web.app.state.db.hub_op(answer["op_id"])
    assert op["state"] == "unknown" and "сверка" in op["error"]
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 0


def test_verify_with_answer_about_the_same_issue_marks_entered(web):  # noqa: F811
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=0, error="timeout")
    verify(web, pid, answer["op_id"])
    run_worker(web, body={"issueId": 101, "issueType": "SAST", "status": "False Positive", "reason": REASON,
                          "expiredAt": "2027-01-26T00:00:00Z"})
    assert web.app.state.db.hub_op(answer["op_id"])["state"] == "done"
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1


@pytest.mark.parametrize("extra", [{}, {"issueId": 101}, {"issueType": "SAST"}, {"issueId": None, "issueType": "SAST"},
                                   {"issueId": 101, "issueType": None}, {"issueId": "101", "issueType": "SAST"}])
def test_verify_with_answer_without_identity_stays_unknown(web, extra):  # noqa: F811
    """Бэклог 118: ответ сверки без номера или типа находки (нет поля, null, номер строкой) исход не подтверждает –
    операция остаётся «результат неизвестен», отметки «Внесено в Hub» нет."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=0, error="timeout")
    verify(web, pid, answer["op_id"])
    run_worker(web, identify=False, body={"status": "False Positive", "reason": REASON,
                                          "expiredAt": "2027-01-26T00:00:00Z", **extra})
    op = web.app.state.db.hub_op(answer["op_id"])
    assert op["state"] == "unknown" and "сверка" in op["error"]
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 0


def test_verify_sca_answer_with_the_manual_record_type_name_marks_entered(web):  # noqa: F811
    """Имя типа ручной записи SCA («SCA Security») подтверждает находку SCA_S, как и раньше."""
    from test_hub_status_routes import sca
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree")
    answer = send(web, pid, "201", kind="sca/findings").json()
    sent = run_worker(web, status=0, error="timeout")["body"]  # что ушло в Hub: статус, комментарий SCA, срок
    verify(web, pid, answer["op_id"])
    job = run_worker(web, identify=False, body={"issueId": 201, "issueType": "SCA Security", "status": sent["status"],
                                                "reason": sent["reason"], "expiredAt": sent["expiredAt"]})
    assert job["path"].startswith("/issue/status?issueId=201")
    assert web.app.state.db.hub_op(answer["op_id"])["state"] == "done"
    assert web.app.state.db.get_review(pid, "201")["entered_hub"] == 1
