"""Статус находки в Hub из приложения (этап 2, app/hub_status.py): тип находки Hub, машинное значение статуса,
срок действия, сборка запроса для одной находки и группы, сверка ответа GET /issue/status. Без сети."""

from __future__ import annotations

from datetime import date

import pytest

from app import hub_status as hs

TODAY = date(2026, 10, 28)


@pytest.mark.parametrize("kind,expected", [("SAST", "SAST"), ("SCA", "SCA_S"), ("SCA-license", "SCA_L"),
                                           ("DAST", "DAST")])
def test_issue_type(kind, expected):
    assert hs.issue_type(kind) == expected


def test_issue_type_unknown():
    with pytest.raises(hs.StatusRefused):
        hs.issue_type("OTHER")


@pytest.mark.parametrize("raw", ["", "abc", "0", "-1", "1.5", "١٢", "1" * 13])
def test_issue_id_refused(raw):
    with pytest.raises(hs.StatusRefused):
        hs.issue_id(raw)


def test_issue_id():
    assert hs.issue_id(" 1000001 ") == 1000001


def test_api_status():
    assert hs.api_status("false_positive") == "False Positive"
    assert hs.api_status("risk_accepted") == "Accepted risk"
    with pytest.raises(hs.StatusRefused):
        hs.api_status("true_positive")


@pytest.mark.parametrize("raw,expected", [("2026-11-27", "2026-11-27T00:00:00Z"), (" 2027-04-26 ", "2027-04-26T00:00:00Z")])
def test_expired_at(raw, expected):
    assert hs.expired_at(raw, TODAY) == expected


@pytest.mark.parametrize("raw,needle", [("", "Укажите срок"), ("27.11.2026", "ГГГГ-ММ-ДД"), ("2026-02-30", "такой даты"),
                                        ("2026-10-28", "позже сегодняшней"), ("2026-10-01", "позже"),
                                        ("2032-01-01", "пяти лет")])
def test_expired_at_refused(raw, needle):
    with pytest.raises(hs.StatusRefused, match=needle):
        hs.expired_at(raw, TODAY)


def test_reason():
    # отступ первой строки – как написан, хвостовые пробелы и пустые строки по краям не уходят (ADR-0149 п. 5)
    assert hs.clean_reason("\n  текст  \n") == "  текст"
    with pytest.raises(hs.StatusRefused, match="Комментария"):
        hs.clean_reason(" ")
    with pytest.raises(hs.StatusRefused, match="длиннее"):
        hs.clean_reason("я" * (hs.REASON_MAX + 1))


def test_status_request_single_and_group():
    one = hs.status_request([{"issue_id": 12, "issue_type": "SAST"}], "False Positive", "текст", "2027-01-01T00:00:00Z")
    assert one == {"method": "POST", "path": "/issue/status/update",
                   "body": {"issueId": 12, "issueType": "SAST", "status": "False Positive", "reason": "текст",
                            "expiredAt": "2027-01-01T00:00:00Z"}}
    group = hs.status_request([{"issue_id": 12, "issue_type": "SAST"}, {"issue_id": 13, "issue_type": "SAST"}],
                              "False Positive", "текст", "2027-01-01T00:00:00Z")
    assert group["path"] == "/issue/status/change"
    assert group["body"] == {"issues": [{"issueId": 12, "issueType": "SAST"}, {"issueId": 13, "issueType": "SAST"}],
                             "status": "False Positive", "reason": "текст", "expiredAt": "2027-01-01T00:00:00Z"}
    with pytest.raises(hs.StatusRefused):
        hs.status_request([], "False Positive", "текст", "2027-01-01T00:00:00Z")


def test_read_request():
    assert hs.read_request({"issue_id": 12, "issue_type": "SCA_S"}) == {
        "method": "GET", "path": "/issue/status?issueId=12&issueType=SCA_S", "body": None}


@pytest.mark.parametrize("answer,ok", [
    ({"status": "False Positive", "reason": "Имя  таблицы\nзадано", "expiredAt": "2027-01-01T00:00:00Z"}, True),
    ({"status": "False Positive", "reason": "Имя таблицы задано", "expiredAt": 1798761600000}, True),  # мс, UTC
    ({"status": "False Positive", "reason": "Имя таблицы задано", "expiredAt": "2027-01-02T00:00:00Z"}, False),
    ({"status": "Accepted risk", "reason": "Имя таблицы задано", "expiredAt": "2027-01-01T00:00:00Z"}, False),
    ({"status": "False Positive", "reason": "другое", "expiredAt": "2027-01-01T00:00:00Z"}, False),
    ({"status": "False Positive", "reason": "Имя таблицы задано"}, False),
    (None, False),
    ("", False),
])
def test_status_matches(answer, ok):
    assert hs.status_matches(answer, "False Positive", "Имя таблицы задано", "2027-01-01T00:00:00Z") is ok



@pytest.mark.parametrize("value,day", [
    ("2027-01-26T00:00:00Z", "2027-01-26"),
    ("2027-01-26T00:00:00.000+0000", "2027-01-26"),
    ("2027-01-26T03:00:00+03:00", "2027-01-26"),
    ("2027-01-26T00:00:00+03:00", "2027-01-25"),  # по UTC – 25 января
    ("2027-01-26T00:00:00", "2027-01-26"),
    ("2027-01-26", "2027-01-26"),
    (1800921600000, "2027-01-26"),
    ("2027-01-26garbage", ""),
    ("2027-01-26T00:00:00Zjunk", ""),
    ("2027-02-30", ""),
    ("2027-01-26T25:00:00Z", ""),
    ("", ""),
    (None, ""),
    (True, ""),
    ("9999-12-31T23:59:59-01:00", ""),  # перевод в UTC – за пределами календаря
    ("0001-01-01T00:00:00+01:00", ""),
])
def test_expiry_day_is_parsed_whole_and_in_utc(value, day):
    assert hs._day(value) == day


def test_status_matches_refuses_garbage_and_shifted_expiry():
    reason = "Ложное: значение – константа."
    ok = {"status": "False Positive", "reason": reason, "expiredAt": "2027-01-26T00:00:00Z"}
    assert hs.status_matches(ok, "False Positive", reason, "2027-01-26T00:00:00Z")
    for bad in ("2027-01-26garbage", "2027-01-26T00:00:00+03:00"):
        assert not hs.status_matches({**ok, "expiredAt": bad}, "False Positive", reason, "2027-01-26T00:00:00Z")
