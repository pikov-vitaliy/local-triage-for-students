"""Проекция решения Hub (dev15, план п. 1.1): одна для сравнения, принятия и страниц.

Ревью плана dev15 (Codex и Kimi, круг 1): если принимать противоречия на стороне Hub по прежней проекции, находка получила
бы основание и срок из ручной записи другой находки. Основание берётся только из ручной записи этой находки с тем же
статусом, у «Риск принят» – из действующей записи риска этой находки. Отсутствие, null и пустая строка – одно «нет».
"""

from app.hub_sync_compare import issue_values, normalized_decision

KEY = "SAST:101"


def manual(**kw):
    return {"issueId": 101, "issueType": "SAST", "status": "False Positive", "reason": "Код недостижим",
            "expiredAt": "2027-01-30T00:00:00Z", **kw}


def test_own_manual_with_same_status_gives_reason_and_term():
    values = issue_values({"detail": {"status": "False Positive"}, "manual": manual()}, KEY)
    assert values == {"status": "False Positive", "reason": "Код недостижим", "expiredAt": "2027-01-30"}


def test_manual_of_another_finding_is_never_the_reason():
    hub = {"detail": {"status": "False Positive"}, "manual": manual(issueId=102)}
    assert issue_values(hub, KEY) == {"status": "False Positive"}
    other_type = {"detail": {"status": "False Positive"}, "manual": manual(issueType="SCA")}
    assert issue_values(other_type, KEY) == {"status": "False Positive"}


def test_manual_contradicting_detail_status_gives_status_only():
    # подробный статус Open, ручная запись – прежнее «Ложное срабатывание» с основанием
    hub = {"detail": {"status": "Open"}, "manual": manual()}
    assert issue_values(hub, KEY) == {"status": "Open"}


def test_without_key_ownership_is_not_proven():
    assert issue_values({"detail": {"status": "False Positive"}, "manual": manual()}) == {"status": "False Positive"}


def test_risk_only_when_active_for_this_finding():
    risk = {"issueId": 101, "issueType": "SAST", "appId": 952, "isActive": True, "deleteTs": None, "isConditional": False,
            "comment": "Риск принят до обновления", "expiredAt": "2027-02-01T00:00:00Z"}
    hub = {"detail": {"status": "Accepted risk", "appId": 952}, "risk": risk}
    assert issue_values(hub, KEY) == {"status": "Accepted risk", "reason": "Риск принят до обновления",
                                      "expiredAt": "2027-02-01"}
    for broken in ({"isActive": False}, {"deleteTs": "2026-11-01"}, {"isConditional": True}, {"issueId": 102},
                   {"appId": 253}, {"expiredAt": "2026-01-01T00:00:00Z"}):
        assert issue_values({**hub, "risk": {**risk, **broken}}, KEY) == {"status": "Accepted risk"}


def test_absent_null_and_empty_are_the_same_value():
    absent = normalized_decision({"status": "False Positive"})
    assert normalized_decision({"status": "False Positive", "reason": None, "expiredAt": None}) == absent
    assert normalized_decision({"status": "False Positive", "reason": "", "expiredAt": ""}) == absent
    assert issue_values({"detail": {"status": "False Positive"}, "manual": manual(reason="", expiredAt=None)}, KEY) == absent


def test_every_group_has_a_place_in_the_order():
    """dev15 (план п. 1.5, ревью круга 2): у каждой группы сравнения своё место в порядке основной группы – новая
    группа (local_only) не показывается как «неполные сведения»."""
    from app.hub_sync_compare import GROUP_ORDER, LABELS, primary_group
    assert set(LABELS) <= set(GROUP_ORDER), set(LABELS) - set(GROUP_ORDER)
    assert primary_group(["local_only"]) == "local_only"
