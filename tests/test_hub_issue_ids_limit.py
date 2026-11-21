"""Предел параметра issueIds у заготовки дефекта (`GET /defects/blank`): десятки находок одной библиотеки входят в один
дефект (десятки пятизначных номеров – больше 200 знаков, прежнего общего предела). Предел один – hub_ops.ISSUE_IDS_MAX;
остальные параметры белого списка по-прежнему до 200 знаков."""
import pytest

from app import hub_defects, hub_ops
from app.hub_ops import HubRequestRejected


def test_blank_request_accepts_dozens_of_findings():
    targets = [{"issue_id": 370000 + i} for i in range(40)]
    request = hub_defects.blank_request(952, targets, "SCA_S")
    assert request["method"] == "GET" and request["path"].startswith("/defects/blank?appId=952&issueIds=370000,370001,")
    assert len(request["path"]) > 200  # прежний предел такой состав не пропускал
    exact = [{"issue_id": 123456}] * 285 + [{"issue_id": 12345}]  # ровно 2000 знаков – проходит
    assert len(hub_defects.blank_request(1, exact, "SAST")["path"]) > 2000


def test_blank_request_still_refuses_over_the_limit():
    count = hub_ops.ISSUE_IDS_MAX // 7 + 2  # шесть цифр и запятая на номер
    with pytest.raises(ValueError, match="issueIds"):
        hub_defects.blank_request(952, [{"issue_id": 600000 + i} for i in range(count)], "SAST")


def test_check_request_issue_ids_limit_and_form():
    exact = ",".join(["123456"] * 285) + ",12345"  # 285 × 6 + 284 + 1 + 5 = 2000 знаков – ровно предел
    assert len(exact) == 2000 == hub_ops.ISSUE_IDS_MAX
    hub_ops.check_request("GET", f"/defects/blank?appId=1&issueIds={exact}&type=SAST")
    with pytest.raises(HubRequestRejected):
        hub_ops.check_request("GET", f"/defects/blank?appId=1&issueIds={exact}6&type=SAST")  # 2001 знак – отказ
    with pytest.raises(ValueError, match="issueIds"):  # та же граница у заготовки дефекта: 2001 знак
        hub_defects.blank_request(1, [{"issue_id": 123456}] * 285 + [{"issue_id": 123456}], "SAST")
    for bad in ("10,,11", ",10", "10,", "10;11", "a,b", "1" * 13):
        with pytest.raises(HubRequestRejected):
            hub_ops.check_request("GET", f"/defects/blank?appId=1&issueIds={bad}&type=SAST")


def test_worker_check_job_shares_the_limit():
    """Исполнитель в ВМ проверяет тот же предел и ту же форму (ADR-0144): прежние 200 знаков отклоняли заготовку из десятков
    находок до обращения к Hub («отклонено исполнителем – значение параметра GET /defects/blank»)."""
    from test_hub_worker import hw
    hub = "https://hub.example.org"

    def check(issue_ids: str):
        hw.check_job({"hub_url": hub, "method": "GET", "path": f"/defects/blank?appId=1&issueIds={issue_ids}&type=SAST",
                      "body": None}, hub)

    check(",".join(str(37000 + i) for i in range(40)))  # 239 знаков – больше прежнего предела
    exact = ",".join(["123456"] * 285) + ",12345"
    check(exact)  # ровно 2000
    for bad in (exact + "6", "10,,11", "a,b", "1" * 13):
        with pytest.raises(hw.Refused):
            check(bad)
    with pytest.raises(hw.Refused):
        hw.check_job({"hub_url": hub, "method": "GET", "path": f"/defects/blank?appId={'1' * 201}&issueIds=10&type=SAST",
                      "body": None}, hub)
    assert hw.ISSUE_IDS_MAX == hub_ops.ISSUE_IDS_MAX


def test_other_parameters_keep_the_old_limit():
    hub_ops.check_request("GET", f"/defects/blank?appId={'1' * 200}&issueIds=10&type=SAST")
    with pytest.raises(HubRequestRejected):
        hub_ops.check_request("GET", f"/defects/blank?appId={'1' * 201}&issueIds=10&type=SAST")
    assert hub_defects.ISSUE_IDS_MAX == hub_ops.ISSUE_IDS_MAX == 2000
