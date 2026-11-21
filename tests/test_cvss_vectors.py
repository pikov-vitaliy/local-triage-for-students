"""Регрессии формата векторов по FIRST, без сети и без пересчёта баллов.

CVSS 2: https://www.first.org/cvss/v2/guide (таблица 13).
CVSS 3.1: https://www.first.org/cvss/v3-1/specification-document (раздел 6).
CVSS 4.0: https://www.first.org/cvss/v4.0/specification-document (таблица 23).
"""
import pytest
from app import cvss

V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.parametrize("vector,expected", [
    (V3 + "/E:P/RL:O/RC:C", "3.1"),
    (V3.replace("3.1", "3.0") + "/E:F/RL:T/RC:R", "3.0"),
    (V3 + "/CR:H/MAV:L/MS:C/MC:H/MI:L/MA:N", "3.1"),
    (V3 + "/CDP:H", ""),                 # метрика 2.0 не относится к 3.x
    (V3 + "/MSC:H", ""),                 # метрика 4.0 не относится к 3.x
    (V3 + "/E:BOOM", ""),                # важно значение, не только имя метрики
    (V3 + "/MAV:NL", ""),                # нельзя принимать подстроку списка значений
    ("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", "3.1"),
    (V2.replace("AV:N", "AV:P"), ""),    # Physical появился в третьей версии
    (V2 + "/E:POC/RL:OF/RC:UC/CDP:LM/TD:M/CR:H/IR:M/AR:L", "2.0"),
    ("(" + V2 + ")", "2.0"),
    (V2 + "/E:X", ""),                   # во второй версии Not Defined обозначается ND
    (V4 + "/E:P/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Clear", "4.0"),
    (V4 + "/U:Green", "4.0"),
    (V4 + "/V:H", ""),                   # Value Density: X, D или C
    (V4 + "/E:H", ""),                   # Exploit Maturity: X, A, P или U
    (V4.replace("AV:N/AC:L", "AC:L/AV:N"), ""),  # в 4.0 порядок обязателен
    (V4 + "/V:C/E:P", ""),               # то же для дополнительных метрик
    (V4 + "/E:P/E:P", ""),
])
def test_vector_format_by_version(vector, expected):
    assert cvss.version_from_extra({"CVSS vector": vector}) == expected


@pytest.mark.parametrize("header,value", [
    ("version", "4.0"), ("Версия", "3.1"), ("CVSS", "3.1"),
    ("Версия оценки", "2.0"), ("release version", "3.0"),
])
def test_ambiguous_column_is_not_cvss_version(header, value):
    assert cvss.version_from_extra({header: value}) == ""


def test_explicit_cvss_version_label():
    assert cvss.version_from_extra({"Версия оценки CVSS": "3.1"}) == "3.1"
    assert cvss.version_from_extra({"CVSS": "CVSS 3.0"}) == "3.0"


def test_range_requires_tenths_and_never_applies_only_valid_half():
    result = cvss.parse({"cvss_min": "7.05", "cvss_max": "9"})
    assert result["errors"] and result["min"] is None and result["max"] is None
    assert cvss.parse({"cvss_min": "7.00"})["min"] == 7.0


def test_missing_selected_version_counter_has_valid_denominator(web):
    from test_sca_cvss import create_project, row, upload_table
    pid = create_project(web.client)
    upload_table(web, pid, [row("88002", "lib-no-version", "7.5")])
    response = web.client.get(f"/projects/{pid}/sca?cvss_version=3.1&cvss=no_score")
    assert "Отобрано 1 из 1" in response.text
    assert 'value="3.1" selected' in response.text


def test_cvss2_high_score_uses_its_own_color(web):
    from test_sca_cvss import create_project, row, upload_table
    pid = create_project(web.client)
    upload_table(web, pid, [row("88001", "lib-legacy", "9.8", version="2.0")])
    response = web.client.get(f"/projects/{pid}/sca?cvss_version=2.0")
    assert response.status_code == 200
    assert 'class="cvss cvss-high"' in response.text
    assert 'class="cvss cvss-critical"' not in response.text


from test_web import web  # noqa: E402,F401
