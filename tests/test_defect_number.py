"""Номер дефекта (Б9): выдача из устаревшей вкладки номер не перезаписывает; одинаковый номер у других находок и
пакетов – предупреждение с подтверждением до записи."""

from __future__ import annotations

import re

from app.models import Finding
from app.routes.sca import set_key
from test_defect import save_sast
from test_sca import AS_JSON, sca_text_ready
from test_sca_package_decision import UPD, post_package
from test_web import prepared, start_run, wait_run, web  # noqa: F401


def shown_number(card: str) -> str:
    return re.search(r'name="number_shown" value="([^"]*)"', card).group(1)


def test_sast_stale_tab_does_not_overwrite_the_number(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    stale = shown_number(web.client.get(url).text)
    assert stale == ""
    first = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "number_shown": stale})
    assert first.status_code == 200, first.text
    # вторая вкладка открыта до выдачи: её номер не перезаписывает сохранённый
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "6", "number_shown": stale})
    assert refused.status_code == 409 and refused.json().get("reload") is True, refused.text
    assert db.defect_number(pid, "sast:510001") == 5
    assert shown_number(web.client.get(url).text) == "5"
    again = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "6", "number_shown": "5"})
    assert again.status_code == 200 and db.defect_number(pid, "sast:510001") == 6


def test_sca_stale_tab_and_foreign_number(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid = db.get_finding_by_hub_id(pid, "73001")["id"]
    url = f"/projects/{pid}/sca/findings/{fid}"
    sca_text_ready(web, url)
    stale = shown_number(web.client.get(url).text)
    first = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "4", "number_shown": stale})
    assert first.status_code == 200 and first.json()["text_sig"], first.text
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "8", "number_shown": stale})
    assert refused.status_code == 409 and refused.json().get("reload") is True, refused.text
    # номер 4 у другого пакета проекта – предупреждение с подтверждением; у 73003 только AST – публичное
    # соответствие, иначе набор дефекта не даёт (ADR-0101)
    db.save_ast_map([("AST-2026-000103", "CVE-2099-10003")])
    other = db.get_finding_by_hub_id(pid, "73003")["id"]
    other_url = f"/projects/{pid}/sca/findings/{other}"
    card = web.client.get(other_url).text
    from test_sca import form_fields
    assert web.client.post(f"{other_url}/review", headers=AS_JSON, data={
        **form_fields(card), **UPD, "reviewed": "1", "action": "save"}).status_code == 200
    sca_text_ready(web, other_url)
    warned = web.client.post(f"{other_url}/defect", headers=AS_JSON, data={"number": "4"})
    assert warned.status_code == 409 and warned.json()["reason"] == "confirm", warned.text
    done = web.client.post(f"{other_url}/defect", headers=AS_JSON, data={"number": "4", "confirm": "1"})
    assert done.status_code == 200, done.text


# ============================================================================ К1, К3: проверки в транзакции записи

def sast_ready(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    web.app.state.db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    return pid, url


def test_sast_number_from_other_tab_between_check_and_write_is_kept(web, monkeypatch):  # noqa: F811
    pid, url = sast_ready(web)
    db = web.app.state.db
    original = db.set_defect_number_checked

    def other_tab_first(*args, **kwargs):
        db.set_defect_number(pid, "sast:510001", 9)  # вторая вкладка успела записать номер
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "set_defect_number_checked", other_tab_first)
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "6", "number_shown": ""})
    assert refused.status_code == 409, refused.text
    assert "другой вкладке" in refused.json()["detail"]
    assert db.defect_number(pid, "sast:510001") == 9


def test_sast_foreign_number_appearing_before_write_needs_confirmation(web, monkeypatch):  # noqa: F811
    pid, url = sast_ready(web)
    db = web.app.state.db
    original = db.set_defect_number_checked

    def foreign_first(*args, **kwargs):
        db.set_defect_number(pid, "sast:999999", 6)  # другая находка получила тот же номер
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "set_defect_number_checked", foreign_first)
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "6", "number_shown": ""})
    assert refused.status_code == 409 and refused.json()["reason"] == "confirm", refused.text
    assert db.defect_number(pid, "sast:510001") is None, "запись откатилась"


def test_sca_foreign_number_appearing_before_write_needs_confirmation(web, monkeypatch):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid = db.get_finding_by_hub_id(pid, "73001")["id"]
    url = f"/projects/{pid}/sca/findings/{fid}"
    sca_text_ready(web, url)
    original = db.set_sca_defect_number_checked

    def foreign_first(*args, **kwargs):
        db.set_defect_number(pid, "sast:999999", 5)
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "set_sca_defect_number_checked", foreign_first)
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "number_shown": ""})
    assert refused.status_code == 409 and refused.json()["reason"] == "confirm", refused.text
    key = set_key(Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"]), 0)
    assert db.defect_number(pid, key) is None, "запись откатилась"
