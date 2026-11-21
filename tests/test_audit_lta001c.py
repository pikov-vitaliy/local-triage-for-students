"""LTA-001 (третья проверка): «Скопировать для Hub» и пропавшая находка – проверка в транзакции записи."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from test_audit_lta001b import (HUB_ID, RATIONALE, decided, reimport, review_form,  # noqa: F401
                                standalone)
from test_defect import save_sast  # noqa: F401
from test_web import ORIGIN, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}


def copy_request(web, url, fields):
    return web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "false_positive", "final_verdict": "", "comment": RATIONALE, "action": "copy"})


def test_finding_disappears_between_the_check_and_the_transaction(web, decided):  # noqa: F811
    """Повторный импорт исключает находку ровно между проверкой маршрута и транзакцией записи: текст не возвращается."""
    pid, url = decided
    fields = review_form(web, url)
    db = web.app.state.db
    before = db.get_review(pid, HUB_ID)
    original = db.save_review

    def injected(*args, **kwargs):
        reimport(web, pid, drop={HUB_ID})
        return original(*args, **kwargs)

    with patch.object(db, "save_review", side_effect=injected):
        r = copy_request(web, url, fields)
    assert r.status_code == 400 and r.json()["reason"] == "rejected" and "hub_text" not in r.json(), r.text
    assert "нет в текущей выгрузке" in r.json()["detail"]
    after = db.get_review(pid, HUB_ID)
    assert after["revision"] == before["revision"] and after["copied_at"] is None, "запись не прошла"


def test_plain_save_of_a_missing_finding_is_still_possible(web, decided):  # noqa: F811
    """Ограничение касается копирования; сохранить решение по пропавшей находке (история) можно."""
    pid, url = decided
    fields = review_form(web, url)
    reimport(web, pid, drop={HUB_ID})
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "true_positive", "final_verdict": "", "comment": RATIONALE, "action": "save"})
    assert r.status_code == 200 and r.json()["defect_ready"] is False


def test_successful_copy_answers_with_the_permission_flag(web, decided):  # noqa: F811
    pid, url = decided
    r = copy_request(web, url, review_form(web, url))
    assert r.status_code == 200 and r.json()["copy_allowed"] is True and r.json()["hub_text"]


def test_script_copies_only_with_the_servers_permission():
    js = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "answer.copy_allowed !== true" in js


def test_sca_copy_has_the_same_permission_and_presence_check(web):  # noqa: F811
    """Карточка SCA копирует тем же скриптом: ответ несёт copy_allowed, а пропавшая находка не копируется."""
    from test_sca import form_fields
    from test_web import prepared

    pid = prepared(web)
    db = web.app.state.db
    row = db.get_finding_by_hub_id(pid, "73002")
    url = f"/projects/{pid}/sca/findings/{row['id']}"

    def copy():
        return web.client.post(f"{url}/review", headers=AS_JSON, data={
            **form_fields(web.client.get(url).text), "decision": "disagree", "final_verdict": "false_positive",
            "comment": "Не применимо.", "action": "copy"})

    r = copy()
    assert r.status_code == 200 and r.json()["copy_allowed"] is True and r.json()["hub_text"]
    original = db.save_review

    def injected(*args, **kwargs):
        reimport(web, pid, drop={"73002"})
        return original(*args, **kwargs)

    with patch.object(db, "save_review", side_effect=injected):
        r = copy()
    assert r.status_code == 400 and "hub_text" not in r.json() and "нет в текущей выгрузке" in r.json()["detail"], r.text
