"""Пакетное решение SCA (ADR-0091 п. 2, 4, 6): одно решение – всем отмеченным находкам версии компонента одной
транзакцией; снятая галочка оставляет находке её решение; устаревшая карточка не записывает ничего; смена исхода
«Обновить» выводит находку из набора дефекта, правка комментария – нет."""

from __future__ import annotations

import re

from test_sca import AS_JSON, answer, answers_json, form_fields, post_answers, sca_card
from test_web import prepared, web  # noqa: F401


def package_fields(card: str) -> dict:
    """Скрытые поля пакетного решения из карточки: признак, отпечаток пакета и редакции находок."""
    return {"apply_package": "1", "package_fp": re.search(r'name="package_fp" value="([^"]*)"', card).group(1),
            **dict(re.findall(r'name="(apply_rev_[^"]+)" value="(\d+)"', card))}


def post_package(web, pid: int, hub_id: str, apply_to: list[str], card: str | None = None, **decision):
    fid, fresh = sca_card(web, pid, hub_id)
    card = card or fresh
    data = {**form_fields(card), **package_fields(card), "apply_to": apply_to, "reviewed": "1", "action": "save",
            **decision}
    return web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data=data)


FP = {"decision": "disagree", "final_verdict": "false_positive",
      "comment": "Уязвимая функция разбора в продукте не вызывается."}


def test_card_lists_package_findings_with_checkboxes(web):  # noqa: F811
    pid = prepared(web)
    _, card = sca_card(web, pid, "73001")
    block = re.search(r'<fieldset class="package-apply".*?</fieldset>', card, re.S).group(0)
    assert 'value="73001" checked disabled' in block and 'value="73002" checked' in block
    assert "Снятая галочка оставляет находке её собственное решение" in block


def test_package_decision_written_to_every_checked_finding(web):  # noqa: F811
    pid = prepared(web)
    saved = post_package(web, pid, "73001", ["73001", "73002"], **FP)
    assert saved.status_code == 200, saved.text
    assert saved.json()["applied"] == ["73002"] and "73002" not in saved.json()["notice"], "сведения – не предупреждение"
    db = web.app.state.db
    for hub_id in ("73001", "73002"):
        review = db.get_review(pid, hub_id)
        assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("disagree", "false_positive", 1)
        assert review["final_comment"] == FP["comment"]


def test_unchecked_finding_keeps_its_own_decision(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    before = db.get_review(pid, "73002")
    saved = post_package(web, pid, "73001", ["73001"], **FP)
    assert saved.status_code == 200, saved.text
    assert db.get_review(pid, "73001")["final_verdict"] == "false_positive"
    assert db.get_review(pid, "73002") == before


def test_stale_package_card_writes_nothing(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    _, card = sca_card(web, pid, "73001")
    # пока карточка открыта, решение по 73002 сохранили в другой вкладке
    db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    refused = post_package(web, pid, "73001", ["73001", "73002"], card=card, **FP)
    assert refused.status_code == 409 and refused.json()["reason"] == "package", refused.text
    assert "73002" in refused.json()["detail"] and "ни для одной находки" in refused.json()["detail"]
    assert db.get_review(pid, "73001") is None
    assert db.get_review(pid, "73002")["final_verdict"] == "true_positive"


def test_agree_not_applied_to_finding_without_same_agent_verdict(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    # ответ агента охватывает только уязвимость находки 73001
    vuln = db.get_finding_by_hub_id(pid, "73001")["data"]
    own = [*(vuln.get("vuln_ids") or []), *(vuln.get("cve") or [])]
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", vulnerabilities=own,
                                                      ids={}))).status_code == 303
    refused = post_package(web, pid, "73001", ["73001", "73002"], decision="agree", final_verdict="",
                           comment="Обновить до 1.4.9.")
    assert refused.status_code == 400 and "73002" in refused.json()["detail"], refused.text
    assert db.get_review(pid, "73001") is None and db.get_review(pid, "73002") is None


def test_outcome_change_leaves_defect_set_comment_edit_does_not(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    upd = {"decision": "disagree", "final_verdict": "true_positive", "reviewed": True}
    db.save_review(pid, "73001", final_comment="Обновить.", **upd)
    ref = db.sca_snapshot(pid, "73001").input_ref
    db.move_sca_member(pid, ref, "73001", 1, "", expect={0: 0, 1: 0})
    assert db.sca_members(pid, ref)["73001"]["set_no"] == 1
    db.save_review(pid, "73001", final_comment="Обновить: функция вызывается.", **upd)  # исход тот же
    assert db.sca_members(pid, ref)["73001"]["set_no"] == 1
    revision = db.sca_sets(pid, ref)[1]["revision"]
    db.save_review(pid, "73001", decision="disagree", final_verdict="false_positive", final_comment="Не вызывается.",
                   reviewed=True)
    assert "73001" not in db.sca_members(pid, ref)
    assert db.sca_sets(pid, ref)[1]["revision"] == revision + 1


# ============================================================================ замечания ревью 1731494

UPD = {"decision": "disagree", "final_verdict": "true_positive", "comment": "Уязвимая функция разбора вызывается."}


def set_form(card: str) -> dict:
    """Скрытые поля формы переноса в набор: редакции наборов, которые видит карточка."""
    form = re.search(r'<form[^>]*id="sca-set-form".*?</form>', card, re.S).group(0)
    return dict(re.findall(r'name="(set_rev_\d+)" value="(\d+)"', form))


def test_new_separate_set_from_the_real_form(web):  # noqa: F811
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    moved = web.client.post(f"{url}/set", headers=AS_JSON, data={**set_form(card), "set_no": "new"})
    assert moved.status_code == 200, moved.text
    db = web.app.state.db
    ref = db.sca_snapshot(pid, "73001").input_ref
    assert db.sca_members(pid, ref)["73001"]["set_no"] == 1
    # та же устаревшая форма второй раз: набор по умолчанию уже другой редакции – отказ, ничего не меняется
    again = web.client.post(f"{url}/set", headers=AS_JSON, data={**set_form(card), "set_no": "new"})
    assert again.status_code == 409 and db.sca_members(pid, ref)["73001"]["set_no"] == 1


def test_stale_text_form_cannot_overwrite_another_set(web):  # noqa: F811
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    shown = {"text_revision": "0", "set_no": "0",
             "input_ref": re.search(r'name="input_ref" value="([^"]*)"', card).group(1),
             "target_version": "9.9.9", "explanation": "Текст из формы набора по умолчанию."}
    assert web.client.post(f"{url}/set", headers=AS_JSON, data={**set_form(card), "set_no": "new"}).status_code == 200
    refused = web.client.post(f"{url}/package-text", headers=AS_JSON, data=shown)
    assert refused.status_code == 409 and refused.json()["reason"] == "text", refused.text
    db = web.app.state.db
    ref = db.sca_snapshot(pid, "73001").input_ref
    assert db.sca_package_text(pid, ref, 1) is None and db.sca_package_text(pid, ref, 0) is None


def test_confirmation_is_lost_when_the_body_changes(web):  # noqa: F811
    from test_sca import sca_text_ready

    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    done = sca_text_ready(web, url)
    assert done["ready"] is True, done
    # Объяснение поменяли, отметку «Версию проверил сам» не ставили заново: подтверждение было о прежнем тексте
    card = web.client.get(url).text
    revision = re.search(r'name="text_revision" value="(\d+)"', card).group(1)
    changed = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        "text_revision": revision, "target_version": "9.9.9",
        "explanation": done["explanation"] + " Дополнено после проверки."})
    assert changed.status_code == 200 and changed.json()["ready"] is False
    assert "Версию проверил сам" in changed.json()["hint"]


def test_package_form_with_only_own_finding_checks_the_package(web):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    _, card = sca_card(web, pid, "73001")
    db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    refused = post_package(web, pid, "73001", ["73001"], card=card, **FP)
    assert refused.status_code == 409 and refused.json()["reason"] == "package", refused.text
    assert "73002" in refused.json()["detail"]
    assert db.get_review(pid, "73001") is None


def test_number_of_another_set_is_refused(web):  # noqa: F811
    from test_sca import sca_text_ready

    pid = prepared(web)
    # набор только с AST дефекта не даёт (ADR-0101): публичное соответствие для находки отдельного набора
    web.app.state.db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid1, card1 = sca_card(web, pid, "73001")
    url1 = f"/projects/{pid}/sca/findings/{fid1}"
    assert web.client.post(f"{url1}/set", headers=AS_JSON, data={**set_form(card1), "set_no": "new"}).status_code == 200
    fid2, _ = sca_card(web, pid, "73002")
    url2 = f"/projects/{pid}/sca/findings/{fid2}"
    sca_text_ready(web, url1)
    sca_text_ready(web, url2)
    first = web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "7", "confirm": "1"})
    assert first.status_code == 200, first.text
    taken = web.client.post(f"{url1}/defect", headers=AS_JSON, data={"number": "7", "confirm": "1"})
    assert taken.status_code == 400 and "уже у другого набора" in taken.json()["detail"], taken.text
