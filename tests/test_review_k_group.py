"""Замечания ревью Б2/Б6/Б9 (группа К плана 0.9.8): отметка «Дефект создан в Hub» по снимку в транзакции (К2),
отметки текста набора только по показанному снимку (К4), подтверждение чужого номера без скрипта (К5), пустое
обоснование после очистки префикса (К8), отметка «Внесено» без текста (К9), прежняя отметка короткого текста у
«Обновить» (К10), черновики отказов обычных форм (К11)."""

from __future__ import annotations

import html
import re

from app.db import text_hash
from app.models import Finding
from app.routes.sca import saved_hub_text_v2
from test_defect import save_sast
from test_sca import AS_JSON, LEGACY_HUB_SUGGESTION, form_fields, sca_card, sca_text_ready
from test_sca_package_decision import UPD, post_package
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: F401


def tp_with_text(web):  # noqa: F811
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    sca_text_ready(web, url)
    return pid, url


def card_value(card: str, name: str) -> str:
    return re.search(rf'name="{name}" value="([^"]*)"', card).group(1)


def test_k2_entered_checks_the_snapshot_inside_the_transaction(web, monkeypatch):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    card = web.client.get(url).text
    sig, revision = card_value(card, "defect_sig"), card_value(card, "review_revision")
    original = db.mark_entered

    def other_tab_changes_text(*args, **kwargs):
        ref = db.sca_snapshot(pid, "73001").input_ref
        record = db.sca_package_text(pid, ref, 0)
        db.save_sca_package_text(pid, ref, 0, expect_revision=int(record["revision"]),
                                 explanation=record["explanation"] + " Дополнено.", ast={},
                                 target_version=record["target_version"], target_basis=record["target_basis"],
                                 version_checked_sig="", text_checked_sig="", text_sig="")
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "mark_entered", other_tab_changes_text)
    refused = web.client.post(f"{url}/entered", headers=AS_JSON,
                              data={"entered": "1", "review_revision": revision, "defect_sig": sig})
    assert refused.status_code == 400 and "Текст дефекта изменился" in refused.json()["detail"], refused.text
    assert not db.get_review(pid, "73001")["entered_hub"]


def test_k4_confirmations_are_not_applied_after_the_package_changed(web):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    card = web.client.get(url).text
    shown = {"text_revision": card_value(card, "text_revision"), "set_no": "0",
             "input_ref": card_value(card, "input_ref"), "shown_fp": card_value(card, "package_fp"),
             "target_version": "9.9.9", "version_checked": "1",
             "explanation": html.unescape(re.search(r'<textarea name="explanation"[^>]*>(.*?)</textarea>', card,
                                                    re.S).group(1))}
    # пока форма открыта, у соседней находки сменился исход – пакет изменился, текст набора – нет
    db.save_review(pid, "73002", decision="disagree", final_verdict="false_positive", final_comment="Не применимо.",
                   reviewed=True)
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data=shown)
    assert saved.status_code == 200, saved.text
    assert saved.json()["confirm_dropped"] is True and "не поставлены" in saved.json()["hint"]
    ref = db.sca_snapshot(pid, "73001").input_ref
    assert db.sca_package_text(pid, ref, 0)["version_checked_sig"] == ""


def test_k5_foreign_number_can_be_confirmed_without_script(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    db.set_defect_number(pid, "sast:999999", 3)
    page = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "3"}, follow_redirects=False)
    assert page.status_code == 409
    assert 'id="defect-confirm-row">' in page.text, "флажок подтверждения открыт"
    assert 'id="defect-number" value="3"' in page.text, "введённый номер сохранён"
    done = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "3", "confirm": "1"},
                           follow_redirects=False)
    assert done.status_code == 303 and db.defect_number(pid, "sast:510001") == 3


def test_k8_reason_only_of_a_prefix_is_empty(web):  # noqa: F811
    pid = prepared(web)
    for decision, verdict, comment in (("disagree", "false_positive", "Ложное срабатывание:"),
                                       ("risk_accepted", "", "Риск принят:")):
        fid, card = sca_card(web, pid, "73002")
        r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
            **form_fields(card), "decision": decision, "final_verdict": verdict, "comment": comment,
            "kapo_state": "not_actual" if decision == "risk_accepted" else "", "action": "save"})
        assert r.status_code == 400 and "обоснованием" in r.json()["detail"], r.text
    assert web.app.state.db.get_review(pid, "73002") is None


def test_k9_no_entered_mark_without_a_text(web):  # noqa: F811
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    assert web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "later", "final_verdict": "", "comment": "", "action": "save"}).status_code == 200
    revision = str(web.app.state.db.get_review(pid, "73002")["revision"])
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": revision})
    assert r.status_code == 400 and "текста для Hub нет" in r.json()["detail"], r.text


def test_k10_previous_short_text_mark_is_not_a_created_defect(web):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    review = db.get_review(pid, "73001")
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    legacy = saved_hub_text_v2(db, web.app.state.settings, pid, f, review)
    db.mark_entered(pid, "73001", True, review["revision"], text_hash(legacy))
    page = web.client.get(url).text
    assert "Отметка относится к прежнему короткому тексту – полный дефект не подтверждён" in page
    assert "Отметка поставлена по прежнему тексту – дефект не подтверждён." in page
    assert "Дефект создан в Hub." not in page
    sig = card_value(page, "defect_sig")
    db.mark_entered(pid, "73001", True, review["revision"], sig)
    page = web.client.get(url).text
    assert "Дефект создан в Hub." in page and 'id="entered-format-updated"' not in page


def test_k11_text_form_conflict_keeps_the_draft(web):  # noqa: F811
    pid, url = tp_with_text(web)
    card = web.client.get(url).text
    draft = "CVE-2099-10002: Черновик оператора, который не должен потеряться при конфликте."
    page = web.client.post(f"{url}/package-text", headers=ORIGIN, follow_redirects=False, data={
        "text_revision": "0", "target_version": "8.8.8", "explanation": draft,
        "set_no": "0", "input_ref": card_value(card, "input_ref")})
    assert page.status_code == 409 and "подставлен в форму" in page.text
    assert draft in html.unescape(page.text) and 'value="8.8.8"' in page.text


def test_k11_comment_check_refusal_keeps_the_package_choice(web):  # noqa: F811
    pid = prepared(web)
    _, card = sca_card(web, pid, "73002")
    suggestion = LEGACY_HUB_SUGGESTION  # прежняя заготовка по данным Hub (до 0.9.11, ADR-0100) – текст «обновить»
    fid = web.app.state.db.get_finding_by_hub_id(pid, "73002")["id"]
    package = {"apply_package": "1", "package_fp": card_value(card, "package_fp"),
               **dict(re.findall(r'name="(apply_rev_[^"]+)" value="(\d+)"', card))}
    page = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=ORIGIN, follow_redirects=False, data={
        **form_fields(card), **package, "apply_to": ["73002"], "decision": "risk_accepted", "final_verdict": "",
        "kapo_state": "not_actual", "comment": suggestion, "action": "save"})
    assert page.status_code == 409, page.status_code
    block = re.search(r'<fieldset class="package-apply".*?</fieldset>', page.text, re.S).group(0)
    assert 'value="73001" checked' not in block, "снятая галочка соседа не вернулась"
