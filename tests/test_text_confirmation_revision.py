"""«Текст проверен» действует только с редакцией решения, которую видел человек (BUG-01 ревью 24.10, ADR-0088): одно
правило для короткого текста, обычного сохранения с ответом JSON, полного дефекта и SCA. Без редакции или с прежней
редакцией текст модели к другому вердикту не выдаётся; решение при этом сохраняется. Данные выдуманные."""

from __future__ import annotations

import html
import re

import pytest

from test_audit_lta001b import HUB_ID
from test_r092_hub_text import JSON, bind_verdict, card_fields
from test_sca import answer, answers_json, form_fields, post_answers, sca_card
from test_web import prepared, web  # noqa: F401

MODEL_COMMENT = "Подтверждено: значение из запроса попадает в SQL без параметров."


def sast_url(web, pid: int) -> str:  # noqa: F811
    return f"/projects/{pid}/findings/{web.app.state.db.get_finding_by_hub_id(pid, HUB_ID)['id']}"


def fields(web, url: str, revision: str) -> dict:  # noqa: F811
    """Поля формы карточки: редакция решения – как есть, отсутствует (страница до обновления) или прежняя."""
    data = card_fields(web, url)
    if revision == "missing":
        data.pop("review_revision")
    elif revision == "stale":
        data["review_revision"] = str(int(data["review_revision"]) + 5)
    return data


@pytest.mark.parametrize("revision, reason", [("missing", "comment"), ("stale", "revision")])
def test_short_copy_rejects_confirmation_without_current_revision(web, revision, reason):  # noqa: F811
    """Без редакции – отказ правила подтверждения; с прежней редакцией страница отклоняется ещё раньше как устаревшая."""
    pid = prepared(web)
    bind_verdict(web, pid, "true_positive", MODEL_COMMENT, "Параметризовать.")
    url = sast_url(web, pid)
    r = web.client.post(url + "/review", headers=JSON, data={
        **fields(web, url, revision), "decision": "false_positive", "final_verdict": "", "comment": MODEL_COMMENT,
        "action": "copy", "comment_confirmed": "1"})
    assert r.status_code == 409 and r.json()["reason"] == reason, r.text
    assert "hub_text" not in r.json()
    review = web.app.state.db.get_review(pid, HUB_ID)
    assert not review or not review.get("copied_at")


def test_short_copy_accepts_confirmation_of_current_revision(web):  # noqa: F811
    pid = prepared(web)
    bind_verdict(web, pid, "true_positive", MODEL_COMMENT, "Параметризовать.")
    url = sast_url(web, pid)
    r = web.client.post(url + "/review", headers=JSON, data={
        **fields(web, url, "current"), "decision": "false_positive", "final_verdict": "", "comment": MODEL_COMMENT,
        "action": "copy", "comment_confirmed": "1"})
    assert r.status_code == 200 and r.json()["copy_allowed"] is True, r.text


def test_own_comment_from_old_page_is_copied_without_confirmation(web):  # noqa: F811
    """Совместимость: своё обоснование со страницы без поля редакции копируется, как раньше."""
    pid = prepared(web)
    bind_verdict(web, pid, "true_positive", MODEL_COMMENT, "Параметризовать.")
    url = sast_url(web, pid)
    r = web.client.post(url + "/review", headers=JSON, data={
        **fields(web, url, "missing"), "decision": "false_positive", "final_verdict": "",
        "comment": "Имя таблицы берётся из заранее заданной строки.", "action": "copy"})
    assert r.status_code == 200 and r.json()["copy_allowed"] is True, r.text


@pytest.mark.parametrize("revision", ["missing", "current"])
def test_json_save_gives_text_only_with_current_confirmation(web, revision):  # noqa: F811
    """Обычное сохранение с ответом JSON: решение записывается всегда, текст модели к другому вердикту – только по
    отметке текущей редакции."""
    pid = prepared(web)
    bind_verdict(web, pid, "true_positive", MODEL_COMMENT, "Параметризовать.")
    url = sast_url(web, pid)
    r = web.client.post(url + "/review", headers=JSON, data={
        **fields(web, url, revision), "decision": "false_positive", "final_verdict": "", "comment": MODEL_COMMENT,
        "action": "save", "comment_confirmed": "1"})
    assert r.status_code == 200, r.text
    assert web.app.state.db.get_review(pid, HUB_ID)["final_verdict"] == "false_positive"
    if revision == "current":
        assert r.json()["copy_allowed"] is True and r.json()["hub_text"]
    else:
        assert r.json()["copy_allowed"] is False and r.json()["hub_text"] == ""


def test_sca_copy_rejects_confirmation_without_revision(web):  # noqa: F811
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    comment = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    data = form_fields(card)
    saved = web.client.post(url + "/review", headers=JSON, data={
        **data, "decision": "disagree", "final_verdict": "false_positive", "comment": comment, "action": "save"})
    assert saved.status_code == 200, saved.text
    data = form_fields(web.client.get(url).text)
    data.pop("review_revision")
    r = web.client.post(url + "/review", headers=JSON, data={
        **data, "decision": "disagree", "final_verdict": "false_positive", "comment": comment, "action": "copy",
        "comment_confirmed": "1"})
    assert r.status_code == 409 and r.json()["reason"] == "comment", r.text
    assert "hub_text" not in r.json()


@pytest.mark.parametrize("revision", ["missing", "current"])
def test_sca_risk_accepted_save_needs_confirmation_of_current_revision(web, revision):  # noqa: F811
    """«Риск принят» с обоснованием агента к другому выводу и прежде сохранялся только с «Текст проверен» (0.4.1):
    отметка без редакции действует как её отсутствие – отказ 409, решение не записано, ввод остаётся в форме."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    comment = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    data = form_fields(card)
    if revision == "missing":
        data.pop("review_revision")
    r = web.client.post(url + "/review", headers=JSON, data={
        **data, "decision": "risk_accepted", "final_verdict": "", "comment": comment, "kapo_state": "neutralized",
        "action": "save", "comment_confirmed": "1"})
    review = web.app.state.db.get_review(pid, "73001")
    if revision == "missing":
        assert r.status_code == 409 and r.json()["reason"] == "comment", r.text
        assert not review or review.get("decision") != "risk_accepted"
    else:
        assert r.status_code == 200, r.text
        assert review["decision"] == "risk_accepted"
