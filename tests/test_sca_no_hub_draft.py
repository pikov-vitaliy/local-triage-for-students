"""ADR-0100: без ответа агента заготовки комментария SCA нет, версия исправления из Hub не подставляется; прежняя
заготовка по данным Hub (до 0.9.11) узнаётся как текст под «обновить» и при загруженном ответе агента."""

from __future__ import annotations

import html
import re

from app.routes.sca import FP_NEEDS_REASON, RISK_NEEDS_REASON
from test_review_k_group import card_value
from test_sca import (AS_JSON, LEGACY_HUB_SUGGESTION, answer, answers_json, form_fields, post_answers, sca_card)
from test_web import ORIGIN, prepared, web  # noqa: F401


def comment_field(card: str) -> str:
    return html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))


def test_card_without_answer_has_empty_comment_and_model_comment(web):  # noqa: F811
    pid = prepared(web)
    _, card = sca_card(web, pid, "73002")
    assert comment_field(card) == ""
    assert 'data-model-comment=""' in card
    assert "безопасная версия" not in card.lower()


def test_empty_comment_is_refused_for_risk_and_false_positive_single_and_package(web):  # noqa: F811
    """Пустое поле (заготовки нет) не превращается в текст: «Риск принят» и «Ложное срабатывание» требуют
    обоснования и в одиночном, и в пакетном сохранении – отказ именно по обоснованию, ничего не записано."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}/review"
    package = {"apply_package": "1", "package_fp": card_value(card, "package_fp"),
               **dict(re.findall(r'name="(apply_rev_[^"]+)" value="(\d+)"', card))}
    risk = {"decision": "risk_accepted", "final_verdict": "", "kapo_state": "not_actual"}
    false_positive = {"decision": "disagree", "final_verdict": "false_positive"}
    for outcome, reason in ((risk, RISK_NEEDS_REASON), (false_positive, FP_NEEDS_REASON)):
        for extra in ({}, {**package, "apply_to": ["73001", "73002"]}):
            r = web.client.post(url, headers=AS_JSON, data={
                **form_fields(card), **extra, **outcome, "comment": "", "action": "save"})
            assert r.status_code == 400, r.text
            assert r.json()["reason"] == "rejected" and r.json()["detail"] == reason, r.text
    db = web.app.state.db
    assert db.get_review(pid, "73001") is None and db.get_review(pid, "73002") is None


def test_card_update_answer_without_version_names_no_target(web):  # noqa: F811
    pid = prepared(web)
    item = answer("example-parser", "1.4.2", recommended_version="", explanation="Уязвимость в разборе документа.")
    # ответ принят с предупреждением о пустой версии: страница с предупреждениями вместо перехода
    loaded = post_answers(web, pid, answers_json(item))
    assert loaded.status_code in (200, 303), loaded.text[:300]
    assert web.app.state.db.sca_answers(pid, "example-parser", "1.4.2", "maven"), "ответ не сохранён"
    _, card = sca_card(web, pid, "73001")
    text = comment_field(card)
    assert text.startswith("Обновить example-parser с версии 1.4.2.\n"), text
    assert "1.4.9" not in text and "безопасн" not in text.lower()


def test_legacy_hub_draft_is_recognized_with_agent_answer_loaded(web):  # noqa: F811
    """Ответ агента загружен, но прежняя заготовка по данным Hub сохранена под «Ложное срабатывание»: она по-прежнему
    текст под «обновить» – копирование без «Текст проверен» отклоняется."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}/review"
    saved = web.client.post(url, headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": LEGACY_HUB_SUGGESTION, "action": "save"})
    assert saved.status_code == 200, saved.text
    _, card = sca_card(web, pid, "73002")
    assert 'data-comment-for="true_positive"' in card
    short = web.client.post(url, headers={**ORIGIN, "Accept": "application/json"}, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": LEGACY_HUB_SUGGESTION, "action": "copy"})
    assert short.status_code == 409 and short.json()["reason"] == "comment", short.text
