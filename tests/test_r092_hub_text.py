"""Замечания ревью 0.9.2 (docs/codex/audits/2026-10-21): в текст для Hub уходит решение человека, а не ответ модели.

R092-01 – «Как исправить» модели входит в требования дефекта только при «Согласен» (ADR-0088);
R092-02 – комментарий модели к другому вердикту не выдаётся молча ни коротким, ни полным текстом (SAST и SCA);
R092-03 – короткий текст SAST не копируется без выбранного решения."""

from __future__ import annotations

import html
import re

from test_audit_lta001b import HUB_ID, bind_model_verdict
from test_defect import save_sast
from test_sca import (LEGACY_HUB_SUGGESTION, answer, answers_json, form_fields, post_answers, sca_card,
                      shown_fields)
from test_web import shown_hash, ORIGIN, prepared, web  # noqa: F401


JSON = {**ORIGIN, "Accept": "application/json"}
REJECTED_FIX = "Исправление не требуется, поскольку это ложное срабатывание."


def card_fields(web, url: str) -> dict:  # noqa: F811
    card = web.client.get(url).text
    return {key: re.search(rf'name="{key}" value="([^"]*)"', card).group(1)
            for key in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}


def bind_verdict(web, pid: int, verdict: str, comment: str, fix: str) -> None:  # noqa: F811
    """Ответ модели с заданным вердиктом, комментарием и рекомендацией, привязанный к находке HUB_ID."""
    bind_model_verdict(web, pid, fix=fix)
    db = web.app.state.db
    case = db.get_case(pid, HUB_ID)
    vid = db.save_verdict(case["case_hash"], "demo-model", "sast-v6",
                          {"verdict": verdict, "confidence": 90, "hub_comment": comment, "fix": fix}, {})
    assert db.save_case(pid, HUB_ID, case["case_hash"], case["context"], vid)


# ---------------------------------------------------------------- R092-01

def test_rejected_model_fix_not_exported_as_operator_requirement(web):  # noqa: F811
    pid = prepared(web)
    bind_model_verdict(web, pid, fix=REJECTED_FIX)
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Подтверждено вручную: пользователь управляет SQL.",
                       fix="Свой пункт оператора.")
    result = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert result.status_code == 200, result.text
    body = result.json()["body"]
    # рекомендация – только своя (ADR-0092): ни рекомендации модели, ни общего пункта
    assert REJECTED_FIX not in body and body.endswith("Рекомендация:\n1) Свой пункт оператора.")


def test_agreed_model_fix_is_not_copied_into_the_defect_by_itself(web):  # noqa: F811
    """«Согласен» с вердиктом модели не переносит её рекомендацию в дефект (ADR-0092): в тексте – пункты оператора."""
    pid = prepared(web)
    fix = "Передавать значение в запрос через параметр, а не склеивать строку."
    bind_verdict(web, pid, "true_positive", "Значение из запроса попадает в SQL без параметров.", fix)
    url, _ = save_sast(web, pid, HUB_ID, "agree", "", "Значение из запроса попадает в SQL без параметров.",
                       fix="Свой пункт.")
    result = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert result.status_code == 200, result.text
    assert fix not in result.json()["body"] and result.json()["body"].endswith("1) Свой пункт.")


def test_disagree_with_same_outcome_does_not_take_model_fix(web):  # noqa: F811
    """«Не согласен» с тем же итогом – человек не принимал ответ модели целиком: её рекомендация не переносится."""
    pid = prepared(web)
    fix = "Передавать значение в запрос через параметр, а не склеивать строку."
    bind_verdict(web, pid, "true_positive", "Разбор модели.", fix)
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Своё обоснование: вход из запроса.")
    result = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert result.status_code == 200, result.text
    assert fix not in result.json()["body"]


# ---------------------------------------------------------------- R092-02

def test_wrong_verdict_model_comment_not_exported_through_full_defect(web):  # noqa: F811
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)
    # короткий текст у подтверждённого дефекта не копируется вовсе (ADR-0089): в Hub уходит текст дефекта
    short = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "true_positive", "final_verdict": "", "comment": comment,
        "action": "copy"})
    assert short.status_code == 400 and "только при решении «Ложное срабатывание»" in short.json()["detail"]
    full = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert full.status_code == 409 and full.json()["reason"] == "comment", full.text
    assert "Текст проверен" in full.json()["detail"]
    db = web.app.state.db
    revision = str(db.get_review(pid, HUB_ID)["revision"])
    # в карточке полный текст с таким обоснованием не показывается – только пояснение и отметка в форме дефекта
    card = web.client.get(url).text
    assert 'id="defect-body-hidden"' in card and comment not in card.split('id="defect-body-text"')[1].split("</pre>")[0]
    assert 'name="comment_confirmed"' in card and f'name="review_revision" value="{revision}"' in card
    # «Текст проверен» – тот же выбор, что у короткого текста: полный текст выдаётся
    confirmed = web.client.post(url + "/defect", headers=JSON, data={
        "number": "1", "comment_confirmed": "1", "review_revision": revision})
    assert confirmed.status_code == 200, confirmed.text
    # отметка без редакции (старая страница) не принимается
    old_page = web.client.post(url + "/defect", headers=JSON, data={"number": "1", "comment_confirmed": "1"})
    assert old_page.status_code == 409 and old_page.json()["reason"] == "comment"
    # без скрипта: отказ – карточка с пояснением; с отметкой – карточка, где выданный текст виден
    plain = web.client.post(url + "/defect", headers=ORIGIN, data={"number": "1"}, follow_redirects=False)
    assert plain.status_code == 409 and "Текст проверен" in plain.text
    plain_ok = web.client.post(url + "/defect", headers=ORIGIN, data={
        "number": "1", "comment_confirmed": "1", "review_revision": revision}, follow_redirects=False)
    assert plain_ok.status_code == 200 and "Рекомендация:" in plain_ok.text


def test_wrong_verdict_model_comment_not_copied_as_false_positive_note(web):  # noqa: F811
    """Тот же запрет для короткого комментария ложного срабатывания: текст модели написан к «истинной»,
    а в Hub уйдёт «ложная» – молча не копируется (R092-02 в карточке 0.9.6)."""
    pid = prepared(web)
    comment = "Подтверждено: значение из запроса попадает в SQL без параметров."
    bind_verdict(web, pid, "true_positive", comment, "Параметризовать.")
    db = web.app.state.db
    url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, HUB_ID)['id']}"
    refused = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "false_positive", "final_verdict": "", "comment": comment,
        "action": "copy"})
    assert refused.status_code == 409 and refused.json()["reason"] == "comment", refused.text
    assert "к вердикту «истинная», а в Hub уйдёт вердикт «ложная»" in refused.json()["detail"]
    # своё обоснование копируется без условий
    own = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "false_positive", "final_verdict": "",
        "comment": "Имя таблицы берётся из заранее заданной строки.", "action": "copy"})
    assert own.status_code == 200 and own.json()["copy_allowed"] is True, own.text


def test_confirmation_from_another_tab_does_not_apply_to_changed_decision(web):  # noqa: F811
    """Вкладка A отметила «Текст проверен» по одной редакции, вкладка B сохранила решение заново: отметка A не действует."""
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)
    seen = str(web.app.state.db.get_review(pid, HUB_ID)["revision"])
    save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)  # вкладка B: та же правка, новая редакция
    stale = web.client.post(url + "/defect", headers=JSON, data={
        "number": "1", "comment_confirmed": "1", "review_revision": seen})
    # с 0.9.6 выдача к другой редакции решения отклоняется раньше проверки комментария (ADR-0089)
    assert stale.status_code == 409 and "другой вкладке" in stale.json()["detail"], stale.text
    assert "другой вкладке" in stale.json()["detail"]


def test_own_comment_full_defect_needs_no_confirmation(web):  # noqa: F811
    pid = prepared(web)
    bind_verdict(web, pid, "false_positive", "Ложное срабатывание: вход ограничен.", "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Своё обоснование: вход из запроса.")
    result = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert result.status_code == 200, result.text


def test_sca_full_copy_checks_comment_like_short_copy(web):  # noqa: F811
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    comment = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    assert comment.strip()
    saved = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": comment,
        "action": "save"})
    assert saved.status_code == 200, saved.text
    card = web.client.get(url).text
    short = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": comment,
        "action": "copy"})
    assert short.status_code == 409 and short.json()["reason"] == "comment"
    # «ложное срабатывание» в SCA – только короткий комментарий, полного текста нет (ADR-0091 п. 3)
    full = web.client.post(url + "/defect", headers=JSON, data={"number": "1"})
    assert full.status_code == 409 and "коротким комментарием" in full.json()["detail"], full.text


# ---------------------------------------------------------------- R092-03

def test_sast_copy_requires_explicit_operator_decision(web):  # noqa: F811
    pid = prepared(web)
    bind_model_verdict(web, pid)
    db = web.app.state.db
    url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, HUB_ID)['id']}"
    result = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "", "final_verdict": "false_positive", "comment": "Разбор.",
        "action": "copy"})
    assert result.status_code == 400
    assert "Ответ модели ещё не принят" in result.json()["detail"]
    review = db.get_review(pid, HUB_ID)
    assert not review or not review.get("copied_at")  # отказ не ставит дату копирования
    # черновик без решения по-прежнему сохраняется
    saved = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "", "final_verdict": "", "comment": "Черновик разбора.",
        "action": "save"})
    assert saved.status_code == 200, saved.text


def test_sast_explicit_decision_and_own_comment_can_be_copied(web):  # noqa: F811
    pid = prepared(web)
    bind_model_verdict(web, pid)
    comment = "Проверено вручную: вход ограничен заранее заданным набором."
    url, _ = save_sast(web, pid, HUB_ID, "false_positive", "", comment)
    result = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "false_positive", "final_verdict": "", "comment": comment,
        "action": "copy"})
    assert result.status_code == 200 and result.json()["copy_allowed"] is True
    assert result.json()["hub_text"] == comment


# ---------------------------------------------------------------- гонки вкладок (второй круг ревью 0.9.3)

def test_no_js_reveal_only_for_the_revision_that_was_confirmed(web, monkeypatch):  # noqa: F811
    """Без скрипта текст выдан по отметке «Текст проверен», а до показа карточки решение сохранили заново в другой
    вкладке: карточка не раскрывает полный текст новой, неподтверждённой редакции."""
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)
    db = web.app.state.db
    seen = int(db.get_review(pid, HUB_ID)["revision"])
    original = db.set_defect_number_checked

    def other_tab_saves_after_number(*args, **kwargs):
        result = original(*args, **kwargs)
        current = db.get_review(pid, HUB_ID)
        db.save_review(pid, HUB_ID, decision="disagree", final_verdict="true_positive", final_comment=comment,
                       reviewed=True, verdict_id=current.get("verdict_id"), code_hash=current.get("code_hash"),
                       code_chars=int(current.get("code_chars") or 0))
        return result

    monkeypatch.setattr(db, "set_defect_number_checked", other_tab_saves_after_number)
    page = web.client.post(url + "/defect", headers=ORIGIN, data={
        "number": "1", "comment_confirmed": "1", "review_revision": str(seen)}, follow_redirects=False)
    assert page.status_code == 200
    assert int(db.get_review(pid, HUB_ID)["revision"]) != seen
    assert 'id="defect-body-hidden"' in page.text, "новая редакция не подтверждена – текст не раскрывается"


def test_sca_short_copy_gives_no_text_of_a_foreign_revision(web, monkeypatch):  # noqa: F811
    """После записи решения SCA, до снимка, решение сохранили в другой вкладке: короткий текст не выдаётся и в ответе."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    db = web.app.state.db
    original = db.sca_snapshot
    calls = []

    def other_tab_saves_before_snapshot(project_id, hub_id):
        if not calls:
            calls.append(1)
            current = db.get_review(project_id, hub_id)
            db.save_review(project_id, hub_id, decision="disagree", final_verdict="false_positive",
                           final_comment="Чужая вкладка: другое обоснование.", reviewed=True,
                           answer_sig=current.get("answer_sig"))
        return original(project_id, hub_id)

    monkeypatch.setattr(db, "sca_snapshot", other_tab_saves_before_snapshot)
    result = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": "Своё обоснование: уязвимая функция не вызывается.", "action": "copy"})
    assert calls, "снимок не запрашивался"
    data = result.json()
    assert data.get("copy_allowed") is False, data
    assert not data.get("hub_text"), "текст чужой редакции не выдаётся в ответе"
    assert "другой вкладке" in (data.get("notice") or data.get("detail") or "")


def test_sca_defect_text_does_not_take_neighbour_comments(web):  # noqa: F811
    """Полный текст дефекта SCA строится из текста набора (Объяснение оператора), а не из комментариев находок: текст
    агента в комментарии соседки с другим исходом в дефект не попадает и выдачу не блокирует (ADR-0091)."""
    pid = prepared(web)
    # набор только с AST дефекта не даёт (ADR-0101): публичное соответствие для находки отдельного набора
    web.app.state.db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid2, card2 = sca_card(web, pid, "73002")
    url2 = f"/projects/{pid}/sca/findings/{fid2}"
    agent_text = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card2, re.S).group(1))
    assert agent_text.strip()
    assert web.client.post(url2 + "/review", headers=JSON, data={
        **form_fields(card2), "decision": "disagree", "final_verdict": "false_positive", "comment": agent_text,
        "action": "save"}).status_code == 200
    fid1, card1 = sca_card(web, pid, "73001")
    url1 = f"/projects/{pid}/sca/findings/{fid1}"
    assert web.client.post(url1 + "/review", headers=JSON, data={
        **form_fields(card1), "decision": "disagree", "final_verdict": "true_positive",
        "comment": "Обновить: уязвимая функция вызывается.", "action": "save"}).status_code == 200
    assert web.client.post(url1 + "/package-text", headers=JSON, data={
        "text_revision": "0", "target_version": "1.4.9"}).status_code == 200
    # «Версию проверил сам» – к проверке, которую карточка уже показала (ревью 82103ee)
    done = web.client.post(url1 + "/package-text", headers=JSON, data={
        **shown_fields(web.client.get(url1).text), "text_revision": "1", "target_version": "1.4.9",
        "version_checked": "1",
        "explanation": "CVE-2099-10002: Уязвимость функции разбора документа позволяет прочитать файлы сервера."})
    assert done.status_code == 200 and done.json()["ready"] is True, done.text
    full = web.client.post(url1 + "/defect", headers=JSON, data={"number": "1"})
    assert full.status_code == 200, full.text
    body = full.json()["body"]
    assert agent_text.strip()[:40] not in body and "73002 – не применимо" in full.json()["note"]


def test_sca_hub_suggestion_counts_as_agent_text(web):  # noqa: F811
    """Совместимость: прежняя заготовка «Обновить … (безопасная версия по данным Hub)» (до 0.9.11, ADR-0100) означает
    «обновить»: под «не применимо» или «Риск принят» она не уходит молча. Новая карточка такой заготовки не предлагает."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    assert "безопасная версия по данным Hub" not in card
    suggestion = LEGACY_HUB_SUGGESTION
    saved = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": suggestion,
        "action": "save"})
    assert saved.status_code == 200, saved.text
    card = web.client.get(url).text
    assert 'data-comment-for="true_positive"' in card
    assert "Текст не показан" in card
    short = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": suggestion,
        "action": "copy"})
    assert short.status_code == 409 and short.json()["reason"] == "comment", short.text
    revision = str(web.app.state.db.get_review(pid, "73002")["revision"])
    entered = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                                    "text_hash": shown_hash(web.client, url)})
    assert entered.status_code == 409 and entered.json()["reason"] == "comment"
    # та же заготовка под «обновить» – своё, согласованное обоснование
    ok = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "true_positive", "comment": suggestion,
        "action": "save"})
    assert ok.status_code == 200, ok.text  # у «обновить» короткого текста нет: только сохранение


def test_preview_and_entered_mark_follow_the_comment_check(web):  # noqa: F811
    """Без решения предпросмотр пуст; с комментарием модели к другому вердикту – пояснение, отметка «внесено» –
    только с «Текст проверен» и редакцией; со своим обоснованием – текст и отметка без условий."""
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    db = web.app.state.db
    url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, HUB_ID)['id']}"
    card = web.client.get(url).text
    assert "Текст появится после выбора и сохранения решения" in card
    assert re.search(r'<pre id="hub-text" class="hub-text"></pre>', card)
    save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)
    card = web.client.get(url).text
    assert "Текст не показан" in card and comment not in card.split('id="hub-text"')[1].split("</pre>")[0]
    revision = str(db.get_review(pid, HUB_ID)["revision"])
    refused = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                                    "text_hash": shown_hash(web.client, url)})
    assert refused.status_code == 409 and refused.json()["reason"] == "comment"
    assert not db.get_review(pid, HUB_ID)["entered_hub"]
    confirmed = web.client.post(url + "/entered", headers=JSON, data={
        "entered": "1", "review_revision": revision, "comment_confirmed": "1",
        "text_hash": shown_hash(web.client, url)})
    assert confirmed.status_code == 200 and confirmed.json()["entered"] is True
    save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Своё обоснование: вход из запроса.")
    card = web.client.get(url).text
    assert 'id="hub-preview-note" hidden' in card
    assert "Своё обоснование: вход из запроса." in card.split('id="hub-text"')[1].split("</pre>")[0]
    revision = str(db.get_review(pid, HUB_ID)["revision"])
    plain = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                                    "text_hash": shown_hash(web.client, url)})
    assert plain.status_code == 200


# ---------------------------------------------------------------- второй круг приёмочного ревью

def test_plain_save_json_gives_no_text_without_decision_or_with_model_comment(web):  # noqa: F811
    """Обычное сохранение (JSON) отдаёт текст для Hub только при тех же условиях, что копирование; черновик сохраняется."""
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    db = web.app.state.db
    url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, HUB_ID)['id']}"
    draft = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "", "final_verdict": "false_positive", "comment": comment, "action": "save"})
    assert draft.status_code == 200 and draft.json()["copy_allowed"] is False and draft.json()["hub_text"] == ""
    stale = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "disagree", "final_verdict": "true_positive", "comment": comment,
        "fix": "Параметризовать запрос.", "action": "save"})
    assert stale.status_code == 200 and stale.json()["copy_allowed"] is False and stale.json()["hub_text"] == ""
    assert db.get_review(pid, HUB_ID)["final_verdict"] == "true_positive"  # сохранено
    own = web.client.post(url + "/review", headers=JSON, data={
        **card_fields(web, url), "decision": "disagree", "final_verdict": "true_positive",
        "comment": "Своё обоснование: вход из запроса.", "fix": "Параметризовать запрос.", "action": "save"})
    assert own.status_code == 200 and own.json()["copy_allowed"] is True
    assert own.json()["hub_text"] == "Своё обоснование: вход из запроса."


def test_sca_plain_save_json_gives_no_text_with_suggestion_under_other_outcome(web):  # noqa: F811
    """Совместимость: прежняя заготовка по данным Hub (до 0.9.11, ADR-0100), сохранённая под другим исходом."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    suggestion = LEGACY_HUB_SUGGESTION
    saved = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": suggestion,
        "action": "save"})
    assert saved.status_code == 200 and saved.json()["copy_allowed"] is False and saved.json()["hub_text"] == ""


def test_entered_form_works_without_script_and_requires_revision(web):  # noqa: F811
    """Форма отметки несёт редакцию и флажок «Текст проверен» сама (без скрипта); без редакции отметка не ставится."""
    pid = prepared(web)
    comment = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", comment, "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", comment)
    db = web.app.state.db
    revision = str(db.get_review(pid, HUB_ID)["revision"])
    card = web.client.get(url).text
    form = card.split('id="entered-form"')[1].split("</form>")[0]
    assert f'name="review_revision" value="{revision}"' in form
    assert 'id="entered-confirm-label">' in form and 'name="comment_confirmed"' in form  # виден: комментарий спорный
    no_revision = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "comment_confirmed": "1"})
    assert no_revision.status_code == 409 and no_revision.json()["reason"] == "revision"
    plain = web.client.post(url + "/entered", headers=ORIGIN, follow_redirects=False, data={
        "entered": "1", "review_revision": revision, "comment_confirmed": "1",
        "text_hash": shown_hash(web.client, url)})
    assert plain.status_code == 303 and plain.headers["location"].endswith("ok=entered")
    assert db.get_review(pid, HUB_ID)["entered_hub"]
    save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Своё обоснование: вход из запроса.")
    card = web.client.get(url).text
    assert 'id="entered-confirm-label" hidden' in card.split('id="entered-form"')[1].split("</form>")[0]


def test_sca_hub_suggestion_recognized_when_vulnerability_list_changed(web):  # noqa: F811
    """Прежняя заготовка по данным Hub (до 0.9.11) узнаётся по заголовку: перечень уязвимостей во второй строке мог
    измениться с картой."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    suggestion = LEGACY_HUB_SUGGESTION
    changed = suggestion.split("\n")[0] + "\nУязвимости: CVE-2099-10001, CVE-2099-99999."
    saved = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": changed,
        "action": "save"})
    assert saved.status_code == 200, saved.text
    card = web.client.get(url).text
    short = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": changed,
        "action": "copy"})
    assert short.status_code == 409 and short.json()["reason"] == "comment", short.text


def test_preview_is_the_saved_text_after_rerun(web):  # noqa: F811
    """После повторного разбора с другим вердиктом предпросмотр показывает сохранённый текст – тот, что подтверждает
    отметка, – а не статус нового ответа модели."""
    pid = prepared(web)
    bind_verdict(web, pid, "false_positive", "Разбор модели.", "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "agree", "", "Своё обоснование: вход ограничен константой.")
    bind_verdict(web, pid, "true_positive", "Новый разбор.", "Параметризовать.")
    card = web.client.get(url).text
    preview = card.split('id="hub-text"')[1].split("</pre>")[0]
    assert "Своё обоснование: вход ограничен константой." in preview and "Новый разбор." not in preview


# ---------------------------------------------------------------- третий круг приёмочного ревью

def test_stale_check_follows_saved_decision_not_current_model_answer(web):  # noqa: F811
    """Модель: «ложная» (С1) → оператор согласен → новый разбор «истинная» → обычное сохранение с С1 → снова «ложная» (С1).
    Сохранено «Согласен, истинная» с комментарием к «ложной»: предпросмотр скрыт, флажок формы отметки виден,
    отметка без «Текст проверен» – отказ."""
    pid = prepared(web)
    c1 = "Ложное срабатывание: входные данные ограничены допустимым набором."
    bind_verdict(web, pid, "false_positive", c1, "Не требуется.")
    url, _ = save_sast(web, pid, HUB_ID, "agree", "", c1)
    bind_verdict(web, pid, "true_positive", "Значение из запроса попадает в SQL.", "Параметризовать.")
    save_sast(web, pid, HUB_ID, "agree", "", c1)
    bind_verdict(web, pid, "false_positive", c1, "Не требуется.")
    db = web.app.state.db
    assert db.get_review(pid, HUB_ID)["final_verdict"] == "true_positive"
    card = web.client.get(url).text
    assert "Текст не показан" in card
    assert 'id="entered-confirm-label">' in card.split('id="entered-form"')[1].split("</form>")[0]
    revision = str(db.get_review(pid, HUB_ID)["revision"])
    refused = web.client.post(url + "/entered", headers=JSON, data={"entered": "1", "review_revision": revision,
                                                                    "text_hash": shown_hash(web.client, url)})
    assert refused.status_code == 409 and refused.json()["reason"] == "comment"


def test_rejected_draft_has_no_preview(web):  # noqa: F811
    """Сохранение отклонено (устаревшая редакция), форма – с черновиком: предпросмотра несохранённого текста нет."""
    pid = prepared(web)
    bind_model_verdict(web, pid)
    url, _ = save_sast(web, pid, HUB_ID, "disagree", "true_positive", "Своё обоснование: вход из запроса.")
    page = web.client.post(url + "/review", headers=ORIGIN, data={
        **card_fields(web, url), "review_revision": "99", "decision": "disagree", "final_verdict": "false_positive",
        "comment": "Другое, несохранённое обоснование.", "action": "save"})
    assert page.status_code == 409 and 'data-draft="1"' in page.text
    assert "Решение не сохранено: текст появится после сохранения" in page.text
    assert "несохранённое обоснование" not in page.text.split('id="hub-text"')[1].split("</pre>")[0]


def test_sca_agent_text_recognized_when_vulnerability_list_changed(web):  # noqa: F811
    """Текст агента узнаётся по началу: перечень уязвимостей мог измениться после загрузки соответствий AST → CVE."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    suggestion = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    assert suggestion.startswith("Обновить ")
    changed = suggestion.split("\n")[0] + "\nУязвимости: CVE-2099-10001, CVE-2099-99999."
    saved = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": changed,
        "action": "save"})
    assert saved.status_code == 200 and saved.json()["copy_allowed"] is False
    card = web.client.get(url).text
    short = web.client.post(url + "/review", headers=JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": changed,
        "action": "copy"})
    assert short.status_code == 409 and short.json()["reason"] == "comment", short.text
