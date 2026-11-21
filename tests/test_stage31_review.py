"""Этап 3.1: замечания независимой проверки версии 0.3.0 (docs/state/review-stage-3.md).

* SCA: ответ без охвата (загружен до этапа 3) не применяется ни к одной уязвимости; соответствия AST → CVE входят
  в отпечаток ответа; дефект строится по действующим решениям человека по каждой находке библиотеки; заголовок,
  похожий на путь, – только с подтверждением; шаг обновления базы 3 → 4.
* «Внесено в Hub» без отпечатка текста (поставлено до этапа 3) – «текст не подтверждён после обновления».
* Дефект SAST: ссылки на строки в обосновании и рекомендациях сверяются с показанным кодом перед выдачей.
"""

from __future__ import annotations

import re
from db_support import connect_db
from pathlib import Path


from app.db import Database
from app.models import ScaAnswer
from app.routes import sca as sca_routes
from app.routes.findings import line_warnings
from test_db_stage2 import load, sca
from test_defect import save_sast
from test_sca import AS_JSON, answer, answers_json, form_fields, post_answers, sca_card, shown_fields
from test_web import shown_hash, ORIGIN, prepared, start_run, wait_run, web  # noqa: F401


def save_sca(web, pid: int, hub_id: str, decision: str, verdict: str, comment: str) -> tuple[str, dict]:
    fid, card = sca_card(web, pid, hub_id)
    url = f"/projects/{pid}/sca/findings/{fid}"
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": decision, "final_verdict": verdict, "reviewed": "1", "comment": comment,
        "action": "save"})
    return url, r.json() if r.headers.get("content-type", "").startswith("application/json") else {"status": r.status_code}


# ============================================================================ охват ответа и отпечаток

def test_answer_without_scope_is_not_applied_to_any_vulnerability(web):
    """Ответ, загруженный до этапа 3 (охват пуст), не охватывает уязвимости находки: «Согласен с агентом»
    недоступно, карточка говорит «охват неизвестен»; новая CVE после обновления тем более не охвачена."""
    pid = prepared(web)
    db = web.app.state.db
    db.save_sca_answers(pid, "Агент 1", [ScaAnswer(component="example-parser", version="1.4.2",
                                                   conclusion="update", recommended_version="1.4.9",
                                                   explanation="Исправлено в 1.4.9.")])
    [stored] = db.sca_answers(pid)
    assert stored["vulnerabilities"] == []
    f = db.get_finding_by_hub_id(pid, "73001")
    from app.models import Finding
    finding = Finding.from_dict(f["data"])
    assert sca_routes.answer_covers(finding, stored) is False and sca_routes.scope_unknown(stored)
    assert sca_routes.answer_verdict(finding, stored) == ""
    _, card = sca_card(web, pid, "73001")
    assert 'id="scope-unknown"' in card and 'id="answer-stale"' not in card
    url, saved = save_sca(web, pid, "73001", "agree", "true_positive", "Обновить.")
    assert saved.get("ok") is not True  # «Согласен» без действующего ответа не сохраняется
    # находка без идентификаторов уязвимостей: сверять нечего – ответ применим
    bare = Finding(hub_id="x", kind="SCA", component="a", version="1")
    assert sca_routes.answer_covers(bare, stored) is True


def test_agree_from_before_stage_3_is_shown_as_unconfirmed(web):
    """«Согласен с агентом» без отпечатка ответа (принято до этапа 3): не «ответ изменился», а «неизвестно, по какому
    ответу»; дефект не готов, подсказка говорит, что сделать."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    db = web.app.state.db
    db.save_review(pid, "73001", decision="agree", final_verdict="true_positive", final_comment="c", reviewed=True,
                   answer_sig="")
    fid, card = sca_card(web, pid, "73001")
    assert 'id="agree-unconfirmed"' in card and 'id="answer-changed"' not in card
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/defect", headers=AS_JSON, data={"number": ""})
    assert r.status_code == 409 and "до обновления приложения" in r.json()["detail"]


def test_ids_mapping_is_part_of_answer_signature():
    base = dict(component="a", version="1", conclusion="update", recommended_version="2", explanation="e",
                vulnerabilities=["AST-1"])
    one = ScaAnswer(**base, ids={"AST-1": ["CVE-2099-0001"]})
    same = ScaAnswer(**base, ids={"ast-1": ["cve-2099-0001"]})
    other = ScaAnswer(**base, ids={"AST-1": ["CVE-2099-0002"]})
    assert one.signature() == same.signature() != other.signature()


def test_new_cve_under_same_ast_reopens_agreed_findings(tmp_path: Path):
    """Смена CVE под тем же AST при прежних выводе, версии и охвате снимает «Проверено» у «Согласен с агентом»."""
    db = Database(tmp_path / "triage.db")
    try:
        pid = db.create_project("Проект")
        load(db, pid, [sca("1", vuln="AST-1")])
        first = ScaAnswer(component="org.example:example-parser", version="1.4.2", conclusion="update",
                          recommended_version="1.4.9", explanation="e", ids={"AST-1": ["CVE-2099-0001"]},
                          vulnerabilities=["AST-1"])
        db.save_sca_answers(pid, "Агент", [first])
        db.save_review(pid, "1", decision="agree", final_verdict="true_positive", final_comment="c", reviewed=True,
                       answer_sig=first.signature())
        second = ScaAnswer(**{**first.to_dict(), "ids": {"AST-1": ["CVE-2099-0002"]}})
        assert db.save_sca_answers(pid, "Агент", [second])["reopened"] == 1
        assert db.get_review(pid, "1")["reviewed"] == 0
    finally:
        db.close()


# ============================================================================ шаг обновления базы 3 → 4

def _as_v3(path: Path) -> None:
    """База приложения, переписанная так, как её оставила схема 3: отпечатки решений – по прежнему правилу."""
    conn = connect_db(path)
    conn.execute("UPDATE meta SET value = '3' WHERE key = 'schema_version'")
    conn.execute("DELETE FROM schema_version WHERE version >= 4")
    conn.commit()
    conn.close()


# ============================================================================ дефект SCA по решениям группы

def test_sca_false_positive_gives_short_comment_not_defect(web):
    """«Ложное срабатывание» в SCA закрывается коротким комментарием, дефект не создаётся (ADR-0091 п. 3)."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    url, saved = save_sca(web, pid, "73001", "disagree", "false_positive",
                          "Не затронута: уязвимый метод разбора в проекте не вызывается.")
    assert saved["defect_ready"] is False
    r = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "4"})
    assert r.status_code == 409 and "коротким комментарием" in r.json()["detail"], r.text


def test_sca_defect_lists_other_outcomes_and_blocks_stale_answer(web):
    """Другой исход у соседней находки версии дефект не блокирует – она перечислена «в дефект не входят»; отложенная –
    тоже. Новый ответ агента делает прежнее «Согласен» недействующим – дефект недоступен до новой проверки."""
    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    url, _ = save_sca(web, pid, "73001", "agree", "true_positive", "Обновить до 1.4.9.")
    url2, saved2 = save_sca(web, pid, "73002", "disagree", "false_positive", "Не затронута.")
    assert saved2["defect_ready"] is False
    card = web.client.get(url).text
    revision = re.search(r'name="text_revision" value="(\d+)"', card)
    data = {"text_revision": revision.group(1) if revision else "0", "version_checked": "1", **shown_fields(card)}
    web.client.post(f"{url}/package-text", headers=AS_JSON, data=data)
    done = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(web.client.get(url).text), "text_revision": "1", "version_checked": "1",
        "explanation": "CVE-2099-10002: Уязвимость функции разбора документа позволяет прочитать файлы сервера."}).json()
    assert done["ready"] is True, done
    got = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5"})
    assert got.status_code == 200 and "73002 – не применимо" in got.json()["note"], got.text
    save_sca(web, pid, "73002", "later", "", "Позже.")
    got = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5"}).json()
    assert "73002 – отложено" in got["note"]
    # новый ответ агента: прежнее «Согласен» больше не действует – дефект недоступен до новой проверки
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", recommended_version="1.5.0"),
                                               source="Агент 2")).status_code in (200, 303)
    r = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5"})
    assert r.status_code == 409 and "прежнему ответу" in r.json()["detail"]
    _, card = sca_card(web, pid, "73001")
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in card


def test_sca_title_that_looks_like_a_path_needs_confirmation():
    assert sca_routes.title_warnings("C:/private/project", "1.0")
    assert sca_routes.title_warnings("src/Foo.java", "1.0")
    assert sca_routes.title_warnings("org.example:example-parser", "1.4.2") == []
    assert sca_routes.title_warnings("@types/chart.js", "4.0.0") == []


# ============================================================================ «Внесено в Hub» без отпечатка

def test_entered_mark_without_hash_asks_to_confirm_again(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    url, _ = save_sast(web, pid, "510001", "disagree", "true_positive", "Подтверждено: owner из запроса.")
    db = web.app.state.db
    db.mark_entered(pid, "510001", True)  # как отметка, перенесённая из схемы 2: отпечатка нет
    assert db.get_review(pid, "510001")["entered_text_hash"] == ""
    card = web.client.get(url).text
    assert 'id="entered-unconfirmed"' in card and "Текст не подтверждён после обновления" in card
    assert not re.search(r'id="mark-entered" hidden', card) and "Подтвердить: " in card
    revision = re.search(r'name="review_revision" value="(\d+)"', card).group(1)
    r = web.client.post(f"{url}/entered", headers={**ORIGIN, "Accept": "application/json"},
                        data={"entered": "1", "review_revision": revision, "text_hash": shown_hash(web.client, url)})
    assert r.status_code == 200 and "entered-unconfirmed" in r.json()["hide"]
    assert db.get_review(pid, "510001")["entered_text_hash"]
    assert 'id="entered-unconfirmed"' not in web.client.get(url).text


# ============================================================================ ссылки на строки в дефекте SAST

def test_line_warnings_check_reason_and_recommendations():
    shown = {10, 11, 12}
    assert line_warnings("Подтверждено: значение из запроса (строка 11).", "Исправить строку 12.", shown) == []
    warnings = line_warnings("Обоснование: строка 40.", "Исправить строку 999999.", shown)
    assert len(warnings) == 2 and "40" in warnings[0] and "999999" in warnings[1]
    # кода нет – не подтверждена ни одна ссылка
    assert line_warnings("См. строка 3.", "", None)


def test_sast_defect_with_unknown_line_needs_confirmation(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    url, saved = save_sast(web, pid, "510001", "disagree", "true_positive",
                           "Подтверждено: значение попадает в запрос (строка 999999).")
    assert saved["defect_ready"] is True
    card = web.client.get(url).text
    assert 'id="defect-warnings"' in card and "999999" in card and 'id="defect-confirm-row">' in card
    r = web.client.post(f"{url}/defect", headers={**ORIGIN, "Accept": "application/json"}, data={"number": ""})
    assert r.status_code == 409 and r.json()["reason"] == "confirm" and "999999" in " ".join(r.json()["warnings"])
    ok = web.client.post(f"{url}/defect", headers={**ORIGIN, "Accept": "application/json"},
                         data={"number": "", "confirm": "1"})
    assert ok.status_code == 200 and "строка 999999" in ok.json()["body"]
