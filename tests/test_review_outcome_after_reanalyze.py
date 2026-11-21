"""Исход SAST после нового разбора моделью (ADR-0097): форма карточки показывает исход человека, а не текущий вердикт
модели; пересохранение формы как есть не переворачивает решение и не снимает отметок переноса. Данные выдуманные,
модель – поддельная."""

from __future__ import annotations

import html as html_lib
import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from fake_ollama import verdict_answer  # noqa: E402
from test_code_snapshots import analysed, card_url, decide, form_of, web  # noqa: E402,F401
from test_web import ORIGIN  # noqa: E402

AS_JSON = {**ORIGIN, "Accept": "application/json"}
HUB_ID = "510001"


def checked_outcome(card: str) -> str:
    m = re.search(r'name="decision" value="(false_positive|true_positive|later)" form="review-form" checked', card)
    return m.group(1) if m else ""


def field(card: str, name: str) -> str:
    m = re.search(rf'<textarea name="{name}"[^>]*>(.*?)</textarea>', card, re.S)
    return html_lib.unescape(m.group(1)) if m else ""


def new_answer(web, pid: int, verdict: str) -> int:
    """Новый ответ модели по тому же срезу – как после «Пересмотреть вердикт»."""
    db = web.app.state.db
    case = db.get_case(pid, HUB_ID)
    verdict_id = db.save_verdict(case["case_hash"], "qwen2.5-coder:14b", "sast-v6", verdict_answer(verdict), {})
    db.save_case(pid, HUB_ID, case["case_hash"], case["context"], verdict_id)
    return verdict_id


def resave_as_shown(web, url: str) -> dict:
    """«Сохранить» без правок: браузер отправляет ровно то, что показала форма."""
    card = web.client.get(url).text
    data = {**form_of(card), "decision": checked_outcome(card), "comment": field(card, "comment"),
            "fix": field(card, "fix"), "reviewed": "1"}
    r = web.client.post(url + "/review", headers=AS_JSON, data=data)
    assert r.status_code == 200, r.text
    return r.json()


def test_false_positive_stays_after_new_true_positive_answer(web):
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    first = new_answer(web, pid, "false_positive")
    decide(web, pid, HUB_ID, decision="false_positive", verdict="false_positive",
           comment="Ложное: значение берётся из константы.")
    assert db.get_review(pid, HUB_ID)["decision"] == "agree"
    assert db.get_review(pid, HUB_ID)["final_verdict"] == "false_positive"
    assert new_answer(web, pid, "true_positive") != first
    card = web.client.get(url).text
    assert checked_outcome(card) == "false_positive"
    saved = db.get_review(pid, HUB_ID)
    assert db.mark_entered(pid, HUB_ID, revision=saved["revision"], entered_hash="h") is not None
    resave_as_shown(web, url)
    review = db.get_review(pid, HUB_ID)
    assert review["final_verdict"] == "false_positive"
    assert review["final_comment"] == "Ложное: значение берётся из константы."
    assert review["entered_hub"] == 1, "текст тот же – отметка остаётся"


def test_defect_keeps_outcome_fix_and_entered_mark_after_new_false_positive_answer(web):
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    new_answer(web, pid, "true_positive")  # решение «Подтверждаю дефект» совпадает с моделью – хранится как «Согласен»
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    saved = db.get_review(pid, HUB_ID)
    assert saved["decision"] == "agree"
    assert saved["final_fix"] == "Параметризовать запрос."
    assert db.mark_entered(pid, HUB_ID, revision=saved["revision"], entered_hash="h") is not None
    new_answer(web, pid, "false_positive")
    card = web.client.get(url).text
    assert checked_outcome(card) == "true_positive"
    resave_as_shown(web, url)
    review = db.get_review(pid, HUB_ID)
    assert review["final_verdict"] == "true_positive"
    assert review["final_fix"] == "Параметризовать запрос."  # у ложного срабатывания рекомендация очищается
    assert review["entered_hub"] == 1 and review["entered_text_hash"] == "h"  # текст тот же – отметка остаётся


def test_agree_without_stored_outcome_is_not_filled_from_the_model(web):
    """Запись «Согласен» без итога (интерфейс таких не создаёт) – исхода нет и в форме: карточка просит выбрать
    решение, а не приписывает человеку текущий вердикт модели (сервер считает такой итог «неясно»)."""
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    case = db.get_case(pid, HUB_ID)
    db.save_review(pid, HUB_ID, decision="agree", final_verdict="", final_comment="Прежнее решение",
                   reviewed=False, verdict_id=case["verdict_id"])
    new_answer(web, pid, "true_positive")
    assert checked_outcome(web.client.get(url).text) == ""


def test_removing_the_decision_drops_transfer_marks(web):
    """Решение снято (пустой вид решения при том же тексте) – отметки переноса не остаются."""
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    saved = db.get_review(pid, HUB_ID)
    assert db.mark_copied(pid, HUB_ID, saved["revision"])
    assert db.mark_entered(pid, HUB_ID, revision=saved["revision"], entered_hash="h") is not None
    card = web.client.get(url).text
    r = web.client.post(url + "/review", headers=AS_JSON, data={
        **form_of(card), "decision": "", "final_verdict": "true_positive", "comment": field(card, "comment"),
        "fix": field(card, "fix")})
    assert r.status_code == 200, r.text
    review = db.get_review(pid, HUB_ID)
    assert review["entered_hub"] == 0 and not review["entered_text_hash"] and not review["copied_at"]
