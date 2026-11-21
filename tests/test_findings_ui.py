"""Карточка и список находок, этап 2: объяснение модели для человека (что делает код, шаги со ссылками на строки,
что проверить глазами, словарик), «Спросить модель», «Пересмотреть вердикт», отметки «Проверено» и «Внесено
в Hub», комментарий модели к другому вердикту (п. 10 проверки этапа 1), фильтры списка."""

from __future__ import annotations

import re
import threading

from fake_ollama import ask_answer, default_reply, verdict_answer
from hub_fixtures import INVOICE, SAST_ROWS, make_hub_xlsx
from test_web import ORIGIN, create_project, prepared, start_run, upload, wait_run, web  # noqa: F401
from test_web_stage2 import AS_JSON, form_fields

WHY_58 = ["Значение `owner` приходит в метод извне (строка 57).",
          "Оно без защиты попадает в текст запроса (строка 58) и в строку 999 вне среза."]


def card_of(web, pid: int, hub_id: str, query: str = "") -> tuple[int, str]:
    fid = web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]
    return fid, web.client.get(f"/projects/{pid}/findings/{fid}{query}").text


def analysed(web, answer=None) -> int:
    """Проект с выгрузкой, папкой и прогоном; answer – ответ модели по умолчанию на время прогона."""
    pid = prepared(web)
    if answer is not None:
        web.fake.default_answer = answer
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    web.fake.default_answer = default_reply
    return pid


def save(web, pid: int, fid: int, card: str, **data):
    return web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=AS_JSON,
                           data={**form_fields(card), **data})


# ============================================================================ объяснение для человека

def test_card_explains_the_verdict_for_a_person(web):
    pid = analysed(web, verdict_answer("true_positive", 85, why=WHY_58, check_by_eye=[
        "Откуда приходит `owner` (строка 57).", "Как собирается запрос (строка 58)."]))
    _, card = card_of(web, pid, "510001")
    for part in ("Что делает код", "Почему такой вердикт", "Что проверить глазами", "Путь данных",
                 "Термины (1)", "уверенность высокая", "Как исправить", "истинная · 85%"):
        assert part in card, part
    assert '<ol class="steps">' in card and '<ul class="checklist" id="check-by-eye" data-store-key="finding-' in card
    assert 'class="conf-fill p-85"' in card and "data-checklist-count" in card
    assert "<dt><code>PreparedStatement</code></dt><dd>запрос с параметрами: данные передаются отдельно от текста запроса</dd>" in card
    # «строка N» – ссылка на показанную строку кода; строки вне среза ссылкой не становятся
    assert '<a class="line-ref" href="#L58">строка 58</a>' in card
    assert '<a class="line-ref" href="#L57">строка 57</a>' in card and 'href="#L999"' not in card
    assert "<code>owner</code>" in card and "разбор прежней версии" not in card


def test_previous_prompt_verdict_still_renders(web):
    pid = analysed(web)
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    old = db.save_verdict(case["case_hash"], "qwen2.5-coder:14b", "sast-v2", {
        "verdict": "false_positive", "confidence": 40, "summary": "Значение приводится к числу.",
        "explanation": "Строка 58 собирает запрос из числа.", "data_flow": ["строка 58: число в запросе"],
        "evidence_lines": [58], "fix": "", "hub_comment": "Ложное срабатывание: число (строка 58).", "cwe_fit": "да",
        "raw": {}}, {"eval_tps": 80.0})
    assert db.save_case(pid, "510001", case["case_hash"], case["context"], old)
    _, card = card_of(web, pid, "510001")
    assert "Почему такой вердикт" in card and "Что проверить глазами" not in card and "Термины" not in card
    assert '<a class="line-ref" href="#L58">Строка 58</a> собирает запрос из числа.' in card
    assert "уверенность низкая" in card and "conf-low" in card and "разбор прежней версии" in card
    assert '<tr id="L58" class="is-target">' in card


# ============================================================================ «Спросить модель»

def test_ask_the_model_from_the_card(web):
    pid = analysed(web)
    fid, card = card_of(web, pid, "510001")
    assert 'id="ask-form" data-ajax' in card and 'id="ask-question"' in card and "Вопросы к модели" in card
    # модель вердикта выбрана; в подписи – объём, параметры и рассуждение
    assert re.search(r'<select name="model" id="ask-model">\s*<option value="gpt-oss:20b">gpt-oss:20b \(12,8 ГБ, '
                     r'20\.9B, с рассуждением\)</option>\s*<option value="qwen2.5-coder:14b" selected>', card)
    web.fake.answers.append(ask_answer("Нет: `owner` подставляется в запрос (строка 58).", "нет"))
    r = web.client.post(f"/projects/{pid}/findings/{fid}/ask?cb=billing-core", headers=AS_JSON,
                        data={"question": "А если owner из сессии?", "model": "qwen2.5-coder:14b"})
    answer = r.json()
    assert r.status_code == 200 and answer["ok"] and answer["answered"]
    q = answer["question"]
    assert q["answer"].startswith("Нет:") and q["tps"] == 100.0 and not q["old"]
    assert answer["redirect"] == (f"/projects/{pid}/findings/{fid}?cb=billing-core&ok=asked&asked={q['id']}"
                                  f"#q{q['id']}")
    card = web.client.get(answer["redirect"].split("#")[0]).text
    assert f'<li class="qa-item" id="q{q["id"]}">' in card and "А если owner из сессии?" in card
    assert '<a class="line-ref" href="#L58">строка 58</a>' in card and "100,0 ток/с" in card
    assert "Модель ответила" in card
    # без скрипта – обычная форма: ответ в той же карточке
    r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=ORIGIN, follow_redirects=False,
                        data={"question": "Ещё вопрос?", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 303 and "ok=asked" in r.headers["location"]
    assert len(web.app.state.db.list_questions(pid, "510001")) == 2


def test_ask_answer_that_changes_the_verdict_gets_a_hint(web):
    pid = analysed(web)
    fid, _ = card_of(web, pid, "510001")
    web.fake.answers.append(ask_answer("Да, тогда это ложное срабатывание.", "да"))
    web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                    data={"question": "Если значение – число?", "model": "qwen2.5-coder:14b"})
    _, card = card_of(web, pid, "510001")
    assert "её вердикт другой" in card and "выберите решение по своему выводу в шаге 5" in card


def test_ask_refusals_and_model_errors(web):
    pid = analysed(web)
    fid, _ = card_of(web, pid, "510001")
    url = f"/projects/{pid}/findings/{fid}/ask"
    r = web.client.post(url, headers=AS_JSON, data={"question": " ", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 400 and r.json()["detail"] == "Напишите вопрос."
    r = web.client.post(url, headers=ORIGIN, data={"question": "x" * 2500, "model": "qwen2.5-coder:14b"})
    assert r.status_code == 400 and "Вопрос слишком длинный" in r.text and "x" * 2500 + "</textarea>" in r.text
    sca = web.app.state.db.get_finding_by_hub_id(pid, "73001")["id"]
    r = web.client.post(f"/projects/{pid}/findings/{sca}/ask", headers=AS_JSON,
                        data={"question": "Вопрос?", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 409 and "ещё не разбирала" in r.json()["detail"]
    assert web.client.post(url, data={"question": "Вопрос?"}).status_code == 403  # только со своей страницы
    web.fake.answers += ["не JSON", "снова не JSON"]
    r = web.client.post(url, headers=AS_JSON, data={"question": "Вопрос?", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 200 and not r.json()["answered"] and r.json()["question"]["state"] == "error"
    assert "ok=ask_failed" in r.json()["redirect"]
    card = web.client.get(r.json()["redirect"].split("#")[0]).text
    assert 'class="qa-item is-error"' in card and "Ответа нет: Модель дважды ответила не по формату" in card
    assert "Модель не ответила – причина ниже" in card and "Модель ответила" not in card


def test_pending_question_is_polled_until_answered(web):
    pid = analysed(web)
    db = web.app.state.db
    fid, _ = card_of(web, pid, "510001")
    case = db.get_case(pid, "510001")
    qid = db.add_question(pid, "510001", "Вопрос из другой вкладки?", "qwen2.5-coder:14b",
                          case_hash=case["case_hash"], verdict_id=case["verdict_id"])
    _, card = card_of(web, pid, "510001")
    assert (f'<li class="qa-item is-pending" id="q{qid}" data-poll="/projects/{pid}/findings/{fid}/questions/{qid}"'
            in card) and "Модель отвечает…" in card
    state = web.client.get(f"/projects/{pid}/findings/{fid}/questions/{qid}").json()
    assert (state["done"], state["question"]["state"]) == (False, "pending")
    db.finish_question(qid, answer="Готово.", answer_data={"answer": "Готово.", "verdict_changes": "нет"},
                       stats={"eval_tps": 50.0, "total_s": 2.0})
    state = web.client.get(f"/projects/{pid}/findings/{fid}/questions/{qid}").json()
    assert state["done"] and state["reload"] and state["question"]["answer"] == "Готово."
    other = db.get_finding_by_hub_id(pid, "510004")["id"]
    assert web.client.get(f"/projects/{pid}/findings/{other}/questions/{qid}").status_code == 404


def test_old_questions_are_marked_after_new_analysis(web):
    pid = analysed(web)
    fid, _ = card_of(web, pid, "510001")
    web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                    data={"question": "Первый?", "model": "qwen2.5-coder:14b"})
    web.fake.answers.append(verdict_answer("true_positive", 90))
    run_id = web.app.state.runner.enqueue(pid, "qwen2.5-coder:14b", "selected", ["510001"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    _, card = card_of(web, pid, "510001")
    assert "к прежнему вердикту" in card


# ============================================================================ «Пересмотреть вердикт»

def gated(answer):
    entered, gate = threading.Event(), threading.Event()

    def handler(body):
        entered.set()
        gate.wait(20)
        return answer

    return entered, gate, handler


def test_reanalyze_with_another_model_and_card_waits(web):
    pid = analysed(web)
    db = web.app.state.db
    fid, card = card_of(web, pid, "510001")
    assert 'id="reanalyze-form"' in card and "Пересмотреть вердикт" in card and 'id="pending-run"' not in card
    # для второго мнения по умолчанию предложена другая модель, модель вердикта подписана
    select = re.search(r'<select name="model" id="reanalyze-model">(.*?)</select>', card, re.S).group(1)
    assert '<option value="gpt-oss:20b" selected>gpt-oss:20b (12,8 ГБ, 20.9B, с рассуждением)</option>' in select
    assert ('<option value="qwen2.5-coder:14b">qwen2.5-coder:14b (8,4 ГБ, 14.8B, без рассуждения) – дала этот '
            'вердикт</option>') in select
    entered, gate, handler = gated(verdict_answer("true_positive", 77))
    web.fake.answers.append(handler)
    r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze?cb=billing-core", headers=ORIGIN,
                        follow_redirects=False, data={"model": "gpt-oss:20b"})
    assert r.status_code == 303 and r.headers["location"] == (f"/projects/{pid}/findings/{fid}"
                                                              "?cb=billing-core&ok=reanalyze")
    assert entered.wait(10)
    page = web.client.get(r.headers["location"]).text
    assert "Находка поставлена на повторный разбор" in page
    assert f'id="pending-run" role="status" data-poll="/projects/{pid}/findings/{fid}/state"' in page
    assert re.search(r'id="reanalyze-btn" disabled', page)
    state = web.client.get(f"/projects/{pid}/findings/{fid}/state").json()
    assert state["done"] is False and state["pending_run"]["model"] == "gpt-oss:20b"
    # пока идёт разбор, второй прогон для проекта не запускается
    r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=AS_JSON, data={"model": "gpt-oss:20b"})
    assert r.status_code == 409 and "идут по одному" in r.json()["detail"]
    gate.set()
    run = wait_run(web, state["pending_run"]["id"])
    assert run["state"] == "done" and run["fresh"] == 1 and run["scope"] == "selected" and run["total"] == 1
    state = web.client.get(f"/projects/{pid}/findings/{fid}/state").json()
    assert state["done"] and state["reload"] and state["verdict_id"] != int(form_fields(card)["verdict_id"])
    case = db.get_case(pid, "510001")
    assert (case["verdict"]["model"], case["verdict"]["verdict"]) == ("gpt-oss:20b", "true_positive")


def test_analyse_single_finding_from_card_without_verdict(web):
    pid = prepared(web)
    fid, card = card_of(web, pid, "510004")
    assert "Модель эту находку ещё не разбирала" in card and "Разобрать моделью" in card
    r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=AS_JSON,
                        data={"model": "qwen2.5-coder:14b", "fresh": "0"})
    assert r.status_code == 200 and r.json()["ok"]
    run = wait_run(web, r.json()["run_id"])
    assert run["state"] == "done" and run["fresh"] == 0
    assert web.app.state.db.get_case(pid, "510004")["verdict"] is not None
    sca = web.app.state.db.get_finding_by_hub_id(pid, "73001")["id"]
    r = web.client.post(f"/projects/{pid}/findings/{sca}/reanalyze", headers=AS_JSON, data={"model": "x"})
    assert r.status_code == 409 and "только находки SAST" in r.json()["detail"]


# ============================================================================ отметки

def test_entered_in_hub_mark(web):
    pid = analysed(web)
    db = web.app.state.db
    fid, card = card_of(web, pid, "510001")
    url = f"/projects/{pid}/findings/{fid}/entered"
    assert re.search(r'id="mark-entered" hidden', card) and 'id="entered-badge" hidden' in card
    r = web.client.post(url, headers=AS_JSON, data={"entered": "1"})
    assert r.status_code == 400 and "Сначала сохраните решение" in r.json()["detail"]
    answer = save(web, pid, fid, card, decision="agree", comment="Проверено вручную.", reviewed="1",
                  action="copy").json()
    assert answer["ok"] and not answer["entered"]  # копирование отметку «Внесено» не ставит
    web.client.post(f"/projects/{pid}/findings/{fid}/copied", headers=AS_JSON, data={"revision": answer["revision"]})
    _, card = card_of(web, pid, "510001")
    assert not re.search(r'id="mark-entered" hidden', card)  # текст скопирован – кнопка рядом видна
    r = web.client.post(url, headers=AS_JSON, data={"entered": "1", "review_revision": str(answer["revision"]),
                                                     "text_hash": answer["entered_hash"]})
    marks = r.json()
    assert r.status_code == 200 and marks["entered"] and marks["entered_at"]
    assert db.get_review(pid, "510001")["revision"] == answer["revision"]  # редакция решения не меняется
    assert "revision" not in marks  # и в форму решения не подставляется: защита от устаревшей вкладки остаётся
    assert marks["show"] == ["entered-badge", "entered-note"] and marks["hide"] == ["mark-entered", "entered-changed", "entered-unconfirmed", "entered-format-updated", "entered-bulk"]
    assert marks['times']['entered-at']=={'prefix':'Внесено в Hub ','datetime':marks['entered_at'],'suffix':'.'}
    _, card = card_of(web, pid, "510001")
    assert 'id="entered-badge" hidden' not in card and "Внесено в Hub <time" in card
    assert re.search(r'id="mark-entered" hidden', card)
    # отметка – о тексте редакции, которую видел человек: решение с тех пор изменили – отказ
    r = web.client.post(url, headers=AS_JSON, data={"entered": "1", "review_revision": "99",
                                                     "text_hash": answer["entered_hash"]})
    assert r.status_code == 409 and r.json()["reason"] == "revision"
    # изменился текст для Hub – отметка снимается сама
    assert save(web, pid, fid, card, decision="agree", reviewed="1", comment="Новый текст.",
                action="save").status_code == 200
    assert db.get_review(pid, "510001")["entered_hub"] == 0
    # снять отметку – обычной формой
    web.client.post(url, headers=AS_JSON, data={"entered": "1", "review_revision": str(db.get_review(pid, "510001")["revision"])})
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False, data={"entered": "0"})
    assert r.status_code == 303 and r.headers["location"].endswith("?ok=unentered")
    assert db.get_review(pid, "510001")["entered_hub"] == 0


def test_reviewed_mark_on_its_own(web):
    pid = analysed(web)
    db = web.app.state.db
    fid, card = card_of(web, pid, "510001")
    url = f"/projects/{pid}/findings/{fid}/reviewed"
    r = web.client.post(url, headers=AS_JSON, data={**form_fields(card), "reviewed": "1"})
    answer = r.json()
    assert r.status_code == 200 and answer["reviewed"] and answer["revision"] == 1
    assert answer["checked"] == {"reviewed-box": True} and answer["show"] == ["reviewed-badge"]
    assert answer["progress"]["reviewed"] == 1 and db.get_review(pid, "510001")["decision"] == ""
    # та же страница второй раз – редакция уже другая
    r = web.client.post(url, headers=AS_JSON, data={**form_fields(card), "reviewed": "0"})
    assert r.status_code == 409 and r.json()["reason"] == "revision"
    _, card = card_of(web, pid, "510001")
    save(web, pid, fid, card, decision="later", action="save")
    _, card = card_of(web, pid, "510001")
    r = web.client.post(url, headers=AS_JSON, data={**form_fields(card), "reviewed": "1"})
    assert r.status_code == 400 and "Отложенная находка" in r.json()["detail"]


def test_reviewed_mark_allowed_when_code_changed_after_analysis(web):
    """ADR-0147: срез модели не совпадает с текущим – отметка «Проверено» ставится, карточка предупреждает."""
    pid = analysed(web)
    invoice = web.tmp / "repos" / "team" / "billing-core" / INVOICE
    invoice.write_text(invoice.read_text(encoding="utf-8").replace("// строка 50", "// правка 50"),
                       encoding="utf-8")
    fid, card = card_of(web, pid, "510001")
    r = web.client.post(f"/projects/{pid}/findings/{fid}/reviewed", headers=AS_JSON,
                        data={**form_fields(card), "reviewed": "1"})
    assert r.status_code == 200 and r.json()["reviewed"], r.text


# ============================================================================ п. 10: комментарий к другому вердикту

def test_copy_of_model_comment_for_other_verdict_needs_check(web):
    pid = analysed(web)  # модель: ложная, комментарий «Ложное срабатывание: …»
    db = web.app.state.db
    fid, card = card_of(web, pid, "510001")
    model_comment = db.get_case(pid, "510001")["verdict"]["data"]["hub_comment"]
    assert model_comment.startswith("Ложное срабатывание")
    assert 'id="comment-stale" hidden' in card and 'data-comment-for="false_positive"' in card
    # «Отложить» в Hub не переносится: копировать нечего (ADR-0089)
    r = save(web, pid, fid, card, decision="later", comment=model_comment, action="copy")
    assert r.status_code == 400 and "только при решении «Ложное срабатывание»" in r.json()["detail"]
    assert db.get_review(pid, "510001") is None  # ничего не сохранено
    # «Подтверждаю дефект» с комментарием модели про ложное срабатывание: решение сохраняется, но текст подсвечен
    r = save(web, pid, fid, card, decision="true_positive", comment=model_comment, fix="Параметризовать запрос.",
             reviewed="1", action="save")
    assert r.status_code == 200 and r.json()["ok"]
    _, card = card_of(web, pid, "510001")
    assert 'id="comment-stale" hidden' not in card and 'class="is-stale" aria-invalid="true"' in card
    assert '<label class="check" id="comment-confirm-label">' in card
    # и дефект с таким текстом молча не выдаётся
    defect_url = f"/projects/{pid}/findings/{fid}/defect"
    r = web.client.post(defect_url, headers=AS_JSON, data={"number": ""})
    assert r.status_code == 409 and r.json()["reason"] == "comment"
    assert "к вердикту «ложная», а в Hub уйдёт вердикт «истинная»" in r.json()["detail"]
    # явное подтверждение – выдаётся
    revision = db.get_review(pid, "510001")["revision"]
    r = web.client.post(defect_url, headers=AS_JSON, data={"number": "", "comment_confirmed": "1", "confirm": "1",
                                                           "review_revision": str(revision)})
    assert r.status_code == 200 and "Параметризовать запрос." in r.json()["body"]
    # поправленный текст – уже текст человека
    _, card = card_of(web, pid, "510001")
    r = save(web, pid, fid, card, decision="true_positive", comment=model_comment + " Но защита не видна.",
             fix="Параметризовать запрос.", reviewed="1", action="save")
    assert r.status_code == 200
    r = web.client.post(defect_url, headers=AS_JSON, data={"number": "", "confirm": "1"})
    assert r.status_code == 200, r.text
    # согласие с моделью и её комментарий – как раньше, без проверки: ложное срабатывание копируется
    _, card = card_of(web, pid, "510001")
    r = save(web, pid, fid, card, decision="false_positive", comment=model_comment, reviewed="1", action="copy")
    assert r.status_code == 200 and r.json()["ok"]


def test_comment_written_for_previous_verdict_after_new_analysis(web):
    pid = analysed(web)
    db = web.app.state.db
    fid, card = card_of(web, pid, "510001")
    model_comment = db.get_case(pid, "510001")["verdict"]["data"]["hub_comment"]
    assert save(web, pid, fid, card, decision="agree", comment=model_comment, reviewed="1",
                action="save").status_code == 200
    web.fake.answers.append(verdict_answer("true_positive", 90))
    run_id = web.app.state.runner.enqueue(pid, "qwen2.5-coder:14b", "selected", ["510001"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    _, card = card_of(web, pid, "510001")
    assert 'id="verdict-changed"' in card and "после вашего решения" in card
    # форма показывает исход человека, а не новый вердикт модели (ADR-0097): «Ложное срабатывание» с комментарием
    # модели к «ложной» – текст подходит; подсветка – только если человек сам выберет другой исход
    assert re.search(r'value="false_positive" form="review-form" checked', card)
    assert 'id="comment-stale" hidden' in card
    r = save(web, pid, fid, card, decision="true_positive", comment=model_comment, fix="Параметризовать запрос.",
             reviewed="1", action="save")
    assert r.status_code == 200, r.text
    r = web.client.post(f"/projects/{pid}/findings/{fid}/defect", headers=AS_JSON, data={"number": ""})
    assert r.status_code == 409 and r.json()["reason"] == "comment"


# ============================================================================ список

def test_list_filters_by_marks_and_missing(web):
    pid = analysed(web)
    db = web.app.state.db
    db.save_review(pid, "510001", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    db.save_review(pid, "510004", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    db.mark_entered(pid, "510004", True)
    listing = web.client.get(f"/projects/{pid}/findings").text
    assert "внесено в Hub 1" in listing and re.search(r'class="badge badge-info"[^>]*>.*?в Hub</span>', listing)
    assert 'href="/projects/%d/findings?reviewed=yes&amp;entered=no">Не внесены в Hub</a>' % pid in listing
    page = web.client.get(f"/projects/{pid}/findings?reviewed=yes&entered=no").text
    assert "510001" in page and "510004" not in page and 'aria-current="true" class="is-active"' in page
    page = web.client.get(f"/projects/{pid}/findings?entered=yes").text
    assert "510004" in page and "510001" not in page
    first = int(re.search(rf'href="/projects/{pid}/findings/(\d+)\?entered=yes[^"]*">Первая в выборке</a>',
                          page).group(1))
    assert db.get_finding(pid, first)["hub_id"] == "510004"  # выборка внесённых – обход по всем
    card = web.client.get(f"/projects/{pid}/findings/{first}?entered=yes").text
    assert "В выборке: внесены в Hub" in card
    # находка, которой нет в новой выгрузке
    path = make_hub_xlsx(web.tmp / "smaller.xlsx", sast=[row for row in SAST_ROWS if row["Issue id"] != "510002"])
    assert upload(web.client, pid, path).status_code == 303
    page = web.client.get(f"/projects/{pid}/findings?missing=yes").text
    assert "510002" in page and "510001" not in page and "нет в выгрузке</span>" in page
    assert "is-missing" in page and 'name="hub_id" value="510002"' not in page  # в прогон не отметить
    page = web.client.get(f"/projects/{pid}/findings?missing=no").text
    assert "510002" not in page and "510001" in page
    fid, card = card_of(web, pid, "510002")
    assert "нет в новой выгрузке</span>" in card


def test_sca_component_opens_in_sca_card(web):
    pid = prepared(web)
    sca = web.app.state.db.get_finding_by_hub_id(pid, "73001")["id"]
    listing = web.client.get(f"/projects/{pid}/findings?kind=SCA").text
    assert f'href="/projects/{pid}/sca/findings/{sca}?back=' in listing
    r = web.client.get(f"/projects/{pid}/findings/{sca}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}/sca/findings/{sca}"


def test_empty_list_says_what_to_do(web):
    pid = create_project(web.client)
    page = web.client.get(f"/projects/{pid}/findings").text
    assert "В проекте пока нет находок" in page and f'href="/projects/{pid}"' in page
    page = web.client.get(f"/projects/{pid}/findings?urgent=1").text
    assert "Под фильтр ничего не попало" in page and "Показать все находки" in page
