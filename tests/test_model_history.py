"""История разборов моделью и решение человека после пересмотра (ADR-0097): новый ответ модели по тому же коду не
снимает «Проверено» и не блокирует дефект; карточка показывает все ответы с метками и пунктами прежнего разбора;
список – исход человека и «модели расходятся»; вид запуска – runs.origin (схема 21). Данные выдуманы, модель
поддельная."""

from __future__ import annotations

import re

from app.routes.findings import need_fix_text
from fake_ollama import verdict_answer
from test_code_snapshots import analysed, card_url, decide, wait_run, web  # noqa: F401
from test_web import ORIGIN

JSON = {**ORIGIN, "Accept": "application/json"}
HUB_ID = "510001"
CODE_ONLY = "```java\nps.setString(1, owner);\n```"


def reanalyze(web, url: str, answer: dict) -> dict:  # noqa: F811
    web.fake.answers.append(answer)
    r = web.client.post(url + "/reanalyze", headers=JSON, data={"model": "qwen2.5-coder:14b", "fresh": "1"})
    assert r.status_code == 200, r.text
    run = wait_run(web, r.json()["run_id"])
    assert run["state"] == "done", run
    return run


def test_reanalysis_keeps_decision_marks_and_defect(web):  # noqa: F811
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    before = db.get_review(pid, HUB_ID)
    assert before["reviewed"] == 1
    first = web.client.post(url + "/defect", headers=JSON, data={"number": ""})
    assert first.status_code == 200
    assert db.mark_copied(pid, HUB_ID, before["revision"])
    assert db.mark_entered(pid, HUB_ID, revision=before["revision"], entered_hash="h") is not None
    before = db.get_review(pid, HUB_ID)
    reanalyze(web, url, verdict_answer("false_positive", 70))
    after = db.get_review(pid, HUB_ID)
    assert after["reviewed"] == 1 and after["revision"] == before["revision"], "решение и отметка не тронуты"
    assert (after["copied_at"], after["entered_hub"], after["entered_text_hash"]) == (
        before["copied_at"], 1, "h"), "отметки переноса не тронуты"
    card = web.client.get(url).text
    assert 'id="verdict-changed"' in card and "остаётся в силе" in card and "расходится с вашим решением" in card
    defect = web.client.post(url + "/defect", headers=JSON, data={"number": ""})
    assert defect.status_code == 200, defect.text  # дефект выдаётся без пересохранения
    assert defect.json()["body"] == first.json()["body"], "текст дефекта тот же"
    assert db.get_run(db.list_runs(pid, 1)[0]["id"])["origin"] == "card"


def test_history_lists_answers_with_labels_and_earlier_points(web):  # noqa: F811
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    reanalyze(web, url, verdict_answer("true_positive", 90, fix="1) Передавать значение параметром."))
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    reanalyze(web, url, verdict_answer("true_positive", 95, fix=CODE_ONLY))
    history = db.finding_model_history(pid, HUB_ID)
    assert len(history["answers"]) == 3
    assert [u["origin"] for a in history["answers"][:2] for u in a["uses"]] == ["card", "card"]
    card = web.client.get(url).text
    block = card.split('id="model-history"')[1].split("</details>\n  {% endif %}")[0]
    assert "История разборов моделью · 3" in card and "показан сейчас" in block
    assert "по нему принято ваше решение" in block and "модели расходятся" in block
    assert "Взять пункты из этого разбора" in block and 'data-points="Передавать значение параметром."' in block
    assert "Уже пересматривали: 2" in card
    # у текущего ответа только код: подсказка у поля ведёт к пунктам прежнего разбора
    need = re.search(r'data-need-fix="([^"]*)"', card).group(1)
    assert "в истории" in need


def test_list_shows_human_outcome_and_disagreement(web):  # noqa: F811
    pid = analysed(web)
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    reanalyze(web, url, verdict_answer("true_positive", 90))
    listing = web.client.get(f"/projects/{pid}/findings").text
    row = listing.split(HUB_ID, 1)[1].split("</tr>", 1)[0]
    assert "подтверждён дефект" in row and "модели расходятся" in row


def test_mark_reviewed_after_reanalysis(web):  # noqa: F811
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    saved = db.get_review(pid, HUB_ID)
    code = {"code_hash": saved["code_hash"], "code_chars": int(saved["code_chars"] or 0)}
    db.set_reviewed(pid, HUB_ID, False, **code)
    reanalyze(web, url, verdict_answer("true_positive", 90))
    review = db.set_reviewed(pid, HUB_ID, True, **code)
    assert review["reviewed"] == 1, "отметка ставится по решению прежнего разбора того же кода"


def test_need_fix_text_points_to_history():
    text = need_fix_text(CODE_ONLY, [], history_points=True)
    assert "в истории" in text and "кнопкой «Взять пункты из рекомендации модели»" not in text


def test_changed_code_is_not_reported_as_decision_in_force(web):  # noqa: F811
    """Решение по прежнему коду, затем код изменился и модель разобрала заново: карточка не говорит «остаётся в силе»,
    дефект не выдаётся (силу решения держат отпечатки находки и кода)."""
    from test_code_snapshots import INVOICE, clone
    pid = analysed(web)
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    path = clone(web) / INVOICE
    path.write_text(path.read_text(encoding="utf-8").replace("owner", "owner_id"), encoding="utf-8")
    reanalyze(web, url, verdict_answer("true_positive", 90))
    card = web.client.get(url).text
    assert 'id="verdict-changed"' in card and "остаётся в силе" not in card and "сохраните заново" in card
    assert web.client.post(url + "/defect", headers=JSON, data={"number": ""}).status_code == 409


def test_card_and_list_count_the_same_answers(web):  # noqa: F811
    """Одно множество ответов: ответ, привязанный к решению вне прогонов, входит и в историю, и в счётчик списка."""
    pid = analysed(web)
    db = web.app.state.db
    case = db.get_case(pid, HUB_ID)
    outside = db.save_verdict(case["case_hash"], "other-model", "sast-v6", verdict_answer("false_positive"), {})
    db.save_review(pid, HUB_ID, decision="disagree", final_verdict="true_positive", final_comment="Подтверждено.",
                   reviewed=False, verdict_id=outside)
    history = db.finding_model_history(pid, HUB_ID)
    counts = db.model_answer_counts(pid, [HUB_ID], "sast-v6")
    assert len(history["answers"]) == counts[HUB_ID]["answers"] == 2


def test_single_earlier_answer_is_shown(web):  # noqa: F811
    """Привязки среза нет (например, сменилась папка клона), остался прежний ответ решения: история показывается – туда
    ведёт подсказка о пунктах."""
    pid = analysed(web)
    db = web.app.state.db
    url = card_url(web, pid, HUB_ID)
    decide(web, pid, HUB_ID, decision="true_positive", verdict="true_positive")
    with db._tx() as c:
        c.execute("UPDATE cases SET verdict_id = NULL WHERE project_id = ? AND hub_id = ?", (pid, HUB_ID))
    card = web.client.get(url).text
    assert 'id="model-history"' in card


def test_card_says_where_the_recommendation_is_and_why_there_is_none(web):  # noqa: F811
    """Рекомендация модели есть не у каждого разбора, и карточка не должна запутывать: у ложной промпт
    рекомендаций не просит, и карточка говорит это прямо; у истинной – «Как исправить», у неясной – «Что проверить»;
    в истории «рекомендация» названа, только если она есть."""
    pid = analysed(web)
    url = card_url(web, pid, HUB_ID)
    reanalyze(web, url, verdict_answer("true_positive", 90))
    card = web.client.get(url).text
    assert "Как исправить – от модели</summary>" in card and 'id="model-fix-none"' not in card
    reanalyze(web, url, verdict_answer("uncertain", 60))
    card = web.client.get(url).text
    assert "Что проверить – от модели</summary>" in card and 'id="model-fix-none"' not in card
    reanalyze(web, url, verdict_answer("false_positive", 92))
    card = web.client.get(url).text
    note = card.split('id="model-fix-none"')[1].split("</section>")[0]
    assert "Рекомендации – от модели" in note and "срабатывание ложное" in note
    assert 'id="model-fix"' not in card, "пустой рекомендации-раскрывашки нет"
    # пояснение – в боковой панели шага 3, шаг 2 его не содержит: первый экран не растёт (e2e 1536×864)
    step2 = card.split('id="step-2"')[1].split('id="step-3"')[0]
    assert "model-fix-none" not in step2 and "verdict-fix-note" not in step2
    block = card.split('id="model-history"')[1]
    assert "Разбор и как исправить" in block and "Разбор и что проверить" in block
    assert "Разбор и рекомендация" not in block


def test_decision_step_shows_a_tally_of_model_answers(web):  # noqa: F811
    """Шаг 5: сводка разборов моделью над решением – сколько разборов, сколько с каждым
    вердиктом и с какой уверенностью, «модели расходятся», выделен последний разбор (модель, время, вердикт)."""
    pid = analysed(web)
    url = card_url(web, pid, HUB_ID)
    reanalyze(web, url, verdict_answer("true_positive", 90, fix="1) Передавать значение параметром."))
    reanalyze(web, url, verdict_answer("false_positive", 70))
    card = web.client.get(url).text
    tally = card.split('id="model-tally"')[1].split("</div>")[0]
    assert "Разборов моделью: <strong>3</strong>" in tally
    # первый разбор (прогон проекта) – ложная 80 %, затем пересмотры: истинная 90 %, ложная 70 %
    assert "истинная – <strong>1</strong> (90 %)" in tally and "ложная – <strong>2</strong> (70 %, 80 %)" in tally
    assert "модели расходятся" in tally and "подсказка – решает человек" in tally
    last = tally.split('id="model-tally-last"')[1]
    assert "ложная · 70%" in last and "показан в шаге 2" in last
    # сводка – в шаге 5, до кнопок решения
    decision = card.split('id="decision"')[1]
    assert decision.index('id="model-tally"') < decision.index('name="decision"')


def test_verdict_tally_orders_verdicts_and_picks_the_latest_answer():
    from app.routes.findings import verdict_tally
    rows = [{"verdict": "false_positive", "confidence": 60, "created_at": "2026-10-29T06:45:00+00:00"},
            {"verdict": "true_positive", "confidence": 80, "created_at": "2026-10-19T01:55:00+00:00"},
            {"verdict": "true_positive", "confidence": None, "created_at": "2026-10-18T01:55:00+00:00"}]
    tally = verdict_tally(rows)
    assert [(p["verdict"], p["count"], p["confidences"]) for p in tally["parts"]] == [
        ("true_positive", 2, [80]), ("false_positive", 1, [60])]
    assert tally["latest"]["confidence"] == 60 and tally["split"] is True
    assert verdict_tally([]) == {"parts": [], "latest": None, "split": False}
    # ответ по прежнему коду (не сопоставим) расхождения не даёт – как история шага 2 (ADR-0097)
    old = [{**rows[1], "comparable": False}, {**rows[0], "comparable": True}]
    assert verdict_tally(old)["split"] is False and len(verdict_tally(old)["parts"]) == 2
