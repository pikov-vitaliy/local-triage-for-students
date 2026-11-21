"""ADR-0154: «Согласен с агентом» для находки, уязвимость которой названа только внутренним номером AST. Исследование
компонента идёт по публичным данным и такой номер не опознаёт: за него берётся вывод исследования по компоненту,
карточка об этом предупреждает. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

import re

from app import sca
from app.models import Finding
from app.routes.sca import answer_covers, answer_current, answer_usable, answer_verdict
from test_sca import AS_JSON, answers_text, form_fields, post_answers, sca_card
from test_sca_applicability import put_research
from test_sca_research_answer import KEY, item, payload, researched, stored
from test_web import prepared, web  # noqa: F401

AST = "AST-2026-000101"  # находка 73001 тестовой выгрузки: только внутренний номер
CVE = "CVE-2099-10001"   # находка 73002


def answer(*findings, **advice) -> dict:
    return sca.research_answer(stored(payload(*findings, **advice)), KEY)


# ============================================================================ вывод

def test_internal_number_takes_the_component_conclusion():
    found = answer(item(CVE, "yes"), item("CVE-2099-20002", "no"))
    assert sca.internal_gap([AST], found) == [AST]
    got = sca.answer_by_ids(found, [AST])
    assert got["conclusion"] == "update" and got["recommended_version"] == "9.9.9" and got["by_component"] == [AST]
    # источники о других уязвимостях компонента этой находке не приписываются; пояснение – по компоненту
    assert got["links"] == [] and got["explanation"] == found["explanation"]
    assert "применимых к версии уязвимостей 1 из 2" in got["explanation"]
    # прежняя функция по уязвимостям не меняется: вывод по компоненту она не подбирает (ADR-0108)
    assert sca.answer_for_ids(found, [AST])["conclusion"] == ""
    # вывод по компоненту «не применимо» за неопознанную уязвимость не берётся
    quiet = answer(item(CVE, "no"))
    assert sca.internal_gap([AST], quiet) == [AST] and sca.component_fills([AST], quiet) == []
    got = sca.answer_by_ids(quiet, [AST])
    assert got["conclusion"] == "" and "by_component" not in got
    unsure = answer(item(CVE, "no"), item("CVE-2099-20002", "unknown"))
    assert sca.answer_by_ids(unsure, [AST])["conclusion"] == "unclear"


def test_recognized_and_internal_together_fold_like_several_vulnerabilities():
    """У находки есть и опознанная уязвимость, и внутренний номер: выводы складываются – хотя бы один «обновить» даёт
    «обновить». Вывод по компоненту «не применимо» за внутренний номер не берётся: ответ к находке не применяется.
    Пояснение и ссылки – по опознанной."""
    found = answer(item(CVE, "no", conditions="Только при включённом модуле X."), item("CVE-2099-20002", "yes"))
    got = sca.answer_by_ids(found, [AST, CVE])
    assert got["conclusion"] == "update" and got["by_component"] == [AST], "по компоненту есть применимая"
    assert got["explanation"].startswith(f"Описание {CVE}.") and got["links"]
    calm = answer(item(CVE, "no"))
    assert "by_component" not in sca.answer_by_ids(calm, [AST, CVE])
    assert not answer_usable(Finding(hub_id="3", kind="SCA", vuln_ids=[AST], cve=[CVE]), calm)
    mixed = sca.answer_by_ids(answer(item(CVE, "no"), item("CVE-2099-20002", "unknown")), [AST, CVE])
    assert mixed["conclusion"] == "unclear" and mixed["by_component"] == [AST]
    # опознанная уязвимость «обновить» остаётся «обновить» при любом выводе по компоненту
    assert sca.answer_by_ids(answer(item(CVE, "yes")), [CVE, AST])["conclusion"] == "update"


def test_public_identifier_outside_the_research_is_still_not_answered():
    """Вне охвата есть публичный идентификатор – это новая уязвимость, а не внутренний номер: вывод по компоненту
    за неё не берётся, нужен новый ответ или своё решение."""
    found = answer(item(CVE, "yes"))
    assert sca.internal_gap(["CVE-2099-99999"], found) == []
    assert sca.internal_gap([AST, "CVE-2099-99999"], found) == []
    got = sca.answer_by_ids(found, [AST, "CVE-2099-99999"])
    assert got["conclusion"] == "" and "by_component" not in got
    assert sca.internal_gap([CVE], found) == [], "всё в охвате – разрыва нет"
    assert sca.internal_gap([], found) == [] and sca.internal_gap([AST], None) == []
    # ответ прежнего формата (не исследование) внутренний номер не получает
    legacy = {"conclusion": "update", "vulnerabilities": [CVE], "explanation": "x", "links": []}
    assert sca.internal_gap([AST], legacy) == [] and sca.answer_by_ids(legacy, [AST]) is legacy


def test_usable_answer_gives_the_verdict_and_keeps_strict_coverage():
    found = answer(item(CVE, "yes"))
    by_ast = Finding(hub_id="1", kind="SCA", vuln_ids=[AST], cve=[])
    by_new = Finding(hub_id="2", kind="SCA", vuln_ids=[], cve=["CVE-2099-99999"])
    assert not answer_covers(by_ast, found) and answer_usable(by_ast, found)
    assert answer_verdict(by_ast, found) == "true_positive"
    assert answer_verdict(by_ast, answer(item(CVE, "no"))) == "", "«не применимо» по компоненту не предлагается"
    assert answer_verdict(by_ast, answer(item(CVE, "unknown"))) == "uncertain"
    assert not answer_usable(by_ast, answer(item(CVE, "no")))
    assert not answer_usable(by_new, found) and answer_verdict(by_new, found) == ""
    review = {"decision": "agree", "answer_sig": "research:sig2"}
    assert answer_current(by_ast, review, found) and not answer_current(by_new, review, found)
    assert not answer_current(by_ast, {**review, "answer_sig": "research:sig1"}, found), "другое исследование"


# ============================================================================ карточка и решение

def test_card_offers_agree_with_a_warning_and_saves_it(web):  # noqa: F811
    pid, db = researched(web, item(CVE, "yes"))
    fid, card = sca_card(web, pid, "73001")
    assert 'value="agree" form="review-form" disabled' not in card
    assert 'data-model-verdict="true_positive"' in card and 'id="answer-stale"' not in card
    warning = card.split('id="answer-by-component"', 1)[1].split("</div>", 1)[0]
    assert AST in warning and "вывод исследования по компоненту в целом" in warning and "Своё решение" in warning
    assert "О самой этой уязвимости в исследовании ничего нет" in warning
    assert re.search(r'id="agent-conclusion">\s*обновить до 9\.9\.9', card)
    caption = card.split('id="answer-from-research">', 1)[1].split("</p>", 1)[0]
    assert "вывод по компоненту в целом" in caption and "по уязвимостям этой находки" not in caption
    known = sca_card(web, pid, "73002")[1].split('id="answer-from-research">', 1)[1].split("</p>", 1)[0]
    assert "вывод по уязвимостям этой находки" in known and "по компоненту в целом" not in known
    draft = re.search(r'data-model-comment="([^"]*)"', card).group(1)
    assert draft.startswith("Обновить example-parser с версии 1.4.2 до 9.9.9.")
    assert "Источники" not in draft and AST not in draft, "чужих источников и внутреннего номера в заготовке нет"
    fields = form_fields(card)
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 9.9.9.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200 and saved.json()["ok"], saved.text
    review = db.get_review(pid, "73001")
    assert (review["decision"], review["final_verdict"], review["answer_sig"]) == ("agree", "true_positive", "research:sig1")
    after = web.client.get(url).text
    assert "по прежнему ответу агента" not in after and 'id="answer-changed"' not in after
    # находка с опознанной уязвимостью предупреждения не получает
    assert 'id="answer-by-component"' not in sca_card(web, pid, "73002")[1]
    # новое исследование: решение «Согласен» по выводу компонента так же требует сверки
    # (переход к «не применимо» – отдельный тест ниже)
    put_research(db, pid, db.sca_snapshot(pid, "73001").research_ref, payload(item(CVE, "unknown")))
    card = web.client.get(url).text
    assert 'id="answer-changed"' in card and 'data-model-verdict="uncertain"' in card
    stale = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить.", "action": "save"})
    assert stale.status_code == 409 and stale.json()["reason"] == "answer"


def test_component_not_applicable_is_not_offered_and_the_card_says_why(web):  # noqa: F811
    """Вывод по компоненту «не применимо» за неопознанную уязвимость не берётся: «Согласен с
    агентом» недоступно, карточка объясняет почему и ведёт к своему решению; запрос с «Согласен» не сохраняется."""
    pid, db = researched(web, item(CVE, "no"))
    fid, card = sca_card(web, pid, "73001")
    assert 'value="agree" form="review-form" disabled' in card and 'data-model-verdict=""' in card
    assert 'id="answer-by-component"' not in card
    hint = card.split('id="answer-stale"', 1)[1].split("</div>", 1)[0]
    assert "«не применимо»" in hint and "Своё решение" in hint and "только вашим решением" in hint
    assert "появилась в новой выгрузке" not in hint and "повторите исследование" not in hint
    label = card.split('value="agree" form="review-form"', 1)[0].rsplit("<label", 1)[1]
    assert "эту уязвимость исследование не проверяло" in label and "Ответа агента по этой библиотеке нет" not in label
    before = db.get_review(pid, "73001")
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "false_positive",
        "comment": "Не применимо по исследованию компонента.", "reviewed": "1", "action": "save"})
    assert r.status_code == 400, (r.status_code, r.text)
    assert db.get_review(pid, "73001") == before, "ничего не записано"
    # своё решение по-прежнему сохраняется
    own = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": "Уязвимая функция разбора в продукте не вызывается.", "reviewed": "1", "action": "save"})
    assert own.status_code == 200 and own.json()["ok"], own.text
    # находка с опознанной уязвимостью «Согласен» с «не применимо» получает как раньше
    assert 'data-model-verdict="false_positive"' in sca_card(web, pid, "73002")[1]


def test_package_agree_does_not_carry_not_applicable_to_the_internal_number(web):  # noqa: F811
    """Общее решение по отмеченным находкам версии (ADR-0091 п. 4): «Согласен» в карточке находки с опознанной
    уязвимостью («не применимо») не записывается находке с одним внутренним номером в обход её карточки."""
    from test_sca_package_decision import post_package
    pid, db = researched(web, item(CVE, "no"))
    before = db.get_review(pid, "73001")
    r = post_package(web, pid, "73002", ["73002", "73001"], decision="agree", final_verdict="false_positive",
                     comment="Не применимо по исследованию компонента.")
    assert r.status_code in (400, 409, 422) and "73001" in r.text, (r.status_code, r.text[:300])
    assert db.get_review(pid, "73001") == before and db.get_review(pid, "73002") is None, "ничего не записано"
    # при выводе «обновить» общее согласие доходит до обеих находок
    pid2, db2 = researched(web, item(CVE, "yes"))
    ok = post_package(web, pid2, "73002", ["73002", "73001"], decision="agree", final_verdict="true_positive",
                      comment="Обновить до 9.9.9.")
    assert ok.status_code == 200 and ok.json()["ok"], ok.text
    assert db2.get_review(pid2, "73001")["final_verdict"] == "true_positive"


def test_agree_by_component_becomes_stale_when_the_research_turns_not_applicable(web):  # noqa: F811
    """Согласие по выводу «обновить» сохранено, новое исследование даёт «не применимо»: решение требует сверки,
    карточка объясняет, почему согласие больше недоступно."""
    from app.models import Finding as F
    from app.routes.sca import decision_state
    pid, db = researched(web, item(CVE, "yes"))
    fid, card = sca_card(web, pid, "73001")
    saved = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 9.9.9.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200 and saved.json()["ok"], saved.text
    put_research(db, pid, db.sca_snapshot(pid, "73001").research_ref, payload(item(CVE, "no")))
    card = sca_card(web, pid, "73001")[1]
    assert 'id="answer-changed"' in card and 'id="answer-stale"' in card and "«не применимо»" in card
    finding = F.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    from app.routes.sca import _latest_answer
    state, _outcome = decision_state(finding, db.get_review(pid, "73001"), _latest_answer(db, pid, finding))
    assert state == "stale"


def test_old_format_answer_does_not_get_the_component_conclusion(web):  # noqa: F811
    """Прежний ответ агента (не исследование), который не охватывает находку, остаётся неприменимым."""
    pid = prepared(web)
    text = answers_text().replace('"AST-2026-000101"', '"AST-2026-000999"')
    assert text != answers_text(), "в ответе был номер находки"
    assert post_answers(web, pid, text).status_code == 303
    _, card = sca_card(web, pid, "73001")
    assert 'id="answer-by-component"' not in card


def test_sca_page_names_the_internal_number_instead_of_asking_for_a_new_answer():
    row = {"component": "example-parser", "version": "1.4.2", "ecosystem": "maven", "vuln_ids": [AST], "cve": [],
           "fixed_versions": []}
    view = sca.component_views([row], {KEY: answer(item(CVE, "yes"))}, {})[0]
    assert view["conclusion"] == "update" and view["answer"]["by_component"] == [AST]
    texts = [n["text"] for n in view["notes"]]
    assert any("не опознаёт внутренний номер " + AST in t and "вывод по компоненту" in t for t in texts)
    assert not any("нужен новый ответ" in t for t in texts)
    fresh = {**row, "vuln_ids": [], "cve": ["CVE-2099-99999"]}
    assert sca.component_views([fresh], {KEY: answer(item(CVE, "yes"))}, {})[0]["answer"] is None
