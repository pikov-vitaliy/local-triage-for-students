"""ADR-0108: исследование компонента – ответ агента для находки SCA. Вывод – по уязвимостям находки; прежний ответ
агента, если он есть, остаётся главным. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

import copy
import re

from app import sca
from test_sca import AS_JSON, answers_text, form_fields, post_answers, sca_card
from test_sca_applicability import EVIDENCE, put_research
from test_web import prepared, web  # noqa: F401

KEY = ("maven", "example-parser", "1.4.2")
ADV = next(e["url"] for e in EVIDENCE if e["evidence_ref"] == "adv")


def item(vuln_id: str, applies: str, aliases=(), conditions=None) -> dict:
    return {"id": vuln_id, "aliases": list(aliases), "applies": applies, "description": f"Описание {vuln_id}.",
            "conditions": conditions, "ranges": [], "fixed_versions": ["1.4.9"], "source_refs": ["adv"]}


def payload(*findings, action: str = "update", target: str = "9.9.9") -> dict:
    return {"public_findings": list(findings), "evidence": copy.deepcopy(EVIDENCE),
            "package_advice": {"action": action, "target_version": target, "source_refs": ["reg"]},
            "package_status": "vulnerable" if findings else "no_known_vulnerabilities"}


def stored(data: dict, rid: int = 7, revision: int = 2) -> dict:
    """Строка исследования так, как её отдаёт база (Database.research_row)."""
    return {"id": rid, "revision": revision, "answer_sig": f"sig{revision}", "payload": data,
            "imported_at": "2026-10-25T20:00:00Z", "observed_at": ""}


# ============================================================================ ответ из исследования

def test_conclusion_is_per_vulnerability():
    data = payload(item("CVE-2099-10001", "yes", aliases=["GHSA-aaaa-bbbb-cccc"]),
                   item("CVE-2099-20002", "no", conditions="Только при включённом модуле X."),
                   item("CVE-2099-30003", "unknown"))
    answer = sca.research_answer(stored(data), KEY)
    assert answer["origin"] == "research" and answer["id"] == "research-7" and "ревизия 2" in answer["source"]
    assert answer["recommended_version"] == "9.9.9" and answer["research_sig"] == "sig2"
    assert {"CVE-2099-10001", "GHSA-aaaa-bbbb-cccc", "CVE-2099-20002", "CVE-2099-30003"} <= set(answer["vulnerabilities"])
    # синонимы – в охвате, но не в «ids»: тексты для Hub по сохранённым решениям не меняются (ревью Codex, круг 21)
    assert answer["ids"] == {}

    def conclusion(*ids: str) -> str:
        return sca.answer_for_ids(answer, ids)["conclusion"]
    assert conclusion("CVE-2099-10001") == conclusion("ghsa-AAAA-bbbb-cccc") == "update", "синоним, регистр"
    assert conclusion("CVE-2099-20002") == "not_applicable" and conclusion("CVE-2099-30003") == "unclear"
    assert conclusion("CVE-2099-20002", "CVE-2099-10001") == "update", "применима хотя бы одна"
    assert conclusion("CVE-2099-20002", "CVE-2099-30003") == "unclear"
    assert answer["conclusion"] == "update", "по всей библиотеке"
    one = sca.answer_for_ids(answer, ["CVE-2099-20002"])
    assert one["explanation"] == "Описание CVE-2099-20002. Условия: Только при включённом модуле X."
    assert one["links"] == [ADV]
    # чужой уязвимости и находке без идентификаторов вывод не подбирается (ревью Codex, круг 20)
    assert sca.answer_for_ids(answer, ["CVE-2099-99999"])["conclusion"] == ""
    assert sca.answer_for_ids(answer, [])["conclusion"] == ""


def test_no_findings_no_answer_and_target_only_for_update():
    assert sca.research_answer(None, KEY) is None
    # «нет известных уязвимостей» не говорит о конкретной CVE из Hub – ответа нет, человек решает сам
    assert sca.research_answer(stored(payload()), KEY) is None
    other = sca.research_answer(stored(payload(item("CVE-2099-10001", "yes"), action="replace", target="2.0.0")), KEY)
    assert other["recommended_version"] == "" and other["conclusion"] == "update"


# ============================================================================ карточка и решение

def researched(web, *findings) -> tuple[int, object]:  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    put_research(db, pid, db.sca_snapshot(pid, "73002").research_ref, payload(*findings))
    return pid, db


def test_card_takes_the_research_as_the_agent_answer_and_agree_saves(web):  # noqa: F811
    """Исследование принято – «Согласен с агентом» доступно (прежде было недоступно)."""
    pid, db = researched(web, item("CVE-2099-10001", "yes"))
    fid, card = sca_card(web, pid, "73002")
    assert 'id="agent-empty"' not in card and 'id="answer-from-research"' in card
    assert re.search(r'id="agent-conclusion">\s*обновить до 9\.9\.9', card), "вывод и цель – из исследования"
    assert 'value="agree" form="review-form" disabled' not in card
    assert 'data-model-verdict="true_positive"' in card
    fields = form_fields(card)
    assert fields["answer_id"].startswith("research-")
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 9.9.9.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200 and saved.json()["ok"], saved.text
    review = db.get_review(pid, "73002")
    assert (review["decision"], review["final_verdict"]) == ("agree", "true_positive")
    assert review["answer_sig"] == "research:sig1"
    # решение действует: дефект по нему не ждёт «сверки с ответом» (routes/sca.decision_state)
    assert "по прежнему ответу агента" not in web.client.get(url).text
    # находка с номером AST, которого в исследовании нет: «Согласен» записывает вывод по компоненту, карточка
    # предупреждает (ADR-0154; подробно – tests/test_sca_agree_by_component.py)
    _, other = sca_card(web, pid, "73001")
    assert 'value="agree" form="review-form" disabled' not in other and 'id="answer-stale"' not in other
    assert 'id="answer-by-component"' in other and "повторите исследование компонента" not in other
    # новая ревизия исследования – решение «Согласен» требует сверки, страница со старым ответом не сохраняет
    put_research(db, pid, db.sca_snapshot(pid, "73002").research_ref, payload(item("CVE-2099-10001", "no")))
    card = web.client.get(url).text
    assert 'id="answer-changed"' in card and re.search(r'id="agent-conclusion">\s*не применимо', card)
    stale = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить.", "action": "copy"})
    assert stale.status_code == 409 and stale.json()["reason"] == "answer"


def test_not_applicable_by_research_is_agreed_as_false_positive(web):  # noqa: F811
    pid, _db = researched(web, item("CVE-2099-10001", "no", conditions="Только при включённом модуле X."))
    _, card = sca_card(web, pid, "73002")
    assert 'data-model-verdict="false_positive"' in card
    assert "Не применимо: CVE-2099-10001 не затрагивает example-parser 1.4.2." in card
    assert "Только при включённом модуле X." in card


def test_old_answer_stays_main_and_research_is_among_other_answers(web):  # noqa: F811
    """Прежний ответ агента главный: решения по нему не становятся «по прежнему ответу» после исследования."""
    pid, _db = researched(web, item("CVE-2099-10001", "no"))
    assert post_answers(web, pid, answers_text()).status_code == 303
    _, card = sca_card(web, pid, "73002")
    assert not form_fields(card)["answer_id"].startswith("research-")
    assert 'id="answer-from-research"' not in card
    others = re.search(r'<details class="other-answers".*?</details>', card, re.S).group(0)
    assert "исследование компонента, ревизия 1" in others


def test_sca_list_counts_the_researched_package_as_answered(web):  # noqa: F811
    pid, _db = researched(web, item("CVE-2099-10001", "yes"))
    listing = web.client.get(f"/projects/{pid}/sca").text
    assert 'Без ответа агента <span class="chip-count">1</span>' in listing, "до исследования – 2"
    rows = re.findall(r'<tr data-component="([^"]+)"', web.client.get(f"/projects/{pid}/sca?show=no_answer").text)
    assert rows == ["demo-xml"]
    rows = re.findall(r'<tr data-component="([^"]+)"', web.client.get(f"/projects/{pid}/sca?show=update").text)
    assert rows == ["example-parser"]


# ============================================================================ ревью Codex, круг 20

def test_records_sharing_an_identifier_are_one_vulnerability_in_any_order():
    """Находка 2: CVE с синонимом GHSA «не применима», та же GHSA с синонимом CVE «применима» – одна уязвимость с
    противоречием: «неясно» при любом порядке записей, а не вывод первой."""
    no = item("CVE-2099-10001", "no", aliases=["GHSA-aaaa-bbbb-cccc"])
    yes = item("GHSA-aaaa-bbbb-cccc", "yes", aliases=["CVE-2099-10001"])
    other = item("CVE-2099-20002", "no")
    for order in ((no, yes, other), (yes, no, other), (other, yes, no)):
        answer = sca.research_answer(stored(payload(*order)), KEY)
        for ids in (["CVE-2099-10001"], ["GHSA-aaaa-bbbb-cccc"], ["CVE-2099-10001", "GHSA-aaaa-bbbb-cccc"]):
            assert sca.answer_for_ids(answer, ids)["conclusion"] == "unclear", (order, ids)
        assert sca.answer_for_ids(answer, ["CVE-2099-20002"])["conclusion"] == "not_applicable"
    same = sca.research_answer(stored(payload(item("CVE-2099-10001", "yes", aliases=["GHSA-aaaa-bbbb-cccc"]),
                                              item("GHSA-aaaa-bbbb-cccc", "yes"))), KEY)
    assert sca.answer_for_ids(same, ["GHSA-aaaa-bbbb-cccc"])["conclusion"] == "update", "согласные записи – их вывод"


def test_finding_without_identifiers_is_not_covered_by_research():
    """Находка 3: находке без CVE и GHSA исследование не отвечает – «Согласен» недоступно; ответ прежнего формата –
    как раньше."""
    from app.models import Finding
    from app.routes.sca import answer_covers, answer_verdict
    bare = Finding.from_dict({"hub_id": "1", "kind": "SCA", "component": "example-parser", "version": "1.4.2"})
    answer = sca.research_answer(stored(payload(item("CVE-2099-10001", "no"))), KEY)
    assert not answer_covers(bare, answer) and answer_verdict(bare, answer) == ""
    assert answer_covers(bare, {"conclusion": "update", "vulnerabilities": []})


def test_new_research_revision_reopens_agreed_findings(web):  # noqa: F811
    """Находка 1: решение «Согласен» по исследованию R1 после R2 – непроверенное, редакция выросла, счётчик проверенных
    уменьшился; решение по прежнему ответу агента (он главнее) не трогается."""
    from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    assert manifest["rows"][0]["component"] == "example-parser"
    document = answer_document(manifest)
    expect_accepted(web, pid, document)
    db = web.app.state.db
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200, saved.text
    before = db.get_review(pid, "73002")
    reviewed = db.review_stats(pid)["sca_reviewed"]
    assert before["reviewed"] == 1 and before["answer_sig"].startswith("research:")
    changed = copy.deepcopy(document)
    changed["rows"][0]["public_findings"][0]["description"] = "Уточнённое описание уязвимости"
    expect_accepted(web, pid, changed)
    after = db.get_review(pid, "73002")
    assert after["reviewed"] == 0 and int(after["revision"]) == int(before["revision"]) + 1
    assert db.review_stats(pid)["sca_reviewed"] == reviewed - 1
    assert 'id="answer-changed"' in web.client.get(url).text


def test_research_revision_keeps_decisions_on_an_old_answer(web):  # noqa: F811
    from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components
    pid = project_with_components(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73002")
    saved = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200, saved.text
    db = web.app.state.db
    before = db.get_review(pid, "73002")
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    after = db.get_review(pid, "73002")
    assert (after["reviewed"], after["revision"]) == (1, before["revision"]), "прежний ответ главнее исследования"


def test_saved_hub_text_does_not_change_when_research_arrives(web):  # noqa: F811
    """Круг 21 Codex: своё решение «ложное срабатывание» с текстом для Hub; затем исследование с синонимом GHSA –
    текст для Hub и отметка «Внесено в Hub» не меняются (синонимы исследования в тексты не идут)."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": "Уязвимая функция разбора в продукте не вызывается.", "reviewed": "1", "action": "save"})
    assert saved.status_code == 200, saved.text

    def hub_text() -> str:
        return re.search(r'<pre id="hub-text" class="hub-text">(.*?)</pre>', web.client.get(url).text, re.S).group(1)
    before = hub_text()
    assert before.startswith("CVE-2099-10001")
    db = web.app.state.db
    put_research(db, pid, db.sca_snapshot(pid, "73002").research_ref,
                 payload(item("CVE-2099-10001", "no", aliases=["GHSA-aaaa-bbbb-cccc"])))
    assert hub_text() == before and "GHSA-aaaa-bbbb-cccc" not in before
    assert 'id="entered-changed"' not in web.client.get(url).text
