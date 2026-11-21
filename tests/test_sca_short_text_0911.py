"""Короткий комментарий SCA для Hub (ADR-0101, Р2): «<публичные идентификаторы находки> в
<компонент> <версия>: <обоснование>». Данные выдуманы."""

from __future__ import annotations

import html
import re

from app import sca
from app.models import Finding
from app.routes.sca import FP_NEEDS_REASON, RISK_NEEDS_REASON
from test_sca import AS_JSON, form_fields, sca_card
from test_sca_package_decision import post_package
from test_web import prepared, web  # noqa: F401

REASON = "Уязвимая функция разбора в продукте не вызывается."


def item(**extra) -> Finding:
    data = {"hub_id": "1", "kind": "SCA", "component": "lodash", "version": "4.17.20", "cve": ["CVE-2021-23337"],
            "vuln_ids": [], **extra}
    return Finding(**data)


def test_prefix_is_ids_component_and_version():
    assert sca.hub_text(item(), "false_positive", REASON) == "CVE-2021-23337 в lodash 4.17.20: " + REASON
    two = item(cve=["CVE-2021-23337", "CVE-2020-8203"])
    assert sca.hub_text(two, "risk_accepted", REASON).startswith("CVE-2021-23337, CVE-2020-8203 в lodash 4.17.20: ")


def test_without_public_ids_component_only():
    only_ast = item(cve=[], vuln_ids=["AST-2026-000101"])
    assert sca.hub_text(only_ast, "false_positive", REASON) == "lodash 4.17.20: " + REASON
    mapped = sca.hub_text(only_ast, "false_positive", REASON,
                          aliases={"AST-2026-000101": {"aliases": ["CVE-2099-10002"], "origin": "map"}})
    assert mapped == "CVE-2099-10002 в lodash 4.17.20: " + REASON


def test_prefix_is_not_doubled_and_matches_whole_token():
    own = "CVE-2021-23337 в lodash 4.17.20: функция template не вызывается."
    assert sca.hub_text(item(), "false_positive", own) == own
    # другой номер, начинающийся так же, приставку не отменяет
    other = "CVE-2021-233371: другой номер."
    assert sca.hub_text(item(), "false_positive", other) == "CVE-2021-23337 в lodash 4.17.20: " + other


def test_empty_reason_gives_no_text_and_update_has_no_short_text():
    for comment in ("", "   ", "Ложное срабатывание:"):
        assert sca.hub_text(item(), "false_positive", comment) == "", comment
    assert sca.hub_text(item(), "true_positive", REASON) == ""
    assert sca.hub_text(item(), "uncertain", REASON) == ""


def test_package_decision_gives_each_finding_its_own_text(web):  # noqa: F811
    """Одно обоснование на две находки версии: у каждой свой текст для Hub – со своим номером (принято по умолчанию,
    ADR-0101)."""
    pid = prepared(web)
    web.app.state.db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    r = post_package(web, pid, "73001", ["73001", "73002"], decision="disagree", final_verdict="false_positive",
                     comment=REASON)
    assert r.status_code == 200, r.text
    texts = {}
    for hub_id in ("73001", "73002"):  # предпросмотр сохранённого пакетом решения – без повторного сохранения
        _, card = sca_card(web, pid, hub_id)
        found = re.search(r'<pre id="hub-text" class="hub-text">(.*?)</pre>', card, re.S)
        assert found, hub_id
        texts[hub_id] = html.unescape(found.group(1))
    assert texts["73001"] == "CVE-2099-10002 в example-parser 1.4.2: " + REASON
    assert texts["73002"] == "CVE-2099-10001 в example-parser 1.4.2: " + REASON


def test_reason_of_only_ast_is_refused(web):  # noqa: F811
    """Обоснование, от которого после удаления внутреннего номера ничего не остаётся, обоснованием не считается."""
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive", "comment": "AST-2026-000101",
        "action": "copy"})
    assert r.status_code == 400 and r.json()["detail"] == FP_NEEDS_REASON, r.text


def test_reason_of_only_ast_is_refused_for_risk_accepted_too(web):  # noqa: F811
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73002")
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "risk_accepted", "final_verdict": "", "kapo_state": "not_actual",
        "comment": "AST-2026-000101", "action": "save"})
    assert r.status_code == 400 and r.json()["detail"] == RISK_NEEDS_REASON, r.text


def test_component_markup_is_cleaned_in_the_prefix():
    text = sca.hub_text(item(component="<b>lodash</b>"), "false_positive", REASON)
    assert "<b>" not in text and text.endswith(": " + REASON), text
