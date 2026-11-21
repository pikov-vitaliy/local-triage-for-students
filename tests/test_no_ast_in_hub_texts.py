"""ADR-0101: внутренние номера уязвимостей AST нигде в текстах для Hub – ни в дефекте
SCA, ни в заготовках из ответов агента; набор только с AST дефекта по шаблону не даёт. Данные выдуманы."""

from __future__ import annotations

import html
import re

import pytest

from app import sca, sca_text as t
from app.routes.sca import NO_PUBLIC_IDS
from test_sca import (AS_JSON, answer, answers_json, form_fields, post_answers, sca_card, sca_finding, sca_text_ready,
                      shown_fields)
from test_sca_package_decision import UPD, post_package
from test_web import prepared, web  # noqa: F401

AST = re.compile(r"AST-\d{4}-\d+")


@pytest.mark.parametrize("text, expected", [
    ("CVE-2099-10002 (это AST-2026-000101): парсер подгружает внешние сущности.",
     "CVE-2099-10002: парсер подгружает внешние сущности."),
    ("Затронуты (CVE-2099-1, AST-2026-000101) и CVE-2099-2.", "Затронуты (CVE-2099-1) и CVE-2099-2."),
    ("AST-2026-000101, CVE-2099-1: отказ в обслуживании.", "CVE-2099-1: отказ в обслуживании."),
    ("Обе уязвимости AST-2026-000101 и CVE-2099-1 закрывает 2.3.9.", "Обе уязвимости и CVE-2099-1 закрывает 2.3.9."),
    ("Без внутренних номеров.\nВторая строка.", "Без внутренних номеров.\nВторая строка."),
    ("AST-2026-000101: описание уязвимости.", "описание уязвимости."),
    ("Подробно: https://hub.example/issues/AST-2026-000101 и https://nvd.nist.gov/vuln/detail/CVE-2099-10001.",
     "Подробно: и https://nvd.nist.gov/vuln/detail/CVE-2099-10001."),
    ("GHSA-abcd-1234-efgh: без внутренних номеров.", "GHSA-abcd-1234-efgh: без внутренних номеров."),
])


def test_strip_internal_ids(text, expected):
    assert t.strip_internal_ids(text) == expected


def test_short_text_never_has_ast():
    f = sca_finding()  # только AST-2026-000101
    text = sca.hub_text(f, "risk_accepted", "AST-2026-000101 неприменима: функция разбора не вызывается.",
                        aliases={"AST-2026-000101": {"aliases": ["CVE-2099-10002"], "origin": "map"}})
    assert text == "CVE-2099-10002 в example-parser 1.4.2: неприменима: функция разбора не вызывается.", text


def test_sources_with_ast_are_not_in_the_body():
    vulns = [t.Vuln(ids=["CVE-2099-10001"], hub_members=["1"])]
    body = t.body("org.example:lib", vulns, "CVE-2099-10001: Отказ в обслуживании при разборе документа.", "1.2.3",
                  ["https://osv.dev/vulnerability/AST-2026-000101", "https://github.com/advisories/GHSA-abcd-1234-efgh"])
    assert not AST.search(body) and "https://github.com/advisories/GHSA-abcd-1234-efgh" in body


def test_saved_explanation_with_ast_is_checked_and_signed_as_issued(web):  # noqa: F811
    """Сохранённое Объяснение с AST (например, до 0.9.11): проверки, подпись «Текст проверен» и выдача – по тексту без
    AST; строка «AST-…: …» объяснением публичной уязвимости не считается."""
    pid = prepared(web)
    web.app.state.db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    ready = sca_text_ready(web, url)
    assert ready["ready"] is True, ready
    clean = ready["explanation"]
    before = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "1", "confirm": "1"})
    assert before.status_code == 200, before.text
    with_ast = "\n".join(line.replace(": ", " (это AST-2026-000101): ", 1) for line in clean.split("\n"))
    shown = shown_fields(web.client.get(url).text)
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown, "text_revision": str(ready["text_revision"]), "target_version": "9.9.9", "version_checked": "1",
        "explanation": with_ast})
    assert saved.status_code == 200, saved.text
    # проверяется и подтверждается тот же текст, что без AST: Объяснение, готовность и подпись тела совпадают
    assert saved.json()["explanation"] == clean and saved.json()["ready"] is True, saved.json()
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "1", "confirm": "1"})
    assert issued.status_code == 200, issued.text
    assert not AST.search(issued.json()["body"]) and issued.json()["text_sig"] == before.json()["text_sig"]


def test_explanation_draft_from_agent_answer_has_no_ast():
    vuln = t.Vuln(ids=["CVE-2099-10002"])
    draft = t.explanation_draft([vuln], {}, "Парсер (это AST-2026-000101) подгружает внешние сущности.")
    assert draft == "CVE-2099-10002: Парсер подгружает внешние сущности." and not AST.search(draft)


def test_ast_line_does_not_count_as_explanation_of_the_public_class():
    vuln = t.Vuln(ids=["AST-2026-000101", "CVE-2099-10002"])
    text = "AST-2026-000101: Уязвимость разбора позволяет прочитать файлы сервера при подстановке сущностей."
    assert t.explanation_problems(text, [vuln]) == ["CVE-2099-10002"]


def test_suggested_comment_names_public_ids_only():
    f = sca_finding()
    aliases = {"AST-2026-000101": {"aliases": ["CVE-2099-10002"], "origin": "agent"}}
    text = sca.suggested_comment(f, {"conclusion": "update", "recommended_version": "1.4.10",
                                     "explanation": "CVE-2099-10002 (это AST-2026-000101): исправлено в 1.4.10."},
                                 aliases)
    assert not AST.search(text), text
    assert "Уязвимость: CVE-2099-10002." in text and "CVE-2099-10002: исправлено в 1.4.10." in text


def test_body_never_has_ast():
    vulns = [t.Vuln(ids=["CVE-2099-10001"], hub_members=["1"]), t.Vuln(ids=["AST-2026-000101"], hub_members=["2"])]
    body = t.body("org.example:lib", vulns, "CVE-2099-10001: Отказ в обслуживании (это AST-2026-000101) при разборе.",
                  "1.2.3", [], recommendation_note="Проверить AST-2026-000101 после обновления.")
    assert not AST.search(body), body
    assert "Описание\nCVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)\n\n" in body


def test_defect_and_card_texts_have_no_ast(web):  # noqa: F811
    """Набор с AST и CVE: в дефекте, его Объяснении и заготовке комментария нет AST; соответствие AST → CVE даёт
    публичный номер."""
    pid = prepared(web)
    item = answer("example-parser", "1.4.2", explanation="CVE-2099-10002 (это AST-2026-000101): разбор документа.")
    assert post_answers(web, pid, answers_json(item)).status_code == 303
    _, card = sca_card(web, pid, "73001")
    comment = html.unescape(re.search(r'<textarea[^>]*name="comment"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    assert comment and not AST.search(comment), comment
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    ready = sca_text_ready(web, url)
    assert ready["ready"] is True, ready
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "1", "confirm": "1"})
    assert issued.status_code == 200, issued.text
    assert not AST.search(issued.json()["body"]) and not AST.search(issued.json()["title"]), issued.json()["body"]
    page = web.client.get(url).text
    assert 'name="ast_hide"' not in page


def test_entered_defect_of_the_previous_format_names_the_reason(web):  # noqa: F811
    """Отметка «Дефект создан в Hub» поставлена в 0.9.10 по тексту со строкой AST: хеш считается по буквальному
    прежнему тексту, а не по коду приложения; карточка говорит, что текст изменился, и называет причину – формат
    0.9.11 (ADR-0101)."""
    from app.routes.sca import _sig
    pid = prepared(web)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    explanation = "CVE-2099-10001: Уязвимость разбора позволяет нарушителю прочитать файлы сервера при подстановке."
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={"text_revision": "0", "target_version": "9.9.9"})
    assert first.status_code == 200, first.text
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(web.client.get(url).text), "text_revision": str(first.json()["text_revision"]),
        "target_version": "9.9.9", "version_checked": "1", "explanation": explanation})
    assert saved.status_code == 200 and saved.json()["ready"] is True, saved.text
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "3", "confirm": "1"})
    assert issued.status_code == 200, issued.text
    # прежний текст 0.9.8–0.9.10 буквально, целиком, независимо от кода: заголовок, AST первой находки строкой в
    # «Описании», Объяснение как ввёл оператор
    old_title = "ID3 - example-parser | Component version: 1.4.2 (SCA)"
    old_body = ("Описание\n"
                "CVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)\n"
                "AST-2026-000101 – публичный идентификатор не установлен\n"
                "\n"
                "Объяснение\n" + explanation + "\n"
                "\n"
                "Рекомендации\n"
                "Обновление example-parser до версии 9.9.9\n"
                "\n"
                "Источники\n"
                "https://nvd.nist.gov/vuln/detail/CVE-2099-10001\n")
    assert issued.json()["title"] == old_title
    old_hash = _sig(old_title, old_body)
    assert old_hash != issued.json()["text_sig"]
    review = db.get_review(pid, "73002")
    db.mark_entered(pid, "73002", True, review["revision"], old_hash)
    page = web.client.get(url).text
    assert 'id="entered-changed"' in page and "Причина – формат текста 0.9.11" in page
    # отметка по текущему тексту – без предупреждений
    db.mark_entered(pid, "73002", True, review["revision"], issued.json()["text_sig"])
    page = web.client.get(url).text
    assert 'id="entered-changed"' not in page and 'id="entered-format-updated"' not in page


def test_text_checked_and_entered_hash_follow_the_cleaned_text(web):  # noqa: F811
    """Объяснение не на русском и с AST: «Текст проверен» подтверждает текст без AST, отметка «Дефект создан в Hub» –
    по хешу выданного текста, посчитанному независимо от кода (title + body через _sig)."""
    from app.routes.sca import _sig
    pid = prepared(web)
    db = web.app.state.db
    db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    foreign = ("CVE-2099-10002 (это AST-2026-000101): XML external entities are resolved by default parser.\n"
               "CVE-2099-10001: Recursive entity expansion exhausts memory on small documents.")
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={"text_revision": "0", "target_version": "9.9.9"})
    assert first.status_code == 200, first.text
    shown = shown_fields(web.client.get(url).text)
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown, "text_revision": str(first.json()["text_revision"]), "target_version": "9.9.9",
        "version_checked": "1", "text_checked": "1", "explanation": foreign})
    assert saved.status_code == 200 and saved.json()["ready"] is True, saved.text
    assert not AST.search(saved.json()["explanation"])
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "4", "confirm": "1"})
    assert issued.status_code == 200 and not AST.search(issued.json()["body"]), issued.text
    assert _sig(issued.json()["title"], issued.json()["body"]) == issued.json()["text_sig"]
    revision = str(db.get_review(pid, "73001")["revision"])
    entered = web.client.post(f"{url}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": revision, "defect_sig": issued.json()["text_sig"]})
    assert entered.status_code == 200, entered.text
    # независимый эталон хеша: text_hash от заголовка и тела через разделитель U+001F (как считает приложение),
    # без вызова производственного _sig
    from app.db import text_hash
    expected = text_hash(issued.json()["title"] + "\x1f" + issued.json()["body"])
    assert issued.json()["text_sig"] == expected
    assert db.get_review(pid, "73001")["entered_text_hash"] == expected


def test_separate_set_with_ast_only_gives_no_defect_but_default_set_does(web):  # noqa: F811
    """Находка только с AST вынесена в отдельный набор: у него нет публичных идентификаторов – дефекта нет; набор по
    умолчанию (с CVE) выдаёт дефект без AST."""
    from test_sca_package_decision import set_form
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid1, card1 = sca_card(web, pid, "73001")
    url1 = f"/projects/{pid}/sca/findings/{fid1}"
    assert web.client.post(f"{url1}/set", headers=AS_JSON, data={**set_form(card1), "set_no": "new"}).status_code == 200
    text1 = web.client.post(f"{url1}/package-text", headers=AS_JSON, data={"text_revision": "0", "target_version": "9.9.9"})
    assert text1.status_code == 200 and text1.json()["ready"] is False and NO_PUBLIC_IDS in text1.json()["problems"]
    fid2, _ = sca_card(web, pid, "73002")
    url2 = f"/projects/{pid}/sca/findings/{fid2}"
    assert sca_text_ready(web, url2)["ready"] is True
    issued = web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "6", "confirm": "1"})
    assert issued.status_code == 200 and not AST.search(issued.json()["body"]), issued.text


def test_ast_only_finding_marked_no_defect_leaves_a_clean_default_set(web):  # noqa: F811
    """Находка только с AST помечена «без дефекта» с обоснованием: её карточка дефекта не даёт (причина – «без
    дефекта»), а набор по умолчанию с CVE выдаёт текст без AST и без этой находки."""
    from test_sca_package_decision import set_form
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid1, card1 = sca_card(web, pid, "73001")
    url1 = f"/projects/{pid}/sca/findings/{fid1}"
    marked = web.client.post(f"{url1}/set", headers=AS_JSON, data={
        **set_form(card1), "set_no": "none", "reason": "Внутренний номер без публичного соответствия, дефект не нужен."})
    assert marked.status_code == 200, marked.text
    own = web.client.post(f"{url1}/defect", headers=AS_JSON, data={"number": "7", "confirm": "1"})
    assert own.status_code == 409 and "без дефекта" in own.json()["detail"], own.text
    fid2, _ = sca_card(web, pid, "73002")
    url2 = f"/projects/{pid}/sca/findings/{fid2}"
    assert sca_text_ready(web, url2)["ready"] is True
    issued = web.client.post(f"{url2}/defect", headers=AS_JSON, data={"number": "7", "confirm": "1"})
    assert issued.status_code == 200, issued.text
    assert not AST.search(issued.json()["body"]) and "73001" in issued.json()["note"]


def test_set_with_ast_only_gives_no_defect(web):  # noqa: F811
    pid = prepared(web)
    fid, card = sca_card(web, pid, "73003")  # demo-xml: только AST-2026-000103
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "true_positive", "comment": "Обновить.",
        "reviewed": "1", "action": "save"})
    assert saved.status_code == 200, saved.text
    text = web.client.post(f"{url}/package-text", headers=AS_JSON, data={"text_revision": "0", "target_version": "2.0.9"})
    assert text.status_code == 200 and text.json()["ready"] is False, text.text
    assert NO_PUBLIC_IDS in text.json()["problems"] and text.json()["body"] == ""
    refused = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "1", "confirm": "1"})
    assert refused.status_code == 409 and refused.json()["detail"].startswith(NO_PUBLIC_IDS), refused.text
