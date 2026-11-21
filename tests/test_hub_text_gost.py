"""Текст для Hub (0.9.0, SAST – 0.9.6): комментарий SAST и короткое заключение SCA, уточнение по ГОСТ Р КАПО, отпечатки отметки
«Внесено в Hub» прежнего и нового формата, совпадение превью карточки с JSON-ответом."""

from __future__ import annotations

import html
import re

import pytest

from app import sca
from app.db import Database, text_hash
from app.models import Finding
from app.prompts import hub_text, hub_text_v1, hub_text_v2
from app.routes.sca import ReviewRejected, normalized_kapo
from app.triage import order_findings
from test_sca import AS_JSON, answers_text, form_fields, post_answers, sca_card
from test_web import prepared, web  # noqa: F401


def sast() -> Finding:
    return Finding(hub_id="1", kind="SAST", rule="Внедрение SQL-кода", file="src/A.java", line=42, cwe=["89"])


def sca_item(**extra) -> Finding:
    data = {"hub_id": "2", "kind": "SCA", "component": "lodash", "version": "4.17.20", "cve": ["CVE-2021-23337"],
            "fixed_version": "4.17.21", "cvss": 7.2, **extra}
    return Finding(**data)


# ============================================================================ SAST

def test_sast_texts_by_outcome():
    """0.9.6 (ADR-0089): в Hub – только обоснование оператора, без «Статус:», места срабатывания и требований."""
    f = sast()
    assert hub_text(f, "true_positive", "Подтверждено: id из запроса без параметров", None) == \
        "Подтверждено: id из запроса без параметров", "текст оператора – как написан (ADR-0149)"
    fp = hub_text(f, "false_positive", "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена.",
                  None)
    assert fp == "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."
    assert "Статус" not in fp and "src/A.java" not in fp and "ГОСТ" not in fp


def test_sast_text_v2_kept_for_old_marks():
    """Формат 0.9.0–0.9.5 остаётся для распознавания отметок «Внесено в Hub», поставленных по нему."""
    f = sast()
    tp = hub_text_v2(f, "true_positive", "Подтверждено: id из запроса без параметров", None)
    assert tp.startswith("Статус: Подтверждено\nКомментарий: Подтверждена ошибка в программе класса CWE-89: "
                         "Внедрение SQL-кода в src/A.java:42.")
    assert "\nОбоснование: id из запроса без параметров\n" in tp
    assert hub_text_v2(f, "false_positive", "x", {"false_positive": "Not an issue"}).startswith("Статус: Not an issue\n")
    assert hub_text_v2(f, "uncertain", "x", {"uncertain": ""}).startswith("Комментарий: "), "пустой статус – без строки"


def test_sast_text_is_kept_as_written():
    """С 0.10.0.dev21 (ADR-0149) теги и длинное тире оператора не вырезаются и не меняются."""
    text = hub_text(Finding(hub_id="3", kind="SAST", rule="<b>XSS</b>", file="a.js", line=1), "false_positive",
                    "Проверено " + chr(0x2014) + " <b>ок</b>", None)
    assert text == "Проверено " + chr(0x2014) + " <b>ок</b>"


def test_legacy_format_kept_for_old_marks():
    f = sast()
    assert hub_text_v1(f, "true_positive", "Подтверждено: x", None) == "Статус: Подтверждено\nКомментарий: Подтверждено: x"


# ============================================================================ SCA

def test_sca_short_text_is_operator_reason_only():
    """Формат 0.9.11 (ADR-0101): у «Ложное срабатывание» и «Риск принят» – номер, компонент и обоснование оператора,
    без «Статус:», заключения по ГОСТ Р КАПО и требований; у «Обновить», «неясно» и «Отложить» текста нет. Прежний
    формат 0.9.8–0.9.10 – только обоснование (hub_text_v3)."""
    f = sca_item()
    reason = "Уязвимая функция template в продукте не вызывается."
    assert sca.hub_text(f, "false_positive", reason) == "CVE-2021-23337 в lodash 4.17.20: " + reason
    assert sca.hub_text(f, "risk_accepted", reason, kapo_state="not_actual") == "CVE-2021-23337 в lodash 4.17.20: " + reason
    assert sca.hub_text_v3(f, "false_positive", reason) == reason
    for verdict in ("true_positive", "uncertain"):
        assert sca.hub_text(f, verdict, reason) == ""
    as_written = sca.hub_text(f, "false_positive", "Проверено " + chr(0x2014) + " <b>ок</b>")
    assert as_written == "CVE-2021-23337 в lodash 4.17.20: Проверено " + chr(0x2014) + " <b>ок</b>"  # ADR-0149


def test_sca_texts_by_kapo_state_v2():
    """Формат 0.9.0–0.9.7 остаётся для узнавания прежних отметок «Внесено в Hub»."""
    f = sca_item()
    default = sca.hub_text_v2(f, "true_positive", "Обновить до 4.17.21.")
    assert "Статус уязвимости по ГОСТ Р КАПО: анализ не завершён – актуальность не установлена." in default
    assert "Критичность: не определена" in default and "CVSS по выгрузке Hub – 7,2" in default
    assert "(по данным Hub – 4.17.21 или новее)" in default and "по регламенту композиционного анализа" in default
    actual = sca.hub_text_v2(f, "true_positive", "x", kapo_state="actual")
    assert "Статус уязвимости по ГОСТ Р КАПО: актуальна." in actual and "принять компенсирующие меры" in actual
    fp = sca.hub_text_v2(f, "false_positive", "x")
    assert "Ложноположительное срабатывание (ГОСТ Р КАПО, п. 6.12)" in fp and "Критичность: не оценивалась" in fp
    not_actual = sca.hub_text_v2(f, "risk_accepted", "template не вызывается", kapo_state="not_actual")
    assert "неактуальна для продукта (ГОСТ Р КАПО, п. 6.14)" in not_actual
    assert "\nОбоснование неактуальности: template не вызывается" in not_actual
    neutral = sca.hub_text_v2(f, "risk_accepted", "доступ закрыт", kapo_state="neutralized")
    assert "нейтрализована принятыми мерами" in neutral and "Принятые меры и обоснование: доступ закрыт" in neutral
    legacy = sca.hub_text_v2(f, "risk_accepted", "x")
    assert "уточнение по ГОСТ Р КАПО не указано" in legacy, "у прежних решений уточнения нет"


def test_sca_text_v2_cleans_inserted_values():
    f = sca_item(fixed_version="4.17.21<img src=x onerror=alert(1)>", component="lodash<script>")
    text = sca.hub_text_v2(f, "true_positive", "x")
    assert "<img" not in text and "<script>" not in text and "4.17.21 или новее" in text
    assert "Критичность: не определена – оценки CVSS в выгрузке нет" in sca.hub_text_v2(sca_item(cvss=None), "uncertain",
                                                                                       "")


# ============================================================================ допустимые уточнения

@pytest.mark.parametrize("outcome,value,expected", [
    ("true_positive", "", "not_finished"), ("true_positive", "actual", "actual"),
    ("false_positive", "", "false_positive"), ("uncertain", "actual", ""), ("risk_accepted", "not_actual", "not_actual"),
    ("risk_accepted", "neutralized", "neutralized")])
def test_normalized_kapo(outcome, value, expected):
    assert normalized_kapo(outcome, value) == expected


def test_normalized_kapo_rejects():
    with pytest.raises(ReviewRejected):
        normalized_kapo("risk_accepted", "")
    with pytest.raises(Exception):
        normalized_kapo("true_positive", "not_actual")


def test_sast_never_keeps_kapo(tmp_path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    db.save_import(pid, "a.csv", "csv", [], {}, [], order_findings([sast()]))
    review = db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="x",
                            reviewed=False, kapo_state="actual")
    assert review["kapo_state"] == ""
    db.close()


def test_reimport_sca_as_sast_drops_kapo(tmp_path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    db.save_import(pid, "a.csv", "csv", [], {}, [], order_findings([sca_item(hub_id="9")]))
    db.save_review(pid, "9", decision="risk_accepted", final_verdict="", final_comment="x", reviewed=False,
                   kapo_state="not_actual")
    db.save_import(pid, "b.csv", "csv", [], {}, [], order_findings([Finding(hub_id="9", kind="SAST", rule="R")]))
    assert db.get_review(pid, "9")["kapo_state"] == ""
    db.close()


def test_decided_at_kept_when_outcome_same(tmp_path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    db.save_import(pid, "a.csv", "csv", [], {}, [], order_findings([sca_item()]))
    first = db.save_review(pid, "2", decision="agree", final_verdict="true_positive", final_comment="x", reviewed=False)
    again = db.save_review(pid, "2", decision="disagree", final_verdict="true_positive", final_comment="x",
                           reviewed=False)
    assert again["decided_at"] == first["decided_at"], "тот же итог, уточнение и комментарий – дата прежняя"
    db.close()


# ============================================================================ карточка SCA: отпечатки и превью

def card_flags(page: str) -> dict:
    return {name: f'id="{name}"' in page for name in ("entered-changed", "entered-format-updated", "entered-unconfirmed")}


def test_sca_entered_marks_v2_v1_other_empty(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "disagree", "final_verdict": "false_positive",
        "comment": "Уязвимая функция разбора в продукте не вызывается.", "reviewed": "1", "action": "copy"}).json()
    db = web.app.state.db
    page = web.client.get(url).text
    preview = html.unescape(re.search(r'<pre id="hub-text"[^>]*>(.*?)</pre>', page, re.S).group(1))
    assert preview == saved["hub_text"], "превью карточки – тот же текст, что скопирован"
    review = db.get_review(pid, "73001")
    from app.models import Finding as F
    f = F.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    from app.routes.sca import saved_hub_text_v1, saved_hub_text_v2, saved_hub_text_v3
    legacy = saved_hub_text_v1(db, web.app.state.settings, pid, f, review)
    legacy_v2 = saved_hub_text_v2(db, web.app.state.settings, pid, f, review)
    legacy_v3 = saved_hub_text_v3(review, f)  # 0.9.8–0.9.10: только обоснование (ADR-0101)
    assert legacy_v3 == "Уязвимая функция разбора в продукте не вызывается." and saved["hub_text"].endswith(legacy_v3)
    cases = {"v2": text_hash(saved["hub_text"]), "v1": text_hash(legacy), "v0.9.0": text_hash(legacy_v2),
             "v0.9.8": text_hash(legacy_v3), "other": text_hash("иной текст"), "empty": ""}
    expected = {"v2": {"entered-changed": False, "entered-format-updated": False, "entered-unconfirmed": False},
                "v0.9.8": {"entered-changed": False, "entered-format-updated": True, "entered-unconfirmed": False},
                "v1": {"entered-changed": False, "entered-format-updated": True, "entered-unconfirmed": False},
                "v0.9.0": {"entered-changed": False, "entered-format-updated": True, "entered-unconfirmed": False},
                "other": {"entered-changed": True, "entered-format-updated": False, "entered-unconfirmed": False},
                "empty": {"entered-changed": False, "entered-format-updated": False, "entered-unconfirmed": True}}
    for name, digest in cases.items():
        db.mark_entered(pid, "73001", True, review["revision"], digest)
        page = web.client.get(url).text
        assert card_flags(page) == expected[name], name
        mark_hidden = 'id="mark-entered" hidden' in page
        assert mark_hidden == (name == "v2"), f"{name}: кнопка «Подтвердить: статус и комментарий внесены в Hub»"
