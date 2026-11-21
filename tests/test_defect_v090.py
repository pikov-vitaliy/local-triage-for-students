"""Полный текст дефекта 0.9.0: область решения, справка по CWE/CAPEC с пределами и сокращением, заключение SCA по
ГОСТ Р КАПО, проверка выдачи по подписи выгрузки."""

from __future__ import annotations


import pytest

from app import defect
from app.db import Database, StaleReview
from app.models import Finding
from app.triage import order_findings
from test_web import web  # noqa: F401


def big_cwe(n_items: int = 8, text: str = "x") -> dict:
    return {"CWE-89": {"name": "SQL Injection", "name_ru": "Внедрение SQL-кода", "likelihood": "High",
                       "description": "The product constructs an SQL command.",
                       "consequences": [{"scope": ["Confidentiality"], "impact": [f"Impact {i}"]} for i in range(n_items)],
                       "mitigations": [{"phases": ["Implementation"], "strategy": "Parameterization",
                                        "description": [text * 50, "second"]} for _ in range(n_items)],
                       "attack_patterns": [f"CAPEC-{i}" for i in range(1, n_items + 1)],
                       "observed": [{"reference": f"CVE-2024-{i:04d}", "description": "desc"} for i in range(n_items)]}}


def test_export_label_and_area():
    assert defect.export_label("AppSec.Hub_issue_report_15_10_2026_20-27.xlsx", "") == "от 15.10.2026 (по имени файла)"
    assert defect.export_label("report_31_02_2026.xlsx", "2026-10-16T10:00:00+00:00") == "загружена в приложение 16.10.2026"
    assert defect.export_label("", "") == ""
    assert defect.area_text(["svc"], ["от 15.10.2026 (по имени файла)"], "2026-10-20T10:00:00+00:00") == (
        "Область: кодовая база svc; текущая выгрузка находки – от 15.10.2026 (по имени файла); решение от 20.10.2026.")
    assert defect.area_text(["a", "b", "a"], [], None) == "Область: кодовые базы a, b."
    assert defect.area_text([], [], None) == ""


def test_reference_limits_names_and_links():
    text = defect.reference_block(["89"], big_cwe(), {"CAPEC-1": "Accessing Functionality"})
    assert text.startswith(defect.REFERENCE_HEAD + "\nCWE-89 – SQL Injection (по БДУ ФСТЭК России: Внедрение SQL-кода). "
                           "Likelihood Of Exploit: High.")
    assert text.count("\n- Confidentiality: Impact") == 5 and text.count("CVE-2024-") == 3
    assert "- CAPEC-1: Accessing Functionality" in text and "- CAPEC-5\n" in text and "CAPEC-6" not in text
    assert "https://cwe.mitre.org/data/definitions/89.html" in text and "capec.mitre.org/data/definitions/1.html" in text
    assert defect.reference_block(["79"], big_cwe()) == "", "нет в каталоге – справки нет"


def test_reference_budget_cuts_in_order_with_note():
    text = defect.reference_block(["89"], big_cwe(text="y" * 10), budget=1500)
    assert "Observed Examples" not in text and "Справка сокращена" in text
    assert len(text) <= 1500
    tiny = defect.reference_block(["89"], big_cwe(text="y" * 10), budget=200)
    assert "Related Attack Patterns" not in tiny and "Potential Mitigations" not in tiny


def test_reference_seen_once_in_group():
    seen: set[str] = set()
    assert defect.reference_block(["89"], big_cwe(), seen=seen)
    assert defect.reference_block(["CWE-89"], big_cwe(), seen=seen) == ""


def test_reference_cleans_html():
    catalog = {"CWE-79": {"name": "<script>x</script>XSS", "description": "<b>bold</b>", "attack_patterns": ["CAPEC-<1>"]}}
    text = defect.reference_block(["79"], catalog)
    assert "<script>" not in text and "<b>" not in text and "CAPEC-<1>" not in text


def sca_row(hub_id: str, **extra) -> Finding:
    data = {"hub_id": hub_id, "kind": "SCA", "component": "lodash", "version": "4.17.20", "cve": ["CVE-2021-23337"],
            "cvss": 7.2, "cwe": ["CWE-94"], "dep_path": "web-ui > forms > lodash", **extra}
    return Finding.from_dict(data)


def test_sca_conclusion_by_outcome():
    rows = [sca_row("1"), sca_row("2", cvss=9.1)]
    text = defect.sca_conclusion(rows, "true_positive", "", ids_text="CVE-2021-23337", area="Область: кодовая база w.")
    assert text.startswith("Заключение AppSec: по выгрузке Hub в продукте используется компонент lodash 4.17.20 с "
                           "известной уязвимостью CVE-2021-23337. Статус уязвимости по ГОСТ Р КАПО: анализ не завершён")
    assert "CVSS по выгрузке Hub – до 9,1" in text and "- 1: web-ui > forms > lodash" in text
    assert defect.NOT_ACTUAL_PROOF in text and defect.GOST_KAPO_BASIS in text
    fp = defect.sca_conclusion(rows, "false_positive", "false_positive", ids_text="CVE-2021-23337")
    assert "ложноположительное срабатывание (ГОСТ Р КАПО, п. 6.12)" in fp and "Требуется от разработчика" not in fp


def test_sast_issue_rejected_when_export_label_changes(tmp_path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    f = Finding(hub_id="1", kind="SAST", rule="R", file="a.java", line=1)
    db.save_import(pid, "AppSec.Hub_issue_report_15_10_2026.xlsx", "xlsx", [], {}, [], order_findings([f]))
    review = db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="x",
                            reviewed=False)
    source = db.case_input(pid, "1")
    from app.db import source_signature
    label = defect.export_label(source["import_filename"], source["import_at"])
    assert label == "от 15.10.2026 (по имени файла)"
    db.save_import(pid, "AppSec.Hub_issue_report_19_10_2026.xlsx", "xlsx", [], {}, [], order_findings([f]))
    with pytest.raises(StaleReview):
        db.set_defect_number_checked(pid, "sast:1", 1, "1", source_sig=source_signature(source),
                                     revision=int(review["revision"]), case_verdict_id=None, export=label)
    db.close()


def test_reference_budget_is_strict_for_many_cwes():
    catalog = {f"CWE-{n}": {"name": f"Weakness {n}", "description": "d" * 600} for n in range(1, 11)}
    text = defect.reference_block([f"CWE-{n}" for n in range(1, 11)], catalog)
    assert len(text) <= defect.REFERENCE_BUDGET and text.endswith("capec.mitre.org.")
    assert text.startswith(defect.REFERENCE_HEAD)


def test_effective_kapo_for_old_decisions():
    assert defect.effective_kapo("true_positive", "") == "not_finished"
    assert defect.effective_kapo("false_positive", "") == "false_positive"
    assert defect.effective_kapo("true_positive", "actual") == "actual"
    assert defect.effective_kapo("risk_accepted", "") == ""


def test_sca_conclusion_actual_requires_measures_not_proof():
    rows = [sca_row("1")]
    actual = defect.sca_conclusion(rows, "true_positive", "actual", ids_text="CVE-2021-23337")
    assert "Статус уязвимости по ГОСТ Р КАПО: актуальна." in actual and "принять компенсирующие меры" in actual
    assert "Что не установлено" not in actual and defect.NOT_ACTUAL_PROOF not in actual
    pending = defect.sca_conclusion(rows, "true_positive", "not_finished", ids_text="CVE-2021-23337")
    assert "Что не установлено" in pending and defect.NOT_ACTUAL_PROOF in pending
    dirty = defect.sca_conclusion(rows, "true_positive", "", ids_text="<b>CVE-1</b>")
    assert "<b>" not in dirty


def test_sast_body_cleans_team_and_keeps_generics():
    f = Finding(hub_id="1", kind="SAST", rule="Unsafe List<String> use", file="a.java", line=1, cwe=["89"])
    body = defect.sast_body(f, "true_positive", "x", "Заменить List<String> на неизменяемый список.", "<b>TEAM</b>")
    assert "<b>" not in body and "команда TEAM" in body and "List<String>" in body


def test_group_siblings_same_line_and_category_across_codebases(tmp_path):
    """Та же категория (правило и CWE), тот же файл и строка в любых кодовых базах – одна группа (ADR-0089)."""
    from app.hub_import import group_key2 as group_key  # ключ группы второй редакции (ADR-0095)
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    rows = [Finding(hub_id="1", kind="SAST", rule="R", file="a.java", line=1, cwe=["CWE-89"], codebase="svc"),
            Finding(hub_id="2", kind="SAST", rule="R", file="a.java", line=1, cwe=["CWE-89"], codebase="fork"),
            Finding(hub_id="3", kind="SAST", rule="R", file="a.java", line=2, cwe=["CWE-89"], codebase="svc"),
            Finding(hub_id="4", kind="SAST", rule="Q", file="a.java", line=1, cwe=["CWE-89"], codebase="svc"),
            Finding(hub_id="5", kind="SAST", rule="R", file="a.java", line=1, cwe=["CWE-89"], codebase="old")]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    siblings = db.group_siblings(pid, group_key(rows[0]), "1")
    assert sorted(s["hub_id"] for s in siblings) == ["2", "5"], "другая строка или правило – не группа"
    assert all(s["decision"] == "" and s["defect_number"] is None for s in siblings)
    db.set_defect_number(pid, defect.defect_key_sast("2"), 7)
    assert {s["hub_id"]: s["defect_number"] for s in db.group_siblings(pid, group_key(rows[0]), "1")}["2"] == 7
    assert db.group_siblings(pid, "", "1") == [], "без строки группы нет (пустой ключ второй редакции)"
    # находки, которых нет в текущей выгрузке, не входят
    db.save_import(pid, "b.xlsx", "xlsx", [], {}, [], order_findings([rows[0], rows[1]]))
    assert [s["hub_id"] for s in db.group_siblings(pid, group_key(rows[0]), "1")] == ["2"]
    db.close()


def test_gost_hints_in_cards_and_settings(web):
    from test_sca import sca_card
    from test_web import prepared
    from app.defect import GOST_STATUS_NOTES
    page = web.client.get("/settings").text
    for verdict in ("true_positive", "false_positive", "uncertain", "risk_accepted"):
        assert f"SAST (ГОСТ Р 71207-2024, п. 5.5) – {GOST_STATUS_NOTES['sast'][verdict]}; SCA" in page
        assert f"SCA (ГОСТ Р КАПО, пп. 6.12, 6.14) – {GOST_STATUS_NOTES['sca'][verdict]}." in page
    pid = prepared(web)
    db = web.app.state.db
    db.set_settings({"hub_status_map": {"false_positive": "<b>Ложное</b>", "uncertain": ""}})
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    # SAST с 0.9.6: два решения, статус ложного срабатывания – из настроек, без списка вердиктов и «Риск принят»
    assert "«Ложное срабатывание» – в Hub статус «&lt;b&gt;Ложное&lt;/b&gt;»" in card and "<b>Ложное" not in card
    assert 'id="final-verdict"' not in card and 'value="risk_accepted"' not in card
    assert 'id="status-gost-head"' not in card
    _, sca = sca_card(web, pid, "73001")
    assert '<p id="status-gost-head">Соответствие ГОСТ Р КАПО, пп. 6.12, 6.14:</p>' in sca
    assert "<li>«Риск принят» – уязвимость неактуальна (с обоснованием) или нейтрализована принятыми мерами</li>" in sca
    assert ">обновить – в Hub «Подтверждено»</option>" in sca
    assert 'id="risk-hint" hidden' in sca and 'aria-describedby="comment-stale risk-hint sca-comment-count"' in sca


@pytest.mark.parametrize("kind", ["DAST", "SCA-license"])
def test_gost_short_text_only_for_sast(kind):
    from app import prompts
    f = Finding(hub_id="1", kind=kind, rule="R", file="a", line=1, cwe=["89"], component="x", version="1")
    for verdict in ("true_positive", "false_positive", "risk_accepted"):
        assert prompts.hub_text(f, verdict, "причина") == prompts.hub_text_v1(f, verdict, "причина")
    assert "ГОСТ" not in prompts.hub_text(f, "true_positive", "причина")



def test_whole_new_text_is_cleaned():
    row = sca_row("1", fixed_version="4.17.21<img src=x onerror=1>", component="lodash<script>x</script>")
    title = defect.sca_title(1, row.component, row.version)
    for text in (title, defect.hub_lines("<b>Подтверждено</b>", "x")):
        assert "<img" not in text and "<script>" not in text and "<b>" not in text
    f = Finding(hub_id="1", kind="SAST", rule="Unsafe Map<String, List<T>> <b>x</b>", file="a.java", line=1)
    assert defect.sast_title(1, f) == "ID1 - Unsafe Map<String, List<T>> x (SAST)"


@pytest.mark.parametrize("kind", ["DAST", "SCA-license"])
def test_card_of_other_kinds_has_no_sast_gost_hints(web, kind):
    from test_db import load
    db = web.app.state.db
    pid = db.create_project("Виды")
    load(db, pid, [Finding(hub_id="77001", kind=kind, rule="R", file="a", line=1, cwe=["CWE-79"],
                           component="x", version="1", licenses="GPL-3.0")])
    fid = db.get_finding_by_hub_id(pid, "77001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert "ГОСТ Р 71207-2024" not in card and 'id="status-gost"' not in card
