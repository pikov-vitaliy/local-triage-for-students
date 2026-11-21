"""Решения оператора о применимости (ADR-0094 Р3) и замечания ревью 82103ee: одна карта классов уязвимостей для области
набора, проверки цели и пояснения о версии Hub; позиции источников; охват проверки цели; источники автоматических
утверждений по общим правилам; отметки – только к показанному; запись текста и решения – одной транзакцией со
сверкой. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

import copy
import json
import re

import pytest

from app import sca, sca_text as t
from app.db import StaleReview
from test_review_k_group import card_value, tp_with_text
from test_sca import AS_JSON, shown_fields
from test_sca_residual import FIXED, NOFIX, finding, research
from test_web import ORIGIN, prepared, web  # noqa: F401


# ============================================================================ ревью 82103ee: проверка цели

def target_check(findings=(), complete=True, version="1.5.0"):
    return {"role": "target", "version": version, "findings": list(findings),
            "coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": complete, "source_refs": ["adv"]}]}


def test_partial_coverage_of_the_target_check_is_not_verified():
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, checks=[target_check(complete=False)]),
                            "2026-10-22")
    assert check.state == "unverified" and "целевой версии неполный" in check.detail
    full = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, checks=[target_check()]), "2026-10-22")
    assert full.state == "verified"


def test_one_class_through_an_external_mapping_is_contradictory():
    """CVE и GHSA связаны только через AST: у CVE «исправления нет» с попаданием цели, у GHSA – исправление не выше
    цели. Это один класс с противоречием – «затронута», а не остаточная."""
    cve = finding("CVE-2099-5001", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.5.0"}],
                  fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]})
    ghsa = finding("GHSA-aaaa-bbbb-cccc", [{"introduced": "1.0.0", "fixed": "1.3.0"}], ["1.3.0"],
                   fix_status={"status": "fixed", "scope": "package", "source_refs": ["adv"]})
    data = research(FIXED, cve, ghsa)
    alone = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
    assert [r["id"] for r in alone.residual] == ["CVE-2099-5001"], "без соответствия классы раздельны"
    rep = t.union_classes(t.class_groups([["AST-2026-000001"]], {"AST-2026-000001": ["CVE-2099-5001",
                                                                                     "GHSA-aaaa-bbbb-cccc"]}, data))
    merged = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22", rep=rep)
    assert merged.state == "affected" and merged.affected == ["CVE-2099-5001"] and not merged.residual


def test_source_positions_count_as_affecting():
    """Общий диапазон кончается до цели, позиция другого источника включает её и называет исправление выше –
    «затронута»; пояснение о версии Hub такую уязвимость не называет."""
    spread = finding("CVE-2099-5002", [{"introduced": "1.0.0", "fixed": "1.2.5"}], ["1.2.5"],
                     source_positions=[{"source": "NVD", "affects": "yes", "ranges": [{"introduced": "1.0.0",
                                                                                     "fixed": "1.2.5"}],
                                        "source_refs": ["adv"]},
                                       {"source": "GitHub", "affects": "yes",
                                        "ranges": [{"introduced": "1.0.0", "fixed": "1.6.0"}], "source_refs": ["adv"]}])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(spread), "2026-10-22")
    assert check.state == "affected" and check.affected == ["CVE-2099-5002"]
    hub = {"role": "hub", "version": "1.4.2", "coverage": [{"purpose": "vulnerabilities", "status": "ok",
                                                            "complete": True}],
           "findings": [finding("CVE-2099-5002", [{"introduced": "1.0.0", "fixed": "1.6.0"}])]}
    assert t.hub_note("maven", ["1.4.2"], "1.5.0", research(spread, checks=[target_check(), hub])) == ""
    # позиция «затрагивает» без диапазонов – о цели ничего не известно
    empty = finding("CVE-2099-5003", [{"introduced": "1.0.0", "fixed": "1.2.5"}], ["1.2.5"],
                    source_positions=[{"source": "GitHub", "affects": "yes", "ranges": [], "source_refs": ["adv"]}])
    assert t.check_version("maven", "1.2.0", "1.5.0", research(empty), "2026-10-22").state == "unverified"


def test_affected_keeps_the_residual_list():
    later = finding("CVE-2099-5004", [{"introduced": "1.0.0", "fixed": "1.6.0"}], ["1.6.0"])
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, NOFIX, later), "2026-10-22")
    assert check.state == "affected" and [r["id"] for r in check.residual] == ["GHSA-nnnn-oooo-ffff"]


def test_hub_note_returns_its_evidence_and_sources_follow_the_common_rules():
    medium = finding("CVE-2099-2001", [{"introduced": "1.4.0", "fixed": "1.5.0"}], ["1.5.0"])
    hub = {"role": "hub", "version": "1.4.2", "findings": [medium],
           "coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": True}]}
    data = research(FIXED, checks=[target_check(), hub])
    text, refs = t.hub_explanation("maven", ["1.4.2"], "1.5.0", data)
    assert "CVE-2099-2001" in text and "adv" in refs
    assert t.evidence_urls(refs, data) == ["https://github.com/example/driver/security/advisories/GHSA-nnnn-oooo-ffff"]
    weak = copy.deepcopy(data)
    weak["evidence"][0]["level"] = "unconfirmed"
    assert t.evidence_urls(refs, weak) == [], "неподтверждённое доказательство в текст не идёт"
    item = {"id": "GHSA-nnnn-oooo-ffff", "severity": "низкая", "status": "no_fix_published", "scope": "package",
            "date": "2026-10-20", "refs": ["adv"], "proof_refs": ["adv"]}
    assert "(github.com)" in t.residual_line(item, "1.5.0", data)
    assert "(github.com)" not in t.residual_line(item, "1.5.0", weak)


def test_all_hub_versions_and_mixed_version_order():
    assert sca.all_versions("1.4.2, 1.4.3; 1.4.2") == ["1.4.2", "1.4.3"]
    assert t._version_key("1.4.RELEASE") > t._version_key("1.4.2"), "сравнение версий с буквами не падает"


# ============================================================================ Р3: решения по классам

def decision(key, ids, value, revision=1):
    return {"vuln_key": key, "ids": ids, "decision": value, "reason": "Проверено.", "research_revision": revision,
            "revision": 1}


def test_decision_is_effective_only_for_the_same_class_and_research():
    rep = t.union_classes([["CVE-2099-6001"], ["GHSA-aaaa-bbbb-cccc"]])
    rows = [decision("CVE-2099-6001", ["CVE-2099-6001"], "not_product")]
    root = t.class_root(rep, "CVE-2099-6001")
    assert t.applicability(rows, rep, 1)[root]["decision"] == "not_product"
    stale = t.applicability(rows, rep, 2)[root]
    assert stale["decision"] == "" and stale["stale"] == "исследование компонента обновлено"
    grown = t.union_classes([["CVE-2099-6001", "GHSA-aaaa-bbbb-cccc"]])  # к классу присоединился GHSA
    info = t.applicability(rows, grown, 1)[t.class_root(grown, "CVE-2099-6001")]
    assert info["decision"] == "" and info["stale"] == "состав уязвимости изменился"
    # два решения, которые стали одним классом после нового соответствия, – противоположные
    both = rows + [decision("GHSA-aaaa-bbbb-cccc", ["GHSA-aaaa-bbbb-cccc"], "applies")]
    info = t.applicability(both, grown, 1)[t.class_root(grown, "CVE-2099-6001")]
    assert info["decision"] == "" and info["stale"] == "противоположные решения в одном классе уязвимости"


def research_item(vuln_id, applies):
    return {"id": vuln_id, "aliases": [], "applies": applies, "ranges": [], "source_refs": []}


def test_decisions_change_only_the_research_applicability_in_the_set():
    research_rows = [research_item("CVE-2099-6101", "yes"), research_item("CVE-2099-6102", "no"),
                     research_item("CVE-2099-6103", "no")]
    members, others = {"1": ["CVE-2099-6104"]}, {"2": ["CVE-2099-6103"]}
    rep = t.union_classes(t.class_groups([*members.values(), *others.values()], {},
                                         {"public_findings": research_rows}))
    root = lambda i: t.class_root(rep, i)  # noqa: E731
    base = [v.main for v in t.set_vulns(members, others, {}, research_rows, rep=rep)]
    assert base == ["CVE-2099-6104", "CVE-2099-6101"]
    decided = {root("CVE-2099-6101"): "not_current", root("CVE-2099-6102"): "applies",
               root("CVE-2099-6103"): "applies", root("CVE-2099-6104"): "not_product"}
    got = [v.main for v in t.set_vulns(members, others, {}, research_rows, rep=rep, applicability=decided)]
    # «не затрагивает» убрала уязвимость исследования; «применима» добавила только не связанную с находкой другого
    # исхода; членство важнее решения
    assert got == ["CVE-2099-6104", "CVE-2099-6102"]
    other_set = [v.main for v in t.set_vulns(members, others, {}, research_rows, default_set=False, rep=rep,
                                             applicability=decided)]
    assert other_set == ["CVE-2099-6104"], "в отдельный набор исследование не добавляется"


def test_not_product_drops_the_class_from_the_target_check_and_not_current_does_not():
    later = finding("CVE-2099-6201", [{"introduced": "1.0.0", "fixed": "1.6.0"}], ["1.6.0"])
    data = research(FIXED, later)
    assert t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22").state == "affected"
    assert t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22",
                           not_applicable=["CVE-2099-6201"]).state == "verified"


# ============================================================================ Р3 через маршрут и базу

EVIDENCE = [
    {"evidence_ref": "adv", "url": "https://github.com/example/parser/security/advisories/GHSA-pppp-qqqq-rrrr",
     "source_type": "advisory", "level": "primary", "quote": "Affected versions", "checked_at": "2026-10-20"},
    {"evidence_ref": "reg", "url": "https://repo.example/parser/9.9.9", "source_type": "registry", "level": "primary"},
]


def payload(disputed_fixed: str | None = "10.0.0") -> dict:
    disputed = {"id": "CVE-2099-30001", "aliases": [], "applies": "no", "description": "Описание.",
                "conditions": None, "ranges": [{"introduced": "5.0.0", "fixed": disputed_fixed}],
                "fixed_versions": [disputed_fixed] if disputed_fixed else [], "source_refs": ["adv"],
                "disputed": {"by": "vendor", "note": "Производитель оспаривает уязвимость.", "source_refs": ["adv"]},
                "source_positions": [{"source": "NVD", "affects": "no", "ranges": [], "source_refs": ["adv"]},
                                     {"source": "GitHub", "affects": "no",
                                      "ranges": [{"introduced": "5.0.0", "fixed": disputed_fixed}],
                                      "source_refs": ["adv"]}]}
    return {"public_findings": [
        {"id": "CVE-2099-10002", "aliases": [], "applies": "yes", "description": "Описание.", "conditions": None,
         "ranges": [{"introduced": "1.0.0", "fixed": "1.4.9"}], "fixed_versions": ["1.4.9"], "source_refs": ["adv"]},
        disputed],
        "evidence": copy.deepcopy(EVIDENCE),
        "package_advice": {"action": "update", "target_version": "9.9.9", "source_refs": ["reg"]},
        "latest_stable_release": {"version": "9.9.9", "source_refs": ["reg"]},
        "research_coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": True}], "version_checks": []}


def put_research(db, pid: int, ref: str, data: dict, observed: str = "2026-10-22") -> int:
    """Ревизия исследования компонента прямо в базе (как после загрузки ответа агента)."""
    with db._tx() as c:
        task = c.execute("SELECT id FROM sca2_tasks WHERE project_id = ?", (pid,)).fetchone()
        if task is None:
            task_id = c.execute("INSERT INTO sca2_tasks(project_id, import_id, task_id, contract, answer_contract,"
                                " validator_version, manifest_sha256, created_at, updated_at) VALUES (?, 0, 't', 'c', 'a', 'v',"
                                " 'm', ?, ?) RETURNING id", (pid, observed, observed)).fetchone()[0]
        else:
            task_id = task[0]
        revision = (c.execute("SELECT MAX(revision) FROM sca2_research WHERE project_id = ? AND input_ref = ?",
                              (pid, ref)).fetchone()[0] or 0) + 1
        c.execute("INSERT INTO sca2_research(project_id, task_id, input_ref, revision, answer_sig, payload_json,"
                  " imported_at, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (pid, task_id, ref, revision, f"sig{revision}", json.dumps(data), observed, observed))
    return revision


def rows_count(db) -> int:
    with db._lock:
        return db._conn.execute("SELECT COUNT(*) FROM sca_applicability").fetchone()[0]


def decide(web, url, card, key, value, reason="Уязвимая функция в продукте не вызывается: проверено по коду.",
           **extra):
    form = re.search(r'<form[^>]*/applicability[^>]*>(?:(?!</form>).)*name="vuln_key" value="' + re.escape(key)
                     + r'"(?:(?!</form>).)*</form>', card, re.S).group(0)
    data = {name: re.search(rf'name="{name}" value="([^"]*)"', form).group(1)
            for name in ("vuln_key", "revision", "research_revision", "shown_fp")}
    return web.client.post(f"{url}/applicability", headers=ORIGIN, follow_redirects=False,
                           data={**data, "decision": value, "reason": reason, **extra})


@pytest.fixture
def disputed(web):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    ref = db.sca_snapshot(pid, "73001").input_ref
    put_research(db, pid, ref, payload())
    return pid, url, db, ref


def test_card_shows_disputed_positions_and_not_product_unblocks_the_target(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    assert 'id="sca-applicability"' in card and "оспорена: производитель" in card
    assert "NVD – не применима" in card and "GitHub – не применима" in card
    assert "затронута: CVE-2099-30001" in card
    before = db.sca_defect_fingerprint(pid, "73001")
    assert decide(web, url, card, "CVE-2099-30001", "not_product", reason="").status_code == 400
    assert rows_count(db) == 0, "без обоснования не записано"
    stale = decide(web, url, card, "CVE-2099-30001", "not_product", shown_fp="другой")
    assert stale.status_code == 409 and rows_count(db) == 0, "устаревший отпечаток – ничего не записано"
    done = decide(web, url, card, "CVE-2099-30001", "not_product")
    assert done.status_code == 303 and "sca_applicability_saved" in done.headers["location"]
    assert rows_count(db) == 1 and db.sca_defect_fingerprint(pid, "73001") != before
    card = web.client.get(url).text
    assert "затронута: CVE-2099-30001" not in card
    assert "Решение оператора: <strong>не применима к продукту</strong>" in card
    # пакетная форма, открытая до решения, устарела: отпечаток включает решения о применимости
    assert decide(web, url, card.replace(card_value(card, "package_fp"), "x"), "CVE-2099-10002",
                  "applies").status_code == 409
    # новая ревизия исследования – решение не действует, причина в карточке
    put_research(db, pid, ref, payload())
    card = web.client.get(url).text
    assert "Решение не действует: исследование компонента обновлено" in card
    assert "затронута: CVE-2099-30001" in card


def test_not_current_does_not_touch_the_target_check(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-30001", "not_current").status_code == 303
    assert "затронута: CVE-2099-30001" in web.client.get(url).text


def test_stale_revision_and_research_are_refused_in_the_transaction(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    snap = db.sca_snapshot(pid, "73001")
    ids = ["CVE-2099-30001"]
    with pytest.raises(StaleReview):
        db.save_sca_applicability(pid, "73001", "CVE-2099-30001", ids, "not_product", "Проверено.",
                                  expect_revision=0, expect_research_revision=2, expect_fp=snap.fingerprint)
    with pytest.raises(StaleReview):
        db.save_sca_applicability(pid, "73001", "CVE-2099-30001", ids, "not_product", "Проверено.",
                                  expect_revision=3, expect_research_revision=1, expect_fp=snap.fingerprint)
    assert rows_count(db) == 0
    saved = db.save_sca_applicability(pid, "73001", "CVE-2099-30001", ids, "not_product", "Проверено.",
                                      expect_revision=0, expect_research_revision=1, expect_fp=snap.fingerprint)
    assert saved["revision"] == 1 and saved["research_revision"] == 1
    # повторное решение по классу под новым ключом удаляет прежние строки, пересекающиеся с классом
    snap = db.sca_snapshot(pid, "73001")
    db.save_sca_applicability(pid, "73001", "CVE-2099-30002", ["CVE-2099-30001", "CVE-2099-30002"], "applies",
                              "Проверено.", expect_revision=0, expect_research_revision=1, expect_fp=snap.fingerprint)
    stored = {r["vuln_key"]: (r["decision"], r["revision"]) for r in db.sca_snapshot(pid, "73001").applicability}
    assert stored == {"CVE-2099-30001": ("", 2), "CVE-2099-30002": ("applies", 1)}, "прежнее снято, не удалено"


def test_opposite_decisions_after_a_new_mapping_do_not_act(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-30001", "not_product").status_code == 303
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-10002", "applies").status_code == 303
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    ast = next(i for i in data.get("vuln_ids") or [] if str(i).upper().startswith("AST"))
    db.save_ast_map([(ast, "CVE-2099-10002"), (ast, "CVE-2099-30001")], "оператор")
    card = web.client.get(url).text
    assert "Решение не действует: противоположные решения в одном классе уязвимости" in card
    # недействующее решение – как отсутствие решения; класс назван основным идентификатором
    assert "затронута: CVE-2099-10002" in card


def test_text_exclusion_does_not_change_applicability(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    with db._tx() as c:  # исключение уязвимости из текста набора (ADR-0091 п. 9) – только текст
        c.execute("INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, excluded_json, updated_at)"
                  " VALUES (?, ?, 0, 1, ?, '2026-10-23') ON CONFLICT(project_id, input_ref, set_no) DO UPDATE SET"
                  " excluded_json = excluded.excluded_json", (pid, ref, json.dumps(["CVE-2099-30001"])))
    assert "затронута: CVE-2099-30001" in web.client.get(url).text


# ============================================================================ ревью 82103ee: отметки и запись текста

@pytest.fixture
def residual(web):  # noqa: F811
    """Цель 9.9.9 с остаточной уязвимостью: исправления нет, наибольшая стабильная версия в диапазоне."""
    pid, url = tp_with_text(web)
    db = web.app.state.db
    ref = db.sca_snapshot(pid, "73001").input_ref
    put_research(db, pid, ref, payload(disputed_fixed=None))
    return pid, url, db, ref


def text_form(card: str) -> dict:
    explanation = re.search(r'<textarea name="explanation"[^>]*>(.*?)</textarea>', card, re.S).group(1)
    import html
    return {"text_revision": card_value(card, "text_revision"), "explanation": html.unescape(explanation).strip(),
            **shown_fields(card)}


def test_residual_mark_counts_only_for_what_was_shown(residual, web):  # noqa: F811
    pid, url, db, ref = residual
    card = web.client.get(url).text
    assert 'id="package-residual-checked"' in card and "исправление не установлено в исследованном охвате" in card
    # оператор сменил цель и отметил прежний флажок – отметка к новой проверке не применяется
    moved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "target_version": "9.9.8", "residual_checked": "1"})
    assert moved.status_code == 200 and moved.json()["confirm_dropped"] is True
    assert "Проверка целевой версии изменилась" in moved.json()["hint"]
    assert db.sca_package_text(pid, ref, 0)["residual_checked_sig"] == ""
    # без отпечатка показанного – тоже нет
    card = web.client.get(url).text
    blind = {k: v for k, v in text_form(card).items() if k != "shown_fp"}
    assert web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **blind, "target_version": "9.9.8", "residual_checked": "1"}).json()["confirm_dropped"] is True
    # к показанному – ставится
    card = web.client.get(url).text
    done = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "target_version": "9.9.8", "residual_checked": "1"})
    assert done.json()["confirm_dropped"] is False and "Остаточный риск проверил" not in done.json()["hint"]


def test_text_write_checks_the_package_inside_the_transaction(residual, web, monkeypatch):  # noqa: F811
    pid, url, db, ref = residual
    card = web.client.get(url).text
    revision = db.sca_package_text(pid, ref, 0)["revision"]
    original = db.save_sca_package_text

    def other_tab_first(*args, **kwargs):
        db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive",
                       final_comment="Обновить: проверено ещё раз.", reviewed=True)  # между снимком и записью
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "save_sca_package_text", other_tab_first)
    refused = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "target_version": "9.9.9", "residual_checked": "1"})
    assert refused.status_code == 409 and "изменились данные пакета" in refused.json()["detail"]
    assert db.sca_package_text(pid, ref, 0)["revision"] == revision, "ничего не записано"


def test_unverified_target_with_residual_needs_both_marks_and_research_revision_resets_them(residual, web):  # noqa: F811
    pid, url, db, ref = residual
    card = web.client.get(url).text
    assert 'id="residual-outside"' in card, "остаточная уязвимость не из набора – предупреждение"
    form = text_form(card)  # исследование добавило в набор CVE-2099-10002: строка Объяснения и для неё
    form["explanation"] += ("\nCVE-2099-10002: Уязвимость разбора документа позволяет прочитать файлы сервера при "
                            "обработке вложений.")
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={**form, "target_version": "9.9.8"})
    assert first.status_code == 200
    card = web.client.get(url).text  # 9.9.8 не опубликована: «не проверена» и остаточная – два флажка
    assert 'id="package-version-checked"' in card and 'id="package-residual-checked"' in card
    assert "кроме названных остаточных уязвимостей" in card
    only = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "target_version": "9.9.8", "residual_checked": "1"}).json()
    assert only["ready"] is False and "Версию проверил сам" in only["hint"]
    card = web.client.get(url).text
    both = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "target_version": "9.9.8", "residual_checked": "1", "version_checked": "1"}).json()
    assert both["ready"] is True, both["hint"]
    put_research(db, pid, ref, payload(disputed_fixed=None))  # новая ревизия исследования
    card = web.client.get(url).text
    assert "Остаточный риск проверил»" in re.search(r'id="sca-set-problems".*?</div>', card, re.S).group(0)


def test_card_without_a_stable_state_has_an_empty_package_fingerprint(web, monkeypatch):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    counter = iter(range(1000))
    monkeypatch.setattr(db, "sca_defect_fingerprint", lambda *a, **k: f"fp{next(counter)}")
    page = web.client.get(url).text
    assert card_value(page, "package_fp") == "" and "обновите карточку через минуту" in page


def test_hub_note_skips_a_class_not_applicable_to_the_product():
    medium = finding("CVE-2099-2001", [{"introduced": "1.4.0", "fixed": "1.5.0"}], ["1.5.0"])
    hub = {"role": "hub", "version": "1.4.2", "findings": [medium],
           "coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": True}]}
    data = research(FIXED, checks=[target_check(), hub])
    assert "CVE-2099-2001" in t.hub_note("maven", ["1.4.2"], "1.5.0", data)
    assert t.hub_explanation("maven", ["1.4.2"], "1.5.0", data, not_applicable=["CVE-2099-2001"]) == ("", [])


# ============================================================================ ADR-0091 п. 9: исключение из текста

def exclusion(web, url, card, key, action="exclude", reason="Уязвимость относится к модулю, которого нет в сборке.",
              **extra):
    form = re.search(r'<form[^>]*/exclude[^>]*>(?:(?!</form>).)*name="vuln_key" value="' + re.escape(key)
                     + r'"(?:(?!</form>).)*</form>', card, re.S).group(0)
    data = {name: re.search(rf'name="{name}" value="([^"]*)"', form).group(1)
            for name in ("vuln_key", "action", "set_no", "set_rev", "shown_fp")}
    return web.client.post(f"{url}/exclude", headers=ORIGIN, follow_redirects=False,
                           data={**data, "reason": reason, **extra})


def test_operator_excludes_a_vulnerability_from_the_text_and_returns_it(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    assert exclusion(web, url, card, "CVE-2099-10001", reason="").status_code == 400
    assert exclusion(web, url, card, "CVE-2099-10001", shown_fp="другой").status_code == 409
    assert db.sca_sets(pid, ref)[0]["excluded"] == [], "отказ – ничего не записано"
    done = exclusion(web, url, card, "CVE-2099-10001")
    assert done.status_code == 303 and "sca_exclusion_saved" in done.headers["location"]
    card = web.client.get(url).text
    vulns = re.search(r'id="sca-set-vulns".*?</ul>', card, re.S).group(0)
    assert "CVE-2099-10001" not in vulns
    assert "Уязвимость относится к модулю, которого нет в сборке." in card and 'id="sca-set-excluded"' in card
    assert "затронута: CVE-2099-30001" in card, "исключение проверку цели не меняет"
    back = exclusion(web, url, card, "CVE-2099-10001", action="include", reason="")
    assert back.status_code == 303
    assert "CVE-2099-10001" in re.search(r'id="sca-set-vulns".*?</ul>', web.client.get(url).text, re.S).group(0)
    assert db.sca_sets(pid, ref)[0]["excluded"] == []


# ============================================================================ ревью 4471a2a

def test_target_check_needs_complete_vulnerability_search_not_just_releases():
    releases = {"role": "target", "version": "1.5.0", "findings": [],
                "coverage": [{"purpose": "releases", "status": "ok", "complete": True}]}
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, checks=[releases]), "2026-10-22")
    assert check.state == "unverified" and "целевой версии неполный" in check.detail
    mixed = target_check()
    mixed["coverage"].append({"purpose": "releases", "status": "partial", "complete": False})
    assert t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, checks=[mixed]), "2026-10-22").state == "verified"


def test_unknown_comparison_is_not_hidden_by_a_known_hit():
    vague = finding("GHSA-nnnn-oooo-ffff", [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                    source_positions=[{"source": "Vendor", "affects": "yes", "source_refs": ["adv"],
                                       "ranges": [{"introduced": None, "fixed": None, "last_affected": None}]}])
    assert t.range_contains("maven", "1.5.0", vague["source_positions"][0]["ranges"][0]) is None
    check = t.check_version("maven", "1.2.0", "1.5.0", research(FIXED, vague), "2026-10-22")
    assert check.state == "unverified" and "не установлено" in check.detail
    assert [r["id"] for r in check.residual] == ["GHSA-nnnn-oooo-ffff"]


def test_residual_evidence_includes_source_positions():
    data = research(FIXED, finding("CVE-2099-7001", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.2.4"}],
                                   source_positions=[{"source": "GitHub", "affects": "yes", "source_refs": ["pos"],
                                                      "ranges": [{"introduced": "1.0.0", "fixed": None}]}]))
    data["evidence"].append({"evidence_ref": "pos", "url": "https://github.com/example/driver/issues/7",
                             "source_type": "issue_tracker", "level": "primary", "checked_at": "2026-10-21"})
    check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
    item = next(r for r in check.residual if r["id"] == "CVE-2099-7001")
    assert "pos" in item["refs"] and "https://github.com/example/driver/issues/7" in t.evidence_urls(item["refs"], data)


def test_hub_note_needs_qualifying_evidence_of_the_named_vulnerability():
    medium = finding("CVE-2099-2001", [{"introduced": "1.4.0", "fixed": "1.5.0"}], ["1.5.0"], source_refs=["weak"])
    hub = {"role": "hub", "version": "1.4.2", "findings": [medium],
           "coverage": [{"purpose": "vulnerabilities", "status": "ok", "complete": True}]}
    data = research(FIXED, checks=[target_check(), hub])
    data["evidence"].append({"evidence_ref": "weak", "url": "https://forum.example/thread/1", "source_type": "advisory",
                             "level": "unconfirmed", "checked_at": "2026-10-21"})
    assert t.hub_note("maven", ["1.4.2"], "1.5.0", data) == ""


def test_clearing_a_decision_does_not_let_an_old_tab_through(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    old = web.client.get(url).text  # вкладка А: решения нет
    assert decide(web, url, old, "CVE-2099-30001", "not_product").status_code == 303  # вкладка Б
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-30001", "", reason="").status_code == 303  # Б снимает решение
    stale = decide(web, url, old, "CVE-2099-30001", "not_product")
    assert stale.status_code == 409
    assert [r["decision"] for r in db.sca_snapshot(pid, "73001").applicability] == [""]


def test_import_between_the_snapshot_and_the_write_refuses_the_decision(disputed, web, monkeypatch):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    original = db.save_sca_applicability

    def import_first(*args, **kwargs):
        put_research(db, pid, ref, payload())  # новая ревизия исследования – после снимка маршрута
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "save_sca_applicability", import_first)
    assert decide(web, url, card, "CVE-2099-30001", "not_product").status_code == 409
    assert rows_count(db) == 0, "ничего не записано"


def test_full_path_through_the_real_import(web):  # noqa: F811
    """Ответ 2.1 через штатный импорт (валидатор, хранение) → карточка → решение о применимости → текст → дефект."""
    from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components
    from test_sca import sca_card
    from test_sca_package_decision import UPD, post_package

    pid = project_with_components(web)
    document = answer_document(build_task(web, pid))
    row = next(r for r in document["rows"] if r["component"].endswith("example-parser"))
    query = {"ecosystem": row["ecosystem"], "coordinates": row["identity_resolution"]["coordinates"],
             "version": "1.4.9"}
    disputed_item = {"id": "CVE-2099-30001", "aliases": [], "applies": "no",
                     "description": "Обход ограничения размера вложенного документа", "conditions": None,
                     "ranges": [{"introduced": "1.4.5", "fixed": "10.0.0"}], "fixed_versions": ["10.0.0"],
                     "cvss": {"score": 6.1, "vector": None, "version": "3.1"}, "source_refs": ["ev-1"],
                     "disputed": {"by": "vendor", "note": "Производитель оспаривает", "source_refs": ["ev-1"]},
                     "source_positions": [{"source": "NVD", "affects": "no", "ranges": [], "source_refs": ["ev-1"]}]}
    own = {"id": "CVE-2099-10001", "aliases": [], "applies": "yes", "description": "Обход проверки значения",
           "ranges": [{"introduced": "1.4.0", "fixed": "1.4.9"}], "conditions": None, "fixed_versions": ["1.4.9"],
           "cvss": {"score": 8.2, "vector": None, "version": "3.1"}, "source_refs": ["ev-1"]}
    row["public_findings"] = [own, disputed_item]
    row["version_checks"] = [{"role": "target", "version": "1.4.9", "findings": [
        {"id": "CVE-2099-30001", "aliases": [], "ranges": [{"introduced": "1.4.5", "fixed": "10.0.0"}],
         "fixed_versions": ["10.0.0"], "cvss": {"score": 6.1, "vector": None, "version": "3.1"},
         "source_refs": ["ev-1"]}],
        "coverage": [{"source": "OSV", "purpose": "vulnerabilities", "query": query, "source_refs": ["ev-1"],
                      "checked_at": "2026-10-16", "status": "ok", "complete": True, "note": ""}]}]
    row["package_advice"].update(action="update", target_version="1.4.9", source_refs=["ev-registry"])
    row["package_status"] = "vulnerable"
    expect_accepted(web, pid, document)
    saved = post_package(web, pid, "73001", ["73001", "73002"], **UPD)
    assert saved.status_code == 200, saved.text
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    assert "затронута: CVE-2099-30001" in card and "оспорена: производитель" in card
    # штатный импорт нового ответа между снимком маршрута и записью решения – отказ, ничего не записано
    db = web.app.state.db
    original = db.save_sca_applicability
    changed = copy.deepcopy(document)
    next(r for r in changed["rows"] if r["component"].endswith("example-parser"))["public_findings"][1][
        "description"] = "Обход ограничения размера вложенного документа (уточнено)"

    def import_first(*args, **kwargs):
        from app import sca_research
        task = db.current_task(pid)
        rows = db.task_rows(task["id"])
        report = sca_research.check_answer(json.dumps(changed, ensure_ascii=False).encode("utf-8"), task, rows)
        assert report.ok, report.errors
        assert db.save_research(pid, task["id"], sca_research.research_results(report.answer, rows))["saved"] == 1
        return original(*args, **kwargs)

    db.save_sca_applicability = import_first
    try:
        assert decide(web, url, card, "CVE-2099-30001", "not_product").status_code == 409
    finally:
        db.save_sca_applicability = original
    assert rows_count(db) == 0
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-30001", "not_product").status_code == 303
    card = web.client.get(url).text
    assert "затронута: CVE-2099-30001" not in card
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **text_form(card), "explanation": "CVE-2099-10001: Обход проверки значения из внешнего источника при "
                                          "разборе документа позволяет подменить данные."})
    assert saved.status_code == 200 and saved.json()["ready"] is True, saved.json()["hint"]
    got = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "1"})
    assert got.status_code == 200, got.text
    body = got.json()["body"]
    assert "до версии 1.4.9" in body and "CVE-2099-30001" not in body.split("Объяснение", 1)[0]


def test_no_fix_published_evidence_includes_source_positions():
    data = research(FIXED, finding("CVE-2099-7002", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.2.4"}],
                                   fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]},
                                   source_positions=[{"source": "GitHub", "affects": "yes", "source_refs": ["pos"],
                                                      "ranges": [{"introduced": "1.0.0", "fixed": None}]}]))
    data["evidence"].append({"evidence_ref": "pos", "url": "https://github.com/example/driver/issues/8",
                             "source_type": "issue_tracker", "level": "primary", "checked_at": "2026-10-21"})
    check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
    item = next(r for r in check.residual if r["id"] == "CVE-2099-7002")
    assert item["status"] == "no_fix_published" and item["refs"][0] == "adv" and "pos" in item["refs"]
    assert "(github.com)" in t.residual_line(item, "1.5.0", data)


def test_excluded_linked_vulnerability_is_not_said_to_stay_in_the_text(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    data = db.get_finding_by_hub_id(pid, "73001")["data"]
    ast = next(i for i in data.get("vuln_ids") or [] if str(i).upper().startswith("AST"))
    db.save_ast_map([(ast, "CVE-2099-10002")], "оператор")  # уязвимость исследования связана с находкой набора
    card = web.client.get(url).text
    assert decide(web, url, card, "CVE-2099-10002", "not_current").status_code == 303
    card = web.client.get(url).text
    assert "членство важнее решения" in card
    assert exclusion(web, url, card, "CVE-2099-10002").status_code == 303
    card = web.client.get(url).text
    item = re.search(r'<li class="item" id="applicability-\d+">(?:(?!</li>).)*CVE-2099-10002(?:(?!</li>).)*</li>',
                     card, re.S).group(0)
    assert "Исключена из текста оператором." in item and "членство важнее решения" not in item


# ============================================================================ ревью c7a4341

def test_legacy_answer_is_a_set_level_basis_seen_from_every_card(web, monkeypatch):  # noqa: F811
    """Прежний ответ агента – основание цели набора (ADR-0091 п. 14.4): из карточки участника с собственным решением
    дефект тот же, что из карточки согласившегося; ответ не охватывает уязвимости одного участника – основания нет ни
    из одной карточки."""
    from app.routes import sca as sca_routes
    from test_sca import answer, answers_json, form_fields, post_answers, sca_card

    pid = prepared(web)
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2"))).status_code == 303
    fid1, card1 = sca_card(web, pid, "73001")
    url1 = f"/projects/{pid}/sca/findings/{fid1}"
    assert web.client.post(f"{url1}/review", headers=AS_JSON, data={
        **form_fields(card1), "decision": "agree", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Обновить.", "action": "save"}).status_code == 200
    fid2, card2 = sca_card(web, pid, "73002")
    url2 = f"/projects/{pid}/sca/findings/{fid2}"
    assert web.client.post(f"{url2}/review", headers=AS_JSON, data={
        **form_fields(card2), "decision": "disagree", "final_verdict": "true_positive", "reviewed": "1",
        "comment": "Обновить: проверено своими силами.", "action": "save"}).status_code == 200
    db = web.app.state.db

    def defect_from(hub_id: str) -> dict:
        from app.models import Finding
        f = Finding.from_dict(db.get_finding_by_hub_id(pid, hub_id)["data"])
        return sca_routes.sca_defect(db, web.app.state.feeds, pid, f, db.get_review(pid, hub_id))

    one, two = defect_from("73001"), defect_from("73002")
    assert one["target"] == two["target"] == "1.4.9" and one["target_basis"] == two["target_basis"]
    assert one["explanation_draft"] == two["explanation_draft"] and one["sources"] == two["sources"]
    # ответ не охватывает уязвимости 73002 – основания нет из обеих карточек
    monkeypatch.setattr(sca_routes, "answer_covers", lambda f, a: f.hub_id != "73002")
    assert defect_from("73001")["target"] == "" and defect_from("73002")["target"] == ""


def test_no_fix_source_in_the_line_is_only_the_proof_of_no_fix():
    """Доказательство «исправления нет» – один источник (single_source), позиция с диапазоном – первоисточник: в
    скобках строки источник позиции не появляется, карточка предупреждает о недостатке доказательства."""
    weak = finding("CVE-2099-7003", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.2.4"}],
                   fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["weak"]},
                   source_positions=[{"source": "GitHub", "affects": "yes", "source_refs": ["pos"],
                                      "ranges": [{"introduced": "1.0.0", "fixed": None}]}])
    data = research(FIXED, weak)
    data["evidence"] += [{"evidence_ref": "weak", "url": "https://forum.example/no-fix", "source_type": "advisory",
                          "level": "single_source", "quote": "no fix", "checked_at": "2026-10-20"},
                         {"evidence_ref": "pos", "url": "https://github.com/example/driver/issues/9",
                          "source_type": "issue_tracker", "level": "primary", "checked_at": "2026-10-21"}]
    check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
    item = next(r for r in check.residual if r["id"] == "CVE-2099-7003")
    assert item["proof_refs"] == ["weak"] and "pos" in item["refs"]
    line = t.residual_line(item, "1.5.0", data)
    assert "github.com" not in line and "(forum.example)" not in line and line.startswith("Исправления нет ни в одной")
    assert t.evidence_urls(item["proof_refs"], data) == [], "предупреждение карточки – по доказательству утверждения"


def test_no_fix_proof_and_date_follow_the_chosen_scope():
    """Доказательство ветки (primary, 22.10) и доказательство пакета (single_source, 20.10) в одном классе: утверждение
    – обо всём пакете, его дата и источник – только от доказательства пакета; источник ветки не приписывается."""
    branch = finding("CVE-2099-7004", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.5.0"}],
                     fix_status={"status": "no_fix_published", "scope": "branch", "branch": "1.5",
                                 "source_refs": ["adv"]})
    package = finding("GHSA-pppp-qqqq-7004", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.5.0"}],
                      aliases=["CVE-2099-7004"],
                      fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["weak"]})
    data = research(FIXED, branch, package)
    data["evidence"][0]["checked_at"] = "2026-10-22"
    data["evidence"].append({"evidence_ref": "weak", "url": "https://forum.example/no-fix", "source_type": "advisory",
                             "level": "single_source", "quote": "no fix", "checked_at": "2026-10-20"})
    check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
    item = next(r for r in check.residual if r["id"] == "CVE-2099-7004")
    assert item["scope"] == "package" and item["proof_refs"] == ["weak"] and item["date"] == "2026-10-20"
    assert "adv" in item["refs"], "доказательство ветки остаётся в общих ссылках для «Источников»"
    line = t.residual_line(item, "1.5.0", data)
    assert "2026-10-20" in line and "github.com" not in line and "ни в одной опубликованной версии" in line
    assert t.evidence_urls(item["proof_refs"], data) == [], "карточка предупредит: у утверждения нет годного доказательства"


def test_no_fix_branch_claim_uses_the_narrowest_branch_only():
    """Две записи класса с доказательствами разных веток цели («1» от 20.10 и «1.5» от 22.10, в любом порядке):
    утверждение – о ветке «1.5», дата и доказательство – только её."""
    data_ref = {"evidence_ref": "b15", "url": "https://github.com/example/driver/issues/15", "source_type": "issue_tracker",
                "level": "primary", "quote": "no fix in 1.5", "checked_at": "2026-10-22"}
    wide = finding("CVE-2099-7005", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.5.0"}],
                   fix_status={"status": "no_fix_published", "scope": "branch", "branch": "1", "source_refs": ["adv"]})
    narrow = finding("GHSA-nnnn-7005-aaaa", [{"introduced": "1.0.0", "fixed": None, "last_affected": "1.5.0"}],
                     aliases=["CVE-2099-7005"],
                     fix_status={"status": "no_fix_published", "scope": "branch", "branch": "1.5",
                                 "source_refs": ["b15"]})
    for order in ((wide, narrow), (narrow, wide)):
        data = research(FIXED, *order)
        data["evidence"].append(dict(data_ref))
        check = t.check_version("maven", "1.2.0", "1.5.0", data, "2026-10-22")
        item = next(r for r in check.residual if r["id"] == "CVE-2099-7005")
        assert (item["scope"], item["branch"], item["date"], item["proof_refs"]) == ("branch", "1.5", "2026-10-22", ["b15"])
        assert "adv" in item["refs"]
        assert t.residual_line(item, "1.5.0", data).startswith("В ветке 1.5 исправления нет на 2026-10-22 (github.com)")
