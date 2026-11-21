"""Замечания ревью 3b6c463: пакетные поля формы – только по состоянию сразу после своей записи (К6); дефект, форма и
отпечаток карточки – из одного снимка (К4); область набора – все находки Hub не из набора, соответствия исторических
(Г10); язык свободного текста и наборов только с AST (Г12); введённый номер не подменяет сохранённый (К5); черновик
без формы набора (К11); подписи отметки из одного состояния (К10); строка запроса – не признак API (Г7)."""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest

from app import sca_text as t
from app.db import Database, ScaSnapshot, text_hash
from app.feeds import FeedStore
from app.models import Finding
from app.routes import sca as sca_routes
from app.routes.sca import saved_hub_text_v2
from test_db_stage2 import load, sca
from test_defect import save_sast
from test_review_k_group import card_value, tp_with_text
from test_sca import AS_JSON, form_fields, sca_card
from test_sca_package_decision import FP, package_fields
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: F401


# ============================================================================ К6

def test_k6_package_fields_only_when_nobody_changed_the_package_after_the_write(web, monkeypatch):  # noqa: F811
    pid = prepared(web)
    db = web.app.state.db
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    data = {**form_fields(card), **package_fields(card), "apply_to": ["73001"], "reviewed": "1", "action": "save", **FP}
    fresh = web.client.post(f"{url}/review", headers=AS_JSON, data=data)
    assert fresh.status_code == 200 and fresh.json()["package"] and fresh.json()["package_stale"] is False
    _, card = sca_card(web, pid, "73001")
    data = {**form_fields(card), **package_fields(card), "apply_to": ["73001"], "reviewed": "1", "action": "save",
            **FP, "comment": "Уязвимая функция разбора не вызывается: проверено ещё раз."}
    original = db.save_reviews

    def other_tab_after_commit(*args, **kwargs):
        saved = original(*args, **kwargs)
        db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                       reviewed=True)  # другая вкладка – уже после своей транзакции
        return saved

    monkeypatch.setattr(db, "save_reviews", other_tab_after_commit)
    stale = web.client.post(f"{url}/review", headers=AS_JSON, data=data)
    assert stale.status_code == 200, stale.text
    assert stale.json()["package"] is None and stale.json()["package_stale"] is True
    assert "обновите карточку" in stale.json()["notice"]


# ============================================================================ К4

def test_k4_card_is_rebuilt_when_the_finding_changes_while_it_is_built(web, monkeypatch):  # noqa: F811
    """Новая выгрузка между чтением находки и снимком пакета: карточка собирается заново и показывает новые
    данные с отпечатком того же состояния – решение не примется по старым данным под новым отпечатком."""
    from test_audit_lta001b import reimport

    pid, url = tp_with_text(web)
    db = web.app.state.db
    original = db.sca_snapshot
    done = []

    def new_export_once(project_id, hub_id):
        if not done:
            done.append(1)

            def change(f):
                if f.hub_id == "73001":
                    f.cve = ["CVE-2099-77777"]
            reimport(web, pid, change)  # между первым чтением находки и снимком
        return original(project_id, hub_id)

    monkeypatch.setattr(db, "sca_snapshot", new_export_once)
    page = web.client.get(url).text
    assert done and "CVE-2099-77777" in page, "карточка собрана по новым данным"
    # решение принято по прежним данным – формы текста набора нет; отпечаток пакетной формы – текущего состояния
    assert 'name="shown_fp"' not in page
    assert card_value(page, "package_fp") == db.sca_defect_fingerprint(pid, "73001")


# ============================================================================ Г10

@pytest.fixture
def package(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    store = FeedStore(tmp_path / "feeds.db")
    pid = db.create_project("Проект")
    load(db, pid, [sca("1", vuln="AST-1"), sca("2", vuln="AST-2"), sca("3", vuln="AST-3")])
    for hub_id in ("1", "2"):
        db.save_review(pid, hub_id, decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                       reviewed=True)
    db.save_ast_map([("AST-2", "CVE-2099-0002"), ("AST-3", "CVE-2099-0003")], "оператор")
    yield db, store, pid
    store.close()
    db.close()


def research_with(*ids: str) -> dict:
    return {"payload": {"public_findings": [{"id": i, "aliases": [], "applies": "yes", "ranges": [],
                                             "source_refs": []} for i in ids], "evidence": []},
            "observed_at": "2026-10-22"}


def set_vulns_of(db, store, pid, hub_id, monkeypatch, research) -> list[str]:
    monkeypatch.setattr(ScaSnapshot, "research", property(lambda self: research))
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, hub_id)["data"])
    view = sca_routes.sca_defect(db, store, pid, f, db.get_review(pid, hub_id))
    return [v["main"] for v in view["vulns"]]


def test_g10_final_scope_excludes_vulns_of_other_hub_findings(package, monkeypatch):
    db, store, pid = package
    ref = db.sca_snapshot(pid, "1").input_ref
    db.move_sca_member(pid, ref, "2", 1, "", expect={0: 0, 1: 0})
    research = research_with("CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0009")
    scope = set_vulns_of(db, store, pid, "1", monkeypatch, research)
    # своя AST-1; CVE-2099-0009 – только исследования (в набор по умолчанию); CVE-2099-0002 – находки отдельного
    # набора; CVE-2099-0003 – находки без решения: обе связаны с находками Hub не из набора и сюда не входят
    assert "CVE-2099-0009" in scope and "AST-1" in scope
    assert "CVE-2099-0002" not in scope and "CVE-2099-0003" not in scope
    # находка 2 пропала из выгрузки: её место и соответствие AST-2 → CVE-2099-0002 по-прежнему учитываются
    load(db, pid, [sca("1", vuln="AST-1"), sca("3", vuln="AST-3")])
    scope = set_vulns_of(db, store, pid, "1", monkeypatch, research)
    assert "CVE-2099-0002" not in scope and "CVE-2099-0009" in scope


# ============================================================================ Г12, Г7

def test_g12_free_text_and_ast_only_sets_need_russian():
    ast_only = [t.Vuln(ids=["AST-2026-000001"])]
    english = "The component parses nested structures without a depth limit and can exhaust memory."
    assert t.free_text(english, ast_only) == english
    assert t.cyrillic_share(t.free_text(english, ast_only)) < 1 / 3
    mixed = [t.Vuln(ids=["CVE-2099-0001"])]
    text = "CVE-2099-0001: Русское объяснение уязвимости компонента и условий её срабатывания.\n" + english
    assert t.non_russian_lines(text, mixed) == [] and t.free_text(text, mixed) == english


def test_g7_query_string_alone_is_not_an_api():
    assert t.human_url("https://bugs.example.org/show_bug.cgi?id=12345")
    assert not t.human_url("https://api.example.org/v1/advisories?id=1")
    assert not t.human_url("https://repo.example.org/maven2/a/b/1.0/b-1.0.pom")


# ============================================================================ К5

def test_k5_entered_number_does_not_replace_the_stored_one(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "true_positive", "", "Подтверждено: owner из запроса.")
    assert web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "number_shown": ""}).status_code == 200
    db.set_defect_number(pid, "sast:999999", 3)
    page = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "3", "number_shown": "5"},
                           follow_redirects=False)
    assert page.status_code == 409
    assert 'id="defect-number" value="3"' in page.text and card_value(page.text, "number_shown") == "5"
    done = web.client.post(f"{url}/defect", headers=ORIGIN, follow_redirects=False,
                           data={"number": "3", "number_shown": "5", "confirm": "1"})
    assert done.status_code == 303 and db.defect_number(pid, "sast:510001") == 3


# ============================================================================ К11

def test_k11_draft_is_shown_when_the_set_form_is_gone(web):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    card = web.client.get(url).text
    ref = db.sca_snapshot(pid, "73001").input_ref
    sets = db.sca_sets(pid, ref)
    db.move_sca_member(pid, ref, "73001", None, "Компонент не входит в сборку.", expect={0: sets[0]["revision"]})
    draft = "CVE-2099-10002: Черновик оператора, который нельзя потерять при переносе в «без дефекта»."
    page = web.client.post(f"{url}/package-text", headers=ORIGIN, follow_redirects=False, data={
        "text_revision": card_value(card, "text_revision"), "set_no": "0", "input_ref": ref,
        "target_version": "9.9.9", "explanation": draft})
    assert page.status_code == 409 and 'id="unsaved-draft"' in page.text
    assert draft in html.unescape(page.text)


# ============================================================================ К10

def test_k10_entered_labels_come_from_one_state(web):  # noqa: F811
    pid, url = tp_with_text(web)
    db = web.app.state.db
    review = db.get_review(pid, "73001")
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    db.mark_entered(pid, "73001", True, review["revision"],
                    text_hash(saved_hub_text_v2(db, web.app.state.settings, pid, f, review)))
    page = web.client.get(url).text
    times = re.search(r'<span id="entered-at">(.*?)</span>', page, re.S).group(1)
    assert "Отметка по прежнему тексту" in times and "Дефект создан в Hub" not in times
    marked = web.client.post(f"{url}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": str(review["revision"]), "defect_sig": card_value(page, "defect_sig")})
    assert marked.status_code == 200, marked.text
    assert marked.json()["text"]["entered-note-text"] == "Дефект создан в Hub."
    page = web.client.get(url).text
    assert "Дефект создан в Hub" in re.search(r'<span id="entered-at">(.*?)</span>', page, re.S).group(1)


def test_g12_each_free_line_is_checked_separately():
    from app.routes import sca as routes  # noqa: F401  – правило в sca_defect: строка за строкой
    russian = "Длинный русский абзац об уязвимости компонента, условиях её срабатывания и последствиях. " * 4
    text = russian + "\nThe parser does not limit nesting depth."
    lines = t.free_text(text, []).split("\n")
    assert t.cyrillic_share(t.free_text(text, [])) >= 1 / 3, "суммарно английская строка не видна"
    assert any(t._LETTER.search(line) and t.cyrillic_share(line) < 1 / 3 for line in lines)


def test_g12_defect_asks_to_check_an_english_free_line(web):  # noqa: F811
    pid, url = tp_with_text(web)
    card = web.client.get(url).text
    current = html.unescape(re.search(r'<textarea name="explanation"[^>]*>(.*?)</textarea>', card, re.S).group(1))
    russian = "Длинное русское пояснение о том, как уязвимость проявляется в продукте и при каких условиях. " * 3
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        "text_revision": card_value(card, "text_revision"), "target_version": "9.9.9", "version_checked": "1",
        "explanation": current.strip() + "\n" + russian + "\nThe parser does not limit nesting depth."})
    assert saved.status_code == 200 and saved.json()["ready"] is False
    # английская строка – предупреждение, не запрет (ADR-0152): готовность держит непроверенная версия
    assert any("не на русском" in c and "текст без идентификатора" in c for c in saved.json()["cautions"]), \
        saved.json()["cautions"]
    assert "не на русском" not in saved.json()["hint"]
