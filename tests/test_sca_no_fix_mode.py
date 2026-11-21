"""Режим «Исправленной версии нет» (ADR-0101, Р6): обновлять некуда – дефект с мерами
оператора вместо строки «Обновление … до версии …». Режим – только по исследованию: у каждой уязвимости «Описания» нет
исправления для текущей версии. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import sca_text as t
from app.db import Database, ScaSnapshot
from app.feeds import FeedStore
from app.models import Finding
from app.routes import sca as sca_routes
from test_db_stage2 import load, sca
from test_sca_residual import finding, research
from test_web import web  # noqa: F401

GHSA = "GHSA-nnnn-oooo-ffff"
PROVEN = finding(GHSA, [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                 fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]},
                 cvss={"score": 3.1, "vector": None, "version": "3.1"})
NOT_FOUND = finding(GHSA, [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                    cvss={"score": 3.1, "vector": None, "version": "3.1"})
EXPLANATION = f"{GHSA}: Разбор файла сертификата без ограничения размера ведёт к отказу в обслуживании."
MEASURES = "Ограничить размер принимаемых файлов сертификатов до 64 КБ на входе сервиса."


def vulns(*ids):
    return [t.Vuln(ids=[i], hub_members=["1"]) for i in ids]


def check(payload, *ids, current="1.5.0", not_applicable=()):
    rep = t.union_classes(t.class_groups([list(ids)], {}, payload))
    return t.no_fix_check("maven", current, payload, "2026-10-22", vulns(*ids), rep, not_applicable)


# ============================================================================ проверка режима

def test_proven_and_not_found_are_allowed_with_their_own_words():
    proven = check(research(PROVEN, latest="1.5.0"), GHSA)
    assert not proven.problems and proven.items[0]["status"] == "no_fix_published"
    assert t.no_fix_line(proven.items[0], research(PROVEN)) == (
        f"Исправления нет ни в одной опубликованной версии на 2026-10-20 (github.com): {GHSA} (низкая).")
    found = check(research(NOT_FOUND, latest="1.5.0"), GHSA)
    assert not found.problems and found.items[0]["status"] == "fix_not_found"
    # отсутствие исправления не доказано – слова ADR-0094, а не «исправления нет»
    assert t.no_fix_line(found.items[0], research(NOT_FOUND)) == (
        f"Исправление не установлено в исследованном охвате на 2026-10-22: {GHSA} (низкая).")


def test_fix_above_current_warns_and_names_the_lowest_version():
    fixed = finding("CVE-2099-1001", [{"introduced": "1.0.0", "fixed": "1.7.0"}], ["1.7.0", "1.6.1"])
    result = check(research(fixed, latest="1.7.0"), "CVE-2099-1001")
    assert not result.items and not result.problems and result.fixed == [
        "CVE-2099-1001: по исследованию есть исправление в версии 1.6.1."]


def test_branch_proof_does_not_prove_that_there_is_nothing_to_update():
    branch = finding(GHSA, [{"introduced": "1.5.0", "fixed": None, "last_affected": "1.5.9"}],
                     fix_status={"status": "no_fix_published", "scope": "branch", "branch": "1.5",
                                 "source_refs": ["adv"]})
    other = check(research(branch, latest="2.0.0"), GHSA)
    assert not other.items and "только в ветке 1.5" in other.problems[0] and "2.0.0" in other.problems[0]
    same = check(research(branch, latest="1.5.9"), GHSA)
    assert not same.problems and same.items[0]["scope"] == "branch"


def test_unknown_status_missing_record_and_no_research_refuse():
    unknown = finding(GHSA, [{"introduced": "1.4.0", "fixed": None, "last_affected": "1.5.0"}])
    assert "статус исправления не установлен" in check(research(unknown, latest="1.6.0"), GHSA).problems[0]
    missing = check(research(PROVEN), GHSA, "CVE-2099-7777")
    assert any(p.startswith("CVE-2099-7777: в исследовании компонента нет сведений") for p in missing.problems)
    assert "только по исследованию" in t.no_fix_check("maven", "1.5.0", None, "", vulns(GHSA), {}).problems[0]


def test_fix_known_only_from_another_version_check_warns():
    """Исправление известно только по проверке другой версии: оно тоже считается найденным – в списке fixed,
    оператор подтверждает его отметкой (ADR-0151; прежде – отказ режима)."""
    unknown_here = finding(GHSA, [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                           fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]})
    fixed_there = finding(GHSA, [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0"])
    payload = research(unknown_here, latest="1.5.0",
                       checks=[{"role": "hub", "version": "1.5.1", "coverage": [], "findings": [fixed_there]}])
    result = check(payload, GHSA)
    assert not result.items and not result.problems and "есть исправление в версии 1.6.0" in result.fixed[0], result.fixed


def test_conflicting_source_positions_warn_and_incomparable_fix_refuses_the_mode():
    """Источники расходятся (один называет версию исправления, другой – нет): исправление считается найденным и
    идёт в список fixed (ADR-0151). Версия исправления несравнима с текущей: статус не установлен – режим
    недоступен, номер версии при неизвестном порядке не называется."""
    disputed = finding(GHSA, [{"introduced": "0", "fixed": None, "last_affected": "1.5.0"}],
                       fix_status={"status": "no_fix_published", "scope": "package", "source_refs": ["adv"]},
                       source_positions=[{"source": "nvd", "affects": "yes",
                                          "ranges": [{"introduced": "1.0.0", "fixed": "1.7.0"}], "source_refs": ["adv"]}])
    result = check(research(disputed, latest="1.5.0"), GHSA)
    assert not result.items and not result.problems and "есть исправление в версии 1.7.0" in result.fixed[0], result.fixed
    odd = finding(GHSA, [{"introduced": "0", "fixed": "1.5.0-vendor"}], ["1.5.0-vendor"])
    result = check(research(odd, latest="1.5.0"), GHSA)  # порядок версий не установлен – статус неизвестен
    assert not result.items and "статус исправления не установлен" in result.problems[0], result.problems


def test_target_basis_is_validated_when_stored(tmp_path: Path):
    db = Database(tmp_path / "triage.db")
    pid = db.create_project("Проект")
    with pytest.raises(ValueError):
        db.save_sca_package_text(pid, "maven:x", 0, expect_revision=0, explanation="", ast={}, target_version="",
                                 target_basis="bogus", version_checked_sig="", text_checked_sig="", text_sig="")
    db.close()


def test_not_product_class_has_no_line_and_does_not_block():
    fixed = finding("CVE-2099-1001", [{"introduced": "1.0.0", "fixed": "1.7.0"}], ["1.7.0"])
    result = check(research(PROVEN, fixed), GHSA, "CVE-2099-1001", not_applicable=["CVE-2099-1001"])
    assert not result.problems and [i["id"] for i in result.items] == [GHSA]


# ============================================================================ в сборке дефекта

@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "triage.db")
    store = FeedStore(tmp_path / "feeds.db")
    pid = db.create_project("Проект")
    load(db, pid, [sca("1", version="1.5.0", vuln=GHSA, fixed="1.5.1")])
    db.save_review(pid, "1", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    state = {"payload": research(PROVEN, latest="1.5.0", target="1.5.0")}
    monkeypatch.setattr(ScaSnapshot, "research", property(
        lambda self: {"payload": state["payload"], "observed_at": "2026-10-22", "revision": state.get("revision", 1)}))
    # решение по компоненту «оставить» противоречит «Обновить», но режим – явный выбор оператора и его перекрывает
    monkeypatch.setattr(ScaSnapshot, "component_decision", property(lambda self: {"action": "keep"}))
    yield db, store, pid, state
    store.close()
    db.close()


def defect(db, store, pid, record):
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "1")["data"])
    return sca_routes.sca_defect(db, store, pid, f, db.get_review(pid, "1"), override=record)


RECORD = {"target_basis": "no_fix", "target_version": "", "explanation": EXPLANATION, "recommendation_note": MEASURES}


def test_defect_with_measures_instead_of_update(env):
    db, store, pid, _ = env
    first = defect(db, store, pid, RECORD)
    assert first["no_fix"] and first["target"] == "" and first["check"] is None
    assert not first["ready"] and "Остаточный риск проверил" in first["hint"], first["hint"]
    done = defect(db, store, pid, {**RECORD, "residual_checked_sig": first["residual_confirm_sig"]})
    assert done["ready"], done["hint"]
    recommendations = done["body"].split("Рекомендации\n", 1)[1].split("\n\nИсточники", 1)[0].split("\n")
    assert recommendations == [
        f"Исправления нет ни в одной опубликованной версии на 2026-10-20 (github.com): {GHSA} (низкая).", MEASURES]
    assert "Обновление" not in done["body"] and "решение по компоненту" not in done["hint"]
    assert "https://github.com/example/driver/security/advisories/GHSA-nnnn-oooo-ffff" in done["body"]


def test_measures_are_required(env):
    db, store, pid, _ = env
    first = defect(db, store, pid, {**RECORD, "recommendation_note": "  "})
    confirmed = defect(db, store, pid, {**RECORD, "recommendation_note": "  ",
                                        "residual_checked_sig": first["residual_confirm_sig"]})
    assert not confirmed["ready"] and "меры обязательны" in confirmed["hint"]


def test_research_with_a_fix_only_warns(env):
    """Бэклог 126, ADR-0153 (решение оператора не блокируется, новых отметок нет):
    исправление, найденное исследованием, режим не отменяет и отметки не требует – предупреждение, текст утверждается
    с мерами оператора. Повод – библиотека, исправления которой вышли только под другими
    координатами."""
    db, store, pid, state = env
    state["payload"] = research(finding(GHSA, [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0"]), latest="1.6.0")
    first = defect(db, store, pid, RECORD)
    assert first["no_fix"] and first["ready"] and "fixed_elsewhere" not in first, first["problems"]
    assert not any("есть исправление" in p for p in first["problems"]), first["problems"]
    warn = [c for c in first["cautions"] if "есть исправление в версии 1.6.0" in c]
    assert len(warn) == 1 and "можно утвердить и так" in warn[0] and "другими координатами" in warn[0], first["cautions"]
    assert MEASURES in first["body"] and "Обновление" not in first["body"]


def test_new_research_changes_the_version_signature(env):
    """Подпись режима включает найденные исправления и ревизию исследования: отметки, поставленные по прежнему
    исследованию, к новому не относятся."""
    db, store, pid, state = env
    state["payload"] = research(finding(GHSA, [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0"]), latest="1.6.0")
    first = defect(db, store, pid, RECORD)
    state["payload"] = research(finding(GHSA, [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0", "2.0.0"]), latest="2.0.0")
    state["revision"] = 2
    again = defect(db, store, pid, RECORD)
    assert again["version_sig"] != first["version_sig"] and again["ready"]


def test_other_reasons_still_refuse_the_mode(env):
    """Запретом остаётся всё, кроме найденного исправления: без исследования режим недоступен и отметка его не открывает."""
    db, store, pid, state = env
    state["payload"] = None
    first = defect(db, store, pid, RECORD)
    assert not first["ready"]
    assert any("только по исследованию" in p for p in first["problems"]), first["problems"]
    marked = defect(db, store, pid, {**RECORD, "version_checked_sig": first["version_confirm_sig"]})
    assert not marked["ready"] and any("только по исследованию" in p for p in marked["problems"])


def test_mixed_fixed_and_unfixed_vulnerabilities():
    """Часть уязвимостей без исправления, у другой исправление найдено: первые – остаточные (их строки в
    «Рекомендациях»), вторая – в списке найденных исправлений; запрета нет."""
    fixed = finding("CVE-2099-1001", [{"introduced": "1.0.0", "fixed": "1.6.1"}], ["1.6.1"])
    result = check(research(PROVEN, fixed, latest="1.6.1"), GHSA, "CVE-2099-1001")
    assert not result.problems and [i["id"] for i in result.items] == [GHSA]
    assert result.fixed == [
        "CVE-2099-1001: по исследованию есть исправление в версии 1.6.1."]


def test_form_refuses_version_and_mode_together_and_keeps_the_choice(web):  # noqa: F811
    """Версия и «Исправленной версии нет» вместе – отказ 400; без скрипта отметка режима остаётся в форме."""
    from test_sca import AS_JSON, sca_card
    from test_sca_package_decision import UPD, post_package
    from test_web import ORIGIN, prepared
    pid = prepared(web)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}/package-text"
    both = {"text_revision": "0", "target_version": "1.4.9", "no_fix": "1", "explanation": EXPLANATION}
    refused = web.client.post(url, headers=AS_JSON, data=both)
    assert refused.status_code == 400 and "одно из двух" in refused.json()["detail"], refused.text
    page = web.client.post(url, headers=ORIGIN, data=both)
    assert page.status_code == 400 and 'id="package-no-fix" checked' in page.text
    saved = web.client.post(url, headers=AS_JSON, data={**both, "target_version": ""})
    assert saved.status_code == 200 and saved.json()["ready"] is False, saved.text
    # исследования нет – режим недоступен, причина названа; выбор сохранён
    assert any("только по исследованию" in p for p in saved.json()["problems"]), saved.json()["problems"]
    assert 'id="package-no-fix" checked' in web.client.get(url.rsplit("/", 1)[0]).text


def test_full_cycle_over_http_and_confirmations_expire(web, monkeypatch):  # noqa: F811
    """Полный цикл режима через HTTP: сохранение текста с режимом → отметка «Остаточный риск проверил» по показанному →
    выдача дефекта без строки обновления → отметка «Дефект создан в Hub»; смена исследования снимает подтверждения
    и показывает «текст изменился»; устаревшая редакция текста – 409 с черновиком и отметкой режима в форме."""
    from test_sca import AS_JSON, sca_card, shown_fields
    from test_sca_package_decision import UPD, post_package
    from test_web import ORIGIN, prepared
    pid = prepared(web)
    state = {"payload": research(finding("CVE-2099-10001", [{"introduced": "0", "fixed": None, "last_affected": "1.4.2"}],
                                         fix_status={"status": "no_fix_published", "scope": "package",
                                                     "source_refs": ["adv"]},
                                         cvss={"score": 7.5, "vector": None, "version": "3.1"}),
                                 latest="1.4.2", target="1.4.2"), "revision": 1}
    monkeypatch.setattr(ScaSnapshot, "research", property(
        lambda self: {"payload": state["payload"], "observed_at": "2026-10-22", "revision": state["revision"]}))
    assert post_package(web, pid, "73002", ["73002"], **UPD).status_code == 200
    fid, _ = sca_card(web, pid, "73002")
    url = f"/projects/{pid}/sca/findings/{fid}"
    explanation = "CVE-2099-10001: Подстановка имени класса в параметры подключения ведёт к выполнению кода."
    first = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        "text_revision": "0", "no_fix": "1", "explanation": explanation, "recommendation_note": MEASURES})
    assert first.status_code == 200 and first.json()["ready"] is False, first.text
    assert any("Остаточный риск проверил" in p for p in first.json()["problems"]), first.json()["problems"]
    card = web.client.get(url).text
    assert 'id="package-no-fix" checked' in card and 'id="package-version-checked"' not in card
    second = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(card), "text_revision": str(first.json()["text_revision"]), "no_fix": "1",
        "explanation": explanation, "recommendation_note": MEASURES, "residual_checked": "1"})
    assert second.status_code == 200 and second.json()["ready"] is True, second.text
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "confirm": "1"})
    assert issued.status_code == 200, issued.text
    body = issued.json()["body"]
    assert "Обновление" not in body and MEASURES in body and "Исправления нет ни в одной опубликованной версии" in body
    card = web.client.get(url).text
    revision = str(web.app.state.db.get_review(pid, "73002")["revision"])
    entered = web.client.post(f"{url}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": revision, "defect_sig": issued.json()["text_sig"]})
    assert entered.status_code == 200, entered.text
    # устаревшая редакция текста – 409, без скрипта черновик и отметка режима остаются в форме
    stale = web.client.post(f"{url}/package-text", headers=ORIGIN, data={
        "text_revision": "0", "no_fix": "1", "explanation": explanation + " Дописано.", "recommendation_note": "Иные меры."})
    assert stale.status_code == 409 and 'id="package-no-fix" checked' in stale.text and "Иные меры." in stale.text
    assert explanation + " Дописано." in stale.text, "черновик объяснения – в форме"
    # только ревизия исследования сменилась (факты те же): подтверждение остаточного риска снято, дефект не выдаётся
    state["revision"] = 2
    again = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "confirm": "1"})
    assert again.status_code == 409 and "Остаточный риск проверил" in again.json()["detail"], again.text
    state["revision"] = 1
    assert web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "confirm": "1"}).status_code == 200
    # смена режима на обычную цель: сохранённое подтверждение режима не действует для целевой версии
    card = web.client.get(url).text
    switched = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(card), "text_revision": str(second.json()["text_revision"]), "target_version": "1.9.9",
        "explanation": explanation, "recommendation_note": MEASURES})
    assert switched.status_code == 200 and switched.json()["ready"] is False, switched.text
    assert any("Версию проверил сам" in p for p in switched.json()["problems"]), switched.json()["problems"]
    back = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(web.client.get(url).text), "text_revision": str(switched.json()["text_revision"]), "no_fix": "1",
        "explanation": explanation, "recommendation_note": MEASURES})
    assert back.status_code == 200 and back.json()["ready"] is False, back.text
    assert any("Остаточный риск проверил" in p for p in back.json()["problems"]), "подтверждение не пережило смену режима"
    redo = web.client.post(f"{url}/package-text", headers=AS_JSON, data={
        **shown_fields(web.client.get(url).text), "text_revision": str(back.json()["text_revision"]), "no_fix": "1",
        "explanation": explanation, "recommendation_note": MEASURES, "residual_checked": "1"})
    assert redo.status_code == 200 and redo.json()["ready"] is True, redo.text
    # исследование сменилось: появилось исправление – это предупреждение, дефект выдаётся с мерами оператора
    # (ADR-0153); остаточных уязвимостей больше нет, у прежней отметки «Внесено» – «текст изменился»
    state["payload"] = research(finding("CVE-2099-10001", [{"introduced": "0", "fixed": "1.6.0"}], ["1.6.0"]),
                                latest="1.6.0", target="1.6.0")
    state["revision"] = 2
    issued = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "5", "confirm": "1"})
    assert issued.status_code == 200 and MEASURES in issued.json()["body"], issued.text
    page = web.client.get(url).text
    assert 'id="entered-changed"' in page and 'id="package-fixed-elsewhere-checked"' not in page
    assert "есть исправление в версии 1.6.0" in page.split('id="sca-set-cautions"', 1)[1].split("</div>", 1)[0]


def test_switching_mode_drops_the_residual_mark(env):
    """Подписи режима свои: отметка «Остаточный риск проверил», поставленная в обычном режиме, режим не подтверждает."""
    db, store, pid, _ = env
    normal = defect(db, store, pid, {**RECORD, "target_basis": "manual", "target_version": "1.5.1"})
    no_fix = defect(db, store, pid, RECORD)
    assert normal["residual_shown_sig"] != no_fix["residual_shown_sig"]
    assert normal["version_sig"] != no_fix["version_sig"]
