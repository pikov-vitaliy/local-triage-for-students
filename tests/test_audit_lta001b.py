"""LTA-001 (повторная проверка): достижимые пути выдачи устаревшего решения SAST.

Независимая проверка нашла, что выдача проверялась по коду модели, а не по коду,
подтверждённому человеком; что переходы привязки вердикта через «нет вердикта» обходили проверку; что отметка
«Проверено» перепривязывала старое решение к новой находке; что выбор модели подставлял «решение»; что проверка и
выдача не были одной операцией; что «Скопировать для Hub» не учитывало пропавшую находку. Реестр –
docs/state/audit-2026-10-15.md.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models import Finding
from app.triage import order_findings
from hub_fixtures import INVOICE
from test_defect import save_sast
from test_sca import form_fields as sca_form_fields
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}
RATIONALE = "Проверено: owner из запроса попадает в SQL без параметров."
MODEL_FIX = "ФИКС-МОДЕЛИ: перейти на PreparedStatement."
HUB_ID = "510001"


def defect(web, url: str, number: str = "", headers=AS_JSON):
    return web.client.post(f"{url}/defect", headers=headers, data={"number": number, "confirm": "1"})


def edit_clone(web, text: str = "    // правка в клоне рядом со строкой срабатывания"):
    path = Path(web.settings.repos_root) / "team" / "billing-core" / INVOICE
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[54] = text
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def reimport(web, pid: int, change=None, drop=()):
    db = web.app.state.db
    rows = [Finding.from_dict(row["data"]) for row in db.findings_data(pid)]
    kept = []
    for f in rows:
        if f.hub_id in drop:
            continue
        if change:
            change(f)
        kept.append(f)
    return db.save_import(pid, "repeat.xlsx", "xlsx", [], {}, [], order_findings(kept))


def change_rule(f: Finding) -> None:
    if f.hub_id == HUB_ID:
        f.rule, f.snippet = "Другое правило", "int другой = код;"


def bind_model_verdict(web, pid: int, fix: str = MODEL_FIX, verdict: str = "false_positive") -> int:
    """Вердикт модели с рекомендацией, привязанный к находке (как после прогона)."""
    db = web.app.state.db
    case = db.get_case(pid, HUB_ID)
    if case is None:  # прогона не было: срез строит сама карточка – берём его из просмотра
        from app.context import build_context
        from app.triage import case_hash

        row = db.case_input(pid, HUB_ID)
        f = Finding.from_dict(row["data"])
        ctx = build_context(Path(web.settings.repos_root) / "team" / "billing-core", f, max_chars=4000, mask_key=web.app.state.mask_key)
        chash, context = case_hash(f, ctx), {**ctx.to_dict(), "max_chars": 4000}
    else:
        chash, context = case["case_hash"], case["context"]
    vid = db.save_verdict(chash, "demo-model", "sast-v3",
                          {"verdict": verdict, "confidence": 90, "hub_comment": "Разбор.", "fix": fix}, {})
    assert db.save_case(pid, HUB_ID, chash, context, vid)
    return vid


@pytest.fixture
def standalone(web):  # noqa: F811
    """Самостоятельное решение без прогона модели: case нет, у решения есть свои отпечатки."""
    pid = prepared(web)
    web.app.state.db.set_settings({"team_name": "Платформа"})
    url, saved = save_sast(web, pid, HUB_ID, "true_positive", "", RATIONALE)
    assert saved["defect_ready"] is True
    assert web.app.state.db.get_case(pid, HUB_ID) is None
    return pid, url


@pytest.fixture
def decided(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    web.app.state.db.set_settings({"team_name": "Платформа"})
    url, saved = save_sast(web, pid, HUB_ID, "true_positive", "", RATIONALE)
    assert saved["defect_ready"] is True
    return pid, url


# ============================================================================ 1. код самого решения

def test_standalone_decision_is_blocked_after_the_file_changed(web, standalone):  # noqa: F811
    pid, url = standalone
    assert defect(web, url).status_code == 200
    edit_clone(web)
    r = defect(web, url)
    assert r.status_code == 409 and "Код в клоне не тот" in r.json()["detail"], r.text
    assert RATIONALE not in r.text


def test_standalone_decision_is_blocked_after_the_file_was_removed(web, standalone):  # noqa: F811
    pid, url = standalone
    (Path(web.settings.repos_root) / "team" / "billing-core" / INVOICE).unlink()
    assert defect(web, url).status_code == 409


def test_resaving_the_decision_unblocks_without_a_new_model_run(web, decided):  # noqa: F811
    """Обещание ADR-0045: достаточно сохранить решение ещё раз. Старый срез модели не должен блокировать."""
    pid, url = decided
    edit_clone(web)
    assert defect(web, url).status_code == 409
    _, saved = save_sast(web, pid, HUB_ID, "true_positive", "", "Проверено по новому коду.")
    assert saved["defect_ready"] is True, "ответ /review и выдача судят по одному правилу"
    r = defect(web, url)
    assert r.status_code == 200, r.text
    assert "Проверено по новому коду." in r.json()["body"]


def test_model_recommendations_are_not_added_to_text_about_other_code(web, decided):  # noqa: F811
    """Решение подтверждено по новому коду, а вердикт модели – про старый: его «Как исправить» в текст не идёт."""
    pid, url = decided
    bind_model_verdict(web, pid, verdict="true_positive")
    # рекомендации модели – только при «Согласен» (ADR-0088): «Подтверждаю дефект» рядом с тем же вердиктом модели
    save_sast(web, pid, HUB_ID, "true_positive", "", RATIONALE)
    assert web.app.state.db.get_review(pid, HUB_ID)["decision"] == "agree"
    # с 0.9.8 (ADR-0092) «Как исправить» модели в текст дефекта не подставляется и при свежем вердикте
    assert MODEL_FIX not in defect(web, url).json()["body"]
    edit_clone(web)
    # код уже не тот, что разбирала модель: то же решение сохраняется как «Не согласен» с итогом «истинная»
    save_sast(web, pid, HUB_ID, "true_positive", "", "Проверено по новому коду.")
    assert web.app.state.db.get_review(pid, HUB_ID)["decision"] == "disagree"
    r = defect(web, url)
    assert r.status_code == 200 and MODEL_FIX not in r.json()["body"]


# ============================================================================ 2. переходы привязки вердикта

def test_verdict_binding_disappears_while_a_new_run_waits(web, decided):  # noqa: F811
    """Привязка вердикта снята до ответа модели, а находка и код в клоне те же, что у решения: решение действует
    (ADR-0097 – силу решения держат отпечатки находки и кода, не привязка ответа модели; до 0.9.10 – отказ 409)."""
    pid, url = decided
    db = web.app.state.db
    case = db.get_case(pid, HUB_ID)
    assert db.save_case(pid, HUB_ID, case["case_hash"] + "x", case["context"], None)
    assert db.get_case(pid, HUB_ID)["verdict_id"] is None
    r = defect(web, url)
    assert r.status_code == 200, r.text


def test_new_verdict_after_a_standalone_decision_adds_no_recommendations(web, standalone):  # noqa: F811
    """None → вердикт: человек его не видел, поэтому «Как исправить» к ранее принятому решению не добавляется."""
    pid, url = standalone
    bind_model_verdict(web, pid, verdict="true_positive")
    r = defect(web, url)
    assert r.status_code == 200 and MODEL_FIX not in r.json()["body"], r.text
    # и после согласия с виденным вердиктом рекомендация модели в текст сама не идёт (ADR-0092)
    save_sast(web, pid, HUB_ID, "true_positive", "", RATIONALE)
    assert MODEL_FIX not in defect(web, url).json()["body"]


# ============================================================================ 3. отметка не перепривязывает решение

def reviewed_request(web, url: str, reviewed: str):
    card = web.client.get(url).text
    data = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
            for name in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}
    return web.client.post(f"{url}/reviewed", headers=AS_JSON, data={**data, "reviewed": reviewed})


@pytest.mark.parametrize("value", ["0", "1"])
def test_reviewed_mark_does_not_rebind_a_stale_decision(web, standalone, value):  # noqa: F811
    pid, url = standalone
    db = web.app.state.db
    before = db.get_review(pid, HUB_ID)
    reimport(web, pid, change_rule)
    assert defect(web, url).status_code == 409
    r = reviewed_request(web, url, value)
    after = db.get_review(pid, HUB_ID)
    assert after["finding_sig"] == before["finding_sig"], "снимок решения не обновлён отметкой"
    assert after["code_hash"] == before["code_hash"]
    if value == "1":
        assert r.status_code == 409 and r.json()["reason"] == "source"
    assert defect(web, url).status_code == 409, "решение по-прежнему устарело"


def test_reviewed_mark_on_the_current_decision_still_works(web, standalone):  # noqa: F811
    pid, url = standalone
    assert reviewed_request(web, url, "0").status_code == 200
    assert reviewed_request(web, url, "1").status_code == 200
    assert web.app.state.db.get_review(pid, HUB_ID)["reviewed"] == 1
    assert defect(web, url).status_code == 200


def test_reviewed_mark_does_not_rebind_a_stale_sca_decision(web):  # noqa: F811
    """Тот же метод у SCA: отметка не перепривязывает согласие к находке с другими уязвимостями."""
    pid = prepared(web)
    db = web.app.state.db
    row = db.get_finding_by_hub_id(pid, "73002")
    url = f"/projects/{pid}/sca/findings/{row['id']}"
    fields = sca_form_fields(web.client.get(url).text)
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive", "comment": "Обновить.", "reviewed": "1",
        "action": "save"})
    assert r.status_code == 200, r.text
    before = db.get_review(pid, "73002")

    def change(f: Finding) -> None:
        if f.hub_id == "73002":
            f.cve = ["CVE-2099-99999"]

    reimport(web, pid, change)
    fields = sca_form_fields(web.client.get(url).text)
    for value in ("0", "1"):
        web.client.post(f"{url}/reviewed", headers=AS_JSON, data={
            "reviewed": value, "finding_version": fields["finding_version"],
            "review_revision": sca_form_fields(web.client.get(url).text)["review_revision"]})
        assert db.get_review(pid, "73002")["finding_sig"] == before["finding_sig"]


# ============================================================================ 4. решение – это выбранное действие

def test_comment_without_a_decision_gives_no_defect(web, decided):  # noqa: F811
    """Вердикт подставлен моделью, человек сохранил только комментарий: «решения» нет, дефект не готовится."""
    pid, url = decided
    card = web.client.get(url).text
    fields = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
              for name in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "fix": "Параметризовать запрос.", "decision": "", "final_verdict": "true_positive", "comment": "Только комментарий.", "action": "save"})
    assert r.status_code == 200 and r.json()["defect_ready"] is False
    d = defect(web, url)
    assert d.status_code == 409 and "сохранённому" in d.json()["detail"], d.text
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in web.client.get(url).text


# ============================================================================ 5. один снимок и повторная проверка

def interleave_before_number(web, action):
    original = web.app.state.db.set_defect_number_checked

    def injected(*args, **kwargs):
        action()
        return original(*args, **kwargs)

    return patch.object(web.app.state.db, "set_defect_number_checked", side_effect=injected)


def test_finding_replaced_between_the_check_and_the_number(web, decided):  # noqa: F811
    pid, url = decided
    with interleave_before_number(web, lambda: reimport(web, pid, change_rule)):
        r = defect(web, url)
    assert r.status_code == 409 and r.json()["reason"] == "source", r.text
    assert web.app.state.db.defect_number(pid, f"sast:{HUB_ID}") is None, "номер не записан"


def test_finding_goes_missing_between_the_check_and_the_number(web, decided):  # noqa: F811
    pid, url = decided
    with interleave_before_number(web, lambda: reimport(web, pid, drop={HUB_ID})):
        r = defect(web, url)
    assert r.status_code == 409 and web.app.state.db.defect_number(pid, f"sast:{HUB_ID}") is None


def test_decision_saved_again_between_the_check_and_the_number(web, decided):  # noqa: F811
    pid, url = decided
    with interleave_before_number(web, lambda: save_sast(web, pid, HUB_ID, "true_positive", "", "Новое.")):
        r = defect(web, url)
    assert r.status_code == 409 and r.json()["reason"] == "revision"


def test_project_deleted_between_the_check_and_the_number(web, decided):  # noqa: F811
    pid, url = decided
    with interleave_before_number(web, lambda: web.app.state.db.delete_project(pid)):
        r = defect(web, url)
    assert r.status_code == 409, "контролируемый отказ, а не ошибка внешнего ключа"


def test_title_comes_from_the_same_snapshot_as_the_check(web, decided):  # noqa: F811
    """Положительный контроль: без вмешательства выдача проходит, заголовок и тело – от проверенной находки."""
    pid, url = decided
    r = defect(web, url)
    assert r.status_code == 200 and r.json()["title"].startswith("ID1 - ")
    assert web.app.state.db.defect_number(pid, f"sast:{HUB_ID}") == 1


# ============================================================================ 6. «Скопировать для Hub» и пропавшая находка

def review_form(web, url: str) -> dict:
    card = web.client.get(url).text
    return {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
            for name in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}


def test_copy_for_hub_is_refused_for_a_missing_finding(web, decided):  # noqa: F811
    pid, url = decided
    fields = review_form(web, url)
    reimport(web, pid, drop={HUB_ID})
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "fix": "Параметризовать запрос.", "decision": "false_positive", "final_verdict": "", "comment": RATIONALE, "action": "copy"})
    assert r.status_code == 400 and r.json()["reason"] == "rejected" and "hub_text" not in r.json(), r.text
    assert "нет в текущей выгрузке" in r.json()["detail"]


def test_card_marks_the_old_hub_text_as_historic(web, decided):  # noqa: F811
    pid, url = decided
    assert 'id="hub-historic"' not in web.client.get(url).text
    reimport(web, pid, change_rule)
    card = web.client.get(url).text
    assert 'id="hub-historic"' in card and "Исторический текст" in card


def test_sast_unclear_and_later_are_not_copied(web):  # noqa: F811
    """С 0.9.6 (ADR-0089) у SAST копируется только комментарий ложного срабатывания: итог «неясно» не сохраняется,
    а отложенная находка в Hub не переносится. У SCA те же итоги копируются по-прежнему."""
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, HUB_ID)["id"]
    url = f"/projects/{pid}/findings/{fid}"
    fields = review_form(web, url)
    unclear = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "uncertain", "comment": "Нужна проверка.",
        "action": "copy"})
    assert unclear.status_code == 400 and "два решения" in unclear.json()["detail"], unclear.text
    later = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **review_form(web, url), "fix": "Параметризовать запрос.", "decision": "later", "final_verdict": "", "comment": "Нужна проверка.",
        "action": "copy"})
    assert later.status_code == 400 and "hub_text" not in later.json(), later.text
    assert "только при решении «Ложное срабатывание»" in later.json()["detail"]
    # ложное срабатывание копируется
    ok = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **review_form(web, url), "fix": "Параметризовать запрос.", "decision": "false_positive", "final_verdict": "",
        "comment": "Имя таблицы берётся из заранее заданной строки.", "action": "copy"})
    assert ok.status_code == 200 and ok.json()["hub_text"], ok.text


def test_sca_short_text_only_for_false_positive_and_risk(web):  # noqa: F811
    """SCA 0.9.8 (ADR-0091 п. 3): короткий текст – только обоснование оператора у «Ложное срабатывание» и «Риск
    принят»; у «Обновить», «неясно» и «Отложить» его нет – копирование отклоняется и ничего не записывает."""
    from test_sca import form_fields

    pid = prepared(web)
    db = web.app.state.db
    row = db.get_finding_by_hub_id(pid, "73002")
    url = f"/projects/{pid}/sca/findings/{row['id']}"

    def copy(decision, verdict, comment="Нужна проверка."):
        return web.client.post(f"{url}/review", headers=AS_JSON, data={
            **form_fields(web.client.get(url).text), "decision": decision, "final_verdict": verdict,
            "comment": comment, "kapo_state": "not_actual" if decision == "risk_accepted" else "", "action": "copy"})

    for decision, verdict in (("disagree", "true_positive"), ("disagree", "uncertain"), ("later", "")):
        r = copy(decision, verdict)
        assert r.status_code == 400 and "короткого текста" in r.json()["detail"], r.text
        assert db.get_review(pid, "73002") is None
    for decision, verdict in (("disagree", "false_positive"), ("risk_accepted", "")):
        r = copy(decision, verdict, "Уязвимая функция в продукте не вызывается.")
        assert r.status_code == 200, r.text
        # номер, компонент и обоснование (ADR-0101)
        assert r.json()["hub_text"] == "CVE-2099-10001 в example-parser 1.4.2: Уязвимая функция в продукте не вызывается."


# ============================================================================ HTTP-контракт блокировки

def test_blocked_defect_answers_409_for_the_html_form_too(web, decided):  # noqa: F811
    pid, url = decided
    reimport(web, pid, drop={HUB_ID})
    r = web.client.post(f"{url}/defect", headers=ORIGIN, data={"number": "", "confirm": "1"})
    assert r.status_code == 409 and "нет в текущей выгрузке" in r.text
