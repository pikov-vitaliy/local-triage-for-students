"""LTA-001: текст дефекта SAST выдаётся только по действующему решению.

Замечание аудита 15.10.2026 (реестр – docs/state/audit-2026-10-15.md): после повторного импорта с изменённым
правилом и кодом отметка «Проверено» снималась, но выдача текста дефекта отвечала 200, и в одном тексте
оказывались новое правило и прежнее обоснование; то же – если находка исчезла из новой выгрузки.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.models import Finding
from app.routes.findings import sast_decision_state, sast_state_text
from app.triage import order_findings
from hub_fixtures import INVOICE, make_hub_xlsx
from test_defect import save_sast
from test_web import ORIGIN, prepared, start_run, upload, wait_run, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}
RATIONALE = "Проверено: owner из запроса попадает в SQL без параметров."


def defect(web, url: str, number: str = "", confirm: str = "1"):
    return web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": number, "confirm": confirm})


def reimport(web, pid: int, change=None, drop: set[str] = frozenset()):
    """Повторный импорт тех же находок: change – правка находки на месте, drop – номера, которых в выгрузке не будет."""
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


@pytest.fixture
def decided(web):  # noqa: F811
    """Проект с разобранной находкой 510001 и сохранённым решением «Подтверждаю дефект» (с 0.9.6 дефект SAST – только
    для подтверждённой находки, ADR-0089; модель считает срабатывание ложным, в базе – «Не согласен»)."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    web.app.state.db.set_settings({"team_name": "Платформа"})
    url, saved = save_sast(web, pid, "510001", "true_positive", "", RATIONALE)
    assert saved["defect_ready"] is True
    assert defect(web, url).status_code == 200
    return pid, url


# ============================================================================ критерий 1: изменённая и пропавшая

def test_changed_finding_blocks_the_defect_text(web, decided):  # noqa: F811
    """Правило и код сменились при повторном импорте: прежнее обоснование не уходит в Hub вместе с новым правилом."""
    pid, url = decided

    def change(f: Finding) -> None:
        if f.hub_id == "510001":
            f.rule, f.snippet = "Другое правило", "int другой = код;"

    stats = reimport(web, pid, change)
    assert stats["reopened"] == 1 and web.app.state.db.get_review(pid, "510001")["reviewed"] == 0
    r = defect(web, url)
    assert r.status_code == 409, r.text
    assert "прежней версии находки" in r.json()["detail"]
    assert RATIONALE not in r.text and "Другое правило" not in r.text
    card = web.client.get(url).text
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in card
    assert 'id="defect-blocked"' in card and "прежней версии находки" in card


def test_missing_finding_blocks_the_defect_text(web, decided):  # noqa: F811
    pid, url = decided
    reimport(web, pid, drop={"510001"})
    r = defect(web, url)
    assert r.status_code == 409 and "нет в текущей выгрузке" in r.json()["detail"]
    assert RATIONALE not in r.text
    review = web.app.state.db.get_review(pid, "510001")
    assert review["decision"] == "disagree" and review["final_comment"] == RATIONALE


# ============================================================================ критерий 2: импорт без изменений

def test_unchanged_reimport_keeps_the_decision_working(web, decided):  # noqa: F811
    pid, url = decided
    stats = reimport(web, pid)
    assert stats["reopened"] == 0
    review = web.app.state.db.get_review(pid, "510001")
    assert review["reviewed"] == 1
    r = defect(web, url)
    assert r.status_code == 200, r.text
    assert RATIONALE in r.json()["body"]


def test_unchanged_reimport_from_the_same_file_keeps_the_decision(web, decided):  # noqa: F811
    """Тот же файл выгрузки, загруженный ещё раз через интерфейс: решение продолжает действовать."""
    pid, url = decided
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "again.xlsx")).status_code == 303
    assert defect(web, url).status_code == 200


# ============================================================================ критерий 3: новое подтверждение

def test_after_new_decision_the_text_holds_one_snapshot(web, decided):  # noqa: F811
    """После повторного решения по новым данным выдача разрешена, а в тексте – данные одного снимка."""
    pid, url = decided

    def change(f: Finding) -> None:
        if f.hub_id == "510001":
            f.rule, f.snippet = "Другое правило", "int другой = код;"

    reimport(web, pid, change)
    assert defect(web, url).status_code == 409
    _, saved = save_sast(web, pid, "510001", "true_positive", "", "Проверено заново: параметры запроса.")
    assert saved["defect_ready"] is True
    r = defect(web, url)
    assert r.status_code == 200, r.text
    body = r.json()["body"]
    assert "Другое правило" in r.json()["title"] and "Проверено заново" in body
    assert RATIONALE not in body, "прежнее обоснование в новый текст не попадает"


# ============================================================================ критерий 4: клон обновился

def test_clone_change_without_reimport_blocks_the_defect_text(web, decided):  # noqa: F811
    """Код в клоне правят, выгрузку не меняют, модель заново не спрашивают: решение относится к прежнему коду."""
    pid, url = decided
    path = Path(web.settings.repos_root) / "team" / "billing-core" / INVOICE
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[54] = "    // правка в клоне рядом со строкой срабатывания"  # строка 55: внутри показанного среза
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = defect(web, url)
    assert r.status_code == 409, r.text
    assert "Код в клоне не тот" in r.json()["detail"]
    card = web.client.get(url).text
    assert 'id="defect-blocked"' in card and "Код в клоне не тот" in card
    # после нового разбора того же кода и нового решения выдача снова разрешена
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    _, saved = save_sast(web, pid, "510001", "true_positive", "", "Проверено по текущему коду.")
    assert saved["defect_ready"] is True
    assert defect(web, url).status_code == 200


def test_new_model_verdict_after_the_decision_keeps_the_defect_text(web, decided):  # noqa: F811
    """Находку разобрали заново по тому же коду, решение осталось прежним: оно действует (ADR-0097;
    до 0.9.10 новый ответ модели блокировал выдачу до пересохранения)."""
    pid, url = decided
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    review = db.get_review(pid, "510001")
    assert review["verdict_id"] == case["verdict_id"]
    # новый ответ модели по тому же коду (как после «Пересмотреть вердикт»)
    verdict_id = db.save_verdict(case["case_hash"], "demo-model", "sast-v3",
                                 {"verdict": "true_positive", "confidence": 0.9, "hub_comment": "Новый разбор."},
                                 {})
    assert db.save_case(pid, "510001", case["case_hash"], case["context"], verdict_id)
    assert db.get_case(pid, "510001")["verdict_id"] == verdict_id != review["verdict_id"]
    r = defect(web, url)
    assert r.status_code == 200, r.text
    card = web.client.get(url).text
    assert 'id="defect-blocked"' not in card and "остаётся в силе" in card


# ============================================================================ состояния: единое правило

def test_states_of_a_sast_decision():
    from app.db import source_signature

    source = {"data": {"kind": "SAST"}, "repos_dir": "", "folder": "", "revision": "", "missing": False}
    review = {"decision": "disagree", "final_verdict": "true_positive", "finding_sig": source_signature(source),
              "verdict_id": 7, "code_hash": "code", "code_chars": 4000}
    case = {"verdict_id": 7, "case_hash": "other-hash-of-model-code"}
    assert sast_decision_state(None) == ("none", "")
    assert sast_decision_state({"decision": "later", "final_verdict": ""}) == ("later", "")
    assert sast_decision_state(review, source, case, "code") == ("ok", "true_positive")
    # ложное срабатывание закрывается комментарием: дефекта нет (ADR-0089)
    assert sast_decision_state({**review, "final_verdict": "false_positive"}, source, case, "code") == (
        "not_ready", "false_positive")
    assert sast_decision_state(review, {**source, "missing": True}, case, "code")[0] == "missing"
    assert sast_decision_state({**review, "finding_sig": "другой"}, source, case, "code")[0] == "changed"
    # новый ответ модели по тому же коду решение не ослабляет (ADR-0097): находку и код сверяют finding_sig и code_hash
    assert sast_decision_state(review, source, {"verdict_id": 8}, "code")[0] == "ok"
    assert sast_decision_state(review, source, case, "другой")[0] == "code_changed"
    assert sast_decision_state({**review, "final_verdict": "uncertain"}, source, case, "code")[0] == "not_ready"
    assert sast_state_text("missing", "") == "нет в текущей выгрузке"
    assert sast_state_text("not_ready", "uncertain") == "прежнее решение «неясно»"
    assert sast_state_text("not_ready", "false_positive") == "ложное срабатывание – дефект не создаётся"


def test_card_without_decision_is_unchanged(web):  # noqa: F811
    """Карточка без решения: панель дефекта скрыта, предупреждения о блокировке нет."""
    pid = prepared(web)
    fid = web.app.state.db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in card
    assert 'id="defect-blocked"' not in card
    assert re.search(r'name="review_revision" value="0"', card)
