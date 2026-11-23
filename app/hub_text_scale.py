"""Масштаб смены правил текста для Hub в 0.10.0.dev21 (текст оператора уходит как написан).

По проекту – решения, у которых текст по прежним правилам (0.9.11–0.10.0.dev20: срез вводного «Подтверждено:», теги,
схемы, невидимые знаки, длинное тире, схлопывание пустых строк, срезанные отступы, у набора дефекта SCA – отступ
Объяснения и добавления к «Рекомендациям», пустые строки добавления)
отличается от нынешнего, и что с их отметками «Внесено в Hub». Уже внесённые тексты не переотправляются и отметки не
снимаются: что с ними делать, решает владелец.

Только чтение: отчёт собирается из сохранённых решений теми же функциями, что строят текст для Hub; аренды Hub не
истекают, дефекты не сверяются, страница ничего не пишет (тест – tests/test_hub_text_as_written.py)."""

from __future__ import annotations

import json
from typing import Any

from app import i18n, package_identity
from app.db import Database, hub_verdict, text_hash
from app.models import Finding
from app.sca_contract import input_ref

ORIGINS = i18n.Labels({"manual": "отметка оператора", "defect": "по созданному дефекту", "status": "по записи статуса",
                       "hub_sync": "принята из Hub", "bulk": "общим комментарием"})
OUTCOMES = i18n.Labels({"true_positive": "истинная (дефект)", "false_positive": "ложное срабатывание",
                        "risk_accepted": "риск принят", "uncertain": "решение не принято"})


def _mark(review: dict, current: str, prior: str) -> dict:
    """Отметка «Внесено в Hub» решения: есть ли, откуда, по какому тексту (прежнему, нынешнему или другому)."""
    if not review.get("entered_hub"):
        return {"entered": False, "origin": "", "basis": ""}
    origin = str(review.get("entered_origin") or "")
    try:
        parts = json.loads(review.get("entered_parts") or "") or {}
    except ValueError:
        parts = {}
    if isinstance(parts, dict) and parts.get("bulk"):
        origin = "bulk"
    hashes = {review.get("entered_text_hash") or "", review.get("entered_decision_hash") or ""} - {""}
    if not hashes:
        basis = i18n._("без отпечатка текста")
    elif text_hash(prior) in hashes:
        basis = i18n._("по прежнему тексту")
    elif text_hash(current) in hashes:
        basis = i18n._("по нынешнему тексту")
    else:
        basis = i18n._("по другому тексту")
    return {"entered": True, "origin": ORIGINS.get(origin, origin or i18n._("не указано")), "basis": basis}


def _set_member(db: Database, project_id: int, item: dict, note: dict) -> bool:
    """Находка – участник набора дефекта по тому же правилу, что у сборщика дефекта (routes/sca.sca_defect): в текущей
    выгрузке, действующее решение «Обновить», размещена в этом наборе («без дефекта» – нет)."""
    from app.routes import sca as sca_routes
    row = item["row"]
    if row.get("missing"):
        return False
    place = note["placed"].get(item["hub_id"], 0)
    if place is None or int(place) != note["set_no"]:
        return False
    f = item["finding"]
    latest = sca_routes._latest_answer(db, project_id, f)
    state, outcome = sca_routes.decision_state(f, db.get_review(project_id, f.hub_id), latest, row)
    return state == "ok" and outcome == "true_positive"


def report(db: Database, settings: Any, project_id: int, store: Any) -> dict:
    """{"sast": [...], "sca": [...], "other": [...], "sets": [...], "totals": {...}} – строки решений, у которых текст
    изменился. store – справочники (FeedStore): набор дефекта SCA строится тем же сборщиком, что у карточки, и
    попадает в отчёт, если его тело по прежним правилам другое (ревью Codex круга 5)."""
    from app.routes import findings as sast_routes
    from app.routes import sca as sca_routes
    rows, _ = db.list_findings(project_id, limit=1_000_000)
    sast_rows: list[dict] = []
    sca_rows: list[dict] = []
    other_rows: list[dict] = []
    packages: dict[str, list[dict]] = {}
    for row in rows:
        f = Finding.from_dict(row["data"])
        if row["kind"] == "SCA":
            # ключ набора – эффективная тройка пакета, как у сборщика карточки (план dev17, п. 4.3)
            ref = input_ref(*package_identity.of(row["data"]))
            packages.setdefault(ref, []).append({"hub_id": f.hub_id, "id": row["id"],
                                                 "component": f.package_display_name,
                                                 "version": f.version, "finding": f, "row": row})
        if not row.get("decision"):
            continue
        review = db.get_review(project_id, f.hub_id)
        if not review or not review.get("decision"):
            continue
        outcome = hub_verdict(review["decision"], review["final_verdict"])
        if row["kind"] == "SAST":
            prior = sast_routes.saved_hub_text_v4(f, review, settings.team_name)
            if not prior:
                continue
            current = sast_routes.sast_entered_text(db, settings, project_id, f, review)
            sast_rows.append({"hub_id": f.hub_id, "id": row["id"], "outcome": OUTCOMES.get(outcome, outcome),
                              **_mark(review, current, prior)})
        elif row["kind"] != "SCA":  # DAST, SCA-license: до 0.10.0.dev21 текущим был формат hub_text_v1
            prior = sast_routes.saved_hub_text_v1(f, review, settings.hub_status_map)
            current = sast_routes.saved_hub_text(f, review, settings.hub_status_map)
            if prior and prior != current:
                other_rows.append({"hub_id": f.hub_id, "id": row["id"], "kind": row["kind"],
                                   "outcome": OUTCOMES.get(outcome, outcome), **_mark(review, current, prior)})
        elif row["kind"] == "SCA" and outcome in ("false_positive", "risk_accepted"):
            current = sca_routes.saved_hub_text(db, settings, project_id, f, review)
            prior = sca_routes.saved_hub_text_v4(db, settings, project_id, f, review)
            if not prior or prior == current:
                continue
            sca_rows.append({"hub_id": f.hub_id, "id": row["id"], "outcome": OUTCOMES.get(outcome, outcome),
                             "component": f.package_display_name, "version": f.version,
                             **_mark(review, current, prior)})
    sets: list[dict] = []
    for note in db.sca_text_notes(project_id):
        chosen = [m for m in packages.get(note["input_ref"], []) if _set_member(db, project_id, m, note)]
        if not chosen:
            continue
        view = sca_routes.sca_defect(db, store, project_id, chosen[0]["finding"],
                                     db.get_review(project_id, chosen[0]["hub_id"]))
        if not view.get("legacy_text_sig_v4"):
            continue  # тело по прежним правилам то же – текст набора не изменился
        first = (packages.get(note["input_ref"]) or [{}])[0]
        sets.append({"component": first.get("component") or "", "version": first.get("version") or "",
                     "set_no": note["set_no"], "members": _set_marks(db, project_id, chosen, view)})
    marks = sast_rows + sca_rows + other_rows + [m for s in sets for m in s["members"]]
    return {"sast": sast_rows, "sca": sca_rows, "other": other_rows, "sets": sets,
            "totals": {"sast": len(sast_rows), "sca": len(sca_rows), "other": len(other_rows), "sets": len(sets),
                       "entered": sum(1 for r in marks if r["entered"])}}


def _set_marks(db: Database, project_id: int, members: list[dict], view: dict) -> list[dict]:
    """Участники набора с отметками «Дефект создан в Hub»: по чему поставлена – по тексту набора прежних правил
    (legacy_text_sig_v4), нынешнему (text_sig) или другому. view – набор из того же сборщика дефекта, что у
    карточки."""
    current, prior = str(view.get("text_sig") or ""), str(view.get("legacy_text_sig_v4") or "")
    out = []
    for m in members:
        review = db.get_review(project_id, m["hub_id"]) or {}
        out.append({"hub_id": m["hub_id"], "id": m["id"], **_mark_by_sig(review, current, prior)})
    return out


def _mark_by_sig(review: dict, current: str, prior: str) -> dict:
    """Как _mark, но по подписям тела набора SCA: у отметки от дефекта – entered_decision_hash, иначе
    entered_text_hash (как в карточке SCA)."""
    if not review.get("entered_hub"):
        return {"entered": False, "origin": "", "basis": ""}
    origin = str(review.get("entered_origin") or "")
    sig = str((review.get("entered_decision_hash") if origin == "defect" else review.get("entered_text_hash")) or "")
    if not sig:
        basis = i18n._("без отпечатка текста")
    elif prior and sig == prior:
        basis = i18n._("по прежнему тексту")
    elif current and sig == current:
        basis = i18n._("по нынешнему тексту")
    else:
        basis = i18n._("по другому тексту")
    return {"entered": True, "origin": ORIGINS.get(origin, origin or i18n._("не указано")), "basis": basis}

