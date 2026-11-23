"""Дефекты приложения по находкам – для списков, групп и карточек: какие компоненты уже с
дефектами, какие нет, и ссылки на конкретные дефекты.

Строки `hub_defects`, кроме отменённых и не принятых Hub; у семьи записи (владелец и строки привязки) состав – все её
строки, подпись – по владельцу. Сводка дефекта: {id, number, hub_defect_id, state, label, done, card_url, kind,
origin, text} – text: «ID1 · №555», у дефекта не «создан» – с его состоянием."""

from __future__ import annotations

from typing import Iterable

from app import hub_defects, i18n
from app.db import Database, loads

HIDDEN_STATES = ("cancelled", "failed")
# находка привязана к дефекту (POST мог дойти до Hub) – как у карточки (db.hub_defect_bound); заготовка и
# предпросмотр – подготовка: значок есть, но «в дефекте» версия не считается (ревью dev19, круг 2)
BOUND_STATES = Database.HUB_DEFECT_BOUND


def _word(bound: bool) -> str:
    """Слово перед text в значке (ревью dev20) – на языке интерфейса."""
    return i18n._("дефект") if bound else i18n._("подготовка дефекта")


def summary(row: dict, project_id: int) -> dict:
    """Сводка строки-владельца дефекта для значка."""
    state = str(row.get("state") or "")
    done = state == "done"  # «создан, привязка неполная» и прочие – с подписью состояния и предупреждающим цветом
    number = row.get("number")
    label = hub_defects.STATE_LABELS.get(state, state)
    parts = [f"ID{number}"] if isinstance(number, int) and not isinstance(number, bool) and number > 0 else []
    if row.get("hub_defect_id"):
        parts.append(f"№{row['hub_defect_id']}")
    text = " · ".join(parts) or i18n._("строка {id}", id=row["id"])
    if not done:
        text += f" · {label}"
    bound = state in BOUND_STATES
    return {"id": int(row["id"]), "number": number, "hub_defect_id": str(row.get("hub_defect_id") or ""),
            "state": state, "label": label, "done": done, "bound": bound,
            "word": _word(bound),  # слово перед text в значке (ревью dev20)
            "card_url": f"/projects/{project_id}/defects/{row['id']}",
            "kind": str(row.get("kind") or ""), "origin": str(row.get("origin") or ""), "text": text}


def by_hub_id(db: Database, project_id: int, kind: str | None = None) -> dict[str, list[dict]]:
    """{hub_id находки: [сводки дефектов]} по строкам hub_defects проекта (kind – только дефекты этого вида). Состав –
    из строк семьи, кроме скрытых (отменённых и не принятых); подпись – по владельцу, а если владелец скрыт, а строка
    привязки действует, – по этой строке с номерами владельца (ревью dev19: привязка не теряется)."""
    rows = db._all("SELECT id, draft_owner_id, number, hub_defect_id, state, kind, origin, targets_json FROM hub_defects"
                   " WHERE project_id = ?" + (" AND kind = ?" if kind else "") + " ORDER BY id",
                   (project_id, *((kind,) if kind else ())))
    families: dict[int, dict] = {}
    for row in rows:
        owner_id = int(row["draft_owner_id"] or row["id"])
        family = families.setdefault(owner_id, {"hub_ids": set(), "bound": set(), "owner": None, "live": None})
        if int(row["id"]) == owner_id:
            family["owner"] = row
        if row["state"] in HIDDEN_STATES:
            continue
        ids = {str(t.get("hub_id") or "") for t in loads(row["targets_json"], []) if isinstance(t, dict)}
        family["hub_ids"] |= ids
        if row["state"] in BOUND_STATES:  # привязка – по состоянию каждой физической строки, не сводки семьи
            family["bound"] |= ids
        if int(row["id"]) == owner_id or family["live"] is None:
            family["live"] = row  # владелец, если действует; иначе первая действующая строка привязки
    out: dict[str, list[dict]] = {}
    for owner_id, family in sorted(families.items()):
        live = family["live"]
        if live is None or not family["hub_ids"]:
            continue
        owner = family["owner"] or live
        item = summary({**live, "id": owner_id, "number": owner["number"], "hub_defect_id": owner["hub_defect_id"],
                        "kind": owner["kind"], "origin": owner["origin"]}, project_id)
        for hub_id in family["hub_ids"]:
            if hub_id:
                bound = hub_id in family["bound"]
                out.setdefault(hub_id, []).append({**item, "bound": bound,
                                                   "word": _word(bound)})
    return out


def merge(groups: Iterable[Iterable[dict]]) -> list[dict]:
    """Сводки без повторов, по возрастанию номера строки."""
    seen: dict[int, dict] = {}
    for items in groups:
        for item in items:
            kept = seen.setdefault(item["id"], dict(item))
            kept["bound"] = bool(kept.get("bound")) or bool(item.get("bound"))
            kept["word"] = _word(kept["bound"])
    return [seen[k] for k in sorted(seen)]


def in_defect(defects: Iterable[dict]) -> bool:
    """Строка в дефекте: хотя бы одна её находка привязана (bound); одна подготовка – нет."""
    return any(d.get("bound") for d in defects)


def confirmed_hub_ids(db: Database, project_id: int, kind: str | None = None) -> set[str]:
    """Номера находок, у которых дефект подтверждён чтением Hub: цели физических строк hub_defects в состоянии done.
    Строка привязки в состоянии linking или unknown подтверждённость владельца не наследует (ревью dev27)."""
    rows = db._all("SELECT targets_json FROM hub_defects WHERE project_id = ? AND state = 'done'"
                   + (" AND kind = ?" if kind else ""), (project_id, kind) if kind else (project_id,))
    return {str(t.get("hub_id") or "") for r in rows for t in loads(r["targets_json"], []) if t.get("hub_id")}


def attach(items: Iterable[dict], by: dict[str, list[dict]], key: str = "hub_id") -> None:
    """Каждой строке – defects (по её hub_id или списку hub_ids) и in_defect (хотя бы одна находка привязана)."""
    for item in items:
        ids = item.get("hub_ids") if "hub_ids" in item else [item.get(key)]
        item["defects"] = merge(by.get(str(h or ""), []) for h in (ids or []))
        item["in_defect"] = in_defect(item["defects"])
