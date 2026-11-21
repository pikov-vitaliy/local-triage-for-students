"""Фактические группы SCA и локальный текст конфликтного состава, без расширения целей."""

from app import defect_drafts, defect_where, package_identity
from app.db import loads
from app.models import Finding
from app.sca_contract import input_ref


def groups_in(c, row):
    groups = {}
    targets = loads(row["targets_json"], [])
    for hub_id in dict.fromkeys(str(t.get("hub_id") or "") for t in targets):
        found = c.execute("SELECT id, kind, data_json, missing, pkg_ecosystem, pkg_name, pkg_source, pkg_note,"
                          " pkg_scope FROM findings WHERE project_id = ? AND hub_id = ?",
                          (row["project_id"], hub_id)).fetchone()
        data = package_identity.with_package(dict(found)) if found else {}
        eco, component, version = package_identity.of(data)  # эффективная тройка (план dev17, п. 4.3)
        place = c.execute("SELECT set_no FROM sca_set_members WHERE project_id = ? AND hub_id = ? AND input_ref = ?",
                          (row["project_id"], hub_id, input_ref(eco, component, version))).fetchone()
        set_no = place["set_no"] if place else 0
        issues = []
        if not found or found["kind"] != "SCA":
            issues.append("находка отсутствует или другого вида")
        if not component or not version:
            issues.append("не указаны компонент или версия")
        if found and found["missing"]:
            issues.append("нет в текущей выгрузке")
        key = (eco, component, version, set_no)
        group = groups.setdefault(key, {"ecosystem": eco, "component": component, "version": version,
                                        "set_no": set_no, "targets": []})
        group["targets"].append({"hub_id": hub_id, "id": found["id"] if found else None, "issues": issues})
    return list(groups.values())


def explanation(groups):
    if not groups:
        return "В дефекте нет локальных целей; версии и наборы определить нельзя."
    if any(t["issues"] for g in groups for t in g["targets"]):
        return "Данных части находок недостаточно для определения единого состава SCA."
    if len({(g["ecosystem"], g["component"]) for g in groups}) > 1:
        return "В дефекте объединены находки разных компонентов или экосистем."
    if len({g["version"] for g in groups}) > 1:
        return "В дефекте объединены находки разных версий компонента."
    if any(g["set_no"] is None for g in groups):
        return "В составе есть находки из группы «без дефекта»."
    return "В дефекте объединены находки разных наборов SCA."


def generate(request, row):
    """Текст из решений; раздел «Где исправлять» из черновика остаётся: он не из решений (план dev7, раздел 11)."""
    prepared = _from_decisions(request, row)
    section = defect_where.own_tail(row.get("draft_command_text"))
    if not section or prepared.get("refusals") or not str(prepared.get("command_text") or "").strip():
        return prepared
    if defect_where.has_head(prepared["command_text"]):  # заголовок уже в тексте решения: второй экземпляр не нужен
        return prepared
    return {**prepared, "command_text": defect_where.join(defect_where.split(prepared["command_text"])[0], section)}


def _from_decisions(request, row):
    from app.routes import hub_defect_routes as flow
    from app.routes import sca as sca_card
    from app.routes.common import db_of
    db = db_of(request)
    if row["kind"] != "SCA" or not loads(row["conflicts_json"], []):
        return flow.prepare_update(request, row, from_decisions=True)
    groups = db.on_connection(lambda c: groups_in(c, row))
    members = db.on_connection(lambda c: defect_drafts.members_in(c, row))
    sources, sections = [], []
    for group in groups:
        number = "без дефекта" if group["set_no"] is None else str(group["set_no"])
        lines = [f"{group['ecosystem'] or 'экосистема не указана'} / {group['component'] or 'компонент не указан'} / "
                 f"{group['version'] or 'версия не указана'} / набор {number}"]
        for target in group["targets"]:
            hub_id = target["hub_id"]
            snap = db.sca_snapshot(row["project_id"], hub_id)
            review = snap.review or {}
            sources.append((hub_id, snap.fingerprint, review.get("revision", 0)))
            lines.append(f"Находка {hub_id}:")
            if snap.row is None:
                lines.append("Находка отсутствует; решение не подставлено.")
                continue
            state, outcome = sca_card.decision_state(Finding.from_dict(snap.row["data"]), review,
                                                     snap.latest_answer, snap.row)
            if state != "ok":
                lines.append(sca_card.state_text(state, outcome) + ". Сохранённый текст не использован.")
                continue
            lines.append("Решение: " + sca_card.OUTCOME_LABELS.get(outcome, outcome))
            lines.append(review.get("final_comment") or "Текст решения не сохранён.")
        sections.append("\n".join(lines))

    def check(c):
        if defect_drafts.members_in(c, row) != members or groups_in(c, row) != groups:
            raise ValueError("Состав изменился во время сборки: повторите действие.")
        for hub_id, fingerprint, revision in sources:
            if db._sca_defect_fingerprint(c, row["project_id"], hub_id) != fingerprint:
                raise ValueError("Источники решения изменились во время сборки.")
            current = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?",
                                (row["project_id"], hub_id)).fetchone()
            if (current[0] if current else 0) != revision:
                raise ValueError("Решение изменилось во время сборки.")
    return {"summary": row["draft_summary"], "command_text": "\n\n".join(sections) or "В дефекте нет локальных целей.",
            "tx_check": check, "refusals": []}
