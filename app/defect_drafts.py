"""Владелец, черновик и история логического дефекта (ADR-0126, dev1)."""

from __future__ import annotations

from app import package_identity

from typing import Any

from app import hub_entity_versions
from app.db import Database, dumps, loads, now_iso, text_hash
from app.defect import defect_key_sca
from app.sca_contract import input_ref

EDITABLE_FIELDS = (
    "priority", "priorityId", "severity", "severityId", "source", "tool", "stage", "type",
    "structureUnitId", "appStructureUnit", "dueDate", "releaseObject", "externalBugs", "isActive", "settings",
)


def fields_of(obj: dict) -> dict:
    """Отсутствие поля сохраняется; null не заменяется пустым значением."""
    return {key: obj[key] for key in EDITABLE_FIELDS if key in obj}


# цель «тип:номер», которой нет среди находок проекта с тем же типом связи (SAST:73001 рядом с SCA_S:73001 – не та же
# цель): единственный набор SCA по такому составу не доказан – одинаково во всех фазах принятия Hub, при подготовке,
# подтверждении и сверке дефекта (план dev17, остаток шага 4)
UNMATCHED_TARGETS = "цели дефекта {ids} нет среди находок SCA проекта или у неё другой тип: единственный набор не определить"


def unmatched_targets(c, project_id: int, targets, *, typeless: bool = False) -> list[str]:
    """Цели «тип:номер», которых нет среди находок проекта с тем же типом связи (порядок сохранён). Цель без типа
    связи (записи до типизированных целей) несопоставленной считается только при typeless=True; иначе её проверяет вид
    находки в sca_identity."""
    from app.hub_status import HUB_ISSUE_TYPE
    out: list[str] = []
    for t in targets:
        hub_id, typ = str(t.get("hub_id") or ""), str(t.get("issue_type") or "")
        if not hub_id or not (typ or typeless):
            continue
        row = c.execute("SELECT kind FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        if (row is None or HUB_ISSUE_TYPE.get(row["kind"]) != typ) and f"{typ}:{hub_id}" not in out:
            out.append(f"{typ}:{hub_id}")
    return out


def sca_identity(c, project_id: int, targets: list[dict]) -> tuple[str, list]:
    """Ключ единственного набора SCA по составу целей: цель с типом связи сопоставляется с находкой того же типа, у
    цели без типа проверяется вид находки (план dev17, остаток шага 4: тот же расчёт во всех фазах принятия)."""
    unmatched = unmatched_targets(c, project_id, targets)
    if unmatched:
        return "", [UNMATCHED_TARGETS.format(ids=", ".join(unmatched[:10]))]
    keys = set()
    for target in targets:
        hub_id = str(target.get("hub_id") or "")
        row = c.execute("SELECT kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings WHERE project_id = ? AND hub_id = ?",
                        (project_id, hub_id)).fetchone()
        if row is None or row["kind"] != "SCA":
            return "", ["Нельзя определить единый набор SCA: находка отсутствует или другого вида."]
        # эффективная тройка (план dev17, п. 4.3) – та же, что у ключей находок (defect_keys_of_findings_in)
        eco, name, version = package_identity.of(package_identity.with_package(dict(row)))
        place = c.execute("SELECT set_no FROM sca_set_members WHERE project_id = ? AND hub_id = ? AND input_ref = ?",
                          (project_id, hub_id, input_ref(eco, name, version))).fetchone()
        if place is not None and place["set_no"] is None:
            return "", ["Находка SCA находится в группе «без дефекта»."]
        number = int(place["set_no"]) if place is not None else 0
        key = defect_key_sca(name, version, eco)
        keys.add(key if not number else f"{key}#{number}")
    if len(keys) != 1:
        return "", ["Цели не определяют единственный набор SCA."]
    return keys.pop(), []


def history(c, owner: dict, event: str, *, row_id=None, op_id=None, details=None) -> None:
    c.execute("INSERT INTO hub_defect_history(defect_id, row_id, revision, event, summary, command_text,"
              " details_json, op_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (owner["id"], row_id or owner["id"], owner["draft_revision"], event, owner["draft_summary"],
               owner["draft_command_text"], dumps(details or {}), op_id, now_iso()))


def migrate(c) -> None:
    """Только новые поля; старые JSON, состояния, операции и последствия не изменяются."""
    rows = [dict(r) for r in c.execute("SELECT * FROM hub_defects ORDER BY id")]
    groups = {}
    for row in rows:
        live = row["state"] not in ("failed", "cancelled", "deleted") and row["hub_defect_id"]
        key = (row["project_id"], row["hub_url"], row["app_id"], row["hub_defect_id"]) if live else (row["id"],)
        groups.setdefault(key, []).append(row)
    for family in groups.values():
        confirmations = []
        for row in family:
            op = c.execute("SELECT id, closed_at FROM hub_ops WHERE id = ?", (row["confirm_op_id"],)).fetchone()
            if op is not None:
                confirmations.append((str(op["closed_at"] or ""), op["id"], row["id"], row))
        owner = max(confirmations, key=lambda x: x[:3])[3] if confirmations else family[0]
        summary, command = owner["summary"], owner["command_text"]
        if owner["state"] in ("import_preview", "import_reading"):
            seen = loads(owner["import_json"], {}) or {}
            summary, command = seen.get("summary", ""), seen.get("command_text", "")
        for row in family:
            c.execute("UPDATE hub_defects SET draft_owner_id = ? WHERE id = ?", (owner["id"], row["id"]))
        key, conflicts = ("", [])
        if owner["kind"] == "SCA":
            targets = [t for row in family for t in loads(row["targets_json"], [])]
            key, conflicts = sca_identity(c, owner["project_id"], targets)
        c.execute("UPDATE hub_defects SET draft_summary = ?, draft_command_text = ?, draft_revision = 1,"
                  " sca_set_key = ?, conflicts_json = ? WHERE id = ?",
                  (summary, command, key, dumps(conflicts), owner["id"]))
        owner.update(draft_summary=summary, draft_command_text=command, draft_revision=1)
        history(c, owner, "migration", details={"full_base_unknown": True, "conflicts": conflicts})


def owner_in(c, row: dict) -> dict:
    owner_id = row.get("draft_owner_id") or row["id"]
    found = c.execute("SELECT * FROM hub_defects WHERE id = ? AND project_id = ?",
                      (owner_id, row["project_id"])).fetchone()
    if found is None:
        raise ValueError("Владелец черновика не найден.")
    return dict(found)


def family_in(c, row: dict) -> list[dict]:
    owner = owner_in(c, row)
    return [dict(r) for r in c.execute(
        "SELECT * FROM hub_defects WHERE project_id = ? AND draft_owner_id = ?"
        " AND state NOT IN ('failed', 'cancelled', 'deleted') ORDER BY id", (row["project_id"], owner["id"]))]


def collapsed(row: dict) -> bool:
    """Строка семьи – история: цели и ключи номера у владельца. `mismatch` остаётся после общей синхронизации, которая
    чистит цели без смены состояния (ADR-0136). То же условие в SQL – Database.HUB_DEFECT_COLLAPSED."""
    return (row["state"] in ("done", "mismatch") and not loads(row.get("targets_json"), [])
            and not loads(row.get("number_keys_json"), []))


def family_single_in(c, row: dict) -> bool:
    """Весь состав дефекта у владельца: остальные строки семьи схлопнуты (ADR-0136)."""
    owner_id = int(owner_in(c, row)["id"])
    return all(int(r["id"]) == owner_id or collapsed(r) for r in family_in(c, row))


def local_edit(owner: dict) -> dict:
    """Есть ли у владельца неотправленная правка относительно принятого: заголовок точно; текст дефекта из приложения по
    строкам (разбор описания Hub отличается от него формой), занесённого точно, как в apply_sync; поля – по основе, не
    строками JSON. Рост редакции сам по себе правкой не считается. {edited, fields_unknown}: основа полей неизвестна –
    сравнить их не с чем."""
    from app import defect_fields
    basis = defect_fields.basis_of(owner)
    if basis["known"]:
        return {"edited": defect_fields.unsent_edit(owner), "fields_unknown": False}
    # основа полей неизвестна: сравнивается то, что можно, поля – по явным правкам
    known = defect_fields.unsent_edit({**owner, "draft_fields_json": "{}", "draft_fields_basis_json": dumps({**basis, "known": True, "base": {}})})
    return {"edited": known or bool(basis.get("pending")), "fields_unknown": True}


def members_in(c, row: dict) -> list[dict]:
    """Канонический снимок физических строк; редакция черновика не подменяет состав."""
    return [{"id": r["id"], "targets": sorted([
        [str(t.get("hub_id") or ""), str(t.get("issue_type") or ""), t.get("revision"), str(t.get("sig") or "")]
        for t in loads(r["targets_json"], [])], key=lambda t: (t[0], t[1])),
        "number_keys": sorted(loads(r["number_keys_json"], [])), "sca_set_key": r["sca_set_key"]}
        for r in family_in(c, row)]


def initialize(c, row: dict, owner_id=None) -> None:
    if owner_id is not None:
        c.execute("UPDATE hub_defects SET draft_owner_id = ? WHERE id = ?", (owner_id, row["id"]))
        return
    key, conflicts = sca_identity(c, row["project_id"], loads(row["targets_json"], [])) if row["kind"] == "SCA" else ("", [])
    c.execute("UPDATE hub_defects SET draft_owner_id = id, draft_summary = summary, draft_command_text = command_text,"
              " draft_revision = 1, sca_set_key = ?, conflicts_json = ? WHERE id = ?",
              (key, dumps(conflicts), row["id"]))
    history(c, owner_in(c, row), "create", details={"conflicts": conflicts})


def edit_problem(c, row: dict) -> str:
    from app import hub_defects
    if row["state"] != "done":
        return "Черновик доступен для правки после создания или занесения дефекта."
    if not family_single_in(c, row):
        return hub_defects.UPDATE_FAMILY_UNMERGED
    if hub_defects.update_unconfirmed(row) or hub_defects.update_busy(row):
        return "Сначала дождитесь или подтвердите результат обновления в Hub."
    if hub_defects.update_state(row).get("phase") == "preview":
        return "Сначала отмените или завершите предпросмотр обновления."
    return hub_defects._update_idle_problem(c, row, local=True)


def save(db: Database, row: dict, revision: str, *, summary="", command="", generate=None,
         operations=None, reference_load=None) -> dict:
    """Проверки, генератор, новый текст и событие одной транзакцией. Ошибка ничего не сохраняет."""
    with db._tx() as c:
        current = owner_in(c, row)
        if str(current["draft_revision"]) != str(revision):
            raise ValueError("Черновик изменился в другой вкладке: обновите страницу.")
        problem = edit_problem(c, current)
        if problem:
            raise ValueError(problem)
        if generate is not None:
            prep = generate(current)
            if prep.get("refusals"):
                raise ValueError("; ".join(prep["refusals"]))
            summary, command = prep["summary"], prep["command_text"]
            if prep.get("tx_check"):
                prep["tx_check"](c)
        from app import defect_fields, defect_references
        fields = loads(current["draft_fields_json"], {})
        basis = defect_fields.basis_of(current)
        fields_raw, basis_raw = current["draft_fields_json"], current["draft_fields_basis_json"]
        if operations is not None and not isinstance(operations, list):
            raise defect_fields.FieldError("changes: требуется массив изменений.")
        if operations:
            choices, reference = defect_references.choices_in(c, current, reference_load)
            proposed = defect_fields.edit(fields, operations, choices)
            delta = defect_fields.diff(fields, proposed)
            if not basis["known"]:
                # Последняя явная команда по пути, включая удаление отсутствующего поля.
                pending = basis.get("pending", [])
                for op in operations:
                    path = op["path"]
                    pending = [x for x in pending if not (x["path"] == path or x["path"].startswith(path + "/"))]
                    pending.append({"path": path, "after_present": op["op"] == "set", "after": op.get("value")})
                basis["pending"] = pending
            changed = set(defect_fields.changed_roots(delta))
            for group in defect_fields.REFERENCE_GROUPS.values():
                if changed.intersection(group):
                    changed.update(group)
            for root in changed:
                if root in ("priority", "structureUnitId", "appStructureUnit", "releaseObject") and reference:
                    basis["references"][root] = reference
            fields = proposed
            fields_raw, basis_raw = dumps(fields), dumps(basis)
        c.execute("UPDATE hub_defects SET draft_summary = ?, draft_command_text = ?, draft_revision = draft_revision + 1,"
                  " draft_fields_json = ?, draft_fields_basis_json = ?, updated_at = ? WHERE id = ?",
                  (summary, command, fields_raw, basis_raw, now_iso(), current["id"]))
        current = owner_in(c, current)
        history(c, current, "edit", details={"from_decisions": generate is not None,
                                             "fields": fields, "basis": basis})
        return current


def clear_dropped(c, project_id: int, pairs) -> None:
    """Связь, прочитанная текущим чтением и принятая, снимает пометку «выбыла из дефекта»: находка снова в дефекте.
    Пара (номер, тип) – только с типом самой находки (связь другого типа – другая находка Hub)."""
    from app.hub_status import HUB_ISSUE_TYPE
    for ident, typ in pairs:
        finding = c.execute("SELECT kind FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, str(ident))).fetchone()
        if finding is not None and HUB_ISSUE_TYPE.get(finding["kind"]) == str(typ or ""):
            c.execute("UPDATE reviews SET defect_dropped = '' WHERE project_id = ? AND hub_id = ?", (project_id, str(ident)))


HUB_DECISION = "hub"  # решение «из Hub»: у SAST «Подтверждаю дефект», у SCA «Обновить» (итог true_positive)
# происхождение такого решения – состав дефекта в Hub, не статус находки: Pull статусов (hub_pull.accept_issue) снимает
# только решения происхождения hub_sync, когда в Hub нет решения по находке; решение по составу дефекта остаётся
HUB_DEFECT_ORIGIN = "hub_defect"


def hub_decisions(c, project_id: int, pairs, source: dict) -> list[str]:
    """Находкам из прочитанного в Hub состава дефекта без решения – решение «из Hub» (SAST –
    «Подтверждаю дефект», SCA – «Обновить»; в базе decision 'hub', final_verdict 'true_positive', происхождение
    hub_defect, без отметки «Проверено»). Решение оператора, отложенное, «Риск принят» и решение из статусов Hub не
    трогаются; находки не из выгрузки и другого вида – тоже. pairs – (номер Hub, тип находки Hub). Возвращает номера
    находок, которым решение поставлено: их редакция решения выросла, цели строки берут её заново."""
    from app.db import review_signature
    from app.hub_status import HUB_ISSUE_TYPE
    given: list[str] = []
    stamp = now_iso()
    for ident, typ in pairs:
        hub_id = str(ident or "")
        f = c.execute("SELECT kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
                      " WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        if f is None or HUB_ISSUE_TYPE.get(f["kind"]) != str(typ):
            continue
        sca = str(f["kind"] or "").startswith("SCA")
        r = c.execute("SELECT decision, final_verdict FROM reviews WHERE project_id = ? AND hub_id = ?",
                      (project_id, hub_id)).fetchone()
        if r is not None and (r["decision"] or (sca and r["final_verdict"])):
            continue  # решение есть (у SCA решением считается и один итог – как в sca.decision_state)
        # у SCA решение сверяется с версией находки по отпечатку (decision_state «changed»): отпечаток – текущий
        # подпись – по эффективной идентичности пакета (план dev17, п. 4.3), как у сохранённого решения
        sig = review_signature(package_identity.with_package(dict(f))) if sca else ""
        c.execute("INSERT INTO reviews(project_id, hub_id, updated_at) VALUES (?, ?, ?)"
                  " ON CONFLICT(project_id, hub_id) DO NOTHING", (project_id, hub_id, stamp))
        c.execute("UPDATE reviews SET decision = ?, final_verdict = 'true_positive', decision_origin = ?,"
                  " decision_source_json = ?, finding_sig = CASE WHEN ? <> '' THEN ? ELSE finding_sig END,"
                  " revision = revision + 1, decided_at = ?, updated_at = ? WHERE project_id = ? AND hub_id = ?",
                  (HUB_DECISION, HUB_DEFECT_ORIGIN, dumps(source), sig, sig, stamp, stamp, project_id, hub_id))
        given.append(hub_id)
    return given


def refresh_revisions(c, project_id: int, targets: list[dict], only=None) -> list[dict]:
    """Цели с текущей редакцией решения находки (после решения «из Hub» редакция выросла); only – номера находок,
    у которых редакция обновляется (None – у всех)."""
    out = []
    for t in targets:
        hub_id = str(t.get("hub_id") or "")
        if only is not None and hub_id not in only:
            out.append(t)
            continue
        r = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        out.append({**t, "revision": int(r["revision"] or 0) if r is not None else int(t.get("revision") or 0)})
    return out


def give_hub_decisions(c, row_id: int, project_id: int, pairs, source: dict) -> list[str]:
    """hub_decisions для строки дефекта: цели строки, получившие решение, берут его редакцию."""
    given = hub_decisions(c, project_id, pairs, source)
    if given:
        current = c.execute("SELECT targets_json FROM hub_defects WHERE id = ?", (row_id,)).fetchone()
        if current is not None:
            targets = refresh_revisions(c, project_id, loads(current["targets_json"], []), only=set(given))
            c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?", (dumps(targets), row_id))
    return given


def accept(c, row: dict, seen: dict, op_id: int) -> None:
    """Первичное занесение: черновик полного чтения, без отметок и номеров находкам; находкам состава без решения –
    решение «из Hub» (hub_decisions)."""
    hub_entity_versions.require_current(c, row, op_id)
    clear_dropped(c, row["project_id"], [(t.get("hub_id"), t.get("issue_type")) for t in loads(row["targets_json"], [])])
    given = give_hub_decisions(c, row["id"], row["project_id"],
                               [(t.get("hub_id"), t.get("issue_type")) for t in loads(row["targets_json"], [])],
                               {"defect": str(row.get("hub_defect_id") or ""), "op_id": op_id, "row_id": row["id"]})
    key, conflicts = sca_identity(c, row["project_id"], loads(row["targets_json"], [])) if row["kind"] == "SCA" else ("", [])
    c.execute("UPDATE hub_defects SET draft_summary = summary, draft_command_text = command_text,"
              " draft_fields_json = ?, confirmed_object_json = ?, sca_set_key = ?, conflicts_json = ? WHERE id = ?",
              (dumps(fields_of(seen.get("object") or {})), dumps(seen["object"]) if seen.get("object") else "",
               key, dumps(conflicts), row["id"]))
    hub_entity_versions.accept(c, row, dumps(seen.get("object")), {"op_id": op_id})
    history(c, owner_in(c, row), "hub_sync", op_id=op_id,
            details={"initial_import": True, "conflicts": conflicts, "hub_decisions": given})
    if seen.get("object"):
        from app.defect_fields import new_basis
        c.execute("UPDATE hub_defects SET draft_fields_basis_json = ? WHERE id = ?",
                  (dumps(new_basis(seen["object"], "accepted", op_id=op_id)), row["id"]))


def apply_sync(c, previous: dict, seen: dict) -> None:
    """Применение прежней одиночной сверки: база и черновик согласуются в транзакции строки.

    Независимые текстовые правки объединяются. Конфликт отклоняет всё применение, сохраняя
    предпросмотр и обе версии; отмена предпросмотра позволяет явно выбрать текст в карточке.
    """
    if seen.get("text_note"):
        raise ValueError("Текст дефекта в Hub не выделен: исправьте описание в Hub и повторите сверку.")
    if not isinstance(seen.get("object"), dict) or not seen["object"]:
        raise ValueError("Полный объект сверки не сохранён: повторите «Pull из Hub».")
    hub_entity_versions.require_current(c, previous, seen.get("op_id"))
    owner = owner_in(c, previous)
    from app.hub_defects import _norm_lines as _lines
    # описание синхронизируется целиком (ADR-0132): блок изменён в Hub, а текст – в неотправленном черновике
    if seen.get("block_changed") and _lines(owner["draft_command_text"]) != _lines(previous["command_text"]):
        raise ValueError("Конфликт сверки: описание изменено с двух сторон – в Hub служебный блок, в приложении текст. Применение "
                         "отменено. Отмените предпросмотр и решите, что оставить: «Push в Hub» отправит ваш текст вместе с блоком из Hub.")
    merged = {}
    from app.hub_defects import _norm_lines
    for field, label in (("summary", "заголовок"), ("command_text", "текст команды")):
        base, local, remote = previous[field], owner[f"draft_{field}"], seen[field]
        if field == "command_text" and previous.get("origin") != "import":
            # у дефекта из приложения текст – исходный текст оператора, а разбор описания Hub отличается от него
            # формой (края строк, пробелы): все три версии сравниваются по строкам с нормализацией (ревью dev34,
            # круги 1 и 3). В Hub текст тот же по строкам – черновик остаётся как есть (принятый текст строки тоже
            # прежний, apply_import_sync); без локальной правки – черновик берёт текст Hub
            b, lo, re_ = _norm_lines(base), _norm_lines(local), _norm_lines(remote)
            if re_ == b or lo == re_:
                merged[field] = local
            elif lo == b:
                merged[field] = remote
            else:
                raise ValueError(f"Конфликт сверки: {label} изменён и локально, и в Hub. "
                                 "Применение отменено. Отмените предпросмотр, выберите текст в карточке и повторите сверку.")
            continue
        if local != base and remote != base and local != remote:
            raise ValueError(f"Конфликт сверки: {label} изменён и локально, и в Hub. "
                             "Применение отменено. Отмените предпросмотр, выберите текст в карточке и повторите сверку.")
        merged[field] = remote if local == base else local
    from app import defect_fields
    basis = defect_fields.basis_of(owner)
    remote = fields_of(seen["object"])
    if not basis["known"] and basis.get("pending"):
        raise ValueError("Сначала явно используйте показанные поля как основу черновика: локальные правки сохранены.")
    fields = dumps(defect_fields.merge(basis["base"], loads(owner["draft_fields_json"], {}), remote)
                   if basis["known"] else remote)
    new_basis = defect_fields.new_basis(seen["object"], "sync", references=basis["references"])
    c.execute("UPDATE hub_defects SET draft_summary = ?, draft_command_text = ?, draft_fields_json = ?,"
              " confirmed_object_json = ?, draft_fields_basis_json = ?, draft_revision = draft_revision + 1 WHERE id = ?",
              (merged["summary"], merged["command_text"], fields, dumps(seen["object"]), dumps(new_basis), owner["id"]))
    hub_entity_versions.accept(c, previous, dumps(seen["object"]), {"op_id": seen.get("op_id")})
    from app.hub_defects import linked_pairs
    clear_dropped(c, previous["project_id"], linked_pairs(seen["object"]))  # прочитанный состав, не сохранённые цели
    # локальная правка осталась поверх принятого: по тексту приложения сравнение – по строкам с нормализацией
    if previous.get("origin") != "import":
        kept_local = (merged["summary"] != seen["summary"]
                      or _norm_lines(merged["command_text"]) != _norm_lines(seen["command_text"]))
    else:
        kept_local = merged != {"summary": seen["summary"], "command_text": seen["command_text"]}
    # сохранённая слиянием правка полей (приоритет, серьёзность, источник…) – тоже неотправленная правка (ревью dev34,
    # круг 4): иначе синхронизация сочтёт её принятой и заменит полями Hub без восстановления
    kept_local = kept_local or loads(fields, {}) != remote
    history(c, owner_in(c, owner), "hub_sync", row_id=previous["id"],
            details={"object": seen["object"], "previous_summary": previous["summary"],
                     "previous_command_text": previous["command_text"], "local_text_preserved": kept_local})
    return kept_local


def mark_kept_local(c, previous: dict) -> None:
    """Локальная правка осталась поверх принятого состояния Hub: следующей редакцией – событие правки после всех
    событий принятия, чтобы синхронизация видела её неотправленной и не перезаписала без восстановления (ревью dev34,
    круги 2–3)."""
    owner = owner_in(c, previous)
    c.execute("UPDATE hub_defects SET draft_revision = draft_revision + 1 WHERE id = ?", (owner["id"],))
    history(c, owner_in(c, owner), "edit", row_id=previous["id"], details={"kept_after_sync": True})


def confirm(c, row: dict, seen: dict, op_id: int, targets: list[dict]) -> None:
    """Подтверждение текста и метаданных целей до любых последствий, на соединении перехода строки."""
    if seen.get("text_note"):
        raise ValueError("Текст команды не выделен: подтверждение недоступно.")
    hub_entity_versions.require_current(c, row, op_id)
    owner = owner_in(c, row)
    from app.defect_fields import new_basis
    basis = dumps(new_basis(seen["object"], "confirmed", op_id=op_id))
    summary = row["summary"] if row["origin"] == "app" else seen["summary"]
    command = row["command_text"] if row["origin"] == "app" else seen["command_text"]
    fields = dumps(fields_of(seen["object"]))
    if row["id"] != owner["id"]:  # привязка не отправляла текст и не заменяет правки владельца
        summary, command = owner["draft_summary"], owner["draft_command_text"]
        fields = owner["draft_fields_json"]
        basis = owner["draft_fields_basis_json"]
    changed = (summary != owner["draft_summary"] or command != owner["draft_command_text"]
               or fields != owner["draft_fields_json"])
    revision = owner["draft_revision"] + int(changed)
    c.execute("UPDATE hub_defects SET draft_summary = ?, draft_command_text = ?, draft_fields_json = ?,"
              " confirmed_object_json = ?, draft_fields_basis_json = ?, draft_revision = ? WHERE id = ?",
              (summary, command, fields, dumps(seen["object"]), basis, revision, owner["id"]))
    content_hash = text_hash(dumps({"summary": seen["summary"], "command_text": seen["command_text"]}))
    # «Внесено в Hub» – только находкам, связь которых с дефектом прочитана в Hub; остальные и прежние отметки вне
    # прочитанного состава – «выбыла из дефекта», решение за оператором
    from app import hub_pull
    from app.hub_defects import linked_pairs
    pairs = {(str(i), t) for i, t in linked_pairs(seen["object"])}
    linked = [t for t in targets if (str(t.get("hub_id")), t.get("issue_type")) in pairs]
    revoked = hub_pull.reconcile_defect_marks(c, owner, owner, pairs)
    dropped = hub_pull.mark_dropped(c, owner, {str(t.get("hub_id")) for t in targets if t not in linked}
                                    | {r["hub_id"] for r in revoked}, "confirm")
    if len(linked) != len(targets):  # номер дефекта – только ключам находок, оставшихся в составе
        narrow_number_keys(c, row, owner, [t["hub_id"] for t in linked],
                           typed_ids(c, row["project_id"], [t for t in targets if t not in linked]))
    targets = linked
    # связь прочитана текущим чтением (require_current выше) – находка в дефекте, пометка снимается
    clear_dropped(c, row["project_id"], [(t["hub_id"], t.get("issue_type")) for t in linked])
    # отметка «Внесено в Hub» – по подтверждённому составу: и цели с пустым отпечатком решения
    # (Push текста как есть при неготовой заготовке набора, 0.9.26.dev15) получают отпечаток содержимого – карточка
    # сверяет текст решения только при непустом decision_hash; цели прежнего формата без поля decision_hash – как раньше
    confirmed_targets = [{**t, "decision_hash": t.get("decision_hash", t.get("entered_hash", "")),
                          "entered_hash": content_hash,
                          "entered_origin": "defect", "entered_defect_id": owner["id"],
                          "entered_op_id": op_id, "entered_defect_revision": revision} for t in targets]
    c.execute("UPDATE hub_defects SET targets_json = ?, confirmed_object_json = ? WHERE id = ?",
              (dumps(confirmed_targets), dumps(seen["object"]), row["id"]))
    hub_entity_versions.accept(c, row, dumps(seen["object"]), {"op_id": op_id})
    history(c, owner_in(c, owner), "hub_confirm", row_id=row["id"], op_id=op_id,
            details={"object": seen["object"], "members_snapshot": members_in(c, row),
                     "revoked_confirmations": revoked, "dropped": dropped})
    # привязка не отправляла текст, а основа записана заново: правка владельца – событием после принятия, иначе
    # синхронизация сочла бы её принятой и заменила (ADR-0136)
    if row["id"] != owner["id"] and local_edit(owner)["edited"]:
        mark_kept_local(c, owner)


def narrow_number_keys(c, row: dict, owner: dict, hub_ids, gone_ids=()) -> None:
    """Ключи номера строки – только находок hub_ids; номер этого дефекта снимается только с ключей выбывших находок
    gone_ids (с их нынешним набором SCA) – прежний ключ записи, за которым теперь другие находки (перенос между
    наборами), не задевается (ревью 31.10); кроме ключей других записей done."""
    keys = loads(row.get("number_keys_json"), [])
    kept = set(Database.defect_keys_of_findings_in(c, row["project_id"], list(hub_ids)))
    gone = set(Database.defect_keys_of_findings_in(c, row["project_id"], in_some_set(c, row["project_id"], gone_ids)))
    others = {k for r in c.execute("SELECT number_keys_json FROM hub_defects WHERE project_id = ? AND draft_owner_id <> ?"
                                   " AND state = 'done'", (row["project_id"], owner["id"]))
              for k in loads(r["number_keys_json"], [])}
    # снимается только номер этого дефекта: ключу могли потом выдать другой номер вручную (ревью 31.10); перенумерацию
    # в Hub ключи записи догоняют при «Применить» (renumber_keys)
    for key in (set(keys) & gone) - kept - others:
        c.execute("DELETE FROM defects WHERE project_id = ? AND defect_key = ? AND number = ?",
                  (row["project_id"], key, row.get("number")))
    c.execute("UPDATE hub_defects SET number_keys_json = ? WHERE id = ?", (dumps([k for k in keys if k in kept]), row["id"]))


def renumber_keys(c, row: dict, old: Any, new: Any, targets) -> None:
    """Hub перенумеровал дефект (ID<old> → ID<new>): ключи номера записи текущего состава (находки целей с их типом и
    нынешним набором SCA), у которых номер этого дефекта, получают новый номер; ключ прежнего набора и ключи с другим
    номером (выданным вручную) не трогаются."""
    ints = all(isinstance(n, int) and not isinstance(n, bool) and n > 0 for n in (old, new))
    if not ints or old == new:
        return
    stamp = now_iso()
    current = set(Database.defect_keys_of_findings_in(c, row["project_id"], typed_ids(c, row["project_id"], targets)))
    for key in [k for k in loads(row.get("number_keys_json"), []) if k in current]:
        c.execute("UPDATE defects SET number = ?, updated_at = ?, assigned_at = ? WHERE project_id = ? AND defect_key = ?"
                  " AND number = ?", (new, stamp, stamp, row["project_id"], key, old))


def in_some_set(c, project_id: int, hub_ids) -> list[str]:
    """hub_id без находок SCA, явно отнесённых оператором к «без дефекта» (set_no NULL): их ключ – набор по умолчанию,
    за которым могут быть другие находки, – номер с него автоматически не снимается (ревью 31.10). Пометка учитывается
    только для текущих компонента, версии и экосистемы находки – как в вычислении ключа набора
    (`defect_keys_of_findings_in`): пометка прежней версии после новой выгрузки не действует (ревью круг 7)."""
    kept = []
    for h in hub_ids:
        finding = c.execute("SELECT kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings WHERE project_id = ? AND hub_id = ?",
                            (project_id, str(h))).fetchone()
        ref = None
        if finding is not None and finding["kind"] == "SCA":
            ref = input_ref(*package_identity.of(package_identity.with_package(dict(finding))))  # план dev17, п. 4.3
        if ref is None or c.execute(
                "SELECT 1 FROM sca_set_members WHERE project_id = ? AND hub_id = ? AND input_ref = ? AND set_no IS NULL",
                (project_id, str(h), ref)).fetchone() is None:
            kept.append(str(h))
    return kept


def typed_ids(c, project_id: int, targets) -> list[str]:
    """hub_id целей, тип связи которых совпадает с видом самой находки."""
    from app.hub_status import HUB_ISSUE_TYPE
    targets = list(targets)
    wanted = sorted({str(t.get("hub_id") or "") for t in targets})
    kinds: dict[str, str] = {}
    # один запрос на все цели, а не на каждую (бэклог 123: страница дефектов – тысячи обращений к базе)
    for start in range(0, len(wanted), 500):
        part = wanted[start:start + 500]
        rows = c.execute(f"SELECT hub_id, kind FROM findings WHERE project_id = ? AND hub_id IN ({','.join('?' * len(part))})",
                         (project_id, *part)).fetchall()
        kinds.update({str(r["hub_id"]): str(r["kind"]) for r in rows})
    ids = []
    for t in targets:
        kind = kinds.get(str(t.get("hub_id") or ""))
        if kind is not None and HUB_ISSUE_TYPE.get(kind) == str(t.get("issue_type") or ""):
            ids.append(str(t["hub_id"]))
    return ids


def drop_removed(c, row: dict, hub_pairs, removed, targets) -> None:
    """«Применить» одиночной сверки: цели, которых в Hub больше нет, ушли из состава строки – их отметки по
    этому дефекту снимаются, им ставится пометка «выбыла из дефекта» (пара с типом самой находки), номер – только
    ключам оставшихся; набор SCA и конфликт состава пересчитываются по новому составу. row – строка до применения:
    прежний номер и ключи номера."""
    from app import hub_pull
    owner = owner_in(c, row)
    revoked = hub_pull.reconcile_defect_marks(c, owner, owner, hub_pairs)
    gone = hub_pull.dropped_ids(c, row["project_id"], set(removed), set(hub_pairs))
    dropped = hub_pull.mark_dropped(c, owner, gone | {r["hub_id"] for r in revoked}, "sync")
    if removed:
        # сохраняются ключи только пар с типом самой находки: связь SCA_S:X не держит ключ локальной SAST-находки X
        typed = typed_ids(c, row["project_id"], targets)
        narrow_number_keys(c, row, owner, typed, gone)
        # номер этого дефекта у находок, которые Hub сейчас из него убрал, – даже если он не записан в number_keys
        from app.hub_defects import release_number_in
        own = Database.defect_keys_of_findings_in(c, row["project_id"], typed)
        release_number_in(c, row, row.get("number"),
                          Database.defect_keys_of_findings_in(c, row["project_id"], in_some_set(c, row["project_id"], gone)), own)
    if row["kind"] == "SCA":
        key, conflicts = sca_identity(c, row["project_id"], targets)
        c.execute("UPDATE hub_defects SET sca_set_key = ?, conflicts_json = ? WHERE id = ?", (key, dumps(conflicts), row["id"]))
    if removed or revoked:
        history(c, owner_in(c, owner), "hub_sync", row_id=row["id"],
                details={"removed": sorted(removed), "revoked_confirmations": revoked, "dropped": dropped})


def use_basis(db, row, revision, source, shown):
    """Локальное принятие показанного наблюдения в основу; подтверждённая версия не меняется."""
    from app import defect_fields, defect_references, hub_defects
    with db._tx() as c:
        current = owner_in(c, row)
        if str(current["draft_revision"]) != str(revision):
            raise ValueError("Черновик изменился: обновите страницу.")
        problem = edit_problem(c, {**current, "sync_json": ""})
        if problem or hub_defects.update_busy(current):
            raise ValueError(problem or "Дождитесь результата операции.")
        basis = defect_fields.basis_of(current)
        if basis["known"]:
            raise ValueError("Основа уже определена: обновите страницу.")
        seen = (loads(current["sync_json"], {}).get("read", {}) if source == "sync"
                else loads(current["import_json"], {}) if source == "observation" else {})
        if not seen.get("object") or defect_references.signature(seen) != shown:
            raise ValueError("Показанное наблюдение изменилось: обновите страницу.")
        obj = seen["object"]
        if str(obj.get("id")) != str(current["hub_defect_id"]) or obj.get("appId") != current["app_id"]:
            raise ValueError("Наблюдение относится к другому дефекту или приложению.")
        new = defect_fields.new_basis(obj, "observation", source=source, observation_signature=shown,
                                     read_at=seen.get("read_at"), references=basis["references"])
        fields = defect_fields.apply_changes(new["base"], basis.get("pending", []))
        c.execute("UPDATE hub_defects SET draft_fields_json = ?, draft_fields_basis_json = ?,"
                  " draft_revision = draft_revision + 1, updated_at = ? WHERE id = ?",
                  (dumps(fields), dumps(new), now_iso(), current["id"]))
        fresh = owner_in(c, current)
        history(c, fresh, "edit", details={"basis_initialized": new, "fields": fields})
        return fresh


def current_effect(c, row: dict, target: dict | None = None) -> bool:
    """Позднее последствие не восстанавливает удалённую цель или прежнее поколение."""
    current = c.execute("SELECT * FROM hub_defects WHERE id = ?", (row["id"],)).fetchone()
    if current is None or current["state"] != "done" or current["confirm_op_id"] != row.get("confirm_op_id"):
        return False
    if current["draft_owner_id"] != row.get("draft_owner_id"):
        return False
    keys = ("hub_id", "issue_type", "revision", "sig", "decision_hash", "entered_hash", "entered_origin",
            "entered_defect_id", "entered_op_id", "entered_defect_revision")
    live = loads(current["targets_json"], [])
    wanted = [target] if target is not None else loads(row["targets_json"], [])
    return all(any(all(t.get(k) == candidate.get(k) for k in keys) for candidate in live) for t in wanted)
