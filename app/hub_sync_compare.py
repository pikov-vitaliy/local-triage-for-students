"""Сравнение сохранённых свидетельств без изменения решений, черновиков и состава."""

from app import hub_entity_versions as versions, hub_sync_api as api
from app.db import dumps, loads, finding_data_sig, text_hash, hub_verdict
from app.defect_drafts import fields_of
from app.hub_defects import UPDATE_SETTLED, linked_pairs, split_description
from app.hub_ops import NOT_SENT, normalize_text
from app.hub_status import HUB_ISSUE_TYPE, _day as expiry_day

LABELS = {
    "new": "Новые в Hub", "changed": "Изменены в Hub", "absent": "Отсутствуют или удалены в Hub",
    "pending": "Ждёт отправки в Hub", "conflict": "Изменены и в приложении, и в Hub после принятой базы",
    "sent_unaccepted": "Отправлено в Hub, ждёт принятия состояния Hub",
    "composition": "Изменения состава", "no_decision": "Статус Hub изменён, локального решения нет",
    "stale": "Устаревшие наблюдения", "unmapped": "Несопоставленные объекты",
    "incomplete": "Неполные или несогласованные сведения", "unknown_base": "Базовая версия неизвестна",
    "decision_diff": "Расхождения основания или срока", "matched": "Совпадают",
    "local_only": "Решение оператора отличается от Hub; отправки не ждёт",
    "coincident": "Совпавшие изменения относительно базы",
    "fixed_external": "Исправлены в Hub, в приложении нет",
    "observed": "Изменены прочие сведения Hub",
    "unsendable": "Не отправляется: в Hub находка исправлена (Fixed)",
}


# порядок основной группы объекта (страница синхронизации и отметки страниц, dev15): неизвестная группа – ошибка,
# а не «неполные сведения» (тест на каждую группу LABELS)
GROUP_ORDER = ("stale", "incomplete", "unmapped", "pending", "sent_unaccepted", "unsendable", "local_only", "conflict",
               "composition", "unknown_base", "decision_diff", "no_decision", "absent", "changed", "coincident",
               "new", "fixed_external", "observed", "matched")


def primary_group(groups) -> str:
    return next((name for name in GROUP_ORDER if name in groups), "incomplete")


# версия расчёта сравнения: страницы берут сохранённое сравнение прогона, только если его посчитал этот же расчёт
# (ревью кода dev15, круг 1 – сравнение, сохранённое dev14, иначе показывалось бы по старым правилам). Увеличивать при
# каждом изменении расчёта групп, причин или сведений отправки (ревью кода dev15, круг 4)
COMPARE_VERSION = 23
# объект появился в приложении после составления списка чтения (compare_in и страницы – одна причина)
LOCAL_AFTER_READ = "Локальный объект появился после составления списка чтения. Нужен новый обход."


def instant_ms(value):
    """Момент срока Hub (миллисекунды или ISO) в миллисекундах; непонятное значение – None."""
    from datetime import datetime
    try:
        if type(value) is int:
            return value
        if isinstance(value, str) and value:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except (ValueError, OverflowError, OSError):
        return None
    return None


DECISION_STATUSES = ("False Positive", "Accepted risk")
HUB_REFUSED = "Hub не принял"  # начало заметки «Push в Hub», когда Hub отказал на отправленный PUT (hub_defects)

# отправка – отдельное измерение состояния (dev15, план п. 2.1–2.2)
DELIVERY_LABELS = {
    "unsendable": "В Hub исправлена – отправить нельзя",
    "queued": "Отправка ждёт исполнителя",
    "unconfirmed": "Отправка не подтверждена",
    "refused": "Hub не принял",
    "unsent": "Не отправлено в Hub",
    "sent": "Отправлено в Hub",
}


def delivery_of(kind, key, local, diff, context, sources=None, observed=True) -> dict:
    """Сведения отправки объекта (dev15, план п. 2.1: видеть, что отправлено, что не
    отправлено и принял ли это Hub): ждёт ли текущее решение отправки, сохранённые правки, операция
    текущей редакции и её исход. Считается до подмены устаревшего наблюдения и им не стирается. Без наблюдения (Hub не
    читался, объекта нет в прочитанном) о Hub ничего не утверждается – только само решение и операции. Доставленное
    решение – «отправлено» и тогда, когда Hub показывает другое (Hub ответил «принято» –
    процесс закончен); отличие от Hub показывается рядом своей группой."""
    groups = set(diff.get("groups") or [])
    delivered = set(diff.get("delivered_pending_ids") or [])
    stored = [i for i in diff.get("pending_ids") or [] if i not in delivered]
    current = bool(diff.get("current_pending"))
    out = {"state": None, "stored": len(stored), "date": "", "error": "", "op_id": None}
    if kind == "defect":
        # этап «Push в Hub» (update_json): идёт запись или подтверждение, исход неизвестен, Hub отказал (ревью кода
        # dev15, круг 1 – неизвестный исход не «не отправлено»: запись могла состояться)
        owner = local.get("owner") or {}
        update = loads(owner.get("update_json"), {}) if owner else {}
        update = update if isinstance(update, dict) else {}
        phase = str(update.get("phase") or "")
        if owner.get("update_op_id"):
            state = "queued"  # операция шага Push в очереди или у исполнителя
        elif phase == "unknown":
            state, out["action"] = "unconfirmed", "verify"  # исход PUT неизвестен – «Сверить»
        elif phase in ("putting", "confirming", "unconfirmed"):
            # PUT мог состояться, подтверждающее чтение не завершилось – «Повторить чтение» (карточка даёт её при
            # confirming и unconfirmed); без операции это не «выполняется» (ревью кода dev15, круг 3)
            state, out["action"] = "unconfirmed", ("reread" if phase != "putting" else "")
            out["error"] = str(update.get("note") or "")
        elif phase in ("observed_old", "unclear") and (current or stored):
            # сверка прочитала Hub, правки в нём сейчас нет: прежний текст – отправить снова («Push в Hub»), третий
            # вариант – сначала посмотреть версию Hub («Pull из Hub»); обе кнопки карточка в этих фазах даёт
            # (ревью кода dev15, круг 4)
            state, out["action"] = "unsent", ("push" if phase == "observed_old" else "pull")
            out["error"] = str(update.get("note") or "")
        elif (current or stored) and phase == "failed" and str(update.get("note") or "").startswith(HUB_REFUSED):
            state, out["error"] = "refused", str(update.get("note") or "")
        elif current or stored:
            # ошибка подготовки (чтение перед PUT, проверка кандидата, запрос не ушёл) – запись в Hub не уходила
            state = "unsent"
            if phase in ("failed", "refused", "read_failed"):
                out["error"] = str(update.get("note") or "")
        else:
            state = "sent" if "sent_unaccepted" in groups else None
        return {**out, "state": state}
    review = local.get("review") or {}
    intent = local.get("status_intent") or {}
    op_state = intent.get("state")
    out["op_id"] = intent.get("op_id")
    equal = set(groups) <= {"matched", "coincident"}
    mine = True
    if not observed:
        values = issue_local_values(local)
        mine = review.get("decision_origin") != "hub_sync" and values.get("status") in DECISION_STATUSES
        current = mine and op_state != "done"
    if "unsendable" in groups:
        state = "unsendable"
    elif op_state in ("queued", "taken"):
        state = "queued"
    elif op_state == "unknown":
        # исход отправки неизвестен – «не подтверждена», пока операция не закрыта, и тогда, когда прочитанное совпадает
        # с Hub: принятие ждёт её результата (ревью кода dev15, круг 9)
        state = "unconfirmed"
    elif op_state == "failed" and current:
        last = (context.last_status.get(key) if context else None) or {}
        out["error"] = (last.get("error") or "") if last.get("id") == intent.get("op_id") else ""
        # исполнитель запрос не отправлял (Hub недоступен, белый список) – это «не отправлено», а не отказ Hub
        state = "unsent" if out["error"].startswith(NOT_SENT) else "refused"
    elif stored:
        # сохранённые правки, которые доставка текущего решения не закрыла, – не отправлены (ревью кода dev15, круги 7–8)
        state = "unsent"
    elif current:
        state = "unsent"
    elif op_state == "done" and mine and (not observed or not equal):
        # доставлено, а Hub его сейчас не показывает – «отправлено»; отличие – своей группой рядом
        state = "sent"
    elif "sent_unaccepted" in groups:
        state = "sent"
    else:
        state = None
    if state == "unsent":
        out["date"] = ((review.get("decided_at") or review.get("updated_at") or "") if current
                       else min(diff.get("stored_dates") or [""]))
    return {**out, "state": state}


# пометки Hub – сведения прочитаны, но расходятся между собой; не отличие и не причина пропуска (dev15, план п. 1.2)
HUB_CONTRADICTIONS = api.HUB_NOTES


def _when(value) -> str:
    text = str(value or "")
    return text[:16].replace("T", " ") + " UTC" if len(text) >= 16 else text


PLACE_FIELDS = ("fileName", "filePath", "lineNumber", "line", "column", "startLine", "endLine", "location")
TEXT_FIELDS = ("description", "recommendation", "category", "cwes", "eduLink", "vulnerability", "title", "name",
               "message", "library", "language", "tool", "severity", "severityDisplayName")


def _branch_changes(before, after) -> list[str]:
    """Что изменилось в сведениях веток: появилась, исчезла, другой статус или поля."""
    def index(value):
        return {str(b.get("branch")): b for b in value or [] if isinstance(b, dict)}
    old, new = index(before), index(after)
    out = []
    for name in sorted(set(old) | set(new)):
        b, h = old.get(name), new.get(name)
        if b == h:
            continue
        if b is None:
            out.append(f"{name}: появилась")
        elif h is None:
            out.append(f"{name}: исчезла")
        elif b.get("status") != h.get("status"):
            out.append(f"{name}: статус был {b.get('status') or '–'}, стал {h.get('status') or '–'}")
        else:
            out.append(f"{name}: поля " + ", ".join(sorted(k for k in set(b) | set(h) if b.get(k) != h.get(k))))
    return out or ["состав сведений"]


def observed_causes(diff) -> list[str]:
    """Причина у справочного отличия Hub (dev15, план п. 3; бэклог 90): что именно Hub изменил – текст справки,
    сведения веток, место или прочее. «Статус и решение не менялись» – только если проекция решения у базы и Hub
    одинакова."""
    texts, place, other, branches = [], [], [], []
    for f in diff.get("fields", []):
        if f.get("kind") != "observed":
            continue
        name = f["field"].split("/", 1)[-1].split("/")[0]
        before, after = f["B"]["value"], f["H"]["value"]
        if name == "issueBranchBriefData":
            branches.extend(_branch_changes(before, after))
        elif name == "currentBranch":
            branches.append(f"текущая ветка была {before or '–'}, стала {after or '–'}")
        elif name in PLACE_FIELDS:
            place.append(f"{name} было {before if before not in (None, '') else '–'}, стало {after if after not in (None, '') else '–'}")
        elif name in TEXT_FIELDS or isinstance(before, str) or isinstance(after, str):
            texts.append(name)
        else:
            other.append(name)
    same = "; статус и решение не менялись" if diff.get("decision_same") else ""
    out = []
    if texts:
        out.append(f"Hub изменил справочный текст находки (поля {', '.join(sorted(set(texts)))}){same}.")
    if branches:
        out.append("Hub изменил сведения веток: " + "; ".join(branches) + ".")
    if place:
        out.append("Hub изменил место находки: " + "; ".join(place) + ".")
    if other:
        out.append(f"Hub изменил сведения находки: поля {', '.join(sorted(set(other)))}.")
    return out


def causes(kind, key, local, diff, context) -> list[str]:
    """Причины отличия простыми словами (базы должны совпадать – каждое отличие объяснено):
    правка без отправки и её дата, неудачная отправка с ответом Hub, Fixed в Hub, противоречие на стороне Hub."""
    out, groups = [], set(diff.get("groups", []))
    # «не отправлено» – только при доказанном исходящем намерении (группа pending остаётся лишь при нём) или при
    # правке, сохранённой отдельно; конфликт без намерения – обе стороны изменились после принятой базы (ревью dev14)
    unsent = bool(groups & {"pending", "sent_unaccepted"}) or bool(diff.get("pending_ids"))
    current = diff.get("current_pending", "pending" in groups and not diff.get("pending_ids"))
    stored = [i for i in diff.get("pending_ids", []) if i not in set(diff.get("delivered_pending_ids", []))]
    if kind == "issue":
        if "unsendable" in groups:
            out.append("В Hub находка исправлена (Fixed): решение приложения туда не уйдёт – Hub не меняет статус "
                       "исправленной находки.")
        elif unsent:
            # текущее решение и сохранённые отдельно правки – разные причины, у каждой своя дата (ревью Kimi dev14, к. 2)
            if current:
                review = local.get("review") or {}
                # дата изменения самого решения, а не отметок «Проверено» и «Внесено в Hub» (ревью Kimi dev14, круг 4)
                when = _when(review.get("decided_at") or review.get("updated_at"))
                unknown = (local.get("status_intent") or {}).get("state") == "unknown"
                # исход отправки этой редакции неизвестен – запись могла состояться: не «не отправлена» (Codex, к. 11)
                out.append("Правка решения в приложении" + (f" от {when}" if when else "")
                           + (": доставка в Hub не подтверждена." if unknown else " в Hub не отправлена."))
            if stored:
                dates = [_when(d) for d in diff.get("stored_dates", []) if d]
                if len(stored) == 1:
                    out.append("Правка решения, сохранённая отдельно при синхронизации" + (f" {dates[0]}" if dates else "")
                               + ", в Hub не отправлена: откройте её, чтобы восстановить или отбросить.")
                else:
                    out.append(f"Правки решения, сохранённые отдельно при синхронизации ({len(stored)}"
                               + (f": {', '.join(dates)}" if dates else "") + "), в Hub не отправлены: откройте их, "
                               "чтобы восстановить или отбросить.")
            if diff.get("pending_ids") and not stored:
                # тело доставленной операции совпадает с каждой сохранённой правкой (hub_pull.delivered_pending_ids):
                # они закроются сверкой после принятия
                out.append("Сохранённая правка уже отправлена в Hub; если принятое состояние Hub её содержит, она закроется "
                           "после «Принять состояние Hub».")
        # изменение Hub объясняется и рядом с сохранённой правкой: текущее решение не ждёт отправки, а Hub после
        # принятой базы изменился – причина не скрывается сообщением о доставке (ревью Kimi dev14, круг 9)
        if "unsendable" not in groups and not current:
            if "conflict" in groups:
                # «текущее решение», а не «правки нет»: рядом может стоять неотправленная сохранённая правка (Kimi, к. 10)
                out.append("Решение изменилось и в приложении, и в Hub после принятой базы; текущее решение отправки не "
                           "ждёт – сравните поля и примите состояние Hub.")
            elif "changed" in groups:
                out.append("Hub изменил находку сам (например, «Fixed» после пересканирования или «Open» при создании "
                           "дефекта): примите состояние Hub.")
        # неизвестный исход называется и у совпавшей с Hub находки: сведения отправки – «не подтверждена» (круг 9)
        unconfirmed = (diff.get("delivery") or {}).get("state") == "unconfirmed"
        last = context.last_status.get(key) if context and ("unsendable" in groups or unsent or unconfirmed) else None
        if last and last["state"] == "failed":  # и у Fixed: ответ Hub не теряется (ревью Kimi dev14)
            out.append(f"Последняя отправка статуса (операция {last['id']}, {_when(last['created_at'])}) не прошла: "
                       f"{last['error'] or 'ошибка'}.")
        elif last and last["state"] == "unknown":
            out.append(f"Исход последней отправки статуса (операция {last['id']}, {_when(last['created_at'])}) "
                       "неизвестен: нажмите «Pull из Hub» в карточке находки – приложение прочитает статус в Hub.")
        if "observed" in groups:
            out.extend(observed_causes(diff))
        for note in diff.get("hub_notes", []):
            # пометка, а не отличие: находка принимается по статусу Hub (dev15, план п. 1.2)
            out.append("В Hub: " + note[0].lower() + note[1:] + " Находка принимается по статусу Hub.")
    elif unsent:
        dstate = (diff.get("delivery") or {}).get("state")
        error = (diff.get("delivery") or {}).get("error") or ""
        action = (diff.get("delivery") or {}).get("action")
        if dstate == "unconfirmed" and action == "reread":
            out.append("«Push в Hub» отправлен, но подтверждающее чтение не завершилось"
                       + (f" ({error})" if error else "") + " – нажмите «Повторить чтение» на карточке дефекта.")
        elif dstate == "unconfirmed" and action == "verify":
            out.append("Исход «Push в Hub» неизвестен: запись могла состояться – нажмите «Сверить» на карточке дефекта, "
                       "прежде чем отправлять снова.")
        elif dstate == "unconfirmed":
            out.append("Исход «Push в Hub» не установлен: запись могла состояться.")
        elif dstate == "unsent" and action == "push":
            out.append(f"Сверка после «Push в Hub»: {error or 'в Hub прежний текст'}. Правки в Hub сейчас нет – отправьте "
                       "её снова («Push в Hub» на карточке дефекта).")
        elif dstate == "unsent" and action == "pull":
            out.append(f"Сверка после «Push в Hub»: {error or 'в Hub другое содержимое'}. Посмотрите версию Hub («Pull из "
                       "Hub» на карточке дефекта) и при необходимости отправьте правку снова.")
        elif dstate == "queued":
            out.append("«Push в Hub» выполняется: дождитесь его итога.")
        elif dstate == "refused":
            out.append(f"Hub не принял правку дефекта: {error.removeprefix(HUB_REFUSED).lstrip(': ') or 'отказ'}.")
        else:
            out.append("Правка дефекта в приложении в Hub не отправлена («Push в Hub» на карточке дефекта)"
                       + (f": {error}" if error else "") + ".")
    elif "conflict" in groups:
        out.append("Дефект изменился и в приложении, и в Hub после принятой базы; правки, ждущей отправки, нет – "
                   "сравните поля и примите состояние Hub.")
    elif "changed" in groups:
        out.append("Дефект изменён в Hub: примите состояние Hub.")
    return out


def three_way(base, local, remote, path=""):
    """Сравнение по полям с различением отсутствующего свойства и null."""
    missing = object()
    changes = []
    for name in sorted(set(base) | set(local) | set(remote)):
        b, l, h = (obj.get(name, missing) for obj in (base, local, remote))
        if l == h == b:
            continue
        if (name == "settings" or path) and all(isinstance(v, dict) for v in (b, l, h)):
            changes.extend(three_way(b, l, h, path + name + "/"))
            continue
        kind = "changed" if l == b else "pending" if h == b else "coincident" if l == h else "conflict"
        changes.append({"field": path + name, "kind": kind,
                        "B": {"present": b is not missing, "value": None if b is missing else b},
                        "L": {"present": l is not missing, "value": None if l is missing else l},
                        "H": {"present": h is not missing, "value": None if h is missing else h}})
    return changes


def defect_values(obj):
    text, block, note = split_description(obj.get("description"))
    # отсутствующий, null и пустой заголовок – одно значение, как в черновике после принятия (`_read_of` даёт "")
    return {**fields_of(obj), "summary": obj.get("summary") or "", "command_text": normalize_text(text),
            "hub_block": normalize_text("\n".join(block)),
            **({"hub_description": normalize_text(obj.get("description"))} if note else {}),
            **({"status": obj["status"]} if "status" in obj else {})}, note


def without_base(local, remote):
    """Совпадение L/H не устанавливает происхождение различий и не принимает базу."""
    return [{**field, "kind": "unknown_base"} for field in three_way({}, local, remote)
            if field["L"] != field["H"]]


def defect_comparison(base, local, remote):
    """Справочные пары атомарны; settings сравнивается по вложенным путям."""
    from app.defect_fields import GROUPS
    objects = [dict(obj) for obj in (base, local, remote)]
    for group in GROUPS:
        if not any(group[1] in obj for obj in objects):
            continue
        for obj in objects:
            values = {k: obj.pop(k) for k in group if k in obj}
            if values:
                obj[" + ".join(group)] = values
    return three_way(*objects) if base else without_base(*objects[1:])


def compare_defect(c, row, item, hub, context=None):
    context = context or ComparisonContext(c, row)
    local = context.defect_local(item["entity_key"])
    if item["entity_key"].startswith("local:"):
        return {}, local, {"groups": ["pending"], "notes": ["Дефект ещё не подтверждён в Hub."], "fields": []}
    notes = api.composition_problems(hub.get("detail"))
    owner = local.get("owner")
    if not owner:
        return {}, {}, {"groups": ["new"] + (["incomplete"] if notes else []), "notes": notes, "fields": []}
    base = loads(owner["confirmed_object_json"], {})
    b, bnote = defect_values(base) if base else ({}, "")
    h, hnote = defect_values(hub.get("detail") or {})
    l = {**loads(owner["draft_fields_json"], {}), "summary": owner["draft_summary"],
         "command_text": normalize_text(owner["draft_command_text"]),
         "hub_block": b.get("hub_block", h.get("hub_block")),
         **({"hub_description": b.get("hub_description", h.get("hub_description"))}
            if "hub_description" in b or "hub_description" in h else {}),
         **({"status": base["status"]} if "status" in base else {})}
    if not base:
        # Статус дефекта не редактируется локально; без B его локального значения нет.
        h.pop("status", None)
    fields = defect_comparison(b, l, h)
    for field in fields:
        if field["field"] in ("hub_block", "hub_description"):
            field["readonly"] = True
    groups = sorted({f["kind"] for f in fields if f["kind"] != "matched"})
    from app.hub_pull import pending_change
    dirty, _ = pending_change("defect", local, base, hub)
    if dirty:
        groups.append("pending")
    else:
        groups = [g for g in groups if g != "pending"]
        groups = ["changed" if g == "conflict" and base else "unknown_base" if g == "conflict" else g for g in groups]
        # поле без исходящего намерения – не скрытое совпадение, а свой вид (dev15, план п. 1.5)
        fields = [{**f, "kind": "local_only"} if f["kind"] == "pending" else f for f in fields]
        if any(f["kind"] == "local_only" for f in fields):
            groups.append("local_only")
    notes += api.composition_problems(base) if base else []
    if notes:
        groups.append("incomplete")
    notes += [n for n in (bnote, hnote) if n]
    local_links = {(int(t[0]), t[1]) for m in local["members"] for t in m["targets"] if t[0].isdigit()}
    remote_links = linked_pairs(hub.get("detail") or {})
    base_links = linked_pairs(base) if base else set()
    composition = {"base": sorted(base_links), "local": sorted(local_links), "hub": sorted(remote_links),
                   "local_only": sorted(local_links - remote_links), "hub_only": sorted(remote_links - local_links),
                   "unmapped": sorted((i, t) for i, t in remote_links
                                      if HUB_ISSUE_TYPE.get(context.findings.get(str(i), {}).get("kind")) != t)}
    if local_links != remote_links or (base and base_links != remote_links):
        groups.append("composition")
        notes.append("Состав (тип:ID): только локально " + ", ".join(f"{t}:{i}" for i, t in composition["local_only"])
                     + "; только в Hub " + ", ".join(f"{t}:{i}" for i, t in composition["hub_only"]) + ".")
        if base and base_links != remote_links:
            notes.append("Относительно принятой базы: добавлены " + (", ".join(f"{t}:{i}" for i, t in sorted(remote_links - base_links)) or "нет")
                         + "; отсутствуют " + (", ".join(f"{t}:{i}" for i, t in sorted(base_links - remote_links)) or "нет") + ".")
        if not base:
            groups.append("unknown_base")
    hub_notes = []
    if composition["unmapped"]:
        text = "Состав Hub не сопоставлен с выгрузкой: " + ", ".join(f"{t}:{i}" for i, t in composition["unmapped"]) + "."
        if base and base_links == remote_links:
            # состав принят как есть (accept_defect хранит все пары): несопоставленная связь – пометка, не остаток
            # синхронизации (dev15, план п. 1.3)
            hub_notes.append(text)
        else:
            groups.append("unmapped")
            notes.append(text)
    if loads(owner["conflicts_json"], []) and ("defect", item["entity_key"]) not in context.applications:
        groups.append("conflict")
    for member in local["family"]:
        phase = loads(member.get("update_json"), {}).get("phase")
        if (member["state"] != "done" or member.get("update_op_id") or member.get("sync_op_id")
                or member.get("verify_op_id") or phase not in UPDATE_SETTLED):
            groups.append("incomplete")
            notes.append("В семье дефекта есть незавершённая операция или неподтверждённая запись.")
            break
    return base, local, {"groups": groups or ["matched"], "notes": notes, "hub_notes": hub_notes, "fields": fields,
                         "composition": composition, "base_pending": not base and not groups}


def intent_index(c, row, last=None):
    """Один раз разбираем операции и их цели, от новых к старым. last – словарь «ТИП:номер» -> последняя операция
    статуса (для причин отличий, dev14): заполняется в том же проходе, цели каждой операции разбираются один раз."""
    index = {}
    for op in c.execute("SELECT id,state,error,created_at,request_json,targets_json FROM hub_ops WHERE project_id=?"
                        " AND hub_url=? AND app_id=? AND purpose='status' AND state!='cancelled' ORDER BY id DESC",
                        (row["project_id"], row["hub_url"], row["app_id"])):
        targets = None
        if last is not None:
            targets = loads(op["targets_json"], [])
            for target in targets:
                last.setdefault(f"{target.get('issue_type')}:{target.get('issue_id')}",
                                {k: op[k] for k in ("id", "state", "error", "created_at")})
        request = loads(op["request_json"], {})
        body, state, then = request.get("body") or {}, op["state"], request.get("then")
        if isinstance(then, dict) and then.get("status") and then.get("reason"):
            # первый шаг замены комментария (dev29): намерение – конечное решение из `then`, а не промежуточный статус
            # (ревью кода dev15, круг 10: в очереди и с неизвестным исходом первый шаг назывался «не отправлено»).
            # Выполненный первый шаг конечное решение не доставляет: второй шаг ещё ставится (taken) или не поставлен
            # (stopped – решение отправляет оператор заново); поставленный второй шаг – своя, более новая операция
            body = {**body, **{k: then.get(k) for k in ("status", "reason", "expiredAt")}}
            if state == "done":
                state = "taken" if then.get("chained") is None else "stopped"
        if not isinstance(body.get("reason"), str) or not isinstance(body.get("expiredAt"), str):
            continue
        members = {(m.get("issueType"), m.get("issueId")) for m in body.get("issues", [body])}
        reason_hash = text_hash(body["reason"])
        decision = {k: body.get(k) for k in ("status", "reason", "expiredAt")}
        for target in (targets if targets is not None else loads(op["targets_json"], [])):
            typ, ident = target.get("issue_type"), target.get("issue_id")
            if ((typ, ident) not in members or target.get("hub_id") != str(ident)
                    or target.get("entered_hash") != reason_hash):
                continue
            key = (typ, str(ident), target.get("revision"), target.get("sig"), body.get("status"))
            index.setdefault(key, {"op_id": op["id"], "state": state, "target": target, "body": decision})
    return index


def _among(column, idents):
    """Условие отбора по номерам находок: None – все, пустой набор – ни одной."""
    if idents is None:
        return "", ()
    if not idents:
        return " AND FALSE", ()
    return f" AND {column} IN ({','.join('?' * len(idents))})", tuple(idents)


class ComparisonContext:
    """Снимок локальных строк под одним замком, без запросов на каждый объект. only – ключи находок («ТИП:номер»):
    карточка считает свою находку, а не проект (dev15, план п. 2.3); дефекты и операции – целиком."""

    def __init__(self, c, row, only=None):
        pid = row["project_id"]
        scope = (pid, row["hub_url"], row["app_id"])
        idents = sorted({str(k).split(":", 1)[-1] for k in only}) if only is not None else None
        cond, args = _among("hub_id", idents)
        self.findings = {r["hub_id"]: dict(r) for r in c.execute("SELECT * FROM findings WHERE project_id=?" + cond,
                                                                 (pid, *args))}
        self.reviews = {r["hub_id"]: dict(r) for r in c.execute("SELECT * FROM reviews WHERE project_id=?" + cond,
                                                                (pid, *args))}
        cond, args = _among("issue_id", idents)
        self.states = {f"{r['issue_type']}:{r['issue_id']}": dict(r) for r in c.execute(
            "SELECT * FROM hub_issue_states WHERE project_id=? AND hub_url=? AND app_id=?" + cond, (*scope, *args))}
        self.defects = {r["id"]: dict(r) for r in c.execute("SELECT * FROM hub_defects WHERE project_id=? ORDER BY id", (pid,))}
        self.owners, self.families = {}, {}
        for d in self.defects.values():
            if d["state"] in ("deleted", "failed", "cancelled"):
                continue
            self.families.setdefault(d["draft_owner_id"], []).append(d)
            if d["hub_url"] == row["hub_url"] and d["app_id"] == row["app_id"] and d["draft_owner_id"] == d["id"]:
                self.owners[str(d["hub_defect_id"])] = d
        self.versions = {(r["entity_kind"], r["entity_key"]): {"accepted_epoch": r["accepted_epoch"],
                         "accepted_hash": r["accepted_hash"]} for r in c.execute(
            "SELECT * FROM hub_entity_versions WHERE project_id=? AND hub_url=? AND app_id=?", scope)}
        self.last_status = {}  # последняя операция статуса по находке – для причин отличий (dev14)
        self.intents = intent_index(c, row, self.last_status)
        # последнее применение каждого объекта (ключ таблицы – прогон, вид, объект): прежде читалась вся история
        # прогонов и в словаре оставалась последняя строка – тот же результат, без передачи истории (бэклог 123)
        self.applications = {(r["entity_kind"], r["entity_key"]): dict(r) for r in c.execute(
            "SELECT DISTINCT ON (a.entity_kind, a.entity_key)"
            " a.run_id,a.entity_kind,a.entity_key,a.presence,a.accepted_epoch,a.accepted_hash"
            " FROM hub_sync_applications a JOIN hub_defect_sync_runs s ON s.id=a.run_id"
            " WHERE s.project_id=? AND s.hub_url=? AND s.app_id=?"
            " ORDER BY a.entity_kind, a.entity_key, a.run_id DESC", scope)}
        # Совместимое решение об ошибке сохраняется при принятии Hub без смены редакции.
        # Для него отличаем прежний вывод от новой правки, читая только нужные поля истории.
        cond, args = _among("s.issue_id", idents)
        self.review_bases = {r["entity_key"]: dict(r) for r in c.execute(
            "SELECT a.entity_key,a.presence,(a.before_json::json -> 'local' ->> 'review') AS review_json,"
            " (a.hub_json::json -> 'detail' ->> 'status') AS status FROM hub_issue_states s"
            " JOIN reviews r ON r.project_id=s.project_id AND r.hub_id=s.issue_id"
            " JOIN hub_sync_applications a ON a.run_id=s.confirmed_run_id AND a.entity_kind='issue'"
            " AND a.entity_key=s.issue_type || ':' || s.issue_id"
            " WHERE s.project_id=? AND s.hub_url=? AND s.app_id=?"
            " AND r.decision_origin='operator' AND r.final_verdict='true_positive'" + cond, (*scope, *args))}
        self.draft_history = {}
        for event in c.execute("SELECT h.defect_id,h.revision,h.event,h.created_at FROM hub_defect_history h"
                               " JOIN hub_defects d ON d.id=h.defect_id WHERE d.project_id=?"
                               " AND d.hub_url=? AND d.app_id=? ORDER BY h.id", scope):
            self.draft_history.setdefault(event["defect_id"], []).append(dict(event))
        # последняя операция отправки статуса по каждой находке – для причины отличия (dev14)
        self.pending, self.pending_meta = {}, {}
        # порядок номеров входит в отпечаток локального состояния: без ORDER BY перестановка строк выглядела бы правкой;
        # дата и значения правки – тем же запросом, а не запросом на объект (dev15, план п. 2.3)
        for p in c.execute("SELECT id,entity_kind,entity_key,created_at,(payload_json::json -> 'values')::text AS values_json"
                           " FROM hub_sync_pending WHERE project_id=? AND hub_url=?"
                           " AND app_id=? AND state IN ('pending','restored') ORDER BY id", scope):
            self.pending.setdefault((p["entity_kind"], p["entity_key"]), []).append(p["id"])
            self.pending_meta[p["id"]] = {"created_at": p["created_at"], "values": loads(p["values_json"], {}) or {}}

    def drop_pending(self, ids):
        """Убрать строки, которые сверка закроет (страницы до записи переходов, план п. 2.1)."""
        ids = set(ids)
        for key in list(self.pending):
            self.pending[key] = [i for i in self.pending[key] if i not in ids]
            if not self.pending[key]:
                del self.pending[key]
        for i in ids:
            self.pending_meta.pop(i, None)

    def observation_current(self, row, kind, key, sources):
        current = self.current(kind, key)
        accepted = self.applications.get((kind, key))
        if accepted and accepted["run_id"] == row["id"]:
            return all(accepted[k] == current[k] for k in ("accepted_epoch", "accepted_hash"))
        return all(s["base_epoch"] == current["accepted_epoch"] and s["base_hash"] == current["accepted_hash"]
                   for s in sources.values())

    def current(self, kind, key):
        return self.versions.get((kind, key), {"accepted_epoch": 0, "accepted_hash": ""})

    def draft_provenance(self, owner, before=None):
        events = [e for e in self.draft_history.get(owner.get("id"), [])
                  if e["revision"] <= owner.get("draft_revision", 0)
                  and (before is None or e["created_at"] <= before)]
        if not events:
            return {}
        accepted = max((e["revision"] for e in events if e["event"] in ("hub_sync", "hub_confirm", "migration", "create")), default=0)
        edited = max((e["revision"] for e in events if e["event"] == "edit"), default=0)
        return {"accepted_revision": accepted, "edit_revision": edited}

    def issue_local(self, key):
        typ, ident = key.split(":", 1)
        finding, review = self.findings.get(ident), self.reviews.get(ident)
        local = {"finding": finding, "review": review, "state": self.states.get(key),
                 "pending": self.pending.get(("issue", key), [])}
        local["review_after_base"] = review_after_base(local, self.review_bases.get(key))
        if self.intents and finding and HUB_ISSUE_TYPE.get(finding["kind"]) == typ:
            desired = issue_local_values({"review": {**(review or {}), "decision_origin": "operator"}}).get("status")
            local["status_intent"] = self.intents.get((typ, ident, review["revision"],
                finding_data_sig(finding["data_json"]), desired)) if review and desired else None
        else:
            local["status_intent"] = None
        return local

    def defect_local(self, key):
        if key.startswith("local:"):
            return self.defects.get(int(key.split(":")[1]), {})
        owner = self.owners.get(key)
        if not owner:
            return {}
        family = self.families.get(owner["id"], [])
        members = [{"id": r["id"], "targets": sorted([
            [str(t.get("hub_id") or ""), str(t.get("issue_type") or ""), t.get("revision"), str(t.get("sig") or "")]
            for t in loads(r["targets_json"], [])], key=lambda t: (t[0], t[1])),
            "number_keys": sorted(loads(r["number_keys_json"], [])), "sca_set_key": r["sca_set_key"]} for r in family]
        return {"owner": owner, "family": family, "members": members, "pending": self.pending.get(("defect", key), []),
                "draft_provenance": self.draft_provenance(owner)}


def status_intent(c, row, key, finding, review, desired):
    if not finding or not review or not desired:
        return None
    typ, ident = key.split(":", 1)
    return intent_index(c, row).get((typ, ident, review["revision"], finding_data_sig(finding["data_json"]), desired))


def observed_issue_values(hub):
    """Содержательные сведения отдельно от решения; счётчики и времена не являются его редакцией."""
    detail = dict(hub.get("detail") or {})
    for key in list(detail):
        if key in ("status", "updateTs", "scanTs") or key.endswith("Count"):
            detail.pop(key)
    current = detail.get("currentBranch")
    for key in ("cwes", "issueBranchBriefData"):
        if isinstance(detail.get(key), list):
            # статус текущей ветки – тот же статус решения, он сравнивается проекцией решения, а не справочными
            # сведениями: иначе каждое отправленное решение выглядело бы «изменением прочих сведений Hub» (dev15)
            values = [{k: v for k, v in obj.items() if k != "lastSeen"
                       and not (key == "issueBranchBriefData" and k == "status" and obj.get("branch") == current)}
                      if isinstance(obj, dict) else obj for obj in detail[key]]
            detail[key] = sorted(values, key=dumps)
    return detail


def compare_issue(c, row, item, hub, adapter, context=None):
    context = context or ComparisonContext(c, row)
    typ, ident = item["entity_key"].split(":", 1)
    local = context.issue_local(item["entity_key"])
    finding, review, state = (local[k] for k in ("finding", "review", "state"))
    base = loads(state["confirmed_json"], {}) if state else {}
    problems = api.evidence_problems(hub, item["entity_key"], row["app_id"], adapter)
    notes, hub_notes = api.blocking(problems), [p for p in problems if p in api.HUB_NOTES]
    key = item["entity_key"]
    b, l, h = issue_values(base, key), issue_local_values(local), issue_values(hub, key)
    intent = local.get("status_intent") or {}
    if (intent.get("state") in (None, "done", "cancelled")
            and operator_defect_compatible(review or {}, hub)):
        # «Подтверждаю дефект» статусом в Hub не уходит: при статусе Hub без «Ложного срабатывания» и «Риска принят»
        # отправлять нечего – как при «Принять» (hub_pull.pending_change); иначе находки,
        # которым Hub после создания дефекта сменил To verify на Open, назывались бы «ждёт отправки»
        l = h
    no_decision = not l
    # Без действующего решения L означает отсутствие правки, а не удаление принятого статуса.
    fields = three_way(b, b if no_decision else l, h) if base else without_base(l, h)
    groups = []
    if typ not in api.DETAIL_PATHS or (finding and HUB_ISSUE_TYPE.get(finding["kind"]) != typ):
        groups.append("unmapped")
    elif not finding:
        groups.append("fixed_external" if h.get("status") == "Fixed" else "new")
    else:
        default_status = (no_decision and h.get("status") == "To verify" and "manual" in hub
                          and hub["manual"] is None and not hub.get("risk"))
        if not base and default_status:
            fields = []
        groups.extend(f["kind"] for f in fields)
        if base and no_decision and fields:
            groups.append("no_decision")
        if l.get("status") in ("False Positive", "Accepted risk") and l.get("status") == h.get("status"):
            if any(f["field"] in ("reason", "expiredAt") and f["L"] != f["H"] for f in fields):
                groups.append("decision_diff")
        if state and state["alignment"] == "pending":
            groups.append("pending")
        if state and loads(state["conflicts_json"], []):
            groups.append("conflict")
    from app.hub_pull import pending_change
    dirty, _ = pending_change("issue", local, base, hub)
    if dirty:
        groups.append("pending")
    else:
        groups = [g for g in groups if g != "pending"]
        # исходящего намерения нет (решение уже доставлено или снято в Hub): поля не «ждут отправки» – отличие
        # решения оператора от Hub показывается своим видом (ревью dev16, A4/B3)
        fields = [{**f, "kind": "local_only"} if f["kind"] == "pending" else f for f in fields]
        if any(f["kind"] == "local_only" for f in fields):
            groups.append("local_only")  # не пустой набор групп, превращающийся в «совпадает» (dev15, план п. 1.5)
    if notes:
        groups.append("incomplete")
    if base:
        observed = three_way(observed_issue_values(base), observed_issue_values(base), observed_issue_values(hub))
        if observed:
            fields.extend({**f, "field": "detail/" + f["field"], "kind": "observed", "readonly": True} for f in observed)
            groups.append("observed")
    # решение у базы и Hub одно и то же – причина справочного отличия так и скажет (план п. 3)
    decision_same = bool(base) and issue_values(base, key) == issue_values(hub, key)
    return base, local, {"groups": sorted(set(groups)) or ["matched"], "notes": notes, "hub_notes": hub_notes,
                         "fields": fields, "decision_same": decision_same,
                         "base_pending": not base and not groups, "deferred": bool(review and review["decision"] == "later")}


def normalized_decision(values):
    """Как при сверке отправки: текст и календарная дата UTC, исходные значения сохранены отдельно. Отсутствующее
    основание или срок, null и пустая строка – одно значение «нет» с обеих сторон (dev15, план п. 1.1)."""
    result = dict(values)
    if "reason" in result:
        result["reason"] = normalize_text(result["reason"] or "")
    if "expiredAt" in result:
        result["expiredAt"] = expiry_day(result["expiredAt"]) or result["expiredAt"]
    for name in ("reason", "expiredAt"):
        if result.get(name) in (None, ""):
            result.pop(name, None)
    return result


def local_key(local):
    """«ТИП:номер» находки по её локальным строкам: принятое состояние Hub, иначе сама находка."""
    state, finding = local.get("state") or {}, local.get("finding") or {}
    if state.get("issue_type") and state.get("issue_id") is not None:
        return f"{state['issue_type']}:{state['issue_id']}"
    typ = HUB_ISSUE_TYPE.get(finding.get("kind"))
    return f"{typ}:{finding['hub_id']}" if typ and finding.get("hub_id") is not None else None


def _own(record, key) -> bool:
    """Запись Hub относится к этой находке: тот же ID и тип. Без ключа принадлежность не доказана."""
    if not isinstance(record, dict) or not key:
        return False
    typ, ident = key.split(":", 1)
    return str(record.get("issueId")) == str(ident) and api.same_issue_type(record.get("issueType"), typ)


def decision_source(hub, key):
    """Запись Hub, из которой проекция берёт основание и срок: своя ручная запись того же статуса или действующий
    риск этой находки; иначе None (dev15, план п. 1.1 – отметка «Внесено в Hub» только по своей записи)."""
    detail = hub.get("detail") or {}
    status = detail.get("status")
    if status == "Accepted risk":
        # приложение – из самого подробного ответа (его номер проверен при чтении, hub_sync.consume_object)
        app_id = detail.get("appId") if type(detail.get("appId")) is int else None
        risk = hub.get("risk")
        return risk if api.risk_valid(risk, key, app_id) else None
    manual = hub.get("manual")
    # ручная запись ветки или условия и истёкшая – не основание решения выбранной ветки (ревью Kimi dev15, круг 3)
    usable = (_own(manual, key) and manual.get("status") == status
              and all(manual.get(k) is None for k in ("conditionalCategory", "branch", "isConditional"))
              and not api.expired(manual.get("expiredAt")))
    return manual if usable else None


def issue_values(hub, key=None):
    """Решение Hub по находке – одна проекция для сравнения, принятия и страниц (dev15, план п. 1.1). Статус –
    подробный статус выбранной ветки. Основание и срок – из ручной записи этой находки с тем же статусом; для «Риск
    принят» – из действующей записи риска этой находки. Чужая или противоречащая статусу запись основанием не
    становится (ревью плана dev15: иначе принятие записало бы находке основание другой находки)."""
    detail = hub.get("detail") or {}
    status = detail.get("status")
    source = decision_source(hub, key) or {}
    reason_key = "comment" if status == "Accepted risk" else "reason"
    return normalized_decision({**({"status": status} if "status" in detail else {}),
            **({"reason": source[reason_key]} if reason_key in source else {}),
            **({"expiredAt": source["expiredAt"]} if "expiredAt" in source else {})})


def operator_defect_compatible(review, hub):
    """Подтверждение ошибки оператором не является исходящим статусом находки Hub."""
    status = (hub.get("detail") or {}).get("status")
    return (review.get("decision_origin") != "hub_sync"
            and hub_verdict(review.get("decision"), review.get("final_verdict")) == "true_positive"
            and bool(status) and status not in ("False Positive", "Accepted risk"))


def review_after_base(local, application):
    """Редакция решения относительно принятия, включая сохранённое совместимое решение."""
    review = local.get("review") or {}
    if not application or review.get("decision_origin") != "operator":
        return False
    previous = loads(application["review_json"], {}) or {}
    # Применение меняет решение только при решении Hub (ложное срабатывание, риск); иначе разбор приложения не
    # трогается и редакция не растёт.
    touched = application["presence"] == "present" and application["status"] in ("False Positive", "Accepted risk")
    revision = previous.get("revision", 0) + int(touched)
    changed = touched or any(review.get(k) != previous.get(k) for k in
        ("decision", "final_verdict", "final_comment", "final_fix", "kapo_state", "desired_hub_expired_at"))
    return review.get("revision", 0) > revision and changed


def issue_local_values(local):
    intent = local.get("status_intent")
    if intent and intent.get("state") not in (None, "done", "cancelled"):
        return normalized_decision({k: intent["body"][k] for k in ("status", "reason", "expiredAt")})
    accepted = loads((local.get("state") or {}).get("confirmed_json"), {})
    if not local.get("review_after_base") and operator_defect_compatible(local.get("review") or {}, accepted):
        return issue_values(accepted, local_key(local))
    review = local.get("review") or {}
    if review.get("decision_origin") == "hub_sync":
        # решение принято из Hub: проекция – то, что принятие записало в решение (статус, основание, срок). Прежде
        # бралась проекция принятого снимка Hub; тогда решение, записанное прежней версией без основания (ручная запись
        # SCA считалась чужой – ревью dev16, Codex круг 1), после обновления выглядело бы «совпадающим», хотя в карточке
        # основания нет. Расхождение – группа decision_diff, закрывается повторным «Принять состояние Hub»
        status = {"false_positive": "False Positive", "risk_accepted": "Accepted risk"}.get(
            hub_verdict(review.get("decision"), review.get("final_verdict")), "")
        if status:
            return normalized_decision({"status": status, "reason": review.get("final_comment"),
                                        "expiredAt": review.get("desired_hub_expired_at")})
        return issue_values(accepted, local_key(local))
    intent = local.get("status_intent")
    if intent:
        return normalized_decision({k: intent["body"][k] for k in ("status", "reason", "expiredAt")})
    review = local.get("review") or {}
    if not review.get("decision") or hub_verdict(review.get("decision"), review.get("final_verdict")) == "uncertain":
        return {}
    verdict = hub_verdict(review["decision"], review.get("final_verdict"))
    return normalized_decision({"status": {"false_positive": "False Positive", "risk_accepted": "Accepted risk"}.get(verdict, verdict),
            "reason": review.get("final_comment"), "expiredAt": review.get("desired_hub_expired_at")})


def compare_in(c, row):
    from app.hub_sync import add_item, local_keys, passport, save_run
    from app.hub_pull import reconcile_pending_in
    reconcile_pending_in(c, row)
    data = passport(row)
    adapter = api.Adapter(**data["adapter"])
    seen = {(r[0], r[1]) for r in c.execute("SELECT entity_kind,entity_key FROM hub_sync_items WHERE run_id=?", (row["id"],))}
    for kind, key in sorted(local_keys(c, row) - seen):
        add_item(c, row, kind, key)
        c.execute("UPDATE hub_sync_items SET stale_reason=? WHERE run_id=? AND entity_kind=? AND entity_key=?",
                  (LOCAL_AFTER_READ, row["id"], kind, key))
    items = c.execute("SELECT * FROM hub_sync_items WHERE run_id=? ORDER BY entity_kind,entity_key", (row["id"],)).fetchall()
    context = ComparisonContext(c, row)
    counts, signatures, bases_pending = {}, [], 0
    apply_counts = {"selectable": 0, "blocked": 0}
    progress_counts = {"issue": 0, "defect": 0, "issue_detail": 0, "defect_detail": 0, "basis": 0}
    exceptions = 0
    links = run_links(items)
    from app.hub_pull import replaced_decision
    replaced = []  # решения приложения, которые «Принять состояние Hub» заменит (dev15, план п. 1.4)
    for raw in items:
        item = dict(raw)
        kind, key = item["entity_kind"], item["entity_key"]
        hub = loads(item["hub_json"], {})
        coverage = loads(item["coverage_json"], {})
        progress_counts[kind] += int("brief" in hub)
        progress_counts[kind + "_detail"] += int("detail" in hub)
        progress_counts["basis"] += int("manual" in hub) + int("risk" in hub)
        exceptions += len(coverage.get("exceptions", {}))
        base, local, diff, stale = evaluate(c, row, context, item, adapter, links)
        from app.hub_pull import absent
        for group in diff["groups"]:
            counts[group] = counts.get(group, 0) + 1
        if not key.startswith("local:"):
            # то же правило пропуска, что у «Принять состояние Hub» (hub_pull.preview); противоречия Hub – пометки, а не
            # пропуск (dev15, план п. 1.2): особого счёта «только противоречия Hub» больше нет
            blocked = bool(stale) or (not absent(item) and "incomplete" in diff["groups"]) or (
                kind == "issue" and "unmapped" in diff["groups"])
            apply_counts["blocked" if blocked else "selectable"] += 1
            finding = local.get("finding") if kind == "issue" else None
            if (finding and not blocked and not key.startswith("UNMAPPED:")
                    and replaced_decision(local, hub, key)):
                section = "sca/findings" if finding["kind"] == "SCA" else "findings"
                replaced.append({"key": key, "hub_id": finding["hub_id"],
                                 "url": f"/projects/{row['project_id']}/{section}/{finding['id']}"})
        bases_pending += int(diff.get("base_pending", False))
        signature = versions.digest(local)
        signatures.append([kind, key, signature])
        c.execute("UPDATE hub_sync_items SET base_json=?,local_json=?,local_signature=?,diff_json=?,stale_reason=?"
                  " WHERE run_id=? AND entity_kind=? AND entity_key=?",
                  (dumps(base), dumps(local), signature, dumps(diff), stale, row["id"], kind, key))
    data.update(comparison_complete=True, groups=counts, bases_pending=bases_pending, apply_counts=apply_counts,
                replaced={"count": len(replaced), "items": replaced[:20]}, compare_version=COMPARE_VERSION,
                matches_snapshot=data["inventory_complete"] and data["details_complete"] and not bases_pending
                and not (set(counts) - {"matched"}))
    latest = {s["request_key"]: s for s in c.execute(
        "SELECT entity_kind,request_key,state FROM hub_sync_requests WHERE run_id=? ORDER BY id", (row["id"],))}
    needed = {"issue": 0, "defect": 0, "basis": 0}
    for step in latest.values():
        part = loads(step["request_key"], ["", "", ""])[2]
        if part == "detail":
            needed[step["entity_kind"]] += 1
        elif part in ("manual", "risk"):
            needed["basis"] += 1
    data["progress_counts"] = {"counts": progress_counts, "needed": needed, "exceptions": exceptions,
                               "complete": sum(s["state"] == "done" for s in latest.values()), "total": len(latest)}
    c.execute("UPDATE hub_defect_sync_runs SET snapshot_hash=? WHERE id=?", (versions.digest(signatures), row["id"]))
    save_run(c, row, data, "ready")
    if data["inventory_complete"] and data["details_complete"]:
        _resync_when_nothing_to_apply(c, row["id"])
    if row["applied_at"]:
        result = loads(row["result_json"], {})
        result["pending"] = counts.get("pending", 0)
        c.execute("UPDATE hub_defect_sync_runs SET result_json=? WHERE id=?", (dumps(result), row["id"]))


def run_links(items):
    """Связи находок с дефектами по спискам Hub прогона: какие дефекты есть в списке, у каких находок известен defectId."""
    issue_links, known_links = {}, set()
    listed_defects = {r["entity_key"] for r in items if r["entity_kind"] == "defect"
                      and "brief" in loads(r["hub_json"], {})}
    for raw in items:
        if raw["entity_kind"] == "issue":
            brief = loads(raw["hub_json"], {}).get("brief", {})
            if "defectId" in brief:
                known_links.add(raw["entity_key"])
            if brief.get("defectId"):
                issue_links.setdefault(str(brief["defectId"]), set()).add(raw["entity_key"])
    return {"issue_links": issue_links, "known_links": known_links, "listed_defects": listed_defects}


def evaluate(c, row, context, item, adapter, links):
    """Расчёт одного объекта прогона без записи (dev15, бэклог 88): его зовут пересчёт (`compare_in`) и страницы, чтобы
    состояние относительно Hub считалось в одном месте. Возвращает (база, локальное, diff, причина устаревания)."""
    from app.hub_pull import absent
    kind, key = item["entity_kind"], item["entity_key"]
    hub = loads(item["hub_json"], {})
    sources, coverage = loads(item["source_ops_json"], {}), loads(item["coverage_json"], {})
    stale = item["stale_reason"]
    if sources and not context.observation_current(row, kind, key, sources):
        stale = "Наблюдение устарело относительно принятой базы. Локальный пересчёт этого не меняет."
    base, local, diff = (compare_defect(c, row, item, hub, context) if kind == "defect"
                         else compare_issue(c, row, item, hub, adapter, context))
    accepted = context.applications.get((kind, key))
    if absent(item):
        agreed = accepted and accepted["presence"] == "absent"
        # исходящее намерение остаётся видно и у отсутствующего в Hub объекта (ревью кода dev15, круг 1): удаление
        # не утверждается, а неотправленное решение не пропадает
        waiting = "pending" in diff["groups"]
        diff = {"groups": ["matched" if agreed else "absent"] + (["pending"] if waiting else []),
                "fields": [f for f in diff.get("fields", []) if f.get("kind") == "pending"],
                "notes": ["Отсутствует в полном списке Hub, чтение по ID вернуло 404. Запись сохраняется с пометкой; удаление не утверждается."]}
    elif accepted and accepted["presence"] == "absent" and hub.get("detail") and "brief" in hub:
        diff["groups"].append("changed")
        diff["notes"].append("Объект снова присутствует в Hub. Пометка отсутствия снимется при принятии состояния.")
    pending_ids = context.pending.get((kind, key), [])
    diff["current_pending"] = "pending" in diff["groups"]  # до сохранённых правок: ждёт ли текущее решение
    if pending_ids:
        diff["pending_ids"] = pending_ids
        delivered = set()
        if kind == "issue":
            from app.hub_pull import delivered_pending_ids
            delivered = delivered_pending_ids(c, pending_ids, local, context.pending_meta)
            if delivered:
                diff["delivered_pending_ids"] = sorted(delivered)
        remaining = [i for i in pending_ids if i not in delivered]
        # все сохранённые правки доставлены, текущее решение не ждёт – не «ждёт отправки», а «отправлено, ждёт
        # принятия» (ревью Codex dev14, круг 11: метка группы не должна спорить с причиной)
        diff["groups"].append("pending" if remaining or diff["current_pending"] else "sent_unaccepted")
        if remaining:  # даты – только неотправленных сохранённых правок (ревью Codex dev14, круг 3); из контекста,
            # а не запросом на объект (dev15, план п. 2.3)
            diff["stored_dates"] = sorted(context.pending_meta[i]["created_at"] for i in remaining
                                          if i in context.pending_meta)
    if kind == "issue" and issue_values(hub, key).get("status") == "Fixed" and "pending" in diff["groups"]:
        # решение оператора по находке, которую Hub считает исправленной, отправить нельзя (форма отправки для
        # Fixed закрыта): не «ждёт отправки», а свой вид с причиной; само намерение сохраняется (dev14:
        # ждущих отправок без причины быть не должно)
        diff["groups"] = [g for g in diff["groups"] if g not in ("pending", "conflict")] + ["unsendable"]
        diff["fields"] = [{**f, "kind": "unsendable"} if f.get("kind") in ("pending", "conflict") else f
                          for f in diff.get("fields", [])]
    if kind == "issue":
        # ближайший срок записи Hub, на которой держится проекция решения (база и наблюдение): после него проекция
        # меняется без правок, и страница считает объект заново (ревью кода dev15, круг 1). decision_source истёкшую
        # запись не возвращает – сроки оставшихся в будущем
        moments = [instant_ms((source or {}).get("expiredAt"))
                   for source in (decision_source(hub, key), decision_source(base or {}, key))]
        moments = [m for m in moments if m is not None]
        if moments:
            diff["valid_until"] = min(moments)
    diff["delivery"] = delivery_of(kind, key, local, diff, context, sources,
                                   observed=bool(hub.get("brief") or hub.get("detail")))
    diff["causes"] = causes(kind, key, local, diff, context)
    if stale:
        # устаревшее наблюдение не стирает сведения отправки: «не отправлено» видно всегда (dev15, план п. 2.1)
        # срок записи Hub сохраняется и здесь: после него страница считает объект заново (ревью кода dev15, круг 2)
        diff = {"groups": ["stale"], "notes": [stale], "fields": [], "delivery": diff["delivery"],
                **({"valid_until": diff["valid_until"]} if "valid_until" in diff else {})}
    if coverage.get("absent_from_list") and not absent(item) and not key.startswith(("local:", "UNMAPPED:")):
        diff["groups"].append("absent")
        diff["notes"].append("Отсутствует в списке; удаление не считается установленным без подтверждённой семантики ответа по ID.")
    if coverage.get("inventory_contradiction"):
        diff["groups"].append("incomplete")
        diff["notes"].append(coverage["inventory_contradiction"])
    for part, exception in coverage.get("exceptions", {}).items():
        diff["groups"].append("incomplete")
        diff["notes"].append(f"Исключение {part}, операция {exception['op_id']}: {exception['reason']}")
    if kind == "issue" and (defect_id := (hub.get("brief") or {}).get("defectId")):
        if str(defect_id) not in links["listed_defects"]:
            diff["groups"].extend(["composition", "incomplete"])
            diff["notes"].append(f"defectId находки ссылается на дефект {defect_id}, отсутствующий в списке дефектов.")
    if kind == "defect" and hub.get("detail"):
        linked = {f"{t}:{i}" for i, t in linked_pairs(hub["detail"])}
        if linked & links["known_links"] != links["issue_links"].get(key, set()):
            diff["groups"].extend(["composition", "incomplete"])
            diff["notes"].append("linkedIssues дефекта и defectId списка находок расходятся.")
    diff["groups"] = sorted(set(diff["groups"]))
    if len(diff["groups"]) > 1 and "matched" in diff["groups"]:
        diff["groups"].remove("matched")
    return base, local, diff, stale


def _resync_when_nothing_to_apply(c, run_id):
    """После восстановления копии признак снимает «Принять состояние Hub»; если принимать нечего, кнопка отказала бы, и признак снимается здесь."""
    from app import hub_pull, hub_sync
    if not hub_sync.resync_pending_in(c):
        return
    row = hub_sync.run_in(c, run_id)
    try:
        selected, skipped = hub_pull.plan_in(c, row)
    except ValueError:
        return
    if not selected:
        hub_sync.resync_done_in(c, row, skipped)


def snapshot_current(db, row):
    """Показ старого сравнения не объявляет текущие изменившиеся данные совпадающими. Сравнение другой версии расчёта
    и сравнение, у объекта которого наступил срок записи Hub, – тоже не текущие (ревью кода dev15, круг 2: то же
    правило, что у страниц, app/hub_state.py)."""
    import time
    from app.hub_sync import local_keys, passport
    if passport(row).get("compare_version") != COMPARE_VERSION:
        return False
    def check(c):
        context = ComparisonContext(c, row)
        items = [dict(r) for r in c.execute("SELECT entity_kind,entity_key,local_signature,source_ops_json,"
                                            "(diff_json::json ->> 'valid_until') AS valid_until FROM hub_sync_items"
                                            " WHERE run_id=?", (row["id"],))]
        if local_keys(c, row) - {(r["entity_kind"], r["entity_key"]) for r in items}:
            return False
        now_ms = int(time.time() * 1000)
        for item in items:
            kind, key = item["entity_kind"], item["entity_key"]
            if item["valid_until"] and now_ms >= int(item["valid_until"]):
                return False
            local = context.defect_local(key) if kind == "defect" else context.issue_local(key)
            if versions.digest(local) != item["local_signature"]:
                return False
            if not context.observation_current(row, kind, key, loads(item["source_ops_json"], {})):
                return False
        return True
    return db.on_connection(check)


def recompare(db, run_id):
    from app.hub_sync import reparse_saved, run_in
    with db._tx() as c:
        row = run_in(c, run_id)
        if row["state"] != "ready" or row["closed_at"]:
            raise ValueError("Пересчёт доступен после завершения чтения.")
        reparse_saved(c, row)
        compare_in(c, run_in(c, run_id))
