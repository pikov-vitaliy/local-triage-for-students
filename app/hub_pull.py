"""Подтверждённое локальное принятие сохранённого Hub. Сетевых операций здесь нет."""

from app import defect_drafts, defect_fields, hub_entity_versions as versions
from app import hub_sync, hub_sync_api as api, hub_sync_compare as compare
from app import i18n, package_identity, package_transition
from app.db import dumps, loads, now_iso, finding_data_sig, review_signature, _group2_columns
from app.hub_defects import NO_NUMBER, _read_of, defect_link, level_name, linked_pairs
from app.hub_status import HUB_ISSUE_TYPE
from app.models import Finding

KINDS = {value: key for key, value in HUB_ISSUE_TYPE.items()}


def scope(row):
    return row["project_id"], row["hub_url"], row["app_id"]


def pending_in(c, row):
    return [dict(r) for r in c.execute(
        "SELECT * FROM hub_sync_pending WHERE project_id=? AND hub_url=? AND app_id=?"
        " AND state IN ('pending','restored') ORDER BY id", scope(row))]


def applied_version(c, row, kind, key):
    result = c.execute("SELECT accepted_epoch,accepted_hash FROM hub_sync_applications"
                       " WHERE run_id=? AND entity_kind=? AND entity_key=?", (row["id"], kind, key)).fetchone()
    return dict(result) if result else None


def absent(item):
    coverage = loads(item["coverage_json"], {})
    return bool(coverage.get("absent_from_list") and coverage.get("id_response", {}).get("status") == 404
                and not coverage.get("inventory_contradiction") and not coverage.get("exceptions"))


def pending_values(kind, local):
    if kind == "issue":
        return compare.issue_local_values(local)
    owner = local.get("owner", local)
    return {**loads(owner.get("draft_fields_json"), {}), "summary": owner.get("draft_summary", ""),
            "command_text": compare.normalize_text(owner.get("draft_command_text", ""))}


def hub_values(kind, hub, key=None):
    if kind == "issue":
        return compare.issue_values(hub, key)
    values = compare.defect_values(hub.get("detail") or {})[0]
    return {k: v for k, v in values.items() if k not in ("hub_block", "hub_description", "status")}


def no_defect_keys(c, project_id, hub_ids) -> set:
    """Ключи номера находок SCA, отнесённых оператором к «без дефекта» в их текущей версии: ключ набора по умолчанию,
    за которым могут быть другие находки, – номер с него автоматически не снимается (ревью dev14)."""
    from app.db import Database
    from app.defect_drafts import in_some_set
    ids = {str(h) for h in hub_ids if str(h or "").strip()}
    return set(Database.defect_keys_of_findings_in(c, project_id, sorted(ids - set(in_some_set(c, project_id, ids)))))


def same_decision(saved, other) -> bool:
    """Сохранённая правка решения (статус, обоснование, срок) совпадает с другим решением – с принятым Hub или с телом
    доставленной операции. Срок сравнивается, только если он есть в самой правке: правка без срока, отправленная со
    сроком из формы отправки, доставлена (ревью dev14: иначе она «ждала отправки» и после синхронизации)."""
    a, b = compare.normalized_decision(saved or {}), compare.normalized_decision(other or {})
    if not a.get("expiredAt"):
        a, b = {k: v for k, v in a.items() if k != "expiredAt"}, {k: v for k, v in b.items() if k != "expiredAt"}
    return bool(a) and a == b


def history_matches(state, values, accepted, local) -> bool:
    """Сохранённая правка решения совпадает с принятым Hub (её можно закрыть как доставленную). Сравнение – со сроком;
    послабление для срока – у прежнего ожидания отправки (`pending`, ADR-0142 п. 5) и у правки, которую доставила
    операция текущей редакции (срок мог добавить формой отправки). Восстановленная, но не отправленная правка и
    история заменённого решения без отправки строго равны Hub (ревью кода dev15, круги 1–2)."""
    if state == "pending":
        return same_decision(values, accepted)
    intent = local.get("status_intent") or {}
    if intent.get("state") == "done" and same_decision(values, intent.get("body") or {}):
        # доставленное тело операции (со сроком из формы) строго равно принятому Hub – срок не выбрасывается с обеих
        # сторон (ревью кода dev15, круг 3)
        body = compare.normalized_decision(intent.get("body") or {})
        return bool(body) and body == compare.normalized_decision(accepted or {})
    mine = compare.normalized_decision(values or {})
    return bool(mine) and mine == compare.normalized_decision(accepted or {})


def delivered_pending_ids(c, ids, local, meta=None) -> set:
    """Номера сохранённых правок находки, доставку которых доказывает доставленная операция текущего решения: тело
    операции совпадает с самой правкой. Другие сохранённые правки остаются неотправленными (ревью Codex dev14, круг 2).
    meta – значения правок из контекста сравнения (dev15, план п. 2.3: без запроса на каждую правку)."""
    intent = local.get("status_intent") or {}
    if intent.get("state") != "done" or not ids:
        return set()
    out = set()
    for ident in ids:
        if meta is not None and ident in meta:
            values = meta[ident]["values"]
        else:
            row = c.execute("SELECT payload_json FROM hub_sync_pending WHERE id=?", (ident,)).fetchone()
            values = (loads(row[0], {}) if row else {}).get("values") or {}
        if values and same_decision(values, intent.get("body") or {}):
            out.add(ident)
    return out


def pending_change(kind, local, base, hub, historical=False):
    """Отличие от Hub сохраняется только при доказанном исходящем намерении."""
    values = pending_values(kind, local)
    pending_links = None
    if kind == "issue":
        review = local.get("review") or {}
        intent = local.get("status_intent") or {}
        explicit = bool(intent and intent.get("state") not in (None, "done", "cancelled"))
        if intent and intent.get("state") == "done":
            # эта редакция доставлена в Hub – отправлено, ждать нечего: оператор нажал
            # «Отправить», Hub ответил «принято» – процесс закончен; если Hub позже покажет другое (возврат на
            # проверку, пересканирование), это изменение на стороне Hub, а не «не отправлено»
            return False, None
        if not explicit and not historical and compare.operator_defect_compatible(review, hub):
            # «Подтверждаю дефект» статусом в Hub не уходит (из приложения – только «Ложное срабатывание» и «Риск
            # принят»): при текущем статусе Hub без такого решения ждать отправки нечего, и после пересохранения
            # решения; Hub поставил одно из них – решение остаётся спорным
            return False, None
        newer = (bool(base) and review.get("decision_origin") == "operator"
                 and values != hub_values(kind, base, compare.local_key(local)))
        if not explicit and (review.get("decision_origin") == "hub_sync"
                             or review.get("entered_origin") == "hub_sync" and not newer):
            return False, None
        # решение оператора для Hub, которого в Hub нет (у Hub своего решения нет), – новая запись из приложения: ждёт
        # отправки и без принятой базы (dev15: из приложения добавляются новые записи,
        # «не отправлено» видно везде). Уже доставленное и снятое самим Hub сюда не попадает (выход выше)
        new_record = (not historical and review.get("decision_origin") in ("operator", "")
                      and values.get("status") in HUB_DECISIONS
                      and compare.issue_values(hub, compare.local_key(local)).get("status") not in HUB_DECISIONS)
        return bool(values and values != hub_values(kind, hub, compare.local_key(local))
                    and (explicit or newer or new_record)), None
    owner = local.get("owner") or {}
    if not owner:
        return False, None
    links = {(int(t[0]), t[1]) for m in local.get("members", []) for t in m["targets"] if t[0].isdigit()}
    if links != linked_pairs(base) and links != linked_pairs(hub.get("detail") or {}):
        pending_links = sorted(links)
    if base and values == hub_values(kind, {"detail": base}) and pending_links is None:
        return False, None
    proof = local.get("draft_provenance") or {}
    revision = owner.get("draft_revision", 0)
    newer = (revision > proof.get("accepted_revision", revision)
             and proof.get("edit_revision", 0) > proof.get("accepted_revision", 0))
    explicit = loads(owner.get("update_json"), {}).get("phase") in (
        "preview", "refused", "read_failed", "unknown", "unconfirmed")
    differs = values != hub_values(kind, hub) or pending_links is not None
    return bool((newer or explicit) and differs), pending_links


HUB_DECISIONS = ("False Positive", "Accepted risk")


def replaced_decision(local, hub, key) -> bool:
    """Заменяет ли принятие действующее решение приложения (dev15, план п. 1.3: после принятия
    состояние приложения равно Hub). Действующее решение – как его видит сравнение (`issue_local_values`, с намерением
    отправки текущей редакции). У Hub решение («Ложное срабатывание», «Риск принят») – Hub источник истины, заменяется
    любое другое. У Hub решения нет (Open, To verify…) – решение оператора для Hub не заменяется: это новая запись, её
    приложение добавит в Hub, до отправки она «не отправлено» (отправленное и неотправленное показываются
    отдельно от «синхронизировано»). Находка исправлена в Hub (Fixed) – решение туда не
    уйдёт никогда, заменяется. «Подтверждаю дефект» и «Позже» статусом не уходят и без решения Hub не трогаются."""
    review = local.get("review") or {}
    if not local.get("finding") or not review:
        return False
    intent = local.get("status_intent") or {}
    if review.get("decision_origin") == "hub_sync" and intent.get("state") in (None, "done", "cancelled"):
        return False  # решение уже из Hub: работы оператора, которую нужно сохранить, нет
    effective = compare.issue_local_values(local)
    if not effective and not review.get("decision"):
        return False  # решения в приложении нет – заменять и сохранять нечего
    h = compare.issue_values(hub, key)
    if h.get("status") in HUB_DECISIONS:
        own = compare.normalized_decision({"status": compare.issue_local_values(
            {"review": {**review, "decision_origin": "operator"}}).get("status"),
            "reason": review.get("final_comment"), "expiredAt": review.get("desired_hub_expired_at")})
        # действующее решение и сама строка решения равны Hub – заменять нечего; иначе (другое основание, срок,
        # решение, «Подтверждаю дефект», «Позже», намерение отправки с другим телом) – решение Hub
        return effective != h or own != h
    return h.get("status") == "Fixed" and effective.get("status") in HUB_DECISIONS


def remember_pending(c, row, item, local, base, hub, *, state="pending"):
    """Сохранить правку в историю. При принятии (dev15, план п. 1.4) – `saved`: история, а не отличие; та же правка
    (та же подпись) не теряется – строка переходит в `saved`, в её историю добавляется событие с новой базой."""
    kind, key = item["entity_kind"], item["entity_key"]
    if kind == "issue" and state == "saved":
        dirty, pending_links = replaced_decision(local, hub, key), None
    else:
        dirty, pending_links = pending_change(kind, local, base, hub)
    if not dirty:
        return None
    values = pending_values(kind, local)
    stamp = now_iso()
    for pending in pending_in(c, row):
        payload = loads(pending["payload_json"], {})
        if (pending["entity_kind"], pending["entity_key"]) == (kind, key) and payload.get("values") == values:
            if state == "pending":
                return None  # та же неотправленная правка уже ждёт отправки
    # Полная локальная строка сохраняет и поля, для которых ещё нет исходящего API-действия.
    payload = {"local": local, "base": base, "values": values, "links": pending_links, "hub_at_save": hub}
    signature = versions.digest({"local": local, "values": values})
    existing = c.execute("SELECT id,state,payload_json FROM hub_sync_pending WHERE project_id=? AND hub_url=? AND app_id=?"
                         " AND entity_kind=? AND entity_key=? AND signature=?", (*scope(row), kind, key, signature)).fetchone()
    if existing:
        if state == "saved":
            old = loads(existing["payload_json"], {})
            old.setdefault("history", []).append({"event": "saved_again", "at": stamp, "run_id": row["id"],
                                                  "previous_state": existing["state"], "base": base, "hub_at_save": hub})
            c.execute("UPDATE hub_sync_pending SET state='saved',resolved_at=NULL,payload_json=? WHERE id=?",
                      (dumps(old), existing["id"]))
            return existing["id"]
        return None
    payload["history"] = [{"event": "saved", "at": stamp, "run_id": row["id"]}] if state == "saved" else []
    return c.execute("INSERT INTO hub_sync_pending(project_id,hub_url,app_id,entity_kind,entity_key,signature,"
                     "payload_json,state,created_run_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?) RETURNING id",
                     (*scope(row), kind, key, signature, dumps(payload), state, row["id"], stamp)).fetchone()[0]


def settle_saved_in(c, row, accepted_keys, before=None):
    """После принятия действующие сохранённые правки принятых объектов – история (dev15, план п. 1.4): равные
    принятому Hub – `delivered`, остальные – `saved`; у Fixed – с причиной. Отличием они больше не считаются.
    before – локальные данные объектов до принятия: операция доставки ищется по редакции решения, а принятие её
    поднимает (ревью кода dev15, круг 3)."""
    context = compare.ComparisonContext(c, row)
    stamp = now_iso()
    replaced = set()  # решения, заменённые состоянием Hub при этом принятии (для итога, план п. 1.4)
    rows = [dict(r) for r in c.execute("SELECT * FROM hub_sync_pending WHERE project_id=? AND hub_url=? AND app_id=?"
                                       " AND state IN ('pending','restored','saved') ORDER BY id", scope(row))]
    for p in rows:
        kind, key = p["entity_kind"], p["entity_key"]
        if (kind, key) not in accepted_keys:
            continue
        local = context.issue_local(key) if kind == "issue" else context.defect_local(key)
        accepted = (loads((local.get("state") or {}).get("confirmed_json"), {}) if kind == "issue"
                    else {"detail": loads((local.get("owner") or {}).get("confirmed_object_json"), {})})
        payload = loads(p["payload_json"], {})
        values = payload.get("values") or {}
        if kind == "issue":
            # заменённое решение (история) закрывается, только когда Hub принял ровно его, со сроком (ревью кода dev15)
            equal = history_matches(p["state"], values, hub_values(kind, accepted, key),
                                    (before or {}).get((kind, key)) or local)
        else:
            # как в reconcile_pending_in: доставлено – только если совпали и поля, и состав (ревью Codex, круг 3)
            links_match = (payload.get("links") is None
                           or {tuple(v) for v in payload["links"]} == linked_pairs(accepted["detail"]))
            equal = values == hub_values(kind, accepted) and links_match
        if p["state"] == "saved" and not equal:
            continue  # история остаётся историей; закрывается, только когда Hub принял то же решение
        fixed = kind == "issue" and compare.issue_values(accepted, key).get("status") == "Fixed"
        live = not equal and not fixed and values == pending_values(kind, local)
        reason = (i18n.N_("Совпадает с принятым состоянием Hub.") if equal
                  else i18n.N_("То же решение действует в редакторе и ждёт отправки – отдельно оно не считается.") if live
                  else i18n.N_("В Hub находка исправлена (Fixed): решение не отправляется.") if fixed
                  else i18n.N_("Заменена состоянием Hub при принятии; её можно восстановить."))
        payload.setdefault("history", []).append({"event": "settled", "at": stamp, "run_id": row["id"],
                                                   "reason": reason, "previous_state": p["state"]})
        c.execute("UPDATE hub_sync_pending SET state=?,resolved_at=?,payload_json=? WHERE id=?",
                  ("delivered" if equal else "saved", stamp if equal else None, dumps(payload), p["id"]))
        if not equal and not live:
            replaced.add(p["id"])
    return replaced


# После принятия у принятого объекта только «совпадает» и «не отправлено» с доказанным исходящим намерением (решение
# оператора при Hub без решения), а также доставленное решение, которое Hub потом снял («Отправлено в Hub» с отличием
# рядом, residual); иное – остаток, ошибка приложения (dev15, план п. 1.5)
AFTER_ACCEPT = ("matched", "pending", "sent_unaccepted", "coincident")


def residual(diff) -> bool:
    """Отличие, которого после принятия быть не должно. Доставленное решение, которого Hub сейчас не показывает, –
    «Отправлено в Hub» с группой отличия: Hub ответил «принято», а потом изменил находку сам. Это изменение на стороне
    Hub, а не ошибка приложения."""
    groups = set(diff.get("groups") or [])
    return bool(groups - set(AFTER_ACCEPT)) and (diff.get("delivery") or {}).get("state") != "sent"


def reconcile_pending_in(c, row):
    """Архивируем ложные ожидания по принятому Hub, сохраняя исходный payload и причину."""
    plan = reconcile_plan(c, row)
    for p, state, reason, accepted in plan:
        stamp = now_iso()
        payload = loads(p["payload_json"], {})
        payload.setdefault("history", []).append({"event": "reconciled", "at": stamp, "reason": reason,
                                                   "previous_state": p["state"], "accepted_hub": accepted})
        c.execute("UPDATE hub_sync_pending SET state=?,resolved_at=?,payload_json=? WHERE id=?",
                  (state, stamp, dumps(payload), p["id"]))
    return bool(plan)


def reconcile_plan(c, row, context=None, keys=None):
    """Сверка сохранённых правок без записи (dev15, план п. 2.1): какие строки закрываются, в какое состояние и почему.
    Её берут и пересчёт (`reconcile_pending_in` записывает переходы), и страницы – чтобы до записи не расходиться с
    сохранённым сравнением. keys – только эти объекты («вид», «ключ»)."""
    pending = [p for p in pending_in(c, row) if keys is None or (p["entity_kind"], p["entity_key"]) in keys]
    if not pending:
        return []
    context = context or compare.ComparisonContext(c, row)
    # сведения для правок прежних форматов – двумя общими запросами, а не запросом на строку (ревью кода dev15, круг 1:
    # страницы зовут сверку при каждом открытии)
    parsed = {p["id"]: loads(p["payload_json"], {}) for p in pending}
    runs, op_ids = set(), set()
    for p in pending:
        original = parsed[p["id"]].get("local") or {}
        if p["entity_kind"] == "issue" and "review_after_base" not in original:
            run_id = (original.get("state") or {}).get("confirmed_run_id")
            if run_id is not None:
                runs.add(int(run_id))
        intent = original.get("status_intent") or {}
        if p["entity_kind"] == "issue" and intent and "state" not in intent and intent.get("op_id"):
            op_ids.add(int(intent["op_id"]))
    applications = {(a["run_id"], a["entity_key"]): a for a in c.execute(
        "SELECT a.run_id,a.entity_key,a.presence,(a.before_json::json -> 'local' ->> 'review') AS review_json,"
        " (a.hub_json::json -> 'detail' ->> 'status') AS status FROM hub_sync_applications a"
        " JOIN hub_defect_sync_runs s ON s.id=a.run_id WHERE a.entity_kind='issue'"
        " AND s.project_id=? AND s.hub_url=? AND s.app_id=?"
        f" AND a.run_id IN ({','.join('?' * len(runs))})", (*scope(row), *sorted(runs)))} if runs else {}
    op_states = {o["id"]: o["state"] for o in c.execute(
        "SELECT id,state FROM hub_ops WHERE project_id=? AND hub_url=? AND app_id=? AND purpose='status'"
        f" AND id IN ({','.join('?' * len(op_ids))})", (*scope(row), *sorted(op_ids)))} if op_ids else {}
    out = []
    for p in pending:
        kind, key = p["entity_kind"], p["entity_key"]
        local = context.issue_local(key) if kind == "issue" else context.defect_local(key)
        accepted = (loads((local.get("state") or {}).get("confirmed_json"), {}) if kind == "issue"
                    else {"detail": loads((local.get("owner") or {}).get("confirmed_object_json"), {})})
        if not accepted.get("detail"):
            continue
        payload = parsed[p["id"]]
        original = payload.get("local") or {}
        if kind == "issue" and "review_after_base" not in original:
            run_id = (original.get("state") or {}).get("confirmed_run_id")
            application = applications.get((int(run_id), key)) if run_id is not None else None
            original = {**original, "review_after_base": compare.review_after_base(original, application)}
        if kind == "defect" and "draft_provenance" not in original:
            original = {**original, "draft_provenance": context.draft_provenance(original.get("owner") or {}, p["created_at"])}
        intent = original.get("status_intent") or {}
        if kind == "issue" and intent and "state" not in intent:
            state = op_states.get(int(intent["op_id"])) if intent.get("op_id") else None
            if state:
                original = {**original, "status_intent": {**intent, "state": state}}
        values = payload.get("values") or {}
        if kind == "issue":
            values = compare.normalized_decision(values)
            if original.get("review_after_base"):
                values = pending_values(kind, original)
        else:
            values = {**values, "command_text": compare.normalize_text(values.get("command_text", ""))}
        links_match = payload.get("links") is None or {tuple(v) for v in payload["links"]} == linked_pairs(accepted["detail"])
        equal = (history_matches(p["state"], values, hub_values(kind, accepted, key), local) if kind == "issue"
                 else values == hub_values(kind, accepted)) and links_match
        # сохранённая правка – историческое решение: совместимость с Hub её не закрывает (ревью 31.10); восстановленная
        # из истории (dev15) – новое действие оператора: отсутствие прежней базы её не отменяет (ревью Codex, круг 3)
        dirty, _ = pending_change(kind, original, payload.get("base") or {}, accepted, historical=True)
        dirty = dirty or bool(payload.get("restored"))
        if not equal and dirty:
            continue
        reason = (i18n.N_("Совпадает с принятым состоянием Hub.") if equal
                  else i18n.N_("Нет доказательства правки оператора после принятой базы."))
        out.append((p, "delivered" if equal else "discarded", reason, accepted))
    return out


def reconcile_pending(db, row):
    with db._tx() as c:
        if not reconcile_pending_in(c, row):
            return False
        for saved in c.execute("SELECT * FROM hub_defect_sync_runs WHERE project_id=? AND hub_url=? AND app_id=?"
                               " AND state='ready'", scope(row)).fetchall():
            compare.compare_in(c, dict(saved))
        return True


def mapped_finding(key, hub, existing=None):
    """Только предоставленные API-поля; файловые поля дополняют отсутствующие сведения."""
    typ, ident = key.split(":", 1)
    data = Finding(hub_id=ident, kind=KINDS[typ]).to_dict()
    if existing:
        data.update(loads(existing["data_json"], {}))
    detail, brief = hub.get("detail") or {}, hub.get("brief") or {}
    for source, target in (("status", "status"), ("fileName", "file"), ("language", "language"), ("tool", "tool")):
        if isinstance(detail.get(source), str):
            data[target] = detail[source]
    if isinstance(detail.get("codebase"), dict) and isinstance(detail["codebase"].get("name"), str):
        data["codebase"] = detail["codebase"]["name"]
    category = detail.get("category")
    if isinstance(category, dict) and isinstance(category.get("category"), str):
        data["rule"] = category["category"]
    line = detail.get("lineNumber")
    if str(line).isascii() and str(line).isdigit():
        data["line"] = int(line)
    severity = detail.get("severityDisplayName")
    if isinstance(severity, str) and severity.lower() in ("critical", "high", "medium", "low", "info"):
        data["severity"] = severity.lower()
    library = detail.get("library")
    if isinstance(library, dict):
        for source, target in (("name", "component"), ("version", "version")):
            if isinstance(library.get(source), str):
                data[target] = library[source]
    cwes = (category or {}).get("cwes") if isinstance(category, dict) else brief.get("cwes")
    if isinstance(cwes, list) and all(isinstance(v, dict) and isinstance(v.get("id"), str) for v in cwes):
        data["cwe"] = [v["id"] for v in cwes]
    return data


def materialize(c, row, item, hub, import_id):
    from app.triage import order_findings
    typ, ident = item["entity_key"].split(":", 1)
    old = c.execute("SELECT * FROM findings WHERE project_id=? AND hub_id=?", (row["project_id"], ident)).fetchone()
    if typ not in KINDS or (old and old["kind"] != KINDS[typ]):
        return None
    if absent(item):
        if old:
            c.execute("UPDATE findings SET missing=1,missing_since=COALESCE(missing_since,?) WHERE id=?", (now_iso(), old["id"]))
        return old["id"] if old else None
    if old:
        # Находка уже есть в приложении: её код, трасса, поля выгрузки и срез разбора (а через него – вердикт модели)
        # принадлежат приложению. Hub – источник истины только о своём состоянии: статус и присутствие (перезапись
        # полей и удаление срезов отвязали бы вердикты модели у всех находок).
        # Данные находки не меняются вовсе: от них зависят отпечатки решения, намерений и среза. Статус Hub хранится
        # в принятом состоянии (hub_issue_states) и показывается оттуда.
        c.execute("UPDATE findings SET missing=0,missing_since=NULL WHERE id=?", (old["id"],))
        return old["id"]
    data = mapped_finding(item["entity_key"], hub, old)
    pos = c.execute("SELECT COALESCE(MAX(pos),-1)+1 FROM findings WHERE project_id=?", (row["project_id"],)).fetchone()[0]
    projection = order_findings([Finding.from_dict(data)])[0]
    return c.execute("INSERT INTO findings(project_id,hub_id,import_id,pos,kind,severity,codebase,data_json,"
                     "group_key,urgent,group_key2,g2_cat,g2_file,g2_line) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)" " RETURNING id",
                     (row["project_id"], ident, import_id, pos, KINDS[typ], data["severity"], data["codebase"],
                      dumps(data), projection["group_key"], int(projection["urgent"]), *_group2_columns(data))).fetchone()[0]


def overlay_file_import(c, project_id):
    """После загрузки выгрузки из принятого Hub действует присутствие; статус Hub – в hub_issue_states. Код, трасса,
    поля и срез разбора находки – из выгрузки."""
    from app.hub_ops import hub_base
    setting = c.execute("SELECT value_json FROM settings WHERE key='hub_url'").fetchone()
    app = c.execute("SELECT hub_app_id FROM projects WHERE id=?", (project_id,)).fetchone()
    url = hub_base(loads(setting[0], "")) if setting else ""
    for state in c.execute("SELECT * FROM hub_issue_states WHERE project_id=? AND hub_url=? AND app_id=?",
                           (project_id, url, app[0])).fetchall():
        finding = c.execute("SELECT * FROM findings WHERE project_id=? AND hub_id=?", (project_id, state["issue_id"])).fetchone()
        if not finding or HUB_ISSUE_TYPE.get(finding["kind"]) != state["issue_type"]:
            continue
        missing = state["confirmed_presence"] == "absent"
        c.execute("UPDATE findings SET missing=?,missing_since=CASE WHEN ? <> 0 THEN COALESCE(missing_since,?) ELSE NULL END"
                  " WHERE id=?", (int(missing), int(missing), now_iso(), finding["id"]))


def withdraw_status_mark(c, row, ident, local):
    """Статус, подтверждённый записью приложения (отметка операции статуса) или принятый из Hub (отметка Pull), в Hub
    потом сняли (To verify, Open…): отметка «Внесено в Hub» снимается, решение оператора, его редакция и «Проверено»
    остаются – как и у предиката «статус уже стоит в Hub» (ревью dev16, B1). Ручная отметка и отметка дефекта с их
    отпечатками не трогаются (A3); отметка операции другого назначения (статуса или чтения синхронизации) – история
    того назначения, не трогается (HUB-AUD-02)."""
    if not local.get("entered_hub") or local.get("entered_origin") not in ("status", "hub_sync"):
        return
    # назначение подтверждающей операции – и у операции статуса, и у чтения синхронизации: отметка другого Hub или
    # приложения Hub – история того назначения, при возврате к нему она снова действует (ревью dev16, круг 3)
    if not c.execute("SELECT 1 FROM hub_ops WHERE id=? AND hub_url=? AND app_id IS NOT DISTINCT FROM ?",
                     (local.get("entered_op_id"), row["hub_url"], row["app_id"])).fetchone():
        return
    c.execute("UPDATE reviews SET entered_hub=0,entered_hub_at=NULL,entered_origin='',entered_op_id=NULL,"
              " entered_text_hash='',entered_parts='',updated_at=? WHERE project_id=? AND hub_id=?",
              (now_iso(), row["project_id"], ident))


def accept_issue(db, c, row, item, hub, finding_id, local=None):
    typ, ident = item["entity_key"].split(":", 1)
    presence = "absent" if absent(item) else "present"
    c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,finding_id,confirmed_json,"
              "confirmed_run_id,confirmed_presence,observed_json,observed_run_id,alignment,revision)"
              " VALUES (?,?,?,?,?,?,?,?,?,?,?,'agreed',1) ON CONFLICT(project_id,hub_url,app_id,issue_type,issue_id)"
              " DO UPDATE SET finding_id=excluded.finding_id,confirmed_json=excluded.confirmed_json,"
              " confirmed_run_id=excluded.confirmed_run_id,confirmed_presence=excluded.confirmed_presence,"
              " observed_json=excluded.observed_json,observed_run_id=excluded.observed_run_id,alignment='agreed',"
              " conflicts_json='[]',revision=hub_issue_states.revision+1",
              (*scope(row), typ, ident, finding_id, dumps(hub), row["id"], presence, dumps(hub), row["id"]))
    if finding_id is None:
        return
    review = c.execute("SELECT * FROM reviews WHERE project_id=? AND hub_id=?", (row["project_id"], ident)).fetchone()
    values = compare.issue_values(hub, item["entity_key"])
    status = values.get("status", "")
    # Hub – источник истины о своём решении по находке (ложное срабатывание, принятый риск) с основанием и сроком.
    # Нет такого решения в Hub (To verify, Open, Fixed…) – разбор приложения не трогается: решение оператора,
    # «Проверено», проверенный код и вердикт модели принадлежат приложению.
    verdict = {"False Positive": "false_positive", "Accepted risk": "risk_accepted"}.get(status, "")
    before = local or {}
    local = dict(review) if review else {}
    if presence != "present" or not verdict:
        own_hub_decision = compare.hub_verdict(local.get("decision"), local.get("final_verdict")) in (
            "false_positive", "risk_accepted")
        if presence == "present" and (local.get("decision_origin") == "hub_sync"
                                      or own_hub_decision and replaced_decision(before, hub, item["entity_key"])):
            # решение для Hub, которого в Hub нет (снято в Hub или не отправлено оператором): после принятия
            # приложение равно Hub (план dev15 п. 1.3) – решение снимается, прежнее уже
            # сохранено в историю; данные разбора остаются; отметка – ниже, по её происхождению (ревью dev16, A3)
            c.execute("UPDATE reviews SET decision='',final_verdict='',final_comment='',desired_hub_expired_at=NULL,"
                      " decision_origin='',decision_source_json='{}',revision=revision+1,updated_at=?"
                      " WHERE project_id=? AND hub_id=?", (now_iso(), row["project_id"], ident))
        if presence == "present":
            withdraw_status_mark(c, row, ident, local)
        return
    # основание, срок и отметка – только из проекции решения Hub (план dev15 п. 1.1): чужая или противоречащая
    # статусу ручная запись основанием не становится
    source = compare.decision_source(hub, item["entity_key"]) or {}
    reason = values.get("reason", "")
    same = (compare.hub_verdict(local.get("decision"), local.get("final_verdict")) == verdict
            and compare.normalized_decision({"status": status, "reason": local.get("final_comment"),
                                             "expiredAt": local.get("desired_hub_expired_at")}) == values
            # строка решения равна Hub, но у текущей редакции намерение отправки с другим телом – редакция растёт,
            # намерение отвязывается (ревью плана dev15, круг 2: ветка same)
            and not (before and replaced_decision(before, hub, item["entity_key"])))
    op_id = loads(item["source_ops_json"], {}).get("detail", {}).get("op_id")
    stamp = now_iso()
    if same:
        # в приложении то же решение, что в Hub: решение не меняется, но Hub подтвердил его присутствие. После восстановления копии операция
        # статуса снята, а Hub мог успеть её выполнить: отметку возвращает только это чтение. Уже стоящая отметка и её отпечаток не трогаются
        if source and not local.get("entered_hub"):
            c.execute("UPDATE reviews SET entered_hub=1,entered_hub_at=?,entered_origin='hub_sync',entered_op_id=?,entered_text_hash='',entered_parts='',"
                      "updated_at=? WHERE project_id=? AND hub_id=?", (stamp, op_id, stamp, row["project_id"], ident))
        elif not source:
            # решение то же, но своей записи с основанием в Hub нет (например, FP при manual=null): отметка «Внесено в
            # Hub» статуса или синхронизации снимается (план dev15 п. 1.2; ревью Codex круг 3)
            withdraw_status_mark(c, row, ident, local)
        return
    c.execute("INSERT INTO reviews(project_id,hub_id,updated_at) VALUES (?,?,?)"
              " ON CONFLICT(project_id,hub_id) DO NOTHING", (row["project_id"], ident, stamp))
    # подпись проекции решения Hub – по текущей эффективной идентичности находки (план dev17, п. 4.3, строка
    # accept_issue): и когда переход идентичности не выполнялся (первое принятие нового назначения при той же тройке)
    # Только у SCA: подпись SAST зависит от источника кода (папка, клон, ревизия), которого здесь нет – её не трогаем,
    # как до dev17 (ревью Codex шага 4, круг 1)
    finding = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    sig = (review_signature(package_identity.with_package(dict(finding)))
           if finding is not None and str(finding["kind"] or "").startswith("SCA") else None)
    # Меняются только поля решения Hub; проверка кода, «Проверено», вердикт модели и состав дефекта не трогаются.
    c.execute("UPDATE reviews SET decision='hub',final_verdict=?,final_comment=?,desired_hub_expired_at=?,"
              " decision_origin='hub_sync',decision_source_json=?,revision=revision+1,finding_sig=COALESCE(?,finding_sig),"
              " entered_hub=?,entered_hub_at=?,entered_origin='hub_sync',entered_op_id=?,"
              " entered_text_hash='',entered_parts='',decided_at=?,updated_at=? WHERE project_id=? AND hub_id=?",
              (verdict, reason, values.get("expiredAt"), dumps({"run_id": row["id"], "status": status}), sig,
               int(bool(source)), stamp if source else None, op_id, stamp, stamp, row["project_id"], ident))


def reconcile_defect_marks(c, row, owner, pairs):
    """Снимает подтверждения вне принятого состава, сохраняя решение и проверку кода."""
    if not owner:
        return []
    pairs = {(str(ident), typ) for ident, typ in pairs}
    reviews = c.execute(
        "SELECT r.*,f.kind AS finding_kind FROM reviews r"
        " JOIN findings f ON f.project_id=r.project_id AND f.hub_id=r.hub_id"
        " JOIN hub_defects d ON d.id=r.entered_defect_id"
        " JOIN hub_ops o ON o.id=r.entered_op_id"
        " WHERE r.project_id=? AND r.entered_origin='defect' AND r.entered_hub=1"
        " AND d.project_id=r.project_id AND d.hub_url=? AND d.app_id=? AND d.draft_owner_id=?"
        " AND o.project_id=r.project_id AND o.hub_url=d.hub_url AND o.app_id=d.app_id",
        (*scope(row), owner["id"])).fetchall()
    revoked = []
    for review in reviews:
        pair = (review["hub_id"], HUB_ISSUE_TYPE.get(review["finding_kind"]))
        if pair in pairs:
            continue
        revoked.append({k: review[k] for k in review.keys() if k != "finding_kind"})
        c.execute("UPDATE reviews SET entered_hub=0,entered_hub_at=NULL,entered_origin='',"
                  " entered_op_id=NULL,entered_defect_id=NULL,entered_defect_revision=0,"
                  " entered_decision_hash='',entered_text_hash='',entered_parts='',updated_at=?"
                  " WHERE project_id=? AND hub_id=?", (now_iso(), row["project_id"], review["hub_id"]))
    return revoked


def mark_dropped(c, owner, hub_ids, via):
    """Находки, выбывшие из дефекта, ждут решения оператора (она не должна потеряться).
    Находку, отмеченную внесённой в другой дефект или входящую в подтверждённый состав другого дефекта, пометка не
    трогает. Возвращает помеченные hub_id."""
    if not owner:
        return []
    elsewhere = set()  # другой дефект – того же Hub и приложения (дефект прежнего экземпляра Hub не в счёт)
    for other in c.execute("SELECT targets_json FROM hub_defects WHERE project_id=? AND state='done' AND draft_owner_id<>?"
                           " AND hub_url=? AND app_id=?", (owner["project_id"], owner["id"], owner["hub_url"], owner["app_id"])):
        elsewhere |= {(str(t.get("hub_id")), str(t.get("issue_type") or "")) for t in loads(other["targets_json"], [])
                      if t.get("hub_id")}
    stamp = now_iso()
    info = dumps({"defect_id": owner["id"], "number": owner.get("number"), "hub_defect_id": owner.get("hub_defect_id"),
                  "at": stamp, "via": via})
    marked = []
    for hub_id in sorted({str(h) for h in hub_ids}):
        finding = c.execute("SELECT kind FROM findings WHERE project_id=? AND hub_id=?", (owner["project_id"], hub_id)).fetchone()
        # в другом дефекте – только связь того же типа, что у самой находки (номер другого типа – другая находка Hub)
        if finding is None or (hub_id, HUB_ISSUE_TYPE.get(finding["kind"])) in elsewhere:
            continue
        review = c.execute("SELECT r.entered_hub, d.draft_owner_id FROM reviews r LEFT JOIN hub_defects d"
                           " ON d.id=r.entered_defect_id AND d.hub_url=? AND d.app_id=? WHERE r.project_id=? AND r.hub_id=?",
                           (owner["hub_url"], owner["app_id"], owner["project_id"], hub_id)).fetchone()
        if review is not None and review["entered_hub"] and review["draft_owner_id"] not in (None, owner["id"]):
            continue
        c.execute("INSERT INTO reviews(project_id,hub_id,revision,updated_at,defect_dropped) VALUES (?,?,0,?,?)"
                  " ON CONFLICT(project_id,hub_id) DO UPDATE SET defect_dropped=excluded.defect_dropped",
                  (owner["project_id"], hub_id, stamp, info))
        marked.append(hub_id)
    return marked


def family_pairs(c, owner):
    """Подтверждённый состав записи дефекта: пары (номер, тип) целей строк семейства в состоянии done (неудавшаяся
    привязка в составе не была)."""
    if not owner:
        return set()
    pairs = set()
    for member in c.execute("SELECT targets_json FROM hub_defects WHERE draft_owner_id=? AND state='done'", (owner["id"],)):
        pairs |= {(str(t.get("hub_id")), str(t.get("issue_type") or "")) for t in loads(member["targets_json"], [])
                  if t.get("hub_id")}
    return pairs


def dropped_ids(c, project_id, before, after):
    """Находки выбывших пар: ушла пара с типом самой находки (связь другого типа с тем же номером – другая находка
    Hub, локальная в дефект не входила)."""
    ids = set()
    for ident, typ in before - after:
        finding = c.execute("SELECT kind FROM findings WHERE project_id=? AND hub_id=?", (project_id, ident)).fetchone()
        if finding is not None and HUB_ISSUE_TYPE.get(finding["kind"]) == typ:
            ids.add(ident)
    return ids


def accept_defect(c, row, item, hub, local):
    """Принять дефект Hub (фаза 3); возвращает номер строки-владельца семейства (None – дефекта нет и не было)."""
    owner = local.get("owner")
    pairs = set() if absent(item) else linked_pairs(hub["detail"])
    before = family_pairs(c, owner)
    revoked = reconcile_defect_marks(c, row, owner, pairs)
    after = {(str(i), t) for i, t in pairs}
    dropped = mark_dropped(c, owner, dropped_ids(c, row["project_id"], before, after) | {r["hub_id"] for r in revoked},
                           "sync")
    history = {"run_id": row["id"], "revoked_confirmations": revoked, "dropped": dropped,
               "members_before": sorted(before)}
    if absent(item):
        if owner:
            # действующего состава нет: позднее последствие прежнего подтверждения не вернёт ни отметки, ни номера,
            # следующая синхронизация не пометит находки снова (ревью 31.10); состав до принятия – в истории.
            # Номер дефекта снимается с его ключей, как при принятии нового состава (кроме ключей других записей).
            family = c.execute("SELECT number_keys_json, targets_json FROM hub_defects WHERE draft_owner_id=?",
                               (owner["id"],)).fetchall()
            keys = {k for member in family for k in loads(member["number_keys_json"], [])}
            others = {k for r in c.execute("SELECT number_keys_json FROM hub_defects WHERE project_id=? AND draft_owner_id<>?"
                                           " AND state='done'", (row["project_id"], owner["id"]))
                      for k in loads(r["number_keys_json"], [])}
            protected = no_defect_keys(c, row["project_id"], {str(t.get("hub_id") or "") for member in family
                                                              for t in loads(member["targets_json"], [])})
            for key in keys - others - protected:
                c.execute("DELETE FROM defects WHERE project_id=? AND defect_key=? AND number=?",
                          (row["project_id"], key, owner["number"]))
            c.execute("UPDATE hub_defects SET error=?,targets_json='[]',number_keys_json='[]',effects_done=1"
                      " WHERE draft_owner_id=?",
                      (i18n.N_("Отсутствует в принятом списке Hub; запись и история сохранены."), owner["id"]))
            defect_drafts.history(c, owner, "hub_sync", details={**history, "presence": "absent",
                                                                 "number_keys_before": sorted(keys)})
        return owner["id"] if owner else None
    obj = hub["detail"]
    seen = _read_of(obj)
    # находкам принятого состава без решения – решение «из Hub»; цели ниже берут новую редакцию
    history["hub_decisions"] = defect_drafts.hub_decisions(c, row["project_id"], sorted(linked_pairs(obj)),
                                                           {"defect": item["entity_key"], "run_id": row["id"]})
    if not owner:
        stamp = now_iso()
        ident = c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,hub_defect_id,"
                          "created_at,updated_at) VALUES (?,?,'done','import',?,?,?,?,?)" " RETURNING id",
                          (row["project_id"], seen["kind"] or "Hub", row["hub_url"], row["app_id"],
                           item["entity_key"], stamp, stamp)).fetchone()[0]
        c.execute("UPDATE hub_defects SET draft_owner_id=id WHERE id=?", (ident,))
        owner = dict(c.execute("SELECT * FROM hub_defects WHERE id=?", (ident,)).fetchone())
    targets = []
    for ident, typ in sorted(linked_pairs(obj)):
        finding = c.execute("SELECT * FROM findings WHERE project_id=? AND hub_id=?", (row["project_id"], str(ident))).fetchone()
        review = c.execute("SELECT revision FROM reviews WHERE project_id=? AND hub_id=?", (row["project_id"], str(ident))).fetchone()
        targets.append({"hub_id": str(ident), "issue_id": ident, "issue_type": typ,
                        "revision": review[0] if review else 0,
                        "sig": finding_data_sig(finding["data_json"]) if finding and HUB_ISSUE_TYPE.get(finding["kind"]) == typ else "",
                        "entered_hash": "", "decision_hash": "", "entered_parts": ""})
    # Исторические физические строки остаются; действующий состав хранится один раз у владельца.
    old_keys = {k for member in local.get("family", []) for k in loads(member["number_keys_json"], [])}
    from app.db import Database
    # ключ находки «без дефекта» – ключ набора по умолчанию, за которым могут быть другие находки: номер с него не
    # снимается и через прежние ключи записи (ревью dev14; как одиночная сверка)
    protected = no_defect_keys(c, row["project_id"], {str(t.get("hub_id") or "") for member in local.get("family", [])
                                                      for t in loads(member.get("targets_json"), [])} | set(dropped))
    # кто уже держит номер дефекта – до снятия: если ID пропал из заголовка, номер остаётся именно у них (ADR-0138)
    holding = set(Database.defect_keys_with_number_in(c, row["project_id"], owner["number"])) if owner.get("number") else set()
    for key in old_keys - protected:
        c.execute("DELETE FROM defects WHERE project_id=? AND defect_key=? AND number=?", (row["project_id"], key, owner["number"]))
    keys = Database.defect_keys_of_findings_in(c, row["project_id"], [t["hub_id"] for t in targets if t["sig"]])
    # связь прочитана и принята – находка в дефекте, пометка «выбыла» снимается (перенос из другого дефекта в Hub)
    for t in targets:
        if t["sig"]:
            c.execute("UPDATE reviews SET defect_dropped='' WHERE project_id=? AND hub_id=?", (row["project_id"], t["hub_id"]))
    # ID пропал из заголовка в Hub – номер остаётся за дефектом, Push вернёт его (ADR-0138); новым ключам он так не выдаётся:
    # резерв занесённого дефекта мог совпасть с чужим номером
    lost = seen["number"] is None and seen.get("number_note") == NO_NUMBER and bool(owner.get("number"))
    number = owner.get("number") if lost else seen["number"]
    if number is not None:
        if lost:
            keys = set(keys) & holding
        for key in keys:
            c.execute("INSERT INTO defects(project_id,defect_key,number,updated_at,assigned_at) VALUES (?,?,?,?,?)"
                      " ON CONFLICT(project_id,defect_key) DO UPDATE SET number=excluded.number,updated_at=excluded.updated_at",
                      (row["project_id"], key, number, now_iso(), now_iso()))
        if dropped:  # номер этого дефекта у выбывших находок – даже если он не записан в number_keys
            from app.defect_drafts import in_some_set
            from app.hub_defects import release_number_in
            # находка «без дефекта» – ключ набора по умолчанию, за которым могут быть другие находки: не снимается,
            # как в одиночной сверке (ревью круг 7)
            release_number_in(c, owner, owner.get("number"), Database.defect_keys_of_findings_in(
                c, row["project_id"], in_some_set(c, row["project_id"], dropped)), set(keys))
    else:
        keys = set()
    c.execute("UPDATE hub_defects SET targets_json='[]',number_keys_json='[]',summary=?,command_text=?,number=?,"
              " priority=?,severity=?,"
              " error='',sync_json='',effects_done=1,updated_at=? WHERE draft_owner_id=?",
              (seen["summary"], seen["command_text"], number, level_name(obj.get("priority")),
               level_name(obj.get("severity")), now_iso(), owner["id"]))
    c.execute("UPDATE hub_defects SET targets_json=?,summary=?,command_text=?,draft_summary=?,draft_command_text=?,"
              " draft_fields_json=?,draft_fields_basis_json=?,confirmed_object_json=?,draft_revision=draft_revision+1,"
              " import_json=?,conflicts_json='[]',hub_link=?,number=?,number_keys_json=?,effects_done=1 WHERE id=?",
              (dumps(targets), seen["summary"], seen["command_text"], seen["summary"], seen["command_text"],
               dumps(defect_fields.fields_of(obj)), dumps(defect_fields.new_basis(obj, "accepted")), dumps(obj),
               dumps(seen), defect_link(row["hub_url"], row["app_id"], item["entity_key"]), number, dumps(sorted(keys)), owner["id"]))
    from app.hub_defects import clear_stale_update_in
    clear_stale_update_in(c, owner["id"])  # дефект приведён к Hub: прошлый отказ подготовки Push устарел
    # Смешанный состав Hub принимается как факт; отправка SCA по-прежнему проверяет свой набор.
    if owner["kind"] == "SCA":
        key, conflicts = defect_drafts.sca_identity(c, row["project_id"], targets)
        c.execute("UPDATE hub_defects SET sca_set_key=?,conflicts_json=? WHERE id=?", (key, dumps(conflicts), owner["id"]))
    defect_drafts.history(c, defect_drafts.owner_in(c, owner), "hub_sync", details={**history, "object": obj})
    return owner["id"]


def plan_in(c, row):
    data = hub_sync.passport(row)
    if row["state"] != "ready" or row["closed_at"] or not data.get("inventory_complete"):
        raise ValueError(i18n._("Применение доступно после полного чтения списков Hub."))
    items = [dict(r) for r in c.execute("SELECT * FROM hub_sync_items WHERE run_id=? ORDER BY entity_kind DESC,entity_key", (row["id"],))]
    if hub_sync.local_keys(c, row) - {(i["entity_kind"], i["entity_key"]) for i in items}:
        raise ValueError(i18n._("Локальные объекты изменились после сравнения: пересчитайте расхождения."))
    context = compare.ComparisonContext(c, row)
    selected, skipped = [], []
    for item in items:
        key, kind = item["entity_key"], item["entity_kind"]
        if key.startswith("local:"):
            continue
        if key.startswith("UNMAPPED:"):
            skipped.append({"kind": kind, "key": key, "reasons": [i18n._("Нет сопоставления с API Hub.")]})
            continue
        groups = set(loads(item["diff_json"], {}).get("groups", []))
        current = context.current(kind, key)
        sources = loads(item["source_ops_json"], {})
        local = context.issue_local(key) if kind == "issue" else context.defect_local(key)
        if versions.digest(local) != item["local_signature"]:
            raise ValueError(i18n._("Локальные данные изменились: пересчитайте расхождения перед применением."))
        if any(s["base_epoch"] != current["accepted_epoch"] or s["base_hash"] != current["accepted_hash"] for s in sources.values()):
            raise ValueError(i18n._("Принятая база изменилась после чтения: нужен новый обход Hub."))
        hub = loads(item["hub_json"], {})
        problems = (api.blocking(api.evidence_problems(hub, key, row["app_id"], api.Adapter(**data["adapter"])))
                    if kind == "issue" and not absent(item) else [])
        if problems and "incomplete" not in groups:
            raise ValueError(i18n._("Пригодность решения изменилась: пересчитайте расхождения. {problems}",
                                    problems="; ".join(i18n._(p) for p in problems)))
        if "stale" in groups or (not absent(item) and (groups & {"incomplete", "unmapped"} or problems)):
            # Несопоставленный состав дефекта сохраняется полностью, без выдуманных локальных находок.
            if kind != "defect" or groups & {"incomplete", "stale"}:
                # все блокирующие причины: противоречие Hub не вытесняет ошибку чтения и устаревание – по ним шаг
                # «Состояние Hub» решает, только ли противоречия Hub держат пропуск (ревью Codex dev14, круг 7)
                reasons = list(dict.fromkeys([*(i18n._(p) for p in problems), *loads(item["diff_json"], {}).get("notes", [])]))
                if groups & {"stale", "unmapped"}:
                    reasons.append(i18n._("Группа сравнения: {groups}.", groups=", ".join(sorted(groups & {"stale", "unmapped"}))))
                skipped.append({"kind": kind, "key": key, "reasons": reasons})
                continue
        selected.append(item)
    return selected, skipped


def preview(db, row):
    if row["applied_at"]:
        return {"applied": True, **loads(row["result_json"], {})}
    if row["state"] != "ready" or row["closed_at"] or not hub_sync.passport(row).get("inventory_complete"):
        return {"error": i18n._("Применение доступно после полного чтения списков Hub.")}
    selected, skipped = [], []
    # Страница использует уже сохранённое сравнение; полная проверка повторяется в транзакции применения.
    for item in db._all("SELECT * FROM hub_sync_items WHERE run_id=?", (row["id"],)):
        if item["entity_key"].startswith("local:"):
            continue
        groups = set(loads(item["diff_json"], {}).get("groups", []))
        blocked = ("stale" in groups or (not absent(item) and "incomplete" in groups)
                   or (item["entity_kind"] == "issue" and "unmapped" in groups))
        (skipped if blocked else selected).append(item)
    fingerprint = db.on_connection(lambda c: package_transition.transition_fingerprint(c, row["project_id"]))
    return {"count": len(selected), "skipped": len(skipped), "issues": sum(i["entity_kind"] == "issue" for i in selected),
            "defects": sum(i["entity_kind"] == "defect" for i in selected),
            # решения приложения, которые принятие заменит (план п. 1.4): посчитаны пересчётом по тому же правилу
            # `replaced_decision`, с тем же контекстом – страница второй раз проект не считает
            "replaced": hub_sync.passport(row).get("replaced") or {"count": 0, "items": []},
            # переход идентичности пакетов SCA, который выполнит применение (план dev17, п. 4.5): тот же расчёт
            "identity": preview_identity(db, row),
            "token": apply_token(row, fingerprint)}


def apply_token(row, fingerprint: str) -> str:
    """Токен подтверждения применения: прогон, его редакция и снимок, отпечаток входов перехода идентичности (план
    dev17, п. 4.5): изменилось что-либо из таблиц перехода между предпросмотром и применением – подтверждение
    недействительно."""
    return versions.digest([row["id"], row["revision"], row["snapshot_hash"], fingerprint])


class _DryRun(Exception):
    """Предпросмотр перехода закончен: транзакция откатывается."""


def identity_changes(c, row, issues) -> bool:
    """Применение изменит идентичность хотя бы одной находки SCA: сведения Hub о библиотеке у присутствующей находки
    дают другие колонки, чем записаны (без записи)."""
    scope_value = package_transition.scope_of(row["hub_url"], row["app_id"])
    for item in issues:
        typ, ident = item["entity_key"].split(":", 1)
        if typ not in ("SCA_S", "SCA_L") or absent(item):
            continue
        found = c.execute("SELECT data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
                          " WHERE project_id=? AND hub_id=? AND kind IN ('SCA','SCA-license')",
                          (row["project_id"], ident)).fetchone()
        if found is None:
            # новую находку создаст принятие – со сведениями Hub о библиотеке: итог перехода будет и в предпросмотре
            # (проверяющий агент ревью шага 4)
            if package_transition.library_of(loads(item["hub_json"], {})) is not None:
                return True
            continue
        new = package_transition.resolved_columns(loads(found["data_json"], {}), loads(item["hub_json"], {}), scope_value)
        if new != tuple(str(found[col] or "") for col in package_identity.PKG_COLUMNS):
            return True
    return False


def identity_changes_saved(db, row) -> bool:
    """Быстрая проверка по сохранённым объектам прогона, без снимка сравнения (страница синхронизации разбирает
    операции один раз, aud08): есть ли находка SCA, у которой сведения Hub о библиотеке дают другие колонки."""
    items = db._all("SELECT entity_key, hub_json, coverage_json FROM hub_sync_items WHERE run_id=? AND entity_kind='issue'"
                    " AND (entity_key LIKE 'SCA_S:%' OR entity_key LIKE 'SCA_L:%')", (row["id"],))
    if not items:
        return False
    found = {str(r["hub_id"]): r for r in db._all(
        "SELECT hub_id, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
        " WHERE project_id=? AND kind IN ('SCA','SCA-license')", (row["project_id"],))}
    scope_value = package_transition.scope_of(row["hub_url"], row["app_id"])
    for item in items:
        local = found.get(item["entity_key"].split(":", 1)[1])
        if absent(item):
            continue
        if local is None:  # новая находка со сведениями Hub о библиотеке – как в identity_changes
            if package_transition.library_of(loads(item["hub_json"], {})) is not None:
                return True
            continue
        new = package_transition.resolved_columns(loads(local["data_json"], {}), loads(item["hub_json"], {}), scope_value)
        if new != tuple(str(local[col] or "") for col in package_identity.PKG_COLUMNS):
            return True
    return False


def preview_identity(db, row) -> dict | None:
    """Итог перехода идентичности пакетов, который выполнит применение: фазы 1 и 2 той же транзакцией, которая
    откатывается (предпросмотр равен применению по построению). None – переход ничего не меняет."""
    if not identity_changes_saved(db, row):
        return None
    holder: dict = {}
    try:
        with db._tx() as c:
            current = hub_sync.run_in(c, row["id"])
            selected, _ = plan_in(c, current)
            issues = [i for i in selected if i["entity_kind"] == "issue"]
            if not identity_changes(c, current, issues):
                raise _DryRun
            context = compare.ComparisonContext(c, current)
            identity_before = package_transition.snapshot(c, current["project_id"])
            import_id = _import_row(c, current, selected)
            _accept_issues(db, c, current, issues, context, import_id, {}, set())
            holder["summary"] = package_transition.rebind_packages(
                c, current["project_id"], current["id"], identity_before,
                package_transition.snapshot(c, current["project_id"]))
            # третья фаза – как в применении: она пересчитывает ключ набора по принятому составу, и сводка «без
            # единственного набора» досчитывается после неё (остаток шага 4)
            _accept_defects(c, current, [i for i in selected if i["entity_kind"] == "defect"], context,
                            holder["summary"], {}, set())
            raise _DryRun
    except _DryRun:
        pass
    except ValueError as e:
        return {"error": str(e)}
    return holder.get("summary")


def _accept_defects(c, row, defect_items, context, identity, before, saved_ids) -> None:
    """Фаза 3 принятия – дефекты по снимку после перехода идентичности; затем сводка перехода «без единственного
    набора» – по итогу всей последовательности (план dev17, остаток шага 4). Одна функция для применения и
    предпросмотра: предпросмотр равен применению по построению."""
    # семейства и number_keys_json – уже после переноса: иначе прежние ключи снимались бы по устаревшему снимку и
    # перенесённые строки defects оставались без владельца; исходные данные – по исходному снимку (история)
    fresh = compare.ComparisonContext(c, row) if (identity or {}).get("findings") else context
    accepted = []
    for item in defect_items:
        key = item["entity_key"]
        hub, base = loads(item["hub_json"], {}), loads(item["base_json"], {})
        local = context.defect_local(key)
        before[("defect", key)] = local
        if saved_id := remember_pending(c, row, item, local, base, hub, state="saved"):
            saved_ids.add(saved_id)
        accepted.append(accept_defect(c, row, item, hub, fresh.defect_local(key)))
        _accepted(c, row, item, hub, local, base)
    package_transition.settle_set_keys(c, row["project_id"], identity, [o for o in accepted if o is not None])


def _import_row(c, row, selected) -> int:
    return c.execute("INSERT INTO imports(project_id,filename,format,total,source_kind,sync_run_id,created_at)"
                     " VALUES (?,'','hub_api_json',?,'hub_sync',?,?)" " RETURNING id",
                     (row["project_id"], sum(i["entity_kind"] == "issue" for i in selected), row["id"],
                      now_iso())).fetchone()[0]


def _accept_issues(db, c, row, issues, context, import_id, before, saved_ids) -> None:
    """Фаза 1 применения (план dev17, п. 4.5): находки – присутствие, идентичность пакета по сведениям Hub о библиотеке
    и проекция решения Hub. `before` накапливает исходные локальные данные по исходному снимку сравнения."""
    scope_value = package_transition.scope_of(row["hub_url"], row["app_id"])
    for item in issues:
        key = item["entity_key"]
        hub, base = loads(item["hub_json"], {}), loads(item["base_json"], {})
        local = context.issue_local(key)
        before[("issue", key)] = local
        if saved_id := remember_pending(c, row, item, local, base, hub, state="saved"):
            saved_ids.add(saved_id)
        finding_id = materialize(c, row, item, hub, import_id)
        if finding_id is not None and not absent(item) and key.split(":", 1)[0] in ("SCA_S", "SCA_L"):
            # идентичность – до проекции решения: подпись проекции Hub пишется по новой тройке
            package_transition.apply_library(c, finding_id, hub, scope_value)
        accept_issue(db, c, row, item, hub, finding_id, local)
        _accepted(c, row, item, hub, local, base)


def _accepted(c, row, item, hub, local, base) -> None:
    """Принятая версия объекта и строка истории применения."""
    kind, key = item["entity_kind"], item["entity_key"]
    accepted_hash = versions.digest(hub.get("detail") if kind == "defect" and not absent(item) else hub)
    c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,"
              "accepted_hash,accepted_source_json) VALUES (?,?,?,?,?,1,?,?)"
              " ON CONFLICT(project_id,hub_url,app_id,entity_kind,entity_key) DO UPDATE SET"
              " accepted_epoch=hub_entity_versions.accepted_epoch+1,accepted_hash=excluded.accepted_hash,"
              " accepted_source_json=excluded.accepted_source_json",
              (*scope(row), kind, key, accepted_hash, dumps({"origin": "hub_sync", "run_id": row["id"]})))
    current = versions.current(c, *scope(row), kind, key)
    c.execute("INSERT INTO hub_sync_applications VALUES (?,?,?,?,?,?,?,?)",
              (row["id"], kind, key, dumps({"base": base, "local": local}), dumps(hub),
               "absent" if absent(item) else "present", current["accepted_epoch"], current["accepted_hash"]))


def card_context(db, project_id, hub_url, app_id, kind, key):
    row = {"project_id": project_id, "hub_url": hub_url, "app_id": app_id}
    pending = db.on_connection(lambda c: [p for p in pending_in(c, row) if (p["entity_kind"], p["entity_key"]) == (kind, key)])
    application = db._one("SELECT a.*,s.applied_at FROM hub_sync_applications a JOIN hub_defect_sync_runs s ON s.id=a.run_id"
                          " WHERE s.project_id=? AND s.hub_url=? AND s.app_id=? AND a.entity_kind=? AND a.entity_key=?"
                          " ORDER BY a.run_id DESC LIMIT 1", (*scope(row), kind, key))
    hub = loads(application["hub_json"], {}) if application else {}
    values = hub_values(kind, hub, key)
    if kind == "defect" and "status" in (hub.get("detail") or {}):
        values["status"] = hub["detail"]["status"]
        if _read_of(hub["detail"])["text_note"]:
            values["description"] = hub["detail"].get("description", "")
    return {"pending": pending, "accepted": application, "values": values, "kind": kind}


def pending_context(db, row, pending_id, *, reconcile=True):
    if reconcile:
        reconcile_pending(db, row)
    pending = db._one("SELECT * FROM hub_sync_pending WHERE id=? AND project_id=? AND hub_url=? AND app_id=?",
                      (pending_id, *scope(row)))
    if not pending:
        raise ValueError(i18n._("Неотправленная правка не найдена в текущем назначении Hub."))
    def current(c):
        ctx = compare.ComparisonContext(c, row)
        return ctx.issue_local(pending["entity_key"]) if pending["entity_kind"] == "issue" else ctx.defect_local(pending["entity_key"])
    local = db.on_connection(current)
    payload = loads(pending["payload_json"], {})
    accepted = (loads((local.get("state") or {}).get("confirmed_json"), {}) if pending["entity_kind"] == "issue"
                else {"detail": loads((local.get("owner") or {}).get("confirmed_object_json"), {})})
    return {"pending": pending, "payload": payload, "current": local,
            "accepted_values": hub_values(pending["entity_kind"], accepted, pending["entity_key"]),
            "current_values": pending_values(pending["entity_kind"], local),
            "confirmation": versions.digest([pending, local])}


def restore(db, row, pending_id, token, *, discard=False, check=None):
    with db._tx() as c:
        if check:
            check(c)
        reconcile_pending_in(c, row)
        ctx = pending_context(db, row, pending_id, reconcile=False)
        p, payload = ctx["pending"], ctx["payload"]
        allowed = ("pending", "saved", "restored") if discard else ("pending", "saved")
        if p["state"] not in allowed or token != ctx["confirmation"]:
            raise ValueError(i18n._("Правка или карточка изменились: откройте подтверждение заново."))
        local = ctx["current"]
        if discard:
            note = ""
            if p["state"] == "restored":
                note = _discard_restored_in(c, row, p, payload, local)
            payload.setdefault("history", []).append({"event": "discarded", "at": now_iso(), "previous_state": p["state"],
                                                       **({"reason": note} if note else {})})
            c.execute("UPDATE hub_sync_pending SET state='discarded',resolved_at=?,payload_json=? WHERE id=?",
                      (now_iso(), dumps(payload), pending_id))
            return i18n._(note) if note else note
        original = payload["local"]
        if p["entity_kind"] == "issue":
            f, r = local.get("finding"), original.get("review") or {}
            if not f:
                raise ValueError(i18n._("Сопоставленной находки нет. Намерение сохранено."))
            accepted = loads((local.get("state") or {}).get("confirmed_json"), {})
            if compare.issue_values(accepted, p["entity_key"]).get("status") == "Fixed":
                # отправить решение по исправленной находке нельзя – Hub не меняет её статус (dev15, план п. 1.4)
                raise ValueError(i18n._("В Hub находка исправлена (Fixed): решение отправить нельзя, правка остаётся в истории."))
            current = local.get("review") or {}
            # решение из Hub или снятое в Hub (решения нет) правку не держит; держит только своё решение оператора
            if (current.get("decision_origin") not in ("hub_sync", defect_drafts.HUB_DEFECT_ORIGIN)
                    and (current.get("decision") or current.get("final_verdict"))):
                raise ValueError(i18n._("В редакторе уже есть локальное решение. Сначала сохраните его применением синхронизации."))
            # «Проверено» и привязка к вердикту модели – прикладные данные: возврат правки их не сбрасывает
            db._save_review_in(c, row["project_id"], f["hub_id"], decision=r.get("decision", ""),
                               final_verdict=r.get("final_verdict", ""), final_comment=r.get("final_comment", ""),
                               final_fix=r.get("final_fix", ""), kapo_state=r.get("kapo_state", ""),
                               reviewed=bool(current.get("reviewed")), verdict_id=current.get("verdict_id"))
            c.execute("UPDATE reviews SET desired_hub_expired_at=?,decision_origin='operator' WHERE project_id=? AND hub_id=?",
                      ((original.get("status_intent") or {}).get("body", {}).get("expiredAt", r.get("desired_hub_expired_at")),
                       row["project_id"], f["hub_id"]))
        else:
            owner = local.get("owner")
            if not owner:
                raise ValueError(i18n._("Сопоставленного дефекта нет. Намерение сохранено."))
            problem = defect_drafts.edit_problem(c, owner)
            if problem:
                raise ValueError(problem)
            base = loads(owner["confirmed_object_json"], {})
            if pending_values("defect", local) != hub_values("defect", {"detail": base}):
                raise ValueError(i18n._("В редакторе уже есть локальная правка. Сначала сохраните её применением синхронизации."))
            draft = original["owner"]
            basis = defect_fields.basis_of(owner)
            basis["references"] = defect_fields.basis_of(draft)["references"]
            c.execute("UPDATE hub_defects SET draft_summary=?,draft_command_text=?,draft_fields_json=?,"
                      " draft_fields_basis_json=?,draft_revision=draft_revision+1 WHERE id=?",
                      (draft["draft_summary"], draft["draft_command_text"], draft["draft_fields_json"], dumps(basis), owner["id"]))
            defect_drafts.history(c, defect_drafts.owner_in(c, owner), "edit", details={"pending_id": pending_id})
        # редакция и подпись восстановленного решения: «Отбросить» снимет его, только если в редакторе всё ещё оно
        # (ревью плана dev15, круг 2: иначе отбрасывание стёрло бы более новую работу оператора)
        payload["restored"] = _editor_mark(c, row, p["entity_kind"], p["entity_key"])
        payload.setdefault("history", []).append({"event": "restored", "at": now_iso(), "previous_state": p["state"]})
        c.execute("UPDATE hub_sync_pending SET state='restored',resolved_at=NULL,payload_json=? WHERE id=?",
                  (dumps(payload), pending_id))


def _editor_mark(c, row, kind, key):
    """Редакция и подпись того, что сейчас в редакторе: решения находки или черновика дефекта."""
    if kind == "issue":
        r = c.execute("SELECT revision,decision,final_verdict,final_comment,desired_hub_expired_at,decision_origin"
                      " FROM reviews WHERE project_id=? AND hub_id=?", (row["project_id"], key.split(":", 1)[1])).fetchone()
        return {"revision": r["revision"], "sig": versions.digest(dict(r))} if r else {}
    context = compare.ComparisonContext(c, row)
    owner = context.owners.get(key) or {}
    if not owner:
        return {}
    return {"revision": owner["draft_revision"], "sig": versions.digest(
        [owner["draft_summary"], owner["draft_command_text"], owner["draft_fields_json"]])}


def _discard_restored_in(c, row, p, payload, local):
    """Отбросить восстановленную правку: в редакторе всё ещё она – вернуть принятую проекцию Hub; там уже другая
    работа оператора – её не трогать (текст для страницы)."""
    kind, key = p["entity_kind"], p["entity_key"]
    mark = payload.get("restored") or {}
    if not mark or _editor_mark(c, row, kind, key) != mark:
        return i18n.N_("В редакторе уже другое решение – оно не изменено; отброшена только сохранённая правка.")
    stamp = now_iso()
    if kind == "issue":
        ident = key.split(":", 1)[1]
        intent = local.get("status_intent") or {}
        if intent.get("state") in ("queued", "taken", "unknown"):
            raise ValueError(i18n._("Отправка этого решения в Hub не завершена: дождитесь её исхода, затем отбросьте правку."))
        state = local.get("state") or {}
        application = c.execute("SELECT accepted_epoch,accepted_hash FROM hub_sync_applications WHERE run_id=?"
                                " AND entity_kind='issue' AND entity_key=?", (state.get("confirmed_run_id"), key)).fetchone()
        now_version = versions.current(c, *scope(row), "issue", key)
        moved = not application or any(application[k] != now_version[k] for k in ("accepted_epoch", "accepted_hash"))
        if intent.get("state") == "done" or moved:
            # восстановленное решение отправлено, или Hub с тех пор подтвердил другое состояние: принятое наблюдение
            # устарело – редактор не откатывается к нему (ревью кода dev15, круг 2)
            return i18n.N_("Решение уже отправлено в Hub или Hub подтвердил новое состояние – в редакторе оставлено как есть; "
                           "отброшена только сохранённая правка.")
        accepted = loads(state.get("confirmed_json"), {})
        values = compare.issue_values(accepted, key)
        verdict = {"False Positive": "false_positive", "Accepted risk": "risk_accepted"}.get(values.get("status"), "")
        if verdict:
            # как при принятии (accept_issue): решение Hub, его источник и отметка «Внесено в Hub» по своей записи Hub –
            # восстановление сняло отметку, отбрасывание её возвращает (ревью Kimi dev15, круг 3)
            source = compare.decision_source(accepted, key)
            state = local.get("state") or {}
            # отметка синхронизации действует только с подтверждающей операцией (db._ENTERED_HUB_SQL) – как при
            # принятии, это операция чтения принятого наблюдения (ревью кода dev15, круг 1)
            item = c.execute("SELECT source_ops_json FROM hub_sync_items WHERE run_id=? AND entity_kind='issue'"
                             " AND entity_key=?", (state.get("confirmed_run_id"), key)).fetchone()
            op_id = (loads(item["source_ops_json"], {}).get("detail") or {}).get("op_id") if item else None
            mark = bool(source and op_id)
            c.execute("UPDATE reviews SET decision='hub',final_verdict=?,final_comment=?,desired_hub_expired_at=?,"
                      " decision_origin='hub_sync',decision_source_json=?,revision=revision+1,"
                      " entered_hub=?,entered_hub_at=?,entered_origin=?,entered_op_id=?,entered_text_hash='',"
                      " entered_parts='',updated_at=? WHERE project_id=? AND hub_id=?",
                      (verdict, values.get("reason", ""), values.get("expiredAt"),
                       dumps({"run_id": state.get("confirmed_run_id"), "status": values.get("status")}),
                       int(mark), stamp if mark else None, "hub_sync" if mark else "", op_id if mark else None,
                       stamp, row["project_id"], ident))
        else:
            c.execute("UPDATE reviews SET decision='',final_verdict='',final_comment='',desired_hub_expired_at=NULL,"
                      " decision_origin='',revision=revision+1,updated_at=? WHERE project_id=? AND hub_id=?",
                      (stamp, row["project_id"], ident))
        return ""
    owner = local.get("owner") or {}
    # та же проверка, что у обычной правки и восстановления: при незавершённой отправке черновик не меняется
    # (ревью кода dev15, круг 1)
    problem = defect_drafts.edit_problem(c, owner) if owner else i18n._("Сопоставленного дефекта нет.")
    if problem:
        raise ValueError(problem)
    obj = loads(owner.get("confirmed_object_json"), {})
    seen = _read_of(obj)
    c.execute("UPDATE hub_defects SET draft_summary=?,draft_command_text=?,draft_fields_json=?,"
              " draft_revision=draft_revision+1 WHERE id=?",
              (seen["summary"], seen["command_text"], dumps(defect_fields.fields_of(obj)), owner["id"]))
    defect_drafts.history(c, defect_drafts.owner_in(c, owner), "hub_sync", details={"pending_id": p["id"], "discarded": True})
    return ""


def apply(db, run_id, token, *, check=None):
    with db._tx() as c:
        row = hub_sync.run_in(c, run_id)
        if check:
            check(c)
        if row["applied_at"]:
            result = loads(row["result_json"], {})
            if token != result.get("token"):
                raise ValueError(i18n._("Подтверждение относится к другому результату."))
            if reconcile_pending_in(c, row):
                compare.compare_in(c, row)
            return loads(hub_sync.run_in(c, run_id)["result_json"], {})
        # отпечаток входов перехода – до любой записи этой транзакции (план dev17, п. 4.5)
        if token != apply_token(row, package_transition.transition_fingerprint(c, row["project_id"])):
            # точная причина, если она есть: локальные данные или принятая база изменились – пересчитать расхождения
            plan_in(c, row)
            raise ValueError(i18n._("Итог изменился: откройте подтверждение применения заново."))
        # чтение модели шаблона – диагностика без последствий (ADR-0139): применение не ждёт его
        if c.execute("SELECT 1 FROM hub_ops WHERE project_id=? AND hub_url=? AND app_id=? AND purpose!='sync_read'"
                     " AND state IN ('queued','taken','unknown')"
                     " AND NOT (purpose = 'read' AND targets_json LIKE '%DEFECT_TEMPLATE_MODEL%') LIMIT 1", scope(row)).fetchone():
            raise ValueError(i18n._("Есть незавершённая операция Hub: сначала установите её результат."))
        selected, skipped = plan_in(c, row)
        if not selected:
            raise ValueError(i18n._("Нет пригодных объектов для применения."))
        context = compare.ComparisonContext(c, row)
        saved_ids, before = set(), {}
        import_id = _import_row(c, row, selected)
        issues = [i for i in selected if i["entity_kind"] == "issue"]
        defect_items = [i for i in selected if i["entity_kind"] == "defect"]
        # фаза 1 – находки; фаза 2 – переход идентичности пакетов; фаза 3 – дефекты по новому снимку (план dev17, п. 4.5)
        identity_before = package_transition.snapshot(c, row["project_id"])
        _accept_issues(db, c, row, issues, context, import_id, before, saved_ids)
        identity = package_transition.rebind_packages(c, row["project_id"], run_id, identity_before,
                                                      package_transition.snapshot(c, row["project_id"]))
        _accept_defects(c, row, defect_items, context, identity, before, saved_ids)
        accepted_keys = {(i["entity_kind"], i["entity_key"]) for i in selected}
        saved_ids |= settle_saved_in(c, row, accepted_keys, before)
        saved = sorted(r[0] for r in c.execute(
            f"SELECT id FROM hub_sync_pending WHERE state='saved' AND id IN ({','.join('?' * len(saved_ids))})",
            tuple(saved_ids))) if saved_ids else []
        result = {"token": token, "count": len(selected), "skipped": skipped, "pending": len(pending_in(c, row)),
                  "saved": len(saved), "applied_at": now_iso(), "identity": identity}
        c.execute("UPDATE hub_defect_sync_runs SET applied_at=?,result_json=? WHERE id=?", (result["applied_at"], dumps(result), run_id))
        compare.compare_in(c, hub_sync.run_in(c, run_id))
        hub_sync.resync_done_in(c, row, skipped)
        result["pending"] = hub_sync.passport(hub_sync.run_in(c, run_id)).get("groups", {}).get("pending", 0)
        # остаток после принятия – по сравнению этого же прогона, в той же транзакции (план п. 1.5)
        result["residue"] = sorted(f"{r['entity_kind']}:{r['entity_key']}" for r in c.execute(
            "SELECT entity_kind,entity_key,diff_json FROM hub_sync_items WHERE run_id=?", (run_id,))
            if (r["entity_kind"], r["entity_key"]) in accepted_keys and residual(loads(r["diff_json"], {})))
        c.execute("UPDATE hub_defect_sync_runs SET result_json=? WHERE id=?", (dumps(result), run_id))
        db._touch(c, row["project_id"], result["applied_at"])
        return result
