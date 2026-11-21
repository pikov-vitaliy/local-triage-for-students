"""Состояние находок и дефектов проекта относительно Hub – для страниц (0.10.0.dev15, бэклог 88).

Неотправленное видно везде: оператор работает в основном списком находок, и сразу видна картина – что
отправлено, что не отправлено, что синхронизировано, что не синхронизировано; всегда понятно, всё ли хорошо с
проектом, есть ли проблемы с синхронизацией с Hub, принял ли Hub запись или нет.

Отметка dev14 выводила состояние своей логикой и расходилась с синхронизацией. Здесь своей логики сравнения нет:
объект считает функция синхронизации `hub_sync_compare.evaluate` по текущим локальным данным. Сохранённое сравнение
прогона берётся как есть, только если с тех пор не изменились ни локальные данные, ни наблюдение (тот же признак, что
у `snapshot_current`); иначе объект пересчитывается той же функцией. Сохранённые правки сверяются тем же расчётом, что
у пересчёта (`hub_pull.reconcile_plan`), без записи. Запросов к Hub нет, в базу ничего не пишется.

Прогон: объекты – по последнему прогону текущего назначения (адрес Hub и номер приложения проекта) со сравнением; идёт
ли чтение сейчас – по последнему прогону вообще. Объект без наблюдения (Hub не читался, объекта нет в прочитанном) –
только чтение и отправка: о состоянии Hub ничего не утверждается.
"""

import time
from urllib.parse import urlencode

from app import hub_entity_versions as versions, hub_sync_api as api, hub_sync_compare as compare
from app.db import dumps, loads
from app.hub_ops import hub_base
from app.hub_status import HUB_ISSUE_TYPE

READ_LABELS = {
    "never": "Hub не читался",
    "missing": "Нет в последнем чтении Hub",
    "stale": "Чтение Hub устарело",
    "incomplete": "Чтение Hub неполное",
}
# отбор «Не отправлено в Hub»: решение для Hub есть, а в Hub его нет или исход не установлен
UNSENT = ("unsent", "refused", "unconfirmed", "queued", "unsendable")
# видимые счётчики отправки: «не отправлено» – только то, что в Hub не уходило; ждущее исполнителя, неподтверждённое
# (запись могла состояться), отказ Hub и исправленное в Hub – своими словами (ревью кода dev15, круг 10). Общий признак
# UNSENT – для отбора «не отправлено в Hub» и выделения строки
COUNT_LABELS = {"unsent": "не отправлено в Hub", "queued": "ждёт исполнителя", "unconfirmed": "без подтверждения",
                "refused": "Hub не принял", "unsendable": "в Hub исправлено и не отправится"}
EQUAL_GROUPS = ("matched", "coincident")
DELIVERY_TONES = {"unsent": "warn", "refused": "warn", "unconfirmed": "warn", "queued": "warn",
                  "unsendable": "muted", "sent": "muted"}


def project_states(db, project: dict, hub_url: str, keys=None) -> dict:
    """Состояние объектов проекта относительно Hub. keys – ключи находок («ТИП:номер»): карточка считает свою находку,
    а не проект (план п. 2.3); без них – весь проект и сводка для обзора."""
    base, app_id = hub_base(hub_url or ""), project.get("hub_app_id")
    if not base or not app_id:
        return {"target": False, "items": {}, "by_hub_id": {}, "run": None, "latest": None, "summary": None}
    return db.on_connection(lambda c: _states_in(c, project, base, app_id, keys))


def issue_key(finding: dict) -> str:
    """Ключ находки в синхронизации – как у `hub_sync.local_keys`."""
    typ = HUB_ISSUE_TYPE.get(finding.get("kind"))
    hub_id = str(finding.get("hub_id") or "")
    return f"{typ}:{hub_id}" if typ and hub_id.isascii() and hub_id.isdigit() else f"UNMAPPED:{hub_id}"


def _runs(c, pid, base, app_id):
    latest = c.execute("SELECT id,state,created_at,applied_at,closed_at FROM hub_defect_sync_runs WHERE project_id=?"
                       " AND hub_url=? AND app_id=? ORDER BY id DESC LIMIT 1", (pid, base, app_id)).fetchone()
    # последний прогон со сравнением – среди всех прогонов назначения, пачками от новых к старым: прерванные прогоны
    # после удачного чтения его не скрывают (ревью кода dev15, круг 5); паспорт разбирается в приложении, а не
    # приведением в базе, – испорченный паспорт одного прогона страницу не роняет
    compared, before = None, None
    while compared is None:
        batch = c.execute("SELECT id,run_json FROM hub_defect_sync_runs WHERE project_id=? AND hub_url=? AND app_id=?"
                          + (" AND id<?" if before is not None else "") + " ORDER BY id DESC LIMIT 50",
                          (pid, base, app_id, *(() if before is None else (before,)))).fetchall()
        if not batch:
            break
        compared = next((r["id"] for r in batch if (loads(r["run_json"], {}) or {}).get("comparison_complete")), None)
        before = batch[-1]["id"]
    row = (dict(c.execute("SELECT * FROM hub_defect_sync_runs WHERE id=?", (compared,)).fetchone())
           if compared is not None else None)
    return (dict(latest) if latest else None), row


def _links(c, run_id, with_issues):
    """`hub_sync_compare.run_links` без разбора каждого hub_json в приложении: списки дефектов и defectId находок –
    выборкой полей в базе (план п. 2.3: на тысячах находок разбор всех наблюдений не укладывается в бюджет страницы).
    Связи находок нужны только пересчёту дефекта."""
    listed = {r[0] for r in c.execute("SELECT entity_key FROM hub_sync_items WHERE run_id=? AND entity_kind='defect'"
                                      " AND (hub_json::json -> 'brief') IS NOT NULL", (run_id,))}
    issue_links, known = {}, set()
    if with_issues:
        for r in c.execute("SELECT entity_key,(hub_json::json -> 'brief' -> 'defectId')::text AS defect FROM hub_sync_items"
                           " WHERE run_id=? AND entity_kind='issue' AND (hub_json::json -> 'brief' -> 'defectId') IS NOT NULL",
                           (run_id,)):
            known.add(r["entity_key"])
            value = loads(r["defect"], None)
            if value:
                issue_links.setdefault(str(value), set()).add(r["entity_key"])
    return {"issue_links": issue_links, "known_links": known, "listed_defects": listed}


def _states_in(c, project, base, app_id, keys):
    from app import hub_pull, hub_sync
    pid = project["id"]
    latest, row = _runs(c, pid, base, app_id)
    pseudo = row is None
    if pseudo:  # Hub не читался: контекст текущего назначения без прогона
        row = {"id": None, "project_id": pid, "hub_url": base, "app_id": app_id, "run_json": "{}", "state": "",
               "applied_at": None, "closed_at": None, "created_at": None}
    wanted = None if keys is None else {("issue", str(k)) for k in keys}
    context = compare.ComparisonContext(c, row, only=None if wanted is None else [k for _, k in wanted])
    if not pseudo:
        # строки, которые сверка закроет при следующем пересчёте, страница уже не считает ждущими (план п. 2.1)
        context.drop_pending([p["id"] for p, *_ in hub_pull.reconcile_plan(c, row, context, wanted)])
    local = hub_sync.local_keys(c, row)
    if wanted is not None:
        local &= wanted
    items = {}
    if not pseudo:
        sql = ("SELECT entity_kind,entity_key,local_signature,source_ops_json,diff_json,stale_reason,"
               "(hub_json='{}') AS unread FROM hub_sync_items WHERE run_id=?")
        args = [row["id"]]
        if wanted is not None:
            names = sorted(k for _, k in wanted)
            sql += f" AND entity_kind='issue' AND entity_key IN ({','.join('?' * len(names))})" if names else " AND FALSE"
            args += names
        items = {(r["entity_kind"], r["entity_key"]): dict(r) for r in c.execute(sql, tuple(args))}
    states, fresh = {}, []
    # сохранённое сравнение берётся, только если его посчитал этот же расчёт и не наступил срок записи Hub, на которой
    # держится решение (ревью кода dev15, круг 1); иначе объект считается заново той же функцией
    same_version = not pseudo and hub_sync.passport(row).get("compare_version") == compare.COMPARE_VERSION
    now_ms = int(time.time() * 1000)
    for (kind, key), meta in items.items():
        local_obj = context.defect_local(key) if kind == "defect" else context.issue_local(key)
        diff = loads(meta["diff_json"], {})
        sources = loads(meta["source_ops_json"], {})
        groups = diff.get("groups") or []
        if (same_version and groups and meta["local_signature"] == versions.digest(local_obj)
                and not (diff.get("valid_until") and now_ms >= diff["valid_until"])
                and ("stale" in groups or context.observation_current(row, kind, key, sources))):
            delivery = diff.get("delivery") or compare.delivery_of(kind, key, local_obj, diff, context, sources,
                                                                   observed=not meta["unread"])
            states[(kind, key)] = _state(pid, row["id"], kind, key, diff, delivery, unread=meta["unread"])
        else:
            fresh.append((kind, key))
    missing = sorted(local - set(items))
    adapter = links = None
    if fresh or (missing and not pseudo):
        adapter = api.Adapter(**hub_sync.passport(row)["adapter"])
        links = _links(c, row["id"], any(kind == "defect" for kind, _ in fresh + missing))
    if fresh:
        names = sorted({key for _, key in fresh})
        wanted_fresh = set(fresh)
        for raw in c.execute(f"SELECT * FROM hub_sync_items WHERE run_id=? AND entity_key IN ({','.join('?' * len(names))})",
                             (row["id"], *names)):
            item = dict(raw)
            if (item["entity_kind"], item["entity_key"]) not in wanted_fresh:
                continue
            _, _, diff, _ = compare.evaluate(c, row, context, item, adapter, links)
            states[(item["entity_kind"], item["entity_key"])] = _state(
                pid, row["id"], item["entity_kind"], item["entity_key"], diff, diff.get("delivery"),
                unread=item["hub_json"] in ("", "{}"))
    for kind, key in missing:
        if pseudo:
            if kind != "issue":
                continue  # Hub не читался: черновик дефекта – своё состояние на странице дефекта
            local_obj = context.issue_local(key)
            delivery = compare.delivery_of(kind, key, local_obj, {}, context, None, observed=False)
            states[(kind, key)] = _state(pid, None, kind, key, {}, delivery, read="never")
            continue
        # как compare_in: элемент без наблюдения с причиной «появился после составления списка чтения» (ревью кода
        # dev15, круг 1 – иначе группы страницы и пересчёта расходились)
        item = {"entity_kind": kind, "entity_key": key, "hub_json": "{}", "source_ops_json": "{}",
                "coverage_json": dumps({"absent_from_list": False}), "stale_reason": compare.LOCAL_AFTER_READ}
        _, _, diff, _ = compare.evaluate(c, row, context, item, adapter, links)
        states[(kind, key)] = _state(pid, None, kind, key, diff, diff.get("delivery"), unread=True)
    # состояние находки – по её полному ключу с типом: объект Hub другого типа с тем же номером его не подменяет
    # (ревью кода dev15, круг 1)
    by_hub_id = {}
    for (kind, key), st in states.items():
        finding = context.findings.get(key.split(":", 1)[-1]) if kind == "issue" else None
        if finding and issue_key(finding) == key:
            by_hub_id[str(finding["hub_id"])] = st
    out = {"target": True, "items": states, "by_hub_id": by_hub_id, "run": None if pseudo else row, "latest": latest,
           "summary": None}
    if keys is None:
        out["summary"] = _summary(pid, row, latest, states, pseudo, complete_local=not missing)
    return out


def _state(pid, run_id, kind, key, diff, delivery, read=None, unread=False) -> dict:
    groups = list(diff.get("groups") or [])
    if read is None:
        # объект без наблюдения, добавленный пересчётом после составления списка чтения, – «нет в последнем чтении»,
        # как и до пересчёта (одна подпись для одной ситуации); ошибка его чтения – «чтение неполное»
        read = ("missing" if unread and "incomplete" not in groups else "stale" if "stale" in groups
                else "incomplete" if "incomplete" in groups else None)
    differing = [g for g in groups if g not in EQUAL_GROUPS]
    group = compare.primary_group(differing or groups) if groups else None
    delivery = delivery or {}
    dstate = delivery.get("state")
    link = ""
    if run_id is not None:
        # по ключу: страница синхронизации сама открывает группу, где объект стоит в сохранённом сравнении (после
        # локальной правки она может отличаться от посчитанной здесь, ревью кода dev15, круг 3)
        link = f"/projects/{pid}/hub-sync/{run_id}?" + urlencode({"q": key})
    badges = []
    # проблема чтения важнее отправки, отправка важнее сравнения; «Hub не читался» – на обзоре, не в каждой строке
    if read in ("missing", "stale", "incomplete"):
        badges.append({"text": READ_LABELS[read], "tone": "warn"})
    if dstate:
        text = compare.DELIVERY_LABELS[dstate]
        if dstate == "refused" and delivery.get("error"):
            text += f": {delivery['error']}"
        badges.append({"text": text, "tone": DELIVERY_TONES[dstate]})
    # «совпавшие изменения» – приложение и Hub изменились одинаково и равны, отстала только принятая база: для
    # оператора это совпадение, а не отличие. Совпадение – когда так у всего набора групп, а не только у основной
    # (ревью кода dev15, круг 1: «совпавшие» рядом со справочным отличием его не скрывают)
    equal = not differing
    if not equal and (not badges or dstate == "sent"):  # «отправлено», а Hub показывает другое – видно и отличие
        badges.append({"text": compare.LABELS[group], "tone": "accent"})
    return {"kind": kind, "key": key, "read": read, "delivery": delivery, "groups": groups, "group": group,
            "causes": list(diff.get("causes") or []), "notes": list(diff.get("notes") or []), "link": link,
            # цель значка: запись синхронизации, а без неё – шаг «Состояние Hub» на обзоре проекта
            "target": link or f"/projects/{pid}#step-hub",
            "badges": badges, "unsent": dstate in UNSENT,
            "differs": read in ("missing", "stale", "incomplete") or not equal}


def _summary(pid, row, latest, states, pseudo, complete_local) -> dict:
    """Строка «Синхронизация с Hub» на обзоре проекта (план п. 2.2): время чтения, принято ли, сколько не отправлено,
    сколько Hub не принял, сколько без подтверждения, сколько отличий. «Всё совпадает с Hub» – только при полном
    чтении, где есть каждый локальный объект, без отличий и неотправленного."""
    from app import hub_sync
    counts = {name: 0 for name in compare.DELIVERY_LABELS}
    # дефекты – отдельно: отбор списка находок их не показывает (ревью кода, к. 1); не отправленное, ждущее исполнителя,
    # неподтверждённое и отказ Hub – разными счётчиками (ревью кода, к. 10)
    defects = {"unsent": 0, "queued": 0, "unconfirmed": 0, "refused": 0, "differs": 0}
    differs = 0
    for st in states.values():
        dstate = st["delivery"].get("state")
        if st["kind"] == "defect":
            if dstate in defects and dstate != "differs":
                defects[dstate] += 1
            defects["differs"] += int(st["differs"])
            continue
        if dstate:
            counts[dstate] += 1
        differs += int(st["differs"])
    data = {} if pseudo else hub_sync.passport(row)
    complete = bool(data.get("inventory_complete") and data.get("details_complete"))
    all_match = (not pseudo and complete and complete_local and not differs and not any(counts.values())
                 and not any(defects.values()))
    return {"never": pseudo, "run_id": None if pseudo else row["id"], "read_at": None if pseudo else row["created_at"],
            "accepted_at": None if pseudo else row["applied_at"], "complete": complete,
            "reading": bool(latest and latest["state"] in (*hub_sync.ACTIVE, "comparing")),
            "counts": counts, "unsent": sum(counts[s] for s in UNSENT), "differs": differs, "all_match": all_match,
            "defects": defects,
            "link": "" if pseudo else f"/projects/{pid}/hub-sync/{row['id']}"}
