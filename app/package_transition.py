"""Переход сущностей при изменении эффективной идентичности пакета SCA (план dev17, п. 4.4–4.5).

Фаза 1 принятия состояния Hub (`hub_pull.apply`) записывает идентичность находки по сведениям Hub о библиотеке
(`apply_library`). Фаза 2 – `rebind_packages`: ревизия идентичности проекта, участники наборов, групповые сущности
(исследования, решения по компоненту, ответы прежнего формата, тексты наборов, применимость, строки наборов), связи и
ключи дефектов, резервы номеров, решения по находкам и архив снятого. Фаза 3 (дефекты) идёт с новым снимком сравнения.

Группа – эффективная тройка (экосистема, имя, версия) находок вида SCA, её ключ – `input_ref`. Виды перехода группы S:
«без изменений», «перенос» (все находки S – в одну новую группу, у которой нет своих находок и сущностей), «частичное
расщепление» (часть находок остаётся в S), «расщепление» (находки S – в несколько групп), «слияние» (в группу ведут
несколько групп или у неё уже есть свои находки и сущности). По находке – «уточнение» (экосистема и версия те же,
прежнее имя без области и группы, новое – область или группа Hub плюс прежнее имя) или «изменение».

Сущности, которые переход снимает, удаляются из живых таблиц и целиком сохраняются в `sca_identity_archive`: история не
живёт под чужими ключами. Предпросмотр считает тот же итог той же транзакцией, которая откатывается
(`hub_pull.preview_identity`).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from app import i18n, package_identity
from app.db import Database, dumps, loads, now_iso, review_signature
from app.defect import defect_key_sca
from app.defect_drafts import UNMATCHED_TARGETS, unmatched_targets
from app.sca_contract import input_ref

SCA = "SCA"
SCA_KINDS = ("SCA", "SCA-license")
# хранимые тексты (причины в архиве и в наборах, конфликты дефекта) пишутся по-русски; перевод – при показе (ADR-0158)
MERGE_REASON = i18n.N_("после слияния пакетов: место в наборах выбрать заново")
NO_SINGLE_SET = i18n.N_("После перехода идентичности пакетов цели не определяют единственный набор SCA.")
# таблицы, все строки проекта которых входят в отпечаток входов перехода (токен подтверждения, план п. 4.5)
FINGERPRINT_TABLES = ("findings", "reviews", "sca_set_members", "sca_defect_sets", "sca_package_texts",
                      "sca_applicability", "sca_answers", "sca2_research", "sca2_decisions", "defects", "hub_defects")


def scope_of(hub_url: Any, app_id: Any) -> str:
    """Назначение Hub, при котором правило применялось (`findings.pkg_scope`)."""
    return f"{hub_url or ''}|{'' if app_id is None else app_id}"


def pending_count(db, project: Mapping[str, Any], hub_url: Any) -> int:
    """Сколько находок SCA ждут применения сведений Hub о библиотеке (подсказка п. 4.4); у проекта без привязки к
    Hub или без адреса Hub – 0: подсказка не показывается."""
    if not hub_url or project.get("hub_app_id") in (None, ""):
        return 0
    return db.identity_pending(int(project["id"]), scope_of(hub_url, project["hub_app_id"]))


def transition_fingerprint(c, project_id: int) -> str:
    """Отпечаток всех строк проекта в таблицах перехода: изменилось что-либо между предпросмотром и применением –
    подтверждение недействительно (план п. 4.5, «Предпросмотр и токен»). Порядок строк не важен: отпечатки строк
    сортируются."""
    parts = []
    for table in FINGERPRINT_TABLES:
        row = c.execute(f"SELECT COALESCE(string_agg(md5(t::text), ',' ORDER BY md5(t::text)), '') AS fp FROM {table} t"
                        " WHERE t.project_id = ?", (project_id,)).fetchone()
        parts.append(f"{table}:{hashlib.sha256(str(row['fp']).encode('ascii')).hexdigest()}")
    return hashlib.sha256("|".join(parts).encode("ascii")).hexdigest()[:32]


# ============================================================================ фаза 1: идентичность находки


def library_of(hub: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    library = ((hub or {}).get("detail") or {}).get("library") if isinstance((hub or {}).get("detail"), Mapping) else None
    return library if isinstance(library, Mapping) else None


def resolved_columns(data: Mapping[str, Any], hub: Mapping[str, Any] | None, scope: str) -> tuple[str, ...]:
    """Колонки `pkg_*` по правилу п. 3 (в порядке `package_identity.PKG_COLUMNS`)."""
    pkg = package_identity.resolve(data.get("build_type"), data.get("component"), data.get("version"), library_of(hub))
    return pkg.ecosystem, pkg.name, pkg.source, pkg.note, scope


def apply_library(c, finding_id: int, hub: Mapping[str, Any] | None, scope: str) -> bool:
    """Фаза 1 (п. 4.4): идентичность находки SCA по сведениям Hub о библиотеке принятого объекта; при `present` без
    `library` или с пустым именем – правила 1, 2 (источник `file`). True – колонки изменились."""
    row = c.execute("SELECT kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
                    " WHERE id = ?", (finding_id,)).fetchone()
    if row is None or row["kind"] not in SCA_KINDS:
        return False
    new = resolved_columns(loads(row["data_json"], {}), hub, scope)
    old = tuple(str(row[col] or "") for col in package_identity.PKG_COLUMNS)
    if new == old:
        return False
    c.execute("UPDATE findings SET pkg_ecosystem = ?, pkg_name = ?, pkg_source = ?, pkg_note = ?, pkg_scope = ?"
              " WHERE id = ?", (*new, finding_id))
    return True


def snapshot(c, project_id: int) -> dict[int, dict]:
    """Все находки SCA проекта: номер строки -> Hub ID, вид, данные с `package`, эффективная тройка, ревизия."""
    out = {}
    for r in c.execute("SELECT id, hub_id, kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope,"
                       " pkg_rev FROM findings WHERE project_id = ? AND kind IN ('SCA', 'SCA-license') ORDER BY id",
                       (project_id,)).fetchall():
        data = package_identity.with_package(dict(r))
        out[int(r["id"])] = {"hub_id": str(r["hub_id"]), "kind": r["kind"], "data": data,
                             "triple": package_identity.of(data), "pkg_rev": int(r["pkg_rev"] or 0)}
    return out


def classify(before: tuple, after: tuple) -> str:
    """«» – тройка не изменилась; «refine» – уточнение; «change» – изменение (п. 4.5, «Виды перехода»)."""
    if before == after:
        return ""
    (eco_b, name_b, ver_b), (eco_a, name_a, ver_a) = before, after
    if eco_b == eco_a and ver_b == ver_a and name_b:
        if (eco_a == "npm" and not name_b.startswith("@") and name_a.startswith("@") and "/" in name_a
                and name_a.split("/", 1)[1] == name_b):
            return "refine"
        if eco_a == "maven" and ":" not in name_b and name_a.count(":") == 1 and name_a.split(":", 1)[1] == name_b:
            return "refine"
    return "change"


def base_key(triple: tuple) -> str:
    eco, name, version = triple
    return defect_key_sca(name, version, eco)


def set_key(triple: tuple, set_no: int | None) -> str:
    base = base_key(triple)
    return base if not set_no else f"{base}#{int(set_no)}"


def split_key(key: str) -> tuple[str, int]:
    """Ключ номера SCA -> (ключ пакета, номер набора)."""
    head, sep, tail = key.rpartition("#")
    if sep and tail.isdigit() and head.startswith("sca:v3|"):
        return head, int(tail)
    return key, 0


# ============================================================================ план перехода


@dataclass
class Group:
    ref: str
    triple: tuple
    members: set[int]
    stays: set[int] = field(default_factory=set)
    dest: dict[str, set[int]] = field(default_factory=dict)
    kind: str = ""  # move | partial | split | merge-in (уходит в группу слияния)
    change: str = ""  # refine | change – у переноса и слияния


@dataclass
class Plan:
    before: dict[int, dict]
    after: dict[int, dict]
    moves: dict[int, str]
    groups: dict[str, Group]
    targets: dict[str, dict]
    merges: set[str]


def _entities_of(c, project_id: int, ref: str, triple: tuple) -> bool:
    """У группы есть свои сущности: исследование, решения, тексты, применимость, наборы, участники, ответы, номера."""
    for table in ("sca2_research", "sca2_decisions", "sca_package_texts", "sca_applicability", "sca_defect_sets",
                  "sca_set_members"):
        if c.execute(f"SELECT 1 FROM {table} WHERE project_id = ? AND input_ref = ? LIMIT 1", (project_id, ref)).fetchone():
            return True
    eco, name, version = triple
    if c.execute("SELECT 1 FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ? AND version = ?"
                 " LIMIT 1", (project_id, eco, name, version)).fetchone():
        return True
    base = base_key(triple)
    return c.execute("SELECT 1 FROM defects WHERE project_id = ? AND (defect_key = ? OR defect_key LIKE ?) LIMIT 1",
                     (project_id, base, base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "#%")
                     ).fetchone() is not None


def plan(c, project_id: int, before: dict[int, dict], after: dict[int, dict], *, change_only: bool = False) -> Plan:
    """Виды перехода групп и находок по снимкам до и после фазы 1. change_only – смена назначения Hub (п. 4.5):
    любая изменившаяся тройка – «изменение», уточнения не бывает (ревью Codex шага 4, круг 2: возврат к тройке файла
    после смены назначения иначе мог бы пройти как уточнение и переписать подпись решения оператора)."""
    moves = {fid: ("change" if change_only else kind) for fid in before if fid in after
             and (kind := classify(before[fid]["triple"], after[fid]["triple"]))}
    sca_ids = [fid for fid in before if before[fid]["kind"] == SCA and fid in after]
    before_groups: dict[str, set[int]] = defaultdict(set)
    triples: dict[str, tuple] = {}
    for fid in sca_ids:
        ref = input_ref(*before[fid]["triple"])
        before_groups[ref].add(fid)
        triples[ref] = before[fid]["triple"]
    after_ref = {fid: input_ref(*after[fid]["triple"]) for fid in sca_ids}
    groups: dict[str, Group] = {}
    incoming: dict[str, list[str]] = defaultdict(list)
    for ref, members in before_groups.items():
        dest: dict[str, set[int]] = defaultdict(set)
        for fid in members:
            dest[after_ref[fid]].add(fid)
        if set(dest) == {ref}:
            continue
        g = Group(ref, triples[ref], set(members), stays=set(dest.pop(ref, set())), dest=dict(dest))
        g.kind = "partial" if g.stays else ("split" if len(g.dest) > 1 else "move")
        if g.kind == "move":
            fid = next(iter(members))
            g.change = moves.get(fid, "change")
        groups[ref] = g
        for target in g.dest:
            incoming[target].append(ref)
    # находки, которых до фазы 1 не было (их создало принятие), – собственные участники своей группы: пришедший туда
    # пакет – слияние, со своими наборами (ревью Codex шага 4: иначе оба номера легли бы на один ключ набора 0)
    new_members: dict[str, set[int]] = defaultdict(set)
    for fid, item in after.items():
        if fid not in before and item["kind"] == SCA:
            new_members[input_ref(*item["triple"])].add(fid)
    targets, merges = {}, set()
    for target, sources in incoming.items():
        fid = next(iter(groups[sources[0]].dest[target]))
        triple = after[fid]["triple"]
        own = (bool(before_groups.get(target)) or bool(new_members.get(target))
               or _entities_of(c, project_id, target, triple))
        targets[target] = {"triple": triple, "sources": sorted(sources)}
        if own or len(sources) > 1:
            merges.add(target)
            for source in sources:
                if groups[source].kind == "move":
                    groups[source].kind = "merge-in"
    return Plan(before, after, moves, groups, targets, merges)


# ============================================================================ фаза 2: переход


class _Counter:
    """Перенесено и в архив – по таблицам, всего и по группе, которую сейчас обходит переход (current): числа по
    сущностям в таблице групп итога (п. 4.5, ревью Kimi шага 4)."""

    def __init__(self):
        self.moved: dict[str, int] = defaultdict(int)
        self.archived: dict[str, int] = defaultdict(int)
        self.current: str | None = None
        self.by_group: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: {"moved": defaultdict(int), "archived": defaultdict(int)})

    def move(self, table: str) -> None:
        self.moved[table] += 1
        if self.current is not None:
            self.by_group[self.current]["moved"][table] += 1

    def archive(self, table: str) -> None:
        self.archived[table] += 1
        if self.current is not None:
            self.by_group[self.current]["archived"][table] += 1

    def as_dict(self):
        return {"moved": dict(self.moved), "archived": dict(self.archived)}


def _archive(c, project_id: int, run_id: int | None, table: str, key: Mapping[str, Any], row: Mapping[str, Any],
             counter: _Counter, *, moved_to: str = "", reason: str = "") -> None:
    c.execute("INSERT INTO sca_identity_archive(project_id, run_id, archived_at, source_table, key_json, row_json,"
              " moved_to_ref, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (project_id, run_id, now_iso(), table, dumps(dict(key)), dumps(dict(row)), moved_to, reason))
    counter.archive(table)


def _research_follows(c, project_id: int, ref: str, triple: tuple) -> bool:
    """Исследование переносится вместе со всеми ревизиями, только если последняя ревизия разрешена и полная тройка
    строки задания совпадает с новой: экосистема и версия строки задания равны новым, координаты – новому имени."""
    last = c.execute("SELECT * FROM sca2_research WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC LIMIT 1",
                     (project_id, ref)).fetchone()
    if last is None:
        return False
    payload = Database._research_row(dict(last))["payload"]
    identity = payload.get("identity_resolution") if isinstance(payload, Mapping) else None
    if not isinstance(identity, Mapping) or identity.get("state") != "resolved":
        return False
    task = c.execute("SELECT ecosystem, version FROM sca2_task_rows WHERE task_id = ? AND input_ref = ?",
                     (last["task_id"], ref)).fetchone()
    eco, name, version = triple
    return (task is not None and str(task["ecosystem"] or "") == eco and str(task["version"] or "") == version
            and str(identity.get("coordinates") or "") == name)


def _move_rows(c, project_id: int, run_id, table: str, key_cols: tuple[str, ...], ref: str, target: str | None,
               counter: _Counter, reason: str, *, reset: Mapping[str, Any] | None = None) -> None:
    """Все строки таблицы группы ref: перенос под target (reset – поля, которые при переносе сбрасываются; прежняя
    строка тогда тоже уходит в архив) или в архив (target is None)."""
    rows = c.execute(f"SELECT * FROM {table} WHERE project_id = ? AND input_ref = ?", (project_id, ref)).fetchall()
    for r in rows:
        key = {col: r[col] for col in key_cols}
        if target is None:
            _archive(c, project_id, run_id, table, key, r, counter, reason=reason)
            c.execute(f"DELETE FROM {table} WHERE project_id = ? AND " + " AND ".join(f"{col} = ?" for col in key_cols),
                      (project_id, *key.values()))
            continue
        if reset:
            _archive(c, project_id, run_id, table, key, r, counter, moved_to=target, reason=reason)
        sets = "input_ref = ?" + "".join(f", {col} = ?" for col in (reset or {}))
        c.execute(f"UPDATE {table} SET {sets} WHERE project_id = ? AND " + " AND ".join(f"{col} = ?" for col in key_cols),
                  (target, *(reset or {}).values(), project_id, *key.values()))
        counter.move(table)


def _move_answers(c, project_id: int, run_id, triple: tuple, counter: _Counter, reason: str) -> None:
    """Ответы прежнего формата – всегда в архив: доказательства, что ответ относится к новой тройке, нет."""
    eco, name, version = triple
    for r in c.execute("SELECT * FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ?"
                       " AND version = ?", (project_id, eco, name, version)).fetchall():
        _archive(c, project_id, run_id, "sca_answers", {"id": r["id"]}, r, counter, reason=reason)
        c.execute("DELETE FROM sca_answers WHERE id = ?", (r["id"],))


def _member(c, project_id: int, hub_id: str):
    return c.execute("SELECT * FROM sca_set_members WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()


def _ensure_set(c, project_id: int, ref: str, set_no: int, counter: _Counter) -> None:
    """Строка набора новой группы с ревизией 1, если её ещё нет (расщепление, изменение, слияние)."""
    if not set_no:
        return
    if c.execute("SELECT 1 FROM sca_defect_sets WHERE project_id = ? AND input_ref = ? AND set_no = ?",
                 (project_id, ref, set_no)).fetchone() is None:
        c.execute("INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, excluded_json, updated_at)"
                  " VALUES (?, ?, ?, 1, '[]', ?)", (project_id, ref, set_no, now_iso()))
        counter.move("sca_defect_sets_new")


def rebind_packages(c, project_id: int, run_id: int | None, before: dict[int, dict], after: dict[int, dict], *,
                    change_only: bool = False) -> dict:
    """Фаза 2 (п. 4.5): все последствия смены эффективных троек. Возвращает сводку для итога и предпросмотра.
    change_only – смена назначения Hub: правила изменения для всех изменившихся троек (plan)."""
    p = plan(c, project_id, before, after, change_only=change_only)
    counter = _Counter()
    summary: dict[str, Any] = {"findings": len(p.moves), "refine": sum(k == "refine" for k in p.moves.values()),
                               "change": sum(k == "change" for k in p.moves.values())}
    if not p.moves:
        if change_only:  # смена назначения состоялась и без смены троек: ревизия проекта растёт, pkg_rev – нет
            c.execute("UPDATE projects SET identity_rev = identity_rev + 1 WHERE id = ?", (project_id,))
        summary.update(marks_summary(after), groups=[], decisions={}, **counter.as_dict())
        return summary
    stamp = now_iso()
    rev = c.execute("UPDATE projects SET identity_rev = identity_rev + 1 WHERE id = ? RETURNING identity_rev",
                    (project_id,)).fetchone()[0]
    for fid in p.moves:
        c.execute("UPDATE findings SET pkg_rev = ? WHERE id = ?", (rev, fid))

    # ---- групповые сущности (план п. 4.5, таблица «Групповые сущности»)
    research_moved: dict[str, bool] = {}
    for ref, g in sorted(p.groups.items()):
        counter.current = ref  # числа по сущностям – и по группе (таблица групп итога)
        if g.kind == "partial":
            continue  # S живёт дальше со своими сущностями; ушедшие ветки их не получают
        target = next(iter(g.dest)) if g.kind == "move" else None
        reason = {"move": f"перенос ({'уточнение' if g.change == 'refine' else 'изменение'})",
                  "split": "расщепление группы", "merge-in": "слияние с другой группой"}[g.kind]
        follows = target is not None and _research_follows(c, project_id, ref, p.targets[target]["triple"])
        research_moved[ref] = follows
        _move_rows(c, project_id, run_id, "sca2_research", ("input_ref", "revision"), ref, target if follows else None,
                   counter, reason if follows else reason + ": исследование не доказывает новую тройку")
        _move_rows(c, project_id, run_id, "sca2_decisions", ("input_ref", "revision"), ref, target if follows else None,
                   counter, reason)
        _move_answers(c, project_id, run_id, g.triple, counter, reason)
        refine = g.kind == "move" and g.change == "refine"
        _move_rows(c, project_id, run_id, "sca_package_texts", ("input_ref", "set_no"), ref, target if refine else None,
                   counter, reason)
        _move_rows(c, project_id, run_id, "sca_applicability", ("input_ref", "vuln_key"), ref,
                   target if refine and follows else None, counter, reason)
        if g.kind == "move":
            _move_rows(c, project_id, run_id, "sca_defect_sets", ("input_ref", "set_no"), ref, target, counter, reason,
                       reset=None if refine else {"revision": 1, "excluded_json": "[]"})
        else:
            _move_rows(c, project_id, run_id, "sca_defect_sets", ("input_ref", "set_no"), ref, None, counter, reason)
        # отметка группы: прежняя тройка для подписей архива и, у перенесённой группы, куда она перенесена – прежний
        # адрес карточки компонента ведёт на новую (план dev17, п. 4.6); в счётчики архива не входит – это не снятая
        # сущность
        c.execute("INSERT INTO sca_identity_archive(project_id, run_id, archived_at, source_table, key_json,"
                  " row_json, moved_to_ref, reason) VALUES (?, ?, ?, 'group', ?, ?, ?, ?)",
                  (project_id, run_id, now_iso(), dumps({"input_ref": ref}), dumps({"triple": list(g.triple)}),
                   target or "", reason))

    # ---- участники наборов (по находке)
    # слияние: каждому пришедшему месту (группа, набор) – и набору 0, и «без дефекта» – новый номер набора цели,
    # следующий за наибольшим (план п. 4.5, «Участники наборов»)
    merge_numbers: dict[str, dict[tuple, int]] = {}
    merge_top: dict[str, int] = {}
    pending: list[dict] = []
    for ref, g in sorted(p.groups.items()):
        counter.current = ref  # числа по сущностям – и по группе (таблица групп итога)
        for target, members in sorted(g.dest.items()):
            in_merge = target in p.merges
            if in_merge and target not in merge_top:
                top = c.execute("SELECT COALESCE(MAX(set_no), 0) AS top FROM (SELECT set_no FROM sca_set_members"
                                " WHERE project_id = ? AND input_ref = ? AND set_no IS NOT NULL UNION ALL SELECT set_no"
                                " FROM sca_defect_sets WHERE project_id = ? AND input_ref = ?) x",
                                (project_id, target, project_id, target)).fetchone()["top"]
                # номера наборов, занятые ключами номеров дефектов цели (резервы без строки набора), тоже заняты:
                # иначе пришедшему месту достался бы ключ резерва (ревью Kimi шага 4)
                base = base_key(p.targets[target]["triple"])
                like = base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "#%"
                for r in c.execute("SELECT defect_key FROM defects WHERE project_id = ? AND (defect_key = ? OR"
                                   " defect_key LIKE ?)", (project_id, base, like)).fetchall():
                    top = max(int(top or 0), split_key(r["defect_key"])[1])
                merge_top[target] = int(top or 0)
                merge_numbers[target] = {}
            for fid in sorted(members):
                hub_id = p.before[fid]["hub_id"]
                member = _member(c, project_id, hub_id)
                old_no = None if member is None else member["set_no"]
                if in_merge:
                    numbers = merge_numbers[target]
                    place = (ref, -1 if member is not None and old_no is None else int(old_no or 0))
                    if place not in numbers:
                        merge_top[target] += 1
                        numbers[place] = merge_top[target]
                    new_no = numbers[place]
                    why = MERGE_REASON
                    if member is not None and old_no is None:
                        why += f" (прежнее место – «без дефекта»: {member['no_defect_reason'] or 'обоснование не указано'})"
                    if member is not None:
                        _archive(c, project_id, run_id, "sca_set_members", {"hub_id": hub_id}, member, counter,
                                 moved_to=target, reason=i18n.N_("слияние с другой группой"))
                        c.execute("UPDATE sca_set_members SET input_ref = ?, set_no = ?, no_defect_reason = '',"
                                  " pending_reason = ?, updated_at = ? WHERE project_id = ? AND hub_id = ?",
                                  (target, new_no, why, stamp, project_id, hub_id))
                    else:
                        c.execute("INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, no_defect_reason,"
                                  " updated_at, pending_reason) VALUES (?, ?, ?, ?, '', ?, ?)",
                                  (project_id, hub_id, target, new_no, stamp, why))
                    _ensure_set(c, project_id, target, new_no, counter)
                    counter.move("sca_set_members")
                    pending.append({"hub_id": hub_id, "source": ref, "target": target, "set_no": new_no})
                    continue
                if member is None:
                    continue  # место по умолчанию (набор 0) – в новой группе тоже набор 0
                # правило изменения – по находке, при любом виде перехода группы (перенос, расщепление, частичный уход;
                # слияние – выше): «без дефекта» прежнего пакета новому не принадлежит (ревью Codex шага 4)
                change = p.moves.get(fid) == "change"
                if change and old_no is None:
                    # «без дефекта» относилось к другому пакету – в архив, находка получает место по умолчанию
                    _archive(c, project_id, run_id, "sca_set_members", {"hub_id": hub_id}, member, counter,
                             reason=i18n.N_("изменение пакета: «без дефекта» относилось к прежнему пакету"))
                    c.execute("DELETE FROM sca_set_members WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
                    continue
                c.execute("UPDATE sca_set_members SET input_ref = ?, updated_at = ? WHERE project_id = ? AND hub_id = ?",
                          (target, stamp, project_id, hub_id))
                counter.move("sca_set_members")
                if g.kind in ("split", "partial") and old_no:
                    _ensure_set(c, project_id, target, int(old_no), counter)

    # ---- связи и ключи дефектов, резервы номеров
    counter.current = None
    defects_summary = _rebind_defects(c, project_id, run_id, p, counter)

    # ---- решения по находкам
    decisions = _rebind_decisions(c, project_id, p, stamp)

    summary.update(marks_summary(after), decisions=decisions, defects=defects_summary, pending=pending[:50],
                   pending_total=len(pending),  # список усечён до 50, счёт – полный (ревью Codex шага 4, круг 3)
                   groups=_groups_summary(p, research_moved, counter, pending), **counter.as_dict())
    return summary


INACTIVE = ("failed", "cancelled", "deleted")  # строка дефекта, которая номер не держит: история не переписывается
# цель семейства не сопоставлена с находкой SCA проекта (её нет или у неё другой тип связи): единственный набор
# семейства не определить – ключ набора пуст, причина названа (ревью Codex шага 4, круг 2); сообщение и проверка –
# общие с defect_drafts.sca_identity (остаток шага 4: тот же расчёт во всех фазах)
# подписи таблиц перехода для подтверждения и итога (п. 4.5)
TABLE_LABELS = i18n.Labels({"sca2_research": "исследования компонента", "sca2_decisions": "решения по компоненту",
                            "sca_answers": "ответы агента", "sca_applicability": "решения о применимости",
                            "sca_package_texts": "тексты наборов дефекта", "sca_set_members": "места находок в наборах",
                            "sca_defect_sets": "наборы дефекта", "sca_defect_sets_new": "новые наборы дефекта (созданы)",
                            "defects": "ключи и резервы номеров дефектов",
                            "reviews": "решения по находкам"})


class TransitionConflict(ValueError):
    """Ключ номера после перехода занят другим номером: применение откатывается целиком (ревью Codex шага 4)."""


def _unmatched_targets(c, project_id: int, targets) -> list[str]:
    """Цели семейства «тип:номер», которых нет среди находок проекта с тем же типом связи (порядок сохранён); цель
    без типа связи здесь тоже несопоставленная."""
    return unmatched_targets(c, project_id, targets, typeless=True)


def _families(c, project_id: int) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = defaultdict(list)
    for r in c.execute("SELECT * FROM hub_defects WHERE project_id = ? AND draft_owner_id IS NOT NULL ORDER BY id",
                       (project_id,)).fetchall():
        out[int(r["draft_owner_id"])].append(dict(r))
    return out


def _rebind_defects(c, project_id: int, run_id, p: Plan, counter: _Counter) -> dict:
    """Связи и ключи дефектов – по составу каждого семейства (п. 4.5): number_keys_json и sca_set_key пересчитываются
    по сохранённым целям после переноса участников; строки defects с номером семейства приводятся к новым ключам;
    резервы номеров (номер не держит ни одно семейство) – по виду перехода своей группы."""
    from app.defect_drafts import sca_identity, typed_ids
    moved_hub_ids = {p.before[fid]["hub_id"] for fid in p.moves}
    moved_bases = {base_key(g.triple): g for g in p.groups.values()}
    families = _families(c, project_id)
    held = {int(r["number"]) for rows in families.values() for r in rows
            if r["id"] == r["draft_owner_id"] and r["number"] is not None and r["state"] not in INACTIVE}
    out = {"families": 0, "keys_rewritten": 0, "keys_archived": 0, "without_set_key": [], "reserves_moved": 0,
           "reserves_archived": 0, "owners": []}
    releases: list[tuple[str, int]] = []
    assigns: list[tuple[str, int]] = []
    for owner_id, rows in families.items():
        owner = next((r for r in rows if r["id"] == owner_id), None)
        if owner is None or owner["state"] in INACTIVE:
            continue  # отменённая или неудавшаяся строка номер не держит: её история не переписывается (ревью Codex)
        active = [r for r in rows if r["state"] not in INACTIVE]
        # цели – только те, тип связи которых совпадает с видом находки (SAST:73001 – не SCA 73001, ревью Codex)
        typed = {r["id"]: typed_ids(c, project_id, loads(r["targets_json"], [])) for r in active}
        targets_all = list(dict.fromkeys(hid for r in active for hid in typed[r["id"]]))
        old_keys = {k for r in active for k in loads(r["number_keys_json"], [])}
        touched = set(targets_all) & moved_hub_ids or {k for k in old_keys if split_key(k)[0] in moved_bases}
        if not touched:
            continue
        out["families"] += 1
        out["owners"].append(owner_id)
        new_keys: set[str] = set()
        for r in active:
            # у строки без сопоставленных целей ключей нет – пустой список записывается, иначе её прежние ключи
            # расходились бы с таблицей номеров после архива (ревью Codex шага 4, круг 3)
            keys = (sorted(Database.defect_keys_of_findings_in(c, project_id, typed[r["id"]]))
                    if typed[r["id"]] else [])
            new_keys |= set(keys)
            if keys != sorted(loads(r["number_keys_json"], [])):
                c.execute("UPDATE hub_defects SET number_keys_json = ? WHERE id = ?", (dumps(keys), r["id"]))
        # несопоставленные цели – по паре (тип связи, номер): SAST:73001 рядом с SCA_S:73001 – не та же цель (ревью
        # Codex шага 4, круг 3)
        unmatched = _unmatched_targets(c, project_id, [t for r in active for t in loads(r["targets_json"], [])])
        if owner["kind"] == "SCA" and unmatched:
            # состав семейства неполон или тип связи не тот: по части целей единственный набор не доказан
            key, conflicts = "", [UNMATCHED_TARGETS.format(ids=", ".join(unmatched[:10]))]
            out["without_set_key"].append(defect_label(owner))
            if key != owner["sca_set_key"] or conflicts != loads(owner["conflicts_json"], []):
                c.execute("UPDATE hub_defects SET sca_set_key = ?, conflicts_json = ? WHERE id = ?",
                          (key, dumps(conflicts), owner_id))
        elif owner["kind"] == "SCA" and targets_all:
            # единственный набор – по составу всего семейства, а не по целям владельца (ревью Codex)
            key, conflicts = sca_identity(c, project_id, [{"hub_id": hid} for hid in targets_all])
            if not key:
                conflicts = [NO_SINGLE_SET, *conflicts]
                out["without_set_key"].append(defect_label(owner))
            # конфликты набора – вычисленные: единственный набор восстановлен – прежний конфликт снимается (ревью Kimi)
            if key != owner["sca_set_key"] or conflicts != loads(owner["conflicts_json"], []):
                c.execute("UPDATE hub_defects SET sca_set_key = ?, conflicts_json = ? WHERE id = ?",
                          (key, dumps(conflicts), owner_id))
        if owner["number"] is None:
            continue
        number = int(owner["number"])
        releases += [(key, number) for key in sorted(old_keys - new_keys)]
        assigns += [(key, number) for key in sorted(new_keys - old_keys)]
    # сначала освобождаются прежние ключи всех семейств, потом назначаются новые: при взаимной смене идентичности
    # (A↔B) порядок обхода семейств итог не меняет; ключ, занятый другим номером и после этого, – отказ с откатом
    # всего применения, а не строка сводки (ревью Codex шага 4)
    for key, number in releases:
        row = c.execute("SELECT * FROM defects WHERE project_id = ? AND defect_key = ? AND number = ?",
                        (project_id, key, number)).fetchone()
        if row is not None:
            source = moved_bases.get(split_key(key)[0])
            counter.current = source.ref if source is not None else None  # в строке группы ключа (ревью Codex)
            _archive(c, project_id, run_id, "defects", {"defect_key": key}, row, counter,
                     reason=i18n.N_("ключ номера дефекта после перехода идентичности"))
            counter.current = None
            c.execute("DELETE FROM defects WHERE project_id = ? AND defect_key = ? AND number = ?",
                      (project_id, key, number))
            out["keys_archived"] += 1
    for key, number in assigns:
        taken = c.execute("SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
                          (project_id, key)).fetchone()
        if taken is None:
            c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at)"
                      " VALUES (?, ?, ?, ?, ?)", (project_id, key, number, now_iso(), now_iso()))
            out["keys_rewritten"] += 1
        elif int(taken["number"]) != number:
            raise TransitionConflict(i18n._(
                "Переход сведений о библиотеках не выполнен: после него дефекту ID{number} нужен ключ номера, который "
                "занят дефектом ID{taken}. Ничего не изменено; разберите номера этих дефектов и примите состояние Hub "
                "заново.", number=number, taken=int(taken["number"])))
    # резервы: строки defects групп, которые ушли, с номером, который не держит ни одно семейство
    for base, g in sorted(moved_bases.items()):
        counter.current = g.ref  # резерв – в строке своей группы
        rows = c.execute("SELECT * FROM defects WHERE project_id = ? AND (defect_key = ? OR defect_key LIKE ?)",
                         (project_id, base, base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "#%")
                         ).fetchall()
        for r in rows:
            if int(r["number"]) in held:
                continue
            if g.kind == "partial":
                continue  # резерв остаётся у сохранившейся группы
            if g.kind == "move":
                target = next(iter(g.dest))
                new_key = set_key(p.targets[target]["triple"], split_key(r["defect_key"])[1])
                if c.execute("SELECT 1 FROM defects WHERE project_id = ? AND defect_key = ?",
                             (project_id, new_key)).fetchone() is None:
                    c.execute("UPDATE defects SET defect_key = ?, updated_at = ? WHERE project_id = ? AND defect_key = ?",
                              (new_key, now_iso(), project_id, r["defect_key"]))
                    out["reserves_moved"] += 1
                    counter.move("defects")
                    continue
            _archive(c, project_id, run_id, "defects", {"defect_key": r["defect_key"]}, r, counter,
                     reason=i18n.N_("резерв номера группы, которая расщепилась или слилась"))
            c.execute("DELETE FROM defects WHERE project_id = ? AND defect_key = ?", (project_id, r["defect_key"]))
            out["reserves_archived"] += 1
    counter.current = None
    out["without_set_key_total"] = len(out["without_set_key"])  # список – до 50, счёт – полный (ревью Codex)
    out["without_set_key"] = out["without_set_key"][:50]
    return out


def defect_label(row: Mapping[str, Any]) -> str:
    """Устойчивая подпись дефекта в сводке перехода: номер дефекта Hub, без него – номер строки. Номер строки
    дефекта, созданного третьей фазой, в откатываемом предпросмотре и в применении разный (ревью Codex, круг 2)."""
    return str(row["hub_defect_id"] or row["id"])


def settle_set_keys(c, project_id: int, summary: Mapping[str, Any] | None, accepted: Iterable[int] = ()) -> None:
    """Сводка «без единственного набора» – по итогу всей последовательности принятия (план dev17, остаток шага 4):
    третья фаза пересчитывает ключ набора по принятому составу Hub и может его вернуть или снять, поэтому список
    семейств перехода досчитывается по записанным строкам после неё – в предпросмотре и в применении одинаково.
    Семейства перехода – затронутые второй фазой по прежнему составу и принятые третьей фазой (accepted – номера
    владельцев), чей принятый состав включает находки, перенесённые этим переходом (ревью Codex, круг 1)."""
    defects = (summary or {}).get("defects")
    if not defects:
        return
    rev = c.execute("SELECT identity_rev FROM projects WHERE id = ?", (project_id,)).fetchone()[0]
    moved = {str(r[0]) for r in c.execute("SELECT hub_id FROM findings WHERE project_id = ? AND pkg_rev = ?",
                                           (project_id, rev)).fetchall()} if rev else set()
    owners = [int(o) for o in defects.pop("owners", None) or []]  # внутренний список: в сводку не входит
    for oid in dict.fromkeys(int(o) for o in accepted):
        if oid in owners:
            continue
        row = c.execute("SELECT kind, targets_json FROM hub_defects WHERE id = ?", (oid,)).fetchone()
        # цель – по номеру, без типа связи: и несопоставленная связь с перенесённой находкой затрагивает переход
        if row is not None and row["kind"] == "SCA" and {
                str(t.get("hub_id") or "") for t in loads(row["targets_json"], [])} & moved:
            owners.append(oid)
    if not owners:
        return
    marks = ",".join("?" * len(owners))
    rows = {int(r["id"]): r for r in c.execute(
        f"SELECT id, kind, state, sca_set_key, hub_defect_id FROM hub_defects WHERE project_id = ? AND id IN ({marks})",
        (project_id, *owners)).fetchall()}
    without = [defect_label(row) for oid in owners if (row := rows.get(int(oid))) is not None
               and row["kind"] == "SCA" and row["state"] not in INACTIVE and not row["sca_set_key"]]
    defects["without_set_key_total"] = len(without)
    defects["without_set_key"] = without[:50]


def _rebind_decisions(c, project_id: int, p: Plan, stamp: str) -> dict:
    """Решения (п. 4.5): у каждой находки с уточнением или изменением снимаются «Проверено» и время отметки, редакция
    растёт один раз; подпись решения оператора при уточнении переписывается, если была подписью «до»; подпись решения
    из Hub (то же назначение) – всегда. «Согласен с агентом» сверяется с главным ответом у всех находок затронутых
    групп."""
    counts = {"reviewed_removed": 0, "sig_rewritten": 0, "other_version": 0, "agree_stale": 0}
    bumped: set[str] = set()
    for fid, kind in sorted(p.moves.items()):
        hub_id = p.before[fid]["hub_id"]
        review = c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        if review is None:
            continue
        sig_before = review_signature(p.before[fid]["data"])
        sig_after = review_signature(p.after[fid]["data"])
        origin = review["decision_origin"] or ""
        sig = review["finding_sig"]
        if origin in ("hub_sync", "hub_defect"):
            sig = sig_after
        elif kind == "refine" and sig == sig_before:
            sig = sig_after
        elif review["decision"]:
            counts["other_version"] += 1
        if sig != review["finding_sig"]:
            counts["sig_rewritten"] += 1
        if review["reviewed"]:
            counts["reviewed_removed"] += 1
        c.execute("UPDATE reviews SET reviewed = 0, reviewed_at = NULL, finding_sig = ?, revision = revision + 1,"
                  " updated_at = ? WHERE project_id = ? AND hub_id = ?", (sig, stamp, project_id, hub_id))
        bumped.add(hub_id)
    affected = {fid for fid in p.moves}
    for target in p.merges:
        affected |= {fid for fid, item in p.after.items()
                     if item["kind"] == SCA and input_ref(*item["triple"]) == target}
    for fid in sorted(affected):
        item = p.after.get(fid)
        if item is None or item["kind"] != SCA:
            continue
        hub_id = item["hub_id"]
        review = c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        if review is None or review["decision"] != "agree":
            continue
        if Database._main_answer(c, project_id, item["data"])[1] == (review["answer_sig"] or ""):
            continue
        counts["agree_stale"] += 1
        if hub_id in bumped:
            continue
        if review["reviewed"]:
            counts["reviewed_removed"] += 1
        c.execute("UPDATE reviews SET reviewed = 0, reviewed_at = NULL, revision = revision + 1, updated_at = ?"
                  " WHERE project_id = ? AND hub_id = ?", (stamp, project_id, hub_id))
        bumped.add(hub_id)
    return counts


def label(triple: tuple) -> str:
    eco, name, version = triple
    return f"{eco or '?'} · {name}@{version}"


def _groups_summary(p: Plan, research_moved: Mapping[str, bool], counter: _Counter | None = None,
                   pending: list[dict] | None = None) -> list[dict]:
    """Таблица групп итога: было → стало, вид перехода, находки, исследование и числа по сущностям группы
    (перенесено / в архив), новые номера наборов при слиянии (п. 4.5)."""
    # итог хранится в hub_defect_sync_runs.result_json – подписи по-русски (msgid), перевод при показе
    kinds = {"move": i18n.N_("перенос"), "partial": i18n.N_("частичное расщепление"), "split": i18n.N_("расщепление"),
             "merge-in": i18n.N_("слияние")}
    out = []
    for ref, g in sorted(p.groups.items(), key=lambda kv: label(kv[1].triple)):
        out.append({"from": label(g.triple), "to": sorted(label(p.targets[t]["triple"]) for t in g.dest),
                    "kind": kinds[g.kind],
                    "change": {"refine": i18n.N_("уточнение"), "change": i18n.N_("изменение")}.get(g.change, ""),
                    "findings": len(g.members) - len(g.stays),
                    "research": i18n.N_("перенесено") if research_moved.get(ref) else
                    (i18n.N_("остаётся") if g.kind == "partial" else i18n.N_("в архив")),
                    "moved": dict(counter.by_group[ref]["moved"]) if counter is not None else {},
                    "archived": dict(counter.by_group[ref]["archived"]) if counter is not None else {},
                    "new_sets": sorted({(x["target"], x["set_no"]) for x in pending or [] if x.get("source") == ref})})
    return out[:200]


def entity_rows(summary: Mapping[str, Any]) -> list[dict]:
    """Строки «что перенесено, что в архив» по таблицам перехода для подтверждения и итога (п. 4.5): подпись,
    перенесено, в архив. Решения из Hub прежнего назначения (смена назначения) – отдельной строкой сводки."""
    moved, archived = summary.get("moved") or {}, summary.get("archived") or {}
    return [{"label": TABLE_LABELS.get(table, table), "moved": int(moved.get(table, 0) or 0),
             "archived": int(archived.get(table, 0) or 0)} for table in sorted(set(moved) | set(archived))
            if (moved.get(table) or archived.get(table))]


def marks_summary(after: Mapping[int, dict]) -> dict:
    """Счётчики пометок по эффективной идентичности (итог «Идентичность пакетов», п. 4.5)."""
    counts = {"ecosystem_refined": 0, "coordinates_added": 0, "scope_added": 0, "name_replaced": 0, "unresolved": 0,
              "no_library": 0, "version_mismatch": 0}
    for item in after.values():
        if item["kind"] != SCA:
            continue
        data = item["data"]
        pkg = data.get("package") or {}
        notes = package_identity.marks(data)
        source = pkg.get("source")
        raw_eco = package_identity.canon_ecosystem(data.get("build_type"))
        eco, name, _ = item["triple"]
        if source == "hub" and eco != raw_eco:
            counts["ecosystem_refined"] += 1
        if source == "hub" and eco == "maven" and ":" in name and ":" not in str(data.get("component") or ""):
            counts["coordinates_added"] += 1
        if source == "hub" and eco == "npm" and name.startswith("@") and not str(data.get("component") or "").startswith("@"):
            counts["scope_added"] += 1
        if any(n.startswith("name_replaced:") for n in notes):
            counts["name_replaced"] += 1
        if any(n == "no_name" or n.startswith(("rule_missing:", "scope_conflict:", "group_conflict:")) for n in notes):
            counts["unresolved"] += 1
        if source == "file" and not notes:
            counts["no_library"] += 1
        if any(n.startswith("version_mismatch:") for n in notes):
            counts["version_mismatch"] += 1
    return counts



# ============================================================================ смена назначения Hub (п. 4.5)

HUB_DECISIONS = ("hub_sync", "hub_defect")  # решения – проекции принятого состояния Hub (своего назначения)
ASSIGNMENT_REASON = i18n.N_("смена назначения Hub: решение из Hub прежнего назначения")


def assignment_affects(c, project_id: int) -> bool:
    """Смена назначения что-то меняет в проекте: есть сведения Hub о библиотеках или решения из Hub прежнего
    назначения. Иначе назначение меняется без подтверждения."""
    return (c.execute("SELECT 1 FROM findings WHERE project_id = ? AND kind IN ('SCA', 'SCA-license')"
                      " AND COALESCE(pkg_source, '') <> '' LIMIT 1", (project_id,)).fetchone() is not None
            or c.execute("SELECT 1 FROM reviews WHERE project_id = ? AND decision_origin IN ('hub_sync', 'hub_defect')"
                         " LIMIT 1", (project_id,)).fetchone() is not None)


def assignment_fingerprint(c, project_id: int, old: str, new: str) -> str:
    """Отпечаток входов смены назначения: строки таблиц перехода и прежнее и новое назначение (п. 4.5, «Предпросмотр
    и токен»)."""
    return hashlib.sha256(f"{transition_fingerprint(c, project_id)}|{old}|{new}".encode("utf-8")).hexdigest()[:32]


def change_assignment(c, project_id: int, write_new) -> dict:
    """Смена назначения Hub у проекта одной транзакцией соединения c (п. 4.5): write_new(c) записывает новое
    значение (номер приложения или адрес Hub); решения из Hub прежнего назначения – в архив и снимаются, как при
    отсутствии решения в Hub (их подпись не переписывается; первое принятие нового назначения спроецирует их заново);
    пять текстовых колонок идентичности очищаются – идентичность файла; затем rebind_packages по правилам «изменения»
    – без третьей фазы и без запросов к Hub. Сбой – исключение, транзакция откатывается целиком."""
    before = snapshot(c, project_id)
    counter = _Counter()
    stamp = now_iso()
    withdrawn = reviewed_withdrawn = 0
    for r in c.execute("SELECT * FROM reviews WHERE project_id = ? AND decision_origin IN ('hub_sync', 'hub_defect')"
                       " ORDER BY hub_id", (project_id,)).fetchall():
        _archive(c, project_id, None, "reviews", {"hub_id": r["hub_id"]}, r, counter, reason=ASSIGNMENT_REASON)
        c.execute("UPDATE reviews SET decision = '', final_verdict = '', final_comment = '', desired_hub_expired_at = NULL,"
                  " decision_origin = '', decision_source_json = '{}', reviewed = 0, reviewed_at = NULL,"
                  " revision = revision + 1, updated_at = ? WHERE project_id = ? AND hub_id = ?",
                  (stamp, project_id, r["hub_id"]))
        withdrawn += 1
        reviewed_withdrawn += 1 if r["reviewed"] else 0  # до перехода: он видит уже снятую отметку (ревью Codex)
    cleared = c.execute("UPDATE findings SET pkg_ecosystem = '', pkg_name = '', pkg_source = '', pkg_note = '',"
                        " pkg_scope = '' WHERE project_id = ? AND kind IN ('SCA', 'SCA-license')"
                        " AND COALESCE(pkg_source, '') <> ''", (project_id,)).rowcount
    write_new(c)
    summary = rebind_packages(c, project_id, None, before, snapshot(c, project_id), change_only=True)
    (summary.get("defects") or {}).pop("owners", None)  # служебный список – только для досчёта принятия
    decisions = dict(summary.get("decisions") or {})
    decisions["reviewed_removed"] = int(decisions.get("reviewed_removed") or 0) + reviewed_withdrawn
    summary.update(hub_decisions_withdrawn=withdrawn, identity_cleared=int(cleared or 0),
                   archived_reviews=counter.archived.get("reviews", 0), decisions=decisions)
    return summary


def ids_of(items: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(i.get("hub_id")) for i in items if i.get("hub_id")]
