"""Нетекстовая правка: присутствие свойств, основа, слияние и подтверждение dev1b."""

import copy
import json

from app import i18n
from app.defect_dto import DEFECT_SCHEMA, REQUIRED_DEFECT, validate_defect, validate_value

EDITABLE_FIELDS = frozenset({"priority", "priorityId", "severity", "severityId", "source", "tool", "stage", "type",
                             "structureUnitId", "appStructureUnit", "dueDate", "releaseObject", "externalBugs",
                             "isActive", "settings"})
GROUPS = (("priority", "priorityId"), ("severity", "severityId"), ("structureUnitId", "appStructureUnit"))
REFERENCE_GROUPS = {"structureUnits": ("structureUnitId", "appStructureUnit"), "releaseObjects": ("releaseObject",)}
MISSING = object()


class FieldError(ValueError):
    """Неверные данные формы (422), в отличие от устаревшего состояния (409)."""


def equal(a, b):
    if a is MISSING or b is MISSING:
        return a is b
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(equal(v, b[k]) for k, v in a.items())
    if isinstance(a, list):
        return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b, strict=True))
    return a == b


def fields_of(obj):
    return copy.deepcopy({k: v for k, v in obj.items() if k in EDITABLE_FIELDS})


def diff(before, after, path=""):
    """Обычные объекты по путям; массив целиком. Значения в diff не нормализуются."""
    if equal(before, after):
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        return [change for key in sorted(before.keys() | after.keys())
                for change in diff(before.get(key, MISSING), after.get(key, MISSING), path + "/" + key)]
    return [{"path": path, "before_present": before is not MISSING, "after_present": after is not MISSING,
             **({"before": copy.deepcopy(before)} if before is not MISSING else {}),
             **({"after": copy.deepcopy(after)} if after is not MISSING else {})}]


def apply_changes(obj, changes):
    result = copy.deepcopy(obj)
    for change in changes:
        keys = change["path"].lstrip("/").split("/")
        parent = result
        for key in keys[:-1]:
            if not isinstance(parent.get(key), dict):
                parent[key] = {}
            parent = parent[key]
        if change["after_present"]:
            parent[keys[-1]] = copy.deepcopy(change["after"])
        else:
            parent.pop(keys[-1], None)
    return result


def new_basis(obj, origin, **source):
    return {"version": 1, "known": True, "base": fields_of(obj), "origin": origin, "references": {}, **source}


def basis_of(row):
    raw = row.get("draft_fields_basis_json") or ""
    if raw:
        return json.loads(raw)
    return {"version": 1, "known": False, "pending": [], "references": {}}


def local_changes(row):
    basis = basis_of(row)
    if not basis["known"]:
        raise ValueError(i18n._("приложение ещё не знает, какие поля дефекта сейчас в Hub – нажмите вверху карточки "
                                "«Принять поля из Hub» и снова «Push в Hub»"))
    return diff(basis["base"], json.loads(row["draft_fields_json"]))


def unsent_edit(row):
    """Есть ли у строки дефекта правка, не отправленная в Hub (план dev9, п. 1): заголовок относительно принятого – точно; текст у
    дефекта приложения – по строкам с нормализацией (разбор описания Hub отличается от него формой), у занесённого – точно, как в
    apply_sync; поля – local_changes, не строками JSON. Рост draft_revision сам по себе правкой не считается. Основа полей неизвестна
    – ValueError из local_changes: это отдельная причина, а не «правки нет»."""
    from app.hub_defects import _norm_lines
    if row["draft_summary"] != row["summary"]:
        return True
    draft, accepted = row["draft_command_text"], row["command_text"]
    if draft != accepted if row.get("origin") == "import" else _norm_lines(draft) != _norm_lines(accepted):
        return True
    return bool(local_changes(row))


def _merge_value(base, local, remote, path):
    if equal(local, base) or equal(local, remote):
        return copy.deepcopy(remote) if remote is not MISSING else MISSING
    if equal(remote, base):
        return copy.deepcopy(local) if local is not MISSING else MISSING
    if all(isinstance(x, dict) for x in (base, local, remote)):
        result = {}
        for key in base.keys() | local.keys() | remote.keys():
            value = _merge_value(base.get(key, MISSING), local.get(key, MISSING), remote.get(key, MISSING), path + "/" + key)
            if value is not MISSING:
                result[key] = value
        return result
    raise ValueError(i18n._("Конфликт сверки {path}: поле изменено локально и в Hub. Применение отменено.", path=path))


def merge(base, local, remote):
    result = {}
    grouped = set()
    for group in GROUPS:
        grouped.update(group)
        b, d, h = ({k: obj[k] for k in group if k in obj} for obj in (base, local, remote))
        if equal(d, b) or equal(d, h):
            result.update(copy.deepcopy(h))
        elif equal(h, b):
            result.update(copy.deepcopy(d))
        else:
            raise ValueError(i18n._("Конфликт сверки /{field}: связанная группа изменена с обеих сторон.", field=group[0]))
    for key in (base.keys() | local.keys() | remote.keys()) - grouped:
        value = _merge_value(base.get(key, MISSING), local.get(key, MISSING), remote.get(key, MISSING), "/" + key)
        if value is not MISSING:
            result[key] = value
    return result


def _known_path(path):
    keys = path.lstrip("/").split("/")
    if not path.startswith("/") or keys[0] not in EDITABLE_FIELDS:
        raise FieldError(i18n._("{path}: поле не редактируется.", path=path))
    schema = DEFECT_SCHEMA
    for key in keys:
        if not isinstance(schema, dict) or key not in schema:
            raise FieldError(i18n._("{path}: неизвестное свойство не редактируется.", path=path))
        schema = schema[key]
    return keys, schema


def _extensions_unchanged(old, new, schema, path, *, preserve_removed=False):
    if equal(old, new):
        return
    if isinstance(schema, dict):
        before = old if isinstance(old, dict) else {}
        after = new if isinstance(new, dict) else {}
        for key in before.keys() | after.keys():
            a, b = before.get(key, MISSING), after.get(key, MISSING)
            if key not in schema:
                if not equal(a, b):
                    raise FieldError(i18n._("{path}/{key}: расширение Hub должно сохраниться.", path=path, key=key))
            else:
                _extensions_unchanged(a, b, schema[key], path + "/" + key, preserve_removed=preserve_removed)
    elif isinstance(schema, list):
        # Порядок и состав записей правятся целиком; расширения сохранённых записей переносим без правки.
        available = [{k: v for k, v in item.items() if k not in schema[0]}
                     for item in old if isinstance(item, dict)] if isinstance(old, list) else []
        for item in new if isinstance(new, list) else []:
            extension = {k: v for k, v in item.items() if k not in schema[0]}
            if extension:
                index = next((i for i, previous in enumerate(available) if equal(previous, extension)), None)
                if index is None:
                    raise FieldError(i18n._("{path}: расширение записи Hub не редактируется.", path=path))
                available.pop(index)
        if preserve_removed and any(available):
            raise FieldError(i18n._("{path}: расширение записи Hub должно сохраниться.", path=path))


def edit(current, operations, choices):
    """Изменяются только явно указанные пути. Неизменённый некорректный ответ Hub остаётся наблюдением."""
    if not isinstance(operations, list):
        raise FieldError(i18n._("changes: требуется массив изменений."))
    proposed = copy.deepcopy(current)
    paths = []
    for op in operations:
        if not isinstance(op, dict) or set(op) - {"path", "op", "value"}:
            raise FieldError(i18n._("Неверный формат изменения поля."))
        path = op.get("path", "")
        if not isinstance(path, str):
            raise FieldError(i18n._("Путь поля должен быть строкой."))
        keys, schema = _known_path(path)
        if any(path == old or path.startswith(old + "/") or old.startswith(path + "/") for old in paths):
            raise FieldError(i18n._("{path}: повтор или пересечение изменений.", path=path))
        paths.append(path)
        action = op.get("op")
        if action == "set" and "value" in op:
            try:
                validate_value(op["value"], schema, path)
            except ValueError as exc:
                raise FieldError(str(exc)) from exc
        elif action == "remove":
            if len(keys) == 1 and keys[0] in REQUIRED_DEFECT:
                raise FieldError(i18n._("{path}: обязательное свойство нельзя удалить.", path=path))
        else:
            raise FieldError(i18n._("{path}: требуется set со значением или remove.", path=path))
        proposed = apply_changes(proposed, [{"path": path, "after_present": action == "set", "after": op.get("value")}])
    for root in EDITABLE_FIELDS - {"appStructureUnit", "releaseObject"}:
        _extensions_unchanged(current.get(root, MISSING), proposed.get(root, MISSING), DEFECT_SCHEMA[root], "/" + root)
    for main, linked in GROUPS:
        old, new = ({k: obj[k] for k in (main, linked) if k in obj} for obj in (current, proposed))
        if equal(old, new):
            continue
        if main == "priority" and linked not in old and linked not in new:
            if (isinstance(old.get(main, {}), dict) and "rank" not in old.get(main, {})
                    and equal({k: v for k, v in old.get(main, {}).items() if k != "name"},
                              {k: v for k, v in new.get(main, {}).items() if k != "name"})
                    and new.get(main, {}).get("name") in choices.get("priorities", [])):
                continue
        if main == "structureUnitId" and (not new or any(equal(new, x) for x in choices.get("structureUnits", []))):
            continue
        raise FieldError(i18n._("/{field}: нет подтверждённого соответствия связанных значений; сохраните текущую "
                                 "комбинацию.", field=main))
    if not equal(current.get("releaseObject", MISSING), proposed.get("releaseObject", MISSING)) and "releaseObject" in proposed:
        if not any(equal(proposed["releaseObject"], x) for x in choices.get("releaseObjects", [])):
            raise FieldError(i18n._("/releaseObject: выберите значение из сохранённого справочника."))
    return proposed


def candidate(fresh, row, summary, description):
    changes = local_changes(row)
    body = apply_changes(fresh, changes)
    draft = json.loads(row["draft_fields_json"])
    changed = set(changed_roots(changes))
    for group in REFERENCE_GROUPS.values():
        if changed.intersection(group):
            # Выбранный вариант переносится целиком, включая отсутствие необязательных свойств.
            for root in group:
                body.pop(root, None)
                if root in draft:
                    body[root] = copy.deepcopy(draft[root])
    body.update(summary=summary, description=description)
    validate_defect(body, row["hub_defect_id"], row["app_id"])
    _extensions_unchanged(fresh, body, DEFECT_SCHEMA, "", preserve_removed=True)
    old_priority = fresh["priority"] if isinstance(fresh.get("priority"), dict) else {}
    new_priority = body["priority"]
    if not equal(old_priority.get("name", MISSING), new_priority.get("name", MISSING)):
        if ("priorityId" in fresh or "priorityId" in body or "rank" in old_priority or "rank" in new_priority):
            raise FieldError(i18n._("/priority: нет подтверждённого соответствия связанных значений; сохраните текущую комбинацию."))
    return body, diff(fresh, body), changes


def changed_roots(changes):
    return sorted({c["path"].split("/")[1] for c in changes})


def confirmation_diffs(defect, sent, roots):
    return [k for k in roots if k not in ("summary", "description")
            and not equal(defect.get(k, MISSING), sent.get(k, MISSING))]
