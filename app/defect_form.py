"""Контролы локального черновика и разбор явных действий формы."""

import json

from app import defect_fields, i18n
from app.defect_dto import SETTINGS
from app.defect_fields import FieldError

# ключи – поля Hub (не переводятся), подписи – на языке интерфейса
LABELS = i18n.Labels({"priority": "Приоритет", "severity": "Серьёзность", "source": "Источник", "tool": "Инструмент",
                      "stage": "Этап", "type": "Тип", "structureUnitId": "Структурная единица",
                      "releaseObject": "Объект выпуска", "dueDate": "Срок: дата, время и часовой пояс",
                      "isActive": "Активность", "settings": "Настройки статусов", "externalBugs": "Внешние дефекты"})
GROUP_FIELDS = {"priority": ("priority", "priorityId"), "severity": ("severity", "severityId"),
                "structureUnitId": ("structureUnitId", "appStructureUnit")}


def controls(fields, basis, choices):
    rows = []
    delta = defect_fields.diff(basis.get("base", {}), fields) if basis["known"] else basis.get("pending", [])
    changed = defect_fields.changed_roots(delta)
    for key, label in LABELS.items():
        group = GROUP_FIELDS.get(key, (key,))
        row = {"key": key, "label": label, "present": key in fields, "value": fields.get(key),
               "observed": {k: fields[k] for k in group if k in fields}, "changed": any(k in changed for k in group),
               "required": key in ("priority", "severity"), "hint": "", "options": []}
        if key == "priority":
            row["options"] = choices.get("priorities", [])
            if "priorityId" in fields or isinstance(fields.get(key), dict) and "rank" in fields[key]:
                row["options"] = []
                row["hint"] = i18n._("Источник соответствия имени, ID и rank не установлен; текущая комбинация сохраняется.")
            elif not row["options"]:
                row["hint"] = i18n._("Загрузите справочник имён приоритета.")
        elif key == "severity":
            row["hint"] = i18n._("Источник новых согласованных значений серьёзности не установлен; текущее значение сохраняется.")
        elif key == "structureUnitId":
            row["options"] = choices.get("structureUnits", [])
            row["hint"] = i18n._("Выбираются только однозначные пары двух ответов одной загрузки с совпадающими ID и именем.")
        elif key == "releaseObject":
            row["options"] = choices.get("releaseObjects", [])
            row["hint"] = i18n._("Принятие изменения Hub проверяется чтением после PUT.")
        elif key == "dueDate":
            row["hint"] = i18n._("Точная строка для Hub, например 2026-11-10T18:00:00+01:00. Часовой пояс обязателен; время не сдвигается.")
        row["reference"] = basis.get("references", {}).get(key)
        rows.append(row)
    return rows


def parse(form, current, choices):
    """Отсутствующий контрол ничего не удаляет. Boolean и отсутствие всегда задаются раздельно."""
    allowed = {"summary", "command_text", "draft_revision", "reference_load", "changes", "bug_order"}
    allowed |= {f"f_{key}_{part}" for key in LABELS for part in ("mode", "value")}
    allowed |= {f"setting_{key}" for key in SETTINGS}
    order = form.getlist("bug_order") if hasattr(form, "getlist") else form.get("bug_order", [])
    if isinstance(order, str):
        order = [order]
    if len(order) != len(set(order)) or any(not str(k).isdigit() for k in order):
        raise FieldError(i18n._("Неверный порядок строк внешних дефектов."))
    allowed |= {f"bug_{i}_{key}_{part}" for i in order for key in ("product", "displayName", "link")
                for part in ("mode", "value")}
    if set(form) - allowed:
        raise FieldError(i18n._("Неизвестные параметры формы: {names}", names=", ".join(sorted(set(form) - allowed))))
    if form.get("changes"):
        if any(k.startswith(("f_", "bug_", "setting_")) for k in form):
            raise FieldError(i18n._("Нельзя смешивать два представления изменений."))
        try:
            return json.loads(form["changes"])
        except ValueError as exc:
            raise FieldError(i18n._("changes: неверный JSON.")) from exc
    ops = []
    for key in LABELS:
        mode = form.get(f"f_{key}_mode", "keep")
        if mode == "keep":
            continue
        if mode not in ("set", "remove"):
            raise FieldError(i18n._("/{key}: неизвестное действие.", key=key))
        if mode == "remove":
            ops.extend({"path": "/" + k, "op": "remove"} for k in GROUP_FIELDS.get(key, (key,)))
            continue
        value = form.get(f"f_{key}_value", "")
        if key == "isActive":
            if value not in ("true", "false"):
                raise FieldError(i18n._("/isActive: выберите true или false."))
            value = value == "true"
        elif key == "priority":
            if value not in choices.get("priorities", []):
                raise FieldError(i18n._("/priority: выберите имя из справочника."))
            previous = current.get("priority")
            value = {**(previous if isinstance(previous, dict) else {}), "name": value}
        elif key in ("severity", "structureUnitId", "releaseObject"):
            variants = choices.get("structureUnits" if key == "structureUnitId" else "releaseObjects", [])
            if key == "severity" or not str(value).isdigit() or int(value) >= len(variants):
                raise FieldError(i18n._("/{key}: новый согласованный вариант недоступен.", key=key))
            value = variants[int(value)]
            if key == "structureUnitId":
                ops.extend({"path": "/" + k, "op": "set", "value": v} for k, v in value.items())
                continue
        elif key == "settings":
            previous = current.get(key)
            value = dict(previous) if isinstance(previous, dict) else {}
            for prop in SETTINGS:
                action = form.get(f"setting_{prop}", "keep")
                if action == "remove":
                    value.pop(prop, None)
                elif action in ("true", "false"):
                    value[prop] = action == "true"
                elif action != "keep":
                    raise FieldError(i18n._("/settings/{prop}: неверное значение.", prop=prop))
        elif key == "externalBugs":
            previous = current.get(key)
            previous = previous if isinstance(previous, list) else []
            value = []
            for index in order:
                item = dict(previous[int(index)]) if int(index) < len(previous) and isinstance(previous[int(index)], dict) else {}
                for prop in ("product", "displayName", "link"):
                    action = form.get(f"bug_{index}_{prop}_mode", "keep")
                    if action == "set":
                        item[prop] = str(form.get(f"bug_{index}_{prop}_value", ""))
                    elif action == "remove":
                        item.pop(prop, None)
                    elif action != "keep":
                        raise FieldError(i18n._("/externalBugs/{index}/{prop}: неверное действие.", index=index, prop=prop))
                value.append(item)
        ops.append({"path": "/" + key, "op": "set", "value": value})
    return ops
