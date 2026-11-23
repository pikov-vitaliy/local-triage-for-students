"""Обзор групп и навигация рабочих таблиц. Только представление, без изменения записей."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlencode, urlsplit

from app import i18n
from app.db import hub_verdict

SIZES = (25, 50, 100, 200)


def options(params, sorts):
    """Только параметры представления, допустимые для конкретной страницы."""
    return {"page": str(params.get("page", ""))[:12],
            "page_size": str(params.get("page_size", ""))[:4],
            "group_by": "family" if params.get("group_by") == "family" else "",
            "family": params.get("family", "") if re.fullmatch(r"[0-9a-f]{24}", params.get("family", "")) else "",
            "sort": params.get("sort", "") if params.get("sort") in sorts else ""}


def return_url(request, fallback):
    """Возврат только в ту же таблицу проекта, без произвольного адреса."""
    value = request.query_params.get("back", "")[:2000]
    try:
        parts = urlsplit(value)
    except ValueError:
        return fallback
    return value if not parts.netloc and not parts.scheme and parts.path == fallback else fallback


_LIST_ANCHORS = {"sca": "#components", "components": "#component-list"}


def list_anchor(url: str) -> str:
    """Адрес списка SCA или компонентов – с якорем таблицы, чтобы возврат и открытая группа не начинались с верха
    страницы. Другие адреса и адреса с якорем – как есть."""
    if "#" in url:
        return url
    m = re.fullmatch(r"/projects/\d+/(sca|components)", urlsplit(url).path)
    return url + _LIST_ANCHORS[m.group(1)] if m else url


def integer(value, fallback=1):
    try:
        return int(str(value)[:12])
    except (ValueError, TypeError):
        return fallback


def family(row, kind):
    if kind == "findings":
        data = row["data"]
        if row["kind"] in ("SCA", "SCA-license"):
            from app import package_identity
            eco, name, _ = package_identity.of(data)  # эффективная тройка (план dev17, п. 4.3)
            key = (row["kind"], eco, name)
        else:
            name = data.get("rule", "")
            key = (row["kind"], data.get("tool", ""), name)
        scope = " · ".join(str(x) for x in key[:-1] if x)
    else:
        name = row.get("name", row.get("component", ""))
        key = (row.get("ecosystem", ""), name)
        scope = key[0]
    if not name:
        key += (str(row.get("id", row.get("input_ref", ""))),)
    token = hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:24]
    return token, str(name or i18n._("Имя не указано")), scope


def severity_key(row):
    score = row.get("cvss") if row.get("kind") in ("SCA", "SCA-license") else None
    if score is not None:
        from app.cvss import version_of
        if version_of(row.get("data")) == "2.0":
            rank = 3 if score >= 7 else 2 if score >= 4 else 1
        else:
            rank = 4 if score >= 9 else 3 if score >= 7 else 2 if score >= 4 else 1 if score > 0 else 0
        return rank, float(score)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(row.get("severity", ""))
    return (rank, 0) if rank is not None else None


def sort_findings(rows, sort):
    if sort not in ("severity_desc", "severity_asc"):
        return rows
    # Стабильный исходный порядок для равных значений; неизвестные всегда в конце.
    known = [r for r in rows if severity_key(r) is not None]
    unknown = [r for r in rows if severity_key(r) is None]
    return sorted(known, key=severity_key, reverse=sort == "severity_desc") + unknown


# столбцы обзора групп находок и SCA (план dev7, раздел 3): находка попадает ровно в один, сумма равна «Находок»
# подписи – msgid (ADR-0158): перевод при построении страницы (buckets в выдаче work_list)
BUCKETS = (("in_defect", i18n.N_("В дефекте"), i18n.N_("Находка входит в дефект")),
           ("false_positive", i18n.N_("Ложные"), i18n.N_("Решение – ложное срабатывание")),
           ("risk_accepted", i18n.N_("Риск принят"), i18n.N_("Решение – риск принят")),
           ("no_defect", i18n.N_("Подтверждено, без дефекта"), i18n.N_("Находка подтверждена, дефекта нет")),
           ("undecided", i18n.N_("Без решения"), i18n.N_("Решения нет, находка отложена или вывод «неясно»")))

GROUP_SEVERITY_LABELS = i18n.Labels({4: "критическая", 3: "высокая", 2: "средняя", 1: "низкая", 0: "информация"})


def finding_bucket(decision, final_verdict, in_defect: bool) -> str:
    """Столбец находки: дефект важнее решения – у находки в дефекте работа уже идёт через него."""
    if in_defect:
        return "in_defect"
    if not decision and not final_verdict:
        return "undecided"
    return {"false_positive": "false_positive", "risk_accepted": "risk_accepted",
            "true_positive": "no_defect"}.get(hub_verdict(decision or "", final_verdict or ""), "undecided")


def table(rows, params, *, path, default_size=200, kind="", sorts=None):
    """Отбор группы и пагинация после предметной фильтрации/сортировки всей выборки."""
    # кортеж значений (многозначный отбор, бэклог 99) сохраняется и кодируется по одному параметру на значение
    params = {k: (tuple(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v))
              for k, v in params.items() if v and k not in ("ok", "err", "n")}
    size = integer(params.get("page_size"), default_size)
    size = size if size in SIZES else default_size
    params["page_size"] = str(size)
    grouped = bool(kind and params.get("group_by") == "family")
    selected = params.get("family", "") if kind else ""
    groups = {}
    for row in rows if kind else []:
        token, name, scope = family(row, kind)
        group = groups.setdefault(token, {"token": token, "name": name, "scope": scope, "rows": [], "versions": set(), "findings": 0, "decided": 0, "buckets": None, "entered": 0, "score": None, "severity": None,
                                          "defect_map": {}, "versions_with_defect": set(), "versions_closed": set(),
                                          "versions_done": set()})
        group["rows"].append(row)
        version = row.get("version") or row.get("data", {}).get("version")
        if version:
            group["versions"].add(version)
        for item in row.get("defects") or []:  # дефекты приложения по записям группы
            group["defect_map"].setdefault(item["id"], item)
            if version and item.get("bound"):  # подготовка (заготовка, предпросмотр) версию «в дефекте» не делает
                group["versions_with_defect"].add(version)
        if version and row.get("closed_without_defect"):  # закрыта в Hub статусом без дефекта
            group["versions_closed"].add(version)
        if version and row.get("all_findings_closed"):  # у каждой находки версии подтверждённый дефект или статус
            group["versions_done"].add(version)
        findings = row.get("finding_count", row.get("findings", 1))
        group["findings"] += len(findings) if isinstance(findings, list) else int(findings)
        group["decided"] += int(bool(row.get("decided", row.get("decision"))))
        if row.get("buckets") is not None:  # у компонентов столбцов нет: там по-прежнему «С решением»
            group["buckets"] = group["buckets"] or dict.fromkeys((b[0] for b in BUCKETS), 0)
            for name, value in row["buckets"].items():
                group["buckets"][name] += value
            group["entered"] += int(row.get("entered") or 0)
        score = row.get("cvss")
        if score is not None:
            group["score"] = max(group["score"] or 0, score)
        level = severity_key(row)
        if level is not None and (group["severity"] is None or level > group["severity"]):
            group["severity"] = level
    all_total = len(rows)
    active = groups.get(selected)
    if selected:
        rows = active["rows"] if active else []
    overview = grouped and not selected
    units = list(groups.values()) if overview else rows
    pages = max(1, (len(units) + size - 1) // size)
    page = min(max(1, integer(params.get("page"))), pages)

    def url(**changes):
        values = {**params, **changes}
        return path + "?" + urlencode({k: v for k, v in values.items() if v != "" and v != () and v is not None},
                                      doseq=True)

    shown = units[(page - 1) * size:page * size]
    numbers = sorted({1, pages, *range(max(1, page - 2), min(pages, page + 2) + 1)})
    links = []
    for n in numbers:
        if links and n > links[-1]["number"] + 1:
            links.append({"number": n - 1, "gap": True})
        links.append({"number": n, "url": url(page=n), "gap": False})
    for g in groups.values():
        g.update(count=len(g["rows"]), version_count=len(g["versions"]),
                 defects=[g["defect_map"][k] for k in sorted(g["defect_map"])],
                 versions_closed=sorted(g["versions_closed"] - g["versions_with_defect"]),
                 # «без дефекта» – только когда у группы уже есть дефект или закрытая версия: нетронутая группа подсказки не получает
                 versions_without_defect=sorted(g["versions"] - g["versions_with_defect"] - g["versions_closed"])
                 if g["versions_with_defect"] or g["versions_closed"] else [],
                 # «все версии закрыты» – только по подтверждённому закрытию каждой находки (ревью dev27: незавершённый
                 # дефект и находка без решения рядом с дефектом группу не закрывают)
                 all_closed=bool(g["versions"]) and g["versions"] <= g["versions_done"],
                 severity_label=(GROUP_SEVERITY_LABELS.get(g["severity"][0], "–") if g["severity"] else "–"),
                 versions_preview=sorted(g["versions"])[:5],
                 # открытая группа – сразу у таблицы, а не в начале страницы
                 url=list_anchor(url(family=g["token"], group_by="family", page=1)))
    sort = params.get("sort", "")
    buckets = [(key, i18n._(label), i18n._(hint)) for key, label, hint in BUCKETS]
    return {"rows": [] if overview else shown, "groups": shown if overview else [], "buckets": buckets,
            "overview": overview, "grouped": grouped, "can_group": bool(kind), "active": active,
            "family_selected": bool(selected), "all_total": all_total, "total": len(units),
            "row_total": len(rows), "group_total": len(groups), "page": page, "pages": pages,
            "start": (page - 1) * size + 1 if units else 0, "end": min(page * size, len(units)),
            "size": size, "sizes": SIZES, "path": path, "params": params,
            "hidden": [(k, item) for k, v in params.items() if k not in ("page", "page_size")
                       for item in (v if isinstance(v, tuple) else (v,))],
            "links": links, "prev": url(page=page - 1) if page > 1 else "",
            "next": url(page=page + 1) if page < pages else "",
            "flat_url": url(group_by="", family="", page=1),
            "group_url": url(group_by="family", family="", page=1),
            "sort": sort, "sorts": [{"key": k, "label": v, "url": url(sort=k, page=1)} for k, v in (sorts or {}).items()],
            "sort_url": lambda key: url(sort=key, page=1), "url": url}
