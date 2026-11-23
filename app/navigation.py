"""Исходная рабочая задача и предыдущая справочная статья – независимые пути возврата."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from app import i18n

PROJECT_PAGE = re.compile(r"/projects/([0-9]+)/(findings|sca/findings|components|sca)(?:/([^/]+))?")
RUN_PAGE = re.compile(r"/(runs|journal)/([0-9]+)")


def local_url(value):
    if not isinstance(value, str) or len(value) > 6000 or not value.startswith("/"):
        return ""
    try:
        p = urlsplit(value)
    except ValueError:
        return ""
    if p.scheme or p.netloc or "\\" in value or any(ord(c) < 32 for c in value):
        return ""
    return value


def clean_url(value, *, article=False):
    value = local_url(value)
    if not value:
        return ""
    p = urlsplit(value)
    ignored = {"origin", "via", "ok", "err", "saved"}
    if article:
        ignored.add("back")
    return urlunsplit(("", "", p.path, urlencode([(k, v) for k, v in parse_qsl(p.query)
                                                if k not in ignored]), p.fragment))


def reference_url(value):
    p = urlsplit(local_url(value))
    return p.path in ("/cwe", "/capec", "/feeds", "/settings", "/journal") or \
        p.path.startswith(("/cwe/", "/capec/", "/bdu/", "/journal/", "/runs/")) or \
        bool(re.fullmatch(r"/projects/[0-9]+/capec", p.path))


def source_context(origin, db):
    origin = clean_url(origin)
    if not origin:
        return None
    p = urlsplit(origin)
    m = PROJECT_PAGE.fullmatch(p.path)
    if m:
        pid, kind, ident = int(m[1]), m[2], unquote(m[3] or "")
        if kind == "sca" and ident:
            return None
        project = db.get_project(pid)
        if not project:
            return None
        fallback = f"/projects/{pid}/" + ("sca" if kind == "sca/findings" else kind)
        title = {"findings": i18n._("Находки"), "sca/findings": "SCA", "sca": "SCA", "components": i18n._("Компоненты")}[kind]
        if ident:
            if kind == "components":
                from app.routes.components import views
                row = next((r for r in views(db, pid)[0] if r["input_ref"] == ident), None)
                if not row:
                    return None
                label = f"{row['name']}@{row['version']}"
                title = i18n._("К компоненту {name}", name=label)
            else:
                row = db.get_finding(pid, int(ident)) if ident.isascii() and ident.isdigit() else None
                if not row:
                    return None
                label = str(row["hub_id"])
                title = i18n._("К находке {id}", id=label)
        else:
            label = title
            title = i18n._("К списку: {title}", title=title)
        back = dict(parse_qsl(p.query)).get("back", "")
        queue = local_url(back)
        if not ident:
            queue = origin
        elif not queue or urlsplit(queue).path not in ({fallback, f"/projects/{pid}/findings"} if kind == "sca/findings" else {fallback}):
            filters = [(k, v) for k, v in parse_qsl(p.query) if k not in ("back", "origin", "via")]
            queue = fallback + ("?" + urlencode(filters) if filters else "")
        return {"origin": origin, "queue": queue, "label": label, "title": title,
                "project": project["name"], "missing": bool(ident and row.get("missing", row.get("export_missing")))}
    if p.path == "/journal" or RUN_PAGE.fullmatch(p.path):
        queue = local_url(dict(parse_qsl(p.query)).get("back", ""))
        if not queue or urlsplit(queue).path != "/journal":
            queue = origin if p.path == "/journal" else "/journal"
        number = p.path.rsplit("/", 1)[-1]
        return {"origin": origin, "queue": queue,
                "label": i18n._("Журнал") if p.path == "/journal" else i18n._("Прогон №{run}", run=number),
                "title": i18n._("К журналу") if p.path == "/journal" else i18n._("К прогону №{run}", run=number),
                "project": i18n._("Локальная модель"), "missing": False}
    return None


def page_context(request, values, db):
    path = request.url.path
    current = clean_url(path + ("?" + request.url.query if request.url.query else ""))
    # Самостоятельно открытая карточка начинает новую задачу; переходы по справочникам её не заменяют.
    own = bool(PROJECT_PAGE.fullmatch(path) or RUN_PAGE.fullmatch(path)) or path == "/journal"
    origin = current if own and not request.query_params.get("origin") else request.query_params.get("origin", "")
    if not origin and request.method == "POST" and values.get("row"):
        origin = clean_url(path.rsplit("/", 1)[0] + ("?" + request.url.query if request.url.query else ""))
    task = source_context(origin, db)
    via = clean_url(request.query_params.get("via", ""), article=True)
    if not reference_url(via) or urlsplit(via).path == path:
        via = ""
    if task:
        task.update(via=via, visible=reference_url(path) and current != task["origin"])

    def link(value):
        value = str(value or "")
        if not task or not local_url(value) or not reference_url(value):
            return value
        target = urlsplit(value)
        params = [(k, clean_url(v, article=True) if k == "back" and reference_url(v) else v)
                  for k, v in parse_qsl(target.query) if k not in ("origin", "via")]
        params.append(("origin", task["origin"]))
        previous = clean_url(current, article=True) if reference_url(path) and path != target.path else via
        if previous and previous != task["origin"]:
            params.append(("via", previous))
        return urlunsplit(("", "", target.path, urlencode(params), target.fragment))

    return {"task_context": task, "work_link": link}
