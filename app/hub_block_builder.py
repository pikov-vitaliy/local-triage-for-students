"""Служебный блок Hub, собранный приложением из ответов `GET /templates/defects/model` (ADR-0139).

Hub пишет блок при создании дефекта и выдаёт заготовку только для непривязанных находок. У дефекта, чьи находки уже привязаны,
а блока в описании нет, взять его негде, поэтому он собирается здесь: данные из ответа Hub, разметка по образцу настоящих блоков.
Шаблона оформления Hub не отдаёт, так что собранный блок может отличаться от того, что написал бы сам Hub; оператор видит это в
предпросмотре Push.

Модуль чистый: ни базы, ни запросов. Текстовые значения экранируются, `description` – разметка Hub и вставляется как есть.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

_SECTION = re.compile(r"<h3[^>]*>\s*(.*?)\s*</h3>(.*?)(?=<h3|\Z)", re.S | re.I)
_PARAGRAPH = re.compile(r"^\s*<p[^>]*>(.*)</p>\s*$", re.S | re.I)
_SAFE_URL = re.compile(r"^https?://", re.I)
_COMPONENT_NAME = re.compile(r"([^/:]+)$")
SCA_SECTIONS = (("Описание", "Description"), ("Объяснение", "Explanation"))


def _text(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=False)


def _link(url: Any, title: Any) -> str:
    """Ссылка только на http и https: адрес приходит из ответа Hub и попадёт в описание дефекта."""
    address = str(url or "")
    if not _SAFE_URL.match(address):
        return _text(title)
    return f'<a href="{html.escape(address, quote=True)}">{_text(title)}</a>'


def _first(values: Any) -> Mapping[str, Any]:
    return values[0] if isinstance(values, list) and values and isinstance(values[0], Mapping) else {}


def _date(value: Any) -> str:
    """Время из миллисекунд UTC в написании Hub: `Jul 24, 2026, 1:21:38 PM`."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return ""
    moment = datetime.fromtimestamp(value / 1000, UTC)
    hour = moment.hour % 12 or 12
    return f"{moment.strftime('%b')} {moment.day}, {moment.year}, {hour}:{moment.minute:02d}:{moment.second:02d} {moment.strftime('%p')}"


def _table(rows: Iterable[tuple[str, Any]]) -> str:
    cells = "".join(f"<tr><th>{_text(name)}</th><td>{_text(value)}</td></tr>" for name, value in rows)
    return f"<table><tbody>{cells}</tbody></table>"


def _issue_of(model: Mapping[str, Any]) -> Mapping[str, Any]:
    issues = model.get("issues") if isinstance(model, Mapping) else None
    if not isinstance(issues, list) or len(issues) != 1 or not isinstance(issues[0], Mapping):
        raise ValueError("в ответе модели шаблона нет одной находки")
    return issues[0]


def _target_rows(issue: Mapping[str, Any], scan_object: str) -> list[tuple[str, Any]]:
    scan = issue.get("lastScan") if isinstance(issue.get("lastScan"), Mapping) else {}
    target = _first(scan.get("scanTarget"))
    return [("Дата сканирования", _date(scan.get("date"))), ("Объект сканирования", scan_object), ("Ветка", target.get("branch") or ""),
            ("Коммит", target.get("commit") or ""), ("URL объекта", target.get("url") or "")]


def _scan_object(issue: Mapping[str, Any], grouped: bool) -> str:
    scan = issue.get("scanObject") if isinstance(issue.get("scanObject"), Mapping) else {}
    ident = scan.get("id")
    number = f"{ident:,}" if grouped and isinstance(ident, int) and not isinstance(ident, bool) else str(ident if ident is not None else "")
    return f"#{number}: {scan.get('name') or ''}"


def _head(issues: list[Mapping[str, Any]]) -> str:
    people = list(dict.fromkeys(str((i.get("lastScan") or {}).get("initiator") or "") for i in issues))
    people = [p for p in people if p]
    table = _table([("Инициаторы", ", ".join(people))]) if people else "<table><tbody></tbody></table>"
    return f"<h3>Информация об объекте сканирования:</h3>\n{table}\n"


def _place(path: Any) -> str:
    entry = path if isinstance(path, Mapping) else {}
    line = entry.get("line")
    # номер строки Hub пишет с разделителем тысяч: `:1,210`
    shown = f"{line:,}" if isinstance(line, int) and not isinstance(line, bool) else str(line if line is not None else "")
    return f"{entry.get('fileName') or ''}:{shown}"


def _first_place(issue: Mapping[str, Any]) -> str:
    """Файл находки в сводке – первый шаг трассы."""
    paths = issue.get("path")
    return _place(paths[0]) if isinstance(paths, list) and paths else ""


def _sast_summary(issues: list[Mapping[str, Any]]) -> str:
    if len(issues) == 1:
        one = issues[0]
        return (f"<p>ID: {_link(one.get('link'), one.get('id'))}</p>\n<p>Файл: {_text(_first_place(one))}</p>\n"
                f"<p>Серьёзность: {_text(one.get('severity'))}</p>\n"
                f"<p>Категория: {_link(_first(one.get('cwes')).get('link'), one.get('category'))}</p>\n")
    rows = "".join(f"<tr><td>{_link(i.get('link'), i.get('id'))}</td><td>{_text(_first_place(i))}</td><td>{_text(i.get('severity'))}</td>"
                   f"<td>{_link(_first(i.get('cwes')).get('link'), i.get('category'))}</td></tr>" for i in issues)
    return f"<table><tbody><tr><th>ID</th><th>Файл</th><th>Серьёзность</th><th>Категория</th></tr>{rows}</tbody></table>\n"


def _sast_detail(issue: Mapping[str, Any]) -> str:
    steps = issue.get("path") if isinstance(issue.get("path"), list) else []
    trace = "<br>\n<br>\n".join(f"<div>{_text(_place(step))}</div>\n<div>{_text((step or {}).get('sourceCode'))}</div>\n" for step in steps)
    return (f"<h2>ID: {_link(issue.get('link'), issue.get('id'))}</h2>\n{_table(_target_rows(issue, _scan_object(issue, False)))}\n"
            f"<h3>Трасса</h3>\n<div>{{code}}</div>\n{trace}<br>\n<br>\n<div>{{code}}</div>\n<br>\n"
            f"<h3>Описание</h3>\n<div>{{panel}}</div>\n{issue.get('description') or ''}\n<div>{{panel}}</div>\n")


def _sast(issues: list[Mapping[str, Any]]) -> str:
    details = "<p>----------</p>\n".join(_sast_detail(i) for i in issues)
    return (f"{_head(issues)}\n<h3>Сводка по уязвимостям:</h3>\n{_sast_summary(issues)}\n<h1>Детальная информация по уязвимостям:</h1>\n"
            f"<p>----------</p>\n{details}")


def _sections(description: Any) -> dict[str, str]:
    """Разделы описания находки SCA: `<h3>Description</h3><p>…</p>`, значение – содержимое абзаца как есть."""
    out: dict[str, str] = {}
    for title, body in _SECTION.findall(str(description or "")):
        inner = _PARAGRAPH.match(body)
        out[html.unescape(re.sub(r"<[^>]+>", "", title)).strip()] = (inner.group(1) if inner else body).strip()
    return out


def _component_name(title: Any) -> str:
    found = _COMPONENT_NAME.search(str(title or "").strip())
    return found.group(1) if found else ""


def _sca_summary(issues: list[Mapping[str, Any]]) -> str:
    if len(issues) == 1:
        one = issues[0]
        cve = one.get("cve") if isinstance(one.get("cve"), Mapping) else {}
        return (f"<p>ID: {_link(one.get('link'), one.get('id'))}</p>\n<p>Компонент: {_text(one.get('title'))}</p>\n"
                f"<p>Серьёзность: {_text(one.get('severity'))}</p>\n<p>Инструмент: {_link(one.get('externalLink'), one.get('foundBy'))}</p>\n"
                f"<p>Уязвимость: {_link(cve.get('link'), cve.get('id'))}</p>\n<p>Версия исправления: {_text(one.get('fixVersion'))}</p>\n")
    rows = ""
    for issue in issues:
        cve = issue.get("cve") if isinstance(issue.get("cve"), Mapping) else {}
        rows += (f"<tr><td>{_link(issue.get('link'), issue.get('id'))}</td><td>{_text(issue.get('title'))}</td><td>{_text(issue.get('severity'))}</td>"
                 f"<td>{_link(issue.get('externalLink'), issue.get('foundBy'))}</td><td>{_link(cve.get('link'), cve.get('id'))}</td>"
                 f"<td>{_text(issue.get('fixVersion'))}</td></tr>")
    head = "".join(f"<th>{name}</th>" for name in ("ID", "Компонент", "Серьёзность", "Инструмент", "Уязвимость", "Версия исправления"))
    return f"<table><tbody><tr>{head}</tr>{rows}</tbody></table>\n"


def _references(value: str) -> str:
    """Источники: каждый адрес отдельным абзацем, как в настоящем блоке. Запятая – разделитель только между адресами: внутри адреса и в
    конце последнего она остаётся; строка с разметкой или с обычным текстом остаётся целой."""
    lines: list[str] = []
    for part in re.split(r"<br\s*/?>", value):
        words = [word for word in part.split() if word not in ("-", "*")]
        words = [word.rstrip(",") if at < len(words) - 1 else word for at, word in enumerate(words)]
        if "<" not in part and all(_SAFE_URL.match(word) for word in words):
            lines += words
        elif part.strip():
            lines.append(part.strip())
    return "".join(f"<p>{line}</p>\n" for line in lines)


def _sca_detail(issue: Mapping[str, Any]) -> str:
    cve = issue.get("cve") if isinstance(issue.get("cve"), Mapping) else {}
    cvss = issue.get("cvss") if isinstance(issue.get("cvss"), Mapping) else {}
    cwes = issue.get("cwes") if isinstance(issue.get("cwes"), list) else []
    sections = _sections(issue.get("description"))
    parts = [f"<p><strong>{name}</strong></p>\n<p>{sections.get(key, '')}</p>\n" for name, key in SCA_SECTIONS]
    target = [("Компонент", issue.get("title")), *_target_rows(issue, _scan_object(issue, True))]
    fix = f"Обновление {_component_name(issue.get('title'))} до версии {issue.get('fixVersion') or ''}"
    return (f"<h4>ID: {_link(issue.get('link'), issue.get('id'))}</h4>\n<h4>Информация по цели сканирования:</h4>\n{_table(target)}\n<br>\n"
            f"<h4>Информация по уязвимости:</h4>\n<p>{_text(cve.get('link'))}</p>\n"
            + _table([("Тип уязвимости CWE", ", ".join(str((c or {}).get("id") or "") for c in cwes)), ("CVSS оценка", cvss.get("score") or ""),
                      ("Связанная уязвимость (CVE)", cve.get("id") or "")])
            + "\n" + "".join(parts) + f"<p><strong>Рекомендации</strong></p>\n<p>{_text(fix)}</p>\n"
            + f"<p><strong>Источники</strong></p>\n{_references(sections.get('Reference', ''))}")


def _sca(issues: list[Mapping[str, Any]]) -> str:
    details = "<p>----------</p>\n".join(_sca_detail(i) for i in issues)
    return (f"{_head(issues)}\n<h3>Сводка по уязвимостям:</h3>\n{_sca_summary(issues)}\n<h3>Детальная информация по уязвимостям:</h3>\n"
            f"<p>----------</p>\n{details}")


def build_block(kind: str, models: Iterable[Mapping[str, Any]]) -> str:
    """Блок дефекта вида kind («SAST», «SCA») по ответам модели шаблона, в порядке находок дефекта. Ответа нет или в нём не одна находка – ValueError:
    из неполного набора блок не собирается."""
    issues = [_issue_of(model) for model in models]
    if not issues:
        raise ValueError("нет ответов модели шаблона")
    if kind == "SAST":
        return _sast(issues)
    if kind == "SCA":
        return _sca(issues)
    raise ValueError(f"блок для вида дефекта «{kind}» не собирается")
