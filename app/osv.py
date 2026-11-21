"""Точный запрос OSV (https://api.osv.dev/v1/query) по паре «экосистема, имя, версия» перед обращением к модели
(ADR-0112, бэклог п. 23). Исследование провайдером получает ответ OSV в первом сообщении (поле osv), а не ищет его
через инструменты: поисковый API провайдера делает GET, а OSV принимает только POST.

Что уходит в OSV – ровно то, что и провайдеру по ADR-0105 п. 1: экосистема, имя и версия компонента, ничего больше.
Адрес и сам факт запроса – часть текста инструкций согласия (строка «адрес запроса OSV: …», sca_research_net.
instructions/osv_url_from): получение по согласию без этой строки OSV не запрашивает, смена адреса – новое согласие.
Запрос идёт под теми же допуском (согласие действует, получение не остановлено, профиль включён, состав тот же) и
блокировками, что и обращение к модели (исполнитель настраивает клиент OSV так же, как клиент модели), по тем же
правилам адреса: https – класс external (глобальный адрес, закреплённое соединение), http – только адреса этого
компьютера (тесты). Обмен пишется в журнал обмена байт в байт (purpose research:osv). Ответ урезается: не больше
MAX_VULNS уязвимостей и MAX_CHARS знаков, у каждой – id, aliases, summary, published, modified, severity, affected
только по этому пакету (ranges; versions опущены), до MAX_REFS ссылок. Сбой запроса или ответ не по формату –
status error с причиной, строка исследуется дальше; повтора нет. Отказ допуска (SendNotAllowed) – наружу, как у
модели: получение останавливается. Запрос OSV бесплатен и не считается отправкой провайдеру: признак outcome.sent
он не ставит (строка после одного лишь запроса OSV при остановке возвращается в очередь)."""
from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any

from app.llm import LlmError, SendNotAllowed
from app.llm_http import track_sent

OSV_PATH = "/v1/query"
TIMEOUT_S = 20.0
MAX_VULNS = 40
MAX_REFS = 5
MAX_CHARS = 24_000

# экосистемы выгрузки (app/sca.py ECOSYSTEMS) → имена экосистем OSV; нет в словаре – unsupported. SwiftURL и Go
# требуют от OSV имени в виде адреса репозитория – короткие имена этих экосистем не поддерживаются (identity_kind).
OSV_ECOSYSTEMS: dict[str, str] = {
    "maven": "Maven", "gradle": "Maven", "sbt": "Maven", "ivy": "Maven",
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "pypi": "PyPI", "pip": "PyPI", "poetry": "PyPI",
    "nuget": "NuGet", "go": "Go", "golang": "Go", "cargo": "crates.io", "crates": "crates.io",
    "rubygems": "RubyGems", "gem": "RubyGems", "bundler": "RubyGems", "composer": "Packagist", "packagist": "Packagist",
    "hex": "Hex", "pub": "Pub", "cran": "CRAN", "conan": "ConanCenter",
}
PREVIEW = {"status": "pending", "note": "ответ OSV на пару координаты/версия этой строки приложение запросит при "
                                       "получении, до обращения к модели, и положит сюда"}
STATUSES = ("ok", "empty", "partial", "unsupported", "error")


def osv_ecosystem(ecosystem: Any) -> str | None:
    return OSV_ECOSYSTEMS.get(str(ecosystem or "").strip().casefold())


def normalize_name(eco: str, name: str) -> str:
    """Имя пакета для сравнения по правилам экосистемы OSV: PyPI – нормализация PEP 503 (регистр, «-_.» → «-»);
    crates.io – «_» и «-» равнозначны; NuGet – без учёта регистра; остальные – точное совпадение."""
    text = str(name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", text).lower()
    if eco == "crates.io":
        return text.replace("_", "-")
    if eco == "NuGet":
        return text.lower()
    return text


def query_for(row: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Тело запроса OSV для строки задания и примечание. None – запрос не делается: экосистема вне перечня OSV,
    координаты не разрешены (короткое имя Maven – identity_kind short_name) или нет имени/версии."""
    eco = osv_ecosystem(row.get("ecosystem"))
    name, version = str(row.get("component") or row.get("name") or "").strip(), str(row.get("version") or "").strip()
    if eco is None:
        return None, f"экосистема «{row.get('ecosystem')}» в OSV не поддерживается – запрос не делался"
    if not name or not version:
        return None, "нет имени или версии компонента – запрос не делался"
    if str(row.get("identity_kind") or "") == "short_name":
        return None, ("координаты не разрешены (короткое имя без groupId): точный запрос OSV до разрешения идентичности "
                      "не делался – пустой ответ по короткому имени ничего бы не доказывал")
    note = ""
    if eco == "Maven" and name.count(":") > 1:
        name = ":".join(name.split(":")[:2])
        note = "классификатор или тип артефакта отброшены: OSV ждёт groupId:artifactId"
    return {"package": {"ecosystem": eco, "name": name}, "version": version}, note


def _same_package(affected: Any, eco: str, name: str) -> bool:
    """Относится ли блок affected к запрошенному пакету. Координаты пакета обязательны: нет объекта package или
    в нём нет строковых ecosystem и name – принадлежность не установлена, это ошибка структуры записи (ValueError),
    а не «другой пакет»."""
    package = affected.get("package") if isinstance(affected, dict) else None
    if not isinstance(package, dict) or not isinstance(package.get("ecosystem"), str) \
            or not isinstance(package.get("name"), str) or not package["ecosystem"].strip() or not package["name"].strip():
        raise ValueError("affected без координат пакета")  # пустые координаты – не «другой пакет», а неизвестно чей
    return package["ecosystem"].strip() == eco and normalize_name(eco, package["name"]) == normalize_name(eco, name)


def _str_list(value: Any, what: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{what} – не список строк")
    return value


def _entry(v: Any, eco: str, name: str) -> dict[str, Any]:
    """Урезанная запись уязвимости; неверная структура сохраняемых полей – ValueError (запись пропускается, это
    считается потерей данных – статус partial)."""
    if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"].strip():
        raise ValueError("запись без id")
    aliases = _str_list(v.get("aliases"), "aliases")
    affected_all = v.get("affected")
    references = v.get("references")
    if affected_all is None:
        affected_all = []
    if references is None:
        references = []
    if not isinstance(affected_all, list) or not all(isinstance(a, dict) for a in affected_all):
        raise ValueError("affected – не список объектов")
    if not isinstance(references, list) or not all(isinstance(r, dict) for r in references):
        raise ValueError("references – не список объектов")
    item: dict[str, Any] = {"id": v["id"], "aliases": aliases, "summary": str(v.get("summary") or "")}
    for key in ("published", "modified"):
        if v.get(key) is not None:
            if not isinstance(v[key], str):
                raise ValueError(f"{key} – не строка")
            item[key] = v[key]
    severity = v.get("severity")
    if severity is not None:
        if not isinstance(severity, list) or not all(
                isinstance(x, dict) and isinstance(x.get("type"), str) and isinstance(x.get("score"), str) for x in severity):
            raise ValueError("severity – не список объектов {type, score}")
        item["severity"] = [{"type": x["type"], "score": x["score"]} for x in severity]
    affected = []
    for a in affected_all:
        if not _same_package(a, eco, name):
            continue
        ranges = a.get("ranges")
        if ranges is None:
            ranges = []
        if not isinstance(ranges, list):
            raise ValueError("ranges – не список")
        kept_ranges = []
        for r in ranges:  # по схеме OSV: {type, events: [{introduced|fixed|last_affected|limit: версия}], repo?}
            events = r.get("events") if isinstance(r, dict) else None
            if not isinstance(r, dict) or not isinstance(r.get("type"), str) or not isinstance(events, list) \
                    or not all(isinstance(e, dict) and all(isinstance(k, str) and isinstance(val, str) for k, val in e.items())
                               for e in events):
                raise ValueError("ranges[] – не объект {type, events[]}")
            entry = {"type": r["type"], "events": events}
            if "repo" in r and r["repo"] is not None:
                if not isinstance(r["repo"], str):
                    raise ValueError("ranges[].repo – не строка")
                entry["repo"] = r["repo"]
            kept_ranges.append(entry)
        affected.append({"ranges": kept_ranges})
    item["affected"] = affected
    refs = []
    for r in references:
        url = r.get("url")
        if url is not None and not isinstance(url, str):
            raise ValueError("references[].url – не строка")
        if url:
            refs.append(url)
    item["references"] = refs[:MAX_REFS]
    return item


def _size(items: list[dict[str, Any]]) -> int:
    return len(json.dumps(items, ensure_ascii=False))


def _fit(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Отрезать хвост списка, пока сериализация не уложится в MAX_CHARS: размер каждой записи считается один раз,
    сумма – арифметикой (скобки и запятые), без повторной сериализации на каждом шаге."""
    sizes = [len(json.dumps(item, ensure_ascii=False)) for item in items]
    keep = len(items)
    # сериализация списка: «[» + записи через «, » (два знака) + «]» – ровно как json.dumps без separators
    while keep and sum(sizes[:keep]) + 2 + 2 * max(0, keep - 1) > MAX_CHARS:
        keep -= 1
    return items[:keep], keep < len(items)


def trim(data: Any, eco: str, name: str) -> dict[str, Any]:
    """Разбор ответа OSV: {"status": ok|empty|partial, "vulns": урезанный список, "total": сколько прислал OSV,
    "skipped": записей с неверной структурой, "partial": есть продолжение (next_page_token), "note": примечание}.
    empty – только чистый пустой ответ ({} или пустой vulns); любая потеря (пропущенные записи, предел числа или
    размера, продолжение) – partial. Ответ не по формату (не объект, объект без vulns, но с другими полями, vulns не
    список, все записи негодные) – ValueError."""
    if not isinstance(data, dict):
        raise ValueError("ответ OSV – не объект JSON")
    if "vulns" not in data and set(data) - {"next_page_token"}:
        raise ValueError("в ответе OSV нет поля vulns")  # {} и страница только с токеном продолжения – допустимы
    raw = data.get("vulns")
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ValueError("поле vulns ответа OSV – не список")
    total = len(raw)
    valid: list[dict[str, Any]] = []
    skipped = 0
    for v in raw[:MAX_VULNS]:
        try:
            valid.append(_entry(v, eco, name))
        except ValueError:
            skipped += 1
    if total and not valid:
        raise ValueError(f"все просмотренные записи ответа OSV не по формату ({skipped} из {total})")
    out, cut_by_size = _fit(list(valid))
    ids_only = False
    if not out and valid:  # ни одна полная запись не помещается – идентификаторы проверенных записей, тоже под предел
        ids_only = True
        out, _ = _fit([{"id": v["id"], "aliases": v["aliases"][:10]} for v in valid])
        if not out:
            out, _ = _fit([{"id": valid[0]["id"]}])
        if not out:  # даже один идентификатор не помещается: обрезать его нельзя – это другое значение
            raise ValueError(f"идентификатор первой записи длиннее предела {MAX_CHARS} знаков")
    token = data.get("next_page_token")
    if token is not None and not isinstance(token, str):
        raise ValueError("next_page_token – не строка")  # неверный тип – не «нет продолжения», а ответ не по формату
    partial_page = bool(token)
    notes: list[str] = []
    if len(out) < total:
        reason = " (остальные не помещаются в предел размера)" if cut_by_size or ids_only else ""
        notes.append(f"показаны {len(out)} из {total} уязвимостей{reason}")
    if ids_only:
        notes.append(f"показаны только идентификаторы: подробности не помещаются в {MAX_CHARS} знаков")
    if skipped:
        notes.append(f"записей с неверной структурой пропущено: {skipped}")
    if partial_page:
        notes.append("у OSV есть продолжение ответа (next_page_token), показана первая страница")
    lossy = skipped > 0 or len(out) < total or ids_only or partial_page
    status = "partial" if lossy else ("ok" if out else "empty")
    return {"status": status, "vulns": out, "total": total, "skipped": skipped, "partial": partial_page,
            "note": "; ".join(notes)}


def make_client(url: str) -> Any:
    """Клиент OSV: тот же транспорт, что у внешних провайдеров (закреплённое соединение, правила адресов); класс
    доверия – по адресу: https – external (глобальный адрес), иначе local (адреса этого компьютера, тесты). Допуск
    (admission, before_send) и блокировки (gate) исполнитель ставит те же, что у клиента модели."""
    from app.llm_chat import ChatCompletionsClient
    client = ChatCompletionsClient(url, timeout=TIMEOUT_S)
    client.trust = "external" if urllib.parse.urlsplit(url).scheme.lower() == "https" else "local"
    client.provider = {"name": "OSV", "trust": client.trust}
    client.strict_body = True  # пустое тело ответа – сбой (status error), а не «OSV уязвимостей не знает»
    client.affiliation_mask = False  # OSV – не модель: имена пакетов уходят как есть (ADR-0118)
    return client


def lookup(url: str, row: dict[str, Any], client: Any = None) -> dict[str, Any]:
    """Ответ OSV для строки: {"status": ok|empty|partial|unsupported|error, "query", "vulns", "note", "sent",
    "seconds"}. Сети нет при unsupported; ошибка или ответ не по формату – error без повтора; отказ допуска
    (SendNotAllowed) – наружу."""
    started = time.monotonic()
    query, note = query_for(row)
    if query is None:
        return {"status": "unsupported", "query": None, "vulns": [], "note": note, "sent": False, "seconds": 0.0}
    result: dict[str, Any] = {"status": "error", "query": query, "vulns": [], "note": note, "sent": False, "seconds": 0.0}
    try:
        client = client or make_client(url)
        with track_sent() as tracker:
            try:
                data = client.post_json(OSV_PATH, query, TIMEOUT_S)
            finally:
                result["sent"] = bool(tracker.sent)
        parsed = trim(data, query["package"]["ecosystem"], query["package"]["name"])
        status = parsed["status"]
        notes = [n for n in (note, parsed["note"]) if n]
        if status == "empty":
            notes.append("уязвимостей для этой пары OSV не знает")
        result.update(status=status, vulns=parsed["vulns"], note="; ".join(notes))
    except SendNotAllowed:
        raise
    except LlmError as e:
        result["note"] = "; ".join(n for n in (note, f"запрос OSV не удался: {e}"[:500]) if n)
    except (ValueError, TypeError, AttributeError) as e:
        result["note"] = "; ".join(n for n in (note, f"ответ OSV не по формату: {e}"[:300]) if n)
    finally:
        result["seconds"] = round(time.monotonic() - started, 3)
    return result
