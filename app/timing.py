"""Замер времени страниц (бэклог 123): сколько отвечает запрос, сколько из этого – запросы к базе и чьи.

Каждый ответ получает заголовок Server-Timing (виден в инструментах разработчика браузера): общее время до начала
ответа и время обращений к базе с их числом. Запрос дольше SLOW_MS пишется в журнал одной строкой: шаблон маршрута
(«/projects/{project_id}», без значений и параметров адреса), время, число обращений к базе (executemany – одно) и пять самых долгих мест
вызова – имена функций приложения («db.sca_snapshot ← projects.project_page»). Текста запросов, значений, путей и
данных находок в строке нет (app/logsafe.py).

Одиночное обращение дольше EXPLAIN_MS – один раз на место вызова за время работы процесса снимается его план
(EXPLAIN ANALYZE, только для запросов чтения) и пишется строка с самыми долгими узлами: тип узла, имя таблицы, CTE
или функции, время, число строк. Условий, выражений и значений из плана в журнал не попадает.

Замер включается только для запроса страницы: фоновые исполнители и прогоны его не ведут и ничего не тратят.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import sys
from time import perf_counter
from typing import Any

log = logging.getLogger("local_triage.timing")


def _console() -> None:
    """Строки замера – в журнал контейнера: Uvicorn не настраивает журналы приложения (уровень WARNING, без
    обработчиков), поэтому у этого журнала свой обработчик в stderr и уровень INFO. Остальные журналы приложения
    не меняются. Повторный вызов обработчик не добавляет."""
    log.setLevel(logging.INFO)
    if not any(getattr(h, "_timing", False) for h in log.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("INFO:     %(message)s"))
        handler._timing = True  # type: ignore[attr-defined]
        log.addHandler(handler)

SLOW_MS = 1000  # запрос дольше – строка в журнал (цель бэклога 123 – страница до 1 с)
TOP = 5  # сколько мест вызова называть
_APP = os.path.dirname(os.path.abspath(__file__))
_STORAGE = os.path.join(_APP, "storage")
_DEPTH = 60  # глубина поиска места вызова по стеку


class PageTiming:
    """Счётчики одного запроса: число и время запросов к базе всего и по местам вызова."""

    __slots__ = ("count", "seconds", "places", "active")

    def __init__(self) -> None:
        self.active = True  # False – замер закрыт (потоковый ответ): обращения больше не учитываются
        self.count = 0
        self.seconds = 0.0
        self.places: dict[str, list[float]] = {}

    def add(self, place: str, seconds: float) -> None:
        self.count += 1
        self.seconds += seconds
        slot = self.places.setdefault(place, [0, 0.0])
        slot[0] += 1
        slot[1] += seconds

    def top(self, n: int = TOP) -> list[tuple[str, int, float]]:
        """Самые долгие места вызова: [(место, число запросов, секунды)]."""
        ranked = sorted(self.places.items(), key=lambda kv: kv[1][1], reverse=True)[:n]
        return [(place, int(c), s) for place, (c, s) in ranked]


CURRENT: contextvars.ContextVar[PageTiming | None] = contextvars.ContextVar("page_timing", default=None)


def current() -> PageTiming | None:
    """Действующий замер запроса страницы или None (вне запроса или замер закрыт)."""
    page = CURRENT.get()
    return page if page is not None and page.active else None


def _name(frame: Any) -> str:
    path = frame.f_code.co_filename
    module = os.path.splitext(os.path.relpath(path, _APP))[0].replace(os.sep, ".")
    return f"{module}.{frame.f_code.co_name}"


def caller(skip: int = 2) -> str:
    """Место вызова запроса к базе: внешняя функция первого модуля приложения вне слоя хранения (общие помощники
    вроде db.run пропускаются – называется метод, который их вызвал) с номером строки, откуда пошёл запрос, и
    функция следующего модуля («db.sca_snapshot:1210 ← routes.projects.project_page»). Если запрос пошёл из
    вложенной функции того же модуля, она называется в скобках со своей строкой («hub_state.<lambda>:51
    (hub_state._runs:62) ← …»): разные запросы одной цепочки различаются. Только имена модулей, функций и номера
    строк кода."""
    try:
        frame = sys._getframe(skip)
    except ValueError:
        return "?"
    first = ""
    first_file = ""
    inner = ""  # функция модуля, из которой пошёл сам запрос (самый внутренний кадр первого модуля)
    for _ in range(_DEPTH):
        if frame is None:
            break
        path = os.path.abspath(frame.f_code.co_filename)
        if path.startswith(_STORAGE):
            pass  # слой хранения (курсор, транзакции, db.read) – не место вызова
        elif path.startswith(_APP):
            if not first_file or path == first_file:
                first, first_file = f"{_name(frame)}:{frame.f_lineno}", path
                inner = inner or first
            else:
                return f"{_label(first, inner)} ← {_name(frame)}"
        elif first_file:
            break  # вызов из-за пределов приложения (тест, библиотека): дальше по стеку приложения нет
        frame = frame.f_back
    return _label(first, inner) or "?"


def _label(first: str, inner: str) -> str:
    return first if inner == first else f"{first} ({inner})"


def route_of(scope: dict) -> str:
    """Шаблон маршрута запроса без значений («/projects/{project_id}/sca»); маршрут не найден – «?»."""
    route = scope.get("route")
    return str(getattr(route, "path", "") or "?")


class TimingMiddleware:
    """Server-Timing каждому ответу и строка в журнал о медленном запросе. Потоковые ответы (text/event-stream)
    медленными не считаются: они открыты, пока открыта страница, и после заголовка замер закрывается. Запросы
    исполнителя Hub (/api/hub/…) в журнал медленных не пишутся: его долгий опрос ждёт заданий намеренно. Слой – самый внешний (снаружи GuardMiddleware):
    замер видит окончательный ответ, в том числе страницу внутренней ошибки и ранний отказ защиты."""

    def __init__(self, app: Any, slow_ms: float | None = None) -> None:
        self.app = app
        self.slow_ms = slow_ms
        _console()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or str(scope.get("path", "")).startswith("/static/"):
            await self.app(scope, receive, send)
            return
        page = PageTiming()
        token = CURRENT.set(page)
        started = perf_counter()
        state = {"status": 0, "stream": False}

        async def timed_send(message: dict) -> None:
            if message["type"] == "http.response.start":
                state["status"] = int(message.get("status") or 0)
                headers = list(message.get("headers") or [])
                state["stream"] = any(k.lower() == b"content-type" and v.startswith(b"text/event-stream")
                                      for k, v in headers)
                if state["stream"]:
                    page.active = False  # поток открыт, пока открыта страница: дальше не считать
                spent = (perf_counter() - started) * 1000
                headers.append((b"server-timing", (f'app;dur={spent:.0f}, sql;dur={page.seconds * 1000:.0f};'
                                                   f'desc="{page.count}"').encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, timed_send)
        finally:
            CURRENT.reset(token)
            spent = (perf_counter() - started) * 1000
            limit = SLOW_MS if self.slow_ms is None else self.slow_ms
            # исполнитель Hub ждёт задания долгим опросом (/api/hub/jobs) – это не страница и не задержка
            if spent >= limit and not state["stream"] and not route_of(scope).startswith("/api/hub/"):
                places = "; ".join(f"{p} ×{c} {s * 1000:.0f} мс" for p, c, s in page.top())
                log.info("медленный запрос %s %s: %.0f мс, ответ %d; обращений к базе %d, %.0f мс; больше всего: %s",
                         scope.get("method", "?"), route_of(scope), spent, state["status"], page.count,
                         page.seconds * 1000, places or "–")


# ---------------------------------------------------------------- план медленного обращения (бэклог 123, шаг 2)

EXPLAIN_MS = 1000  # одиночное обращение дольше – один раз снять его план (EXPLAIN ANALYZE) и записать в журнал
PLAN_TOP = 6  # сколько самых долгих узлов плана называть
_EXPLAINED: set[str] = set()  # места вызова, план которых уже снят этим процессом
_READ_ONLY = re.compile(r"^\s*(SELECT|WITH)\b", re.I)
_WRITES = re.compile(r"\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|COPY|CALL|DO|FOR\s+(NO\s+KEY\s+)?UPDATE|FOR\s+(KEY\s+)?SHARE|"
                     r"NEXTVAL|SETVAL|PG_ADVISORY\w*|PG_TRY_ADVISORY\w*|SET_CONFIG|LO_\w+)\b", re.I)


def explain_wanted(place: str, query: Any, seconds: float) -> bool:
    """Снимать ли план: обращение дольше EXPLAIN_MS, только чтение (SELECT или WITH без записи и блокировок: EXPLAIN
    ANALYZE выполняет запрос ещё раз) и план этого места ещё не снимался. Место отмечается сразу – повтора нет."""
    if seconds * 1000 < EXPLAIN_MS or place in _EXPLAINED or not isinstance(query, str):
        return False
    if not _READ_ONLY.match(query) or _WRITES.search(query):
        return False
    _EXPLAINED.add(place)
    return True


def _nodes(node: dict, depth: int = 0) -> list[tuple[float, str, int, int, int]]:
    """Узлы плана: (собственная доля – мс при ANALYZE, иначе оценка стоимости; название; строк; повторов; глубина).
    Название – тип узла и имя таблицы, CTE, функции или индекса – части схемы, без условий, выражений и значений."""
    analyzed = "Actual Total Time" in node
    if analyzed:
        loops = int(node.get("Actual Loops") or 0)
        total = float(node.get("Actual Total Time") or 0.0) * max(loops, 1)
        rows = int(node.get("Actual Rows") or 0)
    else:
        loops, total, rows = 1, float(node.get("Total Cost") or 0.0), int(node.get("Plan Rows") or 0)
    children = node.get("Plans") or []

    def child_total(ch: dict) -> float:
        if analyzed:
            return float(ch.get("Actual Total Time") or 0.0) * max(int(ch.get("Actual Loops") or 0), 1)
        return float(ch.get("Total Cost") or 0.0)
    own = total - sum(child_total(ch) for ch in children)
    name = str(node.get("Node Type") or "?")
    for key in ("Relation Name", "CTE Name", "Function Name", "Index Name"):
        if node.get(key):
            name += f" {node[key]}"
            break
    found = [(max(own, 0.0), name, rows, loops, depth)]
    for ch in children:
        found += _nodes(ch, depth + 1)
    return found


def plan_summary(plan: Any) -> str:
    """Самые долгие узлы плана EXPLAIN (FORMAT JSON) одной строкой: при ANALYZE – собственное время и строки,
    без него – оценка стоимости и строк (запрос не выполнялся)."""
    data = json.loads(plan) if isinstance(plan, str) else plan
    root = (data[0] if isinstance(data, list) and data else data or {}).get("Plan") or {}
    analyzed = "Actual Total Time" in root
    nodes = sorted(_nodes(root), key=lambda n: n[0], reverse=True)[:PLAN_TOP]
    if analyzed:
        return "; ".join(f"{name} – {own:.0f} мс, строк {rows}×{loops}" for own, name, rows, loops, _ in nodes) or "–"
    return "оценка без выполнения: " + ("; ".join(f"{name} – стоимость {own:.0f}, строк ~{rows}"
                                                  for own, name, rows, _, _ in nodes) or "–")


def log_plan(place: str, seconds: float, plan: Any, spent: float) -> None:
    try:
        summary = plan_summary(plan)
    except (ValueError, TypeError, AttributeError):
        summary = "план не разобран"
    log.info("план медленного обращения %s (%.0f мс; снятие плана %.0f мс): %s", place, seconds * 1000,
             spent * 1000, summary)
