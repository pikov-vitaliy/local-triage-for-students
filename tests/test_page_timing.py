"""Бэклог 123: замер времени страниц. Server-Timing у каждого ответа; медленный запрос – строка в журнал контейнера с
шаблоном маршрута, числом и временем обращений к базе и местами вызова, без значений адреса и данных."""

from __future__ import annotations

import logging
import re

from app import timing
from test_web import prepared, web  # noqa: F401

HEADER = re.compile(r'app;dur=(\d+), sql;dur=(\d+);desc="(\d+)"')


def slow_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("медленный запрос")]


def test_every_page_gets_server_timing_with_database_queries(web):  # noqa: F811
    pid = prepared(web)
    r = web.client.get(f"/projects/{pid}")
    assert r.status_code == 200
    m = HEADER.fullmatch(r.headers["server-timing"])
    assert m, r.headers["server-timing"]
    assert int(m.group(3)) > 0, "страница проекта читает базу"
    assert int(m.group(2)) <= int(m.group(1)) + 1
    assert "server-timing" not in web.client.get("/static/app.css").headers


def test_slow_request_is_logged_by_route_template_without_values(web, monkeypatch, caplog):  # noqa: F811
    """Уровень журнала замера – INFO без настройки со стороны (Uvicorn журналы приложения не настраивает)."""
    pid = prepared(web)
    monkeypatch.setattr(timing, "SLOW_MS", 0)
    r = web.client.get(f"/projects/{pid}/sca?q=секретное-слово&show=urgent")
    assert r.status_code == 200
    lines = slow_lines(caplog)
    assert lines, caplog.text
    line = lines[-1]
    assert line.startswith("медленный запрос GET /projects/{project_id}/sca: ")
    assert "секретное" not in line and "urgent" not in line and f"/projects/{pid}/" not in line
    assert re.search(r"обращений к базе \d+", line) and "ответ 200" in line
    # места вызова – имена модулей и функций приложения, без текста запросов
    assert re.search(r"больше всего: \w[\w.]*:\d+ ", line) and "SELECT" not in line.upper()


def test_timing_log_goes_to_the_console_at_info_level():
    """Строки замера видны в журнале контейнера: у журнала свой обработчик в stderr и уровень INFO; повторное
    создание слоя второй обработчик не добавляет."""
    timing.TimingMiddleware(None)
    timing.TimingMiddleware(None)
    log = logging.getLogger("local_triage.timing")
    assert log.getEffectiveLevel() == logging.INFO
    assert sum(1 for h in log.handlers if getattr(h, "_timing", False)) == 1


def test_internal_error_page_is_timed_with_its_final_status(web, monkeypatch, caplog):  # noqa: F811
    """Необработанная ошибка: замер видит окончательный ответ защиты (500) и ставит заголовок."""
    pid = prepared(web)
    monkeypatch.setattr(timing, "SLOW_MS", 0)

    def broken(*_a, **_k):
        raise RuntimeError("секретный текст ошибки")
    monkeypatch.setattr(web.app.state.db, "get_project", broken)
    r = web.client.get(f"/projects/{pid}")
    assert r.status_code == 500 and HEADER.fullmatch(r.headers["server-timing"])
    line = slow_lines(caplog)[-1]
    assert "ответ 500" in line and "секретный" not in line


def test_rejected_request_is_timed_too(web, monkeypatch, caplog):  # noqa: F811
    """Ранний отказ защиты (чужое имя хоста) – тоже с заголовком и фактическим статусом."""
    monkeypatch.setattr(timing, "SLOW_MS", 0)
    r = web.client.get("/healthz", headers={"Host": "evil.example"})
    assert r.status_code == 400 and HEADER.fullmatch(r.headers["server-timing"])
    assert "ответ 400" in slow_lines(caplog)[-1]


def test_fast_request_is_not_logged(web, caplog):  # noqa: F811
    web.client.get("/healthz")
    assert not slow_lines(caplog)


def test_queries_outside_a_page_are_not_counted(web):  # noqa: F811
    """Фоновая работа (исполнители, прогоны) замера не ведёт: вне запроса страницы текущего замера нет."""
    pid = prepared(web)
    assert timing.current() is None
    web.app.state.db.get_project(pid)
    assert timing.current() is None


def test_caller_names_the_database_method_and_executemany_counts_once(web):  # noqa: F811
    """Место вызова – метод базы (общие помощники пропускаются). Пакет executemany – одно обращение, пустой пакет
    к базе не обращается и не считается."""
    pid = prepared(web)
    db = web.app.state.db
    page = timing.PageTiming()
    token = timing.CURRENT.set(page)
    try:
        db.get_project(pid)
        assert page.count >= 1 and any(p.startswith("db.get_project") for p in page.places), page.places
        before = page.count

        def batch(rows):
            def work(conn):
                conn.executemany("SELECT ?", rows)
            db._store.read(work)
        batch([])
        assert page.count == before, "пустой пакет не считается"
        batch(iter([(1,), (2,), (3,)]))
        assert page.count == before + 1, "пакет – одно обращение"
    finally:
        timing.CURRENT.reset(token)


def test_page_timing_ranks_places_by_time():
    page = timing.PageTiming()
    page.add("db.a ← routes.x.y", 0.2)
    page.add("db.a ← routes.x.y", 0.1)
    page.add("db.b ← routes.x.y", 0.25)
    assert page.count == 3 and abs(page.seconds - 0.55) < 1e-9
    assert page.top(2) == [("db.a ← routes.x.y", 2, page.places["db.a ← routes.x.y"][1]),
                           ("db.b ← routes.x.y", 1, 0.25)]


def test_closed_timing_does_not_count_and_hub_worker_polls_are_not_logged(web, monkeypatch, caplog):  # noqa: F811
    """Потоковый ответ закрывает замер после заголовка – дальнейшие обращения к базе не учитываются. Запросы
    исполнителя Hub не пишутся в журнал медленных: долгий опрос заданий ждёт намеренно."""
    pid = prepared(web)
    page = timing.PageTiming()
    token = timing.CURRENT.set(page)
    try:
        assert timing.current() is page
        page.active = False
        assert timing.current() is None
        web.app.state.db.get_project(pid)
        assert page.count == 0
    finally:
        timing.CURRENT.reset(token)
    monkeypatch.setattr(timing, "SLOW_MS", 0)
    r = web.client.get("/api/hub/jobs")
    assert "server-timing" in r.headers
    assert not [line for line in slow_lines(caplog) if "/api/hub/" in line]


def test_event_stream_closes_the_timing_after_its_headers(caplog):
    """Потоковый ответ через слой замера: до заголовков замер идёт, после них закрыт; строки о медленном нет."""
    import asyncio
    seen = {}

    async def stream_app(scope, receive, send):
        seen["before"] = timing.current() is not None
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/event-stream; charset=utf-8")]})
        seen["after"] = timing.current()
        await send({"type": "http.response.body", "body": b"data: 1\n\n", "more_body": False})

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    layer = timing.TimingMiddleware(stream_app, slow_ms=0)
    asyncio.run(layer({"type": "http", "method": "GET", "path": "/runs/1/events", "headers": []}, receive, send))
    assert seen == {"before": True, "after": None}
    assert any(k == b"server-timing" for k, _ in sent[0]["headers"])
    assert not slow_lines(caplog)
