"""Защита запросов: имя хоста, источник POST, предел размера тела, заголовки безопасности в каждом ответе,
внутренние ошибки без текста исключения в журнале.

Имя хоста – только из разрешённых (защита от подмены DNS, при которой чужая страница обращается к порту
на 127.0.0.1); запрос, меняющий данные, – только со страниц этого же приложения (Origin или, если его нет,
Referer); тело запроса – не больше предела по заголовку Content-Length и по фактически прочитанным байтам.

Необработанная ошибка запроса записывается в журнал без текста исключения (app/logsafe.py) и дальше не уходит:
иначе её с полной трассировкой и текстом записал бы сам сервер (uvicorn), а в тексте бывают код находки или ответ
модели. Человек получает страницу ошибки с номером записи в журнале.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders

from app.logsafe import log_failure

log = logging.getLogger("local_triage.web")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class _BodyTooLarge(Exception):
    pass


def host_name(host: str) -> str:
    """Имя из заголовка Host без порта; IPv6 – без скобок."""
    host = host.strip().casefold()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def same_origin(headers: Headers, scheme: str, host: str) -> bool:
    """POST принят, только если Origin (или, если его нет, Referer) указывает на этот же адрес."""
    for name in ("origin", "referer"):
        value = headers.get(name)
        if value is None:
            continue
        if value == "null":
            return False
        parts = urlsplit(value)
        return parts.scheme == scheme and parts.netloc.casefold() == host.casefold()
    return False


class GuardMiddleware:
    """Проверки каждого запроса, заголовки безопасности в каждом ответе, внутренние ошибки без текста исключения.

    on_error(scope, номер ошибки) – ответ человеку на необработанную ошибку (страница по-русски); не задан или
    сам упал – короткий текст."""

    def __init__(self, app, trusted_hosts: tuple[str, ...], max_body: int,
                 on_error: Callable[[dict, str], Awaitable[Any]] | None = None) -> None:
        self.app = app
        self.trusted = {h.casefold() for h in trusted_hosts}
        self.max_body = max_body
        self.on_error = on_error

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        host = headers.get("host", "")
        if host_name(host) not in self.trusted:
            await self._reply(send, 400, "Неверное имя хоста. На этом компьютере откройте интерфейс по адресу "
                                         "http://127.0.0.1:8765; с другого устройства – по адресу, который задан в "
                                         "TRIAGE_LAN_ADDR (.\\start.ps1 -LanAddress <адрес>).")
            return
        if scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            if not same_origin(headers, scope.get("scheme", "http"), host):
                await self._reply(send, 403, "Запрос отклонён: он отправлен не со страницы этого приложения. "
                                             "Обновите страницу и повторите.")
                return
            length = headers.get("content-length")
            if length is not None:
                if not length.isdigit():
                    await self._reply(send, 400, "Неверный заголовок Content-Length.")
                    return
                if int(length) > self.max_body:
                    await self._reply(send, 413, self._too_large_text())
                    return
            receive = self._limited(receive)
        started = False
        path = scope.get("path", "")

        async def send_with_headers(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                out = MutableHeaders(scope=message)
                for key, value in SECURITY_HEADERS.items():
                    out.setdefault(key, value)
                if not path.startswith("/static/"):
                    out["Cache-Control"] = "no-store"
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except _BodyTooLarge:
            if not started:
                await self._reply(send, 413, self._too_large_text())
        except Exception as exc:
            eid = log_failure(log, "необработанная ошибка запроса", exc)
            if started:  # ответ уже начат (поток событий): его можно только закончить
                try:
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                except Exception:
                    pass  # соединение уже закрыто
                return
            response = None
            if self.on_error is not None:
                try:
                    response = await self.on_error(scope, eid)
                except Exception as e:
                    log_failure(log, "страница ошибки не собрана", e)
            if response is None:
                await self._reply(send, 500, f"Внутренняя ошибка приложения. Номер ошибки в журнале: {eid}.")
            else:
                await response(scope, receive, send_with_headers)

    def _too_large_text(self) -> str:
        return f"Файл слишком большой: допустимо до {self.max_body // (1024 * 1024)} МБ (MAX_UPLOAD_MB)."

    def _limited(self, receive):
        received = 0

        async def limited():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise _BodyTooLarge()
            return message

        return limited

    @staticmethod
    async def _reply(send, status: int, text: str) -> None:
        body = text.encode("utf-8")
        headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode()),
                   (b"cache-control", b"no-store")]
        headers += [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
