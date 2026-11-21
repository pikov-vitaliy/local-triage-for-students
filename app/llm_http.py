"""Общий транспорт клиентов сервера модели (0.9.13, ADR-0104): допуск под блокировкой профиля, ключ, разрешение
имени и закрепление адреса по классу доверия (app/llm_net.py), журнал обмена (app/model_traffic.py), сроки и обрывы.
Вынесен из клиента Ollama без изменения поведения; протокол – в подклассах (app/llm_ollama.py): адрес и его
проверка (_target), чтение потока (_read_stream), разбор ответа (_finish) и тексты ошибок соединения.

Сбой после начала передачи байтов запроса помечается у ошибки (LlmError.sent = True): что успело уйти серверу,
неизвестно – внешний провайдер мог принять и оплатить запрос (К11 плана 0.9.13). У сбоя до передачи – sent = False.
Обращение к модели из нескольких запросов (повтор не по формату, служебные запросы) учитывается целиком (track_sent):
если хоть один его запрос ушёл серверу, ошибка обращения – sent = True, какой бы обёрткой она ни была создана.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import http.client
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from app import affiliation, model_traffic
from app.llm import LlmError, ResolveError, log
from app.llm_net import (_ConnectTimeout, _elapsed_ms, _peer, _PinnedHTTPConnection,
                         _PinnedHTTPSConnection, _read_body, _RecordedResponse, _remaining, _resolve,
                         _response_headers, _Target, _TooLarge, _Watchdog, _wire_headers)
from app.logsafe import log_failure

INFO_TIMEOUT_S = 10.0  # служебные запросы (версия, список моделей) отвечают сразу


class SentTracker:
    """Учёт одного обращения к модели: ушёл ли серверу хоть один его запрос."""

    def __init__(self) -> None:
        self.sent = False


_CALL: contextvars.ContextVar[SentTracker | None] = contextvars.ContextVar("llm_call_sent", default=None)


@contextlib.contextmanager
def track_sent():
    """Учёт отправок на время обращения к модели: LlmError, вышедшая из блока после хоть одной отправки, получает
    sent = True (ошибку могла создать обёртка – «модели нет», «ответ не по формату», отказ допуска перед повтором)."""
    parent = _CALL.get()
    tracker = SentTracker()
    token = _CALL.set(tracker)
    try:
        yield tracker
    except LlmError as e:
        if tracker.sent and not isinstance(e, ResolveError):
            # ResolveError – запрос, на котором сорвалось обращение, не ушёл (ADR-0113): прежние отправки того же
            # обращения (429 с повтором, исправление формата) получили ответ, их исход известен; sent у ошибки не ставится,
            # а внешний tracker узнаёт об отправках как раньше
            e.sent = True
        raise
    finally:
        _CALL.reset(token)
        if parent is not None and tracker.sent:  # вложенное обращение – часть внешнего: его отправки учитываются там
            parent.sent = True


def tracked(method):
    """Метод клиента – одно обращение к серверу для учёта отправок (track_sent): ошибка после ушедшего запроса –
    sent = True, даже если её создал разбор ответа (например, «в ответе нет версии»)."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with track_sent():
            return method(self, *args, **kwargs)
    return wrapper


def _note_sent() -> None:
    tracker = _CALL.get()
    if tracker is not None:
        tracker.sent = True


def _scrub_error(error: LlmError, secrets: Any) -> LlmError:
    """LlmError без значений ключа в тексте, подробностях и начале ответа (сервер мог отразить ключ – и в
    экранировании JSON)."""
    if not secrets:
        return error
    text = model_traffic.scrub_text(str(error), secrets)
    if text != str(error):
        error.args = (text,)
    error.detail = model_traffic.scrub_text(error.detail, secrets)
    error.raw = model_traffic.scrub_text(error.raw, secrets)
    return error


def _scrub_value(value: Any, secrets: Any) -> Any:
    """Разобранный ответ без ключа – значения и имена полей на любой глубине (model_traffic.clean_value; строка, где
    ключ остался в экранировании или внутреннем JSON, скрывается целиком). Слишком глубокая вложенность – LlmError."""
    try:
        return model_traffic.clean_value(value, secrets)
    except RecursionError:
        raise LlmError("Ответ сервера модели вложен слишком глубоко: не разобран.") from None


class ServerClient:
    """Клиент сервера модели: общий транспорт. Каждый запрос – отдельное соединение.

    url – адрес сервера; timeout – общий срок ответа модели, секунды. Адрес проверяется при каждом запросе
    (check_url), поэтому неверный адрес не мешает создать клиент: ошибка придёт понятным LlmError при первом
    обращении."""

    def __init__(self, url: str, timeout: float = 900) -> None:
        self.url = str(url or "").strip()
        self.timeout = float(timeout) if timeout and timeout > 0 else 900.0
        self._schema_unsupported = threading.Event()
        # Проверка непосредственно перед каждой отправкой запроса модели, включая повтор (ADR-0102): прогон передаёт
        # «профиль снимка включён»; исключение – запрос не уходит
        self.before_send: Callable[[], None] | None = None
        # Класс доверия сервера (ADR-0102 п. 7): local – только адреса этого компьютера (ADR-0001, как раньше); lan –
        # частные адреса, подтверждённые в профиле (confirmed: адреса или функция, отдающая их на каждый запрос)
        self.trust = "local"
        self.confirmed: tuple[str, ...] | Callable[[], Any] = ()
        # Заголовок авторизации на каждый запрос (ключ профиля с привязкой к адресу, app/provider_keys.py): функция,
        # отказ которой (SendNotAllowed) не даёт запросу уйти вовсе
        self.auth: Callable[[], dict[str, str]] | None = None
        self.provider: dict[str, Any] | None = None  # профиль исполнителя – в журнал обмена
        # Граница правки профиля (app/profile_gate.py): допуск, адреса, ключ и отправка байтов – под общей блокировкой
        # профиля, правка – под исключительной; admission – проверка допуска (профиль включён) под этой блокировкой
        self.gate: Callable[[], Any] | None = None
        self.admission: Callable[[], None] | None = None
        self._secrets: tuple[str, ...] = ()  # значения ключа последнего запроса – чтобы вырезать их из ответа модели

    def protocol_headers(self) -> dict[str, str]:
        """Служебные заголовки протокола на каждый запрос (ADR-0106): например, версия Messages API. Не секрет:
        в журнале обмена остаются и не маскируются; у Ollama и API чат-завершений – пусто."""
        return {}

    @property
    def secrets(self) -> tuple[str, ...]:
        """Значения ключа последнего запроса (пусто – сервер без ключа): последняя проверка ответа перед сохранением
        (model_traffic.shows_secret)."""
        return self._secrets

    def schema_dropped(self) -> bool:
        """Сервер отверг схему ответа: запросы идут без неё и не совпадают с ключом, где схема учтена."""
        return self._schema_unsupported.is_set()

    def check_url(self) -> str:
        """Адрес сервера без «/» в конце. Не http(s), чужой хост, имя и пароль в адресе, неверный порт – LlmError.
        Без сети: куда указывает имя хоста, проверяется при каждом запросе."""
        return self._target().base

    # ---------------------------------------------------------------- точки протокола

    def _target(self) -> _Target:  # pragma: no cover - у каждого протокола свой
        raise NotImplementedError

    def _read_stream(self, pieces, progress) -> Any:  # pragma: no cover - поток есть не у каждого протокола
        raise NotImplementedError

    def _finish(self, t: _Target, path: str, status: int, body: bytes, secrets: tuple[str, ...],
                headers: dict[str, str]) -> Any:
        """Ответ после обмена: статус, тело (ключ уже вырезан) и заголовки ответа (например, Retry-After) -> разобранный
        ответ или LlmError."""
        raise NotImplementedError  # pragma: no cover - у каждого протокола свой

    def _connect_timeout_error(self, t: _Target, timeout: float) -> LlmError:  # pragma: no cover
        raise NotImplementedError

    def _transport_error(self, error: BaseException, t: _Target, path: str, timeout: float,
                         expired: bool) -> LlmError:  # pragma: no cover
        raise NotImplementedError

    # ---------------------------------------------------------------- запрос

    def _request(self, path: str, payload: Any = None, timeout: float = INFO_TIMEOUT_S, progress=None,
                 origin_path: bool = False) -> Any:
        """GET (payload=None) или POST JSON на сервер модели -> разобранный ответ (_finish). timeout – общий срок
        запроса. origin_path – путь от корня того же адреса, без пути из адреса сервера (поисковый API провайдера:
        тот же хост, порт, ключ и проверки). Любой сбой – LlmError.

        Если задан регистратор журнала обмена с моделью (model_traffic.get_recorder), событие request пишется
        до отправки. Записать его не удалось (нет места, нет прав) – по решению владельца (ADR-0083) запрос всё
        равно уходит, без записи этого обращения: сбой учитывается (model_traffic.note_failure) и показывается
        оператору на странице прогона. После обмена пишется событие response (с точными байтами запроса и
        ответа) или error; сбой их записи работу не ломает. Без регистратора ничего не меняется.
        """
        t = self._target()
        deadline = time.monotonic() + timeout
        if origin_path and not (path.startswith("/") and not path.startswith("//")):
            raise LlmError(f"Путь запроса «{path}» должен начинаться с одного «/»: запрос не отправлен.")
        wire_path = path if origin_path else t.prefix + path
        full_url = (t.base[:len(t.base) - len(t.prefix)] if t.prefix else t.base) + wire_path
        # Допуск, подтверждённые адреса, ключ и отправка байтов – под общей блокировкой профиля: правка профиля
        # (снятие подтверждения, выключение, замена ключа) не вклинивается между проверкой и отправкой
        gate = contextlib.ExitStack()
        if self.gate is not None:
            try:
                gate.enter_context(self.gate())
            except TimeoutError:
                raise LlmError("Профиль провайдера модели слишком долго правится: запрос не отправлен – повторите.") \
                    from None
        try:
            if self.admission is not None:
                self.admission()
            # ключ – до разрешения имени и соединения: отказ привязки (SendNotAllowed) не даёт запросу уйти вовсе
            auth = dict(self.auth()) if self.auth is not None else {}
            confirmed = self.confirmed() if callable(self.confirmed) else self.confirmed
            # имя – один раз на запрос, со своим сроком; у lan – только подтверждённые частные адреса
            entries = _resolve(t.host, t.port, deadline - time.monotonic(), trust=self.trust, confirmed=confirmed)
        except BaseException:
            gate.close()
            raise
        try:  # до отправки блокировка профиля освобождается при любом сбое
            # значения ключа – чтобы вырезать их, если сервер вернёт ключ в ответе или тексте ошибки
            secrets = tuple(s for value in auth.values() for s in (value, value.split(" ", 1)[-1]) if s)
            self._secrets = secrets
            # маска принадлежности (ADR-0118) – последней, на границе отправки: в журнал попадает то, что ушло;
            # клиент не модели (OSV) выключает её у себя: affiliation_mask = False
            if getattr(self, "affiliation_mask", True):
                payload = affiliation.mask_payload(payload)
            # errors="replace": одиночные суррогаты из плохо декодированного файла не должны ронять запрос
            data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8", "replace")
            headers = {"Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            headers.update(self.protocol_headers())  # служебные заголовки протокола – не секрет
            headers.update(auth)  # в журнал заголовок авторизации не попадает (model_traffic.redact_*)
            connection_class = _PinnedHTTPSConnection if t.scheme == "https" else _PinnedHTTPConnection
            watchdog = _Watchdog(deadline)
            conn = connection_class(t.host, t.port, entries, deadline, watchdog)
            recorder = model_traffic.get_recorder()
            method = "GET" if data is None else "POST"
            event_id = request_ts = None
            if recorder is not None:
                try:
                    event_id, request_ts = recorder.request(method=method, url=full_url, body=data,
                                                            provider=self.provider)
                except Exception as e:  # ADR-0083: запрос уходит без записи, оператор увидит предупреждение
                    model_traffic.note_failure(e)
                    log_failure(log, "событие request журнала обмена с моделью не записано", e)
                    recorder = None
        except BaseException:
            gate.close()
            raise
        started = time.monotonic()
        response = None
        error = None
        peer = None
        try:
            try:
                conn.request(method, wire_path, body=data, headers=headers)
            finally:
                gate.close()  # байты запроса переданы (или отправка оборвалась): правка профиля может идти
            settimeout = getattr(conn.sock, "settimeout", None)
            if settimeout is not None:  # соединение и отправка шли с коротким сроком, ответ – с общим
                settimeout(_remaining(deadline))
            peer = _peer(conn)  # соединение установлено: адрес, к которому уходит запрос
            response = conn.getresponse()
            if recorder is not None:
                response = _RecordedResponse(response)
            if progress is not None and 200 <= response.status < 300:
                def pieces():
                    while True:
                        _remaining(deadline)
                        chunk = response.read1(65536)
                        if not chunk:
                            break
                        yield chunk
                    if response.length:
                        raise http.client.IncompleteRead(b'', response.length)
                result = self._read_stream(pieces(), progress)
                cleaned = _scrub_value(result, secrets)
                if recorder is not None:  # журнал – все куски потока, как пришли (и у сервера с ключом)
                    recorder.response(event_id=event_id, request_ts=request_ts, duration_ms=_elapsed_ms(started),
                                      status=response.status, headers=_response_headers(response),
                                      body=bytes(response.read_wire), chunks=response.chunk_count, peer=peer,
                                      request_headers=_wire_headers(conn.request_wire),
                                      request_wire=bytes(conn.request_wire) or None)
                return cleaned
            body = _read_body(response, deadline)
            status = response.status
            reply_headers = _response_headers(response)
        except _ConnectTimeout:
            error = self._connect_timeout_error(t, timeout)
        except LlmError as e:  # сбой разбора потока модели: обмен прервался на чтении ответа
            error = e
        except (OSError, http.client.HTTPException, _TooLarge) as e:
            error = self._transport_error(e, t, path, timeout, watchdog.fired)
        finally:
            gate.close()
            watchdog.cancel()
            if conn.send_started:  # и на успешном выходе из потока (return внутри try)
                _note_sent()
            if response is not None:
                response.close()
            # wire снимается до закрытия соединения: после close() отправленных байт не перечитать
            wire = bytes(conn.request_wire) or None
            conn.close()
        if error is not None:
            error = _scrub_error(error, secrets)
            # передача байтов запроса началась – исход для сервера неизвестен (соединение не установилось – нет)
            error.sent = conn.send_started
            if recorder is not None:
                received = bytes(response.read_wire) if response is not None and response.read_wire else None
                recorder.error(event_id=event_id, request_ts=request_ts, duration_ms=_elapsed_ms(started),
                               error_type=type(error).__name__, error_text=str(error), received=received,
                               peer=peer, request_headers=_wire_headers(wire or b""), request_wire=wire)
            raise error from None
        if recorder is not None:  # журнал – тело как прочитано (и у сервера с ключом)
            recorder.response(event_id=event_id, request_ts=request_ts, duration_ms=_elapsed_ms(started),
                              status=status, headers=_response_headers(response), body=body, peer=peer,
                              request_headers=_wire_headers(wire or b""), request_wire=wire)
        body = model_traffic.scrub(body, secrets)  # сервер мог вернуть переданный ключ в ответе
        try:
            return self._finish(t, path, status, body, secrets, reply_headers)
        except LlmError as e:  # ответ сервера – ошибка или не тот формат: запрос до сервера дошёл
            e.sent = conn.send_started
            raise

