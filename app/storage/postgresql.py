"""PostgreSQL: пул соединений, транзакция записи, согласованный снимок, строка результата (ADR-0128, раздел 5 и 6).

Транзакция записи – READ COMMITTED под транзакционным рекомендательным замком писателя: прикладные записи идут по одной,
как при единственном соединении прежней базы. Составное чтение – снимок REPEATABLE READ READ ONLY. Контекст привязан к
потоку: вложенные вызовы того же потока присоединяются к нему и идут тем же соединением."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import threading
import weakref
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter
from typing import Any

import psycopg
from psycopg import ClientCursor, errors, pq
from psycopg.adapt import Loader
from psycopg_pool import ConnectionPool, PoolClosed, PoolTimeout

from app import timing
from app.storage.sql import PlaceholderError, translate

log = logging.getLogger(__name__)

BUSY_TEXT = "База данных занята: запрос не выполнен, данные не изменились. Повторите через несколько секунд."
MAINTENANCE_TEXT = "Приложение в режиме обслуживания: запись закрыта, данные не изменились."
DOWN_TEXT = "База данных недоступна: запрос не выполнен. Проверьте, что сервис базы запущен, и повторите."

IntegrityError = psycopg.IntegrityError
SerializationFailure = errors.SerializationFailure

WRITER_LOCK = 73_640_128  # транзакционный замок писателя: все записи приложения в этой базе идут по одной
INSTANCE_LOCK = 73_640_129  # сессионный замок экземпляра: одна база – один работающий экземпляр приложения
POOL_MAX = 12
CONNECT_TIMEOUT = 15.0
STATEMENT_TIMEOUT_MS = 300_000
CLOSE_WAIT = 10.0


class DatabaseBusy(Exception):
    """База занята и не освободилась за отведённое время: транзакция достоверно отменена. Это не конфликт версии решения:
    данные не изменились, повторить можно позже."""


class DatabaseUnavailable(DatabaseBusy):
    """Сервер базы недоступен или соединение оборвалось до подтверждения: транзакция отменена сервером."""


class MaintenanceMode(DatabaseBusy):
    """Режим обслуживания: запись закрыта до окончания приёмки (TRIAGE_MAINTENANCE, ADR-0128, п. 6.6)."""


class CommitUnknown(Exception):
    """Соединение оборвалось во время COMMIT: неизвестно, подтвердилась ли транзакция. Повторять можно только запись, безопасную
    при повторе (прогон модели, app/triage.py), остальное перечитывается по устойчивым ключам (ADR-0128, п. 6.4)."""


class Row(tuple):
    """Строка результата: по индексу, по имени (без учёта регистра) и перебор значений; dict(row) – по именам."""

    _names: tuple[str, ...]
    _index: dict[str, int]

    def __new__(cls, values: Iterable[Any], names: tuple[str, ...], index: dict[str, int]) -> Row:
        self = super().__new__(cls, values)
        self._names = names
        self._index = index
        return self

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            try:
                return tuple.__getitem__(self, self._index[key.lower()])
            except KeyError:
                raise IndexError(f"нет колонки {key!r}") from None
        return tuple.__getitem__(self, key)

    def keys(self) -> list[str]:
        return list(self._names)


def row_factory(cursor: Any) -> Callable[[Sequence[Any]], Any]:
    description = cursor.description
    if description is None:
        return tuple
    names = tuple(col.name for col in description)
    index: dict[str, int] = {}
    for i, name in enumerate(names):
        index.setdefault(name.lower(), i)
    return lambda values: Row(values, names, index)


_JSON_NUL = re.compile(r"(?<!\\)((?:\\\\)*)\\u0000")  # нечётное число обратных черт: настоящий NUL; при чётном – обычный текст


def _without_nul(text: str) -> str:
    """Знак NUL текст PostgreSQL не хранит. Его экранирование внутри документа JSON ломает разбор `->>` всего документа, и одна
    строка закрывала бы страницы проекта. Оба заменяются знаком U+FFFD. Текст вне JSON и экранированная черта (код с символом
    NUL в тексте дефекта) не меняются: они законны, а в рабочих данных встречается только второе."""
    text = text.replace("\x00", "\ufffd")
    if "\\u0000" not in text or not _JSON_NUL.search(text):
        return text
    try:
        json.loads(text)
    except ValueError:
        return text
    return _JSON_NUL.sub(lambda m: m.group(1) + "\\ufffd", text)


def _value(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and ("\x00" in value or "\\u0000" in value):
        return _without_nul(value)
    return value


class Cursor(ClientCursor):
    """Клиентская подстановка параметров: запросы писались без объявления типов, сервер не выводит тип «%s» в выражениях
    вроде COALESCE(?, ''). Позиционные «?» переводит лексер; логическое значение уходит числом (флаги в схеме – целые)."""

    def execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
        page = timing.current()  # запрос страницы: время и место вызова – в замер (бэклог 123)
        if page is None:
            return self._execute(query, params, **kwargs)
        started = perf_counter()
        try:
            result = self._execute(query, params, **kwargs)
        finally:
            spent = perf_counter() - started  # до обхода стека: время замера во время базы не входит
            place = timing.caller()
            page.add(place, spent)
        if timing.explain_wanted(place, query, spent):
            self._explain(query, params, place, spent)
        return result

    def _explain(self, query: Any, params: Any, place: str, spent: float) -> None:
        """План медленного обращения в журнал (app/timing.py) отдельным курсором на том же соединении – результат
        исходного курсора не трогается. Запрос выполняется повторно (EXPLAIN ANALYZE) только в транзакции только для
        чтения, которая затем откатывается: вне транзакции – в своей BEGIN READ ONLY … ROLLBACK, в транзакции только
        для чтения – под точкой сохранения с откатом к ней. В транзакции записи – только оценка плана (EXPLAIN без
        ANALYZE: запрос не выполняется) под точкой сохранения с откатом. Любой сбой – плана нет, страница работает."""
        conn = self.connection
        status = conn.info.transaction_status
        if isinstance(params, Mapping) or status not in (pq.TransactionStatus.IDLE, pq.TransactionStatus.INTRANS):
            return
        text, count = translate(query)
        values = tuple(params) if params is not None else ()
        if len(values) != count:
            return
        inside = status == pq.TransactionStatus.INTRANS
        started = perf_counter()
        cur = ClientCursor(conn)
        row = None
        try:
            if inside:
                cur.execute("SHOW transaction_read_only")
                analyze = str((cur.fetchone() or ["off"])[0]) == "on"
                opening, closing = "SAVEPOINT timing_explain", "ROLLBACK TO SAVEPOINT timing_explain"
            else:
                analyze = True
                opening, closing = "BEGIN READ ONLY", "ROLLBACK"
            cur.execute(opening)
            try:
                cur.execute(("EXPLAIN (ANALYZE, FORMAT JSON) " if analyze else "EXPLAIN (FORMAT JSON) ")
                            + (text if values else query), tuple(_value(v) for v in values) if values else None)
                row = cur.fetchone()
            finally:
                cur.execute(closing)  # что бы ни сделал запрос при повторе – откатывается
        except psycopg.Error:
            return
        finally:
            cur.close()
        if row:
            timing.log_plan(place, spent, row[0], perf_counter() - started)

    def _execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
        if isinstance(params, Mapping):
            return super().execute(query, params, **kwargs)
        text, count = translate(query)
        values = tuple(params) if params is not None else ()
        if len(values) != count:
            raise PlaceholderError(f"параметров {len(values)}, а маркеров {count}: {query[:200]}")
        if not values:
            return super().execute(query, None, **kwargs)
        return super().execute(text, tuple(_value(v) for v in values), **kwargs)

    def executemany(self, query: Any, params_seq: Iterable[Any], **kwargs: Any) -> None:
        page = timing.current()
        if page is None:
            return self._executemany(query, params_seq, **kwargs)
        rows = list(params_seq)  # пустой пакет к базе не обращается и в замер не идёт
        if not rows:
            return self._executemany(query, rows, **kwargs)
        started = perf_counter()
        try:
            return self._executemany(query, rows, **kwargs)
        finally:
            spent = perf_counter() - started
            page.add(timing.caller(), spent)  # пакет – одно обращение к базе

    def _executemany(self, query: Any, params_seq: Iterable[Any], **kwargs: Any) -> None:
        text, count = translate(query)
        rows = []
        for params in params_seq:
            values = tuple(params)
            if len(values) != count:
                raise PlaceholderError(f"параметров {len(values)}, а маркеров {count}: {query[:200]}")
            rows.append(tuple(_value(v) for v in values))
        if rows:
            super().executemany(text, rows, **kwargs)


class Connection(psycopg.Connection):
    """Соединение с executemany на самом соединении: прикладной код пишет c.execute и c.executemany."""

    @property
    def in_transaction(self) -> bool:
        return self.info.transaction_status != pq.TransactionStatus.IDLE

    def executemany(self, query: Any, params_seq: Iterable[Any]) -> Any:
        cur = self.cursor()
        cur.executemany(query, params_seq)
        return cur


class _NumberLoader(Loader):
    """SUM по BIGINT – numeric: целое число, как было; дробное – float."""

    def load(self, data: Any) -> Any:
        text = bytes(data).decode()
        return int(text) if text.lstrip("-").isdigit() else float(text)


class _FlagLoader(Loader):
    """Логическое значение выражения – 1 или 0, как в прежней базе: логических колонок в схеме нет."""

    def load(self, data: Any) -> int:
        return 1 if bytes(data) == b"t" else 0


class _JsonTextLoader(Loader):
    """JSON-выражение – строкой, как в прежней базе: разбирает прикладной код."""

    def load(self, data: Any) -> str:
        return bytes(data).decode()


def _configure(conn: psycopg.Connection) -> None:
    conn.adapters.register_loader("numeric", _NumberLoader)
    conn.adapters.register_loader("bool", _FlagLoader)
    conn.adapters.register_loader("json", _JsonTextLoader)
    conn.adapters.register_loader("jsonb", _JsonTextLoader)
    conn.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")


# Куда подключаться: цель Database – строка подключения; путь файла – для совместимости вызовов Database(settings.db_path).
# Рабочее приложение берёт адрес из переменных libpq (PGHOST, PGDATABASE, PGUSER, PGPASSWORD); тесты подставляют свою
# базу на каждый путь (tests/conftest.py).
TARGET_RESOLVER: Callable[[Path], str] | None = None
OPEN_STORES: weakref.WeakSet = weakref.WeakSet()


def conninfo_for(target: Any) -> str:
    if isinstance(target, str) and ("=" in target or target.startswith("postgres")):
        return target
    if TARGET_RESOLVER is not None and target is not None:
        return TARGET_RESOLVER(Path(target))
    return ""


# Просмотр страницы в режиме обслуживания: записи по пути (доведение последствий, сверка ревизий) выполняются и отменяются –
# страница строится как обычно, база не меняется
PAGE_VIEW: contextvars.ContextVar[bool] = contextvars.ContextVar("triage_page_view", default=False)


class _State(threading.local):
    conn: psycopg.Connection | None = None
    kind: str = ""
    depth: int = 0


class _Autocommit:
    """Соединение вне контекста: каждый запрос отдельно, соединение сразу возвращается в пул (служебные проверки и тесты)."""

    def __init__(self, store: PostgresStore) -> None:
        self._store = store

    def execute(self, sql: str, params: Any = None) -> Any:
        return self._store.read(lambda c: c.execute(sql, params))

    def executemany(self, sql: str, rows: Iterable[Any]) -> None:
        self._store.read(lambda c: c.executemany(sql, rows))


def _db_error(e: psycopg.OperationalError, conn: psycopg.Connection) -> Exception | None:
    """Занятая или недоступная база – ошибка приложения. None – настоящая причина (нет места, нет памяти), она не подменяется."""
    if isinstance(e, (errors.QueryCanceled, errors.LockNotAvailable)):
        return DatabaseBusy(BUSY_TEXT)
    if conn.closed or conn.broken:
        return DatabaseUnavailable(DOWN_TEXT)
    return None


class ReadContext:
    """`with db._lock:` – согласованное чтение: снимок на весь блок; внутри транзакции записи – её соединение."""

    def __init__(self, store: PostgresStore) -> None:
        self._store = store

    def __enter__(self) -> ReadContext:
        self._store.enter_snapshot()
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> None:
        conn = self._store._local.conn  # прямой запрос внутри блока (case_input, on_connection) не проходит через _guarded
        mapped = _db_error(exc, conn) if isinstance(exc, psycopg.OperationalError) and conn is not None else None
        self._store.exit_snapshot()
        if mapped is not None:
            raise mapped from exc

    def owned(self) -> bool:
        return self._store.in_context()


class PostgresStore:
    def __init__(self, conninfo: str, *, lock_timeout: Callable[[], float] = lambda: 30.0) -> None:
        self.conninfo = conninfo
        self._lock_timeout = lock_timeout
        self._local = _State()
        self._instance: psycopg.Connection | None = None
        self._instance_pid = 0
        self._writing = 0
        self._closing = False
        self._writers = threading.Condition()
        self._pool = ConnectionPool(
            conninfo, connection_class=Connection, min_size=1, max_size=POOL_MAX, num_workers=1, open=False,
            configure=_configure,
            kwargs={"autocommit": True, "cursor_factory": Cursor, "row_factory": row_factory,
                    "application_name": "local-triage", "connect_timeout": 10},
            reconnect_timeout=30.0)
        try:
            self._pool.open(wait=True, timeout=CONNECT_TIMEOUT)
        except PoolTimeout as e:
            self._pool.close(timeout=0)
            raise DatabaseUnavailable(DOWN_TEXT) from e
        OPEN_STORES.add(self)

    # ------------------------------------------------------------------ соединения

    def close(self) -> None:
        """Новые записи не принимаются, начатые дожидаются конца. Не дождались – замок экземпляра остаётся до выхода процесса:
        подтверждение записи ещё может прийти, а другой экземпляр к базе допускать нельзя."""
        if self._local.kind == "write":
            raise RuntimeError("закрытие базы внутри её транзакции записи")
        with self._writers:
            self._closing = True
            finished = self._writers.wait_for(lambda: self._writing == 0, timeout=CLOSE_WAIT)
        if not finished:
            log.warning("База закрывается при незавершённой записи: замок экземпляра снимется с выходом процесса")
            return
        self.release_instance()
        self._pool.close(timeout=5)
        OPEN_STORES.discard(self)

    def _server_answers(self) -> bool:
        """Счётчики пула включают соединения, которые ещё создаются, поэтому упавший сервер от занятых соединений отличает только
        новое подключение."""
        try:
            psycopg.connect(self.conninfo, autocommit=True, connect_timeout=2).close()
            return True
        except psycopg.Error:
            return False

    def _get(self, timeout: float | None = None) -> psycopg.Connection:
        try:
            return self._pool.getconn(timeout=timeout if timeout is not None else max(float(self._lock_timeout()), 0.05))
        except PoolTimeout as e:
            if not self._server_answers():
                raise DatabaseUnavailable(DOWN_TEXT) from e
            raise DatabaseBusy(BUSY_TEXT) from e
        except PoolClosed as e:
            raise DatabaseUnavailable(DOWN_TEXT) from e

    def _put(self, conn: psycopg.Connection) -> None:
        self._pool.putconn(conn)

    def _start(self, statement: str) -> psycopg.Connection:
        """Соединение с начатой транзакцией. После перезапуска сервера в пуле остаются мёртвые соединения: первая ошибка
        связи – проверка всего пула и одна повторная попытка (транзакция ещё не начата, повтор безопасен)."""
        for attempt in (1, 2):
            conn = self._get()
            try:
                conn.execute(statement)
                return conn
            except psycopg.OperationalError as e:
                self._put(conn)
                if attempt == 2:
                    raise DatabaseUnavailable(DOWN_TEXT) from e
                self._pool.check()
            except BaseException:
                self._put(conn)
                raise
        raise DatabaseUnavailable(DOWN_TEXT)

    def in_context(self) -> bool:
        return self._local.conn is not None

    def current(self) -> Any:
        """Соединение текущего контекста; вне контекста – отдельные запросы без транзакции."""
        return self._local.conn if self._local.conn is not None else _Autocommit(self)

    def read(self, fn: Callable[[psycopg.Connection], Any], *, timeout: float | None = None) -> Any:
        """Один запрос: в открытом контексте – его соединением, иначе отдельным соединением без транзакции. Обрыв связи
        на чтении без контекста повторяется один раз."""
        if self._local.conn is not None:
            return self._guarded(fn, self._local.conn)
        for attempt in (1, 2):
            conn = self._get(timeout)
            try:
                return self._guarded(fn, conn)
            except DatabaseUnavailable:
                if attempt == 2:
                    raise
                self._pool.check()
            finally:
                self._put(conn)
        raise DatabaseUnavailable(DOWN_TEXT)

    @staticmethod
    def _guarded(fn: Callable[[psycopg.Connection], Any], conn: psycopg.Connection) -> Any:
        try:
            return fn(conn)
        except psycopg.OperationalError as e:
            mapped = _db_error(e, conn)
            if mapped is None:
                raise
            raise mapped from e

    # ------------------------------------------------------------------ снимок

    def enter_snapshot(self) -> None:
        state = self._local
        if state.conn is not None:
            state.depth += 1
            return
        state.conn = self._start("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        state.kind = "snapshot"
        state.depth = 1

    def exit_snapshot(self) -> None:
        state = self._local
        state.depth -= 1
        if state.depth > 0:
            return
        conn, state.conn, state.kind = state.conn, None, ""
        try:
            conn.execute("ROLLBACK")
        except psycopg.Error:
            pass  # соединение негодно: пул его заменит
        finally:
            self._put(conn)

    # ------------------------------------------------------------------ запись

    @contextmanager
    def transaction(self, guard: Callable[[], None] | None = None, *, discard: bool = False,
                    exclusive: bool = True) -> Iterator[psycopg.Connection]:
        """Транзакция записи: всё или ничего. Сбой откатывает её целиком, при обрыве на самом COMMIT исход неизвестен (CommitUnknown). Право писать (guard) проверяется после получения
        замка писателя и ещё раз перед COMMIT. discard – в конце отмена вместо подтверждения (просмотр в обслуживании)."""
        state = self._local
        if state.conn is not None:
            raise RuntimeError("транзакция записи внутри открытого контекста: "
                               f"{state.kind}; проверка и запись должны идти в одной транзакции записи")
        with self._writers:
            if self._closing:
                raise DatabaseBusy("Приложение останавливается, запись не принята.")
            self._writing += 1
        try:
            conn = self._start("BEGIN")
        except BaseException:
            self._writer_left()
            raise
        state.conn, state.kind, state.depth = conn, "write", 1
        try:
            try:
                conn.execute(f"SET LOCAL lock_timeout = {max(int(float(self._lock_timeout()) * 1000), 1)}")
                if exclusive:  # справочники (ADR-0133) не трогают таблиц приложения: их подмена не задерживает операторов
                    conn.execute(f"SELECT pg_advisory_xact_lock({WRITER_LOCK})")
                if guard is not None:
                    guard()
                self.check_instance()
                yield conn
                if guard is not None:
                    guard()
                self.check_instance()
                if conn.info.transaction_status == pq.TransactionStatus.INERROR:
                    # ошибка запроса была перехвачена, транзакция уже отменена сервером: COMMIT молча стал бы ROLLBACK
                    raise RuntimeError("транзакция отменена ошибкой запроса внутри неё; запись не выполнена")
            except errors.LockNotAvailable as e:
                raise DatabaseBusy(BUSY_TEXT) from e
            except errors.QueryCanceled as e:
                raise DatabaseBusy(BUSY_TEXT) from e
            except psycopg.OperationalError as e:
                if conn.closed or conn.broken:
                    raise DatabaseUnavailable(DOWN_TEXT) from e
                raise
            try:
                conn.execute("ROLLBACK" if discard else "COMMIT")
            except (psycopg.OperationalError, psycopg.InterfaceError) as e:
                raise CommitUnknown("Соединение с базой оборвалось во время подтверждения записи: результат неизвестен. "
                                    "Обновите страницу и проверьте данные.") from e
        except BaseException:
            if not conn.closed and conn.info.transaction_status != pq.TransactionStatus.IDLE:
                try:
                    conn.execute("ROLLBACK")
                except psycopg.Error:
                    pass  # исходная ошибка важнее; пул заменит негодное соединение
            raise
        finally:
            state.conn, state.kind, state.depth = None, "", 0
            self._put(conn)
            self._writer_left()

    def _writer_left(self) -> None:
        with self._writers:
            self._writing -= 1
            self._writers.notify_all()

    # ------------------------------------------------------------------ единственный экземпляр

    def hold_instance(self) -> None:
        """Замок экземпляра на выделенном соединении: два приложения с разными папками данных не работают с одной базой."""
        conn = psycopg.connect(self.conninfo, autocommit=True, application_name="local-triage-instance",
                               connect_timeout=10)
        if not conn.execute(f"SELECT pg_try_advisory_lock({INSTANCE_LOCK})").fetchone()[0]:
            conn.close()
            raise RuntimeError("С этой базой уже работает другой экземпляр приложения. Остановите его и запустите снова.")
        self._instance = conn
        self._instance_pid = conn.info.backend_pid

    def release_instance(self) -> None:
        conn, self._instance = self._instance, None
        if conn is not None:
            conn.close()

    def instance_lost(self, timeout: float | None = None) -> bool:
        """Замка экземпляра на сервере больше нет: чтение работает, запись отказывает до перезапуска. Проверка – по каталогу
        блокировок с обычного соединения: соединение замка может быть занято проверкой писателя, и /healthz ждал бы её."""
        if self._instance is None:
            return False
        row = self.read(lambda c: c.execute(
            "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted"
            f" AND pid = {int(self._instance_pid)} AND objid = {INSTANCE_LOCK}"
            " AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").fetchone(), timeout=timeout)
        return row is None

    def check_instance(self) -> None:
        """Потеря соединения замка – потеря владения базой: дальше писать нельзя."""
        if self._instance is None:
            return
        from app.lockfile import LockLost
        try:
            self._instance.execute("SELECT 1")
        except psycopg.Error as e:
            raise LockLost("Потеряно соединение, которое держит базу за этим экземпляром. Запись остановлена: "
                           "перезапустите приложение.") from e
