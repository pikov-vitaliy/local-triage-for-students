"""Контракт хранения PostgreSQL (ADR-0128, разделы 5–7): строка результата, типы значений, транзакция записи, снимок,
занятая база, неизвестный COMMIT, потеря соединений, единственный экземпляр, функции базы и манифест схемы."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import psycopg
import pytest

from app import db as db_module
from app.db import Database
from app.hub_ops import hub_base
from app.lockfile import LockLost
from app.storage import CommitUnknown, DatabaseBusy, schema
from app.storage import postgresql
from app.storage.migrate import BASELINE_SCHEMA, BASELINE, checksum
from app.storage.sql import PlaceholderError
from db_support import _admin, database_for_path


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


def other_thread(fn):
    result, errors = [], []

    def run():
        try:
            result.append(fn())
        except BaseException as e:  # noqa: BLE001 – проверяется в тесте
            errors.append(e)
    thread = threading.Thread(target=run)
    thread.start()
    thread.join(30)
    assert not thread.is_alive()
    if errors:
        raise errors[0]
    return result[0] if result else None


def terminate_backends(path: Path) -> None:
    name = database_for_path(path)
    _admin().execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                     (name,))


# --- строка результата и типы значений

def test_row_by_index_name_and_values(db: Database):
    with db._lock:
        row = db._conn.execute("SELECT 1 AS a, 'x' AS b").fetchone()
    assert row[0] == 1 and row["a"] == 1 and row["B"] == "x"
    assert list(row) == [1, "x"] and tuple(row) == (1, "x")
    assert dict(row) == {"a": 1, "b": "x"} and row.keys() == ["a", "b"]
    with pytest.raises(IndexError):
        row["нет"]


def test_empty_values_and_null_are_different(db: Database):
    row = db._one("SELECT ? AS a, ? AS b", ("", None))
    assert row == {"a": "", "b": None}


def test_repeated_and_expression_parameters(db: Database):
    assert db._scalar("SELECT COALESCE(?, 'пусто')", (None,)) == "пусто"
    assert db._scalar("SELECT ? IS NULL", (None,)) == 1
    assert db._scalar("SELECT ? = ?", ("a", "a")) == 1


def test_expression_types_match_previous_base(db: Database):
    pid = db.create_project("p")
    with db._tx() as c:
        c.execute("UPDATE projects SET last_activity = 'x' WHERE id = ?", (pid,))
    row = db._one("SELECT COUNT(*) AS n, SUM(id) AS s, AVG(id) AS a, MAX(id) AS m, EXISTS(SELECT 1) AS e, 1 = 2 AS f,"
                  " json_build_object('k', 1) AS j FROM projects")
    assert row["n"] == 1 and type(row["n"]) is int
    assert row["s"] == pid and type(row["s"]) is int, "SUM по целым – целое число"
    assert type(row["a"]) is float, "AVG – дробное"
    assert (row["e"], row["f"]) == (1, 0) and type(row["e"]) is int, "логическое выражение – 1 или 0"
    assert isinstance(row["j"], str), "JSON разбирает прикладной код"


def test_boolean_parameter_goes_as_number(db: Database):
    assert db._scalar("SELECT ? + 1", (True,)) == 2


def test_parameter_count_mismatch_is_loud(db: Database):
    with pytest.raises(PlaceholderError):
        db._one("SELECT ?", ())


def test_percent_with_and_without_parameters(db: Database):
    assert db._scalar("SELECT 'a%'") == "a%"
    assert db._scalar("SELECT 'a%' || ?", ("b",)) == "a%b"
    assert db._scalar("SELECT 'abc' LIKE 'a%' AND ? = 1", (1,)) == 1


def test_empty_executemany_is_noop(db: Database):
    with db._tx() as c:
        c.executemany("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)", [])
    assert db._scalar("SELECT COUNT(*) FROM settings") == 0


def test_nul_in_text_and_json_does_not_break_reading(db: Database):
    """NUL в строке и его экранирование в JSON: запись проходит, разбор ->> других полей работает."""
    from app.db import dumps
    pid = db.create_project("p")
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('nul', ?)", ("a\x00b",))
        c.execute("INSERT INTO meta(key, value) VALUES ('json', ?)", (dumps({"code": "x\x00y", "status": "ok"}),))
    assert db._scalar("SELECT value FROM meta WHERE key = 'nul'") == "a\ufffdb"
    assert db._scalar("SELECT value::json ->> 'status' FROM meta WHERE key = 'json'") == "ok"
    assert pid


@pytest.mark.parametrize("stored", [
    json.dumps({"code": "char c = '\\u0000';"}),  # в JSON – экранированная черта: обычный текст, как в рабочих данных
    "комментарий: символ '\\u0000' в строке кода",  # не JSON
    "[важно] '\\u0000' в коде",  # похоже на JSON, но не JSON
    json.dumps({"code": "a\\\\u0000b"}),
])
def test_text_with_escaped_nul_is_stored_byte_for_byte(db: Database, stored: str):
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('text', ?)", (stored,))
    assert db._scalar("SELECT value FROM meta WHERE key = 'text'") == stored
    assert db._scalar("SELECT key FROM meta WHERE value = ?", (stored,)) == "text"
    if stored.startswith("{"):
        assert db._scalar("SELECT value::json ->> 'code' FROM meta WHERE key = 'text'") == json.loads(stored)["code"]


def test_retry_of_verdict_with_same_number_keeps_one_row_and_foreign_number_is_refused(db: Database):
    number = db.reserve_verdict_id()
    for _ in range(2):
        assert db.save_verdict("h", "m", "p1", {"verdict": "true_positive", "confidence": 5}, {}, verdict_id=number) == number
    assert db._scalar("SELECT COUNT(*) FROM verdicts WHERE id = ?", (number,)) == 1
    with pytest.raises(RuntimeError, match="занят другим ответом"):
        db.save_verdict("другой", "m", "p1", {"verdict": "false_positive", "confidence": 1}, {}, verdict_id=number)
    with pytest.raises(RuntimeError, match="занят другим ответом"):  # те же ключи, другой ответ
        db.save_verdict("h", "m", "p1", {"verdict": "false_positive", "confidence": 5}, {}, verdict_id=number)
    with pytest.raises(RuntimeError, match="занят другим ответом"):  # та же запись под другой версией промпта
        db.save_verdict("h", "m", "p2", {"verdict": "true_positive", "confidence": 5}, {}, verdict_id=number)
    automatic = db.save_verdict("h", "m", "p1", {"verdict": "true_positive", "confidence": 5}, {})
    assert automatic != number, "автоматический номер не принимает чужую запись за свою"


def test_retry_of_verdict_with_nul_in_answer_is_the_same_record(db: Database):
    number = db.reserve_verdict_id()
    for _ in range(2):
        assert db.save_verdict("h", "m", "p1", {"verdict": "true_positive", "reason": "a\x00b"}, {}, verdict_id=number) == number


def test_long_keys_of_a_finding_are_accepted(db: Database):
    """Длинный Location у DAST входит в ключи группы: выгрузка загружается, равенство находит строку."""
    long = "".join(chr(0x400 + (i * 7919) % 0x400) for i in range(9000))
    pid = db.create_project("p")
    with db._tx() as c:
        imp = c.execute("INSERT INTO imports(project_id, filename, format, created_at) VALUES (?, 'f', 'xlsx', '2026-01-01')"
                        " RETURNING id", (pid,)).fetchone()[0]
        c.execute("INSERT INTO findings(project_id, hub_id, import_id, pos, kind, group_key, group_key2, g2_cat, g2_file, data_json)"
                  " VALUES (?, '1', ?, 1, 'DAST', ?, ?, ?, ?, '{}')", (pid, imp, long, long, long, long))
    assert db._scalar("SELECT hub_id FROM findings WHERE project_id = ? AND group_key2 = ?", (pid, long)) == "1"


# --- запись

def test_transaction_rolls_back_on_exception(db: Database):
    with pytest.raises(ZeroDivisionError):
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('t', '1')")
            assert c.execute("SELECT value FROM meta WHERE key = 't'").fetchone()[0] == "1", "видит своё изменение"
            assert db._scalar("SELECT value FROM meta WHERE key = 't'") == "1", "вложенное чтение – то же соединение"
            1 / 0
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 't'") == 0


def test_uncommitted_write_is_not_visible_to_other_thread(db: Database):
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('t', '1')")
        assert other_thread(lambda: db._scalar("SELECT COUNT(*) FROM meta WHERE key = 't'")) == 0
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 't'") == 1


def test_second_writer_waits_and_gets_busy_without_partial_write(db: Database, monkeypatch):
    monkeypatch.setattr(db_module, "LOCK_TIMEOUT", 0.2)

    def second():
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('second', '1')")

    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('first', '1')")
        with pytest.raises(DatabaseBusy) as e:
            other_thread(second)
        assert str(e.value) == db_module.BUSY_TEXT
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'first'") == 1
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'second'") == 0
    other_thread(second)  # замок свободен: следующая запись работает
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'second'") == 1


def test_writers_do_not_lose_updates(db: Database):
    """Чтение и запись в одной транзакции: шесть потоков увеличивают один счётчик – ничего не теряется."""
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('n', '0')")

    def bump():
        for _ in range(20):
            with db._tx() as c:
                value = int(c.execute("SELECT value FROM meta WHERE key = 'n'").fetchone()[0])
                c.execute("UPDATE meta SET value = ? WHERE key = 'n'", (str(value + 1),))
    threads = [threading.Thread(target=bump) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert db._scalar("SELECT value FROM meta WHERE key = 'n'") == "120"


def test_swallowed_statement_error_does_not_look_like_commit(db: Database):
    """Перехваченная ошибка запроса отменяет транзакцию: тихий ROLLBACK вместо COMMIT был бы потерей записи."""
    with pytest.raises(RuntimeError, match="отменена"):
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('a', '1')")
            try:
                c.execute("INSERT INTO meta(key, value) VALUES ('a', '2')")
            except psycopg.IntegrityError:
                pass
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'a'") == 0
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('a', '3')")
    assert db._scalar("SELECT value FROM meta WHERE key = 'a'") == "3"


def test_savepoint_keeps_transaction_after_expected_conflict(db: Database):
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('a', '1')")
        with pytest.raises(psycopg.IntegrityError):
            with c.transaction():
                c.execute("INSERT INTO meta(key, value) VALUES ('a', '2')")
        c.execute("INSERT INTO meta(key, value) VALUES ('b', '1')")
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key IN ('a', 'b')") == 2


def test_write_guard_refuses_before_and_before_commit(tmp_path: Path):
    allowed = [True]

    def guard():
        if not allowed[0]:
            raise LockLost("запрещено")
    database = Database(tmp_path / "g.db", write_guard=guard)
    try:
        allowed[0] = False
        with pytest.raises(LockLost):
            with database._tx():
                pass
        allowed[0] = True
        with pytest.raises(LockLost):
            with database._tx() as c:
                c.execute("INSERT INTO meta(key, value) VALUES ('x', '1')")
                allowed[0] = False
        allowed[0] = True
        assert database._scalar("SELECT COUNT(*) FROM meta WHERE key = 'x'") == 0, "откат: право потеряно перед COMMIT"
    finally:
        database.close()


def test_commit_lost_is_unknown_and_next_write_works(db: Database, monkeypatch):
    """Обрыв на COMMIT: результат неизвестен, отдельное исключение, без обещания отката; следующая запись работает."""
    real = postgresql.Connection.execute
    failed = [False]

    def failing(self, query, params=None, **kw):
        if query == "COMMIT" and not failed[0]:
            failed[0] = True
            raise psycopg.OperationalError("обрыв")
        return real(self, query, params, **kw)
    monkeypatch.setattr(postgresql.Connection, "execute", failing)
    with pytest.raises(CommitUnknown):
        db.create_project("не определено")
    monkeypatch.undo()
    pid = db.create_project("сохранится")
    assert db.get_project(pid)["name"] == "сохранится"


def test_connections_are_returned_after_failures(db: Database):
    for _ in range(postgresql.POOL_MAX * 3):
        with pytest.raises(ZeroDivisionError):
            with db._tx():
                1 / 0
        with pytest.raises(ZeroDivisionError):
            with db.snapshot():
                1 / 0
        with pytest.raises(psycopg.Error):
            db._all("SELECT нет_такой_колонки FROM meta")
    assert db._scalar("SELECT 1") == 1
    stuck = _admin().execute("SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()"
                             " AND state LIKE 'idle in transaction%%'").fetchone()[0]
    assert stuck == 0


# --- снимок

def test_snapshot_does_not_see_commit_of_other_thread(db: Database):
    def write():
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('new', '1')")

    with db.snapshot():
        before = db._scalar("SELECT COUNT(*) FROM meta")
        other_thread(write)
        assert db._scalar("SELECT COUNT(*) FROM meta") == before, "один снимок на весь блок"
        with db.snapshot():  # вложенный снимок присоединяется к внешнему
            assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'new'") == 0
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'new'") == 1


def test_read_committed_would_fail_the_same_scenario(db: Database):
    """Контрольный сценарий: без снимка второе чтение видит чужой COMMIT – поэтому составным чтениям нужен контекст."""
    before = db._scalar("SELECT COUNT(*) FROM meta")

    def write():
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('new', '1')")
    other_thread(write)
    assert db._scalar("SELECT COUNT(*) FROM meta") == before + 1


def test_snapshot_is_read_only(db: Database):
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        with db.snapshot():
            db._conn.execute("INSERT INTO meta(key, value) VALUES ('x', '1')")
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = 'x'") == 0


def test_write_transaction_inside_snapshot_is_refused(db: Database):
    with pytest.raises(RuntimeError, match="транзакция записи"):
        with db.snapshot():
            with db._tx():
                pass


def test_snapshot_inside_write_sees_own_changes(db: Database):
    with db._tx() as c:
        c.execute("INSERT INTO meta(key, value) VALUES ('own', '1')")
        with db.snapshot():
            assert db._scalar("SELECT value FROM meta WHERE key = 'own'") == "1"
        c.execute("UPDATE meta SET value = '2' WHERE key = 'own'")
    assert db._scalar("SELECT value FROM meta WHERE key = 'own'") == "2"


def test_on_connection_uses_one_snapshot(db: Database):
    def read(c):
        first = c.execute("SELECT COUNT(*) FROM meta").fetchone()[0]
        other_thread(lambda: db.set_settings({"k": 1}) or db_write())
        return first, c.execute("SELECT COUNT(*) FROM meta").fetchone()[0]

    def db_write():
        with db._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('cb', '1')")
    first, second = db.on_connection(read)
    assert first == second


def test_lock_owned_only_inside_context(db: Database):
    assert not db._lock.owned()
    with db._lock:
        assert db._lock.owned()
        assert not other_thread(db._lock.owned)
    assert not db._lock.owned()


def test_journal_reader_does_not_cross_state_change_with_clocks(db: Database, monkeypatch):
    """Чтение строки журнала и часов не пересекается с переходом состояния и его COMMIT."""
    from app import journal
    pid = db.create_project("p")
    run_id = db.create_run(pid, "all", "m", "p1", ["A"])
    entered, release = threading.Event(), threading.Event()
    real = journal.transition

    def slow(*args, **kwargs):
        real(*args, **kwargs)
        entered.set()
        assert release.wait(10)
    monkeypatch.setattr(journal, "transition", slow)
    writer = threading.Thread(target=db.set_run_state, args=(run_id, "running"))
    writer.start()
    assert entered.wait(10)
    read_done = threading.Event()
    reader = threading.Thread(target=lambda: (journal.detail(db, run_id), read_done.set()))
    reader.start()
    assert not read_done.wait(0.3), "чтение ждёт завершения перехода"
    release.set()
    writer.join(10)
    reader.join(10)
    assert read_done.is_set()


# --- потеря соединений

def test_read_and_write_recover_after_connections_are_lost(tmp_path: Path):
    path = tmp_path / "r.db"
    database = Database(path)
    try:
        assert database._scalar("SELECT 1") == 1
        terminate_backends(path)
        assert database._scalar("SELECT 2") == 2, "чтение без контекста повторяется на новом соединении"
        terminate_backends(path)
        pid = database.create_project("после обрыва")
        assert database.get_project(pid)["name"] == "после обрыва"
        terminate_backends(path)
        with database.snapshot():
            assert database._scalar("SELECT 3") == 3
    finally:
        database.close()


def test_connection_lost_inside_transaction_is_controlled_rollback(tmp_path: Path):
    path = tmp_path / "r.db"
    database = Database(path)
    try:
        with pytest.raises(postgresql.DatabaseUnavailable):
            with database._tx() as c:
                c.execute("INSERT INTO meta(key, value) VALUES ('x', '1')")
                terminate_backends(path)
                c.execute("INSERT INTO meta(key, value) VALUES ('y', '1')")
        assert database._scalar("SELECT COUNT(*) FROM meta WHERE key IN ('x', 'y')") == 0
    finally:
        database.close()


def test_unavailable_server_is_a_controlled_error():
    with pytest.raises(postgresql.DatabaseUnavailable):
        original = postgresql.CONNECT_TIMEOUT
        postgresql.CONNECT_TIMEOUT = 0.5
        try:
            postgresql.PostgresStore("host=127.0.0.1 port=1 user=x dbname=x connect_timeout=1")
        finally:
            postgresql.CONNECT_TIMEOUT = original


def test_other_operational_error_is_not_reported_as_down_server(db: Database, monkeypatch):
    real = postgresql.Connection.execute

    def full(self, query, params=None, **kw):
        if "нет места" in str(query):
            raise psycopg.errors.DiskFull("нет места")
        return real(self, query, params, **kw)
    monkeypatch.setattr(postgresql.Connection, "execute", full)
    with pytest.raises(psycopg.errors.DiskFull):
        db._scalar("SELECT 'нет места'")


def test_direct_query_in_snapshot_is_classified(db: Database):
    """Прямой запрос внутри снимка (case_input, on_connection): обрыв и отмена – ошибки приложения, ошибка кода – как есть."""
    from db_support import _admin
    with pytest.raises(postgresql.DatabaseUnavailable):
        with db._lock:
            conn = db._conn
            _admin().execute("SELECT pg_terminate_backend(%s)", (conn.info.backend_pid,))
            conn.execute("SELECT pg_sleep(0.05)")
            conn.execute("SELECT 1")
    with pytest.raises(DatabaseBusy) as e:
        with db._lock:
            db._conn.execute("SET LOCAL statement_timeout = 1")
            db._conn.execute("SELECT pg_sleep(1)")
    assert not isinstance(e.value, postgresql.DatabaseUnavailable)
    with pytest.raises(psycopg.errors.UndefinedTable):
        with db._lock:
            db._conn.execute("SELECT 1 FROM нет_такой_таблицы")
    assert db._scalar("SELECT 1") == 1


def test_pool_timeout_is_down_only_when_server_does_not_answer(db: Database, monkeypatch):
    def timed_out(timeout=None):
        raise postgresql.PoolTimeout("нет соединений")
    monkeypatch.setattr(db._store._pool, "getconn", timed_out)
    monkeypatch.setattr(db._store, "_server_answers", lambda: False)
    with pytest.raises(postgresql.DatabaseUnavailable):
        db._scalar("SELECT 1")
    monkeypatch.setattr(db._store, "_server_answers", lambda: True)
    with pytest.raises(DatabaseBusy) as e:
        db._scalar("SELECT 1")
    assert not isinstance(e.value, postgresql.DatabaseUnavailable)


def test_server_answers_by_new_connection(db: Database, monkeypatch):
    assert db._store._server_answers() is True
    monkeypatch.setattr(db._store, "conninfo", "host=127.0.0.1 port=1 dbname=none connect_timeout=1")
    assert db._store._server_answers() is False


def test_instance_lock_is_checked_without_its_connection(tmp_path: Path):
    database = Database(tmp_path / "i.db")
    try:
        assert database._store.instance_lost() is False, "замка не брали – потерять нечего"
        database.hold_instance()
        assert database._store.instance_lost() is False

        class Busy:
            def __getattr__(self, name):
                raise AssertionError("/healthz не трогает соединение замка")
        held, database._store._instance = database._store._instance, Busy()
        try:
            assert database._store.instance_lost() is False
        finally:
            database._store._instance = held
    finally:
        database.close()


def test_close_with_unfinished_write_keeps_instance_lock(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "u.db")
    database.hold_instance()
    monkeypatch.setattr(postgresql, "CLOSE_WAIT", 0.1)
    entered, release = threading.Event(), threading.Event()

    def write():
        with database._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('u', '1')")
            entered.set()
            release.wait(10)

    writer = threading.Thread(target=write)
    writer.start()
    assert entered.wait(5)
    database.close()
    assert database._store._instance is not None, "замок экземпляра остаётся, пока запись не завершена"
    with pytest.raises(DatabaseBusy, match="останавливается"):
        with database._tx():
            pass
    release.set()
    writer.join(10)
    monkeypatch.setattr(postgresql, "CLOSE_WAIT", 5)
    database.close()
    assert database._store._instance is None


def test_close_inside_own_write_is_refused(db: Database):
    with pytest.raises(RuntimeError, match="внутри её транзакции"):
        with db._tx():
            db.close()


def test_close_waits_for_started_write(tmp_path: Path):
    database = Database(tmp_path / "w.db")
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()

    def write():
        with database._tx() as c:
            c.execute("INSERT INTO meta(key, value) VALUES ('w', '1')")
            entered.set()
            release.wait(10)

    writer = threading.Thread(target=write)
    writer.start()
    assert entered.wait(5)
    closer = threading.Thread(target=lambda: (database.close(), closed.set()))
    closer.start()
    assert not closed.wait(0.3), "закрытие ждёт начатую транзакцию"
    release.set()
    writer.join(10)
    closer.join(15)
    assert closed.is_set()
    reopened = Database(tmp_path / "w.db")
    try:
        assert reopened._scalar("SELECT value FROM meta WHERE key = 'w'") == "1"
    finally:
        reopened.close()


# --- единственный экземпляр

def test_second_instance_on_same_base_is_refused(tmp_path: Path):
    path = tmp_path / "i.db"
    first, second = Database(path), Database(path)
    try:
        first.hold_instance()
        with pytest.raises(RuntimeError, match="другой экземпляр"):
            second.hold_instance()
        first._store.release_instance()
        second.hold_instance()
    finally:
        first.close()
        second.close()


def test_lost_instance_connection_stops_writes(tmp_path: Path):
    path = tmp_path / "i.db"
    database = Database(path)
    try:
        database.hold_instance()
        terminate_backends(path)
        with pytest.raises(LockLost):
            database.create_project("нельзя")
        assert database._scalar("SELECT COUNT(*) FROM projects") == 0
    finally:
        database.close()


# --- функции базы

@pytest.mark.parametrize("url", ["https://hub.example.org/path?x=1", "HTTP://Hub.Example.org:8080/", "  https://a.example  ",
                                 "hub.example.org", "", "https://", "ftp://x.example/y", "https://u:p@h.example/z#f", "https://hub.dev",
                                 "  https://hub.dev/v  ", "https://v"])
def test_hub_base_function_matches_python(db: Database, url: str):
    assert db._scalar("SELECT hub_base(?)", (url,)) == hub_base(url)


def test_hub_base_of_null(db: Database):
    assert db._scalar("SELECT hub_base(NULL)") == ""


@pytest.mark.parametrize("value, expected", [("ДеФеКт", "дефект"), ("ABC", "abc"), ("Ёлка", "ёлка"), (None, "")])
def test_unicode_search(db: Database, value, expected):
    assert db._scalar("SELECT unicode_search(?)", (value,)) == expected


def test_unicode_search_equals_python_casefold_for_every_character(db: Database):
    """Как прежняя функция SQLite: normalize("NFC", ...).casefold(). Образ базы или Python сменились – scripts/gen_unicode_search.py."""
    import unicodedata
    chars = [chr(c) for c in range(1, 0x110000) if unicodedata.category(chr(c)) not in ("Cn", "Cs", "Co")]
    with db._lock:
        got = [row[0] for row in db._conn.execute(
            "SELECT unicode_search(x) FROM unnest(?::text[]) WITH ORDINALITY AS t(x, n) ORDER BY n", (chars,)).fetchall()]
    wrong = [f"U+{ord(c):04X}" for c, value in zip(chars, got, strict=True) if value != unicodedata.normalize("NFC", c).casefold()]
    assert not wrong, wrong[:20]


def test_unicode_search_equals_python_casefold_on_mixed_strings(db: Database):
    """Замены не влияют друг на друга: строки вперемешку из обычных и особых букв и составных знаков."""
    import random
    import unicodedata
    letters = [chr(c) for c in range(1, 0x110000) if unicodedata.category(chr(c)) not in ("Cn", "Cs", "Co")
               and chr(c).lower() != chr(c).casefold()]
    letters += list("abcIiİıSsßſЁёЙйΣσς ̈́") + ["\u0307", "\u0345", "\u0301", "e\u0301", "\u1100\u1161", " ", "-"]
    rng = random.Random(20261104)
    texts = ["".join(rng.choice(letters) for _ in range(rng.randint(1, 40))) for _ in range(3000)]
    with db._lock:
        got = [row[0] for row in db._conn.execute(
            "SELECT unicode_search(x) FROM unnest(?::text[]) WITH ORDINALITY AS t(x, n) ORDER BY n", (texts,)).fetchall()]
    wrong = [ascii(text) for text, value in zip(texts, got, strict=True) if value != unicodedata.normalize("NFC", text).casefold()]
    assert not wrong, (len(wrong), wrong[:5])


@pytest.mark.parametrize("stored, query", [("Straße в заголовке", "STRASSE"), ("STRASSE", "straße"), ("ΣΊΣΥΦΟΣ", "σίσυφος"),
                                           ("ﬁle", "FILE"), ("Ёлка", "ёЛКА")])
def test_defect_search_finds_by_any_form_of_a_letter(db: Database, stored, query):
    assert db._scalar("SELECT strpos(unicode_search(?), unicode_search(?)) > 0", (stored, query)) == 1


@pytest.mark.parametrize("text, expected", [('[1, 2]', 2), ('[]', 0), ('{"a": 1}', 0), ('5', 0), ('null', 0), (None, None)])
def test_json_len(db: Database, text, expected):
    assert db._scalar("SELECT json_len(?::json)", (text,)) == expected


def test_text_order_is_bytewise(db: Database):
    with db._tx() as c:
        c.executemany("INSERT INTO meta(key, value) VALUES (?, '')", [("b",), ("A",), ("а",), ("Я",), ("10",), ("9",)])
    keys = [r["key"] for r in db._all("SELECT key FROM meta WHERE key IN ('b','A','а','Я','10','9') ORDER BY key")]
    assert keys == sorted(keys, key=lambda k: k.encode("utf-8")) == ["10", "9", "A", "b", "Я", "а"]


def test_nullable_app_id_comparison(db: Database):
    for left, right, same in [(None, None, 1), (7, 7, 1), (7, 8, 0), (None, 7, 0), (7, None, 0)]:
        assert db._scalar("SELECT ?::bigint IS NOT DISTINCT FROM ?::bigint", (left, right)) == same


# --- схема

def test_manifest_matches_catalog(db: Database):
    columns: dict[str, list[tuple[str, str]]] = {}
    for row in db._all("SELECT table_name, column_name, data_type FROM information_schema.columns"
                       " WHERE table_schema = current_schema() ORDER BY table_name, ordinal_position"):
        columns.setdefault(row["table_name"], []).append((row["column_name"], row["data_type"].upper()))
    columns.pop("storage_migrations")
    assert set(columns) == set(schema.TABLES) | set(schema.ADDED_TABLES) and len(columns) == 47
    for table, info in schema.ADDED_TABLES.items():  # таблицы миграций после базовой схемы (схема 36)
        assert columns.pop(table) == list(zip(info["columns"], info["types"])), table
    for table, added in schema.ADDED_COLUMNS.items():
        # колонки миграций после базовой схемы – в конце таблицы, базовый манифест их не содержит (схема 35)
        assert columns[table][-len(added):] == list(added), table
        columns[table] = columns[table][:-len(added)]
    for table, info in schema.TABLES.items():
        assert [c for c, _ in columns[table]] == list(info["columns"]), table
        assert [t for _, t in columns[table]] == list(info["types"]), table
    assert sorted(schema.LOAD_ORDER) == sorted(schema.TABLES)
    position = {name: i for i, name in enumerate(schema.LOAD_ORDER)}
    for table, info in schema.TABLES.items():
        for ref in info["refs"]:
            assert position[ref] < position[table], f"{ref} раньше {table}"


def test_all_integers_are_bigint_and_identity_only_where_generated(db: Database):
    assert "INTEGER" not in {t for info in schema.TABLES.values() for t in info["types"]}
    identity = {r["table_name"] for r in db._all("SELECT table_name FROM information_schema.columns"
                                                 " WHERE table_schema = current_schema() AND is_identity = 'YES'")}
    assert identity == {t for t, info in {**schema.TABLES, **schema.ADDED_TABLES}.items() if info["identity"]}
    assert "review_texts" in identity and not {"run_journal", "schema_version"} & identity


def test_foreign_keys_can_be_deferred_but_are_checked_at_once(db: Database):
    row = db._one("SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE condeferrable AND NOT condeferred) AS deferrable"
                  " FROM pg_constraint WHERE contype = 'f' AND connamespace = current_schema()::regnamespace")
    assert row["total"] == row["deferrable"] and row["total"] > 50
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with db._tx() as c:
            c.execute("INSERT INTO imports(project_id, filename, format, created_at) VALUES (999, 'x', 'hub', 'now')")


def test_baseline_is_recorded_with_checksum(db: Database):
    row = db._one("SELECT number, schema_version, checksum FROM storage_migrations")
    assert row == {"number": 1, "schema_version": BASELINE_SCHEMA, "checksum": checksum(BASELINE)}
    assert db_module.SCHEMA_VERSION == schema.SCHEMA_VERSION


def test_other_schema_version_is_refused_without_change(tmp_path: Path):
    path = tmp_path / "v.db"
    database = Database(path)
    with database._tx() as c:
        c.execute("UPDATE meta SET value = '32' WHERE key = 'schema_version'")
    database.close()
    with pytest.raises(RuntimeError, match="обновите схему"):
        Database(path)
    conn = psycopg.connect(postgresql.conninfo_for(path))
    assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "32"
    conn.close()


def test_newer_schema_version_is_refused(tmp_path: Path):
    path = tmp_path / "v.db"
    database = Database(path)
    with database._tx() as c:
        c.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    database.close()
    with pytest.raises(RuntimeError, match="более новой"):
        Database(path)


def test_foreign_database_is_refused(tmp_path: Path):
    path = tmp_path / "f.db"
    database = Database(path)
    with database._tx() as c:
        c.execute("DROP TABLE meta")
    database.close()
    with pytest.raises(RuntimeError, match="не база этого приложения"):
        Database(path)


def test_missing_column_is_refused(tmp_path: Path):
    path = tmp_path / "c.db"
    database = Database(path)
    with database._tx() as c:
        c.execute("ALTER TABLE projects DROP COLUMN model")
    database.close()
    with pytest.raises(RuntimeError, match="нет колонок model"):
        Database(path)


def test_missing_table_is_refused(tmp_path: Path):
    path = tmp_path / "c.db"
    database = Database(path)
    with database._tx() as c:
        c.execute("DROP TABLE review_texts")
    database.close()
    with pytest.raises(RuntimeError, match="нет таблицы review_texts"):
        Database(path)


def test_first_id_after_explicit_default_profile_does_not_collide(db: Database):
    db.ensure_default_profile("http://localhost:11434", "m")
    created = db.create_provider({"name": "x", "kind": "ollama", "base_url": "http://localhost:11434", "trust": "local",
                                  "auth": "none", "purposes_json": "[]", "enabled": 1, "default_model": "m",
                                  "models_json": "[]", "capabilities_json": "{}", "confirmed_addresses_json": "[]",
                                  "generation_json": "{}"})
    assert created["id"] == 2
