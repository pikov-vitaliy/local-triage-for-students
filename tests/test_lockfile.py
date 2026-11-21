"""Замок папки данных: второй экземпляр приложения на той же папке DATA_DIR не стартует."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import metrics
from app.config import Settings
from app.lockfile import LOCK_NAME, InstanceLock, LockBusy
from app.main import create_app


def foreign_lock(folder: Path, age: float = 0.0) -> Path:
    """Замок другого экземпляра: другая машина и процесс, отметка age секунд назад."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / LOCK_NAME
    path.write_text(json.dumps({"host": "other-host", "pid": 4242, "token": "x" * 32, "beat": time.time() - age}),
                    encoding="utf-8")
    return path


def test_acquire_and_release(tmp_path: Path):
    lock = InstanceLock(tmp_path, beat=0.05)
    lock.acquire()
    data = json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))
    assert data["token"] == lock.token and data["pid"] == lock.pid
    first = data["beat"]
    # отметка обновляется; поток отметок под нагрузкой параллельных прогонов может опоздать, предел – с запасом
    deadline = time.monotonic() + 10
    while json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["beat"] <= first and time.monotonic() < deadline:
        time.sleep(0.05)
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["beat"] > first
    lock.release()
    assert not (tmp_path / LOCK_NAME).exists()


def test_fresh_foreign_lock_refuses_and_stale_one_is_taken(tmp_path: Path):
    foreign_lock(tmp_path)
    with pytest.raises(LockBusy, match="другой запущенный экземпляр"):
        InstanceLock(tmp_path).acquire()
    foreign_lock(tmp_path, age=60)  # держатель завершился аварийно
    lock = InstanceLock(tmp_path)
    lock.acquire()
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == lock.token
    lock.release()


def test_same_host_and_pid_do_not_prove_restart(tmp_path: Path):
    """Совпадение машины и номера процесса не доказывает, что прежний держатель не работает: ждём, пока отметка
    устареет."""
    earlier = InstanceLock(tmp_path)
    earlier.acquire()
    earlier._stop.set()  # «упал», не отпустив замок
    with pytest.raises(LockBusy):
        InstanceLock(tmp_path).acquire()
    later = InstanceLock(tmp_path, stale=0.0)  # отметка устарела
    later.acquire()
    later.release()


def test_concurrent_start_lets_only_one_win(tmp_path: Path):
    import threading

    locks = [InstanceLock(tmp_path) for _ in range(8)]
    results: list[str] = []
    barrier = threading.Barrier(len(locks))

    def start(lock):
        barrier.wait()
        try:
            lock.acquire()
            results.append("ok")
        except LockBusy:
            results.append("busy")

    threads = [threading.Thread(target=start, args=(lock,)) for lock in locks]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1 and results.count("busy") == len(locks) - 1
    for lock in locks:
        lock.release()


def test_lost_lock_stops_writes(tmp_path: Path):
    """Держатель долго не обновлял отметку, папку забрал другой экземпляр: записи прежнего прекращаются."""
    from app.db import Database
    from app.lockfile import LockLost

    first = InstanceLock(tmp_path, stale=0.0)
    first.acquire()
    db = Database(tmp_path / "triage.db", write_guard=first.check)
    db.create_project("до")
    second = InstanceLock(tmp_path, stale=0.0)
    second.acquire()  # отметка первого «устарела» – второй забрал замок
    with pytest.raises(LockLost):  # сразу, без задержки: замок перечитывается перед каждой записью
        db.create_project("после")
    assert [p["name"] for p in db.list_projects()] == ["до"]  # чтение работает, запись – нет
    first.revoke()
    db.close()
    first.release()
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == second.token
    second.release()


def test_app_does_not_start_on_busy_data_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path, ollama_url="http://127.0.0.1:9")
    foreign_lock(settings.data_dir / "telemetry")  # замок – в папке телеметрии, ADR-0133
    with pytest.raises(LockBusy):
        with TestClient(create_app(settings)):
            pass
    assert not settings.db_path.exists()  # база не открывалась и не создавалась
    (settings.data_dir / "telemetry" / LOCK_NAME).unlink()
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/healthz").status_code == 200
        assert (settings.data_dir / "telemetry" / LOCK_NAME).exists()
    assert not (settings.data_dir / "telemetry" / LOCK_NAME).exists()  # отпущен при остановке


def test_takeover_is_checked_again_under_change_marker(tmp_path: Path, monkeypatch):
    """Гонка захвата: A увидел устаревший замок, но пока ждал метку смены, замок взял B. Под меткой A проверяет
    замок заново и получает отказ, а не забирает свежий замок B."""
    foreign_lock(tmp_path, age=60)
    a, b = InstanceLock(tmp_path), InstanceLock(tmp_path)
    real_changing = a._changing

    from contextlib import contextmanager

    @contextmanager
    def late_changing():
        b.acquire()  # B успел раньше
        with real_changing():
            yield

    monkeypatch.setattr(a, "_changing", late_changing)
    with pytest.raises(LockBusy):
        a.acquire()
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == b.token
    b.release()


def test_release_does_not_delete_foreign_lock(tmp_path: Path):
    first = InstanceLock(tmp_path, stale=0.0)
    first.acquire()
    second = InstanceLock(tmp_path, stale=0.0)
    second.acquire()
    first.release()  # замок уже не его – файл второго остаётся
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == second.token
    second.release()
    assert not (tmp_path / LOCK_NAME).exists()


def test_schema_creation_respects_guard():
    from app.db import Database
    from db_support import empty_database
    from app.lockfile import LockLost

    def refuse():
        raise LockLost("нельзя")

    with pytest.raises(LockLost):
        Database(empty_database(), write_guard=refuse)


def abandoned_marker(folder: Path, kind: str, age: float = 60.0, created_age: float | None = None) -> Path:
    """Метка смены, брошенная age секунд назад, в одном из трёх форматов (бэклог 132): json – с 0.10.0.dev32, token –
    прежние версии, empty – процесс упал, не успев записать. created_age – возраст по полю created, если он другой."""
    import os
    import socket

    from app import lockfile
    folder.mkdir(parents=True, exist_ok=True)
    marker = folder / lockfile.CHANGE_NAME
    created = time.time() - (age if created_age is None else created_age)
    body = {"json": json.dumps({"token": "b" * 32, "host": socket.gethostname(), "pid": os.getpid(), "created": created}),
            "token": "c" * 32, "empty": ""}[kind]
    marker.write_text(body, encoding="utf-8")
    old = time.time() - age
    os.utime(marker, (old, old))
    return marker


def lock_file(folder: Path, state: str) -> None:
    """Файл замка в состоянии state: absent – нет; empty – пуст, остался от сбоя между созданием и записью минуту
    назад; stale – отметка старше STALE_S; fresh – живой чужой экземпляр."""
    import os
    path = folder / LOCK_NAME
    if state == "absent":
        path.unlink(missing_ok=True)
    elif state == "empty":
        path.write_text("", encoding="utf-8")
        old = time.time() - 60
        os.utime(path, (old, old))
    else:
        foreign_lock(folder, age=60 if state == "stale" else 0)


def test_young_empty_lock_still_refuses_after_marker_is_cleared(tmp_path: Path):
    """Пустой замок моложе STALE_S мог только что создать другой экземпляр: брошенная метка снимается, но сам замок, как
    и раньше, судится по времени изменения – отказ, пока он не устареет."""
    marker = abandoned_marker(tmp_path, "token")
    (tmp_path / LOCK_NAME).write_text("", encoding="utf-8")
    with pytest.raises(LockBusy, match="другой запущенный экземпляр"):
        InstanceLock(tmp_path).acquire()
    assert not marker.exists()


@pytest.mark.parametrize("lock_state", ["absent", "empty", "stale"])
@pytest.mark.parametrize("kind", ["json", "token", "empty"])
def test_abandoned_change_marker_is_cleared_when_lock_is_free(tmp_path: Path, kind: str, lock_state: str, caplog):
    """Брошенная метка смены любого формата снимается сама, если замок свободен: отсутствует (сбой между созданием
    метки и замка при захвате или между удалением замка и метки при отпускании), пуст или устарел (бэклог 132 и 43)."""
    import logging

    from app import lockfile
    marker = abandoned_marker(tmp_path, kind)
    lock_file(tmp_path, lock_state)
    lock = InstanceLock(tmp_path)
    with caplog.at_level(logging.WARNING, logger="local_triage.lock"):
        lock.acquire()
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == lock.token
    assert any("брошенная метка смены" in r.getMessage() for r in caplog.records)
    lock.release()
    assert not marker.exists() and not (tmp_path / LOCK_NAME).exists()
    assert not [p.name for p in tmp_path.iterdir()], "временных файлов метки не остаётся"
    assert lockfile.CHANGE_STALE_S == 10.0 and lockfile.STALE_S == 20.0  # пороги прежние


@pytest.mark.parametrize("kind", ["json", "token", "empty"])
def test_abandoned_marker_with_fresh_lock_is_refused(tmp_path: Path, monkeypatch, kind: str):
    """Метка старая, а замок свежий – живой экземпляр есть: отказ с его описанием, метка не трогается."""
    from app import lockfile
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.1)
    marker = abandoned_marker(tmp_path, kind)
    body = marker.read_text(encoding="utf-8")
    lock_file(tmp_path, "fresh")
    with pytest.raises(LockBusy, match="другой запущенный экземпляр"):
        InstanceLock(tmp_path).acquire()
    assert marker.read_text(encoding="utf-8") == body


@pytest.mark.parametrize("age,created_age", [(5.0, None), (60.0, 1.0), (1.0, 60.0)])
def test_young_change_marker_is_not_cleared(tmp_path: Path, monkeypatch, age: float, created_age: float | None):
    """Метка моложе CHANGE_STALE_S – по времени файла или по полю created (берётся меньший возраст: расхождение часов
    не снимает живую метку) – не снимается и при свободном замке: её может держать живой экземпляр."""
    from app import lockfile
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.1)
    marker = abandoned_marker(tmp_path, "json", age=age, created_age=created_age)
    body = marker.read_text(encoding="utf-8")
    with pytest.raises(LockBusy, match="Повторите запуск"):
        InstanceLock(tmp_path).acquire()
    assert marker.read_text(encoding="utf-8") == body


def test_container_restart_with_same_host_and_pid(tmp_path: Path, monkeypatch):
    """Перезапуск контейнера: метка и замок с прежними именем машины и номером процесса. Живость по номеру процесса не
    проверяется: устаревшие метка и замок снимаются, свежий замок с тем же номером – отказ."""
    import os
    import socket

    from app import lockfile
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.1)
    same = {"host": socket.gethostname(), "pid": os.getpid(), "token": "d" * 32}
    marker = abandoned_marker(tmp_path, "json")
    (tmp_path / LOCK_NAME).write_text(json.dumps({**same, "beat": time.time()}), encoding="utf-8")
    with pytest.raises(LockBusy):
        InstanceLock(tmp_path).acquire()
    assert marker.exists()
    (tmp_path / LOCK_NAME).write_text(json.dumps({**same, "beat": time.time() - 60}), encoding="utf-8")
    lock = InstanceLock(tmp_path)
    lock.acquire()
    assert not marker.exists()
    lock.release()


def test_holder_clears_abandoned_marker_of_its_own_lock(tmp_path: Path):
    """Метку бросил чужой процесс, пока замок держит этот экземпляр: держатель снимает её сам (замок его) и отпускает
    замок, не дожидаясь, пока отметка устареет."""
    lock = InstanceLock(tmp_path)
    lock.acquire()
    lock._stop.set()
    lock._thread.join(timeout=5)
    marker = abandoned_marker(tmp_path, "token")
    lock.release()
    assert not marker.exists() and not (tmp_path / LOCK_NAME).exists()


def test_concurrent_starts_clear_abandoned_marker_once(tmp_path: Path, caplog):
    """Брошенная метка и устаревший замок, несколько запусков одновременно (Д4): метку снимает один, замок берёт один,
    временных файлов не остаётся."""
    import logging
    import threading

    abandoned_marker(tmp_path, "token")
    lock_file(tmp_path, "stale")
    locks = [InstanceLock(tmp_path) for _ in range(8)]
    results: list[str] = []
    barrier = threading.Barrier(len(locks))

    def start(lock):
        barrier.wait()
        try:
            lock.acquire()
            results.append("ok")
        except LockBusy:
            results.append("busy")

    with caplog.at_level(logging.WARNING, logger="local_triage.lock"):
        threads = [threading.Thread(target=start, args=(lock,)) for lock in locks]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert results.count("ok") == 1 and results.count("busy") == len(locks) - 1
    assert sum("брошенная метка смены" in r.getMessage() for r in caplog.records) == 1
    for lock in locks:
        lock.release()
    assert not [p.name for p in tmp_path.iterdir()]


def test_marker_recreated_while_clearing_is_put_back(tmp_path: Path, monkeypatch):
    """Между проверкой и переносом брошенную метку сняли и создали новую: перенесённая – не та, она возвращается на
    место, а метка не считается снятой."""
    from app import lockfile
    marker = abandoned_marker(tmp_path, "token")
    lock = InstanceLock(tmp_path)
    real_state = lock._lock_state
    fresh = json.dumps({"token": "e" * 32, "created": time.time()})

    def swap():
        marker.unlink()
        marker.write_text(fresh, encoding="utf-8")
        return real_state()

    monkeypatch.setattr(lock, "_lock_state", swap)
    assert lock._clear_abandoned_change() is False
    assert marker.read_text(encoding="utf-8") == fresh
    assert sorted(p.name for p in tmp_path.iterdir()) == [lockfile.CHANGE_NAME]


def test_paused_holder_does_not_drop_foreign_marker(tmp_path: Path):
    """Экземпляр стоял дольше CHANGE_STALE_S с меткой: её сняли как брошенную, и другой создал свою. Проснувшись,
    первый не удаляет чужую метку (ревью сборки А, Д4): сверка – после переноса, чужая возвращается на место."""
    from app import lockfile
    a = InstanceLock(tmp_path)
    assert a._create_change()
    other = json.dumps({"token": "f" * 32, "host": "h", "pid": 1, "created": time.time()})
    (tmp_path / lockfile.CHANGE_NAME).unlink()
    (tmp_path / lockfile.CHANGE_NAME).write_text(other, encoding="utf-8")
    a._drop_change()
    assert (tmp_path / lockfile.CHANGE_NAME).read_text(encoding="utf-8") == other
    assert sorted(p.name for p in tmp_path.iterdir()) == [lockfile.CHANGE_NAME]
    b = InstanceLock(tmp_path)
    b._capture = "f" * 32
    b._drop_change()
    assert not (tmp_path / lockfile.CHANGE_NAME).exists()


def test_threads_of_one_instance_do_not_share_change(tmp_path: Path, monkeypatch):
    """Два потока одного экземпляра (отметка и проверка перед записью): пока первый держит смену замка, второй не входит
    и не удаляет метку первого (ревью сборки А, круг 2, Д4)."""
    import threading

    from app import lockfile
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.3)
    lock = InstanceLock(tmp_path)
    inside, release, result = threading.Event(), threading.Event(), {}

    def first():
        with lock._changing():
            inside.set()
            release.wait(5)

    def second():
        try:
            with lock._changing():
                result["second"] = "вошёл"
        except TimeoutError:
            result["second"] = "ждал"

    t1 = threading.Thread(target=first)
    t1.start()
    assert inside.wait(5)
    body = (tmp_path / lockfile.CHANGE_NAME).read_text(encoding="utf-8")
    t2 = threading.Thread(target=second)
    t2.start()
    t2.join(5)
    assert result["second"] == "ждал"
    assert (tmp_path / lockfile.CHANGE_NAME).read_text(encoding="utf-8") == body
    release.set()
    t1.join(5)
    assert not (tmp_path / lockfile.CHANGE_NAME).exists()


def test_misplaced_marker_is_put_back_without_hard_links(tmp_path: Path, monkeypatch):
    """Файловая система без жёстких ссылок: ошибочно перенесённая чужая метка возвращается созданием с O_EXCL и прежним
    содержимым, а не теряется (ревью сборки А, круг 2, Д4)."""
    from app import lockfile
    marker = tmp_path / lockfile.CHANGE_NAME
    body = json.dumps({"token": "e" * 32, "created": time.time()})
    marker.write_text(body, encoding="utf-8")

    def no_links(*args, **kwargs):
        raise OSError(1, "ссылки не поддерживаются")

    monkeypatch.setattr(lockfile.os, "link", no_links)
    assert InstanceLock(tmp_path)._take_marker(lambda raw, st: False) is False
    assert marker.read_text(encoding="utf-8") == body
    assert sorted(p.name for p in tmp_path.iterdir()) == [lockfile.CHANGE_NAME]


def test_paused_starter_does_not_replace_foreign_lock(tmp_path: Path, monkeypatch):
    """Первый запуск стоял после проверки замка дольше CHANGE_STALE_S; за это время второй снял его метку и взял
    папку. Проснувшись, первый не удаляет и не заменяет замок второго – отказ «занято» (ревью сборки А, круг 3, Д4)."""
    from app import lockfile
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.2)
    a = InstanceLock(tmp_path)
    real_busy = a._busy
    other = json.dumps({"host": "h", "pid": 2, "token": "b" * 32, "beat": time.time()})

    def paused_busy():
        answer = real_busy()
        (tmp_path / lockfile.CHANGE_NAME).write_text(json.dumps({"token": "c" * 32, "created": time.time()}), encoding="utf-8")
        (tmp_path / LOCK_NAME).write_text(other, encoding="utf-8")
        return answer

    monkeypatch.setattr(a, "_busy", paused_busy)
    with pytest.raises(LockBusy):
        a.acquire()
    assert (tmp_path / LOCK_NAME).read_text(encoding="utf-8") == other


def test_failed_put_back_keeps_the_only_copy(tmp_path: Path, monkeypatch):
    """Вернуть ошибочно перенесённую метку не удалось ни ссылкой, ни O_EXCL: её файл остаётся, единственная копия не
    удаляется (ревью сборки А, круг 3, Д4)."""
    from app import lockfile
    marker = tmp_path / lockfile.CHANGE_NAME
    body = json.dumps({"token": "e" * 32, "created": time.time()})
    marker.write_text(body, encoding="utf-8")
    real_open = lockfile.os.open

    def no_links(*args, **kwargs):
        raise OSError(1, "ссылки не поддерживаются")

    def deny(path, *args, **kwargs):
        if str(path) == str(marker):
            raise PermissionError(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(lockfile.os, "link", no_links)
    monkeypatch.setattr(lockfile.os, "open", deny)
    assert InstanceLock(tmp_path)._take_marker(lambda raw, st: False) is False
    kept = [p for p in tmp_path.iterdir() if p.name.endswith(".aside")]
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == body


def test_marker_permission_error_means_busy(tmp_path: Path, monkeypatch):
    """Windows отвечает PermissionError на создание метки, которую как раз удаляют: это «метка занята», запуск ждёт
    и берёт замок, а не падает с ошибкой доступа."""
    from app import lockfile
    real_link, real_open = lockfile.os.link, lockfile.os.open
    denials = {"n": 0}
    lock = InstanceLock(tmp_path)

    def busy(real):
        def call(src, *args, **kwargs):
            target = args[0] if real is real_link else src
            if str(target) == str(lock.change) and denials["n"] < 6:
                denials["n"] += 1
                raise PermissionError(str(target))
            return real(src, *args, **kwargs)
        return call

    monkeypatch.setattr(lockfile.os, "link", busy(real_link))
    monkeypatch.setattr(lockfile.os, "open", busy(real_open))
    lock.acquire()
    assert denials["n"] == 6
    lock.release()


def test_unwritable_folder_is_an_access_error(tmp_path: Path, monkeypatch):
    """Временный файл метки не создаётся – это нет доступа к папке (OSError), а не «метка занята»."""
    import builtins

    real_open = builtins.open

    def deny(file, *args, **kwargs):
        if str(file).endswith(".tmp"):
            raise PermissionError(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny)
    with pytest.raises(PermissionError):
        InstanceLock(tmp_path).acquire()


def test_lock_lost_inside_transaction_rolls_it_back(tmp_path: Path):
    """Папку забрали посреди транзакции: проверка перед COMMIT откатывает её, соединение остаётся рабочим."""
    from app.db import Database
    from app.lockfile import LockLost

    calls = {"n": 0, "limit": None}

    def guard():
        calls["n"] += 1
        if calls["limit"] is not None and calls["n"] > calls["limit"]:
            raise LockLost("папку забрали")

    db = Database(tmp_path / "triage.db", write_guard=guard)
    db.create_project("до")
    calls["limit"] = calls["n"] + 1  # проверка до BEGIN проходит, перед COMMIT – уже нет
    with pytest.raises(LockLost):
        db.create_project("после")
    calls["limit"] = None
    assert [p["name"] for p in db.list_projects()] == ["до"]
    db.create_project("снова")  # незакрытой транзакции не осталось
    assert sorted(p["name"] for p in db.list_projects()) == ["до", "снова"]
    db.close()


def test_momentary_missing_lock_file_does_not_stop_writes(tmp_path: Path, monkeypatch):
    """Через том Docker Desktop замена файла замка видна как миг без файла: записи не останавливаются навсегда."""
    from app import lockfile
    lock = InstanceLock(tmp_path)
    lock.acquire()
    real = lockfile._read
    misses = [None]  # одно чтение – «без файла», дальше файл на месте
    monkeypatch.setattr(lockfile, "_read", lambda path: misses.pop() if misses and path == lock.path else real(path))
    lock.check()  # первое чтение «без файла», перепроверка под меткой смены – замок наш
    monkeypatch.setattr(lockfile, "_read", real)
    lock.check()
    lock.release()


def test_read_retries_missing_file(tmp_path: Path, monkeypatch):
    from app import lockfile
    path = tmp_path / LOCK_NAME
    calls = []
    real_read_text = Path.read_text

    def flaky(self, *args, **kwargs):
        if self == path and not calls:
            calls.append(1)
            raise FileNotFoundError(str(self))
        return real_read_text(self, *args, **kwargs)

    path.write_text(json.dumps({"token": "t"}), encoding="utf-8")
    monkeypatch.setattr(Path, "read_text", flaky)
    assert lockfile._read(path) == {"token": "t"}
    assert lockfile._read(tmp_path / "нет") is None


def test_unreadable_lock_refuses_one_write_but_not_forever(tmp_path: Path, monkeypatch):
    """Файл замка не прочитался и при перепроверке: эта запись – LockUnsure, замок не объявляется потерянным."""
    from app import lockfile
    from app.lockfile import LockLost, LockUnsure
    lock = InstanceLock(tmp_path)
    lock.acquire()
    real = lockfile._read
    monkeypatch.setattr(lockfile, "_read", lambda path: None if path == lock.path else real(path))
    with pytest.raises(LockUnsure):
        lock.check()
    monkeypatch.setattr(lockfile, "_read", real)
    lock.check()  # файл снова читается – записи идут
    (tmp_path / LOCK_NAME).write_text(json.dumps({"token": "чужой", "beat": time.time()}), encoding="utf-8")
    with pytest.raises(LockLost):  # чужая метка – по-прежнему навсегда
        lock.check()
    with pytest.raises(LockLost):
        lock.check()


def test_beat_survives_unreadable_lock(tmp_path: Path, monkeypatch):
    from app import lockfile
    lock = InstanceLock(tmp_path, beat=0.05)
    lock.acquire()
    real = lockfile._read
    misses = {"n": 0}

    def flaky(path):
        if path == lock.path and misses["n"] < 3:
            misses["n"] += 1
            return None
        return real(path)

    monkeypatch.setattr(lockfile, "_read", flaky)
    deadline = time.monotonic() + 10  # ожидание по условию: под нагрузкой (параллельные прогоны) отметка реже 0,05 с
    while misses["n"] < 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)  # ещё пара отметок после пропусков
    assert not lock._lost and misses["n"] == 3
    lock.check()
    lock.release()


def test_lock_errors_reach_user_as_503(tmp_path: Path, monkeypatch):
    from app.lockfile import LockUnsure
    from test_web import BASE, ORIGIN
    # адрес Ollama – недоступный: с адресом по умолчанию (host.docker.internal) тест ходил бы к настоящей Ollama (T-11434)
    app = create_app(Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url="http://127.0.0.1:9"))
    with TestClient(app, base_url=BASE) as client:
        def refuse():
            raise LockUnsure("Файл замка папки данных сейчас не прочитался: повторите.")
        monkeypatch.setattr(app.state.db, "_write_guard", refuse)
        r = client.post("/projects", data={"name": "п"}, headers={**ORIGIN, "Accept": "application/json"})
        assert r.status_code == 503 and "повторите" in r.text


@pytest.mark.parametrize("content", ["{}", '{"beat": 123}', '{"token": null}', '{"token": ""}', "[]"])
def test_lock_without_token_is_not_a_takeover(tmp_path: Path, content: str):
    """Замок без метки запуска (повреждён) – не доказательство захвата: запись откладывается, после восстановления –
    идёт; heartbeat не останавливается."""
    from app.lockfile import LockUnsure
    lock = InstanceLock(tmp_path, beat=0.05)
    lock.acquire()
    good = (tmp_path / LOCK_NAME).read_text(encoding="utf-8")
    (tmp_path / LOCK_NAME).write_text(content, encoding="utf-8")
    with pytest.raises(LockUnsure):
        lock.check()
    time.sleep(0.2)  # несколько отметок heartbeat с повреждённым файлом
    assert not lock._lost
    (tmp_path / LOCK_NAME).write_text(good, encoding="utf-8")
    lock.check()
    lock.release()


def test_change_marker_access_error_is_unsure(tmp_path: Path, monkeypatch):
    """Метку смены не создать (PermissionError – «занята») всё время ожидания, а файл замка не прочитался: эта запись –
    LockUnsure, замок не объявляется потерянным."""
    from app import lockfile
    from app.lockfile import LockUnsure
    lock = InstanceLock(tmp_path)
    lock.acquire()
    monkeypatch.setattr(lockfile, "CHANGE_WAIT_S", 0.1)
    real = lockfile._read
    monkeypatch.setattr(lockfile, "_read", lambda path: None if path == lock.path else real(path))
    real_open, real_link = lockfile.os.open, lockfile.os.link

    def deny_open(path, *args, **kwargs):
        if str(path) == str(lock.change):
            raise PermissionError(path)
        return real_open(path, *args, **kwargs)

    def deny_link(src, dst, *args, **kwargs):
        if str(dst) == str(lock.change):
            raise PermissionError(dst)
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(lockfile.os, "open", deny_open)
    monkeypatch.setattr(lockfile.os, "link", deny_link)
    with pytest.raises(LockUnsure):
        lock.check()
    assert not lock._lost


def test_deleted_lock_file_is_restored_by_its_holder(tmp_path: Path):
    """Файл замка удалили (Э4): держатель восстанавливает его под меткой смены, записи продолжаются."""
    lock = InstanceLock(tmp_path)
    lock.acquire()
    (tmp_path / LOCK_NAME).unlink()
    lock.check()  # запись разрешена, файл снова наш
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == lock.token
    lock.release()
    assert not (tmp_path / LOCK_NAME).exists()


def test_beat_restores_deleted_lock_file(tmp_path: Path):
    lock = InstanceLock(tmp_path, beat=0.05)
    lock.acquire()
    (tmp_path / LOCK_NAME).unlink()
    deadline = time.time() + 2
    while not (tmp_path / LOCK_NAME).exists() and time.time() < deadline:
        time.sleep(0.02)
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == lock.token
    assert not lock._lost
    lock.release()


def test_deleted_lock_taken_by_another_instance_is_not_restored(tmp_path: Path):
    """Файл удалили, и папку тут же взял другой экземпляр: восстановления нет – замок потерян."""
    from app.lockfile import LockLost
    lock = InstanceLock(tmp_path)
    lock.acquire()
    (tmp_path / LOCK_NAME).unlink()
    other = InstanceLock(tmp_path)
    other.acquire()
    with pytest.raises(LockLost):
        lock.check()
    assert json.loads((tmp_path / LOCK_NAME).read_text(encoding="utf-8"))["token"] == other.token
    lock.release()
    other.release()


def test_deleted_lock_with_stale_own_beat_is_lost(tmp_path: Path):
    """Экземпляр спал дольше stale: другой мог забрать папку, поработать и удалить свой замок при остановке. Файла
    нет, своя отметка устарела – восстановления нет, записи прекращаются (иначе два писателя на одной базе)."""
    from app.lockfile import LockLost
    lock = InstanceLock(tmp_path, stale=1.0)
    lock.acquire()
    (tmp_path / LOCK_NAME).unlink()
    lock._beat_at = time.time() - 5  # последняя своя отметка – давно
    with pytest.raises(LockLost):
        lock.check()
    assert not (tmp_path / LOCK_NAME).exists()
    with pytest.raises(LockLost):
        lock.check()
    lock.release()


def test_abandoned_marker_removed_when_lock_has_broken_utf8(tmp_path: Path):
    """Брошенная метка смены снимается и при instance.lock с невалидным UTF-8: повреждённый файл судится по mtime, как
    повреждённый JSON (ревью круга 6: был UnicodeDecodeError и отказ запуска)."""
    from app.lockfile import CHANGE_NAME
    old = time.time() - 100
    lock_file = tmp_path / LOCK_NAME
    lock_file.write_bytes(b"\xff\xfe\x00garbage")
    change = tmp_path / CHANGE_NAME
    change.write_text("old-token", encoding="utf-8")
    os.utime(lock_file, (old, old))
    os.utime(change, (old, old))
    lock = InstanceLock(tmp_path)
    lock.acquire()
    lock.release()
