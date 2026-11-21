"""Замок папки телеметрии: один экземпляр приложения на одну папку (ADR-0133; базу охраняет замок базы).

Замеры лежат в файле SQLite, а через том Docker Desktop эта блокировка не действует: процесс
Windows и контейнер могут одновременно писать в один файл, и записи одного из них пропадут. Блокировки файлов
ОС через эту границу тоже не действуют, поэтому замок устроен на обычных файлах:

  * instance.lock – кто держит папку (имя машины, номер процесса, метка запуска) и отметка времени, которую
    держатель обновляет каждые BEAT_S секунд;
  * instance.lock.change – метка «файл замка сейчас меняют»: создаётся без замены существующей, поэтому проверку и
    смену владельца (захват, обновление отметки, отпускание) в один момент делает только один экземпляр. Захватчик
    проверяет замок уже под меткой: если за это время его взял другой, захвата не будет. Метку держат доли секунды.
    Форматы метки – три: JSON {token, host, pid, created} (с 0.10.0.dev32 метка появляется сразу с содержимым:
    временный файл и жёсткая ссылка на него), текст метки запуска (так писали прежние версии) и пустой файл (процесс
    упал, не успев записать). Брошенная метка – старше CHANGE_STALE_S, а файл замка отсутствует, пуст, устарел или
    принадлежит этому экземпляру – снимается автоматически с записью в журнал (бэклог 132 и 43, ADR-0155 уточняет
    ADR-0009): живой экземпляр держит метку доли секунды и обновляет отметку каждые BEAT_S. Живость процесса по номеру
    не проверяется – после перезапуска контейнера номер процесса и имя машины бывают прежними.

Замок со свежей отметкой – отказ запуска с понятной ошибкой до любых записей в базу. Отметка старше STALE_S
секунд считается брошенной: держатель упал или приостановлен (номер процесса и имя машины не доказывают ни того,
ни другого, поэтому перезапуск после аварии ждёт, пока отметка устареет). Держатель перечитывает замок перед
каждой записью в базу и ещё раз перед завершением транзакции (check): если папку забрал другой экземпляр
(держатель долго не обновлял отметку, например компьютер спал), записи прекращаются с LockLost, а начатая
транзакция откатывается. При остановке держатель сначала запрещает свои записи (revoke), затем отпускает замок.

Это защита от ошибки «запустил второй экземпляр на ту же папку», а не гарантия единственного писателя: файлы
через том Docker Desktop не дают настоящей межпроцессной блокировки. Между последней проверкой и COMMIT остаётся
окно – обычно доли секунды. Если держатель приостановлен именно в этот миг дольше STALE_S (сон компьютера,
отладчик), после пробуждения он может завершить одну начатую транзакцию поверх записей нового владельца.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

LOCK_NAME = "instance.lock"
CHANGE_NAME = LOCK_NAME + ".change"
BEAT_S = 5.0  # как часто держатель обновляет отметку
STALE_S = 20.0  # отметка старше – держатель не работает
CHANGE_STALE_S = 10.0  # метка смены старше, а замок свободен – метка брошена и снимается (бэклог 132, ADR-0155)
CHANGE_WAIT_S = 5.0  # сколько ждать метку смены

log = logging.getLogger("local_triage.lock")


class LockBusy(RuntimeError):
    """Папку данных держит другой работающий экземпляр приложения."""


class LockUnsure(RuntimeError):
    """Владельца папки данных сейчас не установить (файл замка не прочитался): эта запись не выполняется, следующие –
    как обычно. Не означает, что папку забрали."""


class LockLost(RuntimeError):
    """Замок этого экземпляра забрал другой экземпляр или приложение останавливается: записи запрещены."""


LOST_TEXT = "Папку данных забрал другой экземпляр приложения: запись остановлена. Перезапустите приложение."
UNSURE_TEXT = ("Файл замка папки данных сейчас не прочитался: запись не выполнена, данные не изменены. Повторите "
               "действие через несколько секунд.")


def _retrying(action: Callable[[], Any], attempts: int = 5, pause: float = 0.05) -> Any:
    """Windows не даёт удалить, заменить или переименовать файл, пока его открыл другой процесс (PermissionError): несколько
    попыток с паузой, затем исключение наружу."""
    for attempt in range(attempts):
        try:
            return action()
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(pause)
    return None


def _marker_fields(raw: str) -> dict:
    """Поля метки смены любого из трёх форматов: JSON {token, host, pid, created}; текст метки запуска (прежние
    версии); пустой файл."""
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    return data if isinstance(data, dict) else {"token": raw.strip()}


def _stand_npm() -> bool:
    from app.config import stand_mode
    return stand_mode() == "npm"


def _read(path: Path) -> dict | None:
    for attempt in range(3):  # файл могли заменять в этот момент
        try:
            data = json.loads(path.read_bytes().decode("utf-8", "replace"))
            return data if isinstance(data, dict) else None
        except FileNotFoundError:
            # через том Docker Desktop атомарная замена (os.replace) видна читающему как миг без файла
            if attempt == 2:
                return None
            time.sleep(0.05)
        except (OSError, ValueError):
            time.sleep(0.05)
    return None


class InstanceLock:
    """Замок папки данных (см. описание модуля). acquire() – до открытия базы, check() – перед записью,
    revoke() и release() – при остановке."""

    def __init__(self, data_dir: Path, beat: float = BEAT_S, stale: float = STALE_S) -> None:
        self.path = Path(data_dir) / LOCK_NAME
        self.change = Path(data_dir) / CHANGE_NAME
        self.beat = beat
        self.stale = stale
        self.token = uuid.uuid4().hex
        self.host = socket.gethostname()
        self.pid = os.getpid()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lost = False
        self._revoked = False
        self._beat_at = 0.0  # когда этот экземпляр последний раз записал свою отметку (time.time())
        # метку смены внутри экземпляра берёт один поток (отметка и проверка перед записью идут из разных потоков), и у
        # каждого захвата своя метка: своя метка – только та, что создана этим захватом (ревью сборки А, Д4)
        self._change_guard = threading.Lock()
        self._capture: str | None = None

    # ---------------------------------------------------------------- метка смены

    @contextmanager
    def _changing(self) -> Iterator[None]:
        """Право проверить и поменять файл замка: своя метка смены. Пока метка чужая – ждать, брошенную – снять
        (_clear_abandoned_change). Не получили метку за CHANGE_WAIT_S – TimeoutError. Удаляется метка, только если она
        своя."""
        deadline = time.monotonic() + CHANGE_WAIT_S
        if not self._change_guard.acquire(timeout=CHANGE_WAIT_S):
            raise TimeoutError("метку смены держит другой поток этого экземпляра")
        try:
            while True:
                # пока метка есть, новая не создаётся: без лишних временных файлов на каждом шаге ожидания
                if not os.path.lexists(self.change) and self._create_change():
                    break
                if self._clear_abandoned_change():
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError("метка смены замка занята")
                time.sleep(0.02)
            try:
                yield
            finally:
                self._drop_change()
        finally:
            self._change_guard.release()

    def _create_change(self) -> bool:
        """Создаёт метку смены сразу с содержимым (бэклог 132): временный файл, fsync, затем жёсткая ссылка под именем
        метки – создание без замены существующей. Файловая система без жёстких ссылок – создание с O_EXCL и запись
        (метка на миг пуста; пустую понимают все версии). True – метка своя; False – метка уже есть или её как раз
        удаляют (Windows отвечает на это PermissionError). Временный файл не создался – OSError наружу: это нет
        доступа к папке, а не «метка занята»."""
        self._capture = uuid.uuid4().hex
        body = json.dumps({"token": self._capture, "owner": self.token, "host": self.host, "pid": self.pid,
                           "created": time.time()})
        tmp = self.change.with_name(f"{CHANGE_NAME}.{self.token}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            try:
                os.link(tmp, self.change)
                return True
            except FileExistsError:
                return False
            except OSError:
                pass  # жёстких ссылок здесь нет (FAT, часть томов) или метку сейчас удаляют – решит O_EXCL
            try:
                fd = os.open(self.change, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
            except (FileExistsError, PermissionError):
                return False
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            return True
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _take_marker(self, accept: Callable[[str, os.stat_result], bool]) -> bool:
        """Снимает метку смены, только если это та метка, которую решено снять: перенос в свой файл (атомарно), сверка
        перенесённого (accept), затем удаление. Перенесена не та – она возвращается под прежнее имя без замены новой.
        Остаётся узкое окно: пока чужая метка перенесена, её имя свободно, и если ровно в этот миг его займёт третий
        экземпляр, вернуть метку не удастся. Замок папки – защита от ошибки, а не гарантия; второй экземпляр на той же
        базе останавливает замок базы (ADR-0009, ADR-0155). True – метка снята."""
        # своё имя на каждую попытку: сохранённая после неудачного возврата копия не затирается следующей (ревью круга 4)
        aside = self.change.with_name(f"{CHANGE_NAME}.{self.token}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.aside")
        try:
            _retrying(lambda: os.rename(self.change, aside))
        except OSError:
            return False  # метки нет, её уже перенёс другой или её держат открытой (Windows)
        try:
            ok = accept(aside.read_bytes().decode("utf-8", "replace"), os.stat(aside))
        except OSError:
            ok = False
        if not ok and not self._put_back(aside):
            # вернуть не удалось: перенесённая метка остаётся в своём файле – её не удалять, это единственная копия
            log.warning("метка смены замка папки данных не возвращена, она сохранена в %s", aside.name)
            return False
        try:
            _retrying(lambda: os.unlink(aside))
        except OSError:
            pass
        return ok

    def _put_back(self, aside: Path) -> bool:
        """Вернуть ошибочно перенесённую метку без замены новой: жёсткая ссылка, а без жёстких ссылок – создание с O_EXCL
        и прежнее содержимое (Д4, ревью сборки А). True – метка на месте; False – имя занято или вернуть не удалось."""
        try:
            os.link(aside, self.change)
            return True
        except FileExistsError:
            return False
        except OSError:
            pass  # жёстких ссылок здесь нет
        try:
            data = aside.read_bytes()
            fd = _retrying(lambda: os.open(self.change, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644))
        except OSError:
            return False
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return True

    def _still_mine(self) -> bool:
        """Метка смены всё ещё этого захвата: перечитывается перед каждым разрушительным шагом под ней. Экземпляр,
        простоявший в критической секции дольше CHANGE_STALE_S, мог лишиться метки – тогда он ничего не трогает
        (ревью сборки А, круг 3, Д4). Остаётся окно в один системный вызов между проверкой и действием."""
        try:
            return bool(self._capture) and _marker_fields(self.change.read_bytes().decode("utf-8", "replace")).get("token") == self._capture
        except OSError:
            return False

    def _drop_change(self) -> None:
        """Удаляет свою метку смены; чужую (её могли создать, пока этот экземпляр стоял дольше CHANGE_STALE_S) не
        трогает: сверка – уже после переноса, а не до удаления."""
        capture, self._capture = self._capture, None
        if capture:
            self._take_marker(lambda raw, _st: _marker_fields(raw).get("token") == capture)

    def _lock_state(self) -> str:
        """Файл замка для решения о брошенной метке смены: absent – нет; empty – пуст; stale – отметка старше stale
        (повреждённый файл – по времени изменения, как в _busy); own – замок этого экземпляра; fresh – живой чужой;
        unknown – не прочитался."""
        try:
            raw = self.path.read_bytes().decode("utf-8", "replace")
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unknown"
        if not raw.strip():
            return "empty"
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if isinstance(data, dict):
            if data.get("token") == self.token:
                return "own"
            try:
                beat = float(data.get("beat") or 0)
            except (TypeError, ValueError):
                beat = 0.0
        else:
            beat = mtime
        return "stale" if time.time() - beat >= self.stale else "fresh"

    def _clear_abandoned_change(self) -> bool:
        """Снимает брошенную метку смены (бэклог 132 и 43): метке больше CHANGE_STALE_S, а замок отсутствует, пуст,
        устарел или принадлежит этому экземпляру. Возраст – меньший из возраста по времени файла и по полю created:
        расхождение часов процессов не должно снять живую метку. Метка переносится в свой файл, и удаляется, только
        если перенесена та самая метка; иначе (её успели снять и создать заново) возвращается на место. True – снята."""
        try:
            seen = os.stat(self.change)
        except OSError:
            return False
        now = time.time()
        if now - seen.st_mtime < CHANGE_STALE_S:  # свежая: содержимое не читается, владельцу не мешаем
            return False
        try:
            raw = self.change.read_bytes().decode("utf-8", "replace")
        except OSError:
            return False
        age = now - seen.st_mtime
        created = _marker_fields(raw).get("created")
        if isinstance(created, (int, float)) and not isinstance(created, bool):
            age = min(age, now - float(created))
        if age < CHANGE_STALE_S:
            return False
        state = self._lock_state()
        if state not in ("absent", "empty", "stale", "own"):
            return False
        def same(moved_raw: str, moved: os.stat_result) -> bool:
            return moved_raw == raw and moved.st_size == seen.st_size and moved.st_mtime_ns == seen.st_mtime_ns

        if not self._take_marker(same):
            return False
        log.warning("брошенная метка смены замка папки данных снята: ей %d с, файл замка – %s", int(age), state)
        return True

    def _change_busy(self) -> LockBusy:
        """Метку смены не получить за CHANGE_WAIT_S: её держит другой экземпляр, либо она брошена, а замок ещё свежий."""
        busy = self._busy()
        if busy is not None:
            return busy
        return LockBusy(f"Замок папки данных {self.path.parent} сейчас меняет другой экземпляр приложения. Повторите "
                        "запуск через несколько секунд.")

    # ---------------------------------------------------------------- файл замка

    def _content(self) -> str:
        return json.dumps({"host": self.host, "pid": self.pid, "token": self.token, "beat": time.time()})

    def _write(self) -> None:
        """Записать свою отметку: временный файл и атомарная замена (читающий видит старое или новое целиком)."""
        tmp = self.path.with_name(f"{LOCK_NAME}.{self.token}.tmp")
        tmp.write_text(self._content(), encoding="utf-8")
        _retrying(lambda: os.replace(tmp, self.path))  # в Windows замену не даёт сделать читающий в этот миг процесс
        self._beat_at = time.time()

    def _owned(self) -> bool:
        return self._owner() == "own"

    def _owner(self) -> str:
        """own – файл замка наш; foreign – прочитан и в нём чужая метка запуска (папку забрали); missing – файла нет и
        при повторных чтениях (его удалили); unknown – файл не прочитался (не целиком, повреждён, папка недоступна):
        кто держит папку, сейчас не установить."""
        current = _read(self.path)
        token = current.get("token") if current is not None else None
        if not isinstance(token, str) or not token:
            try:
                gone = current is None and not self.path.exists()
            except OSError:  # нет доступа к папке – владельца не установить, это не удаление файла
                gone = False
            if gone:
                return "missing"  # _read уже переспросил: короткий миг без файла при замене сюда обычно не попадает
            return "unknown"  # файл не прочитался или метки запуска в нём нет – это не доказательство захвата
        return "own" if token == self.token else "foreign"

    def _restore(self) -> bool:
        """Файл замка удалён, а папку держал этот экземпляр (Э4): создать файл заново, только если его всё ещё нет и
        своя последняя отметка свежая. Вызывается под меткой смены: если папку за это время взял другой экземпляр,
        файл уже есть и чужой. Отметка старше половины stale – этот экземпляр мог спать, другой мог забрать папку,
        поработать и при остановке удалить свой замок: восстановления нет, замок потерян (записи прекращаются)."""
        if not self._still_mine():
            return False  # метку смены сняли, пока этот экземпляр стоял: файл замка не трогается
        if time.time() - self._beat_at >= self.stale / 2:
            self._lost = True
            log.error("файл замка папки данных удалён, а своя отметка устарела: записи в базу остановлены")
            return False
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self._content())
        self._beat_at = time.time()
        log.warning("файл замка папки данных был удалён – восстановлен этим экземпляром")
        return True

    def _busy(self) -> LockBusy | None:
        """Замок держит живой экземпляр – ошибка для показа; держателя нет или он не обновлял отметку дольше
        stale – None."""
        current = _read(self.path)
        try:
            beat = float(current.get("beat") or 0) if current is not None else None
        except (TypeError, ValueError):
            beat = None  # нечисловая отметка – как повреждённый файл (ревью круга 10)
            current = None
        if current is not None:
            age = time.time() - beat
        else:  # файл испорчен: судим по времени его изменения
            try:
                age = time.time() - self.path.stat().st_mtime
            except FileNotFoundError:
                return None
        if age >= self.stale:
            return None
        who = current or {}
        if _stand_npm():  # учебный стенд (ADR-0155): второго держателя не даёт служебный порт стенда
            what = (f"Если прежний процесс приложения стенда завершился аварийно, стенд повторит запуск сам, когда его "
                    f"отметка устареет (через {int(self.stale)} с).")
        else:
            what = ("Остановите его (docker compose down) или укажите другую папку DATA_DIR. Если он уже остановлен "
                    f"аварийно, повторите запуск через {int(self.stale)} с.")
        return LockBusy(
            f"Папку данных {self.path.parent} уже использует другой запущенный экземпляр приложения "
            f"(машина {who.get('host') or 'неизвестна'}, процесс {who.get('pid') or '?'}). Два экземпляра на одной "
            "базе теряют записи друг друга. " + what)

    # ---------------------------------------------------------------- захват, отметка, отпускание

    def acquire(self) -> None:
        """Берёт замок или бросает LockBusy с текстом по-русски."""
        try:
            with self._changing():
                busy = self._busy()
                if busy is not None:
                    raise busy
                if not self._still_mine():
                    raise self._change_busy()
                if os.path.lexists(self.path):
                    try:
                        _retrying(self.path.unlink)  # замок упавшего держателя
                    except FileNotFoundError:
                        pass
                    if not self._still_mine():
                        raise self._change_busy()
                try:
                    fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
                except FileExistsError:  # замок успел создать другой экземпляр
                    raise self._busy() or self._change_busy() from None
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(self._content())
                self._beat_at = time.time()
        except TimeoutError:
            raise self._change_busy() from None
        self._thread = threading.Thread(target=self._beat, name="data-dir-lock", daemon=True)
        self._thread.start()

    def _beat(self) -> None:
        while not self._stop.wait(self.beat):
            try:
                with self._changing():
                    if self._stop.is_set():
                        return
                    owner = self._owner()
                    if owner == "foreign":
                        self._lost = True
                        log.error("замок папки данных забрал другой экземпляр приложения: записи в базу остановлены")
                        return
                    if owner == "own" and self._still_mine():
                        self._write()
                    elif owner == "missing" and not self._restore() and self._lost:
                        return  # своя отметка устарела – замок потерян, отметки больше не пишутся
                    # unknown: файл не прочитался – отметка не обновляется (свой ли это замок, не доказано) и
                    # отслеживание не прекращается: следующая отметка через BEAT_S
            except (OSError, TimeoutError):
                pass  # папка недоступна на миг – отметка обновится в следующий раз

    def check(self) -> None:
        """Перед записью в базу: замок всё ещё наш (файл перечитывается каждый раз). Иначе – LockLost."""
        if self._revoked:
            raise LockLost("Приложение останавливается: запись в базу уже не выполняется.")
        if self._lost:
            raise LockLost(LOST_TEXT)
        if self._owned():
            return
        # файл замка мог на миг не прочитаться (через том Docker Desktop его замена видна как миг без файла):
        # повторная проверка под меткой смены, когда отметку никто не меняет
        try:
            with self._changing():
                owner = self._owner()
                if owner == "missing" and self._restore():  # удалённый файл замка – самовосстановление (Э4)
                    owner = "own"
        except TimeoutError:
            owner = self._owner()
        except OSError:  # метку смены не создать (нет доступа на миг): чужой захват этим не доказан
            owner = "unknown"
        if owner == "own":
            return
        if self._lost:  # файл удалён, а своя отметка устарела (_restore): папку могли забрать – записи прекращаются
            raise LockLost(LOST_TEXT)
        if owner == "foreign":  # чужая метка прочитана дважды – папку забрали: записи прекращаются насовсем
            self._lost = True
            raise LockLost(LOST_TEXT)
        raise LockUnsure(UNSURE_TEXT)  # владельца не установить: эту запись не выполнять, следующие – проверять

    def revoke(self) -> None:
        """Запретить записи этого экземпляра (перед остановкой): дальше check() бросает LockLost."""
        self._revoked = True

    def release(self) -> None:
        """Отпускает замок, если он ещё наш."""
        self._revoked = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=CHANGE_WAIT_S + 1)
        try:
            with self._changing():
                if self._owned() and self._still_mine():
                    _retrying(self.path.unlink)
        except (OSError, TimeoutError):
            pass
