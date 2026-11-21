"""Каталог открытых учебных примеров (ADR-0156, план стенда, раздел 4.4).

Каталог – examples/catalog/catalog.json в приложении: адрес и полный коммит каждого примера, хеш дерева, лимиты
распаковки, выгрузка формата Hub без строк кода. Исходники скачиваются с codeload.github.com по коммиту в
`<корень папок с репозиториями>/examples/<id>-<commit7>/`; после распаковки и сверки хеша папка принадлежит студенту:
стенд её не меняет, не чинит и не удаляет. «Скачать заново» распаковывает рядом в новую папку с суффиксом.

Командная строка (Docker-установка, где корень клонов подключён только для чтения):
    python -m app.examples fetch <id> [<id> ...] --repos-root <корень клонов>
    python -m app.examples fetch --all --repos-root <корень клонов>
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any

from .example_tree import MARKER, tree_hash_of_dir

log = logging.getLogger(__name__)

APP_ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = APP_ROOT / "examples" / "catalog"
CATALOG_FILE = CATALOG_DIR / "catalog.json"
EXAMPLES_FOLDER = "examples"  # папка проекта у проектов из каталога – внутри корня папок с репозиториями
HOST = "codeload.github.com"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
CHUNK = 64 * 1024
FETCH_SECONDS = 120.0
MAX_FILES_ANY = 100_000
MAX_BYTES_ANY = 1024 ** 3
MAX_MEMBERS_ANY = 150_000
_ARCHIVE_PATH = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/tar\.gz/([0-9a-f]{40})$")
_WINDOWS_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')
_WINDOWS_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}

_FETCH_LOCK = threading.Lock()  # одно скачивание за раз
# корень примеров этого процесса после успешной сверки отметок при запуске (routes.examples.revoke_marks_on_root_change):
# допуск внешней отправки проекта из каталога сверяет с ним корень согласия; не сверено – отправки нет (ADR-0157)
ROOT_NOW: dict[str, str | None] = {"value": None}
UNPACK_JOURNAL = ".local-triage-unpacking.json"  # временные папки распаковки, созданные этим модулем
_STATE_LOCK = threading.Lock()
_STATE: dict[str, dict[str, Any]] = {}  # id -> {"phase": "queued|fetching|failed", "message": str}


class ExampleError(Exception):
    """Ошибка по-русски для показа на странице и в командной строке."""


# ============================================================================ каталог

def load_catalog(path: Path | None = None) -> dict:
    """Каталог; файла нет (сборка без каталога) – пустой каталог."""
    path = CATALOG_FILE if path is None else path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": 1, "examples": []}
    except (OSError, ValueError) as e:  # оборванный или нечитаемый каталог: приложение работает, причина – на странице
        raise ExampleError(f"Каталог примеров не читается ({e.__class__.__name__}): переустановите стенд.") from None
    if not isinstance(data, dict) or not isinstance(data.get("examples"), list):
        raise ExampleError("Каталог примеров повреждён: нет списка examples.")
    for item in data["examples"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("codebases"), list):
            raise ExampleError("Каталог примеров повреждён: запись без id или кодовых баз – переустановите стенд.")
        src, exp = item.get("source"), item.get("export")
        if src is None and item.get("builtin") != "demo":
            raise ExampleError(f"Каталог примеров повреждён: у записи {item['id']} нет источника.")
        if src is not None:
            if not (isinstance(src, dict) and isinstance(exp, dict)):
                raise ExampleError(f"Каталог примеров повреждён: у записи {item['id']} нет источника или выгрузки.")
            need = ("commit", "tree_sha256", "files", "unpacked_bytes", "archive_url", "repo_url")
            if any(k not in src for k in need) or any(k not in exp for k in ("file", "sha256")) or \
                    not re.fullmatch(r"[0-9a-f]{40}", str(src.get("commit"))):
                raise ExampleError(f"Каталог примеров повреждён: у записи {item['id']} неполный источник или выгрузка.")
    return data


def entry_of(catalog: dict, example_id: str) -> dict:
    for entry in catalog.get("examples") or []:
        if entry.get("id") == example_id:
            return entry
    raise ExampleError(f"Примера «{example_id}» нет в каталоге.")


def is_downloadable(entry: dict) -> bool:
    return bool(entry.get("source")) and not entry.get("builtin")


def folder_name(entry: dict, suffix: int = 1) -> str:
    base = f"{entry['id']}-{entry['source']['commit'][:7]}"
    return base if suffix == 1 else f"{base}-{suffix}"


def examples_root(repos_root: Path) -> Path:
    return repos_root / EXAMPLES_FOLDER


def read_marker(folder: Path) -> dict | None:
    try:
        data = json.loads((folder / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def downloaded_folders(entry: dict, repos_root: Path) -> list[Path]:
    """Распакованные и сверенные копии примера (по маркеру), первая – основная."""
    root = examples_root(repos_root)
    base = folder_name(entry)
    pattern = re.compile(re.escape(base) + r"(?:-([2-9]|[1-9][0-9]+))?")
    candidates = []
    try:
        names = [p.name for p in root.iterdir() if p.is_dir() and pattern.fullmatch(p.name)]
    except OSError:
        names = []
    for name in names:
        m = pattern.fullmatch(name)
        candidates.append((int(m.group(1) or 1) if m else 1, root / name))
    found = []
    for _, folder in sorted(candidates):
        marker = read_marker(folder)
        if marker and marker.get("id") == entry["id"] and marker.get("commit") == entry["source"]["commit"]:
            found.append(folder)
    return found


def status(entry: dict, repos_root: Path) -> dict:
    """Состояние карточки: downloaded, fetching, queued, failed, missing (и builtin у Demo Library)."""
    if not is_downloadable(entry):
        return {"phase": "builtin", "folders": []}
    folders = downloaded_folders(entry, repos_root)
    with _STATE_LOCK:
        current = dict(_STATE.get(entry["id"]) or {})
    if current.get("phase") in ("queued", "fetching"):
        return {"phase": current["phase"], "folders": folders, "message": current.get("message", "")}
    if folders:
        return {"phase": "downloaded", "folders": folders, "fresh": current.get("phase") == "done"}
    if current.get("phase") == "failed":
        return {"phase": "failed", "folders": [], "message": current.get("message", "")}
    return {"phase": "missing", "folders": []}


def _set_state(example_id: str, phase: str | None, message: str = "") -> None:
    with _STATE_LOCK:
        if phase is None:
            _STATE.pop(example_id, None)
        else:
            _STATE[example_id] = {"phase": phase, "message": message}


# ============================================================================ запас длины пути

def long_paths_enabled() -> bool:
    if os.name != "nt":
        return True
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as key:
            return int(winreg.QueryValueEx(key, "LongPathsEnabled")[0]) == 1
    except OSError:
        return False


TEMP_PREFIX = ".lt-"
TEMP_SUFFIX_LEN = 8  # tempfile.mkdtemp: 8 случайных знаков


def path_room_ok(base_len: int, rel_len: int, is_dir: bool) -> bool:
    return base_len + 1 + rel_len <= (247 if is_dir else 259)


def check_path_room(target: Path, entry: dict) -> None:
    """Канонический путь папки дерева и временной папки распаковки плюс самый длинный путь файла укладывается в 259
    знаков, самой длинной папки – в 247, если в Windows не включены длинные пути."""
    if os.name != "nt" or long_paths_enabled():
        return
    src = entry["source"]
    longest = int(src.get("max_relpath") or 0)
    longest_dir = int(src.get("max_dirpath") or max(0, longest - 2))
    temp_len = len(str(target.parent.resolve())) + 1 + len(TEMP_PREFIX) + TEMP_SUFFIX_LEN
    base = max(len(str(target.resolve())), temp_len)
    if not path_room_ok(base, longest, False) or not path_room_ok(base, longest_dir, True):
        raise ExampleError(
            f"Путь {target} слишком длинный для файлов примера: самый длинный путь внутри – {longest} знаков, в сумме "
            f"{base + 1 + longest} при пределе Windows 259. Запустите стенд с коротким --code-dir (например C:\\lt) или "
            "включите длинные пути Windows (LongPathsEnabled).")


# ============================================================================ скачивание

def archive_url_ok(entry: dict) -> tuple[str, str]:
    """(хост, путь) адреса архива из каталога; иначе ExampleError."""
    url = str(entry["source"].get("archive_url") or "")
    prefix = f"https://{HOST}"
    if not url.startswith(prefix + "/"):
        raise ExampleError(f"Адрес архива примера {entry['id']} – не {HOST}: скачивание не выполняется.")
    path = url[len(prefix):]
    m = _ARCHIVE_PATH.fullmatch(path)
    if not m or m.group(3) != entry["source"]["commit"]:
        raise ExampleError(f"Адрес архива примера {entry['id']} не совпадает с форматом /<владелец>/<репо>/tar.gz/<коммит>.")
    return HOST, path


def _connection(host: str, deadline: float):
    """Соединение HTTPS только с глобальными адресами имени (точка подмены в тестах)."""
    from . import llm_net

    entries = llm_net._getaddrinfo(host, 443, max(0.1, deadline - time.monotonic()), trust="external")
    entries = llm_net._external_entries(host, entries, llm_net.host_networks([]))
    watchdog = llm_net._Watchdog(deadline)
    return llm_net._PinnedHTTPSConnection(host, 443, entries, deadline, watchdog), watchdog


def fetch_archive(entry: dict, tmp_dir: Path, connect=None) -> Path:
    """Потоковый GET архива во временный файл в tmp_dir: только 200, предел 64 МБ, срок 120 с."""
    host, path = archive_url_ok(entry)
    deadline = time.monotonic() + FETCH_SECONDS
    try:
        conn, watchdog = (connect or _connection)(host, deadline)
    except Exception as e:  # noqa: BLE001 – причина сети в понятном сообщении
        raise ExampleError(f"Не удалось соединиться с {host}: {e}") from None
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="example-", suffix=".tar.gz", dir=tmp_dir)
    target = Path(name)
    try:
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": "local-triage-examples",
                                               "Accept-Encoding": "identity"})
            response = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            raise ExampleError(f"Скачивание {entry['id']} прервано: {e.__class__.__name__}") from None
        if response.status != 200:
            raise ExampleError(f"{host} ответил {response.status} на запрос архива {entry['id']}: скачивание отменено "
                               "(перенаправления не принимаются).")
        length = response.getheader("Content-Length")
        if length and length.isdigit() and int(length) > MAX_ARCHIVE_BYTES:
            raise ExampleError(f"Архив {entry['id']} больше {MAX_ARCHIVE_BYTES // 2**20} МБ – отказ.")
        size = 0
        with os.fdopen(fd, "wb") as out:
            fd = -1
            while True:
                if time.monotonic() > deadline:
                    raise ExampleError(f"Скачивание {entry['id']} не уложилось в {int(FETCH_SECONDS)} с.")
                try:
                    chunk = response.read1(CHUNK)
                except (OSError, http.client.HTTPException) as e:
                    raise ExampleError(f"Скачивание {entry['id']} прервано: {e.__class__.__name__}") from None
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise ExampleError(f"Архив {entry['id']} больше {MAX_ARCHIVE_BYTES // 2**20} МБ – отказ.")
                out.write(chunk)
        return target
    except BaseException:
        if fd != -1:
            os.close(fd)
        target.unlink(missing_ok=True)
        raise
    finally:
        try:
            watchdog.cancel()
            conn.close()
        except Exception:  # noqa: BLE001
            pass


# ============================================================================ распаковка

class _CountingInfo(tarfile.TarInfo):
    """Каждый прочитанный заголовок TAR – и служебные (PAX локальный и глобальный, длинные имена GNU), которые tarfile
    разбирает до выдачи элемента, – считается записью; предел – у объекта архива (_lt_limit)."""

    @classmethod
    def fromtarfile(cls, tarfile_obj):  # noqa: ANN001,ANN206 – сигнатура tarfile
        info = super().fromtarfile(tarfile_obj)  # конец архива – исключение, записью не считается
        count = getattr(tarfile_obj, "_lt_headers", 0) + 1
        tarfile_obj._lt_headers = count
        if count > getattr(tarfile_obj, "_lt_limit", MAX_MEMBERS_ANY):
            raise ExampleError("В архиве больше элементов, чем заявлено в каталоге – отказ.")
        return info


class _Counter:
    """Поток gzip через счётчик распакованных байт с пределом."""

    def __init__(self, raw, limit: int) -> None:
        self.raw, self.limit, self.count = raw, limit, 0

    def read(self, size: int = -1) -> bytes:
        data = self.raw.read(size)
        self.count += len(data)
        if self.count > self.limit:
            raise ExampleError("Распакованный архив больше заявленного в каталоге – отказ.")
        return data


def _name_ok(rel: str) -> bool:
    for part in rel.split("/"):
        if not part or part in (".", "..") or _WINDOWS_BAD.search(part) or part.endswith((" ", ".")):
            return False
        if part.split(".")[0].upper() in _WINDOWS_NAMES:
            return False
    return True


def unpack(archive: Path, entry: dict, target: Path) -> Path:
    """Распаковка архива в target через временную папку рядом: проверки состава, сверка хеша, маркер, переименование."""
    src = entry["source"]
    files_limit = min(int(src["files"]), MAX_FILES_ANY)
    bytes_limit = min(int(src["unpacked_bytes"]), MAX_BYTES_ANY)
    members_limit = min(int(src["files"]) + 50_000, MAX_MEMBERS_ANY)
    # предел распакованного потока: точный размер TAR из каталога плюс 1 МиБ (служебные записи TAR – длинные имена и
    # pax-заголовки – тоже идут через счётчик); у прежней записи каталога – объём файлов плюс 10 %
    stream_limit = (int(src["tar_bytes"]) if src.get("tar_bytes") else int(bytes_limit * 1.1)) + 1024 * 1024
    if target.exists():
        raise ExampleError(f"Папка {target} уже есть: стенд не трогает папки примеров.")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=target.parent))
    _journal(target.parent, add=tmp.name)  # очистка после сбоя удаляет только папки из журнала
    tmp_real = os.path.realpath(tmp)
    check_room = os.name == "nt" and not long_paths_enabled()
    try:
        with open(archive, "rb") as raw, gzip.GzipFile(fileobj=raw) as gz:
            stream = _Counter(gz, min(stream_limit, MAX_BYTES_ANY + 64 * 1024 * 1024))
            with tarfile.open(fileobj=stream, mode="r|", tarinfo=_CountingInfo) as tar:
                tar._lt_limit = members_limit  # type: ignore[attr-defined]
                seen: set[str] = set()
                files = total = 0
                root_name: str | None = None
                for member in tar:
                    if member.name.startswith("/") or "\\" in member.name:
                        raise ExampleError(f"Недопустимое имя в архиве: {member.name[:120]}")
                    parts = member.name.split("/", 1)
                    if root_name is None:  # первая запись – общий корень архива (каталог), он срезается
                        if not member.isdir() or len(parts) > 1 and parts[1].strip("/"):
                            raise ExampleError("Архив не того вида: первая запись – не общая папка исходников.")
                        root_name = parts[0]
                        continue
                    if parts[0] != root_name or len(parts) < 2 or not parts[1].strip("/"):
                        raise ExampleError(f"Запись вне общей папки архива: {member.name[:120]} – отказ.")
                    rel = parts[1].rstrip("/")
                    if not _name_ok(rel):
                        raise ExampleError(f"Недопустимое имя в архиве: {rel[:120]}")
                    dest = os.path.realpath(os.path.join(tmp_real, *rel.split("/")))
                    if os.path.commonpath([tmp_real, dest]) != tmp_real or dest == tmp_real:
                        raise ExampleError(f"Путь в архиве выходит за папку распаковки: {rel[:120]}")
                    if check_room and not path_room_ok(len(tmp_real), len(rel), member.isdir()):
                        raise ExampleError(f"Путь {rel[:120]} не помещается в предел длины пути Windows: запустите "
                                           "стенд с коротким --code-dir или включите длинные пути Windows.")
                    if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                        raise ExampleError(f"В архиве ссылка или особый файл: {rel[:120]} – отказ.")
                    key = unicodedata.normalize("NFC", rel).casefold()
                    if key in seen:
                        raise ExampleError(f"Имена в архиве совпадают без учёта регистра: {rel[:120]} – отказ.")
                    seen.add(key)
                    if member.isdir():
                        member.name = rel
                        tar.extract(member, tmp, filter="data")
                        continue
                    files += 1
                    total += member.size
                    if files > files_limit or total > bytes_limit:
                        raise ExampleError("В архиве больше файлов или байт, чем заявлено в каталоге – отказ.")
                    member.name = rel
                    tar.extract(member, tmp, filter="data")
        digest, n, size, _ = tree_hash_of_dir(tmp)
        if digest != src["tree_sha256"] or n != int(src["files"]) or size != int(src["unpacked_bytes"]):
            raise ExampleError(f"Хеш дерева {entry['id']} не совпал с каталогом: архив повреждён или подменён.")
        (tmp / MARKER).write_text(json.dumps({"id": entry["id"], "commit": src["commit"], "tree_sha256": digest,
                                              "license": src.get("license", ""), "repo_url": src.get("repo_url", ""),
                                              "lines": verified_lines(entry, tmp)},
                                             ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        tmp.rename(target)
        _journal(target.parent, remove=tmp.name)
        return target
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        if not tmp.exists():
            _journal(target.parent, remove=tmp.name)
        raise


def _journal(root: Path, add: str = "", remove: str = "") -> list[str]:
    """Журнал временных папок распаковки в папке примеров: по нему после обрыва удаляются только свои папки."""
    path = root / UNPACK_JOURNAL
    try:
        names = [n for n in json.loads(path.read_text(encoding="utf-8")) if isinstance(n, str)]
    except (OSError, ValueError):
        names = []
    if add and add not in names:
        names.append(add)
    if remove:
        names = [n for n in names if n != remove]
    if add or remove:
        try:
            if names:
                path.write_text(json.dumps(names), encoding="utf-8")
            else:
                path.unlink(missing_ok=True)  # пустой журнал не остаётся в папке примеров
        except OSError:
            pass
    return names


def download(entry: dict, repos_root: Path, tmp_dir: Path, again: bool = False, connect=None) -> Path:
    """Скачать и распаковать пример; уже скачан и again=False – прежняя папка. again – новая папка с суффиксом."""
    if not is_downloadable(entry):
        raise ExampleError(f"Пример {entry['id']} поставляется с приложением и не скачивается.")
    existing = downloaded_folders(entry, repos_root)
    if existing and not again:
        return existing[0]
    root = examples_root(repos_root)
    suffix = 1
    while (root / folder_name(entry, suffix)).exists():
        suffix += 1
    target = root / folder_name(entry, suffix)
    with _FETCH_LOCK:
        _set_state(entry["id"], "fetching", "скачивается")
        try:
            check_path_room(target, entry)
            archive = fetch_archive(entry, tmp_dir, connect)
            try:
                result = unpack(archive, entry, target)
            finally:
                archive.unlink(missing_ok=True)
        except ExampleError as e:
            _set_state(entry["id"], "failed", str(e))
            raise
        except Exception as e:  # noqa: BLE001
            _set_state(entry["id"], "failed", f"не удалось скачать: {e.__class__.__name__}")
            raise ExampleError(f"Не удалось скачать {entry['id']}: {e.__class__.__name__}") from None
        _set_state(entry["id"], "done", "скачан в этом запуске")
        return result


def fetch_all_background(repos_root: Path, tmp_dir: Path) -> threading.Thread:
    """Фоновое скачивание всех недостающих примеров по одному; неудача одного не мешает остальным."""
    catalog = load_catalog()
    root = examples_root(repos_root)
    for name in _journal(root):  # только временные папки, которые записал в журнал распаковщик (прошлый запуск оборвался)
        stale = root / name
        if name.startswith(TEMP_PREFIX) and stale.is_dir() and not stale.is_symlink():
            shutil.rmtree(stale, ignore_errors=True)
        if not stale.exists():  # занятый файл Windows – папка останется в журнале до следующего запуска
            _journal(root, remove=name)
    todo = [e for e in catalog["examples"] if is_downloadable(e) and not downloaded_folders(e, repos_root)]
    for e in todo:
        _set_state(e["id"], "queued", "в очереди на скачивание")

    def work() -> None:
        for e in todo:
            try:
                download(e, repos_root, tmp_dir)
                log.info("пример %s скачан", e["id"])
            except ExampleError as err:
                log.warning("пример %s не скачан: %s", e["id"], err)

    thread = threading.Thread(target=work, name="examples-fetch", daemon=True)
    thread.start()
    return thread


# ============================================================================ выгрузка с кодом

def export_path(entry: dict) -> Path:
    return CATALOG_DIR / entry["export"]["file"]


def check_export(entry: dict) -> Path:
    import hashlib

    path = export_path(entry)
    try:
        data = path.read_bytes()
    except OSError:
        raise ExampleError(f"Выгрузки примера {entry['id']} нет в установке: переустановите стенд.") from None
    if hashlib.sha256(data).hexdigest() != entry["export"]["sha256"]:
        raise ExampleError(f"Выгрузка примера {entry['id']} не совпала с каталогом по SHA-256.")
    return path


_XLSX_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _sast_rows(entry: dict) -> list[tuple[str, str, int]]:
    """(кодовая база, файл, строка) находок SAST выгрузки примера."""
    import openpyxl

    wb = openpyxl.load_workbook(check_export(entry), read_only=True)
    try:
        if "SAST" not in wb.sheetnames:
            return []
        rows = wb["SAST"].iter_rows(values_only=True)
        header = [str(x or "") for x in next(rows)]
        col = {name: i for i, name in enumerate(header)}
        out = []
        for row in rows:
            line = str(row[col["Line number"]] or "")
            out.append((str(row[col["Codebase"]] or ""), str(row[col["File"]] or ""), int(line) if line.isdigit() else 0))
        return out
    finally:
        wb.close()


def verified_lines(entry: dict, tree: Path) -> dict[str, str]:
    """Строки находок SAST из распакованного и сверенного по хешу дерева – до того, как папка перейдёт студенту:
    {"<кодовая база>/<файл>:<строка>": строка}. Выгрузки в установке нет – пусто."""
    try:
        rows = _sast_rows(entry)
    except ExampleError:
        return {}
    paths = {cb["name"]: cb["path"] for cb in entry["codebases"]}
    cache: dict[Path, list[str] | None] = {}
    out = {}
    for codebase, file, n in rows:
        target = (tree / paths[codebase] if paths.get(codebase) else tree) / file
        if target not in cache:
            try:
                cache[target] = None if target.is_symlink() else \
                    target.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                cache[target] = None
        lines = cache[target]
        if lines is not None and 0 < n <= len(lines):
            out[f"{codebase}/{file}:{n}"] = lines[n - 1].strip()
    return out


def filled_export(entry: dict, tree: Path, tmp_dir: Path) -> tuple[Path, list[str]]:
    """Копия выгрузки во tmp_dir с заполненным Source code: строка из проверенного дерева (маркер), служебный хвост
    « : <строка>», явно текстом. (путь копии, предупреждения). Строка длиннее предела импорта или с недопустимыми для
    XLSX знаками остаётся «-»."""
    import openpyxl

    from .hub_import import MAX_SNIPPET_CHARS

    marker = read_marker(tree) or {}
    lines = marker.get("lines")
    if not isinstance(lines, dict):
        # копия скачана прежней версией стенда: строки из рабочей папки (её мог править студент) не берутся
        raise ExampleError("Эта копия примера скачана прежней версией стенда: нажмите «Скачать заново» и создайте "
                           f"проект из новой копии (в Docker-установке – на компьютере: python -m app.examples fetch "
                           f"{entry['id']} --again --repos-root <корень клонов>).")
    wb = openpyxl.load_workbook(check_export(entry))
    warnings: list[str] = []
    if "SAST" in wb.sheetnames:
        ws = wb["SAST"]
        header = [c.value for c in ws[1]]
        col = {name: i for i, name in enumerate(header)}
        for row in ws.iter_rows(min_row=2):
            file, line, codebase = (row[col["File"]].value, row[col["Line number"]].value, row[col["Codebase"]].value)
            code = lines.get(f"{codebase}/{file}:{line}")
            if code is None:
                warnings.append(f"{codebase}/{file}:{line} – файла или строки нет в папке примера")
                continue
            value = f"{code} : {line}"
            if len(value) > MAX_SNIPPET_CHARS or _XLSX_BAD.search(value):
                warnings.append(f"{codebase}/{file}:{line} – строка кода не помещается в выгрузку, оставлено «-»")
                continue
            cell = row[col["Source code"]]
            cell.value = value
            cell.data_type = "s"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f"{entry['id']}-", suffix=".xlsx", dir=tmp_dir)
    os.close(fd)
    try:
        wb.save(name)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name), warnings


# ============================================================================ командная строка

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.examples", description="Скачивание учебных примеров каталога")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="скачать и распаковать примеры")
    f.add_argument("ids", nargs="*")
    f.add_argument("--all", action="store_true")
    f.add_argument("--repos-root", type=Path, required=True)
    f.add_argument("--again", action="store_true", help="новая копия рядом с прежней")
    args = ap.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    catalog = load_catalog()
    entries = [e for e in catalog["examples"] if is_downloadable(e)] if args.all else \
        [entry_of(catalog, i) for i in args.ids]
    if not entries:
        print("Укажите примеры или --all.")
        return 2
    failed = 0
    for e in entries:
        try:
            folder = download(e, args.repos_root, Path(tempfile.gettempdir()), again=args.again)
            print(f"{e['id']}: {folder}")
        except ExampleError as err:
            failed += 1
            print(f"{e['id']}: {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
