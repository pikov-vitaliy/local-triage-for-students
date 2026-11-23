"""Срез кода вокруг находки: папка репозитория, поиск файла, чтение, маскирование, объемлющий метод, сверка
строки из выгрузки со строкой файла.

Репозитории только читаются: никаких команд в них не запускается. Папка репозитория и файл должны лежать внутри
корня (resolve_repo, find_file): выход через «..», абсолютный путь или символическую ссылку – отказ. Проверка пути
и чтение не разделены (_read_inside): файл сначала открывается, а проверяется уже открытый дескриптор, и читается
не больше предела размера – подмена файла или папки ссылкой между проверкой и чтением наружу не выводит.

Если кода из репозитория нет (папка не задана, файла нет, файл слишком велик или двоичный, строка за пределами
файла), контекстом служит строка кода из выгрузки (поле snippet находки, колонка Source code) – статус
'export_line_only'. Сверка фрагмента из выгрузки со строкой файла и её соседями (export_line_check)
помогает найти место срабатывания, но сама по себе не доказывает смену кода после сканирования.
"""

from __future__ import annotations

import bisect
import codecs
import hashlib
import html
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

from app import i18n
from app.masking import (PLACEHOLDER_RE, count_placeholders, is_credential_finding, mask_all_literals,
                         mask_literal_token, mask_text, recording_active, secret_assignment_before)
from app.models import CodeContext, Finding

LINE_LIMIT = 400                   # строки длиннее (минифицированный код) обрезаются до стольких знаков
# Файлы больше не читаются: файл маскируется целиком, а это до десятков секунд на мегабайт (строки вида
# password=… подряд). Исходники такого размера – почти всегда код из генераторов или собранный код.
MAX_FILE_BYTES = 2 * 1024 * 1024
MASK_CACHE_FILES = 16              # маскированный текст стольких последних файлов хранится в памяти
MASK_CACHE_CHARS = 40_000_000      # …но не больше стольких знаков вместе
HEADER_LIMIT = 2000                # заголовок блока длиннее не разбирается как сигнатура
SIGNATURE_LIMIT = 300              # предел длины сигнатуры объемлющего метода
CUT_MARK = " …[обрезано]"  # часть строки кода в промпте и в отпечатке случая – не переводится (ADR-0158)
SECRET_NOTE = i18n.N_("находка о секрете в коде: строки в кавычках заменены метками")
MAX_INDEX_FILES = 300_000          # поиск файла по окончанию пути: файлов в индексе репозитория не больше
MAX_INDEX_DIRS = 100_000           # …папок не больше
INDEX_SECONDS = 20.0               # …и не дольше стольких секунд
INDEX_TTL = 120.0                  # секунд: индекс файлов репозитория переиспользуется
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".idea", ".vs",
             ".gradle", "target"}

LANGUAGES = {
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy", ".gradle": "groovy",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".vue": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".py": "python", ".pyw": "python", ".cs": "csharp", ".go": "go", ".php": "php", ".rb": "ruby",
    ".swift": "swift", ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".jsp": "jsp", ".cshtml": "razor", ".html": "html", ".htm": "html",
    ".xml": "xml", ".sql": "sql", ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".properties": "properties",
    ".sh": "shell", ".ps1": "powershell",
}


def language_of(path: str) -> str:
    """Язык файла по расширению ("" – неизвестен)."""
    return LANGUAGES.get(os.path.splitext(str(path))[1].lower(), "")


def norm_path(value: str) -> str:
    """Путь: прямые слэши, без «./», ведущего «/» и двойных слэшей. «..» не раскрывается."""
    s = str(value or "").strip().replace("\\", "/")
    return "/".join(part for part in s.split("/") if part not in ("", "."))


# ============================================================================ границы: корень и репозиторий

_DRIVE = re.compile(r"^[A-Za-z]:")


def _is_inside(path: str, folder: str) -> bool:
    """path – это folder или лежит внутри неё (пути уже раскрыты realpath; без учёта регистра на Windows)."""
    p = os.path.normcase(path)
    f = os.path.normcase(folder).rstrip("\\/")
    return p == f or p.startswith(f + os.sep) or (os.altsep is not None and p.startswith(f + os.altsep))


def resolve_repo(repos_root: Path, folder: str) -> Path:
    """Папка внутри корня repos_root -> абсолютный путь (символические ссылки раскрыты).

    folder – путь от корня, с прямыми или обратными слэшами; "" или "." – сам корень. Абсолютный путь, диск («C:»),
    сетевой путь, сегмент «..», двоеточие и управляющие символы в пути, выход за корень через символическую ссылку –
    ValueError. Существование папки не проверяется.
    """
    text = str(folder or "").strip()
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(i18n._("В пути к папке недопустимые символы."))
    norm = text.replace("\\", "/")
    if norm.startswith("/") or _DRIVE.match(norm):
        raise ValueError(i18n._("Путь к папке должен быть относительным – от корня папки с репозиториями."))
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(i18n._("Путь к папке не должен выходить за пределы корня папки с репозиториями («..»)."))
    if any(":" in p for p in parts):
        raise ValueError(i18n._("В пути к папке не должно быть двоеточия."))
    root = os.path.realpath(str(repos_root))
    target = os.path.realpath(os.path.join(root, *parts)) if parts else root
    if not _is_inside(target, root):
        raise ValueError(i18n._("Папка ведёт за пределы корня папки с репозиториями (символическая ссылка?)."))
    return Path(target)


# ============================================================================ ревизия клона

_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")  # SHA-1 или SHA-256
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,240}")
MAX_PACKED_REFS_BYTES = 50 * 1024 * 1024


def _git_text(git_dir: str, path: str, limit: int = 4096) -> str | None:
    """Небольшой служебный файл git: не ссылка, на самом деле лежит внутри git_dir (проверяется открытый файл,
    поэтому и промежуточные папки наружу не уводят), не больше limit байт; иначе None."""
    try:
        if _is_link_or_junction(path):
            return None
        raw = _read_inside(os.path.realpath(git_dir), path, limit)[0]
    except (OSError, _ReadRefused):
        return None
    return raw.decode("ascii", errors="replace")


def clone_revision(repo_dir: Path | None, example_root: Path | None = None) -> str:
    """Ревизия клона git – хеш коммита, на котором стоит рабочая копия (HEAD): HEAD с хешем или ссылка на ветку
    (файл ссылки либо packed-refs). Не клон, .git – файл (worktree) или ссылка, ревизию не прочитать – "": такие
    папки по ревизии не отслеживаются. Читаются только файлы внутри .git самого клона."""
    if repo_dir is None:
        return ""
    git = os.path.join(str(repo_dir), ".git")
    if not os.path.lexists(git):
        # папка учебного примера без .git: коммит из маркера – только у проекта из каталога и только внутри его папки
        # примеров (example_root – граница поиска; ADR-0156)
        return example_revision(repo_dir, example_root) if example_root is not None else ""
    if _is_link_or_junction(git) or not os.path.isdir(git):
        return ""
    head = (_git_text(git, os.path.join(git, "HEAD")) or "").strip()
    if _COMMIT.fullmatch(head):
        return head  # отсоединённый HEAD
    if not head.startswith("ref:"):
        return ""
    ref = head[4:].strip()
    if not _REF.fullmatch(ref) or ".." in ref.split("/"):
        return ""
    value = (_git_text(git, os.path.join(git, *ref.split("/"))) or "").strip()
    if _COMMIT.fullmatch(value):
        return value
    packed = _git_text(git, os.path.join(git, "packed-refs"), MAX_PACKED_REFS_BYTES) or ""
    for line in packed.splitlines():
        commit, _, name = line.partition(" ")
        if name.strip() == ref and _COMMIT.fullmatch(commit):
            return commit
    return ""


EXAMPLE_MARKER = ".local-triage-example.json"


def example_revision(repo_dir: Path, example_root: Path, levels: int = 3) -> str:
    """Коммит учебного примера из маркера: маркер ищется в папке кодовой базы и выше (не дальше levels уровней), но
    только в корне дерева примера – папке, лежащей прямо в папке «examples» (у монорепозитория crAPI так ревизию
    получают все подпапки). Посторонний маркер выше папки примера не берётся. Маркер – обычный файл не больше 1 МиБ;
    нет или испорчен – ""."""
    import json

    folder = Path(repo_dir)
    try:
        root = Path(os.path.realpath(example_root))
        if os.path.commonpath([str(root), os.path.realpath(folder)]) != str(root):
            return ""
    except (OSError, ValueError):
        return ""
    for _ in range(levels + 1):
        if Path(os.path.realpath(folder.parent)) == root:
            marker = folder / EXAMPLE_MARKER
            try:
                if marker.is_file() and not marker.is_symlink() and marker.stat().st_size <= 1024 * 1024:
                    data = json.loads(marker.read_text(encoding="utf-8"))
                    commit = str(data.get("commit") or "")
                    # маркер – только в корне дерева этого примера: имя папки «<id>-<commit7>[-N]» из самого маркера
                    base = f"{data.get('id')}-{commit[:7]}"
                    named = folder.name == base or (folder.name.startswith(base + "-")
                                                    and folder.name[len(base) + 1:].isdigit())
                    return commit if _COMMIT.fullmatch(commit) and named else ""
            except (OSError, ValueError, AttributeError):
                return ""
            return ""
        if folder.parent == folder:
            break
        folder = folder.parent
    return ""


_INDEX_LOCK = threading.Lock()
_INDEX_CACHE: dict[str, tuple[float, dict[str, list[str]], bool]] = {}


def _is_link_or_junction(path: str) -> bool:
    """Символическая ссылка или точка повторного анализа Windows (точка соединения и т. п.)."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    return os.path.islink(path) or bool(getattr(st, "st_reparse_tag", 0))


def _file_index(root: str) -> tuple[dict[str, list[str]], bool]:
    """({имя файла в нижнем регистре: [пути от корня репозитория]}, индекс полный).

    Обход ограничен: не больше MAX_INDEX_FILES файлов, MAX_INDEX_DIRS папок и INDEX_SECONDS секунд; служебные папки
    (SKIP_DIRS), символические ссылки и точки соединения не обходятся, каждая папка – один раз. Если предел
    достигнут или папку не удалось прочитать, индекс неполный: по нему нельзя утверждать, что совпадение
    единственное. Индекс живёт INDEX_TTL секунд."""
    now = time.monotonic()
    with _INDEX_LOCK:
        cached = _INDEX_CACHE.get(root)
        if cached and now - cached[0] < INDEX_TTL:
            return cached[1], cached[2]
    index: dict[str, list[str]] = {}
    files_seen, dirs_seen, complete = 0, 0, True
    norm_root = os.path.normcase(root)
    visited = {norm_root}
    stack = [(root, "")]
    while stack and complete:
        folder, rel_folder = stack.pop()
        try:
            with os.scandir(folder) as entries:  # папка читается по одной записи: предел проверяется сразу
                for entry in entries:
                    if time.monotonic() - now > INDEX_SECONDS:
                        complete = False
                        break
                    rel = f"{rel_folder}/{entry.name}" if rel_folder else entry.name
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIP_DIRS or _is_link_or_junction(entry.path):
                            continue
                        real = os.path.normcase(os.path.realpath(entry.path))
                        if real in visited or not _is_inside(real, norm_root):
                            continue
                        visited.add(real)
                        dirs_seen += 1
                        if dirs_seen > MAX_INDEX_DIRS:
                            complete = False
                            break
                        stack.append((entry.path, rel))
                    else:
                        files_seen += 1
                        if files_seen > MAX_INDEX_FILES:
                            complete = False
                            break
                        index.setdefault(entry.name.lower(), []).append(rel)
        except OSError:  # папка не прочитана: о файлах в ней ничего не известно
            complete = False
    with _INDEX_LOCK:
        if len(_INDEX_CACHE) >= 32:
            _INDEX_CACHE.clear()
        _INDEX_CACHE[root] = (now, index, complete)
    return index, complete


def _inside_file(root: str, rel: str) -> Path | None:
    """Файл rel от корня root -> абсолютный путь, если это файл и он не ведёт за пределы корня; иначе None."""
    real = os.path.realpath(os.path.join(root, *rel.split("/")))
    return Path(real) if _is_inside(real, root) and os.path.isfile(real) else None


def file_presence(repo_dir: Path | None, rel_path: str) -> str:
    """Есть ли файл находки в репозитории – по тем же правилам, что find_file: "found" – найден однозначно,
    "missing" – подтверждённо нет (обход полный, подходящих файлов нет), "unknown" – не определить: несколько
    подходящих файлов или обход репозитория неполный. Файл не читается."""
    parts = [p for p in str(rel_path or "").strip().replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or repo_dir is None:
        return "missing"
    root = os.path.realpath(str(repo_dir))
    if not os.path.isdir(root):
        return "missing"
    if not any(p == ".." or ":" in p for p in parts) and os.path.isfile(os.path.join(root, *parts)):
        return "found" if _inside_file(root, "/".join(parts)) is not None else "missing"
    index, complete = _file_index(root)
    if not complete:
        return "unknown"
    same_name = index.get(parts[-1].lower(), [])
    for k in range(len(parts), 0, -1):
        tail = "/".join(parts[-k:]).lower()
        hits = [p for p in same_name if p.lower() == tail or p.lower().endswith("/" + tail)]
        if len(hits) > 1:
            return "unknown"
        if len(hits) == 1:
            return "found" if _inside_file(root, hits[0]) is not None else "missing"
    return "missing"


def find_file(repo_dir: Path, rel_path: str) -> Path | None:
    """Файл находки в репозитории -> абсолютный путь или None.

    1. Путь как есть.
    2. Иначе – по окончанию пути среди файлов репозитория: нужно единственное совпадение по самому длинному
       окончанию из двух и более частей пути (так находится и путь с лишним началом, например путь сборки
       builds/app/src/A.java) или единственный файл с таким именем. Несколько подходящих файлов – None.
       Обход репозитория ограничен (_file_index): если предел достигнут или часть папок не прочитана, по окончанию
       пути файл не ищется – единственность совпадения не доказать.
    Файлы в служебных папках (SKIP_DIRS) находятся только по точному пути. Файл, который через символическую ссылку
    ведёт за пределы репозитория, не возвращается.
    """
    parts = [p for p in str(rel_path or "").strip().replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or repo_dir is None:
        return None
    root = os.path.realpath(str(repo_dir))
    if not os.path.isdir(root):
        return None
    if not any(p == ".." or ":" in p for p in parts) and os.path.isfile(os.path.join(root, *parts)):
        return _inside_file(root, "/".join(parts))
    index, complete = _file_index(root)
    if not complete:
        return None  # по неполному индексу единственность совпадения не доказать
    same_name = index.get(parts[-1].lower(), [])
    for k in range(len(parts), 0, -1):
        tail = "/".join(parts[-k:]).lower()
        hits = [p for p in same_name if p.lower() == tail or p.lower().endswith("/" + tail)]
        if len(hits) > 1:
            return None
        if len(hits) == 1:  # при k = 1 это единственный файл с таким именем
            return _inside_file(root, hits[0])
    return None


# ============================================================================ чтение файла

class _ReadRefused(Exception):
    """Файл не читается: status – статус среза ('too_large' или 'file_missing'), reason – причина по-русски."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


# Только чтение; O_BINARY – без перевода строк в Windows; O_NOFOLLOW – последняя часть пути не ссылка (там, где ОС
# это умеет); O_NONBLOCK – канал (FIFO), подложенный вместо файла, открывается сразу, а не ждёт писателя, и затем
# отсеивается проверкой дескриптора.
_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_CLOEXEC", 0)
               | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
_READ_CHUNK = 1024 * 1024


def _open_file(path: str) -> int:
    """Дескриптор файла, открытого только для чтения (_OPEN_FLAGS)."""
    return os.open(path, _OPEN_FLAGS)


def _opened_path(fd: int) -> str | None:
    """Путь открытого файла по его дескриптору, как его знает ядро (Linux: /proc/self/fd); узнать нельзя – None."""
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        return None
    return target[:-len(" (deleted)")] if target.endswith(" (deleted)") else target


def _read_at_most(fd: int, limit: int) -> bytes:
    """Не больше limit + 1 байт из открытого файла: лишний байт значит, что файл больше предела (вырос после
    проверки размера), и дальше он не читается."""
    chunks, size = [], 0
    while size <= limit:
        chunk = os.read(fd, min(_READ_CHUNK, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _read_inside(root: str, path: str, limit: int) -> tuple[bytes, os.stat_result, bool, str]:
    """Файл внутри папки root (уже раскрытой realpath) -> (байты, сведения о файле, файл не менялся во время
    чтения, настоящий путь файла).

    Сначала файл открывается, затем проверяется открытый дескриптор: это обычный файл, и лежит он на самом деле
    внутри root – по пути открытого файла, который знает ядро (Linux), а где ОС его не даёт – по раскрытому заново
    пути внутри root, который должен вести к тому же файлу (устройство и номер файла, os.path.samestat). Подмена
    файла или промежуточной папки ссылкой между поиском файла и чтением поэтому не выводит чтение наружу. Читается
    не больше limit + 1 байт: файл, выросший после проверки размера, целиком не читается.

    Не обычный файл или файл вне root – _ReadRefused('file_missing'); больше limit байт – _ReadRefused('too_large');
    сбой открытия или чтения – OSError."""
    fd = _open_file(path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _ReadRefused("file_missing", i18n.N_("это не обычный файл – не читается"))
        real = _opened_path(fd)
        if real is not None:
            inside = _is_inside(real, root)
        else:
            real = os.path.realpath(path)
            inside = _is_inside(real, root) and os.path.samestat(st, os.stat(real))
        if not inside:
            raise _ReadRefused("file_missing", i18n.N_("файл ведёт за пределы репозитория или подменён во время "
                                                       "чтения – не читается"))
        if st.st_size > limit:
            raise _ReadRefused("too_large", i18n.N_("файл больше предела размера"))
        raw = _read_at_most(fd, limit)
        if len(raw) > limit:
            raise _ReadRefused("too_large", i18n.N_("файл вырос во время чтения и стал больше предела размера"))
        after = os.fstat(fd)
        stable = (after.st_size, after.st_mtime_ns) == (st.st_size, st.st_mtime_ns) and len(raw) == st.st_size
        return raw, st, stable, real
    finally:
        os.close(fd)


def decode_source(raw: bytes) -> str | None:
    """Байты файла -> текст (UTF-8 с BOM или без, UTF-16 с BOM, иначе cp1251); двоичный файл -> None.

    CRLF заменяется на LF; одиночный CR и прочие разделители не трогаются: номера строк должны совпадать
    с номерами в отчёте анализатора.
    """
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = raw.decode("utf-16", errors="replace")
    elif b"\x00" in raw[:8192]:
        return None
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1251", errors="replace")
    return text.replace("\r\n", "\n")


def _split_lines(text: str) -> list[str]:
    lines = text.split("\n") if text else []
    if text.endswith("\n"):
        lines.pop()
    return lines


# ============================================================================ объемлющий метод: простые эвристики

# Комментарии и строковые литералы по языкам. Перед поиском блоков они заменяются пробелами (длина текста и
# переводы строк сохраняются), чтобы скобки и слова внутри них не сбивали разбор. Незакрытый комментарий или
# литерал продолжается до конца текста (однострочный литерал – до конца строки): так разбор линейный даже на
# тексте из одних «/*» или кавычек.
_C_COMMENT = r"//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)"
_DQ = r'"(?:\\.|[^"\\\n])*(?:"|\\?(?=\n)|\\?\Z)'
_SQ = r"'(?:\\.|[^'\\\n])*(?:'|\\?(?=\n)|\\?\Z)"
_TRIPLE_DQ = r'"""(?:\\[\s\S]|(?!""")[^\\])*(?:"""|\\?\Z)'  # экранированная кавычка литерал не заканчивает
_TRIPLE_SQ = r"'''(?:\\[\s\S]|(?!''')[^\\])*(?:'''|\\?\Z)"
_BACKTICK = r"`(?:\\[\s\S]|[^`\\])*(?:`|\\?\Z)"
_CS_VERBATIM = r'(?:@\$?|\$@)"(?:""|[^"])*(?:"|\Z)'
# Сырые строки: C++ R"метка(…)метка" и Rust r#"…"#. Единственная группа в своём разборщике – для \1.
_CPP_RAW = r'(?<![\w])(?:u8|[uUL])?R"([^()\\\s]{0,16})\((?:[\s\S]*?\)\1"|[\s\S]*\Z)'
_RUST_RAW = r'(?<![\w])b?r(#*)"(?:[\s\S]*?"\1|[\s\S]*\Z)'
_RUST_CHAR = r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^'\\\n])'"  # символ, а не время жизни 'a
_HASH = r"#[^\n]*"
_COMMENT_START = ("//", "/*", "#")
_LEXER_PARTS = {
    "java": (_C_COMMENT, _TRIPLE_DQ, _DQ, _SQ),
    "kotlin": (_C_COMMENT, _TRIPLE_DQ, _DQ, _SQ),
    "scala": (_C_COMMENT, _TRIPLE_DQ, _DQ, _SQ),
    "groovy": (_C_COMMENT, _TRIPLE_DQ, _TRIPLE_SQ, _DQ, _SQ),
    "javascript": (_C_COMMENT, _BACKTICK, _DQ, _SQ),
    "typescript": (_C_COMMENT, _BACKTICK, _DQ, _SQ),
    "csharp": (_C_COMMENT, _CS_VERBATIM, _TRIPLE_DQ, _DQ, _SQ),
    "go": (_C_COMMENT, _BACKTICK, _DQ, _SQ),
    "php": (_C_COMMENT, _HASH, _DQ, _SQ),
    "c": (_C_COMMENT, _DQ, _SQ),
    "cpp": (_C_COMMENT, _CPP_RAW, _DQ, _SQ),
    "swift": (_C_COMMENT, _TRIPLE_DQ, _DQ),
    "rust": (_C_COMMENT, _RUST_RAW, _RUST_CHAR, _DQ),
    "python": (_TRIPLE_DQ, _TRIPLE_SQ, _DQ, _SQ, _HASH),
}
_LEXERS = {language: re.compile("|".join(parts)) for language, parts in _LEXER_PARTS.items()}
# Только литералы языка, без комментариев: для тела уже выделенного комментария у находки о секрете (ADR-0117) –
# «//» и «#» внутри него не комментарий, и многострочный литерал после них разбирается целиком
_LITERAL_LEXERS = {language: re.compile("|".join(p for p in parts if p not in (_C_COMMENT, _HASH)))
                   for language, parts in _LEXER_PARTS.items()}
# Разборщики только для поиска комментариев при сверке фрагмента (ADR-0082): в JS/TS литерал регулярного
# выражения разбирается раньше комментария, иначе «/https?:\/\//» дал бы ложное начало «//». Литерал узнаётся по
# предыдущему значимому знаку или слову: после оператора, открывающей скобки, «=>», return, typeof и т. п. и в
# начале строки; после «}», «)», «]», имени и числа «/» – деление.
_JS_REGEX_BEFORE = "|".join([r"\A", r"(?<=[=(,:;!&|?{\[\n])", r"(?<==>)"]
                            + [rf"(?<=\b{word})" for word in ("return", "typeof", "instanceof", "case", "throw",
                                                              "yield", "await", "void", "delete", "in", "of",
                                                              "new", "else", "do")])
_JS_REGEX = rf"(?:{_JS_REGEX_BEFORE})[ \t]*/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*"
# Строки с переносом через «\» в конце строки (Python, JS): литерал продолжается, «#» и «//» в нём не комментарий
_DQ_CONT = r'"(?:\\[\s\S]|[^"\\\n])*(?:"|(?=\n)|\\?\Z)'
_SQ_CONT = r"'(?:\\[\s\S]|[^'\\\n])*(?:'|(?=\n)|\\?\Z)"
_PHP_HASH = r"#(?!\[)[^\n]*"  # «#[» в PHP 8 – атрибут, а не комментарий
# _LEXERS не меняются: от них зависят blank_code и сигнатура метода, а значит и отпечаток case_hash
_COMMENT_LEXERS = {language: re.compile("|".join(parts)) for language, parts in {
    "javascript": (_JS_REGEX, _C_COMMENT, _BACKTICK, _DQ_CONT, _SQ_CONT),
    "typescript": (_JS_REGEX, _C_COMMENT, _BACKTICK, _DQ_CONT, _SQ_CONT),
    "python": (_TRIPLE_DQ, _TRIPLE_SQ, _DQ_CONT, _SQ_CONT, _HASH),
    "php": (_C_COMMENT, _PHP_HASH, _DQ, _SQ),
}.items()}
# Языки программирования: в их коде КЛЮЧ=значение – присваивание, а не строка .env (см. masking.mask_text).
CODE_LANGUAGES = frozenset({"java", "kotlin", "scala", "groovy", "javascript", "typescript", "python", "csharp", "go",
                            "php", "ruby", "swift", "rust", "c", "cpp", "jsp", "razor"})
BRACE_LANGUAGES = {"java", "kotlin", "scala", "groovy", "javascript", "typescript", "csharp", "go", "php", "c", "cpp",
                   "swift", "rust"}

# Языки, где функцию объявляет ключевое слово; в остальных (Java, C#, C/C++, методы JS/TS) – разбор заголовка.
_FUNCTION_KEYWORD = {"go": "func", "kotlin": "fun", "swift": "func", "rust": "fn", "scala": "def", "php": "function"}
_CONTROL_WORDS = frozenset(("if for foreach while switch catch synchronized using lock fixed return new else do try "
                            "finally when select case default sizeof typeof nameof checked unchecked await yield "
                            "throw with assert").split())
# Объявление типа или пространства имён: модификаторы и аннотации, затем ключевое слово (public final class Foo,
# export default class, data class, type User struct, declare module, companion object). Такой блок – граница поиска:
# строка в его теле, но не в методе – поле или инициализатор.
_TYPE_DECLARATION = re.compile(
    r"(?:@[\w.]+(?:\([^)]*\))?\s*|\[[^\]]*\]\s*|type\s+\w+\s+|(?:public|private|protected|internal|static|final|"
    r"abstract|sealed|partial|export|default|declare|data|open|inner|annotation|companion|readonly|unsafe|pub|case|"
    r"enum|value|inline)\s+)*"
    r"(?:class|interface|enum|record|struct|namespace|module|object|trait|impl|extension|protocol|@interface)\b")
# Слова, которые перед списком параметров означают объявление типа, а не метод: record Point(int x), class Foo(val x).
_TYPE_WORDS = re.compile(r"(?<![\w$@])(?:class|interface|enum|record|struct)(?![\w$])|@interface")
_IDENT_CALL = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:<[^()]*>)?\s*\(")  # имя(… или имя<T>(…
_ANNOTATION = re.compile(r"@[\w$.]+\s*")
_TOKEN = re.compile(r"[\w$]+|\s+|.", re.S)
# Что может стоять после списка параметров метода до «{».
_SUFFIX_OK = re.compile(
    r"\s*(?:throws\s+[\w$.,\s<>?]+"                       # Java: throws IOException
    r"|:\s*(?:base|this)\s*\(.*\)"                        # C#: вызов конструктора базового класса
    r"|where\s.+"                                         # C#: ограничения обобщённых параметров
    # C++: const, override, &, && … «&+(?!&)» забирает всю серию «&» сразу: иначе разбор строки из множества «&»
    # перебирает все её разбиения.
    r"|(?:(?:const|override|final|noexcept|volatile)\s*|&+(?!&)\s*)+"
    r"|->\s*[^{};=]+"                                     # C++: тип результата после ->
    r"|:\s*[^{};=]+"                                      # TypeScript: тип результата
    r")?\s*", re.S)


def blank_code(text: str, language: str) -> str:
    """Текст той же длины, где комментарии и строковые литералы заменены пробелами (переводы строк на месте)."""
    lexer = _LEXERS.get(language)
    if lexer is None:
        return text
    return lexer.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _skip_group(text: str, i: int, open_ch: str = "(", close_ch: str = ")") -> int | None:
    """Индекс за парной закрывающей скобкой для открывающей в позиции i; пары нет – None."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _call_parts(header: str):
    """«public <T> T name(параметры) throws X» -> (начало, имя, параметры, хвост) или None.

    Аннотации Java (@Name(...)) и атрибуты C# ([...]) в начало не входят; список параметров должен закрываться.
    """
    i, prefix = 0, []
    while i < len(header):
        if header[i] == "@":
            m = _ANNOTATION.match(header, i)
            i = m.end() if m else i + 1
            if i < len(header) and header[i] == "(":
                i = _skip_group(header, i)
                if i is None:
                    return None
            continue
        if header[i] == "[":
            i = _skip_group(header, i, "[", "]")
            if i is None:
                return None
            continue
        m = _IDENT_CALL.match(header, i)
        if m:
            open_paren = m.end() - 1
            close = _skip_group(header, open_paren)
            if close is None:
                return None
            return "".join(prefix).strip(), m.group(1), header[open_paren:close], header[close:]
        m = _TOKEN.match(header, i)
        prefix.append(m.group())
        i = m.end()
    return None


def _is_method(header: str) -> bool:
    """Заголовок метода в стиле Java, C#, C/C++ или метода класса JS/TS (не if/for/catch, не new Foo() {, не лямбда)."""
    parts = _call_parts(header)
    if parts is None:
        return False
    prefix, name, _params, suffix = parts
    words = prefix.split()
    if name in _CONTROL_WORDS or (words and words[-1] in _CONTROL_WORDS):
        return False
    if _TYPE_WORDS.search(prefix) or "=" in prefix:
        return False
    return bool(_SUFFIX_OK.fullmatch(suffix))


def is_function_header(header: str, language: str) -> bool:
    """Текст перед «{» (комментарии и строки уже убраны) объявляет функцию или метод."""
    keyword = _FUNCTION_KEYWORD.get(language)
    if keyword:
        return re.search(r"(?<![\w$])" + keyword + r"(?![\w$])", header) is not None
    if language in ("javascript", "typescript"):
        if re.search(r"(?<![\w$])function(?![\w$])", header) or header.endswith("=>"):
            return True
    return _is_method(header)


def _short(text: str, limit: int = SIGNATURE_LIMIT) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "…"


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", text))
    return starts


_CONTINUES = (",", "(", "[", "=", "+", "-", "*", "/", "&", "|", "?", ":", ".", "=>")


def _signature_start(blank: str, start: int, opening: int) -> int:
    """Начало сигнатуры в заголовке блока: без ведущих законченных строк, которые остались от кода без «;»
    (package main в Go, const x = f() в JS). Строки аннотаций (@…) и атрибутов ([…]) остаются: в них бывает
    маршрут обработчика."""
    pos = start
    content_end = start + len(blank[start:opening].rstrip())  # за ним до «{» только пробелы и переводы строк
    while True:
        nl = blank.find("\n", pos, opening)
        if nl < 0 or nl + 1 >= content_end:
            return pos
        line = blank[pos:nl].strip()
        complete = not line or (line.count("(") == line.count(")") and line.count("[") == line.count("]")
                                and not line.startswith(("@", "[")) and not line.endswith(_CONTINUES))
        if not complete:
            return pos
        pos = nl + 1


def code_blocks(text: str, language: str) -> list[tuple[int, int, int, str, str]]:
    """Блоки {…} файла: [(смещение заголовка, первая строка заголовка, строка «}», вид, сигнатура)].

    Вид – "func" (метод или функция), "class" (класс, интерфейс, пространство имён) или "other" (if, for, лямбда
    Java, литерал объекта…). Заголовок – текст от предыдущих «;», «{» или «}» до «{» блока.
    """
    blank = blank_code(text, language)
    starts = _line_starts(text)
    raw, stack, last = [], [], -1
    for m in re.finditer(r"[{};]", blank):
        pos, ch = m.start(), m.group()
        if ch == "{":
            stack.append((last + 1, pos))
        elif ch == "}" and stack:
            raw.append(stack.pop() + (pos,))
        last = pos
    raw.extend((head, opening, len(blank)) for head, opening in stack)  # незакрытые – до конца файла
    blocks = []
    for head, opening, close in raw:
        h = head
        while h < opening and (blank[h].isspace() or blank[h] in ")],;"):
            h += 1
        clean = " ".join(blank[h:opening].split())
        if len(clean) > HEADER_LIMIT:  # минифицированный код или выражение на сотни строк – не заголовок метода
            kind = "other"
        elif is_function_header(clean, language):
            kind = "func"
        elif _TYPE_DECLARATION.match(clean):
            kind = "class"
        else:
            kind = "other"
        signature = ""
        if kind == "func":
            h = _signature_start(blank, h, opening)
            while h < opening and blank[h].isspace():
                h += 1
            signature = _short(text[h:opening])
        blocks.append((h, bisect.bisect_right(starts, h), bisect.bisect_right(starts, close), kind, signature))
    return blocks


_PY_DEF = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]+\w")
_PY_CLASS = re.compile(r"[ \t]*class[ \t]+\w")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _python_signature(blank_lines: list[str], lines: list[str], i: int) -> str:
    """def и его параметры до «:» (сигнатура бывает на нескольких строках)."""
    parts, depth = [], 0
    for j in range(i, min(i + 15, len(lines))):
        parts.append(lines[j].strip())
        b = blank_lines[j]
        depth += sum(b.count(c) for c in "([{") - sum(b.count(c) for c in ")]}")
        if depth <= 0 and b.rstrip().endswith(":"):
            break
    return _short(" ".join(parts).rstrip().rstrip(":"))


def python_enclosing(blank_lines: list[str], lines: list[str], line: int) -> tuple[str, int | None]:
    """Объемлющая функция Python по отступам: (сигнатура, номер строки def) или ("", None)."""
    idx = line - 1
    if _PY_DEF.match(blank_lines[idx]):
        return _python_signature(blank_lines, lines, idx), line
    target = _indent(blank_lines[idx])
    for i in range(idx - 1, -1, -1):
        text = blank_lines[i]
        if not text.strip():
            continue  # пустые строки, комментарии и тела многострочных строк
        indent = _indent(text)
        if indent < target:
            if _PY_DEF.match(text):
                return _python_signature(blank_lines, lines, i), i + 1
            if _PY_CLASS.match(text) or indent == 0:
                return "", None  # строка на уровне класса или модуля
            target = indent
    return "", None


def enclosing_of(text: str, language: str, line: int) -> tuple[str, int | None]:
    """Сигнатура объемлющего метода или функции для строки и номер первой строки её заголовка; нет – ("", None)."""
    lines = _split_lines(text)
    if not 1 <= line <= len(lines):
        return "", None
    if language == "python":
        blank_lines = _split_lines(blank_code(text, "python"))
        blank_lines += [""] * (len(lines) - len(blank_lines))
        return python_enclosing(blank_lines, lines, line)
    if language not in BRACE_LANGUAGES:
        return "", None
    around = [b for b in code_blocks(text, language) if b[1] <= line <= b[2]]
    for _head, first, _last, kind, signature in sorted(around, reverse=True):  # изнутри наружу
        if kind == "func":
            return signature, first
        if kind == "class":
            return "", None  # строка в теле класса, но не в методе (поле, инициализатор)
    return "", None


# ============================================================================ срез

def _clip(text: str, limit: int = LINE_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + CUT_MARK


def _window(lines: list[str], line: int, before: int, after: int, max_chars: int,
            sig_line: int | None) -> tuple[int, int, list[str], list[str]]:
    """Окно вокруг строки line -> (первая, последняя, строки окна, заметки).

    Окно – before строк до и after после; если объемлющий метод начинается выше окна и срез с ним укладывается
    в max_chars, окно расширяется до его заголовка. Длинные строки обрезаются (строка срабатывания – до
    max_chars/2), лишнее сверх max_chars срезается с дальнего от строки срабатывания края."""
    n = len(lines)
    width = max(5, len(str(n)))
    start, end = max(1, line - before), min(n, line + after)
    first = sig_line if sig_line and sig_line < start else start
    rendered = {}
    for k in range(first, end + 1):
        rendered[k] = _clip(lines[k - 1], max(LINE_LIMIT, max_chars // 2) if k == line else LINE_LIMIT)

    def cost(k):
        return len(rendered[k]) + width + 5  # метка, номер, «| » и перевод строки

    total = sum(cost(k) for k in range(start, end + 1))
    if first < start:
        above = sum(cost(k) for k in range(first, start))
        if total + above <= max_chars:
            total += above
            start = first
    window = (start, end)
    while total > max_chars and (start < line or end > line):
        if line - start >= end - line:
            total -= cost(start)
            start += 1
        else:
            total -= cost(end)
            end -= 1
    notes = []
    if (start, end) != window:
        notes.append(i18n.N_("срез сокращён до {chars} знаков: строки {start}–{end}").format(chars=max_chars, start=start, end=end))
    cut = sum(1 for k in range(start, end + 1) if rendered[k].endswith(CUT_MARK))
    if cut:
        notes.append(i18n.N_("длинные строки обрезаны: {count}").format(count=cut))
    return start, end, [rendered[k] for k in range(start, end + 1)], notes


EXPORT_LINE_RADIUS = 5
# Версия сверки фрагмента: 1 – вхождение в любую сторону (ADR-0076); 2 – точное совпадение отдельно от частичного
# и закомментированного (ADR-0082). Срезы с меньшей версией пересчитываются только для показа и промпта.
EXPORT_LINE_CHECK_VERSION = 2
_ENTITY = re.compile(r"&(?:quot|apos|amp|lt|gt|#\d{1,7}|#x[0-9a-fA-F]{1,6});")
# Директивы препроцессора и подобные строки на «#» – код, а не комментарий (для языков без разборщика)
_HASH_DIRECTIVE = re.compile(r"#\s*(?:include|define|undef|if|ifdef|ifndef|elif|else|endif|pragma|import|error|warning|"
                             r"line|region|endregion)\b|#!|#\[")
_MARKUP_COMMENT = re.compile(r"<!--[\s\S]*?(?:-->|\Z)")
_MARKUP_LANGUAGES = frozenset({"html", "xml", "jsp", "vue", "svelte", "razor"})
# Фрагмент, который сам начинается с комментария, – выгруженный комментарий: сверяется со строкой целиком
_COMMENT_OPENERS = ("//", "/*", "<!--", "--", "#")
# Ступени сверки одной строки: точное вхождение, только в комментарии, частичное совпадение
_EXACT, _COMMENTED, _PARTIAL = "exact", "commented", "partial"


def _normalize_line(text: str) -> str:
    return "".join(html.unescape(text).split())


def _export_fragments(snippet: str) -> list[str]:
    return [part for line in html.unescape(snippet).splitlines() if (part := "".join(line.split()))]


def _export_parts(snippet: str) -> list[tuple[str, str]]:
    """Значимые строки выгрузки без пробелов (от трёх знаков) и начало каждой, если Hub обрезал строку многоточием.

    Начало берётся, когда до многоточия не меньше 20 знаков со свёрнутыми пробелами (правило ADR-0076)."""
    parts = []
    for line in html.unescape(snippet).splitlines():
        part = "".join(line.split())
        if len(part) < 3:
            continue
        spaced = " ".join(line.split())
        cut = part[:-3] if part.endswith("...") else part[:-1] if part.endswith("…") else ""
        old_cut = spaced[:-3] if spaced.endswith("...") else spaced[:-1] if spaced.endswith("…") else ""
        parts.append((part, cut if len(cut) >= 3 and len(old_cut.rstrip()) >= 20 else ""))
    return parts


def _comment_body(raw: str) -> str | None:
    """Языки без разборщика: текст строки-комментария целиком, если вся строка – комментарий, иначе None.

    Узнаются строки, начинающиеся с //, /*, <!--, «-- », «* » и «#» (кроме директив препроцессора)."""
    text = html.unescape(raw).strip()
    if text.startswith(("//", "/*", "<!--")) or text.startswith("-- ") or text == "--":
        return text
    if text.startswith("* ") or text == "*" or text.startswith("*/"):
        return text
    if text.startswith("#") and not _HASH_DIRECTIVE.match(text):
        return text
    return None


def _split_comments(lines: list[str], language: str = "") -> list[tuple[str, str]]:
    """Каждая строка -> (код без комментариев, текст комментариев); переводы строк и позиции сохраняются.

    Для языков с разборщиком (`_LEXERS`) комментарии находятся им: блочные – через несколько строк, строковые
    литералы комментариями не считаются (адрес «http://…» в кавычках – код), «//» в Python – деление. Для разметки –
    <!-- -->. Для остальных языков комментарием считается только строка целиком (`_comment_body`). Срез, который
    начинается внутри блочного комментария, разобрать с его начала нельзя – это ограничение."""
    lexer = _COMMENT_LEXERS.get(language) or _LEXERS.get(language)
    if lexer is None and language not in _MARKUP_LANGUAGES:
        out = []
        for raw in lines:
            body = _comment_body(raw)
            out.append(("", raw) if body is not None else (raw, ""))
        return out
    text = "\n".join(lines)
    mark = bytearray(len(text))
    if lexer is not None:
        for m in lexer.finditer(text):
            if m.group(0).startswith(_COMMENT_START):
                mark[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    if language in _MARKUP_LANGUAGES:
        for m in _MARKUP_COMMENT.finditer(text):
            mark[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    out, pos = [], 0
    for raw in lines:
        flags = mark[pos:pos + len(raw)]
        code = "".join(" " if flags[i] else ch for i, ch in enumerate(raw))
        comment = "".join(ch if flags[i] else " " for i, ch in enumerate(raw))
        out.append((code, comment))
        pos += len(raw) + 1
    return out


def _line_grade(part: str, cut: str, raw: str, code: str, comment: str) -> str | None:
    """Ступень совпадения одной значимой строки фрагмента (без пробелов) со строкой файла.

    exact – фрагмент входит в код строки (Hub часто выгружает часть строки), совпадает начало обрезанного фрагмента
    или фрагмент сам начинается с комментария и входит в строку; commented – фрагмент есть только в комментарии
    этой строки; partial – код строки короче фрагмента и входит в него (совпала лишь часть фрагмента)."""
    whole = _normalize_line(raw)
    if len(part) < 3 or len(whole) < 3:
        return None
    code_n, comment_n = _normalize_line(code), _normalize_line(comment)

    def has(text: str) -> bool:
        return bool(text) and (part in text or bool(cut and text.startswith(cut)))

    if has(code_n):
        return _EXACT
    if has(whole) and (not has(comment_n) or (part.startswith(_COMMENT_OPENERS) and comment_n.startswith(part))):
        return _EXACT  # фрагмент, захвативший и код, и комментарий после него, или выгруженный сам комментарий
    if has(comment_n):
        return _COMMENTED
    return _PARTIAL if len(code_n) >= 3 and code_n in part else None


def _same_line(export_line: str, file_line: str) -> bool:
    """Любая значимая строка выгрузки входит в строку кода (не в комментарий), без пробелов и HTML-сущностей."""
    (code, comment), = _split_comments([file_line])
    return any(_line_grade(part, cut, file_line, code, comment) == _EXACT for part, cut in _export_parts(export_line))


def _visible_grade(part: str, code: str, comment: str, cut: str = "") -> str | None:
    """Сохранённая строка с метками маскирования: доказательством служит только видимый участок, не метка;
    участок в коде – exact, только в комментарии – commented. Начало обрезанного фрагмента (cut) сверяется с
    видимым началом строки – до первой метки."""
    if len(part) < 3:
        return None
    for text, kind in ((code, _EXACT), (comment, _COMMENTED)):
        visible = ["".join(piece.split()) for piece in PLACEHOLDER_RE.sub("\0", html.unescape(text)).split("\0")]
        if any(part in piece for piece in visible) or (cut and visible[0].startswith(cut)):
            return kind
    return None


def check_export_fragment(snippet: str, lines: list[str], start_line: int, target_line: int | None, *,
                          masked: bool = False, language: str = "") -> tuple[str, int | None]:
    """Сверка фрагмента из выгрузки рядом со строкой сканера (ADR-0076, ADR-0082).

    match/near – фрагмент найден в коде: однострочный входит в код строки в окне ±5, многострочный – все его значимые
    строки подряд (короткие строки файла между ними пропускаются), и блок задевает окно ±5; commented – найден
    только в комментариях (у многострочного – все строки, хотя бы одна в комментарии); partial – совпала лишь часть
    фрагмента. Из нескольких мест – ближайшее к строке сканера, при равном расстоянии – ниже. Для сохранённого
    среза скрытые значения не служат доказательством совпадения или несовпадения."""
    if target_line is None or start_line < 1:
        return "n/a", None
    if not _export_fragments(snippet):
        return "no_export_line", None
    parts = _export_parts(snippet)
    if not parts:
        return "short_export_line", None
    split = _split_comments(lines, language)
    rows = [(start_line + i, raw, split[i][0], split[i][1]) for i, raw in enumerate(lines)]
    hidden = False

    def grade(part: tuple[str, str], row) -> str | None:
        nonlocal hidden
        _, raw, code, comment = row
        if masked and count_placeholders(raw):
            hidden = True
            return _visible_grade(part[0], code, comment, part[1])
        return _line_grade(part[0], part[1], raw, code, comment)

    def distance(first: int, last: int) -> int:
        return 0 if first <= target_line <= last else min(abs(first - target_line), abs(last - target_line))

    best: dict[str, tuple[tuple[int, int], int]] = {}  # ступень -> ((расстояние, -номер), место)

    def offer(kind: str, first: int, last: int, at: int) -> None:
        key = (distance(first, last), -at)
        if kind not in best or key < best[kind][0]:
            best[kind] = (key, at)

    in_window = [i for i, row in enumerate(rows) if abs(row[0] - target_line) <= EXPORT_LINE_RADIUS]
    if len(parts) == 1:
        for i in in_window:
            found = grade(parts[0], rows[i])
            if found:
                offer(found, rows[i][0], rows[i][0], rows[i][0])
    else:
        for i, row in enumerate(rows):  # начало блока – где угодно: пропуски коротких строк его удлиняют
            kinds, j, todo = [], i, list(parts)
            while todo and j < len(rows):
                if j > i and len(_normalize_line(rows[j][1])) < 3:
                    j += 1
                    continue
                found = grade(todo[0], rows[j])
                if found not in (_EXACT, _COMMENTED):
                    break
                kinds.append(found)
                todo.pop(0)
                j += 1
            if not todo:
                first, last = row[0], rows[j - 1][0]
                if distance(first, last) <= EXPORT_LINE_RADIUS:
                    at = target_line if first <= target_line <= last else first
                    offer(_EXACT if all(k == _EXACT for k in kinds) else _COMMENTED, first, last, at)
        for i in in_window:  # неполный многострочный фрагмент: место, где совпала хотя бы одна его строка
            if any(grade(part, rows[i]) for part in parts):
                offer(_PARTIAL, rows[i][0], rows[i][0], rows[i][0])
    for kind, check in ((_EXACT, ""), (_COMMENTED, "commented"), (_PARTIAL, "partial")):
        if kind in best:
            at = best[kind][1]
            return (check or ("match" if at == target_line else "near")), at
    return ("masked_export_line" if hidden else "differs"), None


def legacy_export_check(snippet: str, lines: list[str], start_line: int,
                        target_line: int | None) -> tuple[str, int | None]:
    """Сверка версии 1 (0.8.2, ADR-0076) по коду до маскирования – только для отпечатка случая: чтобы уточнение
    сверки (ADR-0082) не меняло case_hash неизменного кода и не снимало «Проверено»."""
    if target_line is None or start_line < 1:
        return "n/a", None
    fragments = _export_fragments(snippet)
    if not fragments:
        return "no_export_line", None
    if not any(len(part) >= 3 for part in fragments):
        return "short_export_line", None
    candidates = [(start_line + i, text) for i, text in enumerate(lines)
                  if abs(start_line + i - target_line) <= EXPORT_LINE_RADIUS]
    candidates.sort(key=lambda row: (abs(row[0] - target_line), -row[0]))
    for number, text in candidates:
        if _legacy_same_line(snippet, text):
            return ("match" if number == target_line else "near"), number
    return "differs", None


def _legacy_same_line(export_line: str, file_line: str) -> bool:
    """Правило версии 1: любая значимая строка выгрузки входит в строку файла или содержит её."""
    theirs = _normalize_line(file_line)
    if len(theirs) < 3:
        return False
    for part in html.unescape(export_line).splitlines():
        spaced = " ".join(part.split())
        mine = "".join(part.split())
        if len(mine) < 3:
            continue
        if mine in theirs or theirs in mine:
            return True
        cut = mine[:-3] if mine.endswith("...") else mine[:-1] if mine.endswith("…") else ""
        old_cut = spaced[:-3] if spaced.endswith("...") else spaced[:-1] if spaced.endswith("…") else ""
        if len(cut) >= 3 and len(old_cut.rstrip()) >= 20 and theirs.startswith(cut):
            return True
    return False


def export_fragment_scope(snippet: str, text: str) -> str:
    """Что совпало на найденной строке: line – строка целиком, part – часть строки, lines – многострочный фрагмент."""
    parts = _export_parts(snippet)
    if len(parts) > 1:
        return "lines"
    return "line" if parts and _normalize_line(text) == parts[0][0] else "part"


def export_fragment_view(f: Finding, ctx: CodeContext) -> CodeContext:
    """Пересчёт сверки прежних версий только для показа и промпта; исходный срез и его case_hash не меняются.

    Срез версии 1 уже искал вхождение в обе стороны: уточнить можно только найденное совпадение. Его строка со
    скрытыми значениями совпадение не опровергает – тогда прежний результат остаётся."""
    if ctx.status != "ok" or ctx.export_line_check_version >= EXPORT_LINE_CHECK_VERSION:
        return ctx
    if ctx.export_line_check_version >= 1:
        if ctx.export_line_check not in ("match", "near"):
            return ctx
        old = ctx.text_at(ctx.export_line_at)
        if not old or count_placeholders(old):
            return ctx
    language = ctx.language or str(f.language or "").casefold()
    check, at = check_export_fragment(str(f.snippet or ""), ctx.lines, ctx.start_line, _line_of(f), masked=True,
                                      language=language)
    note = "; ".join(part for part in ctx.note.split("; ")
                     if "не совпадает со строкой из выгрузки" not in part)
    # Сверка версии 1 уже сделана по коду до маскирования – она и остаётся в отпечатке (case_hash не меняется).
    # У срезов версии 0 в отпечатке нет export_line_at: их отпечаток по представлению не воспроизводится.
    hashed = {"hash_check": ctx.export_line_check, "hash_check_at": ctx.export_line_at} \
        if ctx.export_line_check_version >= 1 else {}
    return replace(ctx, export_line_check=check, export_line_at=at,
                   export_line_check_version=EXPORT_LINE_CHECK_VERSION, note=note, **hashed)


DISPLAY_LINES = 200  # окно показа в карточке: строк до и после строки сканера (ADR-0087)…
DISPLAY_MAX = 400  # …и не больше строк всего
DISPLAY_CHARS = 80000


class Display(NamedTuple):
    """Контекст показа (ADR-0087): срез ctx и исполняемый код его строк по разбору исходного файла с начала (code –
    номер строки -> код без комментариев и многострочных литералов; только при сверке окна модели differs и только для
    строк, показанных без изменений)."""
    ctx: CodeContext
    code: dict[int, str]


def display_context(repo_dir: Path | None, f: Finding, ctx: CodeContext, *, mask_key: bytes | None = None,
                    no_repo_note: str = "") -> Display | None:
    """Контекст показа для карточки (ADR-0087): из того же клона и с тем же маскированием, что окно модели ctx, до
    DISPLAY_LINES строк до и после строки сканера и не больше DISPLAY_MAX строк, окно модели – целиком. Только если
    тот же файл и язык, на месте окна модели – те же строки по тем же номерам, и показ шире окна модели; иначе None,
    и карточка показывает окно модели. Нигде не сохраняется и в отпечатки не входит: сверка, промпт и вердикт
    остаются по окну модели."""
    if ctx.status != "ok" or not ctx.lines or ctx.start_line < 1 or len(ctx.lines) >= DISPLAY_MAX:
        return None
    # разбор для поиска сдвига – по тому же содержимому файла, из которого построен показ: прочитан до и после
    source = _source_bytes(repo_dir, ctx.file) if ctx.export_line_check == "differs" else None
    wide = build_context(repo_dir, f, before=DISPLAY_LINES, after=DISPLAY_LINES, max_chars=DISPLAY_CHARS,
                         mask_key=mask_key, no_repo_note=no_repo_note)
    if (wide.status != "ok" or wide.start_line < 1 or len(wide.lines) <= len(ctx.lines) or wide.file != ctx.file
            or wide.language != ctx.language):
        return None
    offset = ctx.start_line - wide.start_line
    if offset < 0 or wide.lines[offset:offset + len(ctx.lines)] != ctx.lines:
        return None
    # ±DISPLAY_LINES от строки сканера (build_context расширяет окно до заголовка метода), окно модели – целиком,
    # всего не больше DISPLAY_MAX: лишнее срезается с дальнего от строки сканера края
    line = _line_of(f) or ctx.target_line or ctx.start_line
    first = min(ctx.start_line, max(wide.start_line, line - DISPLAY_LINES))
    last = max(ctx.end_line, min(wide.end_line, line + DISPLAY_LINES))
    while last - first + 1 > DISPLAY_MAX:
        if first < ctx.start_line and (line - first >= last - line or last <= ctx.end_line):
            first += 1
        else:
            last -= 1
    lines = wide.lines[first - wide.start_line:last - wide.start_line + 1]
    if len(lines) <= len(ctx.lines):
        return None
    shown = replace(wide, lines=lines, start_line=first, end_line=last, export_line_check=ctx.export_line_check,
                    export_line_at=ctx.export_line_at)
    code: dict[int, str] = {}
    if source is not None and _source_bytes(repo_dir, ctx.file) == source:  # файл между чтениями не менялся
        code = _code_parts(source, shown)
    return Display(shown, code)


def _source_bytes(repo_dir: Path | None, rel: str) -> bytes | None:
    """Содержимое файла находки в клоне (те же проверки пути и размера, что у build_context) или None."""
    try:
        root = os.path.realpath(str(repo_dir))
        path = find_file(Path(root), rel)
        if path is None:
            return None
        return _read_inside(root, str(path), MAX_FILE_BYTES)[0]
    except (_ReadRefused, OSError):
        return None


def shift_code_lines(repo_dir: Path | None, ctx: CodeContext) -> dict[int, str]:
    """Код строк среза для поиска сдвига (export_fragment_shift) по текущему файлу клона; не прочитан – пусто."""
    source = _source_bytes(repo_dir, ctx.file)
    return _code_parts(source, ctx) if source is not None else {}


def _code_parts(source: bytes, ctx: CodeContext) -> dict[int, str]:
    """Исполняемый код строк среза по разбору исходного файла с начала: без комментариев и без содержимого
    многострочных литералов (блочный комментарий или текстовый блок, начатый выше среза, учитывается). Только для
    строк, которые оператор видит без изменений: строка со скрытыми значениями или обрезанная доказательством не
    служит. Файл не текст или разбор для языка недостоверен – пусто."""
    plain = decode_source(source)
    if plain is None:
        return {}
    lines = _split_lines(plain)[:ctx.end_line]
    code = _executable_code(lines, ctx.language)
    if code is None:
        return {}
    return {ctx.start_line + k: code[ctx.start_line + k - 1] for k, shown in enumerate(ctx.lines)
            if ctx.start_line + k - 1 < len(lines) and lines[ctx.start_line + k - 1] == shown}


def window_code_lines(ctx: CodeContext) -> dict[int, str]:
    """Исполняемый код строк среза по разбору самого среза – когда файла нет (срез из базы, ADR-0087): строки со
    скрытыми значениями не служат доказательством; комментарий или литерал, начатый выше среза, не учитывается."""
    if any(count_placeholders(line) for line in ctx.lines):
        return {}  # маскирование могло скрыть открытие или закрытие комментария – разбор среза недостоверен
    code = _executable_code(list(ctx.lines), ctx.language)
    return {ctx.start_line + k: line for k, line in enumerate(code)} if code is not None else {}


# языки, где многострочные литералы (обычные строки с переводом строки, heredoc) разборщик не видит
_SHIFT_UNSUPPORTED = frozenset({"php"})


def _executable_code(lines: list[str], language: str = "") -> list[str] | None:
    """Каждая строка -> её код без комментариев и без содержимого многострочных литералов (текстовые блоки, тройные
    кавычки, шаблонные строки): текст внутри них – не исполняемый код. Однострочные литералы остаются: фрагменты
    выгрузки их содержат. Позиции и переводы строк сохраняются, как в _split_comments. None – разбор для языка
    недостоверен: разборщика нет (многострочные комментарии и литералы не видны) или в многострочном шаблоне JS/TS
    есть выражение ${…} (вложенные шаблоны плоский разбор не различает)."""
    lexer = _COMMENT_LEXERS.get(language) or _LEXERS.get(language)
    if (lexer is None and language not in _MARKUP_LANGUAGES) or language in _SHIFT_UNSUPPORTED:
        return None
    if language in ("c", "cpp") and any(line.rstrip().endswith("\\") for line in lines):
        return None  # продолжение строки через «\» – комментарий или литерал переходит на следующую строку
    text = "\n".join(lines)
    mark = bytearray(len(text))
    if lexer is not None:
        for m in lexer.finditer(text):
            token = m.group(0)
            if token.startswith("`") and "${" in token:
                return None  # выражения и вложенные шаблоны JS/TS плоский разбор не различает
            if token.startswith("/*") and "/*" in token[2:]:
                return None  # вложенные блочные комментарии (Kotlin, Rust, Swift, Scala) плоский разбор не видит
            if token.startswith(_COMMENT_START) or "\n" in token:
                mark[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    if language in _MARKUP_LANGUAGES:
        for m in _MARKUP_COMMENT.finditer(text):
            mark[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    out, pos = [], 0
    for raw in lines:
        flags = mark[pos:pos + len(raw)]
        out.append("".join(" " if flags[i] else ch for i, ch in enumerate(raw)))
        pos += len(raw) + 1
    return out


def export_fragment_shift(f: Finding, ctx: CodeContext, code: dict[int, str] | None = None) -> int | None:
    """Только для показа (ADR-0086): при сверке differs – строка, где фрагмент из выгрузки найден в показанном коде
    дальше окна ±5 (ближайшая к строке сканера, при равном расстоянии – ниже), иначе None.

    Проверка строже сверки в окне: каждая значимая строка фрагмента целиком входит в код строки (не в комментарий),
    многострочный фрагмент – все строки подряд (короткие строки файла между ними пропускаются); начало фрагмента,
    обрезанного многоточием, и выгруженный комментарий доказательством не служат. Скрытые значения среза не служат
    доказательством. Сверка среза, промпт, отпечатки и ограничение уверенности не меняются: модель разбирала код
    вокруг строки сканера. code – код строк по разбору файла с начала (Display.code): фрагмент должен входить и в
    него, иначе строка внутри блочного комментария, начатого выше среза, сошла бы за код."""
    line = _line_of(f)
    if ctx.status != "ok" or ctx.export_line_check != "differs" or not ctx.lines or line is None:
        return None
    parts = [part for part, cut in _export_parts(str(f.snippet or "")) if not cut]
    if not parts or len(parts) != len(_export_parts(str(f.snippet or ""))):
        return None  # обрезанный многоточием фрагмент целиком не сверить
    if code is not None and not code:
        return None  # разбор файла с начала не получен: строку внутри комментария от кода не отличить
    file_code = code
    split = (_split_comments(ctx.lines, ctx.language or str(f.language or "").casefold()) if file_code is None
             else [("", "")] * len(ctx.lines))

    def exact(part: str, i: int) -> bool:
        raw, (window_code, _) = ctx.lines[i], split[i]
        if file_code is not None:
            # код строки по разбору исходного файла с начала; строки со скрытыми значениями или обрезанные в нём нет
            return ctx.start_line + i in file_code and part in _normalize_line(file_code[ctx.start_line + i])
        if count_placeholders(raw):
            return _visible_grade(part, window_code, "") == _EXACT
        return part in _normalize_line(window_code)

    best: tuple[tuple[int, int], int] | None = None
    for i in range(len(ctx.lines)):
        j, todo = i, list(parts)
        while todo and j < len(ctx.lines):
            if j > i and len(_normalize_line(ctx.lines[j])) < 3:
                j += 1
                continue
            if not exact(todo[0], j):
                break
            todo.pop(0)
            j += 1
        if todo:
            continue
        first, last = ctx.start_line + i, ctx.start_line + j - 1
        inside = first <= line <= last
        at = line if inside else first
        key = (0 if inside else min(abs(first - line), abs(last - line)), -at)
        if best is None or key < best[0]:
            best = (key, at)
    return best[1] if best is not None and best[0][0] > EXPORT_LINE_RADIUS else None


def _line_of(f: Finding) -> int | None:
    """Номер строки находки: положительное целое или None."""
    return f.line if isinstance(f.line, int) and not isinstance(f.line, bool) and f.line >= 1 else None


def _export_only(f: Finding, status: str, reason: str, file: str, language: str, key: bytes | None,
                 credential: bool, notes: list[str], max_chars: int) -> CodeContext:
    """Кода из репозитория нет (reason – почему): контекст – строка кода из выгрузки, если она есть.

    HTML-сущности в строке из выгрузки (&quot; и т. п.) раскрываются до маскирования, иначе значение в «кавычках»
    не узнать. Строка маскируется тем же ключом (у находки о секрете – все литералы, ADR-0117) и укладывается
    в max_chars."""
    line = _line_of(f)
    snippet = str(f.snippet or "").strip("\n")
    if not snippet.strip():
        return CodeContext(status=status, file=file, language=language, start_line=0, end_line=0,
                           target_line=line, lines=[], enclosing="", export_line_check="n/a", masked={},
                           note="; ".join(notes + [reason, i18n.N_("строки кода в выгрузке тоже нет")]))
    if _ENTITY.search(snippet):
        snippet = html.unescape(snippet)
    parts = snippet.split("\n")
    if key is not None:
        # у находки о секрете – все литералы метками (hide), сама строка не скрывается (ADR-0117)
        parts = mask_source_text("\n".join(parts), language, key, hide=credential).split("\n")
    parts = [_clip(part.strip() if k == 0 else part.rstrip(), max(LINE_LIMIT, max_chars // 2) if k == 0 else LINE_LIMIT)
             for k, part in enumerate(parts)]
    width = max(5, len(str((line or 0) + len(parts))))
    kept, total = [], 0
    for part in parts:
        total += len(part) + width + 5
        if kept and total > max_chars:
            break
        kept.append(part)
    start = line or 0
    end = start + len(kept) - 1 if start else 0
    note = i18n.N_("{reason}: видна только строка кода из выгрузки, без окружения").format(reason=reason)
    if len(kept) < len(parts):
        note += "; " + i18n.N_("строка из выгрузки сокращена до {chars} знаков").format(chars=max_chars)
    if credential and key is not None:
        note += "; " + SECRET_NOTE
    return CodeContext(status="export_line_only", file=file, language=language, start_line=start, end_line=end,
                       target_line=line, lines=kept, enclosing="", export_line_check="n/a",
                       masked=count_placeholders("\n".join(kept)) if key is not None else {},
                       note="; ".join(notes + [note]))


_MASK_LOCK = threading.Lock()
_MASK_CACHE: OrderedDict[tuple, str] = OrderedDict()


def clear_mask_cache() -> None:
    with _MASK_LOCK:
        _MASK_CACHE.clear()


def _masked_file(real: str, plain: str, language: str, key: bytes, hide: bool, st: os.stat_result | None) -> str:
    """Весь текст файла после маскирования; повторный вызов для того же файла (настоящий путь, устройство и номер
    файла, размер, время изменения), языка, режима и ключа берётся из памяти: у файла бывают десятки находок,
    а карточку открывают снова и снова.

    real – настоящий путь прочитанного файла (_read_inside); st – сведения об открытом файле, одинаковые до и после
    чтения plain. None – файл меняли во время чтения: память не используется совсем, ни для поиска, ни для записи."""
    cache_key = None
    if st is not None:
        cache_key = ((os.path.normcase(real), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), language, hide,
                     hashlib.sha256(key).hexdigest())
        with _MASK_LOCK:
            # показ без масок восстанавливает значения меток (бэклог 111): для этого метки выдаются заново
            cached = None if recording_active() else _MASK_CACHE.get(cache_key)
            if cached is not None:
                _MASK_CACHE.move_to_end(cache_key)
                return cached
    text = mask_source_text(plain, language, key, hide=hide)
    if cache_key is not None and len(text) <= MASK_CACHE_CHARS:
        with _MASK_LOCK:
            _MASK_CACHE[cache_key] = text
            _MASK_CACHE.move_to_end(cache_key)
            while (len(_MASK_CACHE) > MASK_CACHE_FILES
                   or sum(len(v) for v in _MASK_CACHE.values()) > MASK_CACHE_CHARS):
                _MASK_CACHE.popitem(last=False)
    return text


def mask_source_text(text: str, language: str, key: bytes, hide: bool = False) -> str:
    """Единое маскирование исходного текста из файла и из строки выгрузки."""
    text = _hide_literals(text, language, key, secrets_only=not hide)
    return mask_text(text, key, env_style=language not in CODE_LANGUAGES)[0]


def _hide_literals(text: str, language: str, key: bytes, secrets_only: bool = False) -> str:
    """Строковые литералы по разметке языка (в том числе многострочные и сырые) -> плейсхолдеры; кавычки
    и переводы строк на месте. Комментарии: при secrets_only=True не трогаются; при secrets_only=False строки
    в кавычках внутри комментария тоже заменяются (ADR-0117: закомментированная строка `// pwd = "…"` у находки
    о секрете раньше скрывалась целиком, теперь – только её значение).

    secrets_only=False – все литералы (находка о секрете в коде; для языка без разборщика – однострочные литералы);
    secrets_only=True – только литералы, присвоенные ключу со словом-секретом (password = R"(…)", token = `…`), и их
    продолжения – соседние литералы через пробелы, переводы строк или «+» ("часть" "часть", "часть" + "часть"):
    так значение скрывается целиком при любом синтаксисе строки, а не только в простых кавычках."""
    lexer = _LEXERS.get(language)
    if lexer is None:
        return text if secrets_only else mask_all_literals(text, key)[0]
    previous = {"end": -1, "secret": False}  # последний литерал: где кончился и был ли значением секрета

    def joined(start: int) -> bool:
        """Между предыдущим литералом-секретом и позицией start только пробелы, «+» или «\\» в конце строки."""
        return previous["secret"] and text[previous["end"]:start].strip() in ("", "+", "\\")

    def hide_in_comment(token: str) -> str:
        """Литералы внутри комментария (ADR-0117): тело разбирается разборщиком только литералов языка
        (_LITERAL_LEXERS), без рекурсии – «//» и «#» внутри тела не комментарий, поэтому многострочные литералы
        (текстовые блоки, сырые строки) и после них становятся метками целиком; границы комментария на месте,
        число строк не меняется (mask_literal_token хранит переводы строк)."""
        opener = next(s for s in _COMMENT_START if token.startswith(s))
        closer = "*/" if opener == "/*" and len(token) >= 4 and token.endswith("*/") else ""
        body = token[len(opener):len(token) - len(closer)]
        return opener + _LITERAL_LEXERS[language].sub(lambda m: mask_literal_token(m.group(0), key), body) + closer

    def repl(m):
        token = m.group(0)
        if token.startswith(_COMMENT_START):
            if secrets_only and previous["secret"]:
                if joined(m.start()):  # "часть" /* … */ "часть": комментарий склейку не прерывает
                    previous["end"] = m.end()
                else:  # склейка закончилась: дальше срезы между литералами не нужны
                    previous["secret"] = False
            return token if secrets_only else hide_in_comment(token)
        if secrets_only:
            continued = joined(m.start())
            secret = continued or secret_assignment_before(text[max(0, m.start() - 200):m.start()])
            previous.update(end=m.end(), secret=secret)
            if not secret:
                return token
        return mask_literal_token(token, key)

    return lexer.sub(repl, text)


def build_context(repo_dir: Path | None, f: Finding, before: int = 40, after: int = 40, max_chars: int = 14000,
                  mask_key: bytes | None = None, no_repo_note: str = "") -> CodeContext:
    """Срез кода вокруг находки.

    repo_dir – папка репозитория (уже проверенная resolve_repo) или None; файл ищется find_file. С mask_key весь
    файл маскируется до вырезания среза (секреты и ПДн -> плейсхолдеры, число строк не меняется); у находки
    о секрете в коде все строковые литералы среза, включая строку срабатывания и комментарии, – плейсхолдерами
    (ADR-0117), сама строка видна. Без mask_key код отдаётся как есть (например, для показа человеку).

    Статусы: 'ok' – срез из файла; 'export_line_only' – кода из репозитория нет, контекст – строка из выгрузки;
    без строки в выгрузке – 'no_repo' (папки нет), 'file_missing' (файла нет, он найден неоднозначно или строка
    за пределами файла), 'too_large', 'binary'. Почему – в reason и note; no_repo_note уточняет отсутствие клона.

    max_chars меньше 500 считается равным 500: строка срабатывания всегда остаётся в срезе (длинная – обрезанной
    до max(400, max_chars/2) знаков).
    """
    before, after = max(0, int(before)), max(0, int(after))
    max_chars = max(500, int(max_chars))
    rel = norm_path(f.file)
    language = language_of(rel) or str(f.language or "").strip().lower()
    credential = is_credential_finding(f.rule, f.cwe)
    notes: list[str] = []

    def fallback(status: str, reason: str, note: str, file: str = rel) -> CodeContext:
        ctx = _export_only(f, status, note, file, language, mask_key, credential, notes, max_chars)
        ctx.reason = reason
        return ctx

    if repo_dir is None:
        return fallback("no_repo", "no_repo", no_repo_note or i18n.N_("папка репозитория для кодовой базы не задана"))
    root = os.path.realpath(str(repo_dir))
    if not os.path.isdir(root):
        return fallback("no_repo", "no_repo", i18n.N_("папка репозитория не найдена"))
    if not rel:
        return fallback("file_missing", "missing", i18n.N_("в находке не указан файл"))
    path = find_file(Path(root), rel)
    if path is None:
        if file_presence(Path(root), rel) == "missing":
            return fallback("file_missing", "missing", i18n.N_("файла нет в клоне"))
        return fallback("file_missing", "ambiguous", i18n.N_("файл найден в клоне не однозначно "
                                                             "(несколько подходящих файлов или обход клона не "
                                                             "завершён)"))
    found = os.path.relpath(str(path), root).replace(os.sep, "/")
    language = language_of(found) or language
    if found != rel:
        notes.append(i18n.N_("файл найден по пути {path}").format(path=found))
    try:
        # открытый файл проверяется до чтения, читается не больше предела; по сведениям о нём кэшируется
        # маскированный текст
        raw, st, stable, real = _read_inside(root, str(path), MAX_FILE_BYTES)
    except _ReadRefused as e:
        if e.status == "too_large":
            return fallback("too_large", "too_large",
                            i18n.N_("файл больше {size} МБ – не читается").format(size=MAX_FILE_BYTES // (1024 * 1024)),
                            found)
        return fallback("file_missing", "unreadable", e.reason, found)
    except OSError:
        return fallback("file_missing", "unreadable", i18n.N_("файл не прочитан (нет доступа?)"), found)
    plain = decode_source(raw)
    if plain is None:
        return fallback("binary", "binary", i18n.N_("двоичный файл – не читается"), found)
    # Весь файл маскируется до вырезания среза: иначе ключ на границе среза или обрезанный токен не узнать.
    # У находки о секрете сама строка – секрет: значения всех литералов скрываются первыми, по разметке языка
    # (до общих правил, которые могли бы разрезать сырую строку R"(…)" или r#"…"#), и до обрезки длинных строк.
    hide = credential and mask_key is not None
    text = plain
    if mask_key is not None:
        text = _masked_file(real, plain, language, mask_key, hide, st if stable else None)
    lines = _split_lines(text)
    line = _line_of(f)
    if not lines:
        return fallback("file_missing", "empty", i18n.N_("файл пуст"), found)
    if line is not None and line > len(lines):
        return fallback("file_missing", "line_out_of_range",
                        i18n.N_("строка {line} за пределами файла (в файле {count} строк): репозиторий, похоже, "
                                "не на коммите скана").format(line=line, count=len(lines)), found)
    check = hash_check = "n/a"
    export_line_at = hash_check_at = None
    if line is None:
        notes.append(i18n.N_("в находке нет номера строки: показано начало файла"))
        signature, sig_line = "", None
        start, end, window, cut = _window(lines, 1, 0, before + after, max_chars, None)
    else:
        source_lines = _split_lines(plain)
        check, export_line_at = check_export_fragment(str(f.snippet or ""), source_lines, 1, line,
                                                      language=language)
        hash_check, hash_check_at = legacy_export_check(str(f.snippet or ""), source_lines, 1, line)
        signature, sig_line = enclosing_of(text, language, line)
        if hide:  # у находки о секрете все литералы среза – метки (mask_source_text с hide); строка срабатывания
            # целиком не скрывается (ADR-0117); сигнатура метода – тоже без литералов
            signature = mask_all_literals(signature, mask_key)[0]
        start, end, window, cut = _window(lines, line, before, after, max_chars, sig_line)
    notes.extend(cut)
    if hide:
        notes.append(SECRET_NOTE)
    masked = count_placeholders("\n".join(window + [signature])) if mask_key is not None else {}
    return CodeContext(status="ok", file=found, language=language, start_line=start, end_line=end,
                       target_line=line if line is not None and start <= line <= end else None, lines=window,
                       enclosing=signature, export_line_check=check, masked=masked, note="; ".join(notes),
                       export_line_at=export_line_at, export_line_check_version=EXPORT_LINE_CHECK_VERSION,
                       hash_check=hash_check, hash_check_at=hash_check_at)


# Заметки среза (CodeContext.note) уходят в промпт и в отпечаток случая (triage.case_hash): пишутся русским
# каноническим текстом при любом языке интерфейса (ADR-0158), перевод – только при показе (view.context_note).
NOTE_TEXTS = (
    SECRET_NOTE, i18n.N_("это не обычный файл – не читается"),
    i18n.N_("файл ведёт за пределы репозитория или подменён во время чтения – не читается"),
    i18n.N_("файл больше предела размера"), i18n.N_("файл вырос во время чтения и стал больше предела размера"),
    i18n.N_("срез сокращён до {chars} знаков: строки {start}–{end}"), i18n.N_("длинные строки обрезаны: {count}"),
    i18n.N_("строки кода в выгрузке тоже нет"),
    i18n.N_("{reason}: видна только строка кода из выгрузки, без окружения"),
    i18n.N_("строка из выгрузки сокращена до {chars} знаков"),
    i18n.N_("папка репозитория для кодовой базы не задана"), i18n.N_("папка репозитория не найдена"),
    i18n.N_("в находке не указан файл"), i18n.N_("файла нет в клоне"),
    i18n.N_("файл найден в клоне не однозначно (несколько подходящих файлов или обход клона не завершён)"),
    i18n.N_("файл найден по пути {path}"), i18n.N_("файл больше {size} МБ – не читается"),
    i18n.N_("файл не прочитан (нет доступа?)"), i18n.N_("двоичный файл – не читается"), i18n.N_("файл пуст"),
    i18n.N_("строка {line} за пределами файла (в файле {count} строк): репозиторий, похоже, не на коммите скана"),
    i18n.N_("в находке нет номера строки: показано начало файла"),
    # причины из triage.repo_dir_for (no_repo_note)
    i18n.N_("кодовая база не сопоставлена с папкой"), i18n.N_("клон отвязан: код берётся из срезов в базе"),
    i18n.N_("папка с клоном не найдена"), i18n.N_("папка с клоном пуста"),
)
