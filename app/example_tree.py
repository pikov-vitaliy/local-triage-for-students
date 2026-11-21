"""Хеш дерева учебного примера – один алгоритм для сборщика каталога (scripts/examples/build.py) и приложения
(app/examples.py), план стенда, раздел 4.4.

Срезается один корень архива (его имя зависит от репозитория). Пути – POSIX, UTF-8, NFC; порядок – по байтам пути.
В хеш пишется для каждого обычного файла: длина пути, путь, длина данных, данные – байты как в архиве, без
нормализации концов строк, без прав и времени. Маркер примера (MARKER) в хеш не входит."""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Iterable
from pathlib import Path

MARKER = ".local-triage-example.json"


def _norm(rel: str) -> str:
    return unicodedata.normalize("NFC", rel.replace("\\", "/"))


def tree_hash(entries: Iterable[tuple[str, bytes]]) -> str:
    """entries – (путь от корня дерева, данные) обычных файлов."""
    items = sorted(((_norm(rel).encode("utf-8"), data) for rel, data in entries if _norm(rel) != MARKER),
                   key=lambda item: item[0])
    digest = hashlib.sha256()
    for path, data in items:
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def tree_hash_of_dir(root: Path) -> tuple[str, int, int, int]:
    """Хеш распакованного дерева на диске: (sha256, число файлов, сумма байт, длина самого длинного пути)."""
    entries, total, longest = [], 0, 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == MARKER:
            continue
        data = path.read_bytes()
        entries.append((rel, data))
        total += len(data)
        longest = max(longest, len(rel))
    return tree_hash(entries), len(entries), total, longest
