"""Язык интерфейса (ADR-0158): английский по умолчанию, русский вторым.

Ключ перевода (msgid) – русский текст в коде, как в gettext: при русском языке `_()` возвращает его без изменений,
при английском – перевод из каталога `app/locales/en/*.json` или сам msgid, если перевода нет (тест полноты каталога
не даёт такому случаю дойти до выпуска).

Язык – одно значение на процесс: оператор один (docs/operating-conditions.md), фоновые потоки разбора видят тот же
язык без передачи контекста. Порядок: переопределение в ContextVar (тесты, разовые вызовы) → сохранённая настройка
`ui_language` → переменная окружения TRIAGE_LANG → английский.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import string
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

LANGS = ("en", "ru")
DEFAULT_LANG = "en"
SETTING_KEY = "ui_language"
LANG_NAMES = {"en": "English", "ru": "Русский"}  # названия языков не переводятся
CATALOG_DIR = Path(__file__).with_name("locales") / "en"
JS_PART = "js"  # часть каталога для app.js и других сценариев страницы

_override: contextvars.ContextVar[str | None] = contextvars.ContextVar("triage_lang", default=None)
_saved: str | None = None
_catalog: dict[str, str] | None = None
_parts: dict[str, dict[str, str]] | None = None
_conflicts: list[str] = []


class CatalogError(ValueError):
    """Испорченный каталог переводов: повтор ключа с другим переводом, не строка, не JSON."""


def normalize(value: Any) -> str | None:
    """'en' / 'ru' или None для неизвестного значения."""
    text = str(value or "").strip().casefold()
    return text if text in LANGS else None


def env_lang() -> str:
    return normalize(os.environ.get("TRIAGE_LANG")) or DEFAULT_LANG


def current() -> str:
    """Действующий язык интерфейса."""
    return _override.get() or _saved or env_lang()


def set_saved(value: Any) -> None:
    """Сохранённая в базе настройка (при запуске и после смены в «Настройках»); None – не задана."""
    global _saved
    _saved = normalize(value)


def saved() -> str | None:
    return _saved


@contextlib.contextmanager
def use(lang: str) -> Iterator[None]:
    """Временно другой язык в текущем контексте (тесты, построение текста на заданном языке)."""
    token = _override.set(normalize(lang) or DEFAULT_LANG)
    try:
        yield
    finally:
        _override.reset(token)


def _load() -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    merged: dict[str, str] = {}
    parts: dict[str, dict[str, str]] = {}
    for path in sorted(CATALOG_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as e:
            raise CatalogError(f"{path.name}: не JSON ({e})") from e
        if not isinstance(data, dict):
            raise CatalogError(f"{path.name}: ожидался объект JSON")
        part: dict[str, str] = {}
        for key, value in data.items():
            if not isinstance(value, str) or not isinstance(key, str):
                raise CatalogError(f"{path.name}: перевод «{key}» – не строка")
            if key in merged and merged[key] != value:
                # повтор с другим переводом: действует первый (по имени части), расхождение – в conflicts(); тест
                # полноты каталога (scripts/i18n_check.py) не пропускает такое в выпуск
                _conflicts.append(f"{path.name}: «{key}» – «{value}», а в другой части «{merged[key]}»")
                part[key] = merged[key]
                continue
            merged[key] = value
            part[key] = value
        parts[path.stem] = part
    return merged, parts


def catalog() -> dict[str, str]:
    global _catalog, _parts
    if _catalog is None:
        _conflicts.clear()
        _catalog, _parts = _load()
    return _catalog


def conflicts() -> list[str]:
    """Ключи, переведённые в разных частях каталога по-разному (после загрузки)."""
    catalog()
    return list(_conflicts)


def catalog_part(name: str) -> dict[str, str]:
    catalog()
    return dict((_parts or {}).get(name, {}))


def reload_catalog() -> None:
    """Перечитать каталог (тесты)."""
    global _catalog, _parts
    _catalog, _parts = None, None


def translate(msgid: str, lang: str | None = None) -> str:
    """Перевод без подстановок; msgid – если перевода нет или язык русский."""
    if (lang or current()) == "ru" or not msgid:
        return msgid
    return catalog().get(msgid, msgid)


def _(msgid: Any, /, **kw: Any) -> str:
    """Перевод строки интерфейса. kw – именованные подстановки {name} (str.format после перевода)."""
    if msgid is None:
        return ""
    text = translate(str(msgid))
    return text.format(**kw) if kw else text


def N_(msgid: str) -> str:
    """Метка строки, которую переводят при выводе (константы модуля): возвращает msgid как есть."""
    return msgid


def plural(count: Any, one: str, few: str, many: str) -> str:
    """Форма слова для числа. Русский: 1 находка, 2 находки, 5 находок, 21 находка. Английский: ключ каталога
    «one|few|many», значение «singular|plural» – 1 finding, 2 findings."""
    try:
        n = abs(int(count or 0))
    except (TypeError, ValueError):
        n = 0
    if current() != "ru":
        forms = catalog().get(f"{one}|{few}|{many}")
        if forms and "|" in forms:
            singular, plural_form = forms.split("|", 1)
            return singular if n == 1 else plural_form
    if n % 10 == 1 and n % 100 != 11:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


class Labels(dict):
    """Словарь подписей интерфейса: ключи – значения из базы и протоколов, значения – msgid. Чтение отдаёт перевод
    на действующем языке, ключи не меняются."""

    def __getitem__(self, key: Any) -> str:
        return translate(dict.__getitem__(self, key))

    def get(self, key: Any, default: Any = None) -> Any:
        if dict.__contains__(self, key):
            return self[key]
        return translate(default) if isinstance(default, str) else default

    def values(self):  # type: ignore[override]
        return [translate(v) for v in dict.values(self)]

    def items(self):  # type: ignore[override]
        return [(k, translate(v)) for k, v in dict.items(self)]

    def msgids(self) -> list[str]:
        return list(dict.values(self))

    def copy(self) -> Labels:
        return Labels(dict.items(self))


def placeholders(text: str) -> set[str]:
    """Имена подстановок {name} в строке (для проверки каталога)."""
    names = set()
    for _lit, field, _spec, _conv in string.Formatter().parse(text):
        if field:
            names.add(field.split(".")[0].split("[")[0])
    return names


def js_catalog() -> Mapping[str, str]:
    """Переводы для сценариев страницы: пусто при русском языке."""
    return {} if current() == "ru" else catalog_part(JS_PART)


def html_lang() -> str:
    return current()
