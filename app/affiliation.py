"""Маска принадлежности (ADR-0118): слова, по которым код можно отнести к организации – её название, сокращение,
город, домен, – заменяются на «org»/«орг» в каждом запросе к модели, локальной или внешней. Это важнее секретов:
секреты в коде уже проверены до выгрузки, а связь кода с организацией – то, что
прежде всего нельзя отдавать наружу.

Список слов – настройка «Слова принадлежности» (таблица settings, ключ affiliation_words); в репозитории списка
нет, он задаётся на установке. Слово сравнивается без учёта регистра с частями идентификаторов и словами текста:
«AcmeRuClient» делится на Acme, Ru, Client; «ACME города Exampletown» – на три слова. Поэтому «acmeist» и
«Contora» не трогаются. Слово с «*» в конце совпадает по началу («Контор*» – Контора, Конторы, Конторский).
Замена сохраняет вид части: ACME → ORG, Acme → Org, acme → org, кириллица – орг. Части выделяются по регистру
Unicode (любой алфавит): строчная → Прописная и прописные перед Прописной+строчная (ACMEData → ACME, Data).

Граница – app/llm_http.py ServerClient._request: в теле запроса к серверу модели маскируются сообщения
(`messages[].content`, в том числе блоки Messages API и ответы инструментов) и системный текст (`system`);
служебные поля протокола – имя модели, схема ответа, описания и имена инструментов, роли – не трогаются, иначе
запрос ушёл бы к несуществующей модели или с противоречивой схемой. Журнал обмена записывает уже заменённый текст.
Точный запрос OSV (app/osv.py) идёт тем же транспортом без маски: ему нужны настоящие имена пакетов.
Карточка и база приложения хранят код как есть: оператор – сотрудник организации, маска ему не нужна; отпечатки
срезов и решений от маски не зависят.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

MAX_WORDS = 200  # слов в списке
MAX_WORD = 50  # букв в слове
# слово списка: буквы любого алфавита (без цифр, точек и «_»), в конце допустима «*» – совпадение по началу
WORD_RE = re.compile(r"[^\W\d_]{2,50}\*?")

_LETTERS = re.compile(r"[^\W\d_]+")  # буквенные части текста: идентификаторы режутся по цифрам, «_», точкам
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
_TEXT_KEYS = ("content", "text")  # поля с текстом для модели внутри сообщений и блоков

_rules: tuple[tuple[str, bool], ...] = ()  # (слово в casefold, по началу?)
_given: tuple[str, ...] = ()  # слова как заданы – для страниц и проверок


def configure(words: Iterable[str]) -> None:
    """Задать список слов (при запуске приложения и после сохранения «Настроек»). Пустой список – маски нет."""
    global _rules, _given
    rules = []
    given = []
    for word in words:
        text = str(word or "").strip()
        if not text.rstrip("*"):
            continue
        rules.append((text.rstrip("*").casefold(), text.endswith("*")))
        given.append(text)
    _rules = tuple(rules)
    _given = tuple(given)


def words() -> tuple[str, ...]:
    """Действующие слова списка (как заданы: с «*» у совпадений по началу) – для проверок и страниц."""
    return _given


def active() -> bool:
    return bool(_rules)


def _matches(part: str) -> bool:
    folded = part.casefold()
    return any(folded == word or (prefix and folded.startswith(word)) for word, prefix in _rules)


def _replacement(part: str) -> str:
    base = "орг" if _CYRILLIC.match(part[0]) else "org"
    if len(part) > 1 and part.isupper():
        return base.upper()
    if part[0].isupper():
        return base.capitalize()
    return base


def _parts(segment: str) -> list[str]:
    """Части буквенной последовательности по регистру Unicode: граница между строчной и Прописной и перед последней
    прописной в ряду прописных, за которой идёт строчная (getACMEData → get, ACME, Data). Буквы без регистра
    (иероглифы и т. п.) границ не дают – такая последовательность сравнивается целиком."""
    parts = []
    start = 0
    n = len(segment)
    for i in range(1, n):
        prev, cur = segment[i - 1], segment[i]
        if (prev.islower() and cur.isupper()) or (
                prev.isupper() and cur.isupper() and i + 1 < n and segment[i + 1].islower()):
            parts.append(segment[start:i])
            start = i
    parts.append(segment[start:])
    return parts


def mask_text(text: str) -> str:
    """Текст с заменёнными словами принадлежности; без списка или без текста – тот же объект."""
    if not _rules or not text:
        return text

    def segment(m: re.Match) -> str:
        return "".join(_replacement(p) if _matches(p) else p for p in _parts(m.group(0)))

    return _LETTERS.sub(segment, text)


def _mask_block(value: Any) -> Any:
    """Строка – текст; словарь-блок – его поля content/text (строка или вложенные блоки); список – поэлементно."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        return [_mask_block(item) for item in value]
    if isinstance(value, dict):
        out = dict(value)
        for key in _TEXT_KEYS:
            if key in out:
                out[key] = _mask_block(out[key])
        return out
    return value


def mask_payload(payload: Any) -> Any:
    """Тело запроса к модели с заменой в сообщениях (`messages`) и системном тексте (`system`); остальные поля –
    имя модели, схема ответа, инструменты, параметры – как есть. Без списка или не словарь – тот же объект."""
    if not _rules or not isinstance(payload, dict):
        return payload
    out = dict(payload)
    if isinstance(out.get("messages"), list):
        out["messages"] = [_mask_block(m) for m in out["messages"]]
    if "system" in out:
        out["system"] = _mask_block(out["system"])
    return out


def mask_messages(messages: list[dict]) -> list[dict]:
    """Сообщения как уйдут модели (предпросмотр)."""
    return [_mask_block(m) for m in messages] if _rules else messages
