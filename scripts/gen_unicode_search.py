"""Тело SQL-функции unicode_search для базовой схемы: результат как normalize("NFC", ...).casefold() в Python.

В PostgreSQL 17 нет свёртки регистра по Юникоду, а lower() расходится с ней примерно у 250 букв («ß» и «ss», «ς» и «σ», лигатуры).
Сценарий сравнивает lower() сервера с Python и печатает функцию: lower, затем замена этих букв. Запускается при смене образа базы
или версии Python, результат вставляется в app/storage/migrations/postgresql/0001_baseline.sql. Проверка – по всем знакам Юникода,
tests/test_storage_store.py::test_unicode_search_equals_python_casefold_for_every_character.

Запуск: scripts/test-db.ps1, затем python scripts/gen_unicode_search.py (TRIAGE_TEST_DSN, как у тестов).
"""
from __future__ import annotations

import os
import unicodedata

import psycopg

BATCH = 5000


def characters() -> list[str]:
    """Все назначенные знаки, кроме суррогатов и частной области (NUL текст PostgreSQL не хранит)."""
    return [chr(c) for c in range(1, 0x110000) if unicodedata.category(chr(c)) not in ("Cn", "Cs", "Co")]


def literal(text: str) -> str:
    """Строка SQL только из знаков ASCII: файл схемы читается глазами и не зависит от редактора."""
    return "E'" + "".join(f"\\u{ord(c):04X}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08X}" for c in text) + "'"


def replacements(con: psycopg.Connection) -> tuple[dict[str, str], dict[str, str]]:
    """Что заменить до lower() и что после. До – буквы, чей lower совпадает с результатом другой буквы, которую менять нельзя
    («İ» даёт «i»). Знаки, которые NFC раскладывает, отдельно не считаются: их части сами входят в перечень."""
    chars = [c for c in characters() if unicodedata.normalize("NFC", c) == c]
    lowered: list[str] = []
    for start in range(0, len(chars), BATCH):
        lowered += [row[0] for row in con.execute("SELECT lower(x) FROM unnest(%s::text[]) WITH ORDINALITY AS t(x, n) ORDER BY n",
                                                  (chars[start:start + BATCH],))]
    keep = {low for char, low in zip(chars, lowered, strict=True) if low == char.casefold()}
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for char, low in zip(chars, lowered, strict=True):
        want = char.casefold()
        if low == want:
            continue
        if low in keep or after.get(low, want) != want:
            before[char] = want
        else:
            after[low] = want
    return before, after


def function_sql(before: dict[str, str], after: dict[str, str]) -> str:
    single = {low: want for low, want in after.items() if len(want) == 1}
    multi = {low: want for low, want in after.items() if len(want) > 1}
    body = "normalize(COALESCE(value, ''), NFC)"
    for char, want in before.items():
        body = f"replace({body}, {literal(char)}, {literal(want)})"
    body = f"translate(lower({body}),\n        {literal(''.join(single))},\n        {literal(''.join(single.values()))})"
    for low, want in multi.items():
        body = f"replace({body}, {literal(low)}, {literal(want)})"
    return f"CREATE FUNCTION unicode_search(value TEXT) RETURNS TEXT LANGUAGE SQL STABLE AS $body$\n    SELECT {body}\n$body$;"


def main() -> None:
    dsn = os.environ.get("TRIAGE_TEST_DSN", "host=127.0.0.1 port=5433 user=triage password=triage-test")
    with psycopg.connect(f"{dsn} dbname=postgres", autocommit=True) as con:
        print(function_sql(*replacements(con)))


if __name__ == "__main__":
    main()
