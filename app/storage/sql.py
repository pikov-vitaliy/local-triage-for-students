"""Привязки параметров: запросы приложения пишутся с позиционными «?», драйвер psycopg ждёт «%s».

Драйвер ищет маркеры, не обращая внимания на кавычки SQL, поэтому в запросе с параметрами каждый буквальный «%» удваивается
везде – и в литералах, и в комментариях; «?» переводится только вне литералов и комментариев (ADR-0128, раздел 5).
Запрос без параметров драйвер не разбирает: он уходит как есть. Запрос с именованными %(name)s лексер не проходит."""

from __future__ import annotations

from functools import lru_cache


class PlaceholderError(ValueError):
    """Запрос нельзя перевести: нумерованный маркер ?N или число параметров не совпало."""


@lru_cache(maxsize=8192)
def translate(sql: str) -> tuple[str, int]:
    """Текст для драйвера и число позиционных параметров."""
    out: list[str] = []
    count = 0
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'" or ch == '"':  # литерал или имя в кавычках; удвоенная кавычка – внутри него
            end = i + 1
            while end < n:
                if sql[end] == ch:
                    if end + 1 < n and sql[end + 1] == ch:
                        end += 2
                        continue
                    break
                end += 1
            out.append(sql[i:end + 1].replace("%", "%%"))
            i = end + 1
        elif sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end < 0 else end
            out.append(sql[i:end].replace("%", "%%"))
            i = end
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append(sql[i:end].replace("%", "%%"))
            i = end
        elif ch == "?":
            if i + 1 < n and sql[i + 1].isdigit():
                raise PlaceholderError(f"нумерованный маркер в запросе: {sql[i:i + 4]!r} – нужны именованные параметры")
            out.append("%s")
            count += 1
            i += 1
        elif ch == "%":
            out.append("%%")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out), count
