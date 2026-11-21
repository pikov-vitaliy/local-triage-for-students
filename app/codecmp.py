"""Отпечаток сравнения кода находок одной группы SAST (ADR-0092).

Находки с одинаковыми правилом, CWE, путём файла и строкой (группа ADR-0089) в разных кодовых базах могут стоять на
разном коде. Решение и текст должны совпадать только у находок с одинаковым кодом вокруг строки срабатывания. Отпечаток
считается по сохранённому срезу находки (`cases.context_json`) и отделён от отпечатков вердиктов и кэша: его смена не
трогает ни вердикты, ни отметки.

Окно – строки «срабатывание −15 … +5» точно как в срезе (пробелы значимы: в Python и строковых литералах они меняют
смысл), положение строки срабатывания в окне и язык. Пустой отпечаток – «сравнение недостоверно»: среза нет или он не
«ok», в окне есть обрезанная длинная строка или маскированное значение, окно не помещается в срез (сверху – если срез
не начинается с первой строки файла; снизу – всегда: где кончается файл, по срезу не установить).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from app.context import CUT_MARK
from app.masking import PLACEHOLDER_RE

VERSION = "cmp-1"
BEFORE = 15  # строк над строкой срабатывания
AFTER = 5    # строк под ней


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def code_cmp(context: Mapping[str, Any] | None) -> str:
    """Отпечаток сравнения по срезу находки или "" – сравнение недостоверно."""
    ctx = context or {}
    if str(ctx.get("status") or "") != "ok":
        return ""
    lines = ctx.get("lines")
    if not isinstance(lines, list) or not lines or not all(isinstance(x, str) for x in lines):
        return ""
    start, target = _int(ctx.get("start_line")), _int(ctx.get("target_line"))
    if start is None or target is None or start < 1:
        return ""
    end = start + len(lines) - 1
    if not start <= target <= end:
        return ""
    low, high = target - BEFORE, target + AFTER
    if low < start and start != 1:  # окно сверху не помещается, а срез начинается не с начала файла
        return ""
    if high > end:  # конец файла по срезу не установить
        return ""
    window = lines[max(low, start) - start: high - start + 1]
    if any(CUT_MARK in line or PLACEHOLDER_RE.search(line) for line in window):
        return ""
    position = target - max(low, start)
    payload = "\n".join([VERSION, str(ctx.get("language") or ""), str(position), *window])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
