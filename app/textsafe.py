"""Невидимые знаки и текст для AppSec.Hub.

* Знаки направления текста (U+202A–202E, U+2066–2069, U+200E/200F, U+061C) и прочие невидимые знаки меняют то,
  как браузер показывает строку: человек видит не тот код, что получила модель (Trojan Source, CVE-2021-42574).
  В карточке они заменяются видимой меткой, в промпте – меткой «<U+202E>», из ответов модели и агента
  удаляются.
* Текст для Hub собирается и из недоверенных источников (ответ модели, ответ внешнего агента): из него
  удаляются теги HTML, опасные схемы адресов и невидимые знаки. Обобщения вида List<String> остаются.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from markupsafe import Markup, escape

# Заполнители Хангыль: выглядят как пробел, но буквами считаются
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0))
FILLER_CHARS = tuple(chr(code) for code in sorted(_FILLERS))
_ZWJ = 0x200D


def is_invisible(ch: str) -> bool:
    """Знак, которого не видно или который меняет показ соседних: категории Cf, Co, Cn, суррогаты, заполнители.
    Обычные пробелы, табуляция и переводы строк сюда не входят."""
    code = ord(ch)
    if code in _FILLERS:
        return True
    return unicodedata.category(ch) in ("Cf", "Co", "Cn", "Cs")


def has_invisible(text: Any) -> bool:
    return any(is_invisible(ch) for ch in str(text or ""))


def _keep_zwj(text: str, k: int) -> bool:
    """ZWJ внутри эмодзи (между двумя знаками не из ASCII и не невидимыми) оставляем."""
    if ord(text[k]) != _ZWJ or k == 0 or k + 1 >= len(text):
        return False
    before, after = text[k - 1], text[k + 1]
    return (ord(before) > 0x2000 and ord(after) > 0x2000 and not is_invisible(before)
            and not is_invisible(after) and unicodedata.category(before) == "So"
            and unicodedata.category(after) == "So")


def strip_invisible(text: Any) -> str:
    """Текст без невидимых знаков (ZWJ внутри эмодзи остаётся)."""
    source = str(text or "")
    if not has_invisible(source):
        return source
    return "".join(ch for k, ch in enumerate(source) if not is_invisible(ch) or _keep_zwj(source, k))


def code_point(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def visible_markers(text: Any) -> str:
    """Невидимые знаки -> «<U+202E>»: для промпта, чтобы модель видела их явно."""
    source = str(text or "")
    if not has_invisible(source):
        return source
    return "".join(f"<{code_point(ch)}>" if is_invisible(ch) else ch for ch in source)


def mark_invisible(text: Any) -> Markup:
    """Текст для страницы: экранирован, каждый невидимый знак заменён видимой меткой ⟨U+202E⟩."""
    source = str(text or "")
    if not has_invisible(source):
        return Markup(escape(source))
    out = []
    for ch in source:
        if is_invisible(ch):
            cp = code_point(ch)
            out.append(f'<span class="invis" title="Невидимый знак {cp}">⟨{cp}⟩</span>')
        else:
            out.append(str(escape(ch)))
    return Markup("".join(out))


# ============================================================================ текст для Hub

# Любой тег с атрибутами (<img src=x>, <details open ontoggle=…>) и закрывающий тег с пробелом
_TAG_WITH_ATTRS = re.compile(r"</?[A-Za-z][\w:-]*[\s/][^<>]*>")
# Элементы HTML без атрибутов (<b>, </script>, <br/>): полный список, чтобы List<String> не задеть
_HTML_ELEMENTS = (
    "a abbr acronym address applet area article aside audio b base basefont bdi bdo bgsound big blink blockquote "
    "body br button canvas caption center cite code col colgroup data datalist dd del details dfn dialog dir div "
    "dl dt em embed fieldset figcaption figure font footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup "
    "hr html i iframe image img input ins isindex kbd keygen label legend li link listing main map mark marquee "
    "math menu menuitem meta meter multicol nav nextid nobr noembed noframes noscript object ol optgroup option "
    "output p param picture plaintext portal pre progress q rb rp rt rtc ruby s samp script search section select "
    "slot small source spacer span strike strong style sub summary sup svg table tbody td template textarea tfoot "
    "th thead time title tr track tt u ul var video wbr xmp"
).split()
_HTML_TAG = re.compile(r"</?(?:" + "|".join(sorted(_HTML_ELEMENTS, key=len, reverse=True)) + r")\s*/?>", re.I)
_SCHEME = re.compile(r"\b(?:javascript|vbscript|data)\s*:", re.I)


def hub_clean(text: Any) -> str:
    """Текст из недоверенного источника для Hub: без тегов HTML, схем javascript:, vbscript:, data: и невидимых
    знаков. Обобщения вида List<String> и Map<K, V> остаются."""
    return remove_markup(strip_invisible(text))


def remove_markup(text: str) -> str:
    """Без тегов HTML и схем javascript:, vbscript:, data: – вторая половина hub_clean (невидимые знаки hub_clean
    снимает до неё)."""
    out = text
    for _ in range(3):  # вложенные «<<img …>img …>» снимаются за несколько проходов
        cleaned = _HTML_TAG.sub("", _TAG_WITH_ATTRS.sub("", out))
        if cleaned == out:
            break
        out = cleaned
    return _SCHEME.sub("", out)
