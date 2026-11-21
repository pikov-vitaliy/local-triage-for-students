"""Правила чистоты текста, общие для теста репозитория (tests/test_repo_hygiene.py) и стража пакета npm
(scripts/npm_package_guard.py): длинное тире, «ФСТЭК» без «России», пути с диска разработчика, управляющие знаки, номера
Hub по виду записи. Правила с реальными значениями (названия проектов и имена людей, подсеть стенда, слова о месте
работы) читаются из файла вне репозитория – переменная LOCAL_TRIAGE_PRIVATE_RULES или ~/.local-triage-private-rules.txt;
строки «раздел: регулярное выражение», разделы project, lan, place. Нет файла – эти правила ничего не находят.

Слова для поиска собираются из частей: иначе проверка нашла бы сама себя."""

from __future__ import annotations

import os
import re
from pathlib import Path

BINARY = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".xlsx", ".xls", ".zip", ".tar", ".pdf", ".woff", ".woff2"}

LONG_DASH = chr(0x2014)
FSTEC = "ФСТ" + "ЭК"
FSTEC_BARE = re.compile(FSTEC + r"(?!\s+России)")
# Названия поставщиков моделей и ИИ-инструментов в репозитории допустимы: прежний запрет вводился, чтобы по коду не
# было видно, какими агентами он сделан; с внешними провайдерами он потерял смысл.
LOCAL_PATHS = re.compile(r"\b[" + "V" + r"]:[\\/]|\bUsers[\\/]")
NEVER = re.compile(r"(?!)")


def _private_rules() -> dict[str, re.Pattern[str]]:
    """Правила с реальными значениями из файла вне репозитория; нет файла – пусто."""
    name = os.environ.get("LOCAL_TRIAGE_PRIVATE_RULES", "").strip()
    path = Path(name) if name else Path.home() / ".local-triage-private-rules.txt"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        if name:  # путь задан явно: молча отключить правила нельзя – проверка выглядела бы успешной (ревью круга 9)
            raise RuntimeError(f"Файл правил LOCAL_TRIAGE_PRIVATE_RULES={name} не прочитан: {error}") from error
        return {}
    parts: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        parts.setdefault(key.strip(), []).append(value.strip())
    flags = {"place": re.I}
    return {key: re.compile("|".join(f"(?:{v})" for v in values), flags.get(key, 0)) for key, values in parts.items()}


_PRIVATE = _private_rules()
PRIVATE_RULES_LOADED = bool(_PRIVATE)
# реальные проекты и люди, адрес стенда – только по файлу вне репозитория; в примерах и тестах – адреса RFC 5737
REAL_PROJECT = _PRIVATE.get("project", NEVER)
STAND_LAN = _PRIVATE.get("lan", NEVER)
# управляющие знаки в тексте – след порченой правки (heredoc превращает \b в забой, \t в табуляцию)
CONTROL = re.compile("[" + chr(0) + "-" + chr(8) + chr(11) + chr(12) + chr(14) + "-" + chr(31) + chr(127) + "]")
# Номера Hub проекта владельца (дефекты, находки) в репозиторий не попадают (бэклог 119). Настоящих номеров страж не
# знает и знать не должен, поэтому правило – по виду записи: после знака номера, в словах «находка NNNNN» и в ссылках
# Hub допустимы только заведомо вымышленные номера – начинающиеся с 9 (от пяти цифр) или из рядов тестовых данных:
# 12345 и 123456 (образцы формата), 1001NN (демо SAST), 5100NN, 7300N (демо SCA), 37NNNN (шесть цифр), 6000NN.
INVENTED = re.compile(r"9\d{4,}|12345\d?|1001\d\d|5100\d\d|7300\d|37\d{4}|6000\d\d")
_NO = chr(0x2116)
# номер документа, а не номер Hub: «приказ № 1234», «постановление от … № 1236»
_DOCUMENT = re.compile(r"(?i)(?:приказ|постановлени|распоряжени|закон|письм|ГОСТ|протокол|решени[еяю] комисси)")
# между словом о документе и его номером не должно быть слова об объекте Hub: «согласно письму закрыт дефект …»
_HUB_WORD = re.compile(r"(?i)дефект|находк|defect|issue|\bID")
_SIGN = re.compile(_NO + r"((?:[\s,*_`" + _NO + r"]|\bи\b)*\d{4,}(?!\d))+")
# номер после слова о находке, в том числе в разметке и в перечислении через запятую и «и»
_FINDING = re.compile(r"(?i)\bнаходк[а-яё]*((?:[\s,:*_`" + _NO + r"]|\bи\b)*\d{5,7}(?!\d))+")
_LINK = re.compile(r"(?:#/defects?/|/issues/[A-Za-z_]+/)(\d{4,})")


def hub_number_hits(text: str) -> list[tuple[str, str, int]]:
    """Номера, записанные как номера Hub и не входящие в вымышленные: (что, запись, место в тексте)."""
    hits = []
    for found in _SIGN.finditer(text):
        before = text[max(0, found.start() - 80):found.start()].split("\n")[-1]
        words = list(_DOCUMENT.finditer(before))
        if words and not _HUB_WORD.search(before[words[-1].end():]):
            continue  # номер документа
        if any(not INVENTED.fullmatch(number) for number in re.findall(r"\d{4,}", found.group(0))):
            hits.append(("номер после знака номера", found.group(0), found.start()))
    for found in _FINDING.finditer(text):
        for number in re.findall(r"\d{5,7}", found.group(0)):
            if not INVENTED.fullmatch(number):
                hits.append(("номер находки", found.group(0), found.start()))
                break
    for found in _LINK.finditer(text):
        if not INVENTED.fullmatch(found.group(1)):
            hits.append(("номер в ссылке Hub", found.group(0), found.start()))
    return hits

# Документы и пакет не называют место работы автора – слова из того же файла вне репозитория
PLACE_WORDS = _PRIVATE.get("place", NEVER)
