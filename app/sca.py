"""Разбор SCA без исходного кода: компоненты проекта, пакет для внешних агентов, их ответы, соответствие
идентификаторов AST → CVE и текст для AppSec.Hub.

Что уходит наружу. В пакет для внешних агентов попадают только экосистема и имя библиотеки, её версия,
идентификаторы уязвимостей и версия исправления из отчёта Hub. Кодовых баз, путей зависимостей, номеров находок,
названия системы и кода в пакете нет.

Что приходит снаружи. Ответ агента – данные, а не указания: из него берутся только поля по схеме из задания,
типы приводятся, длины ограничиваются, управляющие и невидимые знаки убираются, ссылки – только http и https;
ответ по библиотеке, которой нет в проекте, не сохраняется.

Вывод по библиотеке (update – обновить, not_applicable – не применимо, unclear – неясно) в решении человека
хранится вердиктом находки, как у SAST: update – true_positive, not_applicable – false_positive, unclear –
uncertain. Статус в Hub для них берётся из настроек.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

from app.config import DEFAULT_STATUS_MAP
from app import cvss
from app.ecosystem import canon_ecosystem
from app.hub_import import decode_text, parse_cves  # noqa: F401 – decode_text: общий декодер
from app.models import Finding, ScaAnswer
from app.textsafe import hub_clean, strip_invisible

ANSWER_FORMAT = "local-triage/sca-answers/1"
DEFAULT_SOURCE = "внешний агент"

CONCLUSION_LABELS = {"update": "обновить", "not_applicable": "не применимо", "unclear": "неясно"}
# Подписи вывода в выборе решения человека: «не применимо» – ложное срабатывание (docs/hub-format.md). Текст для Hub,
# отборы и ответ агента остаются с CONCLUSION_LABELS
DECISION_LABELS = {**CONCLUSION_LABELS,
                   "not_applicable": "ложное срабатывание (компонент или уязвимость определены ошибочно)"}
CONCLUSION_VERDICT = {"update": "true_positive", "not_applicable": "false_positive", "unclear": "uncertain"}
VERDICT_CONCLUSION = {verdict: conclusion for conclusion, verdict in CONCLUSION_VERDICT.items()}

# Отборы на странице SCA: (ключ из ?show=, подпись)
FILTERS = (("", "Все"), ("urgent", "Срочные"), ("no_answer", "Без ответа агента"), ("update", "Обновить"),
           ("not_applicable", "Совет агента: не применимо"), ("unclear", "Неясно"), ("unreviewed", "Непроверенные"),
           ("not_entered", "Не внесены в Hub"), ("todo", "К разбору"), ("in_defect", "В дефекте"), ("no_defect", "Без дефекта"))
FILTER_KEYS = tuple(key for key, _ in FILTERS)

# Пределы разбора ответа агента и соответствия AST → CVE
MAX_ANSWER_BYTES = 4 * 1024 * 1024
MAX_MAP_BYTES = 8 * 1024 * 1024
MAX_ANSWERS = 5000
MAX_MAP_ROWS = 200_000
MAX_COMPONENT = 300
MAX_VERSION = 100
MAX_SOURCE = 100
MAX_EXPLANATION = 4000
MAX_LINKS = 10
MAX_URL = 500
MAX_IDS = 50
MAX_ALIASES = 20
SCAN_ATTEMPTS = 40  # сколько раз искать начало JSON в тексте с пояснениями

# В тексте для Hub: пояснение агента – не длиннее, ссылок – не больше
COMMENT_EXPLANATION = 400
COMMENT_LINKS = 2

# Особые знаки задаются кодами: в исходном тексте их не видно
NBSP, BOM = chr(0xA0), chr(0xFEFF)
EM_DASH, NB_HYPHEN = chr(0x2014), chr(0x2011)
# Невидимые знаки и знаки направления текста: в ответе агента их быть не должно (подмена отображения)
_INVISIBLE = "".join(chr(c) for c in (*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF))
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f" + _INVISIBLE + "]")
_SPACES = re.compile("[ \t\r\n" + NBSP + chr(0x2028) + chr(0x2029) + "]+")
_DASHES = str.maketrans({EM_DASH: "–", NB_HYPHEN: "-"})  # длинное тире -> «–», неразрывный дефис -> «-»
_ID = re.compile(r"[A-Za-z]{2,10}(?:[-:][A-Za-z0-9._]+){1,5}")
_FENCE = re.compile(r"```[ \t]*[A-Za-z0-9_+.-]*[ \t]*\r?\n(.*?)(?:\r?\n)?[ \t]*```", re.S)
_URL = re.compile(r"https?://[^\s<>\"'`\[\]()]+", re.I)
_VERSION_HEAD = re.compile(r"\d+(?:[._-]\d+)*")
_CSV_RISKY = ("=", "+", "-", "@", "\t", "\r")

# Цели соответствия AST → …: публичные идентификаторы, у которых есть страницы в открытых базах
TARGET_PREFIXES = ("CVE", "GHSA", "BDU", "PYSEC", "GO", "RUSTSEC", "OSV", "GSD")

_CONCLUSION_WORDS = {
    "update": "update", "upgrade": "update", "fix": "update", "обновить": "update", "обновление": "update",
    "обновиться": "update", "not_applicable": "not_applicable", "not applicable": "not_applicable",
    "not-applicable": "not_applicable", "n/a": "not_applicable", "na": "not_applicable",
    "not_affected": "not_applicable", "not affected": "not_applicable", "не применимо": "not_applicable",
    "неприменимо": "not_applicable", "не затронута": "not_applicable", "unclear": "unclear", "unknown": "unclear",
    "uncertain": "unclear", "неясно": "unclear", "неизвестно": "unclear", "непонятно": "unclear",
}


class ScaInputError(ValueError):
    """Ответ агента или соответствие AST → CVE не прочитать. Текст – по-русски, для показа в интерфейсе."""


TOO_DEEP = "В JSON слишком глубокая вложенность: это не ответ по схеме из задания."


# ============================================================================ текст

def one_line(value: Any, limit: int) -> str:
    """Одна строка без управляющих и невидимых знаков и лишних пробелов, не длиннее limit."""
    text = _CONTROL.sub("", strip_invisible("" if value is None else str(value)))
    return _SPACES.sub(" ", text).strip()[:limit].strip()


def text_block(value: Any, limit: int) -> tuple[str, bool]:
    """Текст с абзацами: переводы строк сохраняются, управляющие знаки убираются, пустых строк подряд не больше
    одной. Возвращает (текст, обрезан ли)."""
    if value is None:
        return "", False
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(x) for x in value if x is not None)
    text = str(value).replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    text = _CONTROL.sub("", strip_invisible(text))
    lines = [re.sub("[ " + NBSP + "]+", " ", line).strip() for line in text.split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if len(text) > limit:
        return text[:limit].rstrip() + "…", True
    return text, False


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def short_text(text: Any, limit: int) -> str:
    """Начало текста в одну строку: целыми предложениями, если получается, иначе по слову, с «…»."""
    line = one_line(text, 100_000)
    if len(line) <= limit:
        return line
    cut = line[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if end >= limit // 2:
        return cut[:end + 1]
    space = cut.rfind(" ")
    return (cut[:space] if space > limit // 2 else cut).rstrip(" ,;:") + "…"


def plural(count: int, one: str, few: str, many: str) -> str:
    """Форма слова для числа: 1 библиотека, 2 библиотеки, 5 библиотек."""
    n = abs(int(count))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


# ============================================================================ идентификаторы и ссылки

def norm_id(value: Any) -> str:
    """Идентификатор уязвимости: CVE – в виде CVE-ГГГГ-N…; прочие (AST-…, GHSA-…, BDU:…) – с приставкой
    в верхнем регистре. Не похоже на идентификатор – ""."""
    text = one_line(value, 80)
    if not text:
        return ""
    cves = parse_cves(text)
    if cves and len(cves[0]) == len(text):
        return cves[0]
    if not _ID.fullmatch(text):
        return ""
    if not re.search(r"\d", text) and not text.upper().startswith("GHSA"):
        return ""
    prefix, sep, rest = re.split(r"([-:])", text, maxsplit=1)
    return prefix.upper() + sep + rest


def is_target_id(value: str) -> bool:
    """Идентификатор из открытой базы (CVE, GHSA, BDU и подобные): им можно сопоставить номер AST."""
    return bool(value) and re.split(r"[-:]", value, maxsplit=1)[0].upper() in TARGET_PREFIXES


def norm_link(value: Any) -> str:
    """Ссылка на источник: только http и https, без пробелов, кавычек, имени и пароля в адресе, только знаки ASCII.
    Ссылка в разметке Markdown («[OSV](https://…)») тоже принимается. Не подходит – ""."""
    text = str(value or "").strip()
    if not text:
        return ""
    # Строка, которая сама начинается как адрес, но содержит табуляцию, перевод строки или другой управляющий знак, –
    # отказ целиком, а не обрезка до префикса: браузер такие знаки внутри адреса молча удаляет (WHATWG)
    if re.match(r"https?://", text, re.I) and _ANY_CONTROL.search(text):
        return ""
    if not re.fullmatch(r"https?://\S+", text, re.I) or re.search(r"[<>\"'`\[\]]", text):
        found = _URL.search(text)
        if found is None:
            return ""
        text = found.group(0)
    # знаки в конце, которые обычно – пунктуация предложения, снимаются; но «..» в конце пути – сегмент, который браузер
    # удалит, а не пунктуация: такой адрес отвергается до снятия знаков
    try:
        if any(_DOT_SEGMENT.fullmatch(segment) for segment in urlsplit(text).path.split("/")):
            return ""
    except ValueError:
        return ""
    text = text.rstrip(".,;:")
    while text.endswith(")") and text.count("(") < text.count(")"):  # закрывающая скобка предложения, а не пути
        text = text[:-1].rstrip(".,;:")
    return text if _strict_url(text) is not None else ""


# управляющие знаки, включая табуляцию, переводы строки, DEL и невидимые знаки: в адресе недопустимы
_ANY_CONTROL = re.compile("[\x00-\x1f\x7f" + _INVISIBLE + "]")
# знаки, которые браузер в пути заменяет на %XX (набор кодирования пути WHATWG, кроме пробела и «#», «?» – они разделители):
# принятый адрес не должен менять запись пути
_PATH_REENCODED = re.compile(r"[\"<>`{}]")
_DOT_SEGMENT = re.compile(r"(?:\.|%2e){1,2}", re.I)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_LABEL = re.compile(r"\d+|0x[0-9a-f]*", re.I)


def _strict_url(text: str) -> tuple[str, str] | None:
    """Адрес без неоднозначных форм -> (имя сайта в нижнем регистре, путь), иначе None.

    Проверка идёт по тому, что понимает браузер (WHATWG URL), а не по исходной строке: браузер декодирует проценты в
    имени сайта, разбирает IPv4 в десятичной, восьмеричной и шестнадцатеричной записи («127.0.0x0.1») и удаляет
    сегменты «.» и «..» (в том числе «%2e») из пути. Полного разбора на сервере нет, поэтому такие формы отвергаются, а
    не приводятся: имя сайта – только латинские буквы, цифры и дефис по меткам, без «%», без конечной точки и без
    последней метки из цифр или «0x…» (браузер считает её адресом IPv4); сегмент пути «.» или «..», записанный и как
    «%2e», – отказ; повторное декодирование не применяется. Схема http или https, без имени и пароля, порт 80 или 443,
    адреса IP и локальные имена не принимаются."""
    # общие ограничения одним слоем для norm_link и is_primary_source: длина, только ASCII, ни пробелов, ни управляющих
    # знаков (табуляция, CR и LF тоже), ни обратной косой черты
    if (not text or len(text) > MAX_URL or not text.isascii() or "\\" in text or _ANY_CONTROL.search(text)
            or re.search(r"\s", text)):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        with_login = parts.username is not None or parts.password is not None
        port = parts.port  # неверный порт – ValueError
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or with_login or port not in (None, 80, 443):
        return None
    labels = host.split(".")
    if (len(labels) < 2 or len(host) > 253 or not all(_HOST_LABEL.fullmatch(x) for x in labels)
            or _NUMERIC_LABEL.fullmatch(labels[-1]) or not _public_host(host)
            or not all(_valid_a_label(x) for x in labels)):
        return None
    if any(_DOT_SEGMENT.fullmatch(segment) for segment in parts.path.split("/")) or _PATH_REENCODED.search(parts.path):
        return None
    return host, parts.path


def _valid_a_label(label: str) -> bool:
    """Метка «xn--…» должна быть настоящим punycode и расшифровываться в слово с не-ASCII знаками; иначе браузер адрес не
    разберёт (WHATWG: ошибка IDNA), а принять его за обычное имя нельзя."""
    if not label.startswith("xn--"):
        return True
    try:
        return not label.encode("ascii").decode("idna").isascii()
    except UnicodeError:
        return False


# Адреса внутренней сети и локальные имена: ссылка ответа агента на них не принимается
_LOCAL_ZONES = (".local", ".internal", ".lan", ".corp", ".localhost", ".home", ".intranet", ".localdomain")


def _public_host(host: str) -> bool:
    """Имя сайта в интернете: не адрес IP (IPv4 и IPv6), не localhost, с точкой, не во внутренней зоне."""
    host = host.lower().rstrip(".")
    if not host or ":" in host or host == "localhost" or "." not in host:
        return False
    if re.fullmatch(r"[\d.]+", host) or re.fullmatch(r"0x[0-9a-f.x]+", host):  # 127.0.0.1, 2130706433, 0x7f.1
        return False
    if _NUMERIC_LABEL.fullmatch(host.rsplit(".", 1)[-1]):  # последняя метка из цифр или 0x…: браузер разберёт как IPv4
        return False
    return not host.endswith(_LOCAL_ZONES)


# Первоисточники из задания: только такие ссылки попадают в текст для Hub, остальные видны лишь в карточке.
# (имя сайта, начало пути или "")
PRIMARY_SOURCES = (
    ("osv.dev", ""), ("github.com", "/advisories"), ("nvd.nist.gov", ""), ("cve.org", ""), ("www.cve.org", ""),
    ("bdu.fstec.ru", ""), ("central.sonatype.com", ""), ("repo1.maven.org", ""), ("pypi.org", ""),
    ("npmjs.com", ""), ("www.npmjs.com", ""), ("nuget.org", ""), ("www.nuget.org", ""), ("pkg.go.dev", ""),
    ("crates.io", ""),
)


# Путь первоисточника, у которого путь существенен: страницы GitHub Advisory Database – «/advisories» (список) или
# «/advisories/GHSA-xxxx-xxxx-xxxx» (запись), не любой путь с этим началом
_ADVISORY_PATH = re.compile(r"/advisories(?:/GHSA(?:-[a-z0-9]{4}){3})?/?", re.I)


def is_primary_source(url: str) -> bool:
    """Ссылка на первоисточник из задания: точное имя сайта (или его поддомен) и, где нужно, точный формат пути.
    Адрес сначала проходит ту же строгую проверку, что в norm_link (имя сайта и путь в том виде, как их разберёт
    браузер): неоднозначный адрес первоисточником не считается. Для сайта с путём (GitHub Advisory Database) имя сайта
    должно быть точным, без поддоменов."""
    strict = _strict_url(str(url or ""))
    if strict is None:
        return False
    host, path = strict
    for site, prefix in PRIMARY_SOURCES:
        if prefix:
            if host == site and _ADVISORY_PATH.fullmatch(path):
                return True
        elif host == site or host.endswith("." + site):
            return True
    return False


def link_label(url: str) -> str:
    """Подпись ссылки: сайт и начало пути – по ним видно, куда она ведёт."""
    parts = urlsplit(url)
    label = (parts.hostname or "").removeprefix("www.") + parts.path.rstrip("/")
    return label if len(label) <= 70 else label[:69] + "…"


def check_links(vuln_id: str) -> list[tuple[str, str]]:
    """Где проверить идентификатор уязвимости в открытых базах: [(подпись, адрес)]. У номеров AST публичных
    страниц нет."""
    upper = vuln_id.upper()
    if upper.startswith("CVE-"):
        return [("NVD", f"https://nvd.nist.gov/vuln/detail/{vuln_id}"),
                ("OSV", f"https://osv.dev/vulnerability/{vuln_id}")]
    if upper.startswith("GHSA-"):
        return [("GitHub", f"https://github.com/advisories/{vuln_id}"),
                ("OSV", f"https://osv.dev/vulnerability/{vuln_id}")]
    if upper.startswith("BDU:"):
        return [("БДУ ФСТЭК России", f"https://bdu.fstec.ru/vul/{vuln_id[4:]}")]
    if re.split(r"[-:]", upper, maxsplit=1)[0] in ("PYSEC", "GO", "RUSTSEC", "OSV", "GSD"):
        return [("OSV", f"https://osv.dev/vulnerability/{vuln_id}")]
    return []


def finding_ids(f: Finding | Mapping[str, Any]) -> list[str]:
    """Идентификаторы уязвимостей находки: сначала номера AST, GHSA и BDU, затем CVE."""
    if isinstance(f, Mapping):
        vuln_ids, cves = f.get("vuln_ids") or [], f.get("cve") or []
    else:
        vuln_ids, cves = f.vuln_ids or [], f.cve or []
    return _dedupe([*vuln_ids, *cves])


def aliases_for(ids: Iterable[str], ast_map: Mapping[str, list[str]],
                answer: Mapping[str, Any] | None = None) -> dict[str, dict]:
    """Что известно о соответствии идентификаторов: {идентификатор: {"aliases": [...], "origin": "map" | "agent"
    | ""}}. Загруженное соответствие AST → CVE (выгрузка поставщика) важнее ответа агента; пустой список
    с origin "agent" – агент соответствия не нашёл. Идентификаторы сравниваются без учёта регистра: хвост GHSA
    в отчёте и в ответе бывает записан по-разному."""
    vendor = {str(k).casefold(): v for k, v in ast_map.items()}
    agent = {str(k).casefold(): v for k, v in ((answer or {}).get("ids") or {}).items()}
    result: dict[str, dict] = {}
    for vuln_id in ids:
        key = vuln_id.casefold()
        known = [x for x in vendor.get(key) or [] if x.casefold() != key]
        if known:
            result[vuln_id] = {"aliases": _dedupe(known), "origin": "map"}
        elif key in agent:
            result[vuln_id] = {"aliases": _dedupe(x for x in agent[key] or [] if x.casefold() != key),
                               "origin": "agent"}
        else:
            result[vuln_id] = {"aliases": [], "origin": ""}
    return result


def public_ids_text(ids: Iterable[str], aliases: Mapping[str, dict]) -> str:
    """«CVE-2099-10002, CVE-2099-10001» – публичные идентификаторы находки (CVE, GHSA, БДУ) и её известные публичные
    соответствия, без внутренних номеров AST (ADR-0101): для текстов, которые уходят в Hub. Прежние форматы
    (describe_ids) не меняются: по ним узнаются старые отметки."""
    from app.sca_text import kind_of
    out: list[str] = []
    for vuln_id in ids:
        for candidate in [vuln_id, *((aliases.get(vuln_id) or {}).get("aliases") or [])]:
            text = str(candidate or "").strip()
            if text and kind_of(text) != "other" and text not in out:
                out.append(text)
    return ", ".join(out)


def describe_ids(ids: Iterable[str], aliases: Mapping[str, dict]) -> str:
    """«AST-2026-000101 (CVE-2099-10002), CVE-2099-10001» – идентификаторы с найденными соответствиями."""
    parts = []
    for vuln_id in ids:
        known = (aliases.get(vuln_id) or {}).get("aliases") or []
        parts.append(f"{vuln_id} ({', '.join(known)})" if known else vuln_id)
    return ", ".join(parts)


# ============================================================================ версии

def version_key(value: Any) -> tuple[int, ...] | None:
    """Числовая часть версии для сравнения: «2.3.9.RELEASE» -> (2, 3, 9), «v1.0.10» -> (1, 0, 10); без цифр – None."""
    text = str(value or "").strip().lstrip("vV")
    m = _VERSION_HEAD.match(text)
    return tuple(int(x) for x in re.findall(r"\d+", m.group(0))) if m else None


def compare_versions(a: Any, b: Any) -> int | None:
    """-1, 0 или 1 по числовой части версий; сравнить нельзя – None."""
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    width = max(len(ka), len(kb))
    ka, kb = ka + (0,) * (width - len(ka)), kb + (0,) * (width - len(kb))
    return (ka > kb) - (ka < kb)


def major_change(current: Any, target: Any) -> bool:
    """Обновление меняет старшую версию (2.x -> 3.x): возможны несовместимые изменения."""
    ka, kb = version_key(current), version_key(target)
    return bool(ka and kb and ka[0] != kb[0])


def all_versions(text: Any) -> list[str]:
    """Все версии из перечня версий исправления Hub без повторов («2.3.9, 3.0.1» -> [«2.3.9», «3.0.1»]) – тем же
    разбором, что и в задании исследования (hub_fix_candidate)."""
    out: list[str] = []
    for part in re.split(r"[,;\s]+", str(text or "")):
        part = part.strip()[:MAX_VERSION]
        if re.search(r"\d", part) and part not in out:
            out.append(part)
    return out


_PRERELEASE = re.compile(
    r"(?:^|[.\-_~])(?:alpha|beta|rc|cr|snapshot|preview|pre|dev|milestone)(?:[.\-_]?\d+)?(?=$|[.\-_~])"
    r"|(?:^|[.\-_])M\d+(?=$|[.\-_])|\d(?:a|b|rc)\d+$", re.I)


def prerelease(version: Any) -> bool:
    """Версия – предварительный выпуск (20.0.0-rc.0, 3.0.0-M1, 1.0.0-beta.2, 2.1-SNAPSHOT, 1.0a1, 0.9.dev3): как
    цель обновления не годится. Метаданные сборки после «+» (1.2.3+dev.7) на это не влияют. Только пометка в списке
    и карточке SCA, выбор цели не запрещается."""
    text = str(version or "").strip().split("+", 1)[0]
    return bool(text) and bool(_PRERELEASE.search(text))


def prerelease_versions(value: Any) -> list[str]:
    """Предварительные выпуски среди версий исправления Hub: перечень строкой («2.3.9, 3.0.0-M1») или списком таких
    строк (в списке SCA элемент сам может быть перечнем – ревью Codex)."""
    items = value if isinstance(value, (list, tuple)) else [value]
    out: list[str] = []
    for item in items:
        for part in re.split(r"[,;\s]+", str(item or "")):
            if part.strip() and prerelease(part.strip()) and part.strip() not in out:
                out.append(part.strip())
    return out


def first_version(text: Any) -> str:
    """Первая версия из перечня версий исправления Hub («2.3.9, 3.0.1» -> «2.3.9»)."""
    for part in re.split(r"[,;\s]+", str(text or "")):
        part = part.strip()
        if re.search(r"\d", part):
            return part[:MAX_VERSION]
    return ""


def answer_notes(version: str, answer: Mapping[str, Any] | None, hub_safe: Iterable[str] = ()) -> list[dict]:
    """Замечания к ответу агента для человека: [{"tone": "warn" | "accent", "text"}]."""
    if not answer:
        return []
    notes = []
    target = str(answer.get("recommended_version") or "")
    conclusion = answer.get("conclusion") or ""
    if not answer.get("links"):
        notes.append({"tone": "warn", "text": "нет ссылок на источники"})
    if not conclusion:
        notes.append({"tone": "warn", "text": "вывод не указан"})
    if conclusion == "update" and not target:
        notes.append({"tone": "warn", "text": "нет версии для обновления"})
    if target:
        order = compare_versions(target, version)
        if order == 0:
            notes.append({"tone": "warn", "text": "рекомендуемая версия совпадает с текущей"})
        elif order == -1:
            notes.append({"tone": "warn", "text": "рекомендуемая версия ниже текущей"})
        elif major_change(version, target):
            notes.append({"tone": "accent", "text": "смена старшей версии"})
        safe = first_version(", ".join(hub_safe))
        if safe and compare_versions(target, safe) == -1:
            notes.append({"tone": "warn", "text": f"ниже версии исправления по данным Hub ({safe})"})
    return notes


# ============================================================================ исследование компонента как ответ агента

RESEARCH_SOURCE = "исследование компонента"
# применимость уязвимости к версии из исследования → вывод ответа агента (ADR-0108)
APPLIES_CONCLUSION = {"yes": "update", "no": "not_applicable", "unknown": "unclear"}
RESEARCH_EXPLANATION = 1200  # предел пояснения по одной уязвимости; в текст для Hub оно идёт ещё короче


def research_answer(research: Mapping[str, Any] | None, key: tuple[str, str, str]) -> dict | None:
    """Ответ агента по пакету из принятого исследования компонента (ADR-0108): тот же вид, что у строки
    sca_answers, плюс вывод по каждой уязвимости (per_vuln: {идентификатор или его синоним без учёта регистра:
    {conclusion, explanation, links}}) – вывод находки берётся по её уязвимостям (answer_for). Охват –
    публичные уязвимости исследования с синонимами: уязвимости, которой в исследовании нет, ответ не охватывает.
    key – (экосистема, имя, версия) пакета так, как их видит вызывающий. Исследования или уязвимостей в нём нет –
    None: «нет известных уязвимостей» не означает, что конкретная CVE из Hub не применима."""
    if not research:
        return None
    payload = research.get("payload") if isinstance(research.get("payload"), Mapping) else {}
    findings = [x for x in payload.get("public_findings") or [] if isinstance(x, Mapping) and str(x.get("id") or "")]
    if not findings:
        return None
    evidence = {str(e.get("evidence_ref")): str(e.get("url") or "") for e in payload.get("evidence") or []
                if isinstance(e, Mapping) and e.get("evidence_ref")}
    advice = payload.get("package_advice") if isinstance(payload.get("package_advice"), Mapping) else {}
    target = one_line(advice.get("target_version"), MAX_VERSION) if advice.get("action") == "update" else ""
    ids: dict[str, list[str]] = {}
    links: list[str] = []
    records: list[tuple[list[str], dict]] = []
    for item in findings:
        vuln_id = one_line(item.get("id"), MAX_VERSION)
        aliases = _dedupe(one_line(a, MAX_VERSION) for a in item.get("aliases") or [] if one_line(a, MAX_VERSION))
        own = [u for u in (evidence.get(str(ref), "") for ref in item.get("source_refs") or [])
               if u.startswith(("https://", "http://"))]
        parts = [one_line(item.get("description"), RESEARCH_EXPLANATION)]
        if one_line(item.get("conditions"), RESEARCH_EXPLANATION):
            parts.append("Условия: " + one_line(item.get("conditions"), RESEARCH_EXPLANATION))
        records.append(([n.casefold() for n in (vuln_id, *aliases)],
                        {"conclusion": APPLIES_CONCLUSION.get(str(item.get("applies") or ""), "unclear"),
                         "explanation": " ".join(p for p in parts if p), "links": _dedupe(own)}))
        ids[vuln_id] = [a for a in aliases if a.casefold() != vuln_id.casefold()]
        links += own
    per_vuln = _vulnerability_groups(records)
    eco, name, version = key
    applicable = sum(1 for item in findings if item.get("applies") == "yes")
    updated = str(research.get("observed_at") or research.get("imported_at") or "")
    answer = {"id": f"research-{research.get('id')}", "ecosystem": eco, "component": name, "version": version,
              "source": f"{RESEARCH_SOURCE}, ревизия {int(research.get('revision') or 0)}",
              "recommended_version": target, "conclusion": "",
              "explanation": f"Исследование компонента: применимых к версии уязвимостей {applicable} из "
                             f"{len(findings)}.",
              # синонимы исследования в «ids» не идут: по ним aliases_for дописал бы GHSA к номерам находки в текстах
              # для Hub, и отметки «Внесено в Hub» по уже сохранённым решениям стали бы «текст изменился» (ревью
              # Codex, круг 21); охват (vulnerabilities) синонимы включает
              "ids": {}, "links": _dedupe(links), "vulnerabilities": _dedupe(n for v, a in ids.items() for n in (v, *a)),
              "created_at": str(research.get("imported_at") or ""), "updated_at": updated,
              "origin": "research", "per_vuln": per_vuln, "research_sig": str(research.get("answer_sig") or ""),
              "research_revision": int(research.get("revision") or 0)}
    answer["conclusion"] = answer_for_ids(answer, list(ids))["conclusion"]
    return answer


def _vulnerability_groups(records: list[tuple[list[str], dict]]) -> dict[str, dict]:
    """Записи исследования с общим идентификатором (id одной – синоним другой) – одна уязвимость: вывод группы не
    зависит от порядка записей, противоречие между ними – «неясно» (ревью Codex, круг 20). {идентификатор без учёта
    регистра: вывод группы} – один и тот же объект для всех идентификаторов группы."""
    parent = list(range(len(records)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    owner: dict[str, int] = {}
    for index, (names, _entry) in enumerate(records):
        for name in names:
            if name in owner:
                parent[root(index)] = root(owner[name])
            else:
                owner[name] = index
    groups: dict[int, list[dict]] = {}
    for index, (_names, entry) in enumerate(records):
        groups.setdefault(root(index), []).append(entry)
    merged: dict[int, dict] = {}
    for key, entries in groups.items():
        found = {e["conclusion"] for e in entries}
        merged[key] = {"conclusion": found.pop() if len(found) == 1 else "unclear",
                       "explanation": " ".join(_dedupe(e["explanation"] for e in entries if e["explanation"])),
                       "links": _dedupe(u for e in entries for u in e["links"])}
    return {name: merged[root(index)] for name, index in owner.items()}


def answer_for_ids(answer: Mapping[str, Any] | None, ids: Iterable[str]) -> Any:
    """Ответ агента применительно к уязвимостям ids (ADR-0108): у ответа исследования вывод, пояснение и ссылки –
    по этим уязвимостям: применима хотя бы одна – «обновить», все не применимы – «не применимо», иначе «неясно».
    Ни одной из ids в ответе исследования нет (или у находки нет идентификаторов) – вывода нет: общий вывод по
    библиотеке находке не приписывается (ревью Codex, круг 20). Ответ прежнего формата – как есть."""
    per = (answer or {}).get("per_vuln")
    if not per:
        return answer
    entries = list({id(e): e for e in (per.get(str(i).casefold()) for i in ids) if e}.values())
    if not entries:
        return {**answer, "conclusion": "", "explanation": "", "links": []}
    found = {e["conclusion"] for e in entries}
    conclusion = ("update" if "update" in found else "not_applicable" if found == {"not_applicable"} else "unclear")
    return {**answer, "conclusion": conclusion,
            "explanation": " ".join(_dedupe(e["explanation"] for e in entries if e["explanation"])),
            "links": _dedupe(u for e in entries for u in e["links"])}


def internal_gap(ids: Iterable[str], answer: Mapping[str, Any] | None) -> list[str]:
    """Уязвимости из ids, которых нет в охвате ответа исследования и которые названы только внутренним номером AST
    (ADR-0154): исследование идёт по публичным данным и такой номер не опознаёт, повтор исследования этого не
    изменит. Возвращает эти номера, когда вне охвата только они. Ответ не исследования, охват не записан или вне
    охвата есть публичный идентификатор – []."""
    if not answer or not answer.get("per_vuln"):
        return []
    scope = {str(x).casefold() for x in answer.get("vulnerabilities") or []}
    missing = [i for i in ids if str(i).casefold() not in scope]
    return missing if missing and all(_AST_ID.search(str(i)) for i in missing) else []


# выводы исследования по компоненту, которые берутся за неопознанный внутренний номер (ADR-0154). «Не применимо» –
# нет: ложное срабатывание уязвимости, которую исследование не проверяло, – только своё решение оператора
COMPONENT_FILLS = ("update", "unclear")


def component_fills(ids: Iterable[str], answer: Mapping[str, Any] | None) -> list[str]:
    """Номера internal_gap, за которые берётся вывод исследования по компоненту: только при выводе «обновить» или
    «неясно» (COMPONENT_FILLS). Иначе – []: ответ к такой находке не применяется."""
    gap = internal_gap(ids, answer)
    return gap if gap and str((answer or {}).get("conclusion") or "") in COMPONENT_FILLS else []


def answer_by_ids(answer: Mapping[str, Any] | None, ids: Iterable[str]) -> Any:
    """Ответ агента применительно к уязвимостям ids (answer_for_ids) с учётом ADR-0154: за уязвимость, названную
    только внутренним номером AST, берётся вывод исследования по компоненту, если он «обновить» или «неясно»
    (component_fills). С выводами по опознанным уязвимостям он складывается по правилу answer_for_ids: хотя бы
    один «обновить» – «обновить», иначе «неясно». Пояснение и ссылки – только по опознанным уязвимостям: источники
    о других уязвимостях компонента этой находке не приписываются; опознанных нет – пояснение исследования по
    компоненту. В ответе появляется by_component – номера, за которые взят вывод по компоненту."""
    ids = list(ids)
    known = answer_for_ids(answer, ids)
    gap = component_fills(ids, answer)
    if not answer or not gap:
        return known
    recognized = bool(known.get("conclusion"))
    found = {c for c in (known.get("conclusion"), answer.get("conclusion")) if c}
    conclusion = ("" if not found else "update" if "update" in found
                  else "not_applicable" if found == {"not_applicable"} else "unclear")
    return {**answer, "conclusion": conclusion,
            "explanation": str((known if recognized else answer).get("explanation") or ""),
            "links": list(known.get("links") or []) if recognized else [], "by_component": gap}


def answer_for(f: Finding | Mapping[str, Any], answer: Mapping[str, Any] | None) -> Any:
    """Ответ агента применительно к уязвимостям находки (answer_by_ids)."""
    return answer_by_ids(answer, finding_ids(f))


# ============================================================================ компоненты на странице SCA

def uncovered_ids(ids: Iterable[str], answer: Mapping[str, Any] | None) -> list[str]:
    """Уязвимости библиотеки, которых нет в охвате ответа агента (появились после ответа). Ответа нет – [].
    Охват не записан (ответ загружен до этапа 3) – неизвестен: не охвачена ни одна уязвимость."""
    if not answer:
        return []
    scope = {str(x).casefold() for x in answer.get("vulnerabilities") or []}
    return [i for i in ids if i.casefold() not in scope]


def package_key(c: Mapping[str, Any]) -> tuple[str, str, str]:
    """Ключ пакета (экосистема, компонент, версия) после очистки имени и версии (one_line): один и тот же для строк
    задания исследования (package_report) и для мест использования (Database.sca_usages) – иначе невидимый знак в
    имени из выгрузки развёл бы их."""
    return (group_ecosystem(c), one_line(c.get("component"), MAX_COMPONENT), one_line(c.get("version"), MAX_VERSION))


def group_ecosystem(c: Mapping[str, Any]) -> str:
    """Экосистема группы пакета: поле ecosystem группы (Database.sca_components) или, если его нет, первая
    известная из build_types."""
    if c.get("ecosystem") is not None:
        return str(c["ecosystem"])
    return next((e for e in (canon_ecosystem(x) for x in c.get("build_types") or []) if e), "")


def component_views(components: Iterable[dict], latest: Mapping[tuple[str, str, str], dict],
                    ast_map: Mapping[str, list[str]]) -> list[dict]:
    """Пакеты (Database.sca_components) вместе с последним ответом агента и известными соответствиями
    идентификаторов: к полям пакета добавляются ids, aliases, answer, conclusion, ecosystem, notes. latest –
    последние ответы по ключу (экосистема, компонент, версия)."""
    views = []
    for c in components:
        ids = _dedupe([*(c.get("vuln_ids") or []), *(c.get("cve") or [])])
        # у ответа исследования вывод – по уязвимостям этой библиотеки в выгрузке (ADR-0108); ни одной из них в
        # исследовании нет – ответа у библиотеки нет (ревью Codex, круг 20). Исключение – уязвимости только с
        # внутренним номером AST: за них берётся вывод по компоненту (ADR-0154)
        answer = answer_by_ids(latest.get((group_ecosystem(c), c["component"], c["version"])), ids)
        if answer and answer.get("per_vuln") and not answer.get("conclusion"):
            answer = None
        notes = answer_notes(c["version"], answer, c.get("fixed_versions") or [])
        uncovered = uncovered_ids(ids, answer)
        by_component = (answer or {}).get("by_component") or []
        if answer and not answer.get("vulnerabilities") and ids:
            notes.append({"tone": "warn", "text": "охват ответа неизвестен (ответ загружен до обновления) – "
                                                  "нужен новый ответ"})
        elif by_component:
            notes.append({"tone": "accent", "text": "исследование не опознаёт внутренний номер "
                          + ", ".join(by_component[:3]) + (" и другие" if len(by_component) > 3 else "")
                          + " – за него вывод по компоненту"})
        elif uncovered:
            notes.append({"tone": "warn", "text": "ответ не про " + ", ".join(uncovered[:3])
                          + (" и другие" if len(uncovered) > 3 else "") + " – нужен новый ответ"})
        views.append({**c, "ids": ids, "aliases": aliases_for(ids, ast_map, answer), "answer": answer,
                      "conclusion": (answer or {}).get("conclusion") or "", "uncovered": uncovered,
                      "ecosystem": group_ecosystem(c), "notes": notes})
    return views


def research_conflict(answer: Mapping[str, Any] | None, status: str, status_label: str, applicable: Any) -> str:
    """Совет агента «не применимо» расходится с принятым исследованием компонента: исследование находит применимые уязвимости. Пояснение или «».
    Ответ самого исследования с собой не сравнивается."""
    if not answer or answer.get("conclusion") != "not_applicable" or answer.get("origin") == "research":
        return ""
    if status != "vulnerable" and int(applicable or 0) <= 0:
        return ""
    return f"исследование компонента: {status_label}, применимых уязвимостей {int(applicable or 0)}"


def filter_views(views: Iterable[dict], show: str) -> list[dict]:
    """Отбор компонентов по ключу из FILTERS."""
    views = list(views)
    if show == "urgent":
        return [v for v in views if v["urgent"]]
    if show == "no_answer":
        return [v for v in views if not v["answer"]]
    if show in CONCLUSION_LABELS:
        return [v for v in views if v["conclusion"] == show]
    if show == "unreviewed":
        return [v for v in views if v["reviewed"] < v["findings"]]
    if show == "not_entered":
        return [v for v in views if v["entered"] < v["findings"]]
    if show == "todo":
        # «К разбору»: версия не в дефекте приложения, и у неё есть хоть одна находка, не внесённая
        # в Hub и не отложенная оператором – то, по чему ещё предстоит решить и создать дефект
        return [v for v in views if not v.get("in_defect") and todo_count(v) > 0]
    if show == "in_defect":  # версия компонента входит в дефект приложения
        return [v for v in views if v.get("in_defect")]
    if show == "no_defect":
        return [v for v in views if not v.get("in_defect")]
    return views


def todo_count(view: dict) -> int:
    """Находки версии, которые ещё к разбору: не внесены в Hub и не отложены оператором – счётчик `todo` группы
    компонентов (`Database._sca_component_groups`, по каждой находке отдельно). У представления без счётчика
    отложенные неизвестны – берётся правило «не внесены в Hub»."""
    todo = view.get("todo")
    if todo is None:
        return int(view["findings"]) - int(view["entered"])
    return int(todo)


def cvss_views(views: Iterable[dict], version: str = "") -> list[dict]:
    """Дополняет пакеты сведениями об оценке для таблицы: cvss_score – балл выбранной версии (без выбора –
    наибольший из всех), cvss_parts – разбор баллов пакета по версиям для раскрытия в ячейке."""
    views = list(views)  # список создаётся до прохода: на входе может быть и генератор
    for v in views:
        v["cvss_score"] = cvss.score_of(v, version)
        v["cvss_parts"] = cvss.breakdown(v)
    return views


def cvss_versions(views: Iterable[dict]) -> list[tuple[str, str]]:
    """Все поддерживаемые версии; отсутствие оценок обозначено явно, а выбор не исчезает при фильтрации.
    Неизвестная версия имеет значение «?», отличное от «все версии вместе»."""
    found = {part["version"] for v in views for part in cvss.breakdown(v)}
    return [(cvss.UNKNOWN_CHOICE if version == cvss.UNKNOWN else version,
             cvss.VERSION_LABELS[version] + (" (нет оценок)" if version not in found else ""))
            for version in (*cvss.VERSIONS, cvss.UNKNOWN)]


# ============================================================================ пакет для внешних агентов

# Знак формулы сразу или через пробелы после разделителя внутри значения: русский Excel делит CSV по «;», и такое
# значение распалось бы на ячейки, одна из которых – формула
_CSV_INNER_RISKY = re.compile(r"([;,\t|])(\s*)([=+\-@])")


def _csv_safe(value: str) -> str:
    """Значение ячейки CSV, которое редактор таблиц не примет за формулу ни целиком, ни после деления по «;»."""
    value = _CSV_INNER_RISKY.sub(r"\1\2'\3", value)
    return "'" + value if value.startswith(_CSV_RISKY) else value


# Экосистемы пакетов, которые передаются агенту (колонка Type выгрузки); прочие значения – только в карточке
ECOSYSTEMS = frozenset((
    "maven", "gradle", "npm", "yarn", "pnpm", "pypi", "pip", "poetry", "nuget", "go", "golang", "cargo", "crates",
    "rubygems", "gem", "bundler", "composer", "packagist", "conan", "cocoapods", "swift", "hex", "pub", "cran", "conda",
    "debian", "deb", "rpm", "alpine", "apk", "docker", "sbt", "ivy",
))
# Координаты пакета: имя maven (groupId:artifactId), npm (@scope/name), pypi, nuget, go (github.com/org/repo) и т. п.
_COMPONENT_OK = re.compile(r"[A-Za-z0-9@][A-Za-z0-9@/._:+~-]{0,213}")
_VERSION_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,99}")
_CODE_FILE = re.compile(r"\.(?:java|kt|scala|groovy|py|rb|php|cs|vb|go|rs|c|cc|cpp|h|hpp|m|swift|jsx?|tsx?|xml|"
                        r"ya?ml|json|properties|ini|cfg|conf|env|txt|sql|sh|ps1|bat)$", re.I)


_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:|[/~])")
_NPM_SCOPED = re.compile(r"@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")


def looks_like_path(component: str) -> bool:
    """Имя компонента похоже на путь, а не на координаты пакета: абсолютный путь (C:/…, C:…, /…, ~…), обратная
    косая черта, «..», «./» или «папка/файл» с расширением файла кода или настроек в последней части. Имена пакетов
    вида chart.js, @types/chart.js, github.com/org/repo, gopkg.in/yaml.v3 путями не считаются."""
    name = str(component or "").strip()
    if not name:
        return False
    if _ABSOLUTE.match(name) or "\\" in name or ".." in name or "./" in name:
        return True
    if "/" in name and not _NPM_SCOPED.fullmatch(name):
        return bool(_CODE_FILE.search(name.rsplit("/", 1)[-1]))
    return False


def internal_prefix(component: str, prefixes: Iterable[str]) -> str:
    """Префикс внутреннего компонента, с которого начинается имя (без учёта регистра); не внутренний – ""."""
    name = component.casefold()
    return next((p for p in prefixes if p and name.startswith(str(p).casefold())), "")


def package_exclusion(component: str, version: str, prefixes: Iterable[str] = ()) -> str:
    """Почему библиотека не уходит внешнему агенту ("" – уходит): внутренний компонент по префиксу из настроек;
    имя или версия не похожи на координаты пакета – в поле выгрузки мог оказаться путь, фрагмент кода или название
    внутренней системы."""
    prefix = internal_prefix(component, prefixes)
    if prefix:
        return f"внутренний компонент (префикс «{prefix}»)"
    if looks_like_path(component):
        return "имя похоже на путь к файлу или папке"
    if not _COMPONENT_OK.fullmatch(component) or component.count("/") > 3 or "//" in component:
        return "имя не похоже на имя пакета (путь, код или пробелы)"
    if version and not _VERSION_OK.fullmatch(version):
        return "версия не похожа на номер версии"
    return ""


# Имя пакета по правилам экосистемы (колонка Type выгрузки). Имя, которое правилам своей экосистемы не отвечает,
# не отвергается, а считается сомнительным: агенту оно уходит только после подтверждения человеком.
# maven: groupId:artifactId (иногда с классификатором) или только artifactId – без «/», «@» и пробелов
_MAVEN_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*){0,2}")
# npm: имя или @scope/имя; старые пакеты бывают с заглавными буквами
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*")
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_NUGET_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*")
_GO_NAME = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:/[A-Za-z0-9._~+-]+)+")
_CARGO_NAME = re.compile(r"[A-Za-z0-9_-]+")
_GEM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_COMPOSER_NAME = re.compile(r"[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*")
ECOSYSTEM_RULES: dict[str, tuple[re.Pattern, str]] = {}
for _names, _rule, _hint in (
    (("maven", "gradle", "sbt", "ivy"), _MAVEN_NAME, "у maven ожидается groupId:artifactId без «/»"),
    (("npm", "yarn", "pnpm"), _NPM_NAME, "у npm ожидается имя пакета или @scope/имя"),
    (("pypi", "pip", "poetry", "conda"), _PYPI_NAME, "у PyPI ожидается имя пакета без «/» и «:»"),
    (("nuget",), _NUGET_NAME, "у NuGet ожидается имя вида Company.Package"),
    (("go", "golang"), _GO_NAME, "у Go ожидается путь модуля с доменом (example.org/org/repo)"),
    (("cargo", "crates"), _CARGO_NAME, "у Cargo ожидается имя пакета без «/» и «.»"),
    (("rubygems", "gem", "bundler"), _GEM_NAME, "у RubyGems ожидается имя пакета без «/» и «:»"),
    (("composer", "packagist"), _COMPOSER_NAME, "у Composer ожидается vendor/package в нижнем регистре"),
):
    for _name in _names:
        ECOSYSTEM_RULES[_name] = (_rule, _hint)
# Слова, по которым имя похоже на внутреннее название (системы, команды, внутренней сети), а не на публичный пакет
_INTERNAL_WORDS = re.compile(r"(?:^|[^a-z])(?:internal|private|corp|corporate|intranet|inhouse|in-house|"
                             r"proprietary|confidential|local|localhost|company)(?:$|[^a-z])", re.I)


def package_doubt(component: str, version: str, ecosystems: Iterable[str] = ()) -> str:
    """Почему имя библиотеки сомнительно ("" – не сомнительно): не отвечает правилам своей экосистемы (если она
    известна), похоже на «папку/имя» без домена или на внутреннее название. Такое имя проходит отбор package_exclusion,
    но агенту уходит только после явного подтверждения человеком: это может быть внутренний компонент или путь."""
    name = str(component or "").strip()
    known = [e for e in (str(x or "").strip().casefold() for x in ecosystems) if e in ECOSYSTEM_RULES]
    if known:
        failed = [ECOSYSTEM_RULES[e][1] for e in known if not ECOSYSTEM_RULES[e][0].fullmatch(name)]
        if len(failed) == len(known):
            return f"имя не похоже на пакет своей экосистемы ({failed[0]})"
    elif "/" in name and not _NPM_SCOPED.fullmatch(name) and "." not in name.split("/", 1)[0]:
        return "имя похоже на «папку/имя», а не на координаты пакета"
    if _INTERNAL_WORDS.search(name):
        return "имя похоже на внутреннее название"
    return ""


def doubt_key(component: str, version: str, ecosystem: str = '') -> str:
    """Ключ сомнительной библиотеки в списке подтверждённых человеком."""
    return json.dumps([ecosystem, component, version], ensure_ascii=False, separators=(',', ':'))


def confirmed_keys(components: Iterable[dict], confirmed: Iterable[str]) -> set[str]:
    """Совместимость прежних подтверждений: не распространять одно имя на несколько экосистем."""
    result = set(confirmed)
    legacy: dict[str, set[str]] = {}
    for item in components:
        name, ver = one_line(item.get('component'), MAX_COMPONENT), one_line(item.get('version'), MAX_VERSION)
        legacy.setdefault(f'{name}@{ver}', set()).add(doubt_key(name, ver, group_ecosystem(item)))
    for key in tuple(result):
        if key in legacy and len(legacy[key]) == 1:
            result.update(legacy[key])
    return result


def package_report(components: Iterable[dict], prefixes: Iterable[str] = (),
                   confirmed: Iterable[str] | None = None) -> tuple[list[dict], list[dict]]:
    """Состав пакета для внешних агентов: (строки пакета, исключённые [{component, version, reason}]).

    В строку попадают только экосистема (из списка ECOSYSTEMS), имя библиотеки, версия, идентификаторы уязвимостей
    и версии исправления из отчёта Hub, похожие на номера версий. Кодовые базы, пути зависимостей, номера находок,
    CVSS и CWE в пакет не попадают. Внутренние компоненты (prefixes – настройка sca_internal_prefixes) и значения,
    не похожие на координаты пакета, исключаются – их список человек видит на странице SCA до передачи.

    Сомнительные имена (package_doubt: не отвечают правилам своей экосистемы, похожи на «папку/имя» или на внутреннее
    название) попадают в пакет, только если их ключ (doubt_key) есть в confirmed – списке, который человек
    подтвердил на странице SCA; иначе они в excluded с признаком doubtful=True."""
    components = list(components)
    prefixes = tuple(prefixes)
    confirmed = confirmed_keys(components, confirmed or ())
    rows, excluded, seen = [], [], set()
    for c in components:
        ecosystem, component, version = package_key(c)
        if not component or (ecosystem, component, version) in seen:
            continue
        seen.add((ecosystem, component, version))
        reason = package_exclusion(component, version, prefixes)
        if reason:
            excluded.append({"component": component, "version": version, "reason": reason, "doubtful": False})
            continue
        ecosystems = [ecosystem] if ecosystem else []
        doubt = package_doubt(component, version, ecosystems)
        if doubt and doubt_key(component, version, ecosystem) not in confirmed:
            excluded.append({"component": component, "version": version, "ecosystem": ecosystem, "reason": doubt, "doubtful": True,
                             "key": doubt_key(component, version, ecosystem)})
            continue
        vulns = _dedupe(norm_id(x) for x in [*(c.get("cve") or []), *(c.get("vuln_ids") or [])])
        safe = [v for v in (one_line(x, MAX_VERSION) for raw in c.get("fixed_versions") or []
                            for x in re.split(r"[,;\s]+", str(raw or ""))) if v and _VERSION_OK.fullmatch(v)]
        rows.append({"ecosystem": ecosystem, "component": component, "version": version,
                     "vulnerabilities": vulns, "hub_safe_version": one_line(", ".join(_dedupe(safe)), 200)})
    return rows, excluded


def package_rows(components: Iterable[dict], prefixes: Iterable[str] = (),
                 confirmed: Iterable[str] | None = None) -> list[dict]:
    """Строки пакета для внешних агентов (package_report без списка исключённых)."""
    return package_report(components, prefixes, confirmed)[0]


def answer_template(rows: Iterable[dict]) -> dict:
    """Заготовка ответа: строки пакета с пустыми полями, которые заполняет агент."""
    return {"format": ANSWER_FORMAT, "source": "", "components": [
        {**row, "conclusion": "", "recommended_version": "",
         "ids": {x: [] for x in row["vulnerabilities"] if not x.startswith("CVE-")}, "explanation": "",
         "links": []} for row in rows]}


def template_json(rows: Iterable[dict]) -> str:
    """Заготовка ответа в JSON: по библиотеке в строке – так её удобно и читать, и заполнять."""
    data = answer_template(rows)
    head = json.dumps({k: v for k, v in data.items() if k != "components"}, ensure_ascii=False)[:-1]
    items = [json.dumps(item, ensure_ascii=False) for item in data["components"]]
    if not items:
        return head + ', "components": []}'
    return head + ', "components": [\n  ' + ",\n  ".join(items) + "\n]}"


def package_csv(rows: Iterable[dict]) -> str:
    """Таблица компонентов в CSV (разделитель – запятая, UTF-8)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_ALL)
    writer.writerow(["ecosystem", "component", "version", "vulnerabilities", "hub_safe_version"])
    for row in rows:
        writer.writerow([_csv_safe(row["ecosystem"]), _csv_safe(row["component"]), _csv_safe(row["version"]),
                         _csv_safe(" ".join(row["vulnerabilities"])), _csv_safe(row["hub_safe_version"])])
    return buf.getvalue()


TASK_INTRO = """\
# Задание: безопасные версии библиотек

Ниже – библиотеки, в которых анализатор состава программного обеспечения (SCA) нашёл уязвимости. Для каждой
библиотеки и её версии нужно выяснить, до какой версии обновиться, чтобы закрыть все перечисленные уязвимости,
и подтвердить вывод ссылками на первоисточники.

Кода проекта в задании нет и не будет: только названия библиотек, их версии и идентификаторы уязвимостей.
Используется ли уязвимая функция в коде, отсюда не видно.

## Что известно о каждой библиотеке

- `ecosystem` – экосистема пакета (maven, pypi, npm и т. п.): вместе с именем и версией она определяет пакет, один и тот
  же `component` и `version` в разных экосистемах – разные пакеты; в ответе верните её без изменений;
- `component` – имя пакета, у maven – `groupId:artifactId`;
- `version` – используемая версия;
- `vulnerabilities` – идентификаторы уязвимостей из отчёта: CVE-…, GHSA-…, BDU:… и внутренние номера
  анализатора AST-… (у номеров AST публичных страниц нет);
- `hub_safe_version` – версия, которую анализатор считает безопасной: её нужно проверить, а не переписать.

## Что сделать по каждой библиотеке

1. Найдите сведения об уязвимостях в первоисточниках: OSV (osv.dev), GitHub Advisory Database
   (github.com/advisories), NVD (nvd.nist.gov), БДУ ФСТЭК России (bdu.fstec.ru) для идентификаторов BDU:…,
   страница проекта и журнал изменений, реестр пакетов (Maven Central, PyPI, npm).
2. Определите наименьшую версию, в которой исправлены все перечисленные уязвимости. Если такая версия есть
   в той же старшей версии (major), укажите её; если исправление есть только в новой старшей версии, скажите
   об этом в пояснении.
3. Убедитесь, что рекомендуемая версия опубликована в реестре пакетов, и дайте ссылку на неё.
4. Сопоставьте идентификаторы: для каждого AST-…, GHSA-… и BDU:… из заготовки укажите в `ids` соответствующие
   CVE (или GHSA), если соответствие есть в первоисточниках. Не нашли – оставьте пустой список.
5. Выберите вывод `conclusion`:
   - `update` – уязвимость затрагивает используемую версию, нужно обновиться до `recommended_version`;
   - `not_applicable` – используемая версия не входит в затронутый диапазон или сообщение об уязвимости
     отозвано (это должно быть видно в первоисточнике);
   - `unclear` – сведений недостаточно или источники противоречат друг другу.
6. В `explanation` коротко и простыми словами, по-русски, объясните вывод: какие уязвимости, в каких версиях
   они исправлены, что меняется при обновлении.

## Правила

- Ничего не придумывайте: ни номера CVE, ни версии, ни ссылки. Не нашли – вывод `unclear` и пояснение,
  чего не хватает.
- Подтвердите каждый вывод ссылками на первоисточники в `links`: OSV, GitHub Advisory, NVD, БДУ ФСТЭК России,
  сайт или репозиторий проекта, реестр пакетов. Пересказы, форумы и блоги не подходят. В комментарий
  для AppSec.Hub попадут только ссылки на osv.dev, github.com/advisories, nvd.nist.gov, cve.org, bdu.fstec.ru
  и реестры пакетов; остальные человек увидит лишь при проверке. Ссылки – только на сайты в интернете, без
  адресов IP и нестандартных портов.
- Не меняйте `component` и `version`: по ним ответ сопоставляется с отчётом.
- Вывод `not_applicable` – только по версиям или по отзыву сообщения об уязвимости: кода проекта нет.
- Если библиотек много, отвечайте частями: каждая часть – такой же JSON со своими библиотеками.

## Формат ответа

Только JSON: заполните пустые поля заготовки ниже и верните её целиком, без текста вне JSON.

- `source` – кто отвечает: имя агента, сервиса или специалиста;
- `conclusion` – `update`, `not_applicable` или `unclear`;
- `recommended_version` – версия, до которой обновить (для `update` обязательно);
- `ids` – соответствие идентификаторов, например `{"AST-2026-000101": ["CVE-2026-12345"]}`;
- `explanation` – пояснение по-русски;
- `links` – ссылки на первоисточники: `["https://…"]`.

Поля `ecosystem`, `vulnerabilities` и `hub_safe_version` можно оставить как есть.
"""


def task_text(rows: list[dict]) -> str:
    """Задание для внешнего агента по-русски вместе с заготовкой ответа."""
    count = len(rows)
    word = plural(count, "библиотека", "библиотеки", "библиотек")
    return (TASK_INTRO + f"\n## Заготовка ответа: {count} {word}\n\n```json\n" + template_json(rows)
            + "\n```\n").translate(_DASHES)


def package_zip(rows: list[dict]) -> bytes:
    """Пакет для внешних агентов одним архивом: задание с заготовкой, таблица CSV и заготовка ответа JSON."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("task.md", task_text(rows))
        archive.writestr("components.csv", package_csv(rows))
        archive.writestr("answer-template.json", template_json(rows) + "\n")
    return buf.getvalue()


# ============================================================================ ответы внешних агентов

@dataclass
class AnswersReport:
    """Итог разбора ответа агента: что сохранить и что сказать человеку."""

    source: str
    answers: list[ScaAnswer] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)  # библиотеки, которых нет в проекте («имя@версия»)
    ambiguous: list[str] = field(default_factory=list)  # имя и версия есть в нескольких экосистемах, ecosystem не указана
    warnings: list[str] = field(default_factory=list)
    without_answer: list[str] = field(default_factory=list)  # библиотеки проекта, по которым ответа нет


RESEARCH_ANSWER_NOTE = ("Это ответ по контракту исследования компонентов (local-triage/sca-answer): загрузите его на "
                        "странице «Компоненты» кнопкой «Загрузить ответ», а не в форму ответа агента по находкам.")


def _answer_items(value: Any) -> list[dict] | None:
    """Записи ответа из значения JSON: объект с components (answers, results) или список объектов с component.
    Ответ контракта исследования (поле contract «local-triage/sca-answer/…», rows вместо components) – ScaInputError
    с подсказкой, куда его загружать (хвост SCA-IMP)."""
    if isinstance(value, dict) and str(value.get("contract") or "").startswith("local-triage/sca-answer"):
        raise ScaInputError(RESEARCH_ANSWER_NOTE)
    if isinstance(value, dict):
        for key in ("components", "answers", "results", "items"):
            if isinstance(value.get(key), list):
                return [x for x in value[key] if isinstance(x, dict)]
        return [value] if "component" in value else None
    if isinstance(value, list):
        items = [x for x in value if isinstance(x, dict)]
        return items if any("component" in x for x in items) else None
    return None


def _scan(text: str) -> Any:
    """Первый объект или массив JSON с ответом внутри текста с пояснениями; не нашёлся – None."""
    decoder = json.JSONDecoder()
    attempts = 0
    for m in re.finditer(r"[\[{]", text):
        start = m.start()
        rest = text[start + 1:start + 64].lstrip()
        if text[start] == "{" and not rest.startswith(('"', "}")):
            continue
        if text[start] == "[" and not rest.startswith(("{", "]")):
            continue
        attempts += 1
        if attempts > SCAN_ATTEMPTS:
            break
        try:
            value, _ = decoder.raw_decode(text, start)
        except (ValueError, RecursionError):  # не JSON или слишком глубокая вложенность
            continue
        if _answer_items(value) is not None:
            return value
    return None


def _json_error(text: str) -> str:
    """Почему текст с JSON не разобрать как ответ – для человека."""
    try:
        json.JSONDecoder().raw_decode(text)
    except RecursionError:
        return TOO_DEEP
    except json.JSONDecodeError as e:
        if e.pos >= len(text.rstrip()) - 1 or e.msg.startswith("Unterminated string"):
            return ("JSON обрывается на середине: похоже, ответ обрезан. Попросите агента продолжить или ответить "
                    "частями и загрузите части по очереди.")
        return f"В JSON ошибка: строка {e.lineno}, позиция {e.colno}. Проверьте, что ответ вставлен целиком."
    return "В ответе нет списка библиотек: нужен объект с полем components, как в заготовке из задания."


def extract_answers(text: str) -> tuple[list[dict], str]:
    """Записи ответа агента и подпись источника из текста: весь текст – JSON; иначе блоки в ограде ```, иначе
    первый подходящий объект JSON в тексте. ScaInputError – ответа не найти."""
    text = str(text or "").replace(BOM, "").strip()
    if not text:
        raise ScaInputError("Вставьте ответ агента или выберите файл.")
    values: list[Any] = []
    try:
        values.append(json.loads(text))
    except RecursionError:
        raise ScaInputError(TOO_DEEP) from None
    except ValueError:
        for m in _FENCE.finditer(text):
            block = m.group(1).strip()
            try:
                values.append(json.loads(block))
            except RecursionError:
                raise ScaInputError(TOO_DEEP) from None
            except ValueError:
                found = _scan(block)
                if found is not None:
                    values.append(found)
        if not values:
            found = _scan(text)
            if found is not None:
                values.append(found)
    items: list[dict] = []
    source = ""
    for value in values:
        part = _answer_items(value)
        if part is None:
            continue
        items += part
        if isinstance(value, dict) and not source:
            source = one_line(value.get("source"), MAX_SOURCE)
    if not items:
        starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
        if not starts:
            raise ScaInputError("В тексте нет JSON. Вставьте ответ агента целиком – вместе с блоком JSON.")
        fence = _FENCE.search(text)
        candidate = fence.group(1) if fence else text[min(starts):]
        raise ScaInputError(_json_error(candidate.strip()))
    if len(items) > MAX_ANSWERS:
        raise ScaInputError(f"Слишком много записей в ответе: {len(items)}, допустимо до {MAX_ANSWERS}.")
    return items, source


def norm_conclusion(value: Any) -> str:
    """Вывод агента: update, not_applicable, unclear (принимаются и русские слова); не распознан – ""."""
    text = one_line(value, 60).casefold().replace("ё", "е").strip(" .!")
    return _CONCLUSION_WORDS.get(text, "")


def norm_ids(value: Any) -> dict[str, list[str]]:
    """Соответствие идентификаторов: {"AST-…": ["CVE-…", "GHSA-…"]}. Принимается и список объектов
    [{"id": "AST-…", "aliases": [...]}]; пустой список – агент соответствия не нашёл."""
    if isinstance(value, dict):
        pairs = list(value.items())
    elif isinstance(value, list):
        pairs = [(x.get("id") or x.get("ast") or x.get("from"), x.get("aliases") or x.get("cve") or x.get("to"))
                 for x in value if isinstance(x, dict)]
    else:
        return {}
    result: dict[str, list[str]] = {}
    for key, aliases in pairs:
        source = norm_id(key)
        if not source or source in result:
            continue
        raw = aliases if isinstance(aliases, (list, tuple)) else re.split(r"[\s,;]+", str(aliases or ""))
        result[source] = [x for x in _dedupe(norm_id(a) for a in raw) if x != source][:MAX_ALIASES]
        if len(result) >= MAX_IDS:
            break
    return result


def norm_links(value: Any) -> tuple[list[str], int]:
    """Ссылки на источники (до MAX_LINKS); второе значение – сколько отброшено (не http и не https и т. п.)."""
    if isinstance(value, str):
        raw: list[Any] = _URL.findall(value) or ([value] if value.strip() else [])
    elif isinstance(value, (list, tuple)):
        raw = [(x.get("url") or x.get("href") or x.get("link")) if isinstance(x, dict) else x for x in value]
    else:
        raw = []
    links, dropped = [], 0
    for item in raw:
        if item is None or str(item).strip() == "":
            continue
        link = norm_link(item)
        if not link:
            dropped += 1
        elif link not in links:
            links.append(link)
    return links[:MAX_LINKS], dropped + max(0, len(links) - MAX_LINKS)


def _name_key(value: str) -> str:
    return re.sub(r"\s+", "", value).casefold()


def parse_answers(text: str, components: Iterable[dict], source: str = "",
                  history: Iterable[dict] | None = None) -> AnswersReport:
    """Ответ внешнего агента -> ответы по библиотекам проекта (models.ScaAnswer) и замечания.

    Ответ сопоставляется с библиотекой проекта по имени и версии: точно, затем без учёта регистра и пробелов,
    затем – по одному имени, если версия не указана, а библиотека с таким именем в проекте одна. Библиотеки,
    которых в проекте нет, не сохраняются: их перечисляет unknown. source – подпись источника из формы; пусто –
    из поля source ответа, иначе «внешний агент». ScaInputError – ответ не прочитать."""
    components = list(components)
    items, json_source = extract_answers(text)
    report = AnswersReport(source=one_line(source, MAX_SOURCE) or json_source or DEFAULT_SOURCE)
    known = {(group_ecosystem(c), c["component"], c["version"]): c for c in components}
    # Единое правило для старых ответов без экосистемы (как при прямом сохранении и в миграции): кандидаты – пакеты
    # проекта по всем находкам, в том числе пропавшим из последней выгрузки (history); ответ не приписывается пакету
    # другой экосистемы только потому, что прежний пакет исчез. Ответ про пакет, которого нет в текущей выгрузке, сохраняется.
    candidates = {**{(group_ecosystem(c), c["component"], c["version"]): c for c in (history or ())}, **known}
    loose: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    by_name: dict[str, list[tuple[str, str, str]]] = {}
    for key in known:
        loose.setdefault((_name_key(key[1]), _name_key(key[2])), []).append(key)
        by_name.setdefault(_name_key(key[1]), []).append(key)
    loose_all: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    by_name_all: dict[str, list[tuple[str, str, str]]] = {}
    for key in candidates:
        loose_all.setdefault((_name_key(key[1]), _name_key(key[2])), []).append(key)
        by_name_all.setdefault(_name_key(key[1]), []).append(key)
    chosen: dict[tuple[str, str, str], ScaAnswer] = {}
    nameless = 0
    for item in items:
        component = one_line(item.get("component") or item.get("name") or item.get("package"), MAX_COMPONENT)
        raw_version = item.get("version") if item.get("version") is not None else item.get("current_version")
        version = one_line(raw_version, MAX_VERSION)
        if not component:
            nameless += 1
            continue
        # Экосистема – часть идентичности пакета. Указана – пакет только этой экосистемы (неизвестное значение – только
        # пакет с неизвестной экосистемой); не указана – пакет с этим именем и версией, если он один: ответ не
        # переносится на другую экосистему и не выбирается наугад
        raw_ecosystem = item.get("ecosystem") if item.get("ecosystem") is not None else item.get("type")
        given = bool(str(raw_ecosystem or "").strip())
        wanted = canon_ecosystem(raw_ecosystem)
        exact = [(wanted, component, version)] if (wanted, component, version) in known else []
        if given and exact:
            hits = exact
        elif given:
            hits = [k for k in loose.get((_name_key(component), _name_key(version)), []) if k[0] == wanted]
            if not hits and not version:
                hits = [k for k in by_name.get(_name_key(component), []) if k[0] == wanted]
        else:
            hits = [k for k in candidates if k[1] == component and k[2] == version]
            if not hits:
                hits = loose_all.get((_name_key(component), _name_key(version)), [])
            if not hits and not version:
                hits = by_name_all.get(_name_key(component), [])
        if len(hits) > 1 and len({(k[1], k[2]) for k in hits}) > 1:
            hits = []  # имя без версии подходит к нескольким версиям: однозначно выбрать нельзя (как и раньше)
        if len(hits) > 1:
            ecosystems = ", ".join(sorted({k[0] or "без экосистемы" for k in hits}))
            report.ambiguous.append(f"{component}@{version}" if version else component)
            report.warnings.append(f"{component}@{version}: в проекте несколько экосистем ({ecosystems}), а ecosystem "
                                   "в ответе не указана – ответ не сохранён. Верните ecosystem из заготовки.")
            continue
        key = hits[0] if hits else None
        if key is None:
            report.unknown.append(f"{component}@{version}" if version else component)
            continue
        label = f"{key[1]}@{key[2]}" if key[2] else key[1]
        if key in chosen:
            report.warnings.append(f"{label}: ответ повторяется – взят последний.")
        raw_conclusion = item.get("conclusion", item.get("verdict", item.get("decision")))
        conclusion = norm_conclusion(raw_conclusion)
        recommended = one_line(item.get("recommended_version") or item.get("fixed_version")
                               or item.get("safe_version"), MAX_VERSION)
        explanation, cut = text_block(item.get("explanation") or item.get("comment") or item.get("reason"),
                                      MAX_EXPLANATION)
        links, dropped = norm_links(item.get("links") or item.get("sources") or item.get("references"))
        # Охват ответа – уязвимости, по которым агент отвечал: поле vulnerabilities из заготовки; его нет –
        # уязвимости библиотеки в проекте на момент загрузки
        raw_vulns = item.get("vulnerabilities")
        if isinstance(raw_vulns, str):
            raw_vulns = re.split(r"[\s,;]+", raw_vulns)
        vulns = _dedupe(norm_id(x) for x in raw_vulns or [])[:MAX_IDS] if isinstance(raw_vulns, (list, tuple,
                                                                                                str)) else []
        if not vulns:
            vulns = _dedupe(norm_id(x) for x in [*(candidates[key].get("cve") or []),
                                                 *(candidates[key].get("vuln_ids") or [])])
        answer = ScaAnswer(component=key[1], version=key[2], ecosystem=key[0], recommended_version=recommended,
                           conclusion=conclusion, explanation=explanation.translate(_DASHES),
                           ids=norm_ids(item.get("ids") or item.get("aliases") or item.get("mapping")), links=links,
                           vulnerabilities=vulns)
        chosen[key] = answer
        if not conclusion:
            shown = one_line(raw_conclusion, 40)
            report.warnings.append(f"{label}: вывод {'«' + shown + '» не распознан' if shown else 'не указан'} – "
                                   "ответ сохранён без вывода.")
        for note in answer_notes(key[2], answer.to_dict(), candidates[key].get("fixed_versions") or []):
            if note["tone"] == "warn" and note["text"] != "вывод не указан":
                report.warnings.append(f"{label}: {note['text']}.")
        if dropped:
            report.warnings.append(f"{label}: отброшено ссылок – {dropped} (принимаются только адреса http и https).")
        if cut:
            report.warnings.append(f"{label}: пояснение обрезано до {MAX_EXPLANATION} знаков.")
    if nameless:
        report.warnings.append(f"Записей без имени библиотеки (component) пропущено: {nameless}.")
    report.answers = list(chosen.values())
    report.without_answer = [f"{k[1]}@{k[2]}" if k[2] else k[1] for k in known if k not in chosen]
    return report


# ============================================================================ соответствие AST → CVE

@dataclass
class MapReport:
    """Итог разбора соответствия AST → CVE: пары, номера пропущенных строк файла, была ли строка заголовка."""

    pairs: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[int] = field(default_factory=list)
    header: bool = False


def _map_row(cells: list[str]) -> tuple[str, list[str]]:
    """Строка соответствия -> (идентификатор, [CVE-… или GHSA-…]); не подходит – ("", [])."""
    cells = [c.strip() for c in cells if c is not None and c.strip()]
    if len(cells) == 1:
        cells = re.split(r"\s+", cells[0], maxsplit=1)
    if not cells:
        return "", []
    source = norm_id(cells[0])
    targets = _dedupe(t for t in (norm_id(x) for cell in cells[1:] for x in re.split(r"[\s,;|]+", cell))
                      if t and t != source and is_target_id(t))
    return (source, targets) if source and targets else ("", [])


def _guess_delimiter(text: str) -> str:
    """Разделитель колонок: тот, при котором больше строк из первых 50 дают пару «идентификатор – CVE»."""
    sample = "\n".join(text.splitlines()[:50])
    best, best_score = ",", -1
    for delimiter in (",", ";", "\t", "|"):
        try:
            rows = list(csv.reader(io.StringIO(sample, newline=""), delimiter=delimiter))
        except csv.Error:
            continue
        score = sum(1 for cells in rows if _map_row(cells)[0])
        if score > best_score:
            best, best_score = delimiter, score
    return best


def parse_ast_map(text: str) -> MapReport:
    """CSV с двумя колонками: идентификатор (AST-…) и соответствующие CVE или GHSA (несколько – через пробел,
    запятую или точку с запятой внутри ячейки). Разделитель колонок – запятая, точка с запятой, табуляция или «|»;
    строка заголовка пропускается. ScaInputError – соответствий в файле нет."""
    text = str(text or "").replace(BOM, "")
    if not text.strip():
        raise ScaInputError("Вставьте соответствие AST → CVE или выберите файл CSV.")
    report = MapReport()
    seen: set[tuple[str, str]] = set()
    try:
        rows = csv.reader(io.StringIO(text, newline=""), delimiter=_guess_delimiter(text))
        for lineno, cells in enumerate(rows, start=1):
            if lineno > MAX_MAP_ROWS:
                raise ScaInputError(f"Слишком много строк: допустимо до {MAX_MAP_ROWS}.")
            if not any(c.strip() for c in cells):
                continue
            source, targets = _map_row(cells)
            if not source:
                if not report.pairs and not report.skipped and not report.header:
                    report.header = True  # первая непустая строка без пары – заголовок
                else:
                    report.skipped.append(lineno)
                continue
            for target in targets:
                if (source, target) not in seen:
                    seen.add((source, target))
                    report.pairs.append((source, target))
    except csv.Error:
        raise ScaInputError("Файл не похож на CSV: нужны две колонки – AST-… и CVE-….") from None
    if not report.pairs:
        raise ScaInputError("Соответствий не найдено: нужны две колонки – идентификатор AST-… и CVE-… или GHSA-….")
    return report


# ============================================================================ текст для AppSec.Hub

# Сайты первоисточников, где страница относится к версии пакета, а не к уязвимости: реестры (остальные в PRIMARY_SOURCES – базы уязвимостей)
_REGISTRY_SITES = ("central.sonatype.com", "repo1.maven.org", "pypi.org", "npmjs.com", "nuget.org", "pkg.go.dev", "crates.io")


def _registry_version(site: str, path: str) -> str:
    """Версия из декодированного пути страницы реестра site (из _REGISTRY_SITES), по формату его адресов; страница пакета в целом – ""."""
    parts = [p for p in path.split("/") if p]
    if site == "pkg.go.dev":  # /example.org/lib@v4.1.2/sub
        return next((p.rpartition("@")[2] for p in parts if "@" in p), "")
    if site == "repo1.maven.org":  # /maven2/org/example/lib/4.1.2/lib-4.1.2.pom или каталог версии
        if parts and parts[-1].rpartition(".")[2] in ("pom", "jar", "war", "aar", "module", "sha1", "md5", "asc"):
            return parts[-2] if len(parts) >= 2 else ""
        return parts[-1] if parts else ""
    # /project/lib/4.1.2, /packages/Lib/4.1.2, /crates/lib/4.1.2, /package/lib/v/4.1.2, /package/@s/lib/v/4.1.2, /artifact/org/lib/4.1.2
    if site == "npmjs.com":
        return parts[-1] if len(parts) >= 2 and parts[-2] == "v" else ""
    return parts[-1] if len(parts) >= {"central.sonatype.com": 4}.get(site, 3) else ""


def comment_link_fits(url: str, target: str) -> bool:
    """Ссылка годится в заготовку комментария (план dev9, часть 2, п. 6): база уязвимостей – да; страница реестра – только целевой
    версии, страница другой версии или пакета в целом – нет. url уже прошёл is_primary_source."""
    parts = urlsplit(url)
    host = (parts.hostname or "").removeprefix("www.")
    site = next((s for s in _REGISTRY_SITES if host == s or host.endswith("." + s)), "")
    if not site:
        return True
    return bool(target) and _registry_version(site, unquote(parts.path)) in (target, "v" + target)


def suggested_comment(f: Finding, answer: Mapping[str, Any] | None, aliases: Mapping[str, dict], target: str | None = None) -> str:
    """Комментарий для Hub по ответу агента (вывод, версия, пояснение, источники). Без ответа агента заготовки нет:
    версия исправления из выгрузки Hub – справка, а не основание, и в тексте для Hub не называется безопасной
    (ADR-0100). target – целевая версия, та же, что у дефекта (карточка, sca_text.resolve_target); None – версия из ответа
    агента, "" – версию не называть. Нечего предложить – ""."""
    component = one_line(f.package_display_name, MAX_COMPONENT) or "библиотека"
    version = one_line(f.version, MAX_VERSION)
    named = f"{component} {version}".strip()
    ids = public_ids_text(finding_ids(f), aliases)  # без внутренних номеров AST (ADR-0101)
    answer = answer_for(f, answer)  # ответ исследования – по уязвимостям этой находки (ADR-0108)
    conclusion = (answer or {}).get("conclusion") or ""
    # версия Hub целью не бывает: она бывает уязвимой
    target = one_line((answer or {}).get("recommended_version") if target is None else target, MAX_VERSION)
    lines: list[str] = []
    if conclusion == "update":
        head = f"Обновить {component}" + (f" с версии {version}" if version else "")
        lines.append(head + (f" до {target}." if target else "."))
        if ids:
            lines.append(f"{'Уязвимости' if ', ' in ids else 'Уязвимость'}: {ids}.")
    elif conclusion == "not_applicable":
        lines.append(f"Не применимо: {ids or 'уязвимость'} не затрагивает {named}.")
    elif conclusion == "unclear":
        lines.append(f"Требуется проверка: {ids or 'уязвимость'} в {named}.")
    else:
        return ""
    from app.sca_text import strip_internal_ids
    explanation = short_text(hub_clean(strip_internal_ids((answer or {}).get("explanation") or "")),
                             COMMENT_EXPLANATION)
    if explanation:
        lines.append(explanation)
    # в Hub – только ссылки на первоисточники: ссылку на другой сайт агент мог взять с прочитанной страницы
    links = [link for link in (norm_link(x) for x in ((answer or {}).get("links") or []))
             if link and is_primary_source(link) and not _AST_ID.search(link) and comment_link_fits(link, target)][:COMMENT_LINKS]
    if links:
        lines.append("Источники: " + ", ".join(links))
    return "\n".join(lines).translate(_DASHES)


def fallback_comment(f: Finding, verdict: str, aliases: Mapping[str, dict] | None = None) -> str:
    """Комментарий, если его не написали: вывод по библиотеке, её версии и уязвимостям."""
    component = one_line(f.package_display_name, MAX_COMPONENT) or "библиотека"
    version = one_line(f.version, MAX_VERSION)
    named = f"{component} {version}".strip()
    ids = describe_ids(finding_ids(f), aliases or {})
    if verdict == "true_positive":
        target = first_version(f.fixed_version)
        text = f"Обновить {component}" + (f" с версии {version}" if version else "") + (
            f" до {target}." if target else ".")
        return text + (f" {'Уязвимости' if ', ' in ids else 'Уязвимость'}: {ids}." if ids else "")
    if verdict == "false_positive":
        return f"Не применимо: {ids or 'уязвимость'} не затрагивает {named}."
    return f"Требуется проверка: {ids or 'уязвимость'} в {named}."


def sca_comment(f: Finding, verdict: str, comment: str, aliases: Mapping[str, dict] | None = None,
                kapo_state: str = "") -> str:
    """Короткое заключение по находке SCA по ГОСТ Р КАПО (окончательная редакция, пп. 6.12, 6.14) – текст поля
    «Комментарий» для «Скопировать для Hub». verdict – итог решения (hub_verdict), kapo_state – уточнение решения
    (у прежних решений пусто). Обоснование – комментарий оператора, не сокращается."""
    from app import defect
    component = hub_clean(one_line(f.package_display_name, MAX_COMPONENT)) or "компонент"
    version = hub_clean(one_line(f.version, MAX_VERSION))
    named = f"{component} {version}".strip()
    ids = describe_ids(finding_ids(f), aliases or {}) or "уязвимость"
    reason = defect.reason_text(comment, clean=True)  # прежний формат: прежняя чистка, отпечатки не меняются
    # безопасная версия из выгрузки – только символы обозначения версии: разметка и мусор после неё в текст не идут
    found = re.match(r"[0-9A-Za-z][0-9A-Za-z.+~:_-]*", hub_clean(first_version(f.fixed_version)))
    hub_safe = found.group(0) if found else ""
    target = f" (по данным Hub – {hub_safe} или новее)" if hub_safe else ""
    # критичность – в каждом заключении: число CVSS из выгрузки без приписанного источника
    severity = (f"Критичность: не определена – оценка по регламенту КАПО не выполнена; CVSS по выгрузке Hub – "
                f"{cvss.number(f.cvss)} (версия CVSS и источник в выгрузке не указаны)." if f.cvss is not None
                else "Критичность: не определена – оценки CVSS в выгрузке нет, оценка по регламенту КАПО не выполнена.")
    lines: list[str] = []
    if verdict == "true_positive":
        state = kapo_state if kapo_state in ("not_finished", "actual") else "not_finished"
        lines.append(f"По выгрузке Hub в продукте используется компонент {named} с известной уязвимостью {ids}. "
                     f"Статус уязвимости по ГОСТ Р КАПО: {defect.KAPO_LABELS[state]}.")
        if reason:
            lines.append(f"Обоснование: {reason}")
        if state == "actual":
            lines.append(f"Требуется от разработчика: принять компенсирующие меры – обновить {component} до безопасной "
                         f"версии{target}, а если обновить нельзя – доработать компонент или ограничить условия "
                         f"эксплуатации. {defect.DEADLINE_SCA}")
        else:
            lines.append(f"Требуется от разработчика: обновить {component} до безопасной версии{target} или представить "
                         "обоснование неактуальности уязвимости; если обновить нельзя – принять компенсирующие меры. "
                         f"{defect.DEADLINE_SCA}")
        lines.insert(1, severity)
    elif verdict == "false_positive":
        lines.append(f"Ложноположительное срабатывание (ГОСТ Р КАПО, п. 6.12): {ids} в {named} не подтверждена.")
        lines.append("Критичность: не оценивалась – уязвимость в компоненте не подтверждена.")
        if reason:
            lines.append(f"Обоснование: {reason}")
    elif verdict == "risk_accepted":
        if kapo_state == "not_actual":
            lines.append(f"Уязвимость {ids} в {named} неактуальна для продукта (ГОСТ Р КАПО, п. 6.14).")
            if reason:
                lines.append(f"Обоснование неактуальности: {reason}")
        elif kapo_state == "neutralized":
            lines.append(f"Уязвимость {ids} в {named} нейтрализована принятыми мерами (ГОСТ Р КАПО, п. 6.14).")
            if reason:
                lines.append(f"Принятые меры и обоснование: {reason}")
        else:
            lines.append(f"Риск принят по уязвимости {ids} в {named}; уточнение по ГОСТ Р КАПО не указано.")
            if reason:
                lines.append(f"Обоснование: {reason}")
        lines.insert(1, severity)
    else:
        lines.append(f"Требуется проверка: {ids} в {named}.")
        lines.append(severity)
        if reason:
            lines.append(reason)
    return "\n".join(lines).translate(_DASHES)


_AST_ID = re.compile(r"\bAST-\d{4}-\d+\b", re.I)  # внутренний номер (ADR-0101), как в sca_text
SHORT_OUTCOMES = ("false_positive", "risk_accepted")  # исходы SCA с коротким текстом для Hub (ADR-0091 п. 3)


def hub_text(f: Finding, verdict: str, comment: str, status_map: Mapping[str, str] | None = None,
             aliases: Mapping[str, dict] | None = None, *, kapo_state: str = "") -> str:
    """Короткий текст для Hub по находке SCA (ADR-0101 п. 2): у «Ложное срабатывание» и
    «Риск принят» – «<публичные идентификаторы находки> в <компонент> <версия>: <обоснование оператора>».
    Идентификаторы – CVE, GHSA, БДУ находки и её известные публичные соответствия, без AST; публичных нет –
    «<компонент> <версия>: <обоснование>»; обоснование уже начинается с одного из этих идентификаторов – без приставки.
    С 0.10.0.dev21 обоснование – как написал оператор: без среза вводного слова, тегов, схем,
    невидимых знаков и замены тире; убираются только внутренние номера AST (ADR-0101 п. 1). Приставка собрана из
    данных выгрузки и чистится, как раньше. Пустое обоснование – "" (приставка обоснованием не служит). У «Обновить»
    короткого текста нет (только дефект набора), у «Отложить» и «неясно» – тоже: "". status_map и kapo_state – общие
    с прежними форматами."""
    from app import defect
    from app.sca_text import strip_ids_keep_indent
    if verdict not in SHORT_OUTCOMES or not short_reason(comment):
        return ""  # одно вводное слово или одни номера AST – обоснования нет, приставка его не заменяет
    reason = defect.edges(strip_ids_keep_indent(defect._finish(comment)))
    head = _short_head(f, reason, aliases)
    return defect._finish(f"{defect._finish(head, clean=True)}: {reason}") if head else reason


def _short_head(f: Finding, reason: str, aliases: Mapping[str, dict] | None) -> str:
    """Приставка короткого текста SCA (ADR-0101 п. 2) – или "", если обоснование уже начинается с одного из
    публичных идентификаторов находки целым токеном; начальный отступ обоснования не мешает (как в браузере,
    hasOwnId; ревью Kimi круга 4)."""
    ids = [x for x in public_ids_text(finding_ids(f), aliases or {}).split(", ") if x]
    if any(re.match(rf"{re.escape(vuln_id)}(?![\w-])", reason.lstrip(), re.I) for vuln_id in ids):
        return ""
    named = " ".join(x for x in (one_line(f.package_display_name, MAX_COMPONENT), one_line(f.version, MAX_VERSION))
                     if x)
    return f"{', '.join(ids)} в {named}" if ids and named else (", ".join(ids) or named)


def hub_text_v4(f: Finding, verdict: str, comment: str, status_map: Mapping[str, str] | None = None,
                aliases: Mapping[str, dict] | None = None, *, kapo_state: str = "") -> str:
    """Формат 0.9.11–0.10.0.dev20 (только узнавание отметок «Внесено в Hub», поставленных до 0.10.0.dev21):
    приставка, обоснование по прежним правилам hub_text_v3 (вводное слово снято, прежняя чистка) без AST, весь текст
    ещё раз через прежнюю чистку."""
    from app import defect
    from app.sca_text import strip_internal_ids
    reason = hub_text_v3(f, verdict, comment)
    reason = strip_internal_ids(reason).strip() if reason else ""
    if not reason:
        return ""
    head = _short_head(f, reason, aliases)
    return defect._finish(f"{head}: {reason}", clean=True) if head else reason


def short_reason(comment: str) -> str:
    """Обоснование короткого текста SCA для проверки, есть ли оно: без вводного «Ложное срабатывание:» и подобного
    (одно вводное слово обоснованием не считается) и без внутренних номеров AST (ADR-0101). Пусто – обоснования нет,
    приставка его не заменяет. В Hub уходит комментарий как написан (hub_text), вводное слово не срезается."""
    from app import defect
    from app.sca_text import strip_internal_ids
    return strip_internal_ids(defect._finish(defect.reason_text(comment), clean=True)).strip()


def hub_text_v3(f: Finding, verdict: str, comment: str, status_map: Mapping[str, str] | None = None,
                aliases: Mapping[str, dict] | None = None, *, kapo_state: str = "") -> str:
    """Формат 0.9.8–0.9.10 (ADR-0091 п. 3): у «Ложное срабатывание» и «Риск принят» – только обоснование оператора
    без вводного слова, с прежней чисткой; иначе "". По нему узнаются отметки «Внесено в Hub», поставленные до 0.9.11
    («формат обновился»), и из него строится формат hub_text_v4. Не меняется."""
    from app import defect
    if verdict not in SHORT_OUTCOMES:
        return ""
    return defect._finish(defect.reason_text(comment, clean=True), clean=True)


def hub_text_v2(f: Finding, verdict: str, comment: str, status_map: Mapping[str, str] | None = None,
                aliases: Mapping[str, dict] | None = None, *, kapo_state: str = "") -> str:
    """Формат 0.9.0–0.9.7 (по нему узнаются отметки «Внесено в Hub», поставленные до 0.9.8): «Статус: …» и
    «Комментарий: …» с коротким заключением по ГОСТ Р КАПО (sca_comment)."""
    from app import defect
    statuses = dict(DEFAULT_STATUS_MAP)
    statuses.update({str(k): v.strip() for k, v in (status_map or {}).items() if isinstance(v, str)})
    return defect.hub_lines(statuses.get(verdict, ""), sca_comment(f, verdict, comment, aliases, kapo_state))


def hub_text_v1(f: Finding, verdict: str, comment: str, status_map: Mapping[str, str] | None = None,
                aliases: Mapping[str, dict] | None = None) -> str:
    """Прежний формат текста для Hub (до 0.9.0): по нему узнаются отметки «Внесено в Hub», поставленные до смены
    формата.

    Текст для вставки в AppSec.Hub: «Статус: …» и «Комментарий: …», как у SAST.

    verdict – вердикт решения (true_positive – обновить, false_positive – не применимо, uncertain – неясно);
    status_map – статусы Hub по вердиктам поверх значений по умолчанию. Пустой комментарий заменяется коротким
    выводом по библиотеке. Длинное тире заменяется на «–»."""
    statuses = dict(DEFAULT_STATUS_MAP)
    statuses.update({str(k): v.strip() for k, v in (status_map or {}).items() if isinstance(v, str)})
    status = statuses.get(verdict, "")
    text = str(comment or "").replace("\r\n", "\n")
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(line.rstrip() for line in text.split("\n"))).strip()
    lines = [f"Статус: {status}"] if status else []
    lines.append(f"Комментарий: {text or fallback_comment(f, verdict, aliases)}")
    return "\n".join(lines).translate(_DASHES)
