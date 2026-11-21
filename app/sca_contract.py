"""Контракт ответа агента по исследованию компонентов SCA, версия 2.

Один модуль обслуживает и приложение, и внешнего агента: из одного описания полей собираются и JSON Schema
для агента, и все проверки приложения, поэтому описание и проверки разойтись не могут. Только стандартная
библиотека Python 3.11: этот же файл без изменений копируется в комплект задания как validate.py и запускается
агентом отдельно от приложения, поэтому импортировать app.* здесь нельзя.

Что проверяется и с какой строгстью: значения и перечисления, лишние и пропущенные поля, полный набор строк
задания без пропусков и дублей, неизменность входных координат, несуществующие ссылки на доказательства,
будущие даты, внутренние номера AST, пределы объёма (отказ с кодом, без обрезки) и очевидные противоречия
между полями. Состояние пакета не принимается на веру: оно вычисляется по проверенным полям, и заявленный
агентом статус должен совпасть с вычисленным.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field as dc_field
from datetime import date, datetime, timedelta
from hashlib import sha256 as _sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# ------------------------------------------------------------------ контракт и пределы

ANSWER_CONTRACT = "local-triage/sca-answers/2"
TASK_CONTRACT = "local-triage/sca-task/2"
REPORT_CONTRACT = "local-triage/sca-report/2"
# 2.1.1 – явный диапазон «от начала без верхней границы» (introduced="0", без fixed и last_affected) затрагивает все
# версии, а не «порядок не проверен»; схема ответа та же, что у 2.1.0
VALIDATOR_VERSION = "sca-contract/2.1.1"
ACCEPTED_VALIDATORS = (VALIDATOR_VERSION, "sca-contract/2.1.0", "sca-contract/2.0.2", "sca-contract/2.0.1")
# версии схемы ответа, в которых допустимы расширения 2.1 (ADR-0094): проверка версий Hub и цели, статус
# исправления, оспоренность и позиции источников
EXTENSION_VALIDATORS = ("sca-contract/2.1.0", VALIDATOR_VERSION)
EXTENSION_FIELDS = ("version_checks", "fix_status", "disputed", "source_positions")

# Пределы объёма. Обновление ответов первой версии заканчивалось десятью ссылками на компонент, поэтому здесь
# запас на десятки публичных уязвимостей и доказательств. Пределы публикуются в manifest и в схеме ответа:
# агент узнаёт о них до работы, а отказ приходит с кодом и без обрезки.
LIMITS: dict[str, int] = {
    "answer_bytes": 16 * 1024 * 1024,
    "row_bytes": 512 * 1024,
    "max_rows": 5000,
    "findings_per_row": 500,
    "evidence_per_row": 128,
    "coverage_per_row": 64,
    "gaps_per_row": 32,
    "aliases_per_finding": 64,
    "ranges_per_finding": 32,
    "fixed_versions_per_finding": 32,
    "source_refs": 128,
    "candidates_per_row": 32,
    "id_chars": 64,
    "version_chars": 64,
    "url_chars": 1000,
    "text_chars": 4000,
    "note_chars": 2000,
    "quote_chars": 4000,
    "source_chars": 120,
    "version_checks_per_row": 8,
    "positions_per_finding": 8,
    "depth": 12,
    # больше этого числа ошибок в отчёте не показываем, но обязательно говорим, что список неполный
    "reported_errors": 200,
}

IDENTITY_STATES = ("resolved", "ambiguous", "unresolved", "unknown")
UPDATE_STATUSES = ("up_to_date", "update_available", "unknown")
SUPPORT_STATES = ("supported", "maintenance", "eol", "deprecated", "archived", "unknown")
SUPPORT_SCOPES = ("oss", "commercial", "unknown")
APPLIES_VALUES = ("yes", "no", "unknown")
COVERAGE_STATUSES = ("ok", "partial", "error")
EVIDENCE_SOURCES = ("registry", "advisory", "release_notes", "policy", "aggregator", "issue_tracker", "other")
EVIDENCE_LEVELS = ("primary", "corroborated", "single_source", "unconfirmed")
ADVICE_ACTIONS = ("update", "replace", "keep", "remove", "accept_risk", "needs_identity", "no_action",
                  "insufficient_data")
PACKAGE_STATUSES = ("vulnerable", "no_known_vulnerabilities", "incomplete", "identity_unresolved")
GAP_CODES = ("IDENTITY_AMBIGUOUS", "IDENTITY_UNRESOLVED", "VERSION_UNKNOWN", "RELEASE_UNKNOWN", "COVERAGE_INCOMPLETE",
             "SOURCE_UNAVAILABLE", "SOURCE_BLOCKED", "NO_PUBLIC_FIX", "FIX_UNCONFIRMED", "APPLICABILITY_UNCLEAR",
             "LICENSE_UNKNOWN", "SUPPORT_UNKNOWN", "NOT_RESEARCHED", "OTHER")

# Дата проверки источника не может быть в будущем: источника с таким ответом ещё не существует.
# Допуск в сутки – на разницу часовых поясов у агента и у этого компьютера.
FUTURE_TOLERANCE_DAYS = 1
# Источники, где ищут уязвимости, определяются не названием, а целью проверки: официальный бюллетень проекта
# годится, а проверка метаданных публикации в реестре – нет. Поэтому запись охвата объявляет, зачем её делали.
# Обе формы названия цели принимаются (релиз/release), важна не форма, а смысл.
COVERAGE_PURPOSES = ("vulnerabilities", "releases", "release", "support", "identity", "licenses", "license",
                     "other")
# Номера AST-соответствий внутренние: в публичном ответе по компоненту им не место (AGENTS.md).
_AST = re.compile(r"(?i)\bast[-\u2013]?[0-9]{4}[-\u2013]?[0-9]{3,}")
_REF_PREFIX = re.compile(r"^[a-z][a-z0-9]*$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


# ------------------------------------------------------------------ вспомогательное

def canonical(obj: Any) -> bytes:
    """Один канонический вид JSON: UTF-8, ключи по алфавиту, без пробелов. По нему считаются отпечатки,
    поэтому и манифест, и ответ агента канонизируются одинаково."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha256(data: bytes | str) -> str:
    """Отпечаток SHA-256 в нижнем регистре: тот же для байтов и для текста в UTF-8."""
    return _sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def input_ref(ecosystem: str, name: str, version: str) -> str:
    """Устойчивый ключ входной строки: экосистема, исходное имя и исходная версия. Подтверждённая агентом
    координата ключ не меняет (ecosystem:name@version)."""
    digest = sha256(canonical([str(ecosystem or ""), str(name or ""), str(version or "")]))
    prefix = str(ecosystem or "").casefold()
    prefix = prefix if _REF_PREFIX.match(prefix) else "unk"
    return f"{prefix}:{digest[:16]}"


def row_status(row: Mapping[str, Any]) -> str:
    """Состояние пакета по проверенным полям, а не по заявлению агента: неподтверждённая идентичность, затем
    применимые находки, затем полнота охвата. Пустой результат при ошибке источника чистым не считается."""
    identity = _obj(row.get("identity_resolution"))
    state = _text(identity.get("state"))
    if state not in ("resolved", "unknown"):
        return "identity_unresolved"
    if state == "unknown" or not _text(identity.get("coordinates")):
        return "incomplete"  # идентичность ещё не определяли – это неполнота исследования, а не вывод о пакете
    findings = [_obj(item) for item in _list(row.get("public_findings"))]
    if any(item.get("applies") == "yes" for item in findings):
        return "vulnerable"
    if any(item.get("applies") == "unknown" for item in findings):
        return "incomplete"  # применимость не выяснена: чистым результат не может быть
    coverage = [_obj(item) for item in _list(row.get("research_coverage"))]
    checked = [item for item in coverage if _text(item.get("purpose")) == "vulnerabilities"]
    if not checked:
        return "incomplete"  # проверяли публикацию пакета или поддержку, а уязвимости по нему не искали
    if any(item.get("status") != "ok" or not item.get("complete") for item in checked):
        return "incomplete"
    # сорванный поиск релизов или политики поддержки не отменяет удавшийся поиск уязвимостей: это пробел,
    # а не провал проверки, о которой спрашивает состояние
    return "no_known_vulnerabilities"


def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


# ------------------------------------------------------------------ описание полей

class Field:
    """Одно поле контракта: тип, границы, перечисление, шаблон, необязательность. Из него и JSON Schema,
    и проверка значения, поэтому лишнее поле или неверный тип нельзя пропустить незаметно."""

    __slots__ = ("kind", "fields", "item", "enum", "min_chars", "max_chars", "pattern", "fmt", "minimum",
                 "maximum", "min_items", "max_items", "unique_key", "unique_code", "nullable", "required")

    def __init__(self, kind: str, *, fields: Mapping[str, "Field"] | None = None, item: "Field | None" = None,
                 enum: Iterable[str] | None = None, min_chars: int | None = None, max_chars: int | None = None,
                 pattern: str | None = None, fmt: str | None = None, minimum: float | None = None,
                 maximum: float | None = None, min_items: int | None = None, max_items: int | None = None,
                 unique_key: str | tuple[str, ...] | None = None, unique_code: str = "SCA-M005", nullable: bool = False,
                 required: bool = True):
        self.kind = kind
        self.fields = dict(fields or {})
        self.item = item
        self.enum = tuple(enum) if enum else None
        self.min_chars = min_chars
        self.max_chars = max_chars
        self.pattern = pattern
        self.fmt = fmt
        self.minimum = minimum
        self.maximum = maximum
        self.min_items = min_items
        self.max_items = max_items
        self.unique_key = unique_key
        self.unique_code = unique_code
        self.nullable = nullable
        self.required = required

    def schema(self) -> dict:
        if self.kind == "object":
            out: dict[str, Any] = {"type": "object", "additionalProperties": False,
                                   "required": [name for name, item in self.fields.items() if item.required],
                                   "properties": {name: item.schema() for name, item in self.fields.items()}}
        elif self.kind == "array":
            out = {"type": "array", "items": (self.item or Field("string")).schema()}
            if self.min_items is not None:
                out["minItems"] = self.min_items
            if self.max_items is not None:
                out["maxItems"] = self.max_items
        elif self.kind == "string":
            out = {"type": "string"}
            if self.enum:
                out["enum"] = list(self.enum)
            if self.min_chars is not None:
                out["minLength"] = self.min_chars
            if self.max_chars is not None:
                out["maxLength"] = self.max_chars
            if self.pattern:
                out["pattern"] = self.pattern
            if self.fmt:
                out["format"] = self.fmt
        else:
            out = {"type": self.kind}
        if self.minimum is not None:
            out["minimum"] = self.minimum
        if self.maximum is not None:
            out["maximum"] = self.maximum
        if self.nullable:
            out["type"] = [out["type"], "null"]
        return out

    def check(self, value: Any, path: str, ctx: "Context", errors: list[dict]) -> None:
        if value is None and self.nullable:
            return
        if self.kind == "object":
            self._check_object(value, path, ctx, errors)
        elif self.kind == "array":
            self._check_array(value, path, ctx, errors)
        elif self.kind == "string":
            self._check_string(value, path, ctx, errors)
        else:
            self._check_number(value, path, ctx, errors)

    def _fail(self, code: str, path: str, message: str, errors: list[dict]) -> None:
        errors.append({"code": code, "path": path or "ответ", "message": message})

    def _check_object(self, value: Any, path: str, ctx: "Context", errors: list[dict]) -> None:
        if not isinstance(value, dict):
            self._fail("SCA-M005", path, "ожидался объект", errors)
            return
        for name in value:
            if name not in self.fields:
                self._fail("SCA-M003", f"{path}.{name}", "поля нет в контракте", errors)
        for name, item in self.fields.items():
            if name not in value:
                if item.required:
                    self._fail("SCA-M004", f"{path}.{name}", "обязательное поле не заполнено", errors)
                continue
            item.check(value[name], f"{path}.{name}", ctx, errors)

    def _check_array(self, value: Any, path: str, ctx: "Context", errors: list[dict]) -> None:
        if not isinstance(value, list):
            self._fail("SCA-M005", path, "ожидался список", errors)
            return
        limit = self.max_items if self.max_items is not None else ctx.limits["max_rows"]
        if len(value) > limit:
            self._fail("SCA-M002", path, f"элементов больше предела ({len(value)} при пределе {limit})", errors)
            return
        if self.min_items is not None and len(value) < self.min_items:
            self._fail("SCA-M005", path, f"элементов меньше минимума ({len(value)})", errors)
        if self.unique_key:
            seen: set[Any] = set()
            for index, item in enumerate(value):
                names = self.unique_key if isinstance(self.unique_key, tuple) else (self.unique_key,)
                parts = tuple(_obj(item).get(name) for name in names)
                if any(not isinstance(part, str) for part in parts):
                    # Тип проверяется ниже описанием поля; списки и объекты нельзя хешировать.
                    continue
                key = parts if len(names) > 1 else parts[0]
                if key in seen:
                    self._fail(self.unique_code, f"{path}[{index}].{names[0]}",
                               f"повтор значения {key!r}", errors)
                seen.add(key)
        for index, item in enumerate(value):
            (self.item or Field("string")).check(item, f"{path}[{index}]", ctx, errors)

    def _check_string(self, value: Any, path: str, ctx: "Context", errors: list[dict]) -> None:
        if not isinstance(value, str):
            self._fail("SCA-M005", path, "ожидалась строка", errors)
            return
        if self.enum and value not in self.enum:
            self._fail("SCA-M005", path, f"значение не из перечисления: {value!r}", errors)
            return
        if self.min_chars is not None and len(value.strip()) < self.min_chars:
            self._fail("SCA-M005", path, f"строка короче {self.min_chars} символов", errors)
        if self.max_chars is not None and len(value) > self.max_chars:
            self._fail("SCA-M002", path, f"строка длиннее предела ({len(value)} при пределе {self.max_chars})",
                       errors)
        if self.pattern and not re.match(self.pattern, value):
            self._fail("SCA-M005", path, "значение не по шаблону контракта", errors)
        if self.fmt and value.strip():  # пустое значение – факт ещё не установлен, а не ошибка даты
            stamp = _timestamp(value)
            if stamp is None:
                self._fail("SCA-M005", path, f"не дата и не время ISO 8601: {value!r}", errors)
            elif stamp > ctx.today + timedelta(days=FUTURE_TOLERANCE_DAYS):
                self._fail("SCA-D001", path, f"дата в будущем: {value}", errors)

    def _check_number(self, value: Any, path: str, ctx: "Context", errors: list[dict]) -> None:
        if self.kind == 'integer' and type(value) is not int:
            self._fail('SCA-M005', path, 'ожидалось целое число', errors)
            return
        if self.kind == "boolean":
            if not isinstance(value, bool):
                self._fail("SCA-M005", path, f"ожидалось true или false, получено {type(value).__name__}",
                           errors)
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            self._fail("SCA-M005", path, f"ожидалось число, получено {type(value).__name__}", errors)
            return
        if isinstance(value, float) and not math.isfinite(value):
            self._fail("SCA-M001", path, "число вне диапазона (NaN или бесконечность)", errors)
            return
        if self.minimum is not None and value < self.minimum:
            self._fail("SCA-M005", path, f"меньше минимума {self.minimum}", errors)
        if self.maximum is not None and value > self.maximum:
            self._fail("SCA-M005", path, f"больше максимума {self.maximum}", errors)


def compare_versions(ecosystem: str, left: str, right: str) -> int | None:
    """SemVer, PEP 440, RubyGems и ограниченные числовые формы Maven/NuGet/Composer.

    Maven: числовые сегменты и alpha/beta/milestone/rc/snapshot/final/ga/release/sp с номером.
    Это не полная реализация ComparableVersion. Неизвестные суффиксы поставщика дают None:
    приложение не делает вид, что знает их порядок. У npm метаданные сборки порядок не меняют.
    """
    def sign(a, b):
        return (a > b) - (a < b)

    def numeric(parts):
        values = [int(x) for x in parts.split('.')]
        while len(values) > 1 and values[-1] == 0:
            values.pop()
        return tuple(values)

    def compare_core(a, b):
        size = max(len(a), len(b))
        return sign(a + (0,) * (size - len(a)), b + (0,) * (size - len(b)))

    left, right = _text(left), _text(right)
    if not left or not right:
        return None
    if left == right:
        return 0
    eco = ecosystem.casefold()
    if eco == 'pypi':
        a, b = _pep440_key(left), _pep440_key(right)
        return sign(a, b) if a is not None and b is not None else None
    if eco == 'gem':
        def gem(value):
            if not re.fullmatch(r'[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z.-]+)?', value):
                return None
            tokens = re.findall(r'[0-9]+|[A-Za-z]+', value.replace('-', '.pre.'))
            result = [(1, int(x)) if x.isdigit() else (0, x) for x in tokens]
            first_string = next((i for i,x in enumerate(result) if x[0] == 0),len(result))
            numeric_part = result[:first_string]
            while numeric_part and numeric_part[-1] == (1,0):
                numeric_part.pop()
            result = numeric_part + result[first_string:]
            while result and result[-1] == (1, 0):
                result.pop()
            return result
        a, b = gem(left), gem(right)
        if a is None or b is None:
            return None
        size = max(len(a), len(b))
        return sign(a + [(1, 0)] * (size-len(a)), b + [(1, 0)] * (size-len(b)))
    if eco in ('nuget', 'composer'):
        # NuGet: до четырёх числовых частей, регистр prerelease незначим.
        # Composer: опубликованные числовые релизы с необязательным v, без branch alias/dev-веток.
        def normalize(value):
            if eco == 'composer':
                value = value.removeprefix('v')
            m = re.fullmatch(r'([0-9]+(?:\.[0-9]+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?', value)
            if not m:
                return None
            nums = [int(x) for x in m[1].split('.')]
            nums += [0] * (4-len(nums))
            pre = m[2] or ''
            return nums, pre.casefold() if eco == 'nuget' else pre
        a, b = normalize(left), normalize(right)
        if a is None or b is None:
            return None
        core = sign(a[0], b[0])
        if core:
            return core
        left, right = '0.0.0' + ('-' + a[1] if a[1] else ''), '0.0.0' + ('-' + b[1] if b[1] else '')
        eco = 'npm'
    if ecosystem.casefold() == 'maven':
        pattern = r'([0-9]+(?:\.[0-9]+)*)(?:[.-]?(alpha|beta|milestone|rc|cr|snapshot|final|ga|release|sp|a|b|m)(?:[.-]?([0-9]+))?)?'
        a, b = re.fullmatch(pattern, left, re.I), re.fullmatch(pattern, right, re.I)
        if not a or not b:
            return None
        core = compare_core(numeric(a[1]), numeric(b[1]))
        if core:
            return core
        ranks = {'alpha': -5, 'a': -5, 'beta': -4, 'b': -4, 'milestone': -3, 'm': -3,
                 'rc': -2, 'cr': -2, 'snapshot': -1, '': 0, 'final': 0, 'ga': 0, 'release': 0, 'sp': 1}
        return sign((ranks[(a[2] or '').lower()], int(a[3] or 0)),
                    (ranks[(b[2] or '').lower()], int(b[3] or 0)))
    if eco not in ('npm', 'cargo'):
        return None
    pattern = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
    a, b = re.fullmatch(pattern, left), re.fullmatch(pattern, right)
    if not a or not b:
        return None
    pre_a, pre_b = (a[4] or '').split('.'), (b[4] or '').split('.')
    if any(x.isdigit() and len(x) > 1 and x[0] == '0' for x in pre_a + pre_b):
        return None
    core = sign(tuple(int(a[i]) for i in (1, 2, 3)), tuple(int(b[i]) for i in (1, 2, 3)))
    if core:
        return core
    if not a[4] or not b[4]:
        return sign(not a[4], not b[4])
    for x, y in zip(pre_a, pre_b, strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return sign(int(x), int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return sign(x, y)
    return sign(len(pre_a), len(pre_b))


def _pep440_key(value: str) -> tuple | None:
    """PEP 440: epoch, release, pre/post/dev и local; неизвестная форма остаётся неизвестной."""
    pattern = (r'v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)'
               r'(?:[-_.]?(?P<pre>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<prenum>[0-9]+)?)?'
               r'(?:(?:-(?P<postnum1>[0-9]+))|(?:[-_.]?(?P<post>post|rev|r)[-_.]?(?P<postnum2>[0-9]+)?))?'
               r'(?:[-_.]?(?P<dev>dev)[-_.]?(?P<devnum>[0-9]+)?)?'
               r'(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?')
    match = re.fullmatch(pattern, value, re.I)
    if not match:
        return None
    m = match.groupdict();release = [int(x) for x in m['release'].split('.')]
    while release and release[-1] == 0:
        release.pop()
    post = m['post'] is not None or m['postnum1'] is not None
    pre_names = {'a':0,'alpha':0,'b':1,'beta':1,'rc':2,'c':2,'pre':2,'preview':2}
    pre = (pre_names[m['pre'].lower()],int(m['prenum'] or 0)) if m['pre'] else (
        (-1,0) if m['dev'] and not post else (3,0))
    local = tuple((1,int(x)) if x.isdigit() else (0,x.lower())
                  for x in re.split(r'[-_.]',m['local'] or '') if x)
    return (int(m['epoch'] or 0),tuple(release),pre,
            (1,int(m['postnum1'] or m['postnum2'] or 0)) if post else (0,0),
            (0,int(m['devnum'] or 0)) if m['dev'] else (1,0),local)


def public_url_parts(text: str) -> tuple[str, str] | None:
    """Общие правила ссылок источников, без DNS-запросов и неоднозначной записи WHATWG."""
    if (not text or len(text) > LIMITS['url_chars'] or not text.isascii()
            or re.search(r'[\x00-\x20\x7f\\]', text)):
        return None
    try:
        parts = urlsplit(text); host = parts.hostname or ''
        if parts.scheme.lower() not in ('http','https') or parts.username is not None or parts.password is not None or parts.port not in (None,80,443):
            return None
    except ValueError:
        return None
    labels = host.split('.')
    if (len(labels)<2 or len(host)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels)
            or re.fullmatch(r'[0-9]+|0x[0-9a-f]*', labels[-1],re.I)
            or host.endswith(('.local','.internal','.lan','.corp','.localhost','.home','.intranet','.localdomain'))):
        return None
    for label in labels:
        if label.startswith('xn--'):
            try:
                if label.encode('ascii').decode('idna').isascii():
                    return None
            except UnicodeError:
                return None
    if re.search(r'["<>`{}]',parts.path) or any(re.fullmatch(r'(?:\.|%2e){1,2}',x,re.I) for x in parts.path.split('/')):
        return None
    return host, parts.path


def _timestamp(value: str) -> date | None:
    """Дата или время ISO 8601 из строки; пустая строка и мусор – None."""
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _date_field(max_chars: int = 40, required: bool = True) -> Field:
    """Поле-дата: пустое значение допустимо (факт ещё не установлен), непустое должно быть датой ISO 8601."""
    return Field("string", min_chars=0, max_chars=max_chars, fmt="date-time", required=required)


def _short(nullable: bool = False) -> Field:
    return Field("string", max_chars=LIMITS["id_chars"], nullable=nullable)


def _text_field(max_chars: int = LIMITS["text_chars"], nullable: bool = False) -> Field:
    return Field("string", max_chars=max_chars, nullable=nullable)


def _source_refs() -> Field:
    """Список ссылок на доказательства строки: значения сверяются с массивом evidence этой же строки."""
    return Field("array", item=_short(), max_items=LIMITS["source_refs"])

_CVSS = {
    "score": Field("number", minimum=0, maximum=10),
    "vector": _text_field(max_chars=200, nullable=True),
    "version": Field("string", min_chars=0, max_chars=8, nullable=True),
}
_RANGE = {"introduced": Field("string", max_chars=LIMITS["version_chars"], nullable=True),
          "fixed": Field("string", max_chars=LIMITS["version_chars"], nullable=True),
          "last_affected": Field("string", max_chars=LIMITS["version_chars"], nullable=True, required=False)}

_EVIDENCE_ITEM = {
    "evidence_ref": _short(),
    "url": Field("string", min_chars=8, max_chars=LIMITS["url_chars"], pattern=r"^https?://\S+$"),
    "checked_at": _date_field(),
    "source_type": Field("string", enum=EVIDENCE_SOURCES),
    "justification": Field("string", min_chars=3, max_chars=LIMITS["text_chars"]),
    "quote": Field("string", min_chars=1, max_chars=LIMITS["quote_chars"], nullable=True),
    "level": Field("string", enum=EVIDENCE_LEVELS),
}

FIX_STATUSES = ("fixed", "no_fix_published", "unknown")
FIX_SCOPES = ("package", "branch")
DISPUTED_BY = ("vendor", "other")
CHECK_ROLES = ("hub", "target")

_FIX_STATUS = Field("object", fields={
    "status": Field("string", enum=FIX_STATUSES),
    "scope": Field("string", enum=FIX_SCOPES),
    # ветка утверждения при scope=branch: префикс версий («42.7»), к цели относится, только если цель в этой ветке
    "branch": Field("string", max_chars=LIMITS["version_chars"], nullable=True, required=False),
    "source_refs": _source_refs(),
}, nullable=True, required=False)

_DISPUTED = Field("object", fields={
    "by": Field("string", enum=DISPUTED_BY),
    "note": _text_field(max_chars=LIMITS["note_chars"]),
    "source_refs": _source_refs(),
}, nullable=True, required=False)

_POSITION_ITEM = {
    "source": Field("string", min_chars=1, max_chars=LIMITS["source_chars"]),
    "affects": Field("string", enum=APPLIES_VALUES),
    "ranges": Field("array", item=Field("object", fields=_RANGE), max_items=LIMITS["ranges_per_finding"]),
    "source_refs": _source_refs(),
}

_FINDING_ITEM = {
    "id": Field("string", min_chars=3, max_chars=LIMITS["id_chars"]),
    "aliases": Field("array", item=_short(), max_items=LIMITS["aliases_per_finding"]),
    "applies": Field("string", enum=APPLIES_VALUES),
    "description": Field("string", min_chars=1, max_chars=LIMITS["text_chars"]),
    "ranges": Field("array", item=Field("object", fields=_RANGE), max_items=LIMITS["ranges_per_finding"]),
    "conditions": Field("string", max_chars=LIMITS["text_chars"], nullable=True),
    "fixed_versions": Field("array", item=_short(), max_items=LIMITS["fixed_versions_per_finding"]),
    "cvss": Field("object", fields=_CVSS, nullable=True),
    "source_refs": _source_refs(),
    "fix_status": _FIX_STATUS,
    "disputed": _DISPUTED,
    "source_positions": Field("array", item=Field("object", fields=_POSITION_ITEM),
                              max_items=LIMITS["positions_per_finding"], unique_key="source", required=False),
}

_COVERAGE_ITEM = {
    "source": Field("string", min_chars=1, max_chars=LIMITS["source_chars"]),
    "purpose": Field("string", enum=COVERAGE_PURPOSES),
    "query": Field("object", fields={"ecosystem": Field("string", max_chars=LIMITS["source_chars"], nullable=True),
                                     "coordinates": Field("string", max_chars=LIMITS["source_chars"],
                                                          nullable=True),
                                     "version": Field("string", max_chars=LIMITS["version_chars"],
                                                      nullable=True)}, nullable=True),
    "source_refs": Field("array", item=_short(), max_items=LIMITS["source_refs"]),
    "checked_at": _date_field(),
    "status": Field("string", enum=COVERAGE_STATUSES),
    "complete": Field("boolean"),
    "note": _text_field(max_chars=LIMITS["note_chars"], nullable=True),
}

_GAP_ITEM = {
    "code": Field("string", enum=GAP_CODES),
    "text": Field("string", min_chars=1, max_chars=LIMITS["note_chars"]),
}

_ADVICE = {
    "action": Field("string", enum=ADVICE_ACTIONS),
    "target_version": Field("string", max_chars=LIMITS["version_chars"], nullable=True),
    "source_refs": Field("array", item=_short(), max_items=LIMITS["source_refs"], required=False),
    "compatibility_notes": Field("string", max_chars=LIMITS["text_chars"], nullable=True),
    "remaining_risks": Field("array", item=_text_field(max_chars=LIMITS["note_chars"]),
                             max_items=LIMITS["gaps_per_row"]),
}

_ROW = Field("object", fields={
    "input_ref": Field("string", max_chars=LIMITS["id_chars"]),
    "ecosystem": Field("string", min_chars=0, max_chars=LIMITS["source_chars"]),
    "component": Field("string", min_chars=1, max_chars=LIMITS["source_chars"]),
    "current_version": Field("string", min_chars=1, max_chars=LIMITS["version_chars"]),
    "identity_resolution": Field("object", fields={
        "state": Field("string", enum=IDENTITY_STATES),
        "coordinates": Field("string", max_chars=LIMITS["source_chars"], nullable=True),
        "candidates": Field("array", item=_short(), max_items=LIMITS["candidates_per_row"]),
        "note": Field("string", max_chars=LIMITS["note_chars"], nullable=True),
        "basis": Field("string", max_chars=LIMITS["note_chars"], nullable=True, required=False),
        "source_refs": _source_refs(),
    }),
    "latest_stable_release": Field("object", fields={
        "version": Field("string", max_chars=LIMITS["version_chars"], nullable=True),
        "released_at": _date_field(),
        "note": Field("string", max_chars=LIMITS["note_chars"], nullable=True),
        "source_refs": _source_refs(),
    }),
    "update_status": Field("string", enum=UPDATE_STATUSES),
    "support_status": Field("object", fields={
        "state": Field("string", enum=SUPPORT_STATES),
        "scope": Field("string", enum=SUPPORT_SCOPES),
        "as_of": _date_field(),
        "note": Field("string", max_chars=LIMITS["note_chars"], nullable=True),
        "source_refs": _source_refs(),
    }),
    "public_findings": Field("array", item=Field("object", fields=_FINDING_ITEM),
                             max_items=LIMITS["findings_per_row"], unique_key="id",
                             unique_code="SCA-E001"),
    "research_coverage": Field("array", item=Field("object", fields=_COVERAGE_ITEM),
                               max_items=LIMITS["coverage_per_row"], unique_key=("source", "purpose"),
                               unique_code="SCA-M005"),
    "package_advice": Field("object", fields=_ADVICE),
    "evidence": Field("array", item=Field("object", fields=_EVIDENCE_ITEM),
                      max_items=LIMITS["evidence_per_row"], unique_key="evidence_ref", unique_code="SCA-E001"),
    "gaps": Field("array", item=Field("object", fields=_GAP_ITEM), max_items=LIMITS["gaps_per_row"]),
    "package_status": Field("string", enum=PACKAGE_STATUSES),
    # ADR-0094 Р2: проверка конкретных версий – исправления из Hub (role=hub) и цели (role=target); находки здесь
    # описывают проверенную версию и уязвимостями текущей версии не становятся
    "version_checks": Field("array", item=Field("object", fields={
        "role": Field("string", enum=CHECK_ROLES),
        "version": Field("string", min_chars=1, max_chars=LIMITS["version_chars"]),
        "coverage": Field("array", item=Field("object", fields=_COVERAGE_ITEM),
                          max_items=LIMITS["coverage_per_row"], unique_key=("source", "purpose"),
                          unique_code="SCA-M005"),
        "findings": Field("array", item=Field("object", fields={
            "id": Field("string", min_chars=3, max_chars=LIMITS["id_chars"]),
            "aliases": Field("array", item=_short(), max_items=LIMITS["aliases_per_finding"]),
            "ranges": Field("array", item=Field("object", fields=_RANGE), max_items=LIMITS["ranges_per_finding"]),
            "fixed_versions": Field("array", item=_short(), max_items=LIMITS["fixed_versions_per_finding"]),
            "fix_status": _FIX_STATUS,
            "cvss": Field("object", fields=_CVSS, nullable=True),
            "source_refs": _source_refs(),
        }), max_items=LIMITS["findings_per_row"], unique_key="id", unique_code="SCA-E001"),
    }), max_items=LIMITS["version_checks_per_row"], unique_key=("role", "version"), unique_code="SCA-M005",
        required=False),
})

ROW_SCHEMA = _ROW.schema()


def extensions_used(row: Mapping[str, Any]) -> list[str]:
    """Поля расширения 2.1 (ADR-0094), которые есть в строке ответа."""
    used = []
    if "version_checks" in _obj(row):
        used.append("version_checks")
    for finding in _list(_obj(row).get("public_findings")):
        for name in ("fix_status", "disputed", "source_positions"):
            if name in _obj(finding) and name not in used:
                used.append(name)
    return used

_ANSWER_SPEC: dict[str, Field] = {
    "contract": Field("string", enum=[ANSWER_CONTRACT]),
    "task_id": Field("string", min_chars=1, max_chars=LIMITS["id_chars"]),
    "manifest_sha256": Field("string", pattern=r"^[0-9a-f]{64}$"),
    "validator_version": Field("string", enum=ACCEPTED_VALIDATORS),
    # время ответа необязательно: приложение само помнит, когда ответ загружен, а часы агента доказательством
    # поддержки не являются
    "generated_at": _date_field(required=False),
    "row_count": Field("integer", minimum=1, maximum=LIMITS["max_rows"]),
    "rows": Field("array", item=_ROW, max_items=LIMITS["max_rows"]),
}


def schema() -> dict:
    """Схема ответа для агента – из того же описания полей, которым проверяет приложение. Пределы и версия
    валидатора объявлены здесь же: агент видит их до работы, а не после отказа."""
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Ответ по исследованию компонентов SCA", "x-contract": ANSWER_CONTRACT,
            "x-validator": VALIDATOR_VERSION, "x-limits": dict(LIMITS), "additionalProperties": False,
            "required": [name for name, item in _ANSWER_SPEC.items() if item.required],
            "properties": {name: item.schema() for name, item in _ANSWER_SPEC.items()}}


def empty_row(source: Mapping[str, Any]) -> dict:
    """Заготовка одной строки ответа: правильная по контракту и честно незаполненная. Входные поля в ней уже
    стоят из задания – их не приходится переписывать, и подмена заметна проверке. Статус «неполно»
    намеренный: пустая заготовка не должна выглядеть чистым результатом."""
    return {
        "input_ref": _text(source.get("input_ref")),
        "ecosystem": _text(source.get("ecosystem")),
        "component": _text(source.get("component") or source.get("name")),
        "current_version": _text(source.get("version")),
        "identity_resolution": {"state": "unknown", "coordinates": None, "candidates": [], "note": None,
                                "source_refs": []},
        "latest_stable_release": {"version": None, "released_at": "", "note": None, "source_refs": []},
        "update_status": "unknown",
        "support_status": {"state": "unknown", "scope": "unknown", "as_of": "", "note": None, "source_refs": []},
        "public_findings": [],
        "research_coverage": [{
            "source": "", "purpose": purpose,
            "query": {"ecosystem": _text(source.get('ecosystem')), "coordinates": None,
                      "version": _text(source.get('version'))},
            "source_refs": [], "checked_at": "", "status": "error", "complete": False,
            "note": "Проверка ещё не выполнена"
        } for purpose in ('identity', 'vulnerabilities', 'releases', 'support')],
        "package_advice": {"action": "insufficient_data", "target_version": None,
                           "compatibility_notes": None, "remaining_risks": []},
        "evidence": [],
        "gaps": [{"code": "NOT_RESEARCHED", "text": "Компонент ещё не исследован"}],
        "package_status": "incomplete",
    }


def template(task: Mapping[str, Any], rows: Iterable[Mapping[str, Any]]) -> dict:
    """Заготовка ответа на всё задание: те же строки в том же порядке, что в components.json."""
    items = [empty_row(item) for item in rows]
    return {"contract": ANSWER_CONTRACT, "task_id": _text(task.get("task_id")),
            "manifest_sha256": _text(task.get("manifest_sha256")), "validator_version": VALIDATOR_VERSION,
            "generated_at": "", "row_count": len(items), "rows": items}


# ------------------------------------------------------------------ проверка ответа

@dataclass
class Context:
    """Состояние проверки: границы, сегодняшний день для дат и строки сохранённого задания."""
    limits: dict = dc_field(default_factory=lambda: dict(LIMITS))
    today: date = dc_field(default_factory=date.today)
    rows: dict = dc_field(default_factory=dict)
    manifest_sha256: str = ""


@dataclass
class Report:
    """Итог проверки: годен ли ответ, все ли поля проверены и что именно не так, по каждой строке и полю."""
    ok: bool
    errors: list[dict]
    answer: dict | None = None
    answer_sha256: str = ""
    answer_bytes: int = 0
    summary: dict = dc_field(default_factory=dict)

    def codes(self) -> list[str]:
        return [error["code"] for error in self.errors]

    def paths(self) -> list[str]:
        return [error["path"] for error in self.errors]

    def text(self) -> str:
        """Отчёт для человека и агента: по одной строке на ошибку с путём до поля."""
        if self.ok:
            summary = ", ".join(f"{key}: {value}" for key, value in sorted(self.summary.items())) or "нет строк"
            return f"Ответ принят: строк {len(_list((self.answer or {}).get('rows')))}, состояния – {summary}."
        lines = [f"Ответ не принят: ошибок {len(self.errors)}."]
        lines += [f"  {item['code']} {item['path']}: {item['message']}" for item in self.errors]
        return "\n".join(lines)

    def as_dict(self) -> dict:
        """Машинный отчёт: целиком, без сокращений, чтобы агент исправил все поля за один проход."""
        return {"ok": self.ok, "contract": ANSWER_CONTRACT, "validator": VALIDATOR_VERSION,
                "answer_sha256": self.answer_sha256, "answer_bytes": self.answer_bytes, "summary": self.summary,
                "errors": self.errors}


def _fail(code: str, path: str, message: str, errors: list[dict]) -> None:
    errors.append({"code": code, "path": path or "ответ", "message": message})


def _pairs_hook(dupes: list[str]):
    """Разбор объекта с запоминанием повторов ключей: повтор в JSON молча берёт последнее значение."""
    def hook(pairs):
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                dupes.append(key)
            seen[key] = value
        return seen
    return hook


def _reject_constant(name: str):
    raise ValueError(f"недопустимое число {name}")


def validate_answer(text: bytes | str, task: Mapping[str, Any], *, today: date | None = None,
                    limits: Mapping[str, int] | None = None) -> Report:
    """Проверка ответа агента по сохранённому заданию. task – {task_id, manifest_sha256, row_count, rows}.
    Неверный ответ отклоняется целиком: частичная запись строк невозможна, потому что проверка идёт до записи."""
    ctx = Context(limits={**LIMITS, **dict(limits or {})}, today=today or date.today())
    raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    errors: list[dict] = []
    if len(raw) > ctx.limits["answer_bytes"]:
        _fail("SCA-M002", "ответ", f"размер ответа {len(raw)} байт при пределе {ctx.limits['answer_bytes']}",
              errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    try:
        body = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        _fail("SCA-M001", "ответ", f"файл не в UTF-8: {exc.reason}", errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    if not body.strip():
        _fail("SCA-M001", "ответ", "файл ответа пуст", errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    dupes: list[str] = []
    try:
        answer = json.loads(body, object_pairs_hook=_pairs_hook(dupes), parse_constant=_reject_constant)
    except RecursionError:
        _fail("SCA-M006", "ответ", "слишком глубокое вложение JSON", errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    except ValueError as exc:
        _fail("SCA-M001", "ответ", f"JSON не разобран: {exc}", errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    for key in dict.fromkeys(dupes):
        _fail("SCA-M001", "ответ", f"повтор ключа JSON: {key}", errors)
    if not isinstance(answer, dict):
        _fail("SCA-M001", "ответ", f"ожидался объект ответа, получено {type(answer).__name__}", errors)
        return Report(ok=False, errors=errors, answer_bytes=len(raw))
    stack = [(answer, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > ctx.limits['depth']:
                _fail('SCA-M006', 'ответ', 'превышен предел глубины JSON', errors)
                return Report(ok=False, errors=_limited(errors, ctx.limits['reported_errors']), answer_bytes=len(raw))
            stack.extend((child,depth+1) for child in (node.values() if isinstance(node,dict) else node))
    ctx.rows = {_text(item.get("input_ref")): item for item in _list(task.get("rows"))}
    ctx.manifest_sha256 = _text(task.get("manifest_sha256"))
    for name, item in _ANSWER_SPEC.items():
        if name not in answer:
            _fail("SCA-M004", name, "обязательное поле не заполнено", errors)
            continue
        item.check(answer[name], name, ctx, errors)
    for name in answer:
        if name not in _ANSWER_SPEC:
            _fail("SCA-M003", name, "поля нет в контракте", errors)
    if _text(answer.get("contract")) not in ("", ANSWER_CONTRACT):
        _fail("SCA-T002", "contract", f"контракт {answer.get('contract')!r}, ожидался {ANSWER_CONTRACT}", errors)
    if _text(answer.get("validator_version")) not in ("", *ACCEPTED_VALIDATORS):
        _fail("SCA-T002", "validator_version", f"версия валидатора {answer.get('validator_version')!r}",
              errors)
    declared = _text(answer.get("validator_version"))
    if declared in ACCEPTED_VALIDATORS and declared not in EXTENSION_VALIDATORS:
        for index, row in enumerate(_list(answer.get("rows"))):
            used = extensions_used(row) if isinstance(row, dict) else []
            if used:
                _fail("SCA-T002", f"rows[{index}]",
                      f"поля {', '.join(used)} есть только в схеме {EXTENSION_VALIDATORS[0]}, а объявлена {declared}",
                      errors)
    if ctx.manifest_sha256 and _text(answer.get("manifest_sha256")) and not _SHA.match(
            _text(answer.get("manifest_sha256"))):
        _fail("SCA-M005", "manifest_sha256", "отпечаток манифеста не 64 знака sha256", errors)
    if _text(task.get("task_id")) and _text(answer.get("task_id")) != _text(task.get("task_id")):
        _fail("SCA-T002", "task_id", f"задание {answer.get('task_id')!r}, а сохранено {task.get('task_id')!r}",
              errors)
    if (ctx.manifest_sha256 and _text(answer.get("manifest_sha256"))
            and _text(answer.get("manifest_sha256")) != ctx.manifest_sha256):
        _fail("SCA-C004", "manifest_sha256", "отпечаток манифеста не совпадает с сохранённым на сервере", errors)
    rows = _list(answer.get("rows"))
    if isinstance(answer.get("row_count"), int) and not isinstance(answer.get("row_count"), bool) \
            and answer["row_count"] != len(rows):
        _fail("SCA-C003", "row_count", f"в ответе {answer['row_count']} строк, а в rows {len(rows)}", errors)
    seen: set[str] = set()
    for index, row in enumerate(rows):
        path = f"rows[{index}]"
        if not isinstance(row, dict):
            continue
        ref = _text(row.get("input_ref"))
        source = ctx.rows.get(ref)
        if source is None:
            _fail("SCA-C001", f"{path}.input_ref", f"строки {ref!r} нет в сохранённом задании", errors)
        elif ref in seen:
            _fail("SCA-C003", f"{path}.input_ref", f"повтор строки {ref!r}", errors)
        else:
            seen.add(ref)
            # сверяются те поля, которые есть в сохранённом задании: у сервера их полный набор,
            # в манифесте комплекта – тоже, но проверка не должна ломаться на неполном описании строки
            for name in ("ecosystem", "component", "version"):
                if name not in source:
                    continue
                given = _text(row.get("current_version")) if name == "version" else _text(row.get(name))
                if given != _text(source.get(name)):
                    _fail("SCA-C002", f"{path}.{'current_version' if name == 'version' else name}",
                          f"{given!r} вместо {source.get(name)!r} из задания", errors)
            confirmed = _text(_obj(row.get("identity_resolution")).get("coordinates"))
            raw_name, eco = _text(source.get('component')), _text(source.get('ecosystem')).lower()
            same = confirmed == raw_name
            if eco == 'maven' and ':' not in raw_name:
                group, separator, artifact = confirmed.partition(':')
                same = bool(group and separator and artifact == raw_name and ':' not in artifact)
            elif eco == 'npm' and not raw_name.startswith('@'):
                same = same or bool(re.fullmatch(r'@[^/]+/' + re.escape(raw_name), confirmed))
            if confirmed and not same:
                _fail("SCA-C002", f"{path}.identity_resolution.coordinates",
                      f"{confirmed!r} не соответствует исходному пакету {raw_name!r}", errors)
        _check_row(row, path, ctx, errors)
        declared = _text(row.get("package_status"))
        computed = row_status(row)
        if declared and declared != computed:
            _fail("SCA-T001", f"{path}.package_status",
                  f"заявлено {declared!r}, по проверенным полям {computed!r}", errors)
    missing = [ref for ref in ctx.rows if ref not in seen]
    if missing:
        _fail("SCA-C003", "rows", f"нет строк задания: {', '.join(sorted(missing)[:5])}"
                  + (f" и ещё {len(missing) - 5}" if len(missing) > 5 else ""), errors)
    if len(rows) != int(task.get("row_count") or len(rows)):
        _fail("SCA-C003", "rows", f"в ответе {len(rows)} строк, в задании {task.get('row_count')}", errors)
    summary: dict[str, int] = {}
    for row in rows:
        if isinstance(row, dict):
            status = _text(row.get("package_status")) or "?"
            summary[status] = summary.get(status, 0) + 1
    try:
        digest = sha256(canonical(answer))
    except ValueError as exc:  # 1e999 и подобное разбирается в число, которое нельзя ни записать, ни посчитать
        _fail("SCA-M001", "ответ", f"ответ не пригоден для отпечатка: {exc}", errors)
        digest = ""
    return Report(ok=not errors, errors=_limited(errors, ctx.limits['reported_errors']), answer=answer, answer_sha256=digest,
                  answer_bytes=len(raw), summary=summary)


def _limited(errors: list[dict], limit: int) -> list[dict]:
    """Список ошибок ограничен по числу, но о том, что он неполный, сообщаем явно."""
    if len(errors) <= limit:
        return errors
    kept = errors[:limit]
    kept.append({"code": "SCA-M007", "path": "ответ",
                 "message": f"показаны первые {limit} ошибок из {len(errors)}: исправьте их и проверьте снова"})
    return kept


def _check_row(row: dict, path: str, ctx: Context, errors: list[dict]) -> None:
    """Доказательства, объём строки, внутренние номера и очевидные противоречия одной строки."""
    try:
        body = canonical(row)
    except ValueError as exc:  # число вне диапазона JSON: строку нельзя ни посчитать, ни сравнить с пределом
        _fail("SCA-M001", path, f"строка не пригодна для проверки: {exc}", errors)
        body = b""
    if len(body) > ctx.limits["row_bytes"]:
        _fail("SCA-M002", path, f"строка ответа {len(body)} байт при пределе {ctx.limits['row_bytes']}", errors)
    evidence = [_text(item.get("evidence_ref")) for item in _list(row.get("evidence")) if isinstance(item, dict)]
    known = {ref for ref in evidence if ref}

    def refs(owner: str, value: Any, path_to: str, code: str = "SCA-E001") -> None:
        missing = sorted({ref for ref in _list(value) if isinstance(ref, str) and ref not in known})
        if missing:
            _fail(code, path_to, f"ссылки на доказательства без записи в evidence: {', '.join(missing[:5])}",
                  errors)

    identity = _obj(row.get("identity_resolution"))
    refs("identity", identity.get("source_refs"), f"{path}.identity_resolution.source_refs")
    if identity.get("state") == "resolved" and not identity.get("source_refs"):
        _fail("SCA-E001", f"{path}.identity_resolution.source_refs", "подтверждённая идентификация без источника",
              errors)
    needs_basis = ((_text(row.get('ecosystem')) == 'maven' and ':' not in _text(row.get('component')))
                   or (_text(row.get('ecosystem')) == 'npm' and not _text(row.get('component')).startswith('@')))
    if identity.get('state') == 'resolved' and needs_basis:
        if not _text(identity.get('basis')):
            _fail('SCA-E001', f'{path}.identity_resolution.basis',
                  'краткое имя требует основания выбора namespace, а не совпадения имени первого кандидата', errors)
        identity_checks = [entry for entry in _list(row.get('research_coverage'))
                           if isinstance(entry, dict) and entry.get('purpose') == 'identity'
                           and entry.get('status') == 'ok' and entry.get('complete')]
        if not identity_checks:
            _fail('SCA-E001', f'{path}.research_coverage',
                  'не подтверждена проверка идентичности краткого имени и текущей версии', errors)
    latest = _obj(row.get("latest_stable_release"))
    refs("latest", latest.get("source_refs"), f"{path}.latest_stable_release.source_refs")
    if _text(latest.get("version")) and not latest.get("source_refs"):
        _fail("SCA-E001", f"{path}.latest_stable_release.source_refs", "назван последний релиз без источника",
              errors)
    support = _obj(row.get("support_status"))
    refs("support", support.get("source_refs"), f"{path}.support_status.source_refs")
    if _text(support.get("state")) not in ("", "unknown") and not support.get("source_refs"):
        _fail("SCA-E001", f"{path}.support_status.source_refs", "состояние поддержки без источника", errors)
    for index, finding in enumerate(_list(row.get("public_findings"))):
        if not isinstance(finding, dict):
            continue
        owner = f"{path}.public_findings[{index}]"
        refs("finding", finding.get("source_refs"), f"{owner}.source_refs")
        if not finding.get("source_refs"):
            _fail("SCA-E001", f"{owner}.source_refs", "публичная находка без источника", errors)
    evidence_by_ref = {entry.get('evidence_ref'): entry for entry in _list(row.get('evidence'))
                       if isinstance(entry, dict) and isinstance(entry.get('evidence_ref'), str)}
    urls: set[str] = set()
    for index, entry in enumerate(_list(row.get('evidence'))):
        url = _text(_obj(entry).get('url'))
        if public_url_parts(url) is None:
            _fail('SCA-E001', f'{path}.evidence[{index}].url', 'нужна однозначная ссылка на публичный источник', errors)
        if url in urls:
            _fail('SCA-E001', f'{path}.evidence[{index}].url', 'повтор URL: используйте один evidence_ref в нескольких source_refs', errors)
        urls.add(url)
    advice = _obj(row.get('package_advice'))
    refs('advice', advice.get('source_refs'), f'{path}.package_advice.source_refs')
    if _text(advice.get('target_version')):
        publications = [evidence_by_ref.get(ref, {}) for ref in _list(advice.get('source_refs'))]
        if not any(ev.get('source_type') in ('registry', 'release_notes') for ev in publications):
            _fail('SCA-E001', f'{path}.package_advice.source_refs',
                  'целевая версия требует источника публикации: реестр или официальный релиз', errors)
    for index, entry in enumerate(_list(row.get("research_coverage"))):
        if not isinstance(entry, dict):
            continue
        # запись «искали уязвимости» должна называть, что именно проверяли, и ссылаться на источник:
        # иначе по названию источника нельзя понять, относится ли проверка к этому пакету
        owner = f"{path}.research_coverage[{index}]"
        query = _obj(entry.get("query"))
        if entry.get('status') == 'ok' and entry.get('complete') and (
                not _text(query.get('ecosystem')) or not _text(query.get("coordinates")) or not _text(query.get("version"))):
            _fail("SCA-E001", f"{owner}.query", "проверка уязвимостей без координат и версии: непонятно, что "
                  "проверяли", errors)
        else:  # запрос должен совпадать с тем, что человек смотрит: иначе это вывод о другом пакете
            resolved = _text(_obj(row.get("identity_resolution")).get("coordinates"))
            if resolved and _text(query.get("coordinates")) and _text(query.get("coordinates")) != resolved:
                _fail("SCA-E001", f"{owner}.query.coordinates",
                      f"{_text(query.get('coordinates'))!r} вместо {resolved!r} – проверяли другой пакет", errors)
            if _text(query.get("version")) and _text(query.get("version")) != _text(row.get("current_version")):
                _fail("SCA-E001", f"{owner}.query.version",
                      f"{_text(query.get('version'))!r} вместо {_text(row.get('current_version'))!r} из задания",
                      errors)
            if _text(query.get('ecosystem')) and _text(query.get('ecosystem')) != _text(row.get('ecosystem')):
                _fail('SCA-E001', f'{owner}.query.ecosystem', 'запрос относится к другой экосистеме', errors)
        refs("coverage", entry.get("source_refs"), f"{owner}.source_refs")
        if entry.get('status') == 'ok' and entry.get('complete') and not _list(entry.get("source_refs")):
            _fail("SCA-E001", f"{owner}.source_refs", "проверка уязвимостей без источника", errors)
    def fix_status_ok(status: Any, owner: str) -> None:
        state = _obj(status)
        refs("fix", state.get("source_refs"), f"{owner}.source_refs")
        if state.get("status") in ("fixed", "no_fix_published") and not _list(state.get("source_refs")):
            _fail("SCA-E001", f"{owner}.source_refs", "утверждение об исправлении без источника", errors)
        if state.get("scope") == "branch" and not _text(state.get("branch")):
            _fail("SCA-E001", f"{owner}.branch", "scope=branch требует ветку (префикс версий)", errors)
        if state.get("status") == "no_fix_published":
            proofs = [evidence_by_ref.get(ref, {}) for ref in _list(state.get("source_refs"))]
            if not any(p.get("source_type") in ("advisory", "issue_tracker") and _text(p.get("quote"))
                       and _text(p.get("checked_at")) for p in proofs):
                _fail("SCA-E001", f"{owner}.source_refs", "«исправления нет» требует бюллетеня или трекера с "
                      "выдержкой и датой проверки", errors)

    for index, finding in enumerate(_list(row.get("public_findings"))):
        owner = f"{path}.public_findings[{index}]"
        finding = _obj(finding)
        if "fix_status" in finding and finding.get("fix_status") is not None:
            fix_status_ok(finding.get("fix_status"), f"{owner}.fix_status")
        disputed = _obj(finding.get("disputed"))
        refs("disputed", disputed.get("source_refs"), f"{owner}.disputed.source_refs")
        if disputed and not _list(disputed.get("source_refs")):
            _fail("SCA-E001", f"{owner}.disputed.source_refs", "оспоренность без источника", errors)
        for k, position in enumerate(_list(finding.get("source_positions"))):
            refs("position", _obj(position).get("source_refs"), f"{owner}.source_positions[{k}].source_refs")
            if not _list(_obj(position).get("source_refs")):
                _fail("SCA-E001", f"{owner}.source_positions[{k}].source_refs", "позиция источника без ссылки",
                      errors)
    for index, check in enumerate(_list(row.get("version_checks"))):
        check = _obj(check)
        owner = f"{path}.version_checks[{index}]"
        version = _text(check.get("version"))
        resolved = _text(_obj(row.get("identity_resolution")).get("coordinates"))
        for k, entry in enumerate(_list(check.get("coverage"))):
            entry = _obj(entry)
            query = _obj(entry.get("query"))
            where = f"{owner}.coverage[{k}]"
            # те же требования, что у охвата текущей версии: что проверяли, по какому пакету и источнику
            if entry.get("status") == "ok" and entry.get("complete") and (
                    not _text(query.get("ecosystem")) or not _text(query.get("coordinates"))
                    or not _text(query.get("version"))):
                _fail("SCA-E001", f"{where}.query", "проверка версии без координат и версии: непонятно, что "
                      "проверяли", errors)
            if _text(query.get("version")) and _text(query.get("version")) != version:
                _fail("SCA-E001", f"{where}.query.version",
                      f"{_text(query.get('version'))!r} вместо проверяемой версии {version!r}", errors)
            if resolved and _text(query.get("coordinates")) and _text(query.get("coordinates")) != resolved:
                _fail("SCA-E001", f"{where}.query.coordinates", "проверяли другой пакет", errors)
            if _text(query.get("ecosystem")) and _text(query.get("ecosystem")) != _text(row.get("ecosystem")):
                _fail("SCA-E001", f"{where}.query.ecosystem", "запрос относится к другой экосистеме", errors)
            refs("coverage", entry.get("source_refs"), f"{where}.source_refs")
            if entry.get("status") == "ok" and entry.get("complete") and not _list(entry.get("source_refs")):
                _fail("SCA-E001", f"{where}.source_refs", "проверка версии без источника", errors)
        for k, finding in enumerate(_list(check.get("findings"))):
            finding = _obj(finding)
            refs("finding", finding.get("source_refs"), f"{owner}.findings[{k}].source_refs")
            if not finding.get("source_refs"):
                _fail("SCA-E001", f"{owner}.findings[{k}].source_refs", "находка проверки версии без источника",
                      errors)
            if finding.get("fix_status") is not None and "fix_status" in finding:
                fix_status_ok(finding.get("fix_status"), f"{owner}.findings[{k}].fix_status")
            # находка проверки версии описывает уязвимость, затрагивающую именно эту версию: интервалы корректны,
            # и проверяемая версия не исключена ни одним из них
            intervals = [_obj(r) for r in _list(finding.get("ranges"))]
            for interval in intervals:
                start = _text(interval.get("introduced"))
                if start and start != "0":
                    for end, inclusive in (("fixed", False), ("last_affected", True)):
                        order = compare_versions(_text(row.get("ecosystem")), start, _text(interval.get(end)))
                        if order is not None and (order > 0 or (order == 0 and not inclusive)):
                            _fail("SCA-A001", f"{owner}.findings[{k}].ranges", "пустой или обратный диапазон", errors)
            hits = [range_contains(_text(row.get("ecosystem")), version, r) for r in intervals]
            if intervals and hits and all(hit is False for hit in hits):
                _fail("SCA-A001", f"{owner}.findings[{k}].ranges",
                      f"диапазоны находки исключают проверяемую версию {version}", errors)
    for match in _AST.finditer(body.decode("utf-8", "replace")):
        _fail("SCA-A001", path, f"внутренний номер соответствия {match.group(0)!r} в ответе по компоненту",
              errors)
    if not _list(row.get("research_coverage")):
        # нет ни проверенных источников, ни находок, ни доказательств – это незаполненная заготовка, а не
        # исследование: принять её можно было бы, только выдав пустой ответ за результат
        _fail("SCA-L001", path, "нет протокола попыток проверки источников: строка не исследована", errors)
    if row.get('package_status') in ('incomplete', 'identity_unresolved') and not _list(row.get('gaps')):
        _fail('SCA-L001', f'{path}.gaps', 'неполный результат требует конкретной причины', errors)
    if any(isinstance(gap, dict) and gap.get('code') == 'NOT_RESEARCHED' for gap in _list(row.get('gaps'))):
        _fail('SCA-L001', f'{path}.gaps', 'незаполненная заготовка не является выполненным исследованием', errors)
    _contradictions(row, path, errors)


def _contradictions(row: dict, path: str, errors: list[dict]) -> None:
    """Очевидные противоречия между полями: их проверяет программа, а не доверие к тексту агента."""
    identity = _obj(row.get("identity_resolution"))
    state = _text(identity.get("state"))
    coordinates = _text(identity.get("coordinates"))
    if state == "resolved" and not coordinates:
        _fail("SCA-L001", f"{path}.identity_resolution.coordinates", "идентичность подтверждена, а координат нет",
              errors)
    if state in ("ambiguous", "unresolved") and coordinates:
        _fail("SCA-L001", f"{path}.identity_resolution.coordinates",
              f"идентичность {state}, а координаты указаны", errors)
    latest = _text(_obj(row.get("latest_stable_release")).get("version"))
    update = _text(row.get("update_status"))
    current = _text(row.get("current_version"))
    latest_order = compare_versions(_text(row.get('ecosystem')), latest, current)
    if update == 'up_to_date' and (not latest or not _obj(row.get('latest_stable_release')).get('source_refs')):
        _fail('SCA-E001', f'{path}.latest_stable_release.source_refs', 'актуальность версии требует последнего релиза и источника', errors)
    if update == "up_to_date" and latest and latest_order != 0:
        _fail("SCA-L001", f"{path}.update_status", f"up_to_date, а последний релиз {latest} отличается от {current}",
              errors)
    if update == "update_available" and not latest:
        _fail("SCA-L001", f"{path}.update_status", "доступно обновление, но версия не названа", errors)
    if update == "update_available" and latest and latest_order is not None and latest_order != 1:
        _fail("SCA-L001", f"{path}.update_status",
              f"не подтверждён порядок версий {current} → {latest}: используйте unknown и пояснение", errors)
    advice = _obj(row.get("package_advice"))
    action = _text(advice.get("action"))
    target = _text(advice.get("target_version"))
    if action == "update" and not target:
        _fail("SCA-L001", f"{path}.package_advice.target_version", "действие «обновить» без версии", errors)
    if target and target == current:
        _fail("SCA-L001", f"{path}.package_advice.target_version",
              f"советуемая версия совпадает с текущей {current}: обновлять нечего", errors)
    target_order = compare_versions(_text(row.get('ecosystem')), target, current)
    if action == 'update' and target and target_order is not None and target_order != 1:
        _fail("SCA-L001", f"{path}.package_advice.target_version",
              f"версия {target} не подтверждена как более новая, чем {current}; поясните кандидат без совета update", errors)
    if state != 'resolved' and (latest or update != 'unknown' or target
                               or _obj(row.get('support_status')).get('state') != 'unknown'
                               or _list(row.get('public_findings'))):
        _fail('SCA-L001', path, 'неразрешённой идентичности нельзя приписывать факты о пакете-кандидате', errors)
    if action == "replace" and not _text(advice.get("compatibility_notes")):
        _fail("SCA-L001", f"{path}.package_advice.compatibility_notes", "замена без указания заменяющего пакета",
              errors)
    if action == "needs_identity" and state == "resolved":
        _fail("SCA-L001", f"{path}.package_advice.action", "действие «нужна идентификация» при подтверждённой "
              "идентичности", errors)
    applicable = [item for item in _list(row.get("public_findings"))
                  if isinstance(item, dict) and item.get("applies") == "yes"]
    for index, finding in enumerate(_list(row.get('public_findings'))):
        if not isinstance(finding, dict) or not finding.get('ranges'):
            continue
        matches = [range_contains(_text(row.get('ecosystem')), current, _obj(r)) for r in _list(finding.get('ranges'))]
        known = True if True in matches else (None if None in matches else False)
        applies = finding.get('applies')
        owner = f'{path}.public_findings[{index}].ranges'
        for interval in _list(finding.get('ranges')):
            interval = _obj(interval)
            start = _text(interval.get('introduced'))
            if start and start != '0':
                for end, inclusive in (('fixed',False), ('last_affected',True)):
                    order = compare_versions(_text(row.get('ecosystem')), start, _text(interval.get(end)))
                    if order is not None and (order > 0 or (order == 0 and not inclusive)):
                        _fail('SCA-A001', owner, 'пустой или обратный диапазон не доказывает неприменимость', errors)
        if known is None:
            if applies != 'unknown' or not any(_obj(g).get('code')=='APPLICABILITY_UNCLEAR' for g in _list(row.get('gaps'))):
                _fail('SCA-A001', owner, 'порядок версий не проверен: нужны applies=unknown и gap APPLICABILITY_UNCLEAR', errors)
        elif applies in ('yes','no') and (applies == 'yes') != known:
            _fail('SCA-A001', owner, f'вывод applies={applies} противоречит диапазону для текущей версии {current}', errors)
    if applicable and action in ("keep", "no_action", "remove"):
        if not _text(advice.get("compatibility_notes")) and not _list(advice.get("remaining_risks")):
            _fail("SCA-L001", f"{path}.package_advice",
                  f"при применимых уязвимостях ({len(applicable)}) действие {action!r} не объяснено", errors)


def range_contains(ecosystem: str, current: str, interval: Mapping[str, Any]) -> bool | None:
    """Нижняя граница включена, fixed исключена, last_affected включена. None означает неизвестность. introduced="0" –
    от первой версии; без fixed и last_affected такой диапазон затрагивает все версии (как в OSV), а пустой интервал
    без границ остаётся неизвестностью."""
    bounds = []
    start = _text(interval.get('introduced'))
    if start == '0' and not _text(interval.get('fixed')) and not _text(interval.get('last_affected')):
        return True
    if start and start != '0':
        order = compare_versions(ecosystem,current,start)
        bounds.append(None if order is None else order >= 0)
    for name, inclusive in (('fixed',False),('last_affected',True)):
        end = _text(interval.get(name))
        if end:
            order = compare_versions(ecosystem,current,end)
            bounds.append(None if order is None else (order <= 0 if inclusive else order < 0))
    if False in bounds:
        return False
    return None if None in bounds or not bounds else True


# ------------------------------------------------------------------ командная проверка из комплекта

EXIT_OK = 0
EXIT_CONTRACT = 2
EXIT_TECHNICAL = 3


def _load(path: str) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ValueError(f"не удалось прочитать {path}: {exc.strerror or exc}") from exc
    return json.loads(raw.decode("utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    """python validate.py --manifest manifest.json --answer answer.json [--report report.json]

    0 – ответ принят, 2 – нарушения контракта (полный отчёт в stdout и в файле отчёта), 3 – техническая
    ошибка проверки (нечитаемый манифест или файл ответа)."""
    for stream in (sys.stdout, sys.stderr):  # консоль агента может быть не в UTF-8: отчёт читает человек
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(prog="validate.py", add_help=True,
                                     description="Проверка ответа по исследованию компонентов SCA.")
    parser.add_argument("--manifest", required=True, help="manifest.json из комплекта задания")
    parser.add_argument("--answer", required=True, help="answer.json с ответом агента")
    parser.add_argument("--report", default="", help="куда записать машинный отчёт об ошибках (JSON)")
    parser.add_argument("--base", default="", help="сегодняшняя дата для проверки дат (YYYY-MM-DD)")
    args = parser.parse_args(argv)
    try:
        manifest = _load(args.manifest)
        answer_bytes = Path(args.answer).read_bytes()
    except (OSError, ValueError) as exc:
        print(f"Техническая ошибка: {exc}", file=sys.stderr)
        return EXIT_TECHNICAL
    if not isinstance(manifest, dict) or not isinstance(manifest.get("rows"), list):
        print("Техническая ошибка: в манифесте нет списка rows", file=sys.stderr)
        return EXIT_TECHNICAL
    base = date.today()
    if args.base:
        try:
            base = date.fromisoformat(args.base)
        except ValueError:
            print(f"Техническая ошибка: неверная дата --base {args.base!r}", file=sys.stderr)
            return EXIT_TECHNICAL
    task = {"task_id": manifest.get("task_id", ""), "manifest_sha256": manifest.get("manifest_sha256", ""),
            "row_count": manifest.get("row_count", len(manifest["rows"])), "rows": manifest["rows"]}
    report = validate_answer(answer_bytes, task, today=base)
    print(report.text())
    if args.report:
        try:
            Path(args.report).write_text(json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n",
                                         encoding="utf-8")
        except OSError as exc:
            print(f"Техническая ошибка: отчёт не записан: {exc}", file=sys.stderr)
            return EXIT_TECHNICAL
    return EXIT_OK if report.ok else EXIT_CONTRACT


if __name__ == "__main__":  # комплект задания: python validate.py --manifest ... --answer ...
    sys.exit(main())
