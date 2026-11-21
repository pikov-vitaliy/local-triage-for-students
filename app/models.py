"""Модели данных: находка, итог разбора выгрузки, контекст кода, вердикт модели, замеры работы модели, ответ
внешнего агента по компоненту SCA.

Все классы – dataclass. Метод to_dict() отдаёт обычный словарь (для JSON и базы), from_dict() собирает объект
обратно: лишние ключи пропускаются, недостающие получают значения по умолчанию, типы приводятся мягко
(«58» -> 58, «9.8» -> 9.8, строка CWE через запятую -> список).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

KINDS = ("SAST", "SCA", "SCA-license", "DAST")
SEVERITIES = ("critical", "high", "medium", "low", "info")  # от самой высокой
CONTEXT_STATUSES = ("ok", "export_line_only", "file_missing", "no_repo", "too_large", "binary")
EXPORT_LINE_CHECKS = ("match", "near", "commented", "partial", "differs", "no_export_line", "short_export_line",
                      "masked_export_line", "n/a")
# Сверки, при которых фрагмент из выгрузки не подтверждён показанным кодом: уверенность ограничена (ADR-0080, ADR-0082)
UNCONFIRMED_EXPORT_CHECKS = ("differs", "commented", "partial")
TARGET_MARK = ">>"  # метка строки срабатывания в CodeContext.numbered()
SCA_CONCLUSIONS = ("update", "not_applicable", "unclear")  # вывод по компоненту: обновить / не применимо / неясно


@dataclass
class Finding:
    """Находка из выгрузки AppSec.Hub (одна строка листа практики)."""

    hub_id: str
    kind: str  # 'SAST' | 'SCA' | 'SCA-license' | 'DAST'
    tool: str = ""  # колонка Found By
    application: str = ""
    severity: str = ""  # critical/high/medium/low/info; у SCA отчёта Hub – "" (см. policy_severity)
    policy_severity: str = ""  # у SCA отчёта Hub колонка Severity – уровень политики Hub, а не тяжесть уязвимости
    cvss: float | None = None
    rule: str = ""  # колонка Category
    cwe: list[str] = field(default_factory=list)  # ['CWE-89']
    cwe_links: list[str] = field(default_factory=list)
    codebase: str = ""
    file: str = ""  # прямые слэши, от корня кодовой базы
    line: int | None = None
    snippet: str = ""  # Source code без хвоста « : N»
    status: str = ""
    language: str = ""
    build_type: str = ""  # колонка Type: тип сборки или экосистема пакета, а не вид находки
    component: str = ""
    version: str = ""
    fixed_version: str = ""
    dep_path: str = ""  # колонка Path у SCA – путь зависимости, а не файл
    vuln_ids: list[str] = field(default_factory=list)  # идентификаторы уязвимостей, кроме CVE (AST-…, GHSA-…)
    cve: list[str] = field(default_factory=list)
    licenses: str = ""
    location: str = ""  # адрес проверки DAST
    extra: dict[str, str] = field(default_factory=dict)  # колонки выгрузки без своего поля
    sheet: str = ""  # лист книги
    row: int = 0  # номер строки на листе, как в Excel
    # эффективная идентичность пакета SCA из колонок findings.pkg_* (план dev17, п. 4.2): только во время работы,
    # в data_json, finding_data_sig и отпечатки не входит – to_dict поля с метаданными runtime исключает
    package: dict = field(default_factory=dict, metadata={"runtime": True})

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        for f in dataclasses.fields(self):
            if f.metadata.get("runtime"):
                data.pop(f.name, None)
        return data

    def _identity_data(self) -> dict[str, Any]:
        return {"build_type": self.build_type, "component": self.component, "version": self.version,
                "package": self.package}

    @property
    def package_ecosystem(self) -> str:
        """Эффективная экосистема пакета (сведения Hub о библиотеке или Type выгрузки)."""
        from app import package_identity
        return package_identity.of(self._identity_data())[0]

    @property
    def package_name(self) -> str:
        """Эффективное имя пакета: координаты Maven, имя npm с областью или компонент выгрузки."""
        from app import package_identity
        return package_identity.of(self._identity_data())[1]

    @property
    def identity_marks(self) -> list[str]:
        """Пометки идентичности пакета для оператора (план dev17, п. 4.6)."""
        from app import package_identity
        return package_identity.mark_texts(self._identity_data())

    @property
    def package_display_name(self) -> str:
        """Короткое имя для текстов Hub: у Maven – artifactId, у остальных – эффективное имя."""
        from app import package_identity
        return package_identity.display_name(self._identity_data())

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Finding:
        return _from_dict(cls, data)


@dataclass
class ImportResult:
    """Итог разбора выгрузки.

    format   – 'hub' (отчёт AppSec.Hub) или 'table' (одна таблица с заголовками);
    sheets   – по записи на лист книги: {'name', 'rows', 'skipped', 'reason', ...};
    summary  – {'application', 'by_practice', 'by_severity', 'total', 'report_created', ...};
    warnings – предупреждения по-русски.
    """

    findings: list[Finding]
    format: str
    sheets: list[dict]
    summary: dict
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]  # без полей времени работы (Finding.package)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ImportResult:
        return _from_dict(cls, data)


@dataclass
class CodeContext:
    """Срез кода вокруг находки.

    status            – 'ok' | 'export_line_only' | 'file_missing' | 'no_repo' | 'too_large' | 'binary';
    file              – путь файла от корня репозитория (если файл не найден – путь из находки);
    start_line, end_line – номера первой и последней строки среза (0 – номеров нет);
    target_line       – строка срабатывания (None – неизвестна или вне среза);
    lines             – строки среза без номеров (после маскирования, если был ключ);
    enclosing         – сигнатура объемлющего метода или функции;
    export_line_check – match, near (фрагмент найден), commented (только в комментарии), partial (совпала часть),
                        differs; нейтральные no_export_line, short_export_line, masked_export_line, n/a;
    export_line_at    – номер строки найденного фрагмента, иначе None;
    export_line_check_version – 0: прежняя сверка, 1: сверка по фрагменту до маскирования (вхождение в обе стороны),
                        2: точное совпадение отдельно от частичного и закомментированного (ADR-0082);
    masked            – сколько значений замаскировано в срезе, по типам: {'SECRET': 1, 'EMAIL': 2};
    note              – пояснения по-русски (почему нет кода, что сокращено);
    reason            – причина отсутствия кода из файла; пусто для «ok» и срезов прежних версий.
    """

    status: str
    file: str
    language: str
    start_line: int
    end_line: int
    target_line: int | None
    lines: list[str] = field(metadata={"code_lines": True})  # пустые строки кода сохраняются: на них нумерация
    enclosing: str = ""
    export_line_check: str = ""
    masked: dict[str, int] = field(default_factory=dict)
    note: str = ""
    reason: str = ""
    export_line_at: int | None = None
    export_line_check_version: int = 0
    # Сверка версии 1 по коду до маскирования – только для отпечатка случая (triage.case_hash, ADR-0082): уточнение
    # сверки не меняет отпечаток неизменного кода. У срезов версий 0–1 пусто: отпечаток берёт export_line_check.
    hash_check: str = ""
    hash_check_at: int | None = None

    def text_at(self, number: int | None) -> str:
        """Строка среза по номеру в файле; вне среза – пусто."""
        if number is None or not self.start_line or not self.start_line <= number < self.start_line + len(self.lines):
            return ""
        return self.lines[number - self.start_line]

    def rows(self) -> list[tuple[int, str, bool]]:
        """Строки среза для показа: (номер, текст, это строка срабатывания). Без номеров – номер 0."""
        result = []
        for k, text in enumerate(self.lines):
            n = self.start_line + k if self.start_line >= 1 else 0
            result.append((n, text, bool(n) and n == self.target_line))
        return result

    def numbered(self) -> str:
        """Строки среза с номерами для промпта: «>>   58| код» у строки срабатывания, «     57| код» у остальных.

        Если номеров нет (строка из выгрузки без номера строки), строки отдаются как есть.
        """
        if not self.lines:
            return ""
        if self.start_line < 1:
            return "\n".join(self.lines)
        width = max(5, len(str(self.start_line + len(self.lines) - 1)))
        out = []
        for n, text, is_target in self.rows():
            mark = TARGET_MARK if is_target else " " * len(TARGET_MARK)
            out.append(f"{mark}{n:>{width}}| {text}")
        return "\n".join(out)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> CodeContext:
        return _from_dict(cls, data)


@dataclass
class Verdict:
    """Ответ модели по находке.

    Поля обеих версий промпта: verdict, confidence, summary (одна фраза), data_flow (шаги пути данных), fix,
    hub_comment, cwe_fit. Только sast-v2: explanation (обоснование одним текстом), evidence_lines (номера строк-
    доказательств). Только sast-v3 – объяснение для человека, который читает код, но давно не программирует:
    what_code_does (что делает фрагмент, простыми словами), why (почему такой вердикт – по шагам, со ссылками
    «строка N»), check_by_eye (2–4 пункта «что проверить глазами»), terms (словарик: [{"term", "meaning"}]).
    Вердикт одной версии читается с пустыми полями другой.

    why и check_by_eye – списки пунктов: строка из базы делится на пункты по переводам строк, а не по запятым
    (пункт – это фраза, запятые в нём свои). Разбор ответа модели (prompts.py) приводит поля к этим типам сам.
    """

    verdict: str  # 'true_positive' | 'false_positive' | 'uncertain'
    confidence: int
    summary: str = ""
    explanation: str = ""
    data_flow: list[str] = field(default_factory=list)
    evidence_lines: list[int] = field(default_factory=list)
    fix: str = ""
    hub_comment: str = ""
    cwe_fit: str = ""  # 'да' | 'нет' | 'частично'
    raw: dict = field(default_factory=dict)
    what_code_does: str = ""
    why: list[str] = field(default_factory=list, metadata={"text_list": True})
    check_by_eye: list[str] = field(default_factory=list, metadata={"text_list": True})
    terms: list[dict[str, str]] = field(default_factory=list, metadata={"terms": True})
    # sast-v7 (ADR-0109): цитаты кода со статусом сверки приложением ([{"line", "code", "status", "found_line",
    # "note"}], prompts.check_quotes) и «какого кода не хватило»; у прежних версий пустые
    evidence_quotes: list[dict] = field(default_factory=list)
    missing_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Verdict:
        return _from_dict(cls, data)


@dataclass
class ScaAnswer:
    """Ответ внешнего агента по пакету SCA (группа «экосистема + компонент + версия»).

    recommended_version – версия, до которой обновить; conclusion – 'update' (обновить), 'not_applicable'
    (не применимо), 'unclear' (неясно) или "" (агент не ответил); explanation – пояснение; ids – соответствие
    идентификаторов уязвимостей: {"AST-…": ["CVE-…", "GHSA-…"]}; links – ссылки на источники; vulnerabilities –
    охват ответа: уязвимости, по которым агент отвечал (из ответа или из пакета на момент загрузки). Ответ
    не относится к уязвимости, которой в охвате нет (новая CVE после повторной выгрузки).
    """

    component: str
    version: str
    recommended_version: str = ""
    conclusion: str = ""
    explanation: str = ""
    ids: dict[str, list[str]] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    ecosystem: str = ""  # экосистема пакета (app/ecosystem.py): часть идентичности вместе с именем и версией

    def complete(self) -> bool:
        """Ответ по существу: вывод распознан, пояснение есть, у «обновить» – версия для обновления."""
        return (self.conclusion in SCA_CONCLUSIONS and bool(self.explanation.strip())
                and (self.conclusion != "update" or bool(self.recommended_version.strip())))

    def signature(self) -> str:
        """Существенная часть ответа – вывод, версия, охват и соответствия идентификаторов (AST → CVE): от неё
        зависит решение «Согласен с агентом». Смена CVE под тем же AST меняет описание БДУ и основания решения,
        поэтому тоже снимает «Проверено». Идентификаторы сравниваются без учёта регистра и порядка."""
        ids = {str(k).strip().upper(): sorted({str(x).strip().upper() for x in (v or []) if str(x).strip()})
               for k, v in (self.ids or {}).items() if str(k).strip()}
        data = {"conclusion": self.conclusion, "recommended_version": self.recommended_version,
                "vulnerabilities": sorted(self.vulnerabilities), "ids": ids}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ScaAnswer:
        answer = _from_dict(cls, data)
        if answer.conclusion not in SCA_CONCLUSIONS:
            answer.conclusion = ""
        return answer


@dataclass
class LlmStats:
    """Замеры одного ответа модели."""

    model: str
    prompt_tokens: int
    output_tokens: int
    eval_tps: float  # токенов в секунду при выводе
    prompt_tps: float  # токенов в секунду при чтении промпта
    total_s: float
    load_s: float
    attempts: int
    # уровень рассуждения каждой попытки отправки после успешного допуска (ADR-0102): через запятую; low/medium/high
    # – уровень gpt-oss, on/off – рассуждение другой модели включено/выключено, «-» – поле не передавалось; пусто –
    # ответ до 0.9.12 или ни одна попытка не прошла допуск
    think: str = ""
    # 0.9.13, API чат-завершений: токены рассуждения и попадания в кэш провайдера (usage); timing – откуда время:
    # "server" – длительности сервера, "app" – часы приложения (скорость токенов неизвестна, 0), "" – запись до 0.9.13
    reasoning_tokens: int = 0
    cache_hit_tokens: int = 0
    timing: str = ""
    # 0.9.14: сколько раз запрос автоматически отправлен заново после обрыва без ответа
    # (отметка профиля внешнего провайдера «Повторять после обрыва без ответа»; не больше одного раза на находку)
    drop_retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> LlmStats:
        return _from_dict(cls, data)


# ---------------------------------------------------------------- мягкое приведение типов для from_dict


def _to_str(value: Any) -> str:
    return "" if value is None else str(value)


def _to_float_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool) or value == "":
        return None
    try:
        number = float(str(value).replace(",", ".")) if isinstance(value, str) else float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) or math.isinf(number) else number


def _to_int_or_none(value: Any) -> int | None:
    number = _to_float_or_none(value)
    return int(number) if number is not None and number.is_integer() else None


def _to_int(value: Any) -> int:
    number = _to_int_or_none(value)
    return 0 if number is None else number


def _to_float(value: Any) -> float:
    number = _to_float_or_none(value)
    return 0.0 if number is None else number


def _to_str_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [_to_str(x) for x in value if x is not None and _to_str(x) != ""]
    return [_to_str(value)]


def _to_code_lines(value: Any) -> list[str]:
    """Строки кода: пустая строка – тоже строка кода, её нельзя выбрасывать, иначе съедут номера строк."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return value.split("\n")
    if isinstance(value, (list, tuple)):
        return ["" if x is None else _to_str(x) for x in value]
    return []


def _to_text_list(value: Any) -> list[str]:
    """Пункты текста (шаги, «что проверить»): строка делится по переводам строк, а не по запятым."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split("\n") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [_to_str(x).strip() for x in value if x is not None and _to_str(x).strip()]
    return [_to_str(value)]


def _to_terms(value: Any) -> list[dict[str, str]]:
    """Словарик терминов: [{"term", "meaning"}]; словарь «термин: пояснение» тоже принимается. Пункты без термина
    пропускаются."""
    if isinstance(value, dict):
        value = [{"term": k, "meaning": v} for k, v in value.items()]
    if not isinstance(value, (list, tuple)):
        return []
    result = []
    for item in value:
        if not isinstance(item, dict):
            continue
        term = _to_str(item.get("term")).strip()
        if term:
            result.append({"term": term, "meaning": _to_str(item.get("meaning")).strip()})
    return result


def _to_str_list_dict(value: Any) -> dict[str, list[str]]:
    return {_to_str(k): _to_str_list(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _to_int_list(value: Any) -> list[int]:
    items = _to_str_list(value) if isinstance(value, str) else (value if isinstance(value, (list, tuple)) else [])
    result = []
    for item in items:
        number = _to_int_or_none(item)
        if number is not None:
            result.append(number)
    return result


def _to_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def _to_str_dict(value: Any) -> dict[str, str]:
    return {_to_str(k): _to_str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _to_int_dict(value: Any) -> dict[str, int]:
    return {_to_str(k): _to_int(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _to_findings(value: Any) -> list[Finding]:
    if not isinstance(value, (list, tuple)):
        return []
    return [x if isinstance(x, Finding) else Finding.from_dict(x) for x in value if isinstance(x, (Finding, dict))]


def _to_dict_list(value: Any) -> list[dict]:
    return [dict(x) for x in value if isinstance(x, dict)] if isinstance(value, (list, tuple)) else []


_COERCE = {
    "str": _to_str,
    "int": _to_int,
    "float": _to_float,
    "float | None": _to_float_or_none,
    "int | None": _to_int_or_none,
    "list[str]": _to_str_list,
    "list[int]": _to_int_list,
    "list[dict]": _to_dict_list,
    "list[Finding]": _to_findings,
    "dict": _to_dict,
    "dict[str, str]": _to_str_dict,
    "dict[str, int]": _to_int_dict,
    "dict[str, list[str]]": _to_str_list_dict,
}
# Особые приведения по метаданным поля (тип у них общий, а правила свои)
_COERCE_META = {"code_lines": _to_code_lines, "text_list": _to_text_list, "terms": _to_terms}


def _coercer(f: dataclasses.Field):
    for flag, coerce in _COERCE_META.items():
        if f.metadata.get(flag):
            return coerce
    return _COERCE.get(str(f.type), lambda v: v)


def _from_dict(cls, data):
    """Объект dataclass из словаря: лишние ключи пропускаются, недостающие – по умолчанию или «пустые»."""
    data = data if isinstance(data, dict) else {}
    kwargs = {}
    for f in dataclasses.fields(cls):
        coerce = _coercer(f)
        if f.name in data:
            kwargs[f.name] = coerce(data[f.name])
        elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            kwargs[f.name] = coerce(None)
    return cls(**kwargs)
