"""Дефект SCA по шаблону команды (ADR-0091): уязвимости набора, Объяснение, целевая версия и её проверка, источники,
текст «Описание → Объяснение → Рекомендации → Источники».

Функции модуля – чистые: всё нужное передаётся аргументами (находки набора, соответствия идентификаторов, исследование
компонента формата 2, записи БДУ, прежний ответ агента, запись текста набора). База и сеть здесь не читаются – данные
собирает маршрут из одного снимка пакета (ADR-0060, ADR-0091 п. 20).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.sca_contract import compare_versions, range_contains

NVD = "https://nvd.nist.gov/vuln/detail/{}"
GHSA = "https://github.com/advisories/{}"
BDU = "https://bdu.fstec.ru/vul/{}"
SOURCE_TYPES = ("advisory", "release_notes", "registry", "issue_tracker")
SOURCE_LEVELS = ("primary", "corroborated")
MIN_EXPLANATION_LETTERS = 20
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_GHSA = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$", re.I)
_BDU = re.compile(r"^BDU:\d{4}-\d{5}$", re.I)
_LETTER = re.compile(r"[A-Za-zА-Яа-яЁё]")
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
# внутренний номер уязвимости поставщика анализатора (AST-2026-000101): команда разработки его не знает, в тексты для Hub он не
# входит (ADR-0101)
_AST = re.compile(r"\bAST-\d{4}-\d+\b", re.I)
_AST_THIS = re.compile(r"\b(?:это|это же|он же|она же)\s+(?=AST-\d{4}-\d+\b)", re.I)
_AST_URL = re.compile(r"https?://\S*?AST-\d{4}-\d+\S*", re.I)  # адрес с внутренним номером – целиком


def has_internal_id(text: str) -> bool:
    """В тексте или адресе есть внутренний номер AST (ADR-0101)."""
    return bool(_AST.search(str(text or "")))


def kind_of(vuln_id: str) -> str:
    """cve, ghsa, bdu или other (AST и прочие внутренние идентификаторы)."""
    text = str(vuln_id or "").strip()
    if _CVE.match(text):
        return "cve"
    if _GHSA.match(text):
        return "ghsa"
    if _BDU.match(text):
        return "bdu"
    return "other"


def link_of(vuln_id: str) -> str:
    """Каноническая ссылка идентификатора или "" (внутренние идентификаторы ссылки не имеют)."""
    kind, text = kind_of(vuln_id), str(vuln_id).strip()
    if kind == "cve":
        return NVD.format(text.upper())
    if kind == "ghsa":
        return GHSA.format("GHSA" + text[4:].lower())
    if kind == "bdu":
        return BDU.format(text.split(":", 1)[1])
    return ""


def _norm(vuln_id: str) -> str:
    text = str(vuln_id or "").strip()
    return text.upper() if kind_of(text) in ("cve", "bdu") else (text if kind_of(text) != "ghsa" else
                                                                "GHSA" + text[4:].lower())


@dataclass
class Vuln:
    """Уязвимость – класс объединённых идентификаторов (ADR-0091 п. 8)."""

    ids: list[str]
    hub_members: list[str] = field(default_factory=list)  # находки набора, связанные с уязвимостью
    research: list[Mapping[str, Any]] = field(default_factory=list)  # находки исследования (public_findings)

    @property
    def main(self) -> str:
        """Идентификатор для текста: CVE, затем GHSA, затем БДУ, иначе первый (AST)."""
        for kind in ("cve", "ghsa", "bdu"):
            found = sorted(i for i in self.ids if kind_of(i) == kind)
            if found:
                return found[0]
        return self.ids[0]

    @property
    def public(self) -> bool:
        return kind_of(self.main) != "other"

    @property
    def public_ids(self) -> list[str]:
        """Публичные идентификаторы класса (CVE, GHSA, БДУ): по ним строки Объяснения узнаются и проверяются."""
        return [i for i in self.ids if kind_of(i) != "other"]


def strip_internal_ids(text: str) -> str:
    """Текст без внутренних номеров AST (ADR-0101): из заготовок по ответам агента («CVE-… (это AST-…): …») и из
    сохранённых до 0.9.11 текстов. Номер убирается вместе с «это» перед ним; пустые скобки и лишние запятые и пробелы,
    оставшиеся после него, – тоже. Перевод строки сохраняется."""
    out = []
    for line in str(text or "").split("\n"):
        if not _AST.search(line):
            out.append(line)
            continue
        line = _AST_URL.sub("", line)  # ссылку с номером не обрезаем до домена, а убираем целиком
        line = _AST_THIS.sub("", line)
        line = _AST.sub("", line)
        line = re.sub(r"\(\s*(?:[,;]\s*)*\)", "", line)  # «()», «(, )»
        line = re.sub(r"\(\s*[,;]\s*", "(", line)
        line = re.sub(r"\s*[,;]\s*\)", ")", line)
        line = re.sub(r"(?:\s*,){2,}", ",", line)
        line = re.sub(r"[ \t]{2,}", " ", line)
        line = re.sub(r"[ \t]+([,.;:)])", r"\1", line)
        line = re.sub(r"^([^:]*?):\s*,\s*", r"\1: ", line)
        line = re.sub(r"^\s*[:,;]\s*", "", line)  # «AST-…: описание» – без двоеточия в начале
        out.append(line.strip(" \t,;") if line.strip(" \t,;") else "")
    return "\n".join(out)


def _union(groups: Iterable[Iterable[str]]) -> dict[str, str]:
    """Транзитивное объединение идентификаторов: {идентификатор: представитель класса}."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for group in groups:
        items = [_norm(i) for i in group if str(i or "").strip()]
        for item in items:
            find(item)
        for a, b in zip(items, items[1:], strict=False):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
    return {x: find(x) for x in parent}


def set_vulns(members: Mapping[str, Iterable[str]], others: Mapping[str, Iterable[str]],
              aliases: Mapping[str, Iterable[str]], research: Iterable[Mapping[str, Any]],
              excluded: Iterable[str] = (), default_set: bool = True, rep: Mapping[str, str] | None = None,
              applicability: Mapping[str, str] | None = None) -> list[Vuln]:
    """Уязвимости набора (ADR-0091 п. 9).

    members – {номер находки набора: её идентификаторы}; others – то же для находок пакета с другим исходом или из
    других наборов; aliases – известные соответствия {идентификатор: соответствующие}; research – находки исследования
    (`public_findings`); excluded – идентификаторы, исключённые оператором; rep – общая карта классов пакета
    (class_groups), иначе строится по этим данным; applicability – действующие решения оператора {корень класса:
    решение} (ADR-0094 Р3): меняют применимость находки исследования, правила области – прежние. Порядок: по первому
    появлению у находок набора, затем уязвимости исследования."""
    research = list(research)
    if rep is None:
        groups: list[list[str]] = []
        for ids in (*members.values(), *others.values()):  # каждый идентификатор находки – сам по себе: совместное
            groups += [[i] for i in ids]                    # присутствие в находке соответствием не является
        for key, values in aliases.items():
            groups.append([key, *values])
        for item in research:
            groups.append([str(item.get("id") or ""), *[str(a) for a in item.get("aliases") or []]])
        rep = _union(groups)
    classes: dict[str, Vuln] = {}
    order: list[str] = []

    def touch(root: str) -> Vuln:
        if root not in classes:
            classes[root] = Vuln(ids=sorted(x for x, r in rep.items() if r == root))
            order.append(root)
        return classes[root]

    member_roots, other_roots = set(), set()
    for hub_id, ids in members.items():
        for i in ids:
            if str(i or "").strip():
                vuln = touch(rep[_norm(i)])
                member_roots.add(rep[_norm(i)])
                if hub_id not in vuln.hub_members:
                    vuln.hub_members.append(hub_id)
    for ids in others.values():
        for i in ids:
            if str(i or "").strip():
                other_roots.add(rep[_norm(i)])
    for item in research:
        root = rep.get(_norm(str(item.get("id") or "")))
        if root is None:
            continue
        applies = effective_applies(item, (applicability or {}).get(root, ""))
        if root in member_roots or (default_set and applies == "yes" and root not in other_roots):
            touch(root).research.append(item)
    excluded_roots = {rep[_norm(x)] for x in excluded_ids(excluded) if _norm(x) in rep}
    return [classes[r] for r in order if r not in excluded_roots]


def update_comment(component: str, target: str, payload: Mapping[str, Any] | None, members: Mapping[str, Iterable[str]],
                   others: Mapping[str, Iterable[str]], decisions: Iterable[Mapping[str, Any]], research_revision: int,
                   excluded: Iterable[Any], mapping: Mapping[str, Iterable[str]] | None = None, default_set: bool = True) -> str:
    """Заготовка комментария к выводу «обновить» (план dev7, раздел 6): целевая версия и применимые уязвимости по тем же правилам, что
    текст набора (set_vulns): решения о применимости действуют, исключённые из набора и уязвимости других наборов не называются. Цели или
    применимых уязвимостей нет – ""."""
    findings = [x for x in (payload or {}).get("public_findings") or [] if isinstance(x, Mapping) and str(x.get("id") or "").strip()]
    if not target or not findings:
        return ""
    rep = union_classes(class_groups([*members.values(), *others.values()], mapping or {}, payload))
    decided = {root: info["decision"] for root, info in applicability(decisions, rep, research_revision).items() if info["decision"]}
    vulns = set_vulns(members, others, mapping or {}, findings, excluded=excluded, default_set=default_set, rep=rep, applicability=decided)
    ids = [str(item["id"]).strip() for vuln in vulns for item in vuln.research
           if effective_applies(item, decided.get(rep.get(_norm(str(item.get("id") or "")), ""), "")) == "yes"]
    if not ids:
        return ""
    return f"Обновить {component} до версии {target}. Применимые уязвимости: {', '.join(dict.fromkeys(ids))}."


def excluded_ids(items: Iterable[Any]) -> list[str]:
    """Идентификаторы исключённых из текста набора уязвимостей: элемент – {"id", "ids", "reason"} (с обоснованием,
    ADR-0091 п. 9) или строка-идентификатор."""
    out: list[str] = []
    for item in items or []:
        if isinstance(item, Mapping):
            out += [str(i) for i in item.get("ids") or [item.get("id")] if str(i or "").strip()]
        elif str(item or "").strip():
            out.append(str(item))
    return out


def explanation_draft(vulns: Iterable[Vuln], bdu: Mapping[str, list[Mapping[str, Any]]],
                      legacy: str = "") -> str:
    """Заготовка Объяснения – строка на публичную уязвимость (ADR-0091 п. 13): русское описание БДУ ФСТЭК России,
    иначе описание и условия из исследования, иначе объяснение прежнего ответа агента (только если уязвимость одна).
    Строка без найденного текста остаётся «<идентификатор>: » – её дописывает оператор."""
    vulns = [v for v in vulns if v.public]
    lines = []
    for vuln in vulns:
        text = ""
        for vuln_id in vuln.ids:
            for record in bdu.get(vuln_id) or []:
                text = str(record.get("description") or record.get("name") or "").strip()
                if text:
                    break
            if text:
                break
        if not text:
            for item in vuln.research:
                text = str(item.get("description") or "").strip()
                conditions = str(item.get("conditions") or "").strip()
                if conditions:
                    text = f"{text} Условия: {conditions}".strip()
                if text:
                    break
        if not text and len(vulns) == 1:
            text = " ".join(str(legacy or "").split())
        lines.append(f"{vuln.main}: {' '.join(strip_internal_ids(text).split())}".rstrip())
    return "\n".join(lines)


def explanation_problems(text: str, vulns: Iterable[Vuln]) -> list[str]:
    """Публичные уязвимости, для которых в Объяснении нет строки «<идентификатор>: <не меньше 20 букв>»."""
    lines = [line.strip() for line in str(text or "").replace("\r\n", "\n").split("\n")]
    missing = []
    for vuln in vulns:
        if not vuln.public:
            continue
        ok = False
        for line in lines:
            for vuln_id in vuln.public_ids:  # строка «AST-…: …» объяснением публичной уязвимости не считается
                if line.upper().startswith(vuln_id.upper() + ":"):
                    rest = line[len(vuln_id) + 1:]
                    if len(_LETTER.findall(rest)) >= MIN_EXPLANATION_LETTERS:
                        ok = True
        if not ok:
            missing.append(vuln.main)
    return missing


def cyrillic_share(text: str) -> float:
    """Доля кириллицы среди букв (0 – букв нет)."""
    letters = _LETTER.findall(str(text or ""))
    return len(_CYRILLIC.findall(str(text or ""))) / len(letters) if letters else 0.0


def free_text(text: str, vulns: Iterable[Vuln]) -> str:
    """Строки Объяснения, которые не начинаются с идентификатора публичной уязвимости набора (свободный текст)."""
    ids = [i.upper() + ":" for v in vulns if v.public for i in v.public_ids]
    lines = [line.strip() for line in str(text or "").replace("\r\n", "\n").split("\n")]
    return "\n".join(line for line in lines if line and not any(line.upper().startswith(i) for i in ids))


def non_russian_lines(text: str, vulns: Iterable[Vuln]) -> list[str]:
    """Публичные уязвимости, строка Объяснения которых не на русском (кириллица – меньше трети букв после
    идентификатора). Проверяется каждая строка: длинная русская строка не прячет английскую (Г12)."""
    lines = [line.strip() for line in str(text or "").replace("\r\n", "\n").split("\n")]
    out = []
    for vuln in vulns:
        if not vuln.public:
            continue
        for line in lines:
            vuln_id = next((i for i in vuln.public_ids if line.upper().startswith(i.upper() + ":")), None)
            rest = line[len(vuln_id) + 1:] if vuln_id is not None else ""
            # пустой остаток после «CVE-…:» – не «не на русском»: пустоту ловит explanation_problems
            if vuln_id is not None and any(ch.isalpha() for ch in rest) and cyrillic_share(rest) < 1 / 3:
                out.append(vuln.main)
                break
    return out


# ---------------------------------------------------------------------------- целевая версия

@dataclass
class Target:
    version: str = ""
    basis: str = ""  # manual, component, research, legacy
    problem: str = ""  # причина, по которой выдача невозможна


BASIS_LABELS = {"manual": "указана оператором", "component": "решение по компоненту",
                "research": "совет исследования компонента", "legacy": "ответ внешнего агента (формат 1)",
                "no_fix": "исправленной версии нет – меры оператора вместо обновления"}
TARGET_BASES = ("", "manual", "no_fix")  # что форма текста набора может записать в target_basis (ADR-0101 п. 4);
# при записи db.save_sca_package_text проверяет полный перечень STORED_TARGET_BASES


def resolve_target(manual: str, component: Mapping[str, Any] | None, research: Mapping[str, Any] | None,
                   legacy: Mapping[str, Any] | None, today: str) -> Target:
    """Основание целевой версии по приоритету (ADR-0091 п. 14). component – текущее решение по компоненту
    (sca2_decisions: action, target_version, review_at); research – строка исследования (`payload`); legacy – прежний
    ответ агента, уже проверенный маршрутом на «Согласен», актуальность и охват (иначе None); today – дата YYYY-MM-DD."""
    manual = str(manual or "").strip()
    if manual:
        return Target(manual, "manual")
    if component:
        action = str(component.get("action") or "")
        review_at = str(component.get("review_at") or "")[:10]
        expired = bool(review_at) and review_at <= today
        if not expired:
            if action == "update" and str(component.get("target_version") or "").strip():
                return Target(str(component["target_version"]).strip(), "component")
            if action in ("keep", "replace", "remove", "accept_risk", "investigate"):
                return Target(problem=f"Решение по компоненту – «{action}»: оно противоречит исходу «Обновить». "
                                      "Укажите целевую версию вручную или измените решение по компоненту.")
    advice = (research or {}).get("package_advice") or {}
    if str(advice.get("target_version") or "").strip():
        return Target(str(advice["target_version"]).strip(), "research")
    if legacy and str(legacy.get("recommended_version") or "").strip():
        return Target(str(legacy["recommended_version"]).strip(), "legacy")
    return Target(problem="Нет проверенной целевой версии: исследуйте компонент, загрузите ответ агента или "
                          "укажите версию.")


@dataclass
class VersionCheck:
    state: str  # verified, unverified, affected, not_newer
    detail: str = ""
    affected: list[str] = field(default_factory=list)
    # остаточные уязвимости цели (ADR-0094 Р1): исправления нет или оно не установлено в исследованном охвате;
    # хранятся при любом состоянии, кроме «не новее текущей»
    residual: list[dict] = field(default_factory=list)


RESIDUAL_STATUSES = ("no_fix_published", "fix_not_found")


def severity_label(records: Iterable[Mapping[str, Any]]) -> str:
    """Важность по наибольшей оценке CVSS записей класса (ADR-0094 Р1.5)."""
    scores = [float(r.get("cvss", {}).get("score")) for r in records
              if isinstance(r.get("cvss"), Mapping) and isinstance(r["cvss"].get("score"), (int, float))]
    if not scores:
        return "важность не указана"
    top = max(scores)
    return "низкая" if top < 4 else "средняя" if top < 7 else "высокая" if top < 9 else "критическая"


def research_records(research: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    """Все записи об уязвимостях исследования: находки текущей версии и находки всех проверок версий (ADR-0094)."""
    out = [r for r in (research or {}).get("public_findings") or [] if isinstance(r, Mapping)]
    for check in (research or {}).get("version_checks") or []:
        if isinstance(check, Mapping):
            out += [r for r in check.get("findings") or [] if isinstance(r, Mapping)]
    return out


def class_groups(hub_ids: Iterable[Iterable[str]], aliases: Mapping[str, Iterable[str]],
                 research: Mapping[str, Any] | None) -> list[list[str]]:
    """Группы объединения идентификаторов (ADR-0091 п. 8) – одни на область набора, проверку цели, пояснение о версии
    Hub и решения о применимости (ADR-0094): идентификаторы находок Hub пакета (каждый сам по себе: совместное
    присутствие в находке соответствием не является), известные соответствия (AST → CVE, прежний ответ агента),
    находки исследования и всех проверок версий с их псевдонимами."""
    groups = [[i] for ids in hub_ids for i in ids]
    groups += [[key, *values] for key, values in aliases.items()]
    groups += [[str(r.get("id") or ""), *[str(a) for a in r.get("aliases") or []]] for r in research_records(research)]
    return groups


def union_classes(groups: Iterable[Iterable[str]]) -> dict[str, str]:
    """Карта классов {идентификатор: корень класса} по группам class_groups."""
    return _union(groups)


def class_root(rep: Mapping[str, str], vuln_id: Any) -> str:
    key = _norm(str(vuln_id or ""))
    return rep.get(key, key)


def class_ids(rep: Mapping[str, str], root: str) -> list[str]:
    return sorted({x for x, r in rep.items() if r == root} or {root})


def target_records(research: Mapping[str, Any], target: str) -> list[Mapping[str, Any]]:
    """Записи об уязвимостях для проверки цели: находки исследования текущей версии и находки проверки точно этой
    целевой версии (ADR-0094 Р1.1)."""
    out = [r for r in research.get("public_findings") or [] if isinstance(r, Mapping)]
    for check in research.get("version_checks") or []:
        if isinstance(check, Mapping) and check.get("role") == "target" and str(check.get("version") or "") == target:
            out += [r for r in check.get("findings") or [] if isinstance(r, Mapping)]
    return out


def record_intervals(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Интервалы записи: общие диапазоны и диапазоны позиций источников (ADR-0094 Р1.1, Р3.1). Источники противоречат
    друг другу – учитываются все: попадание цели хотя бы в один означает «затрагивает»."""
    out = [i for i in record.get("ranges") or [] if isinstance(i, Mapping)]
    for position in record.get("source_positions") or []:
        if isinstance(position, Mapping):
            out += [i for i in position.get("ranges") or [] if isinstance(i, Mapping)]
    return out


def record_refs(record: Mapping[str, Any]) -> list[str]:
    """Ссылки на доказательства записи: свои и позиций источников, диапазоны которых участвуют в проверке."""
    refs = [str(x) for x in record.get("source_refs") or []]
    for position in record.get("source_positions") or []:
        if isinstance(position, Mapping):
            refs += [str(x) for x in position.get("source_refs") or []]
    return list(dict.fromkeys(refs))


def _vulnerability_coverage_complete(check: Mapping[str, Any]) -> bool:
    """Полный поиск уязвимостей в проверке версии: есть записи охвата purpose = vulnerabilities, и все они полные.
    Полнота другого вида охвата (релизы, идентичность) поиск уязвимостей не заменяет."""
    own = [c for c in check.get("coverage") or [] if isinstance(c, Mapping) and c.get("purpose") == "vulnerabilities"]
    return bool(own) and all(c.get("complete") and c.get("status") == "ok" for c in own)


def _no_ranges(record: Mapping[str, Any]) -> bool:
    """Диапазонов нет: пусты общие или их нет у позиции источника «затрагивает»/«неясно». Позиция «не затрагивает» без
    диапазонов о других версиях ничего не говорит и не учитывается."""
    if not (record.get("ranges") or []):
        return True
    return any(isinstance(p, Mapping) and p.get("affects") != "no" and not (p.get("ranges") or [])
               for p in record.get("source_positions") or [])


def _branch_matches(target: str, branch: str) -> bool:
    return bool(branch) and (target == branch or target.startswith(branch + "."))


def fix_status(ecosystem: str, target: str, records: list[Mapping[str, Any]], research: Mapping[str, Any],
               research_date: str = "") -> dict:
    """Статус исправления класса уязвимости для цели (ADR-0094 Р1.2) – по всем записям класса и позициям их
    источников, сверху вниз: fixed_beyond (есть версия исправления новее цели), no_fix_published (доказанное
    «исправления нет» без противоречащих записей), fix_not_found (исправлений нет ни в одной записи, наибольшая
    стабильная в диапазоне), unknown."""
    fixes = []
    for r in records:
        fixes += [str(v) for v in r.get("fixed_versions") or [] if str(v or "").strip()]
        fixes += [str(i.get("fixed")) for i in record_intervals(r) if i.get("fixed")]
    if any(compare_versions(ecosystem, v, target) == 1 for v in fixes):
        return {"status": "fixed_beyond"}
    declared = [r.get("fix_status") for r in records if isinstance(r.get("fix_status"), Mapping)]
    evidence = {str(e.get("evidence_ref")): e for e in research.get("evidence") or [] if isinstance(e, Mapping)}
    proofs = [d for d in declared if d.get("status") == "no_fix_published"
              and (d.get("scope") == "package" or _branch_matches(target, str(d.get("branch") or "")))]
    if proofs and not fixes and not any(d.get("status") == "fixed" for d in declared):
        # сначала область утверждения (весь пакет перекрывает ветку), затем доказательства и дата только этой
        # области: доказательству ветки не приписывается утверждение обо всём пакете (ревью c7a4341/01b1d90)
        scope = "package" if any(d.get("scope") == "package" for d in proofs) else "branch"
        if scope == "package":
            chosen = [d for d in proofs if d.get("scope") == "package"]
        else:  # несколько веток цели («1» и «1.5»): утверждение – о самой узкой, доказательства – только её
            branch = max((str(d.get("branch") or "") for d in proofs if d.get("scope") == "branch"), key=len)
            chosen = [d for d in proofs if d.get("scope") == "branch" and str(d.get("branch") or "") == branch]
        dates = [str(evidence.get(str(ref), {}).get("checked_at") or "")[:10]
                 for d in chosen for ref in d.get("source_refs") or []]
        proof_refs = list(dict.fromkeys(str(ref) for d in chosen for ref in d.get("source_refs") or []))
        return {"status": "no_fix_published", "scope": scope,
                "branch": "" if scope == "package" else str(chosen[0].get("branch") or ""),
                "date": max([d for d in dates if d] or [research_date]),
                # доказательства утверждения «исправления нет» (proof_refs – источник в скобках строки) и, отдельно,
                # доказательства попадания цели – записей класса и позиций источников (Р1.5)
                "proof_refs": proof_refs,
                "refs": list(dict.fromkeys(proof_refs + [ref for r in records for ref in record_refs(r)]))}
    latest = str((research.get("latest_stable_release") or {}).get("version") or "")
    if (not fixes and not any(d.get("status") == "fixed" for d in declared) and latest
            and any(range_contains(ecosystem, latest, i) is True for r in records for i in record_intervals(r))):
        return {"status": "fix_not_found", "date": research_date,
                "refs": sorted({ref for r in records for ref in record_refs(r)})}
    return {"status": "unknown"}


def check_version(ecosystem: str, current: str, target: str, research: Mapping[str, Any] | None,
                  research_date: str = "", rep: Mapping[str, str] | None = None,
                  not_applicable: Iterable[str] = ()) -> VersionCheck:
    """Проверка целевой версии (ADR-0091 пп. 15–16, ADR-0094 Р1): цель не новее текущей – запрет; затем классы
    уязвимостей, затрагивающих цель (находки исследования и проверки цели, с позициями источников), делятся на
    остаточные (исправления нет или оно не установлено) и прочие (блокируют); затем порядок версий, неизвестные
    попадания, диапазоны, охват исследования и проверки цели, публикация. Остаточные возвращаются при любом исходе,
    кроме «не новее текущей».

    rep – общая карта классов пакета (class_groups), иначе строится по записям исследования; not_applicable –
    идентификаторы классов с действующим решением оператора «не применима к продукту» (ADR-0094 Р3): такие классы
    исключаются до всех проверок."""
    order = compare_versions(ecosystem, target, current)
    if order is not None and order <= 0:
        return VersionCheck("not_newer", "целевая версия не новее текущей: обновлять нечего")
    if not research:
        return VersionCheck("unverified", "исследования компонента нет")
    records = target_records(research, target)
    if rep is None:
        rep = _union([[str(r.get("id") or ""), *[str(a) for a in r.get("aliases") or []]] for r in records])
    dropped = {class_root(rep, x) for x in not_applicable}
    classes: dict[str, list[Mapping[str, Any]]] = {}
    for r in records:
        root = class_root(rep, r.get("id"))
        if root and root not in dropped:
            classes.setdefault(root, []).append(r)
    records = [r for items in classes.values() for r in items]
    hit_roots, unknown = [], False
    for root, items in classes.items():
        hits = [range_contains(ecosystem, target, i) for r in items for i in record_intervals(r)]
        if True in hits:
            hit_roots.append(root)
        if None in hits:  # неизвестное сравнение не скрывается известным попаданием того же класса
            unknown = True
    affected, residual = [], []
    for root in hit_roots:
        items = classes[root]
        ids = class_ids(rep, root)
        main = Vuln(ids=ids).main
        status = fix_status(ecosystem, target, items, research, research_date)
        if status["status"] in RESIDUAL_STATUSES:
            residual.append({"id": main, "ids": ids, "severity": severity_label(items), **status})
        else:
            affected.append(main)
    residual.sort(key=lambda r: r["id"])
    if affected:
        return VersionCheck("affected", "целевая версия входит в диапазон уязвимости", sorted(set(affected)),
                            residual=residual)
    if order is None:
        return VersionCheck("unverified", "порядок версий не установлен", residual=residual)
    if unknown:
        return VersionCheck("unverified", "попадание в диапазон уязвимости не установлено", residual=residual)
    if any(_no_ranges(r) for r in records):
        return VersionCheck("unverified", "у уязвимости нет диапазонов версий", residual=residual)
    coverage = [c for c in research.get("research_coverage") or [] if c.get("purpose") == "vulnerabilities"]
    if not coverage or not all(c.get("complete") and c.get("status") == "ok" for c in coverage):
        return VersionCheck("unverified", "поиск уязвимостей в исследовании неполный", residual=residual)
    # проверка точно этой целевой версии (ответ 2.1) – со своим охватом: неполный поиск по цели не даёт «проверена»
    target_check = next((c for c in research.get("version_checks") or [] if isinstance(c, Mapping)
                         and c.get("role") == "target" and str(c.get("version") or "") == target), None)
    if target_check is not None and not _vulnerability_coverage_complete(target_check):
        return VersionCheck("unverified", "поиск уязвимостей целевой версии неполный", residual=residual)
    if not published(target, research):
        return VersionCheck("unverified", "публикация целевой версии не подтверждена", residual=residual)
    return VersionCheck("verified", f"проверена по исследованию от {research_date}".strip(), residual=residual)


@dataclass
class NoFixCheck:
    """Проверка режима «Исправленной версии нет» (ADR-0101): items – уязвимости «Описания»
    без исправления для текущей версии (как остаточные ADR-0094 Р1.2: id, ids, severity, status, date, refs,
    proof_refs); problems – почему режим недоступен; fixed – уязвимости, у которых исследование нашло исправление
    новее текущей версии: это предупреждение, а не запрет (бэклог 126: исправление
    бывает выпущено под другими координатами, и под текущими обновлять некуда)."""
    items: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)


def _fix_versions(records: list[Mapping[str, Any]]) -> list[str]:
    fixes: list[str] = []
    for r in records:
        fixes += [str(v) for v in r.get("fixed_versions") or [] if str(v or "").strip()]
        fixes += [str(i.get("fixed")) for i in record_intervals(r) if i.get("fixed")]
    return list(dict.fromkeys(fixes))


def _lowest_fix_above(ecosystem: str, current: str, records: list[Mapping[str, Any]]) -> str:
    """Наименьшая версия исправления новее текущей; порядок хоть одной не установлен – "" (версия не называется)."""
    newer = []
    for version in _fix_versions(records):
        order = compare_versions(ecosystem, version, current)
        if order is None:
            return ""
        if order == 1:
            newer.append(version)
    best = ""
    for version in newer:
        if not best:
            best = version
            continue
        order = compare_versions(ecosystem, version, best)
        if order is None:
            return ""
        if order == -1:
            best = version
    return best


def no_fix_check(ecosystem: str, current: str, research: Mapping[str, Any] | None, research_date: str,
                 vulns: Iterable[Vuln], rep: Mapping[str, str], not_applicable: Iterable[str] = ()) -> NoFixCheck:
    """Режим «Исправленной версии нет» (ADR-0101): обновлять некуда, если по исследованию у каждой публичной уязвимости
    «Описания» нет исправления для текущей версии – статус no_fix_published (утверждение обо всём пакете или о ветке,
    в которой и наибольшая стабильная версия) или fix_not_found (ADR-0094 Р1.2). Уязвимость без записи в исследовании
    или с неизвестным статусом – режим недоступен, причина называет её (problems). Уязвимость с исправлением новее
    текущей (fixed_beyond) режим не отменяет: она идёт в список fixed, оператор подтверждает её отметкой (ADR-0151).
    Классы с решением оператора «не применима к продукту» (ADR-0094 Р3) проверку не проходят и строки не получают."""
    if not research:
        return NoFixCheck(problems=["Режим «Исправленной версии нет» доступен только по исследованию компонента: по нему "
                                    "проверяется, что исправления действительно нет. Исследуйте компонент или укажите "
                                    "целевую версию."])
    # все записи класса – находки текущей версии и всех проверок версий (ревью шага 8): версия исправления, известная
    # по проверке другой версии, тоже значит «обновлять есть куда»
    records = research_records(research)
    dropped = {class_root(rep, x) for x in not_applicable}
    classes: dict[str, list[Mapping[str, Any]]] = {}
    for r in records:
        root = class_root(rep, r.get("id"))
        if root and root not in dropped:
            classes.setdefault(root, []).append(r)
    latest = str((research.get("latest_stable_release") or {}).get("version") or "")
    out = NoFixCheck()
    for vuln in vulns:
        if not vuln.public:
            continue
        root = class_root(rep, vuln.ids[0])
        if root in dropped:
            continue
        items = classes.get(root) or []
        if not items:
            out.problems.append(f"{vuln.main}: в исследовании компонента нет сведений об этой уязвимости – что исправления "
                                "нет, не установлено. Укажите целевую версию или исследуйте компонент заново.")
            continue
        status = fix_status(ecosystem, current, items, research, research_date)
        if status["status"] == "fixed_beyond":
            version = _lowest_fix_above(ecosystem, current, items)
            out.fixed.append(f"{vuln.main}: по исследованию есть исправление"
                             + (f" в версии {version}" if version else "") + ".")
        elif (status["status"] == "no_fix_published" and status.get("scope") == "branch"
              and not (latest and _branch_matches(latest, str(status.get("branch") or "")))):
            out.problems.append(f"{vuln.main}: исправления нет только в ветке {status.get('branch')}"
                                + (f", а наибольшая стабильная версия {latest} – в другой ветке: проверьте её"
                                   if latest else ", наибольшая стабильная версия не установлена")
                                + " и укажите целевую версию.")
        elif status["status"] in RESIDUAL_STATUSES:
            out.items.append({"id": vuln.main, "ids": class_ids(rep, root), "severity": severity_label(items), **status})
        else:
            out.problems.append(f"{vuln.main}: статус исправления не установлен – исследуйте компонент или укажите "
                                "целевую версию.")
    out.items.sort(key=lambda r: r["id"])
    return out


def published(target: str, research: Mapping[str, Any]) -> bool:
    """Публикация версии подтверждена доказательством registry или release_notes (ADR-0091 п. 16)."""
    evidence = {str(e.get("evidence_ref")): e for e in research.get("evidence") or []}
    for part in (research.get("latest_stable_release") or {}, research.get("package_advice") or {}):
        version = str(part.get("version") or part.get("target_version") or "").strip()
        if version != target:
            continue
        for ref in part.get("source_refs") or []:
            if str((evidence.get(str(ref)) or {}).get("source_type") or "") in ("registry", "release_notes"):
                return True
    return False


def _version_key(version: str) -> list[tuple[int, Any]]:
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-]", version)]


def hub_explanation(ecosystem: str, hub_versions: Iterable[str], target: str, research: Mapping[str, Any] | None,
                    rep: Mapping[str, str] | None = None, not_applicable: Iterable[str] = ()) -> tuple[str, list[str]]:
    """Пояснение «почему не версия Hub» (ADR-0094 Р2.7) и ссылки на его доказательства (Р1.5) – одно на набор, по
    версиям Hub находок набора: называется уязвимость из проверки точно этой версии Hub (ответ 2.1), только если она
    затрагивает версию Hub и доказанно не затрагивает цель – проверка цели есть, её охват полный, у всех записей класса
    (находки исследования, проверок версий, позиции источников) есть диапазоны и цель не попадает ни в один. Иначе –
    ничего: строка, называющая не ту уязвимость, хуже её отсутствия. rep – общая карта классов пакета;
    not_applicable – классы с действующим решением «не применима к продукту»: они не называются."""
    if not research or not target:
        return "", []
    checks = [c for c in research.get("version_checks") or [] if isinstance(c, Mapping)]
    target_check = next((c for c in checks if c.get("role") == "target" and str(c.get("version") or "") == target), None)
    if target_check is None or not _vulnerability_coverage_complete(target_check):
        return "", []
    coverage = [c for c in target_check.get("coverage") or [] if isinstance(c, Mapping)
                and c.get("purpose") == "vulnerabilities"]
    records = research_records(research)
    if rep is None:
        rep = _union([[str(r.get("id") or ""), *[str(a) for a in r.get("aliases") or []]] for r in records])
    by_root: dict[str, list[Mapping[str, Any]]] = {}
    for r in records:
        by_root.setdefault(class_root(rep, r.get("id")), []).append(r)
    dropped = {class_root(rep, x) for x in not_applicable}
    lines, refs = [], []
    for hub in sorted({str(v) for v in hub_versions if str(v or "").strip() and str(v) != target}, key=_version_key):
        hub_check = next((c for c in checks if c.get("role") == "hub" and str(c.get("version") or "") == hub), None)
        if hub_check is None:
            continue
        named = []
        for finding in hub_check.get("findings") or []:
            root = class_root(rep, finding.get("id"))
            items = by_root.get(root, [])
            intervals = [i for r in items for i in record_intervals(r)]
            if not items or root in dropped or any(_no_ranges(r) for r in items):
                continue
            own_refs = list(dict.fromkeys(ref for r in items for ref in record_refs(r)))
            # утверждение в тексте – только с подходящим доказательством именно этой уязвимости (Р1.5)
            if all(range_contains(ecosystem, target, i) is False for i in intervals) and any(
                    range_contains(ecosystem, hub, i) is True for i in intervals) and evidence_urls(own_refs, research):
                named.append(f"{Vuln(ids=class_ids(rep, root)).main} ({severity_label(items)})")
                refs += own_refs
        if named:
            refs += [str(x) for c in coverage for x in c.get("source_refs") or []]
            lines.append(f"Версия {hub}, указанная в Hub, затронута {', '.join(named)}; по исследованным диапазонам "
                         f"версия {target} не затронута.")
    return "\n".join(lines), list(dict.fromkeys(refs))


def hub_note(ecosystem: str, hub_versions: Iterable[str], target: str, research: Mapping[str, Any] | None,
             rep: Mapping[str, str] | None = None) -> str:
    """Текст пояснения «почему не версия Hub» (hub_explanation без ссылок)."""
    return hub_explanation(ecosystem, hub_versions, target, research, rep)[0]


# ---------------------------------------------------------------------------- решения оператора о применимости

APPLICABILITY_LABELS = {"applies": "применима", "not_current": "не затрагивает текущую версию",
                        "not_product": "не применима к продукту"}


def effective_applies(item: Mapping[str, Any], decision: str = "") -> str:
    """Применимость находки исследования с учётом действующего решения оператора (ADR-0094 Р3.2)."""
    if decision == "applies":
        return "yes"
    if decision in ("not_current", "not_product"):
        return "no"
    return str(item.get("applies") or "")


def applicability(decisions: Iterable[Mapping[str, Any]], rep: Mapping[str, str],
                  research_revision: int) -> dict[str, dict]:
    """Решения оператора о применимости по классам уязвимостей (ADR-0094 Р3.3): {корень класса: {"decision" –
    действующее решение или "", "rows" – сохранённые решения, чьи идентификаторы попали в класс, "stale" – почему
    решение не действует}}. Решение действует, только если оно в классе одно, его идентификаторы совпадают с текущим
    составом класса и оно принято на текущей ревизии исследования. Решение сопоставляется по сохранённым
    идентификаторам, а не по ключу: основной идентификатор класса сдвигается, когда к нему присоединяется CVE."""
    out: dict[str, dict] = {}
    for row in decisions:
        if not str(row.get("decision") or ""):  # решение снято: строка хранит только редакцию
            continue
        ids = sorted({_norm(i) for i in row.get("ids") or [] if str(i or "").strip()})
        for root in sorted({rep[i] for i in ids if i in rep}):
            out.setdefault(root, {"decision": "", "rows": [], "stale": ""})["rows"].append(row)
    for root, info in out.items():
        rows = info["rows"]
        if len(rows) > 1:
            info["stale"] = ("противоположные решения в одном классе уязвимости"
                             if len({r.get("decision") for r in rows}) > 1 else "состав уязвимости изменился")
            continue
        ids = sorted({_norm(i) for i in rows[0].get("ids") or [] if str(i or "").strip()})
        if ids != class_ids(rep, root):
            info["stale"] = "состав уязвимости изменился"
        elif int(rows[0].get("research_revision") or 0) != int(research_revision or 0):
            info["stale"] = "исследование компонента обновлено"
        else:
            info["decision"] = str(rows[0].get("decision") or "")
    return out


# ---------------------------------------------------------------------------- источники и текст

TEXT_SOURCE_TYPES = ("advisory", "release_notes", "issue_tracker")  # в «Источники» – страницы для человека (Г7)


def human_url(url: str) -> bool:
    """Адрес страницы для человека: не запрос к API (хост api.*, путь /api/, строка запроса) и не файл метаданных
    реестра (maven-metadata.xml, .pom)."""
    from urllib.parse import urlsplit
    parts = urlsplit(str(url or ""))
    host, path = parts.netloc.lower(), parts.path.lower()
    # строка запроса сама по себе не признак API: у трекеров ошибок страница записи – show_bug.cgi?id=…
    return bool(parts.scheme in ("http", "https") and host and not host.startswith("api.") and "/api/" not in path
                and not path.endswith(("maven-metadata.xml", ".pom", ".json")))


def research_sources(vulns: Iterable[Vuln], research: Mapping[str, Any] | None, target: str) -> list[str]:
    """Ссылки доказательств исследования по уязвимостям набора (ADR-0091 п. 19, уточнение dev7: ссылки совета и условий перехода к целевой версии про другое, в «Источники» не идут) – только страницы
    для человека: реестры и адреса API служат доказательством публикации, но в текст для команды разработки не идут (Г7)."""
    if not research:
        return []
    refs: list[str] = []
    for vuln in vulns:
        for item in vuln.research:
            refs += [str(r) for r in item.get("source_refs") or []]
    return evidence_urls(refs, research)


def evidence_urls(refs: Iterable[str], research: Mapping[str, Any] | None) -> list[str]:
    """Адреса доказательств для «Источников» (ADR-0091 п. 19) – одни правила для всех автоматических утверждений
    текста: бюллетень, заметки о релизе или трекер, уровень primary или corroborated, страница для человека (Г7)."""
    evidence = {str(e.get("evidence_ref")): e for e in (research or {}).get("evidence") or [] if isinstance(e, Mapping)}
    out = []
    for ref in refs:
        item = evidence.get(str(ref)) or {}
        url = str(item.get("url") or "")
        if (url and item.get("source_type") in TEXT_SOURCE_TYPES and item.get("level") in SOURCE_LEVELS
                and human_url(url) and url not in out):
            out.append(url)
    return out


def residual_line(item: Mapping[str, Any], target: str, research: Mapping[str, Any] | None) -> str:
    """Строка «Рекомендаций» об остаточной уязвимости цели (ADR-0094 Р1.5): слова – по статусу исправления."""
    return f"{residual_lead(item, research)}: {item.get('id')} ({item.get('severity')}) – обновление до {target} её не закрывает."


def no_fix_line(item: Mapping[str, Any], research: Mapping[str, Any] | None) -> str:
    """Строка «Рекомендаций» режима «Исправленной версии нет» (ADR-0101): те же слова по статусу, что у остаточного
    риска, без «обновление до … её не закрывает». fix_not_found – «не установлено в исследованном охвате», а не «нет»:
    отсутствие исправления не доказано."""
    return f"{residual_lead(item, research)}: {item.get('id')} ({item.get('severity')})."


def residual_lead(item: Mapping[str, Any], research: Mapping[str, Any] | None) -> str:
    """Начало строки о статусе исправления: «Исправления нет ни в одной опубликованной версии на <дата> (<источник>)»,
    «В ветке <ветка> исправления нет на …» или «Исправление не установлено в исследованном охвате на <дата>»."""
    from urllib.parse import urlsplit
    # источник в скобках – только доказательство самого утверждения «исправления нет», не диапазонов (ревью c7a4341)
    hosts = [urlsplit(url).netloc for url in evidence_urls(item.get("proof_refs") or [], research)]
    source = next((h for h in hosts if h), "")
    date = str(item.get("date") or "")
    if item.get("status") == "no_fix_published" and item.get("scope") == "branch":
        lead = f"В ветке {item.get('branch')} исправления нет на {date}" + (f" ({source})" if source else "")
    elif item.get("status") == "no_fix_published":
        lead = f"Исправления нет ни в одной опубликованной версии на {date}" + (f" ({source})" if source else "")
    else:
        lead = f"Исправление не установлено в исследованном охвате на {date}"
    return lead


ALSO_AFFECTED = "Также затрагивают эту версию:"


def description_lines(vulns: Iterable[Vuln]) -> tuple[list[str], list[str]]:
    """Строки «Описания» (ADR-0101 п. 3): уязвимости находок Hub набора и применимые по исследованию, которых Hub не
    нашёл (их генератор ставит после ALSO_AFFECTED), – только публичные, «<идентификатор> (<ссылка>)». Те же строки
    сверяет проверка текста перед Hub (ADR-0123 п. 4.2)."""
    vulns = list(vulns)
    found = [f"{v.main} ({link_of(v.main)})" for v in vulns if v.public and v.hub_members]
    extra = [f"{v.main} ({link_of(v.main)})" for v in vulns if v.public and not v.hub_members]
    return found, extra


def body_v0910(component: str, vulns: list[Vuln], explanation: str, target: str, sources: Iterable[str],
               hub_note: str = "", ast_shown: Iterable[str] = (), residual_lines: Iterable[str] = (),
               recommendation_note: str = "") -> str:
    """Текст дефекта набора в формате 0.9.8–0.9.10 (строки AST в «Описании», без «Также затрагивают эту версию:»,
    без очистки от AST) – только для узнавания отметок «Дефект создан в Hub», поставленных до 0.9.11: карточка
    называет причину, по которой текст изменился (ADR-0101). Не меняется."""
    lines = ["Описание"]
    for vuln in vulns:
        if vuln.public:
            lines.append(f"{vuln.main} ({link_of(vuln.main)})")
    for ast in ast_shown:
        lines.append(f"{ast} – публичный идентификатор не установлен")
    lines += ["", "Объяснение", *[x.rstrip() for x in str(explanation or "").strip().split("\n")], "",
              "Рекомендации"]
    if hub_note:
        lines.append(hub_note)
    lines += [str(x) for x in residual_lines if str(x).strip()]
    lines += [x.rstrip() for x in str(recommendation_note or "").strip().split("\n") if x.strip()]
    lines.append(f"Обновление {component} до версии {target}")
    links = []
    for vuln in vulns:
        if vuln.public and link_of(vuln.main) not in links:
            links.append(link_of(vuln.main))
    for url in sources:
        if url not in links:
            links.append(url)
    lines += ["", "Источники", *links]
    return "\n".join(lines).strip() + "\n"


def strip_ids_keep_indent(text: str) -> str:
    """strip_internal_ids для текста оператора в нынешнем формате (ADR-0149 п. 5): внутренний номер AST убирается,
    отступ строки остаётся – сама чистка схлопывает пробелы и срезает края строки, где был номер (ревью Kimi круга
    5). Строка, от которой остался один номер, – пустая. Прежние форматы – strip_internal_ids как был."""
    out = []
    for line in str(text or "").split("\n"):
        body = line.lstrip(" \t")
        cleaned = strip_internal_ids(body)
        out.append(line[:len(line) - len(body)] + cleaned if cleaned.strip() else cleaned)
    return "\n".join(out)


def note_lines(note: str, *, legacy: bool = False) -> list[str]:
    """Строки «Добавления к «Рекомендациям»» для тела дефекта: как написал оператор – с пустыми строками между
    абзацами, без внутренних номеров AST (ADR-0101 п. 1); строка, от которой после удаления
    номера ничего не осталось, не входит. legacy=True – правила до 0.10.0.dev21: пустые строки не входят (только для
    узнавания прежних подписей текста)."""
    if legacy:  # в точности как до 0.10.0.dev21: края срезаны целиком, пустые строки не входят (ревью Codex круга 5)
        return [x.rstrip() for x in strip_internal_ids(str(note or "").strip()).split("\n") if x.strip()]
    from app.defect import edges
    text = edges(note)  # пустые строки по краям не уходят, отступ первой строки остаётся (ADR-0149 п. 5)
    if not text.strip():
        return []
    out = []
    for raw in text.split("\n"):
        if not raw.strip():
            out.append("")
            continue
        line = strip_ids_keep_indent(raw).rstrip()
        if line.strip():
            out.append(line)
    return out


def body(component: str, vulns: list[Vuln], explanation: str, target: str, sources: Iterable[str],
         hub_note: str = "", residual_lines: Iterable[str] = (), recommendation_note: str = "", *,
         legacy_note: bool = False) -> str:
    """Текст дефекта по шаблону команды (ADR-0091 п. 12; ADR-0094: строки остаточного риска и добавление оператора
    – перед строкой обновления). Внутренних номеров AST в тексте нет (ADR-0101): уязвимость без публичного
    идентификатора в «Описание» не входит, из Объяснения и добавления оператора номера убираются. Добавление
    оператора – с его пустыми строками (note_lines); legacy_note=True – без них, как до 0.10.0.dev21 (узнавание
    прежних подписей «Текст проверен», «Версию проверил сам», «Остаточный риск проверил» и отметок)."""
    # «Описание» (ADR-0101): сначала уязвимости находок Hub этого набора, затем – после строки
    # «Также затрагивают эту версию:» – применимые по исследованию, которых Hub не нашёл; заголовок – только если над
    # ним есть уязвимости Hub
    found, extra = description_lines(vulns)
    lines = ["Описание", *found]
    if extra:
        if found:
            lines.append(ALSO_AFFECTED)
        lines += extra
    from app.defect import edges
    if legacy_note:  # прежние правила – как были: края текста срезаны целиком
        explanation = strip_internal_ids(str(explanation or "").strip())
        lines += ["", "Объяснение", *[x.rstrip() for x in explanation.split("\n")], "", "Рекомендации"]
    else:  # отступ первой строки оператора остаётся (ADR-0149 п. 5)
        explanation = edges(strip_ids_keep_indent(edges(explanation)))
        lines += ["", "Объяснение", *explanation.split("\n"), "", "Рекомендации"]
    if hub_note:
        lines.append(strip_internal_ids(hub_note))
    lines += [strip_internal_ids(str(x)) for x in residual_lines if str(x).strip()]
    lines += note_lines(recommendation_note, legacy=legacy_note)
    if target:  # режим «Исправленной версии нет» (ADR-0101): вместо строки обновления – меры оператора выше
        lines.append(f"Обновление {component} до версии {target}")
    links = []
    for vuln in vulns:
        if vuln.public and link_of(vuln.main) not in links:
            links.append(link_of(vuln.main))
    for url in sources:
        if url not in links and not has_internal_id(url):  # адрес с внутренним номером – не источник для получателя дефекта
            links.append(url)
    lines += ["", "Источники", *links]
    return "\n".join(lines).strip() + "\n"
