"""Сценарий исследования компонентов SCA: сборка задания внешнему агенту, комплект для него и отчёты.

Задание собирается из текущей выгрузки AppSec.Hub: по каждому пакету – экосистема, исходное имя, исходная
версия и вид идентичности, плюс устойчивый input_ref (экосистема, имя, версия). Агент получает комплект из шести
файлов и возвращает один answer.json; проверяет его app/sca_contract.py, который же копируется в комплект как
validate.py. Решение человека хранится отдельно от фактов ответа и никогда их не переписывает.

Правила отбора строк (внутренние имена, сомнительные координаты) те же, что у прежнего пакета для агентов
(sca.package_report): этот сценарий не заводит второго понимания того, что вообще является пакетом.
"""

from __future__ import annotations

import json
import re
import io
import secrets
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from app import sca, sca_contract as contract
from app.sca_contract import (ANSWER_CONTRACT, FUTURE_TOLERANCE_DAYS, LIMITS, TASK_CONTRACT, VALIDATOR_VERSION,
                              canonical, input_ref, schema, sha256,
                              template as answer_template, validate_answer)

# Задание /3 (план 0.9.13, К8): в строках – публичные идентификаторы уязвимостей из выгрузки (vulnerability_ids).
# Контракт ответа /2 и валидатор прежние: комплект несёт тот же sca_contract.py побайтно
CONTRACT = "local-triage/sca-task/3"
# Подпись пакета (input_sig) считается от основы прежнего контракта: подъём контракта задания пакеты не меняет –
# исследования и решения по компонентам остаются действующими (план 0.9.13, шаг B2)
IDENTITY_CONTRACT = TASK_CONTRACT
PUBLIC_ID_LIMIT = 64
_PUBLIC_IDS = (re.compile(r"CVE-\d{4}-\d{4,}"), re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"),
               re.compile(r"BDU:\d{4}-\d{5}"))
PAGE_SIZE = 200
ZIP_NAME = "sca-components-{task_id}.zip"

DECISIONS = ("update", "replace", "remove", "keep", "accept_risk", "investigate")
#: решение требует заполнить эти поля, иначе оно не про смысл. У замены достаточно имени: точную версию
#: заменяющего пакета часто выбирают позже, и ждать её ради решения о замене не нужно.
DECISION_NEEDS = {"update": ("target_version",), "replace": ("replacement_name",)}
RATIONALE_CHARS = 2000
VERSION_CHARS = 200

STATUS_LABELS = {"vulnerable": "уязвим", "no_known_vulnerabilities": "уязвимостей не найдено",
                 "incomplete": "исследование неполное", "identity_unresolved": "идентичность не подтверждена",
                 "": "не исследован"}
IDENTITY_LABELS = {"resolved": "подтверждена", "ambiguous": "неоднозначна", "unresolved": "не разрешена",
                   "unknown": "не определялась"}
IDENTITY_KIND_LABELS = {"coordinates": "координаты", "short_name": "краткое имя", "registry_name": "имя реестра"}
UPDATE_LABELS = {"up_to_date": "актуальная", "update_available": "доступно обновление", "unknown": "неизвестно"}
SUPPORT_LABELS = {"supported": "поддерживается", "maintenance": "только исправления",
                  "eol": "поддержка закончилась", "deprecated": "объявлен устаревшим",
                  "archived": "проект архивирован", "unknown": "неизвестно"}
SCOPE_LABELS = {"oss": "открытая поддержка", "commercial": "платная поддержка", "unknown": "неизвестно"}
COVERAGE_LABELS = {"ok": "проверен", "partial": "проверен частично", "error": "не проверен"}
ADVICE_LABELS = {"update": "обновить", "replace": "заменить", "remove": "вывести из зависимостей",
                 "keep": "оставить", "accept_risk": "рассмотреть принятие риска", "needs_identity": "сначала идентификация",
                 "no_action": "без действий", "insufficient_data": "данных недостаточно"}
DECISION_LABELS = {"update": "обновить", "replace": "заменить", "remove": "вывести из зависимостей",
                   "keep": "оставить", "accept_risk": "риск принят", "investigate": "исследовать позже"}
APPLIES_LABELS = {"yes": "относится к этой версии", "no": "не относится", "unknown": "неясно"}
LEVEL_LABELS = {"primary": "первоисточник", "corroborated": "подтверждено несколькими источниками",
                "single_source": "один источник", "unconfirmed": "не подтверждено"}
EVIDENCE_LABELS = {"registry": "реестр пакетов", "advisory": "бюллетень", "release_notes": "изменения релиза",
                   "policy": "политика поддержки", "aggregator": "агрегатор уязвимостей",
                   "issue_tracker": "трекер задач", "other": "прочее"}
GAP_LABELS = {"IDENTITY_AMBIGUOUS": "идентичность неоднозначна", "IDENTITY_UNRESOLVED": "идентичность не разрешена",
              "VERSION_UNKNOWN": "версия неизвестна", "RELEASE_UNKNOWN": "последний релиз неизвестен",
              "COVERAGE_INCOMPLETE": "охват источников неполный", "SOURCE_UNAVAILABLE": "источник недоступен",
              "SOURCE_BLOCKED": "источник не отвечает", "NO_PUBLIC_FIX": "публичного исправления нет",
              "FIX_UNCONFIRMED": "исправление не подтверждено", "APPLICABILITY_UNCLEAR": "применимость неясна",
              "LICENSE_UNKNOWN": "условия лицензии неизвестны", "SUPPORT_UNKNOWN": "поддержка неизвестна",
              "NOT_RESEARCHED": "не исследовано", "OTHER": "прочее"}
TASK_STATE_LABELS = {"current": "актуальное задание", "superseded": "задание устарело"}

# Подписи отдаются шаблонам только для чтения и не словарём dict: в шаблонах к ним обращаются как
# `labels.update.get(...)`, а у обычного словаря на этом месте получается метод обновления, а не набор подписей.

LABELS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "status": MappingProxyType(STATUS_LABELS), "identity": MappingProxyType(IDENTITY_LABELS),
    "identity_kind": MappingProxyType(IDENTITY_KIND_LABELS), "update": MappingProxyType(UPDATE_LABELS),
    "support": MappingProxyType(SUPPORT_LABELS), "scope": MappingProxyType(SCOPE_LABELS),
    "coverage": MappingProxyType(COVERAGE_LABELS), "advice": MappingProxyType(ADVICE_LABELS),
    "decision": MappingProxyType(DECISION_LABELS), "applies": MappingProxyType(APPLIES_LABELS),
    "level": MappingProxyType(LEVEL_LABELS), "source_type": MappingProxyType(EVIDENCE_LABELS),
    "gap": MappingProxyType(GAP_LABELS), "task_state": MappingProxyType(TASK_STATE_LABELS),
})

STATUS_FILTERS = ("vulnerable", "no_known_vulnerabilities", "incomplete", "identity_unresolved", "unresearched")
# ADR-0096: версии шкалы CVSS, виды строк без балла, значения отборов поддержки, совета агента и действия оператора
CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")
SCORE_KINDS = {"unresearched": "не исследован", "applies_unknown": "применимость не установлена",
               "none_applicable": "применимых не найдено", "score_unknown": "балл неизвестен"}
SUPPORT_FILTERS = ("supported", "maintenance", "eol", "deprecated", "archived", "unknown")
ACTION_FILTERS = ("update", "replace", "remove", "keep", "accept_risk", "investigate", "none")
AGE_FILTERS = ("30", "90")
SOURCE_FILE = Path(__file__).with_name("sca_contract.py")


# ------------------------------------------------------------------ состав задания

def identity_kind(ecosystem: str, name: str) -> str:
    """Вид идентичности по экосистеме и исходному имени.

    maven: координаты groupId:artifactId, если имя их содержит, иначе краткое имя, которое агент разрешает по
    источникам и не угадывает; остальные реестры: имя как есть, область npm (@scope) не отбрасывается."""
    if ecosystem == "maven":
        return "coordinates" if ":" in (name or "") else "short_name"
    return "registry_name"


def public_vulnerability_ids(values: Iterable[Any]) -> list[str]:
    """Публичные идентификаторы уязвимостей для задания (П19):
    только CVE-ГГГГ-N…, GHSA-xxxx-xxxx-xxxx (тело – в нижнем регистре) и BDU:ГГГГ-NNNNN, без повторов, по порядку,
    не больше 64. Это отдельная строгая выборка, а не копия списка уязвимостей выгрузки: там и внутренние номера
    анализатора (AST-…), а они в задание не уходят."""
    found: set[str] = set()
    for raw in values or ():
        text = str(raw or "").strip()
        candidate = "GHSA-" + text[5:].lower() if text.upper().startswith("GHSA-") else text.upper()
        if any(pattern.fullmatch(candidate) for pattern in _PUBLIC_IDS):
            found.add(candidate)
    return sorted(found)[:PUBLIC_ID_LIMIT]


def ids_of(item: Mapping[str, Any]) -> list[str]:
    """vulnerability_ids строки: список из задания или JSON-строка из базы (sca2_task_rows); иначе пусто."""
    value = item.get("vulnerability_ids")
    if isinstance(value, str):
        try:
            value = json.loads(value or "[]")
        except ValueError:
            value = []
    return [str(x) for x in value] if isinstance(value, list) else []


def input_sig(contract: str, ecosystem: str, name: str, version: str, kind: str) -> str:
    """Подпись пакета: что исследование считает тем же самым пакетом. Меняется при смене координат и не меняется
    от новых находок выгрузки – поэтому решение человека не обесценивается переимпортом с другими номерами."""
    return sha256(canonical([contract, ecosystem, name, version, kind]))[:24]


def new_task_id() -> str:
    """Подпись задания: дата и короткая случайная часть – по такой подписи задание ищется в адресе и ответе."""
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"t-{stamp}-{secrets_hex()}"


def secrets_hex(size: int = 6) -> str:
    """Случайная часть подписи задания в нижнем регистре."""
    return secrets.token_hex((size + 1) // 2)[:size]


def composition(rows: Sequence[Mapping[str, Any]]) -> bytes:
    """Канонические байты состава: по ним отпечаток задания и проверка «состав не изменился»."""
    return canonical([row_text(item) for item in sorted(rows, key=lambda item: item["input_ref"])])


def task_rows(components: Iterable[dict], prefixes: Iterable[str] = (),
              confirmed: Iterable[str] | None = None) -> tuple[list[dict], list[dict]]:
    """Строки задания из пакетов проекта и то, что в задание не попало.

    Отбор тот же, что у прежнего пакета (sca.package_report): внутренние имена и сомнительные координаты без
    подтверждения человека уходят в excluded. К каждой строке добавляются input_ref, вид идентичности, подпись
    пакета и местный охват (число строк выгрузки и число кодовых баз – в комплект они не попадают)."""
    packages, excluded = sca.package_report(components, prefixes, confirmed)
    local = {(str(item.get("ecosystem") or ""), str(item.get("component") or ""),
              str(item.get("version") or "")): item for item in components}
    rows = []
    for package in packages:
        key = (package["ecosystem"], package["component"], package["version"])
        source = local.get(key, {})
        kind = identity_kind(*key[:2])
        rows.append({"input_ref": input_ref(*key), "ecosystem": key[0], "name": key[1], "version": key[2],
                     "identity_kind": kind, "input_sig": input_sig(IDENTITY_CONTRACT, *key, kind),
                     "hub_fix_candidate": package["hub_safe_version"],
                     "vulnerability_ids": public_vulnerability_ids(package.get("vulnerabilities") or []),
                     "finding_count": int(source.get("findings") or 0),
                     "codebase_count": len(source.get("codebases") or [])})
    return rows, excluded


#: поля строки состава: из них строится отпечаток задания и сам комплект
def row_text(item: Mapping[str, Any]) -> dict:
    """Строка состава в виде, который уходит агенту: только публичные поля, и словарь тот же, что у строки ответа
    (component, а не name), чтобы components.json и ответ говорили на одном языке."""
    return {"input_ref": item.get("input_ref", ""), "ecosystem": item.get("ecosystem", ""),
            "component": item.get("name", ""), "version": item.get("version", ""),
            "identity_kind": item.get("identity_kind", ""),
            "hub_fix_candidate": item.get("hub_fix_candidate", ""), "vulnerability_ids": ids_of(item)}


# ------------------------------------------------------------------ файлы комплекта

def manifest(task: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], created_at: str = "") -> dict:
    """Манифест комплекта: контракт, версия и отпечаток валидатора, отпечаток состава, пределы и строки.

    manifest_sha256 – отпечаток состава: агент копирует его в ответ, и сервер сверяет присланное значение с
    сохранённым, а не с тем, что прислал в ответ."""
    return {"contract": CONTRACT, "answer_contract": ANSWER_CONTRACT, "validator_version": VALIDATOR_VERSION,
            "validator_sha256": validator_sha256(), "task_id": task["task_id"], "created_at": created_at,
            "manifest_sha256": task.get("manifest_sha256") or sha256(composition(rows)), "row_count": len(rows),
            "ecosystems": sorted({item["ecosystem"] for item in rows if item.get("ecosystem")}),
            "limits": dict(LIMITS), "freshness": {"as_of": date.today().isoformat(),
                                                  "future_dates_allowed": False,
                                                  "future_tolerance_days": FUTURE_TOLERANCE_DAYS},
            "rows": [{"input_ref": item["input_ref"], "ecosystem": item["ecosystem"], "component": item["name"],
                      "version": item["version"], "identity_kind": item["identity_kind"],
                      "vulnerability_ids": ids_of(item)} for item in rows]}


def components_doc(task: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], created_at: str = "") -> dict:
    """Таблица строк задания – единственное место, где перечислены экосистема, имя, версия и вид идентичности."""
    return {"contract": CONTRACT, "answer_contract": ANSWER_CONTRACT, "task_id": task["task_id"],
            "created_at": created_at, "row_count": len(rows), "rows": [row_text(item) for item in rows]}


def validator_source() -> bytes:
    """Побайтная копия общего валидатора: в комплекте он должен быть тем же файлом, что проверяет приложение."""
    return SOURCE_FILE.read_bytes()


def validator_sha256() -> str:
    return sha256(validator_source())


def task_text(task: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> str:
    """Самодостаточное задание, контракт, протокол источников и самопроверка до передачи оператору."""
    header = (f"# Исследование компонентов программного обеспечения\n\nДата среза: {date.today().isoformat()}. "
              f"Строк в задании: {len(rows)}. Идентификатор задания: {task['task_id']}.\n\n")
    return header + """## Результат и файлы

Исследуйте каждую строку components.json по открытым источникам. Заполните answer.template.json и верните
один полный answer.json по answer.schema.json. manifest.json содержит сохранённый состав и пределы.
validate.py – самодостаточная программа проверки, идентичная серверному валидатору. Код приложения не нужен.
Исходные input_ref, ecosystem, component, current_version должны совпадать с заданием. Не меняйте их после
уточнения namespace. hub_fix_candidate – непроверенный кандидат из исходной выгрузки, а не готовый совет.
vulnerability_ids – публичные идентификаторы (CVE, GHSA, БДУ), которые указал анализатор в исходной выгрузке:
подсказка, с чего начать поиск, а не доказательство применимости. Проверьте каждый по источникам и ищите и другие.
Внутренние номера анализатора (AST-…) не исследуйте, не восстанавливайте и не включайте в ответ.

## Порядок исследования каждой строки

1. Идентичность. Проверьте точную текущую версию в реестре и namespace. Не угадывайте groupId:
   короткое имя Maven разрешается только в groupId:artifactId с тем же artifactId. У npm сохраняйте
   @scope/name; короткие core/common/compiler/devtools могут иметь утраченный scope. Совпадение имени
   первого кандидата не доказывает идентичность. В identity_resolution запишите coordinates, basis
   (основание выбора), note и source_refs; для коротких имён нужен успешный охват purpose=identity.
   При неоднозначности перечислите candidates и конкретную причину в gaps. У такой строки findings пусты,
   latest и target не названы, update/support неизвестны: факты кандидата нельзя приписывать входному пакету.
2. Уязвимости. Запросите точную пару координаты/текущая версия в OSV и изучите официальные advisories,
   GitHub Advisory Database, NVD. Учтите пагинацию, aliases и дубли одной уязвимости. Сохраните применимые
   публичные CVE/GHSA/advisory, диапазоны, fixed_versions, условия, описание и источники. applies=yes/no/unknown
   относится к версии пакета. Эксплуатируемость в конкретном приложении без его кода и конфигурации неизвестна.
   Диапазон introduced включён, fixed исключён, last_affected включён; introduced="0" без fixed и last_affected –
   все версии (исправления нет). Противоречие applies диапазону
   отклоняется; при неизвестном порядке версий нужны applies=unknown и gap APPLICABILITY_UNCLEAR.
3. Релизы. Отдельно найдите latest_stable_release с источником и датой релиза, затем update_status.
   Последний стабильный релиз и минимальное исправление – разные факты. npm dist-tag latest задаёт издатель;
   не выбирайте предварительный релиз только потому, что его номер больше.
4. Поддержка. Проверьте официальную политику текущей ветки: supported/maintenance/eol/deprecated/archived/unknown,
   дату и источник. scope=oss – открытая поддержка, commercial – коммерческая поддержка, unknown – неизвестно.
   Лицензия не доказывает поддержку. Возраст релиза не доказывает EOL. Депрекация не равна концу поддержки.
5. Совет. Заполните package_advice, compatibility_notes и remaining_risks. Для target_version нужны source_refs
   на публикацию этой версии в реестре или официальном релизе; отдельно проверьте её публичные уязвимости
   и опишите охват в пояснении. Обновление может требовать проверки совместимости. Не объявляйте версию
   исправляющей все проблемы, если это не подтверждено. Рекомендация accept_risk – только предложение человеку.
   Принятие риска не отменяет публичную уязвимость. Решение оставить/обновить/заменить/удалить/принять риск
   или исследовать дополнительно оператор сохранит самостоятельно.
6. Проверка версий (схема 2.1). В version_checks проверьте каждую версию из hub_fix_candidate (role=hub) и
   target_version (role=target): какие публичные уязвимости затрагивают именно эту версию. Поля находки – ровно
   id, aliases, ranges, fixed_versions, fix_status, cvss, source_refs (без applies, description, conditions,
   disputed, source_positions); диапазоны не должны исключать проверяемую версию. Охват coverage – как
   research_coverage, где query.version – проверяемая версия. Пустой
   findings при неполном охвате не доказывает, что версия не затронута. Уязвимости других версий не переносите
   в public_findings: там только уязвимости текущей версии.
7. Статус исправления (схема 2.1). У каждой находки fix_status: fixed – есть опубликованная версия с
   исправлением; no_fix_published – исправления нет ни в одной опубликованной версии (scope=package) или в ветке
   цели (scope=branch и branch – префикс версий ветки, например 42.7), только по бюллетеню или трекеру проекта с
   выдержкой quote и датой checked_at; unknown – не установлено. Для fixed и no_fix_published нужны source_refs. Оспоренную уязвимость отметьте disputed (by=vendor, если оспаривает производитель),
   расхождение источников – source_positions (позиция каждого источника о текущей версии). applies остаётся
   вашим выводом и должен соответствовать общим ranges.

## Открытые источники

- OSV: https://api.osv.dev/v1/query ; инструкция https://google.github.io/osv.dev/quickstart/ . Запрос содержит
  package.ecosystem (Maven или npm), package.name (полные координаты) и version. Пустой успешный ответ и ошибка
  HTTP/парсинга/пагинации – разные результаты. Не делайте вывод только по совпадению с одним CVE.
- GitHub Advisory Database: https://github.com/advisories ; NVD: https://nvd.nist.gov/ . Приоритет имеют
  бюллетени разработчика и диапазоны именно нужного артефакта, а не соседнего пакета.
- Maven Central: https://central.sonatype.org/search/rest-api-guide/ ; npm: https://registry.npmjs.org/ .
  Реестр подтверждает координаты и публикацию, но одна проверка реестра не является поиском уязвимостей.
- Официальные release notes и политики поддержки проектов. БДУ ФСТЭК России: https://bdu.fstec.ru/ – банк
  данных уязвимостей с описаниями, затронутыми версиями и ссылками на первоисточники. Это дополнительный
  источник сведений об уязвимостях, а не источник нормативных требований или расшифровки внутренних номеров.

## Протокол поиска и происхождение

Каждая попытка входит в research_coverage. Обязательны source, purpose, query, source_refs, checked_at,
status, complete, note. Цели: identity, vulnerabilities, releases, support. query содержит ecosystem
из задания, разрешённые coordinates и текущую version; это пакет, по которому выполнялось исследование.
При неразрешённой идентичности зафиксируйте attempted query и причины, не изображайте успешный точный запрос.

Пример формы успешной проверки (выдуманные значения заменяются данными исследуемой строки):

```json
{
  "source": "Официальные бюллетени Example Parser",
  "purpose": "vulnerabilities",
  "query": {"ecosystem": "maven", "coordinates": "org.example:example-parser", "version": "1.0.0"},
  "source_refs": ["ev-advisory"],
  "checked_at": "<дата фактической проверки ISO 8601>",
  "status": "ok", "complete": true, "note": "Получен полный результат поиска по пакету и версии"
}
```

ev-advisory должен существовать в evidence той же строки. Для каждого источника укажите настоящий URL,
дату, source_type, краткую quote или содержательную выжимку и justification. Уровень primary/corroborated
описывает утверждение исследователя, а не независимую проверку приложением. URL и цитаты не выдумывайте.
URL и evidence_ref уникальны внутри строки: один источник описывается одной записью evidence,
а её evidence_ref используется в нескольких source_refs. Охват уникален по паре (source, purpose):
один реестр может подтверждать identity и releases. Ссылки только на публичные HTTP(S)-адреса, без
userinfo, частных сетей, IP-адресов и неоднозначной записи домена.
Не ставьте complete=true при ошибке, обрезанном ответе или непроверенных страницах. status=error/partial
требует конкретного note и gap. При удавшемся поиске без находок тоже сохраните evidence самого запроса.
Если часть вопросов осталась открытой, gap объясняет каждый существенный пробел; «AST неизвестен» не пробел.
Нетронутая заготовка и ответ без протокола попыток не считаются выполненным исследованием.

## Независимые состояния

- Применимая публичная находка → vulnerable, даже если другой источник недоступен.
- Неизвестная применимость → incomplete. Неразрешённая идентичность → identity_unresolved.
- Полный успешный поиск уязвимостей без применимых находок → no_known_vulnerabilities в указанном охвате.
- Ошибки поиска уязвимостей → incomplete, а не «уязвимостей не найдено».
- Сбой поиска релизов или поддержки не отменяет успешный результат по уязвимостям: эти пробелы показываются отдельно.

Окончание поддержки (EOL) само по себе не является уязвимостью. Отсутствие публичного исправления не отменяет
уязвимость. Не обещайте, что последний релиз полностью безопасен: сведения относятся к дате проверки.
update_available допустим только при подтверждённо более новом релизе, up_to_date – при равенстве версий.
Валидатор сравнивает npm/cargo SemVer, PEP 440, числовые NuGet/Composer, RubyGems и числовые версии Maven
с обычными alpha/beta/milestone/rc/snapshot/final/ga/release/sp. Неизвестные формы не сортируются наугад:
update_available и совет update с источниками принимаются с заметной пометкой «порядок версий не проверен
приложением». Объясните основание совета и неопределённость в note/gap, не скрывайте её ради успешной проверки.

## Самопроверка до передачи оператору

```text
python validate.py --manifest manifest.json --answer answer.json --report report.json
```

0 – контракт выполнен; 2 – ошибки полей; 3 – техническая ошибка проверки. При 2 исправьте все перечисленные
нарушения и повторите проверку самостоятельно. Не выдавайте неправильный файл за готовый. Не заменяйте
содержательную неопределённость выдумкой. При технической невозможности закончить честно сообщите сбой,
вместо бесконечных повторов или заполнения всех строк формальным «неясно» без исследования.
Пределы опубликованы в manifest/schema; строки, находки и источники не обрезайте молча.
После успешной самопроверки верните только answer.json, без пересказа работы и без правки входных полей.
"""


def kit(task: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], created_at: str = "") -> bytes:
    """Комплект задания одним архивом: задание, манифест, таблица строк, заготовка, схема и валидатор."""
    created_at = created_at or datetime.now(UTC).isoformat(timespec="seconds")
    files = [("task.md", task_text(task, rows).encode("utf-8")),
             ("manifest.json", canonical(manifest(task, rows, created_at))),
             ("components.json", canonical(components_doc(task, rows, created_at))),
             ("answer.template.json", canonical(answer_template(task, rows))),
             ("answer.schema.json", canonical(schema_doc())),
             ("validate.py", validator_source())]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))  # время из содержимого не следует
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, body)
    return buffer.getvalue()


def schema_doc() -> dict:
    """Схема ответа из общего описания полей (app.sca_contract.schema)."""
    return schema()


# ------------------------------------------------------------------ проверка ответа

def check_answer(text: bytes | str, task: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> Any:
    """Проверка ответа по сохранённому заданию: тот же валидатор, что у агента в комплекте. Отпечаток состава
    сверяется с сохранённым на сервере, а не с присланным в ответе."""
    return validate_answer(text, {"task_id": task["task_id"],
                                  "manifest_sha256": task.get("manifest_sha256", ""),
                                  "row_count": len(rows), "rows": [row_text(item) for item in rows]})


#: поля ответа, которые меняются от повторной проверки того же источника и ничего по сути не говорят.
#: Они не входят в подпись содержания: перечитывание источников в другой день не должно требовать нового
#: решения человека.
VOLATILE_FIELDS = ("checked_at", "as_of")


def content_sig(row: Mapping[str, Any]) -> str:
    """Подпись содержания ответа по строке: по ней решение устаревает. Даты обращения к источникам в неё не
    входят – их обновление не меняет фактов, а любое другое изменение (находки, условия применения, охват,
    цитаты, поддержка, релиз) меняет."""
    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: strip(item) for key, item in value.items() if key not in VOLATILE_FIELDS}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return sha256(canonical(strip(row)))


def research_results(answer: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> list[dict]:
    """Разобранный и принятый ответ в виде строк для сохранения: одна запись на строку задания."""
    known = {item["input_ref"]: item for item in rows}
    results = []
    for item in answer.get("rows", []):
        if not isinstance(item, dict):
            continue
        source = known.get(item.get("input_ref", ""))
        if source is None:
            continue
        findings = [entry for entry in item.get("public_findings") or [] if isinstance(entry, dict)]
        coverage = [entry for entry in item.get("research_coverage") or [] if isinstance(entry, dict)]
        results.append({"input_ref": item["input_ref"], "input_sig": source["input_sig"],
                        "answer_sig": content_sig(item), "status": item.get("package_status", ""),
                        "coverage_checked": len(coverage),
                        "coverage_errors": sum(1 for entry in coverage if entry.get("status") != "ok"
                                               or not entry.get("complete")),
                        "findings_total": len(findings),
                        "applicable": sum(1 for entry in findings if entry.get("applies") == "yes"),
                        "gaps_count": len(item.get("gaps") or []),
                        "evidence_count": len(item.get("evidence") or []), "payload": item,
                        # объявленная схема ответа (ADR-0094 Р2.6) – отдельно от версии проверки сервера
                        "answer_schema": str(answer.get("validator_version") or "")})
    return results


# ------------------------------------------------------------------ представления

def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def status_note(payload: Mapping[str, Any], status: str) -> str:
    """Почему строка получила такое состояние: вывод считает программа, пояснение читает человек."""
    if not payload:
        return ""
    if status == "identity_unresolved":
        note = _text(_obj(payload.get("identity_resolution")).get("note"))
        return note or "идентичность пакета не подтверждена источником"
    coverage = _items(payload.get("research_coverage"))
    failed = sum(1 for item in coverage if _obj(item).get("status") != "ok" or not _obj(item).get("complete"))
    if status == "vulnerable":
        applicable = sum(1 for item in _items(payload.get("public_findings"))
                         if _obj(item).get("applies") == "yes")
        tail = f", охват неполный: источников с ошибкой {failed}" if failed else ""
        return f"применимых уязвимостей: {applicable}{tail}"
    if status == "incomplete":
        parts = []
        if not coverage:
            parts.append("источники не проверялись")
        elif failed:
            parts.append(f"источников с ошибкой или неполным ответом: {failed}")
        if not _text(_obj(payload.get("latest_stable_release")).get("version")):
            parts.append("последний релиз неизвестен")
        if _text(payload.get("update_status")) not in ("up_to_date", "update_available"):
            parts.append("неизвестно, есть ли обновление")
        return "; ".join(parts) or "исследование неполное"
    if status == "no_known_vulnerabilities":
        return f"проверенных источников: {len(coverage)}, применимых уязвимостей не найдено"
    return ""


def review_due(value: Any) -> bool:
    """Наступила ли дата пересмотра решения (сегодня или раньше). Один разбор для карточки, списка и счётчиков обзора;
    некорректное значение – не наступила (и не скрывает остальные причины пересмотра)."""
    text = _text(value)
    if not text:
        return False
    try:
        return date.fromisoformat(text) <= date.today()
    except ValueError:
        return False


def row_view(source: Mapping[str, Any], research: Mapping[str, Any] | None,
             decision: Mapping[str, Any] | None, task_state: str) -> dict:
    """Строка списка и карточки одним словарём: состав строки плюс принятые факты и решение человека."""
    payload = _obj(_obj(research).get("payload"))
    status = _text(payload.get("package_status"))
    findings = [_obj(item) for item in _items(payload.get("public_findings"))]
    coverage = [_obj(item) for item in _items(payload.get("research_coverage"))]
    advice = _obj(payload.get("package_advice"))
    support = _obj(payload.get("support_status"))
    latest = _obj(payload.get("latest_stable_release"))
    identity = _obj(payload.get("identity_resolution"))
    reasons = []
    if decision and research and _text(decision.get("research_sig")) != _obj(research).get("answer_sig", ""):
        reasons.append("research_changed")
    # Календарная дата приложения; она показана рядом с полем срока, без зависимости от открытого браузера.
    if review_due(_obj(decision).get("review_at")):
        reasons.append("review_date")
    evidence = {item.get("evidence_ref"): item for item in (_obj(x) for x in _items(payload.get("evidence")))
                if _text(item.get("evidence_ref"))}
    view = {
        "version_order_unchecked": bool(research) and any(
            _text(value) and contract.compare_versions(_text(source.get('ecosystem')), _text(value), _text(source.get('version'))) is None
            for value in (latest.get('version'), advice.get('target_version'))),
        "prior_validation_rules": bool(research) and _obj(research).get('validation_rules', 'sca-contract/2.0.1') != VALIDATOR_VERSION,
        "input_ref": source.get("input_ref", ""), "ecosystem": source.get("ecosystem", ""),
        "name": source.get("name", ""), "version": source.get("version", ""),
        "identity_kind": source.get("identity_kind", ""),
        "identity_kind_label": IDENTITY_KIND_LABELS.get(source.get("identity_kind", ""), "неизвестно"),
        "input_sig": source.get("input_sig", ""), "task_id": source.get("task_id", ""),
        "task_state": task_state, "task_current": task_state == "current", "task_stale": task_state != "current",
        "hub_fix_candidate": source.get("hub_fix_candidate", ""),
        "finding_count": int(source.get("finding_count") or 0),
        "codebase_count": int(source.get("codebase_count") or 0),
        "status": status, "status_label": STATUS_LABELS.get(status, STATUS_LABELS[""]),
        "status_note": status_note(payload, status),
        "researched": bool(research), "revision": int(_obj(research).get("revision") or 0),
        "answer_sig": _obj(research).get("answer_sig", ""),
        "coverage": {"checked": len(coverage),
                     "ok": sum(1 for item in coverage if item.get("status") == "ok" and item.get("complete")),
                     "errors": sum(1 for item in coverage if item.get("status") != "ok"
                                   or not item.get("complete")),
                     "complete": bool(coverage) and all(item.get("status") == "ok" and item.get("complete")
                                                        for item in coverage)},
        "findings_total": len(findings),
        "applicable": sum(1 for item in findings if item.get("applies") == "yes"),
        "latest_stable": _text(latest.get("version")),
        "update_status": _text(payload.get("update_status")),
        "support_state": _text(support.get("state")), "support_scope": _text(support.get("scope")),
        "advice": _text(advice.get("action")), "advice_target": _text(advice.get("target_version")),
        "gaps": len(_items(payload.get("gaps"))), "evidence": len(evidence),
        "identity": {**identity, "state_label": IDENTITY_LABELS.get(_text(identity.get("state")), "")},
        "latest": latest, "support": support, "advice_detail": {**advice,
                                                                "action_label": ADVICE_LABELS.get(
                                                                    _text(advice.get("action")), "")},
        "update_label": UPDATE_LABELS.get(_text(payload.get("update_status")), ""),
        "support_label": SUPPORT_LABELS.get(_text(support.get("state")), ""),
        "scope_label": SCOPE_LABELS.get(_text(support.get("scope")), ""),
        "findings": [_finding_view(item, evidence) for item in findings],
        "coverage_items": [{**item, "status_label": COVERAGE_LABELS.get(_text(item.get("status")), "")}
                           for item in coverage],
        "gaps_items": [{**item, "code_label": GAP_LABELS.get(_text(item.get("code")), "")}
                       for item in _items(payload.get("gaps"))],
        "evidence_items": [_evidence_view(item) for item in evidence.values()],
        "imported_at": _obj(research).get("imported_at", ""),
        # ADR-0096 п. 8: когда агент последний раз подтвердил сведения (повторная проверка обновляет observed_at)
        "fresh_at": _text(_obj(research).get("observed_at")) or _text(_obj(research).get("imported_at")),
        # ADR-0096 п. 2: поиск по идентификаторам публичных находок и подтверждённым координатам
        "search_ids": sorted({_text(value).casefold() for item in findings
                              for value in (item.get("id"), *_items(item.get("aliases"))) if _text(value)}),
        # только подтверждённые координаты (identity_resolution.state = resolved) – п. 2 ADR-0096
        "coordinates": _text(identity.get("coordinates")) if _text(identity.get("state")) == "resolved" else "",
        # ADR-0096 п. 3: оспоренная применимая находка балл не теряет, строка помечается
        "disputed": any(_text(item.get("applies")) == "yes" and isinstance(item.get("disputed"), Mapping)
                        and item.get("disputed") for item in findings),
        "validator_version": _obj(research).get("validation_rules", 'sca-contract/2.0.1'),
        "decision": decision_view(decision) if decision else None,
        "decision_stale": bool(reasons), "decision_reasons": reasons,
        "decided": bool(decision),
    }
    return view


def _finding_view(item: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]]) -> dict:
    sources = []
    for ref in _items(item.get("source_refs")):
        found = evidence.get(ref)
        if found:
            sources.append(_evidence_view(found))
    return {**item, "applies_label": APPLIES_LABELS.get(_text(item.get("applies")), ""), "sources": sources}


def _evidence_view(item: Mapping[str, Any]) -> dict:
    url = _text(item.get('url'))
    return {**item, 'url': url if contract.public_url_parts(url) is not None else '', "source_type_label": EVIDENCE_LABELS.get(_text(item.get("source_type")), ""),
            "level_label": LEVEL_LABELS.get(_text(item.get("level")), "")}


def decision_view(row: Mapping[str, Any] | None) -> dict | None:
    """Решение человека с подписями для интерфейса."""
    if not row:
        return None
    return {**row, **decision_values(row), "action_label": DECISION_LABELS.get(_text(row.get("action")), _text(row.get("action"))),
            "state_label": "" if _text(row.get("state")) == "current" else "прежнее решение"}


DEFECT_FILTERS = ("in", "none")  # отбор «Дефект»: компонент входит в дефект приложения / не входит


def summaries(rows: Iterable[Mapping[str, Any]]) -> dict:
    """Счётчики для шапки и отчёта: состояния, решения и устаревшие решения; отдельно (OR-07) – исследованные с
    пробелами и с неизвестной поддержкой: они не меняют состояние строки («уязвим» остаётся «уязвим»)."""
    rows = list(rows)
    result = {"total": len(rows)}
    for status in ("vulnerable", "no_known_vulnerabilities", "incomplete", "identity_unresolved"):
        result[status] = sum(1 for item in rows if item["status"] == status)
    result["unresearched"] = sum(1 for item in rows if not item["researched"])
    result["decided"] = sum(1 for item in rows if item["decided"])
    result["stale"] = sum(1 for item in rows if item["decision_stale"])
    result["with_gaps"] = sum(1 for item in rows if item["researched"] and int(item.get("gaps") or 0) > 0)
    result["support_unknown"] = sum(1 for item in rows if item["researched"]
                                    and _text(item.get("support_state")) in ("", "unknown"))
    result["in_defect"] = sum(1 for item in rows if item.get("in_defect"))
    return result


def filter_rows(rows: Sequence[dict], filters: Mapping[str, Any]) -> list[dict]:
    """Отбор строк по фильтрам адреса: состояние, решение, устаревшее решение, экосистема и поиск по имени."""
    status = _text(filters.get("status"))
    decision = _text(filters.get("decision"))
    stale = _text(filters.get("stale")) == "1"
    ecosystem = _text(filters.get("ecosystem"))
    needle = _text(filters.get("q")).casefold()
    spec = score_filter(filters)
    support = _text(filters.get("support")) if _text(filters.get("support")) in SUPPORT_FILTERS else ""
    advice = _text(filters.get("advice")) if _text(filters.get("advice")) in contract.ADVICE_ACTIONS else ""
    action = _text(filters.get("action")) if _text(filters.get("action")) in ACTION_FILTERS else ""
    review_due = _text(filters.get("review_due")) == "1"
    age = int(_text(filters.get("age"))) if _text(filters.get("age")) in AGE_FILTERS else 0
    gaps = _text(filters.get("gaps")) == "1"
    defect = _text(filters.get("defect")) if _text(filters.get("defect")) in DEFECT_FILTERS else ""
    result = []
    for item in rows:
        if defect == "in" and not item.get("in_defect"):
            continue
        if defect == "none" and item.get("in_defect"):
            continue
        if spec["active"] and not _score_fits(item, spec):
            continue
        # у неисследованной строки поддержки, совета и свежести нет – в эти отборы она не входит (ADR-0096 п. 7)
        if (support or advice or age or gaps) and not item["researched"]:
            continue
        if support and (_text(item.get("support_state")) or "unknown") != support:
            continue
        if advice and _text(item.get("advice")) != advice:
            continue
        if gaps and not int(item.get("gaps") or 0):
            continue
        if age and not _older_than(item.get("fresh_at", ""), age):
            continue
        current = _text(_obj(item.get("decision")).get("action"))
        if action == "none" and current:
            continue
        if action and action != "none" and current != action:
            continue
        if review_due and "review_date" not in (item.get("decision_reasons") or []):
            continue
        if status == "unresearched":
            if item["researched"]:
                continue
        elif status and item["status"] != status:
            continue
        if decision == "set" and not item["decided"]:
            continue
        if decision == "unset" and item["decided"]:
            continue
        if stale and not item["decision_stale"]:
            continue
        if ecosystem and item["ecosystem"] != ecosystem:
            continue
        if needle and needle not in item["name"].casefold() and needle not in item["version"].casefold() \
                and not any(needle in value for value in item.get("search_ids") or []) \
                and needle not in _text(item.get("coordinates")).casefold():
            continue
        result.append(item)
    return result


def cvss_version(value: Any) -> str:
    """Версия шкалы CVSS из ответа агента: «3.1», «CVSS:3.1», «v3.1» – одна версия; пустое и иное – "" (не указана)."""
    text = _text(value).casefold().strip()
    text = text[5:] if text.startswith("cvss:") else text
    text = text[1:] if text.startswith("v") else text
    return text if text in CVSS_VERSIONS else ""


def row_score(row: Mapping[str, Any], version: str = "") -> dict:
    """Балл CVSS строки по выводу агента (ADR-0096 пп. 3–6): наибольший cvss.score среди находок с applies = yes
    выбранной версии шкалы ("" – любая, включая «версия не указана»); оспоренность балл не убирает. Без балла –
    kind из SCORE_KINDS; incomplete – балл есть, но у части применимых находок балла этой версии нет."""
    if not row.get("researched"):
        return {"kind": "unresearched", "score": None, "incomplete": False}
    found = [_obj(item) for item in row.get("findings") or []]
    applicable = [item for item in found if _text(item.get("applies")) == "yes"]
    if not applicable:
        unknown = any(_text(item.get("applies")) == "unknown" for item in found)
        return {"kind": "applies_unknown" if unknown else "none_applicable", "score": None, "incomplete": False}
    scores = []
    for item in applicable:
        cvss = _obj(item.get("cvss"))
        value = cvss.get("score")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if version and cvss_version(cvss.get("version")) != version:
            continue
        scores.append(float(value))
    if not scores:
        return {"kind": "score_unknown", "score": None, "incomplete": False}
    return {"kind": "", "score": max(scores), "incomplete": len(scores) < len(applicable)}


_BOUND = re.compile(r"(?:10(?:[.,]0)?|[0-9](?:[.,][0-9])?)")


def _bound(value: Any) -> float | None:
    """Граница отбора CVSS: число от 0 до 10 с одним знаком после запятой («7», «7.5», «7,5», «10») или None. Иное
    значение (7.05, -0.04, 11) негодно целиком и не округляется: показанный порог – ровно применённый."""
    text = _text(value).strip()
    if not _BOUND.fullmatch(text):
        return None
    return float(text.replace(",", "."))


def score_filter(filters: Mapping[str, Any]) -> dict:
    """Параметры отбора CVSS (ADR-0096 п. 5): версия, нижняя граница с «≥»/«>», верхняя «≤», вид строки без балла;
    empty – «от» больше «до»: выборка пуста с пояснением."""
    version = _text(filters.get("cvss_ver")) if _text(filters.get("cvss_ver")) in CVSS_VERSIONS else ""
    low, high = _bound(filters.get("cvss_from")), _bound(filters.get("cvss_to"))
    strict = _text(filters.get("cvss_op")) == "gt"
    kind = _text(filters.get("score")) if _text(filters.get("score")) in SCORE_KINDS else ""
    return {"version": version, "low": low, "high": high, "strict": strict, "kind": kind,
            # выбор версии шкалы – уже отбор: строки без балла этой версии в него не входят (ADR-0096 пп. 4, 6)
            "active": low is not None or high is not None or bool(kind) or bool(version),
            "empty": low is not None and high is not None and low > high}


def _score_fits(row: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    if spec["empty"]:  # «от» больше «до» – пусто при любых остальных параметрах (п. 5)
        return False
    got = row_score(row, spec["version"])
    if spec["kind"]:
        return got["kind"] == spec["kind"]
    if got["score"] is None:
        return False
    if spec["low"] is not None and (got["score"] <= spec["low"] if spec["strict"] else got["score"] < spec["low"]):
        return False
    return spec["high"] is None or got["score"] <= spec["high"]


def _older_than(value: str, days: int) -> bool:
    try:
        seen = date.fromisoformat(_text(value)[:10])
    except ValueError:
        return False
    return (date.today() - seen).days > days


def sort_rows(rows: Sequence[dict]) -> list[dict]:
    """Порядок списка: сначала те, где есть решение человека, потом состояние, затем имя пакета."""
    rank = {"vulnerable": 0, "identity_unresolved": 1, "incomplete": 2, "no_known_vulnerabilities": 3, "": 4}
    return sorted(rows, key=lambda item: (not item["decided"], rank.get(item["status"], 5),
                                          item["ecosystem"], item["name"].casefold(), item["version"]))


# ------------------------------------------------------------------ решение человека

def decision_values(data: Mapping[str, Any]) -> dict:
    """Применимые поля решения. Исходная форма и историческая запись не изменяются."""
    action = _text(data.get("action"))
    return {"target_version": _text(data.get("target_version")) if action == "update" else "",
            "replacement_name": _text(data.get("replacement_name")) if action == "replace" else "",
            "replacement_version": _text(data.get("replacement_version")) if action == "replace" else ""}


def decision_form(data: Mapping[str, Any], revision: int, *, input_sig: str = "", research_sig: str = "",
                  research_revision: int = 0) -> dict:
    """Значения формы решения: при отказе вернутся введёнными, чтобы человек их не набирал заново.

    Кроме полей решения форма несёт отпечатки того, что человек видел: строку задания и ревизию
    исследования. По ним сервер понимает, что форма посмотрена на устаревшем ответе, и не привязывает решение
    молча к новому."""
    return {"action": _text(data.get("action")), "rationale": _text(data.get("rationale")),
            "target_version": _text(data.get("target_version")),
            "replacement_name": _text(data.get("replacement_name")),
            "replacement_version": _text(data.get("replacement_version")),
            "review_at": _text(data.get("review_at")), "revision": int(revision),
            "expected_input_sig": _text(data.get("expected_input_sig")) or input_sig,
            "expected_research_sig": _text(data.get("expected_research_sig")) or research_sig,
            "expected_research_revision": _integer(data.get("expected_research_revision"), 0)
            or int(research_revision)}


# совет исследования → действие оператора для черновика (вариант Б); без совета – «исследовать
# позже»: черновик не выбирает за человека «оставить»
ADVICE_DECISION = {"update": "update", "replace": "replace", "keep": "keep", "remove": "remove",
                   "accept_risk": "accept_risk", "no_action": "keep", "needs_identity": "investigate",
                   "insufficient_data": "investigate"}
REVIEW_PRESETS = (30, 90, 180)  # быстрый срок пересмотра, дней от даты приложения (вариант А)
DRAFT_REVIEW_DAYS = 90  # срок пересмотра в черновике для «риск принят» и «исследовать позже»
DRAFT_IDS = 5  # уязвимостей в черновике поимённо, остальные – числом


def iso_date(value: Any) -> bool:
    """Значение – дата ГГГГ-ММ-ДД (то, что принимает поле type=date браузера)."""
    try:
        date.fromisoformat(_text(value))
    except ValueError:
        return False
    return len(_text(value)) == 10


def review_presets(today: date) -> list[tuple[int, str]]:
    """Даты быстрого срока пересмотра: (дней, ГГГГ-ММ-ДД) от даты приложения."""
    return [(days, (today + timedelta(days=days)).isoformat()) for days in REVIEW_PRESETS]


def decision_draft(view: Mapping[str, Any], today: date) -> dict:
    """Черновик решения по фактам исследования (row_view) для кнопки «Заполнить по исследованию»: действие по совету,
    целевая версия совета, обоснование из применимых уязвимостей, совета, релиза, поддержки, остаточных рисков и
    пробелов; срок пересмотра – через DRAFT_REVIEW_DAYS для «риск принят» и «исследовать позже». Ничего не решает
    сам: форма заполняет только пустые поля, человек проверяет и сохраняет. Исследования нет – {}."""
    if not view.get("researched"):
        return {}
    advice = _obj(view.get("advice_detail"))
    action = ADVICE_DECISION.get(_text(advice.get("action")), "investigate")
    version = _text(view.get("version"))
    findings = [_obj(item) for item in _items(view.get("findings"))]

    def named(items: list[dict]) -> str:
        ids = [_text(item.get("id")) for item in items if _text(item.get("id"))]
        return ", ".join(ids[:DRAFT_IDS]) + (f" и ещё {len(ids) - DRAFT_IDS}" if len(ids) > DRAFT_IDS else "")
    applies = [item for item in findings if item.get("applies") == "yes"]
    unclear = [item for item in findings if item.get("applies") == "unknown"]
    when = _text(view.get("fresh_at"))[:10]
    parts = [f"По исследованию компонента ({'от ' + when + ', ' if when else ''}ревизия {int(view.get('revision') or 0)})."]
    if applies:
        parts.append(f"К версии {version} применимы уязвимости ({len(applies)} из {len(findings)}): {named(applies)}.")
    elif findings:
        parts.append(f"Применимых к версии {version} уязвимостей не найдено (проверено {len(findings)}).")
    else:
        parts.append(f"Публичных уязвимостей версии {version} не найдено.")
    if unclear:
        parts.append(f"Применимость не установлена: {named(unclear)}.")
    label = ADVICE_LABELS.get(_text(advice.get("action")), "")
    target = _text(advice.get("target_version"))
    if label:
        parts.append(f"Совет исследования: {label}" + (f" до {target}" if target and action == "update" else "") + ".")
    if _text(view.get("latest_stable")):
        parts.append(f"Последний стабильный релиз – {_text(view.get('latest_stable'))}.")
    if _text(view.get("support_label")) and _text(view.get("support_state")) != "unknown":
        parts.append(f"Поддержка: {_text(view.get('support_label'))}.")
    if _text(advice.get("compatibility_notes")):
        note = _text(advice.get("compatibility_notes"))
        parts.append(f"Совместимость: {note}" + ("" if note.endswith((".", "!", "?", "…")) else "."))
    risks = [_text(x) for x in _items(advice.get("remaining_risks")) if _text(x)]
    if risks:
        parts.append("Остаточные риски: " + "; ".join(risks) + ".")
    gaps = list(dict.fromkeys(_text(_obj(g).get("code_label")) for g in _items(view.get("gaps_items"))
                              if _text(_obj(g).get("code_label"))))
    if gaps:
        parts.append("Пробелы исследования: " + ", ".join(gaps) + ".")
    rationale = " ".join(parts)
    if len(rationale) > RATIONALE_CHARS:
        rationale = rationale[:RATIONALE_CHARS - 1].rstrip() + "…"
    return {"action": action, "rationale": rationale,
            "target_version": target if action == "update" else "",
            "review_at": ((today + timedelta(days=DRAFT_REVIEW_DAYS)).isoformat()
                          if action in ("accept_risk", "investigate") else "")}


def batch_decision_draft(views: list, today: date) -> dict:
    """Черновик общего решения по нескольким версиям одного компонента (страница «Решение по выбранным версиям»):
    действие и целевая версия – только если совет у всех версий один, иначе пусто с пояснением (note); обоснование –
    черновики версий подряд, каждый с номером версии; срок пересмотра – ближайший из черновиков. Версии без
    исследования пропускаются; нет ни одного исследования – {}."""
    drafts = [(_text(v.get("version")), decision_draft(v, today)) for v in views]
    drafts = [(version, d) for version, d in drafts if d]
    if not drafts:
        return {}
    actions = {d["action"] for _, d in drafts}
    targets = {d["target_version"] for _, d in drafts}
    same = len(actions) == 1
    if len(drafts) == 1:
        rationale = drafts[0][1]["rationale"]
    else:
        rationale = " ".join(f"Версия {version}: {d['rationale']}" for version, d in drafts)
        if len(rationale) > RATIONALE_CHARS:
            rationale = rationale[:RATIONALE_CHARS - 1].rstrip() + "…"
    review = sorted(d["review_at"] for _, d in drafts if d["review_at"])
    note = ""
    if not same:
        labels = ", ".join(f"{version} – {LABELS['decision'].get(d['action'], d['action'])}" for version, d in drafts)
        note = f"Совет исследования у версий разный ({labels}): действие и целевую версию выберите сами."
    elif len(targets) > 1:
        note = "Целевая версия в советах разная: укажите её сами."
    return {"action": next(iter(actions)) if same else "", "rationale": rationale,
            "target_version": next(iter(targets)) if same and len(targets) == 1 else "",
            "review_at": review[0] if review else "", "note": note,
            "skipped": len(views) - len(drafts)}


def _integer(value: Any, fallback: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return fallback


def check_decision(form: Mapping[str, Any]) -> str:
    """Проверка решения человека. Пустая строка – решение можно сохранять; иначе текст ошибки по-русски.

    Решение не меняет факты ответа агента: ни уязвимости, ни применимость, ни охват. «Риск принят» ничего не
    отменяет, а «исследовать позже» не значит, что уязвимости нет."""
    return decision_problem(form)[1]


def decision_problem(form: Mapping[str, Any]) -> tuple[str, str]:
    """Имя ошибочного поля и конкретная подсказка; пустая пара означает корректную форму."""
    form = {**form, **decision_values(form)}
    action = _text(form.get("action"))
    if action not in DECISIONS:
        return "action", "Выберите, что делать с компонентом."
    rationale = _text(form.get("rationale"))
    if not rationale:
        return "rationale", "Напишите причину решения: по ней видно, на чём оно основано."
    if len(rationale) > RATIONALE_CHARS:
        return "rationale", f"Причина решения длиннее {RATIONALE_CHARS} знаков."
    for field in DECISION_NEEDS.get(action, ()):  # бессмысленное решение не сохраняем
        if not _text(form.get(field)):
            names = {"target_version": "версию, на которую переходим",
                     "replacement_name": "имя заменяющего пакета",
                     "replacement_version": "версию заменяющего пакета"}
            return field, f"Для действия «{DECISION_LABELS[action]}» укажите {names.get(field, field)}."
    for field in ("target_version", "replacement_version"):
        value = _text(form.get(field))
        if value and len(value) > VERSION_CHARS:
            return field, f"Значение слишком длинное ({len(value)} знаков при пределе {VERSION_CHARS})."
    review = _text(form.get("review_at"))
    if review:
        try:
            date.fromisoformat(review)
        except ValueError:
            return "review_at", "Дата пересмотра должна быть в формате ГГГГ-ММ-ДД."
    return "", ""


# ------------------------------------------------------------------ отчёты

def report(*, project: Mapping[str, Any], task: Mapping[str, Any] | None, rows: Sequence[dict],
           generated_at: str = "", archive: Sequence[Mapping[str, Any]] = ()) -> dict:
    """Отчёт для сохранения: публичные факты по строкам и решение человека. Без номеров находок выгрузки,
    названий кодовых баз, путей и внутренних номеров соответствий."""
    researched = [item for item in rows if item["researched"]]
    document = {"contract": "local-triage/sca-report/2", "generated_at": generated_at or _now(),
            "project": {"id": project.get("id", 0), "name": project.get("name", "")},
            "scope": {"rows": len(rows), "researched": len(researched),
                      "ecosystems": sorted({item["ecosystem"] for item in rows if item["ecosystem"]}),
                      "task_id": (task or {}).get("task_id", ""),
                      "manifest_sha256": (task or {}).get("manifest_sha256", ""),
                      "task_state": (task or {}).get("state", ""),
                      "imported_at": (task or {}).get("imported_at", "")},
            "summary": summaries(researched), "components": [_report_row(item) for item in researched]}
    if archive:
        # исследования и решения, снятые переходом идентичности пакетов (план dev17, п. 4.6): только факт снятия,
        # без содержимого ответа – оно относилось к прежней тройке
        document["identity_archive"] = [
            {"input_ref": a["input_ref"], "table": a["table"], "revision": (a.get("row") or {}).get("revision"),
             "archived_at": a["archived_at"], "reason": a["reason"], "moved_to_ref": a["moved_to_ref"]}
            for a in archive]
    return document


def _report_row(item: Mapping[str, Any]) -> dict:
    return {
        "input_ref": item["input_ref"], "ecosystem": item["ecosystem"], "name": item["name"],
        "version": item["version"], "identity_kind": item["identity_kind"], "task_state": item["task_state"],
        "researched": item["researched"], "revision": item["revision"], "status": item["status"],
        "status_label": item["status_label"], "status_note": item["status_note"],
        "identity": {"state": _text(item["identity"].get("state")),
                     "coordinates": _text(item["identity"].get("coordinates")),
                     "candidates": list(_items(item["identity"].get("candidates"))),
                     "note": _text(item["identity"].get("note"))},
        "latest_stable_release": {"version": item["latest_stable"],
                                  "released_at": _text(item["latest"].get("released_at")),
                                  "note": _text(item["latest"].get("note"))},
        "update_status": item["update_status"],
        "support_status": {"state": item["support_state"], "scope": item["support_scope"],
                           "as_of": _text(item["support"].get("as_of")),
                           "note": _text(item["support"].get("note"))},
        "public_findings": [{"id": entry.get("id", ""), "aliases": list(entry.get("aliases") or []),
                             "applies": entry.get("applies", ""), "description": entry.get("description", ""),
                             "conditions": _text(entry.get("conditions")),
                             "fixed_versions": list(entry.get("fixed_versions") or []),
                             "ranges": list(entry.get("ranges") or []), "cvss": entry.get("cvss"),
                             "sources": [{"url": source.get("url", ""),
                                          "source_type": source.get("source_type", ""),
                                          "level": source.get("level", ""),
                                          "checked_at": source.get("checked_at", ""),
                                          "justification": source.get("justification", ""),
                                          "quote": _text(source.get("quote"))} for source in entry["sources"]]}
                            for entry in item["findings"]],
        "research_coverage": [{key: entry.get(key, "") for key in ("source", "checked_at", "status", "complete",
                                                                   "note")} for entry in item["coverage_items"]],
        "gaps": [{key: entry.get(key, "") for key in ("code", "text")} for entry in item["gaps_items"]],
        "advice": {"action": item["advice"], "action_label": item["advice_detail"]["action_label"],
                   "target_version": item["advice_target"],
                   "compatibility_notes": _text(item["advice_detail"].get("compatibility_notes")),
                   "remaining_risks": list(item["advice_detail"].get("remaining_risks") or [])},
        "evidence": [{key: entry.get(key, "") for key in ("evidence_ref", "url", "source_type", "level",
                                                          "checked_at", "justification", "quote")}
                     for entry in item["evidence_items"]],
        "decision": ({key: item["decision"].get(key, "") for key in
                      ("action", "rationale", "target_version", "replacement_name", "replacement_version",
                       "review_at", "decided_at", "revision", "state")}
                     if item["decision"] else None),
        "decision_stale": item["decision_stale"],
    }


def report_text(document: Mapping[str, Any]) -> str:
    """Тот же отчёт текстом для сохранения в файл человеком."""
    project = document["project"]
    scope = document["scope"]
    summary = document["summary"]
    lines = [f"Исследование компонентов SCA: {project['name']}",
             f"Отчёт от {document['generated_at']}, строк в отчёте: {len(document['components'])}, "
             f"исследовано: {scope['researched']}",
             f"Задание: {scope['task_id'] or 'нет'} ({scope['task_state'] or 'нет'}), "
             f"отпечаток состава: {scope['manifest_sha256'] or 'нет'}",
             f"Состояния: уязвим {summary['vulnerable']}, уязвимостей не найдено "
             f"{summary['no_known_vulnerabilities']}, неполно {summary['incomplete']}, "
             f"идентичность не подтверждена {summary['identity_unresolved']}",
             "", "Состав:", ""]
    for index, item in enumerate(document["components"], 1):
        lines += [f"{index}. {item['ecosystem']} {item['name']} {item['version']}",
                  f"   Состояние: {item['status_label']}" + (f" ({item['status_note']})" if item["status_note"] else ""),
                  f"   Идентичность: {item['identity']['state'] or 'не определялась'}"
                  + (f", {item['identity']['coordinates']}" if item["identity"]["coordinates"] else "")
                  + (f", кандидаты: {', '.join(item['identity']['candidates'])}"
                     if item["identity"]["candidates"] else ""),
                  f"   Последний релиз: {item['latest_stable_release']['version'] or 'неизвестен'}"
                  + (f" ({item['latest_stable_release']['released_at']})" if item["latest_stable_release"]["released_at"] else ""),
                  f"   Обновление: {item['update_status'] or 'неизвестно'}; поддержка: "
                  f"{item['support_status']['state'] or 'неизвестно'} ({item['support_status']['scope'] or 'неизвестно'})"
                  + (f"; на {item['support_status']['as_of']}" if item["support_status"]["as_of"] else ""),
                  f"   Находки: {len(item['public_findings'])}, применимых "
                  f"{sum(1 for entry in item['public_findings'] if entry['applies'] == 'yes')}"]
        for finding in item["public_findings"]:
            lines.append(f"     - {finding['id']} ({finding['applies'] or 'неясно'})"
                         + (f": {finding['description']}" if finding["description"] else ""))
            for source in finding["sources"]:
                lines.append(f"       {source['url']} [{source['source_type']}, {source['checked_at']}]")
        lines.append("   Охват: " + ("; ".join(f"{entry['source']} – {entry['status']}" for entry in
                                                item["research_coverage"]) or "не проверялся"))
        advice = item["advice"]
        lines.append(f"   Совет: {advice['action_label'] or advice['action'] or 'нет'}"
                     + (f" на {advice['target_version']}" if advice["target_version"] else "")
                     + (f"; {advice['compatibility_notes']}" if advice["compatibility_notes"] else ""))
        for gap in item["gaps"]:
            lines.append(f"   Пробел: {gap['code']} – {gap['text']}")
        decision = item["decision"]
        lines.append("   Решение человека: " + (f"{decision['action']} – {decision['rationale']}"
                                                f" (от {decision['decided_at']})" if decision else "не принято")
                     + (" [требует пересмотра]" if item["decision_stale"] else ""))
        lines.append("")
    archive = document.get("identity_archive") or []
    if archive:
        # тот же факт снятия, что в JSON (ревью Codex, круг 2): в действующий состав выше не входит
        labels = {"sca2_research": "исследование", "sca2_decisions": "решение человека"}
        lines += ["Снято переходом идентичности пакетов (сведения Hub о библиотеке) – в состав выше не входит:", ""]
        for entry in archive:
            lines.append(f"- {labels.get(entry['table'], entry['table'])} строки {entry['input_ref']}"
                         f" (ревизия {entry.get('revision') or '–'}), снято {str(entry['archived_at'])[:10]}"
                         + (f": {entry['reason']}" if entry.get('reason') else ""))
        lines.append("")
    return "\n".join(lines) + "\n"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
