"""Текст дефекта для AppSec.Hub: заголовок и тело, которые человек вставляет в Hub, создавая дефект вручную.

Формат – docs/hub-format.md, разделы «Дефект: заголовок» и «Дефект: тело».

* SAST (с 0.9.6, ADR-0089) – два исхода. Ложное срабатывание закрывается коротким комментарием оператора
  (sast_comment), дефект не создаётся. Подтверждённая находка – дефект: заголовок `ID<n> - <Category> (SAST)`,
  тело – стандартная фраза команды, «Обоснование:» и «Рекомендация:» по пунктам «1)», «2)» (sast_body). Ничего
  больше: ни внутренних номеров Hub, ни требований ГОСТ к конвейеру, ни справки по CWE.
* SCA – дефект для итога «истинная» или «ложная»; для «неясно», «Отложить» и «Риск принят» не создаётся.
* SCA – один дефект на библиотеку и версию: заголовок `ID<n> - <Component name> | Component version: <версия> (SCA)`;
  тело – сводная таблица связанных уязвимостей и блок по каждой (CWE, CVSS, связанная уязвимость, описание,
  объяснение, рекомендации, источники). Сведения – из выгрузки, ответа внешнего агента и справочников (БДУ ФСТЭК
  России по CVE).

Ветка и коммит клона в текст не входят: сведения об объекте сканирования Hub добавляет сам. Номер `ID<n>` вводит
человек, приложение предлагает следующий по счётчику проекта (Database.next_defect_number). Все функции здесь
чистые: сведения из базы и справочников передаёт вызывающий.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from app import cvss, defect_where, i18n
from app.models import Finding
from app.textsafe import hub_clean, is_invisible

READY_VERDICTS = ("true_positive", "false_positive")
# SAST с 0.9.6: дефект – только для подтверждённой находки, ложное срабатывание – короткий комментарий (ADR-0089)
SAST_READY_VERDICTS = ("true_positive",)
DEFAULT_RECOMMENDATION = i18n.N_("Исправить код так, чтобы недостаток не мог быть использован для реализации угроз.")
CATEGORY = {"true_positive": "True Positive", "false_positive": "False Positive"}  # категория Hub – не переводится
NO_INFO = i18n.N_("Нет информации")  # msgid: в текущих текстах – i18n._(NO_INFO), в прежних форматах – как есть
SEPARATOR = "-" * 10
# Пробелов после самого длинного значения колонки сводной таблицы SCA (ID, Компонент, Серьёзность, Уязвимость) –
# как в образце дефекта Hub (docs/hub-format.md)
COLUMN_GAPS = (3, 5, 3, 4)
MAX_SOURCES = 10
MAX_DESCRIPTION = 1500  # знаков описания из справочника в одном блоке
MAX_CWE_DESCRIPTION = 600

# Длинное тире и неразрывный дефис в тексте для Hub не нужны
_DASHES = str.maketrans({chr(0x2014): "–", chr(0x2011): "-", chr(0x2010): "-"})
# Начало комментария модели для Hub («Подтверждено: …»): в обосновании дефекта оно лишнее – категория уже названа.
# Узнаётся на обоих языках независимо от языка интерфейса (ADR-0158): модель при английском интерфейсе пишет
# «False positive: …». Прежние форматы (только узнавание отметок, тексты до dev38 – русские) – прежнее правило.
_VERDICT_PREFIX_RU = re.compile(r"^\s*(?:подтверждено|ложное срабатывание|нужна проверка|требуется (?:дополнительная )?"
                                r"проверка|риск принят)\s*[:.–-]\s*", re.I)
_VERDICT_PREFIX = re.compile(r"^\s*(?:подтверждено|ложное срабатывание|нужна проверка|требуется (?:дополнительная )?"
                             r"проверка|риск принят|confirmed|true positive|false positive|(?:needs|requires) "
                             r"(?:an? )?(?:additional )?(?:review|verification|check)|risk accepted)\s*[:.–-]\s*", re.I)
# маркер пункта: «2)» – и без пробела («2)текст»), «2.», «-», «*», «•» – только с пробелом, чтобы не резать «1.5 раза»,
# «-x» и «*args»; цифры только ASCII, пробелы – только пробел и табуляция (одинаково в Python и JS); то же выражение –
# в предпросмотре app/static/app.js (recommendationPoints)
_LIST_ITEM = re.compile(r"^[ \t]*(?:[0-9]{1,2}\)[ \t]*|[0-9]{1,2}\.[ \t]+|[-*•][ \t]+)")
# правило до 0.9.11: «2)текст» оставалось пунктом «2)текст» – по нему узнаётся, что текст изменился из-за маркера
_LIST_ITEM_0910 = re.compile(r"^\s*(?:\d{1,2}[.)]|[-*•])\s+")
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_INDENTED_CODE = re.compile(r"^(?: {4}|\t)")
_FENCE_MARK = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_LETTERS = re.compile(r"[A-Za-zА-Яа-яЁё]")


def defect_key_sast(hub_id: str) -> str:
    return f"sast:{hub_id}"


def defect_key_sca(component: str, version: str, ecosystem: str = "") -> str:
    """Ключ номера дефекта SCA: пакет – это экосистема, имя и версия; тройка кодируется JSON-массивом `["экосистема","имя",
    "версия"]` (`sca:v3|…`), поэтому границы компонентов однозначны для любых значений: `("npm", "a@b", "c")` и
    `("npm", "a", "b@c")` дают разные ключи, «@» и «|» в имени и версии ничего не ломают, пустая экосистема – пустая строка.
    Пространство `sca:v3|` текущее: прежние ключи (`sca:имя@версия`, `sca:экосистема|имя@версия`, `sca:v2|…`) остаются
    историей и текущими не бывают; однозначно распознаваемые v2 переносит шаг обновления 12 (Database.migrate_12)."""
    return "sca:v3|" + json.dumps([str(ecosystem), str(component), str(version)], ensure_ascii=True,
                                  separators=(",", ":"))


def ready(outcome: str) -> bool:
    """Дефект SCA готовится только для итога «истинная» или «ложная» (hub_verdict решения)."""
    return outcome in READY_VERDICTS


def sast_ready(outcome: str) -> bool:
    """Дефект SAST готовится только для итога «истинная»: ложное срабатывание закрывается комментарием (ADR-0089)."""
    return outcome in SAST_READY_VERDICTS


def one_line(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def edges(text: str) -> str:
    """Формат текста оператора для Hub (ADR-0149 п. 5): переводы строк «\\n», без хвостовых пробелов строк и без пустых
    строк по краям текста; отступ первой содержательной строки и пустые строки внутри остаются как написаны."""
    lines = [line.rstrip() for line in str(text or "").replace("\r\n", "\n").split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _finish(text: str, *, clean: bool = False) -> str:
    """Вид текста для Hub целиком (edges): переводы строк «\\n», без хвостовых пробелов строк и без пустых строк по
    краям текста – формат, слова, отступы и пустые строки внутри не меняются. Текст оператора уходит в Hub как написан: приложение
    не правит тексты оператора без его ведома.

    clean=True – прежние правила (до 0.10.0.dev21): ещё и без тегов HTML, схем javascript:, vbscript:, data: и
    невидимых знаков (hub_clean), длинное тире – «–», не больше одной пустой строки подряд. Только для текстов из
    данных выгрузки (заголовки дефектов) и для прежних форматов, по которым узнаются отметки «Внесено в Hub». Прежний
    формат hub_text_v1 сюда не идёт: его отпечатки сверяются как были."""
    text = str(text or "")
    if not clean:
        return edges(text)
    # прежние правила – как были, с обрезкой краёв (по ним узнаются прежние отметки)
    text = hub_clean(text).translate(_DASHES)
    text = "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n"))
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# ============================================================================ заключение для Hub (ГОСТ)

# Короткие нормативные опоры текста для Hub (docs/hub-verdict-text.md)
GOST_DEADLINE_SAST = ("Срок – исправить либо запланировать сроки устранения не позже 10 рабочих дней после разметки; "
                      "при гибкой методологии план устранения включается в ближайший цикл разработки; потенциальные "
                      "критические ошибки, выявленные при анализе ПО целиком, устраняются не позднее начала "
                      "квалификационного тестирования (ГОСТ Р 71207-2024, п. 5.9).")
GOST_TRUE_NO_FIX = ("«истинные, но не требующие исправлений кода предупреждения» (ГОСТ Р 71207-2024, п. 5.5)")
DEADLINE_SCA = "Срок – по регламенту композиционного анализа."
# Уточнение решения SCA по ГОСТ Р КАПО (окончательная редакция, пп. 6.12, 6.14). KAPO_UI_LABELS – подписи карточки на
# языке интерфейса; KAPO_LABELS – те же подписи по-русски для текста прежних форматов (sca.sca_comment, sca_conclusion):
# по нему узнаются прежние отметки, он не переводится
KAPO_UI_LABELS = i18n.Labels({"not_finished": "анализ не завершён – актуальность не установлена",
                              "actual": "актуальна", "not_actual": "неактуальна для продукта",
                              "neutralized": "нейтрализована принятыми мерами",
                              "false_positive": "ложноположительное срабатывание"})
KAPO_LABELS = dict(dict.items(KAPO_UI_LABELS))


# соответствие статусов Hub и ГОСТ для подсказок в карточках и настройках (docs/hub-verdict-text-plan.md); только
# показ – подписи на языке интерфейса
GOST_STATUS_NOTES = {
    "sast": i18n.Labels({"true_positive": "истинное срабатывание: ошибка в программе, требуется исправление",
                         "false_positive": "ложное срабатывание",
                         "risk_accepted": "истинное срабатывание, не требующее исправлений кода",
                         "uncertain": "решение не принято"}),
    "sca": i18n.Labels({"true_positive": "уязвимость актуальна или анализ не завершён: требуется обновление или "
                                         "обоснование неактуальности",
                        "false_positive": "ложноположительное: компонент или сведения об уязвимости определены ошибочно",
                        "risk_accepted": "уязвимость неактуальна (с обоснованием) или нейтрализована принятыми мерами",
                        "uncertain": "решение не принято"}),
}
GOST_STATUS_BASIS = i18n.Labels({"sast": "ГОСТ Р 71207-2024, п. 5.5", "sca": "ГОСТ Р КАПО, пп. 6.12, 6.14"})


def effective_kapo(outcome: str, kapo_state: str) -> str:
    """Уточнение по ГОСТ Р КАПО с учётом итога: у прежних решений его нет – «Подтверждено» считается «анализ не
    завершён», «Ложное срабатывание» – ложноположительным; у остальных итогов – как сохранено."""
    if kapo_state:
        return kapo_state
    return {"true_positive": "not_finished", "false_positive": "false_positive"}.get(outcome, "")


def where_text(f: Finding) -> str:
    """«<правило> в <файл>:<строка>» – место срабатывания SAST одной строкой (без HTML и переводов строк)."""
    rule = hub_clean(one_line(f.rule)) or "срабатывание анализатора"
    place = hub_clean(one_line(f.file))
    if place and f.line:
        place += f":{f.line}"
    return f"{rule} в {place}" if place else rule


def cwe_phrase(f: Finding) -> str:
    """« класса CWE-89» или « классов CWE-89, CWE-564»; без CWE – ""."""
    keys = [k for k in (cwe_id(c) for c in f.cwe) if k]
    keys = list(dict.fromkeys(keys))
    if not keys:
        return ""
    return f" {'классов' if len(keys) > 1 else 'класса'} {', '.join(keys)}"


def sast_comment(f: Finding, outcome: str, comment: str) -> str:
    """Текст для Hub по находке SAST (формат 0.9.6, ADR-0089): только обоснование оператора его словами – без
    «Статус: …», места срабатывания и требований. У ложного срабатывания это комментарий к смене статуса в Hub, одна-две
    фразы («Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена»). У подтверждённой находки
    тот же текст – обоснование дефекта (по нему считается отпечаток отметки «Внесено в Hub»); дефект – sast_body.
    f и outcome в тексте не участвуют: подпись общая с прежними форматами. С 0.10.0.dev21 текст оператора уходит как
    написан; меняется только первая буква – заглавная (sast_reason, ADR-0101 п. 7)."""
    return _finish(sast_reason(comment))


def sast_comment_v4(f: Finding, outcome: str, comment: str) -> str:
    """Формат 0.9.11–0.10.0.dev20: вводное «Подтверждено:» и подобное снято, первая буква заглавная, прежняя чистка
    (теги, схемы, невидимые знаки, длинное тире, лишние пустые строки). По нему узнаются отметки «Внесено в Hub»,
    поставленные до 0.10.0.dev21 (причина «формат текста»)."""
    return _finish(sast_reason(comment, legacy=True), clean=True)


def sast_comment_v3(f: Finding, outcome: str, comment: str) -> str:
    """Формат 0.9.6–0.9.10: обоснование как написал оператор, без поднятия первой буквы, с прежней чисткой. По нему
    узнаются отметки «Внесено в Hub», поставленные до 0.9.11 (причина «формат текста»)."""
    return _finish(reason_text(comment, clean=True, legacy=True), clean=True)


def sast_comment_v2(f: Finding, outcome: str, comment: str) -> str:
    """Формат 0.9.0–0.9.5 (по нему узнаются отметки «Внесено в Hub», поставленные до 0.9.6).

    Короткое заключение по находке SAST – текст поля «Комментарий» для «Скопировать для Hub». Зависит только от
    находки, итога решения и комментария оператора: отпечаток отметки «Внесено в Hub» не меняется от справочников
    и соседних находок. Обоснование – комментарий оператора без вводного «Подтверждено:», не сокращается. Чистка –
    прежняя (формат узнавания, clean=True). Текст прежнего формата – русский при любом языке интерфейса."""
    reason = reason_text(comment, clean=True, legacy=True)
    where = where_text(f)
    lines: list[str] = []
    if outcome == "true_positive":
        lines.append(f"Подтверждена ошибка в программе{cwe_phrase(f)}: {where}.")
        if reason:
            lines.append(f"Обоснование: {reason}")
        lines.append("Требуется от разработчика: исправить код по рекомендациям дефекта, проверить такие же места "
                     "в кодовой базе, добавить тест. " + GOST_DEADLINE_SAST)
    elif outcome == "false_positive":
        lines.append(f"Срабатывание признано ложным: {where}.")
        if reason:
            lines.append(f"Обоснование: {reason}")
    elif outcome == "risk_accepted":
        lines.append(f"Подтверждена ошибка в программе{cwe_phrase(f)}: {where}; исправление кода не требуется – "
                     f"{GOST_TRUE_NO_FIX}.")
        if reason:
            lines.append(f"Обоснование: {reason}")
    else:
        lines.append(f"Требуется дополнительная проверка: {where}.")
        if reason:
            lines.append(reason)
    return _finish("\n".join(lines), clean=True)


def hub_lines(status: str, comment: str) -> str:
    """«Статус: …» (если статус задан) и «Комментарий: …» – текст формата 0.9.0–0.9.7 (только узнавание прежних отметок
    «Внесено в Hub»), с прежней чисткой."""
    lines = [f"Статус: {status}"] if status else []
    lines.append(f"Комментарий: {comment}")
    return _finish("\n".join(lines), clean=True)


GOST_VULNERABILITY = ("Что это значит: если ошибку можно использовать для реализации угроз, это уязвимость программы – "
                      "«Недостаток программы, который может быть использован для реализации угроз безопасности "
                      "информации» (ГОСТ Р 56939-2024, п. 3.20). Есть ли у недостатка публичный идентификатор (CVE, BDU), "
                      "на необходимость исправления не влияет.")
GOST_KAPO_BASIS = ("Нормативная опора: правила анализа устанавливают «необходимость присвоения каждой уязвимости статуса "
                   "о ее актуальности и критичности, в случае неактуальности уязвимости - обоснование неактуальности»; "
                   "на основании отчета по результатам КАПО разработчик «должен определять и принимать компенсирующие "
                   "меры» (ГОСТ Р КАПО, окончательная редакция, пп. 6.14, 7.11).")
NOT_ACTUAL_PROOF = ("Обоснование неактуальности должно показать для проверенной версии продукта: где подключён компонент "
                    "(прямая или транзитивная зависимость, модуль); вызывается ли уязвимая функция – места в коде или "
                    "результат анализа графа вызовов с названием инструмента и его ограничениями; может ли нарушитель "
                    "прямо или косвенно влиять на её входные данные; от какой конфигурации это зависит. Учитываются все "
                    "пути выполнения, а не только основной.")
REFERENCE_HEAD = "Справочно (класс слабости; применимость к продукту отдельно не оценивалась):"
REFERENCE_BUDGET = 6000  # знаков справки на дефект: при превышении она сокращается с пометкой
REFERENCE_LIMITS = {"consequences": 5, "mitigations": 5, "capec": 5, "observed": 3}
MAX_MITIGATION = 300
_DATE_IN_NAME = re.compile(r"(?<!\d)(\d{2})[_.-](\d{2})[_.-](\d{4})(?!\d)")


def export_label(filename: str, created_at: str) -> str:
    """Подпись выгрузки находки: дата из имени файла выгрузки Hub («…_15_10_2026_…» – «от 15.10.2026 (по имени
    файла)», только настоящая календарная дата), иначе – дата загрузки в приложение."""
    import datetime as _dt
    for day, month, year in _DATE_IN_NAME.findall(str(filename or "")):
        try:
            _dt.date(int(year), int(month), int(day))
        except ValueError:
            continue
        return f"от {day}.{month}.{year} (по имени файла)"
    loaded = str(created_at or "")[:10]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", loaded):
        return f"загружена в приложение {loaded[8:10]}.{loaded[5:7]}.{loaded[:4]}"
    return ""


def area_text(codebases: Iterable[str], exports: Iterable[str], decided_at: str | None) -> str:
    """«Область: кодовая база …; текущая выгрузка находки – …; решение от ДД.ММ.ГГГГ.» – то, что известно; дату решения
    у прежних решений не знаем и не выводим."""
    parts: list[str] = []
    bases = list(dict.fromkeys(hub_clean(one_line(c, 200)) for c in codebases if one_line(c)))
    if bases:
        parts.append(("кодовые базы " if len(bases) > 1 else "кодовая база ") + ", ".join(bases))
    labels = list(dict.fromkeys(x for x in exports if x))
    if labels:
        parts.append("текущая выгрузка находки – " + "; ".join(labels))
    decided = str(decided_at or "")[:10]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", decided):
        parts.append(f"решение от {decided[8:10]}.{decided[5:7]}.{decided[:4]}")
    return ("Область: " + "; ".join(parts) + ".") if parts else ""


def _paragraphs(value: Any, limit: int) -> str:
    if isinstance(value, (list, tuple)):
        value = " ".join(str(x) for x in value)
    return hub_clean(one_line(value, limit))


def reference_block(cwes: Iterable[str], catalog: Mapping[str, Mapping[str, Any]],
                    capec_names: Mapping[str, str] | None = None, *, budget: int = REFERENCE_BUDGET,
                    seen: set[str] | None = None) -> str:
    """Справка по классам CWE из каталогов MITRE (содержимое фидов – как в источнике, без перевода; русское название –
    из БДУ ФСТЭК России с пометкой): название, Likelihood Of Exploit, описание, Common Consequences, Potential
    Mitigations, Related Attack Patterns (CAPEC с названиями), Observed Examples и ссылки. Нет в каталоге – не
    выводится; seen – уже показанные CWE (в групповом дефекте справка по классу – один раз). Больше budget знаков –
    сокращается: сначала Observed Examples, затем Mitigations, Consequences и CAPEC, с пометкой."""
    keys = [k for k in dict.fromkeys(cwe_id(c) for c in cwes) if k and catalog.get(k)
            and (seen is None or k not in seen)]
    if not keys:
        return ""
    names = capec_names or {}
    limits = dict(REFERENCE_LIMITS)

    def build() -> str:
        lines = [REFERENCE_HEAD]
        links: list[str] = []
        for key in keys:
            info = catalog[key]
            name = hub_clean(one_line(info.get("name"), 300))
            head = f"{key} – {name}" if name else key
            ru = hub_clean(one_line(info.get("name_ru"), 300))
            if ru:
                head += f" (по БДУ ФСТЭК России: {ru})"
            likelihood = hub_clean(one_line(info.get("likelihood"), 40))
            lines.append(head + (f". Likelihood Of Exploit: {likelihood}." if likelihood else "."))
            description = hub_clean(one_line(info.get("description"), MAX_CWE_DESCRIPTION))
            if description:
                lines.append(description)
            consequences = []
            for c in (info.get("consequences") or [])[:limits["consequences"]]:
                scope = ", ".join(hub_clean(one_line(s, 100)) for s in c.get("scope") or [] if one_line(s))
                impact = "; ".join(hub_clean(one_line(i, 150)) for i in c.get("impact") or [] if one_line(i))
                if impact:
                    consequences.append(f"- {scope}: {impact}" if scope else f"- {impact}")
            if consequences:
                lines += ["Common Consequences:", *consequences]
            mitigations = []
            for m in (info.get("mitigations") or [])[:limits["mitigations"]]:
                phases = ", ".join(hub_clean(one_line(x, 60)) for x in m.get("phases") or [] if one_line(x))
                strategy = hub_clean(one_line(m.get("strategy"), 100))
                text = _paragraphs(m.get("description"), MAX_MITIGATION)
                label = " – ".join(x for x in (phases, strategy) if x)
                if text or label:
                    mitigations.append(f"- {label}: {text}" if label and text else f"- {label or text}")
            if mitigations:
                lines += ["Potential Mitigations:", *mitigations]
            capec = []
            for pattern in (info.get("attack_patterns") or [])[:limits["capec"]]:
                pid = hub_clean(one_line(pattern, 20))
                if not re.fullmatch(r"CAPEC-\d{1,7}", pid):
                    continue
                title = hub_clean(one_line(names.get(pid), 200))
                capec.append(f"- {pid}: {title}" if title else f"- {pid}")
                links.append(f"https://capec.mitre.org/data/definitions/{pid.split('-')[1]}.html")
            if capec:
                lines += ["Related Attack Patterns (CAPEC):", *capec]
            observed = []
            for o in (info.get("observed") or [])[:limits["observed"]]:
                ref = hub_clean(one_line(o.get("reference"), 60))
                text = hub_clean(one_line(o.get("description"), 200))
                if ref or text:
                    observed.append(f"- {ref}: {text}" if ref and text else f"- {ref or text}")
            if observed:
                lines += ["Observed Examples (другие продукты):", *observed]
            links.insert(0, f"https://cwe.mitre.org/data/definitions/{key.split('-')[1]}.html")
        lines.append("Ссылки: " + ", ".join(dict.fromkeys(links)))
        return "\n".join(lines)

    note = "\nСправка сокращена: полный текст – на cwe.mitre.org и capec.mitre.org."
    text = build()
    if len(text) > budget:  # итог с пометкой не длиннее budget
        for part in ("observed", "mitigations", "consequences", "capec"):
            limits[part] = 0
            text = build()
            if len(text) + len(note) <= budget:
                break
        lines = text.split("\n")
        while len(lines) > 1 and len("\n".join(lines)) + len(note) > budget:
            lines.pop()  # и после сокращения разделов – по строкам с конца, заголовок справки остаётся
        text = "\n".join(lines) + note
    if seen is not None:
        seen.update(keys)
    return text


# ============================================================================ заголовки

def sast_title(number: int, f: Finding) -> str:
    # заголовок собирается из данных выгрузки (правило), не из текста оператора: чистка прежняя
    return _finish(f"ID{number} - {one_line(f.rule) or i18n._('Правило не указано')} (SAST)", clean=True)


def sca_title(number: int, component: str, version: str) -> str:
    # каркас «ID<n> - … | Component version: … (SCA)» – формат Hub, не переводится; переводятся только заглушки
    return _finish(f"ID{number} - {one_line(component) or i18n._('Библиотека не указана')} | Component version: "
                   f"{one_line(version) or i18n._(NO_INFO)} (SCA)", clean=True)


# ============================================================================ SAST

def reason_text(comment: str, *, clean: bool = True, legacy: bool = False) -> str:
    """Комментарий человека без вводного «Подтверждено:», «Ложное срабатывание:» и подобного и с прежней чисткой
    тегов, схем и невидимых знаков – только для проверки, есть ли обоснование (ADR-0089 п. 6: одно вводное слово,
    пустой тег или невидимый знак обоснованием не считаются; критерий тот же, что до 0.10.0.dev21) и для прежних
    форматов. В Hub с 0.10.0.dev21 уходит комментарий как написан. clean=False – без чистки
    (ссылки «строка N» в обосновании и т. п.). Вводное слово узнаётся на обоих языках («False positive:» – как
    «Ложное срабатывание:», ADR-0158); legacy=True – только русское, как в прежних форматах (узнавание отметок)."""
    text = (hub_clean(str(comment or "")) if clean else str(comment or "")).strip()
    return (_VERDICT_PREFIX_RU if legacy else _VERDICT_PREFIX).sub("", text, count=1).strip()


def sast_reason(comment: str, *, legacy: bool = False) -> str:
    """Обоснование SAST, как оно уходит в Hub: как написал оператор, с одной правкой
    (ADR-0101 п. 7) – первая буква заглавная, если это строчная кириллическая («строка 26 формирует…» → «Строка 26
    формирует…»). Латиница и имена из кода (owner, customerId) не трогаются.

    Комментарий из одного вводного слова («Ложное срабатывание:») обоснованием не считается (ADR-0089 п. 6): тогда "".

    legacy=True – формат 0.9.11–0.10.0.dev20 (только узнавание прежних отметок): вводное слово снято, прежняя чистка
    тегов, схем и невидимых знаков."""
    if legacy:
        text = reason_text(comment, clean=True, legacy=True)
    else:
        text = edges(comment) if reason_text(comment) else ""  # отступ первой строки остаётся (ревью Kimi)
    # первая видимая буква: невидимые знаки перед ней остаются на месте (их прежде вырезала чистка, ревью Kimi)
    k = 0
    while k < len(text) and (is_invisible(text[k]) or text[k].isspace()):
        k += 1
    if k < len(text) and ("а" <= text[k] <= "я" or text[k] == "ё"):
        return text[:k] + text[k].upper() + text[k + 1:]
    return text


def recommendations(fix: str) -> list[str]:
    """Рекомендации по пунктам из поля «Как исправить»: пункты списка и абзацы – отдельными пунктами; пример кода
    в ограде ``` – строками под пунктом (с отступом), без строк ограды."""
    items: list[list[str]] = []
    in_code = False
    for raw in str(fix or "").replace("\r\n", "\n").split("\n"):
        if _FENCE.match(raw):
            in_code = not in_code
            if in_code and not items:
                items.append([])
            continue
        if in_code:
            if raw.strip():
                items[-1].append("   " + raw.rstrip())
            continue
        line = raw.strip()
        if not line:
            if items and items[-1]:
                items.append([])  # пустая строка – конец абзаца
            continue
        if _LIST_ITEM.match(line):
            items.append([_LIST_ITEM.sub("", line, count=1)])
        elif items and items[-1]:
            if items[-1][-1].startswith("   "):  # после кода – новый пункт
                items.append([line])
            else:
                items[-1][-1] += " " + line
        else:
            if items and not items[-1]:
                items[-1].append(line)
            else:
                items.append([line])
    result = []
    for item in items:
        lines = [x for x in item if x.strip()]
        if lines:
            result.append("\n".join([hub_clean(lines[0]).strip(), *lines[1:]]))
    return result


def fix_items(fix: str, *, clean: bool = False) -> list[str]:
    """Пункты рекомендации дефекта SAST: в Hub идут только меры словами (ADR-0098) – то же
    правило, что у recommendation_points: строки вне ограды ``` или ~~~ и вне отступа кода, маркер «1.», «2)», «-»
    снят, в строке есть буква. Пример кода в текст дефекта не переносится."""
    return recommendation_points(fix, clean=clean)[0]


def recommendation_points(fix: str, marker: re.Pattern = _LIST_ITEM, *, clean: bool = False) -> tuple[list[str], bool]:
    """Пункты рекомендации словами (ADR-0092): строки вне блоков кода, маркер списка снят. Блок кода – в ограде ``` или
    ~~~ (незакрытая ограда – до конца текста) или строки с отступом в четыре пробела или табуляцию. Строка без букв
    пунктом не считается. Второе значение – был ли в тексте код, который в пункты не вошёл. По этим пунктам кнопка
    «Взять пункты из рекомендации модели» заполняет поле, и по ним же проверяется, что рекомендация есть. marker –
    правило маркера пункта (прежнее – только для причины «Текст для Hub изменился»). Слова пункта – как написал оператор;
    clean=True – прежняя чистка тегов и схем: заготовка из ответа модели и прежние форматы
    для узнавания отметок."""
    points: list[str] = []
    dropped = False
    fence = ""  # открывающая ограда: блок закрывает только ограда из тех же знаков не короче её (как в CommonMark)
    for raw in str(fix or "").replace("\r\n", "\n").split("\n"):
        mark = _FENCE_MARK.match(raw)
        if mark:
            dropped = True
            if not fence:
                fence = mark.group(1)
                continue
            if mark.group(1)[0] == fence[0] and len(mark.group(1)) >= len(fence) and not raw.strip()[len(mark.group(1)):]:
                fence = ""
            continue
        if fence or (_INDENTED_CODE.match(raw) and raw.strip()):
            dropped = dropped or bool(raw.strip())
            continue
        bare = marker.sub("", raw.strip(), count=1)
        cleaned = hub_clean(bare).strip()  # прежние правила – как были
        # пункт ли это – по прежнему критерию (ADR-0149 п. 3): пустой тег или одни невидимые знаки пунктом не
        # считаются и рядом с другим пунктом (ревью Codex круга 6); слова пункта – как написаны (clean=False), с
        # отступом строки в 1–3 пробела (ADR-0149 п. 5; четыре пробела и табуляция – код, выше)
        if cleaned and _LETTERS.search(cleaned):
            points.append(cleaned if clean else raw[:len(raw) - len(raw.lstrip(" "))] + bare.strip())
    return points, dropped


def marker_rule_changed(fix: str) -> bool:
    """Пункты рекомендации по правилу маркера 0.9.11 не те, что по прежнему (например, «2)текст»): текст дефекта,
    внесённого в Hub до 0.9.11, изменился из-за этого."""
    return (recommendation_points(fix, clean=True)[0]
            != recommendation_points(fix, _LIST_ITEM_0910, clean=True)[0])


def as_written_changed(comment: str, fix: str = "") -> bool:
    """Прежние правила (срез вводного «Подтверждено:», теги HTML, схемы javascript:, vbscript:, data:, невидимые
    знаки, длинное тире, лишние пустые строки) меняли обоснование или пункты рекомендации: текст, внесённый в Hub до
    0.10.0.dev21, отличается от нынешнего этим (текст оператора уходит как написан)."""
    return (_finish(sast_reason(comment, legacy=True), clean=True) != _finish(sast_reason(comment))
            or [_finish(x, clean=True) for x in fix_items(fix, clean=True)] != [_finish(x) for x in fix_items(fix)])


def has_recommendation(fix: str) -> bool:
    """Есть ли в рекомендации хотя бы один пункт словами (ADR-0092): пробелы, пустой список и один код – нет. Критерий
    – с прежней чисткой (пустой тег или невидимые знаки пунктом не считаются, как до 0.10.0.dev21); пункты, которые
    уходят в Hub, – как написаны (fix_items)."""
    return bool(recommendation_points(fix, clean=True)[0])


def sast_effective(outcome: str, comment: str, final_fix: str, decision: str = "", model_fix: str = "") -> tuple:
    """Итоговый текст решения SAST, который уходит в Hub, – для сравнения находок одной группы (ADR-0089):
    (итог, обоснование, пункты рекомендации). У ложного срабатывания рекомендации нет. У дефекта рекомендация – только
    своя (final_fix, ADR-0092): «Как исправить» модели и общий пункт в текст не подставляются. decision и model_fix не
    участвуют: параметры остались от прежних вызовов. Тексты нормализованы так же, как в Hub (_finish)."""
    reason = _finish(sast_reason(comment))
    if outcome != "true_positive":
        return (outcome, reason, ())
    return (outcome, reason, tuple(_finish(item) for item in fix_items(final_fix)))


def cwe_id(value: Any) -> str:
    """«89», «CWE-89», «cwe 89» -> «CWE-89»; не похоже – ""."""
    m = re.search(r"(\d{1,5})", str(value or ""))
    return f"CWE-{int(m.group(1))}" if m else ""


# Стандартная фраза команды (ADR-0089) на языке интерфейса (ADR-0158): с названием команды и без него; категория Hub –
# «True Positive» / «False Positive» – не переводится
PHRASE_TEAM = i18n.N_("После тщательного анализа уязвимости команда {team} приняла решение присвоить данной уязвимости "
                      "категорию {category}.")
PHRASE_NO_TEAM = i18n.N_("После тщательного анализа уязвимости команда приняла решение присвоить данной уязвимости "
                         "категорию {category}.")


def _phrase(team: str, outcome: str) -> str:
    name = hub_clean(one_line(team, 100)) if hub_clean(one_line(team)) else ""
    if name:
        return i18n._(PHRASE_TEAM, team=name, category=CATEGORY[outcome])
    return i18n._(PHRASE_NO_TEAM, category=CATEGORY[outcome])


def sast_phrase(team: str = "", outcome: str = "true_positive") -> str:
    """Стандартная фраза команды – первая строка тела дефекта SAST (ADR-0089) так, как её выдаёт sast_body: с ней
    проверка текста перед Hub сверяет первую строку (ADR-0123, требование S2). На языке интерфейса."""
    return _finish(_phrase(team, outcome))


def sast_phrases(team: str = "", outcome: str = "true_positive") -> tuple[str, ...]:
    """Стандартная фраза на обоих языках: текст, собранный до переключения языка интерфейса, проходит проверку S2."""
    return tuple(dict.fromkeys(in_both_languages(lambda: sast_phrase(team, outcome))))


def phrase_variants(phrase: str) -> tuple[str, ...]:
    """Стандартная фраза команды и она же на другом языке: название команды и категория берутся из самой фразы (её
    собрал sast_phrase на языке интерфейса вызывающего). Не узнана – (phrase,)."""
    text = str(phrase or "")
    out = [text]
    templates = [(t, PHRASE_TEAM) for t in defect_where.variants((PHRASE_TEAM, _PHRASE_TEAM_EN))]
    templates += [(t, PHRASE_NO_TEAM) for t in defect_where.variants((PHRASE_NO_TEAM, _PHRASE_NO_TEAM_EN))]
    for template, _msgid in templates:
        pattern = re.escape(template).replace(re.escape("{team}"), "(?P<team>.+?)").replace(
            re.escape("{category}"), "(?P<category>True Positive|False Positive)")
        found = re.fullmatch(pattern, text.strip())
        if found is None:
            continue
        team, category = found.groupdict().get("team"), found.group("category")
        for t, msgid in templates:
            if (msgid == PHRASE_TEAM) == (team is not None):
                out.append(t.replace("{category}", category).replace("{team}", team or ""))
        break
    return tuple(dict.fromkeys(out))


# английские варианты фразы – те же, что в каталоге (app/locales/en/defects.json): разбор не зависит от каталога
_PHRASE_TEAM_EN = "After a thorough analysis of the vulnerability, team {team} decided to assign this vulnerability the " \
                  "{category} category."
_PHRASE_NO_TEAM_EN = "After a thorough analysis of the vulnerability, the team decided to assign this vulnerability " \
                     "the {category} category."


def _neutral_phrase(line: str) -> str:
    """Стандартная фраза команды на английском -> та же фраза на русском (для body_key); иначе строка как есть."""
    text = line.strip()
    for template, msgid in ((_PHRASE_TEAM_EN, PHRASE_TEAM), (_PHRASE_NO_TEAM_EN, PHRASE_NO_TEAM),
                            (i18n.translate(PHRASE_TEAM, "en"), PHRASE_TEAM),
                            (i18n.translate(PHRASE_NO_TEAM, "en"), PHRASE_NO_TEAM)):
        if template == msgid:
            continue
        pattern = re.escape(template).replace(re.escape("{team}"), "(?P<team>.+?)").replace(
            re.escape("{category}"), "(?P<category>True Positive|False Positive)")
        found = re.fullmatch(pattern + r"\.?", text)
        if found:
            team = found.groupdict().get("team")
            ru = msgid.replace("{category}", found.group("category")).replace("{team}", team or "")
            return _finish(ru)
    return line


def body_key(text: str) -> str:
    """Тело дефекта (до раздела «Где исправлять», defect_where.body_of) в языконезависимом виде – для сравнения
    отпечатков текстов дефектов (ADR-0158): английские заголовки разделов, подписи полей, «not specified», строка
    обновления и стандартная фраза команды заменяются русскими. Тексты одного решения, собранные на разных языках
    интерфейса, дают один ключ; разные решения остаются разными – меняются только написания из таблиц генератора."""
    body = defect_where.body_of(str(text or ""))
    # подписи полей живут только в разделе «Где исправлять», который body_of отрезает: в теле нормализуются одни
    # заголовки разделов – отдельной строкой (ревью Codex dev38, круги 2–3: «Branch: …» в обосновании – текст)
    pairs = [(en, ru) for ru, en in defect_where.HEADS.values()]
    pairs += [(i18n.translate(ru, "en"), ru) for ru, _en in defect_where.HEADS.values()]
    pairs = sorted({(a, b) for a, b in pairs if a and a != b}, key=lambda x: -len(x[0]))
    upd_ru, upd_en = defect_where.UPDATE_LINE
    upd = []
    for template in dict.fromkeys((upd_en, i18n.translate(upd_ru, "en"))):
        if template != upd_ru:
            upd.append(re.compile(re.escape(template).replace(re.escape("{component}"), "(?P<component>.+?)")
                                  .replace(re.escape("{target}"), "(?P<target>.+)")))
    out = []
    first = True
    in_recs = False  # строка обновления SCA стоит в разделе «Рекомендации»: только там её написание нормализуется
    recs = set(defect_where.variants(defect_where.HEADS["recommendations"]))
    for line in body.split("\n"):
        if first and line.strip():
            line, first = _neutral_phrase(line), False
        # только заголовки разделов отдельной строкой: текст оператора (обоснование, рекомендация), даже если похож на
        # подпись поля или строку обновления, сравнивается буквально (ревью Codex dev38, круги 2–4)
        for en, ru in pairs:
            if line == en:
                line = ru
                break
        if line in recs or line == defect_where.HEADS["recommendations"][0]:
            in_recs = True
        elif in_recs:
            for rx in upd:
                m = rx.fullmatch(line)
                if m:
                    line = upd_ru.format(component=m.group("component"), target=m.group("target"))
                    break
        out.append(line)
    return "\n".join(out)


def in_both_languages(build: Callable[[], Any]) -> list[Any]:
    """build() на русском и на английском – для сверки отпечатков текста дефекта (ADR-0158): отметка «Внесено в Hub»
    совпадает, если текст, собранный на любом из двух языков, совпал с отправленным."""
    out = []
    for lang in ("ru", "en"):
        with i18n.use(lang):
            out.append(build())
    return out


def sast_body(f: Finding, outcome: str, comment: str, fix: str, team: str = "", legacy_0910: bool = False,
              legacy_0911: bool = False) -> str:
    """Полный текст дефекта SAST (формат 0.9.6, ADR-0089) – классическая структура команды AppSec:

    После тщательного анализа уязвимости команда <команда> приняла решение присвоить данной уязвимости категорию
    True Positive.

    Обоснование:
    <комментарий оператора: откуда приходят данные, что за ошибка и чем опасна>

    Рекомендация:
    1) …
    2) …

    Рекомендации – только пункты оператора (поле «Рекомендация» решения, ADR-0092); без них текст не готовится.
    Внутренних номеров Hub, требований ГОСТ к конвейеру, срока и справки по CWE в тексте нет: сведения об объекте
    сканирования и находки, из которых создан дефект, Hub показывает сам. f в тексте не участвует (заголовок – sast_title).
    Обоснование – как написал оператор (первая буква заглавная, ADR-0101 п. 7), пункты – меры словами (ADR-0098);
    других правок текста оператора нет.
    legacy_0910 – текст по правилам 0.9.6–0.9.10 (обоснование без поднятой первой буквы, маркер «N)» только с пробелом),
    legacy_0911 – по правилам 0.9.11–0.10.0.dev20 (вводное слово снято, прежняя чистка): только для узнавания отметок
    «Внесено в Hub», поставленных до 0.9.11 и до 0.10.0.dev21."""
    if not sast_ready(outcome):
        raise ValueError(i18n._("дефект SAST готовится только для подтверждённой находки (итог «истинная»)"))
    if not has_recommendation(fix):
        raise ValueError(i18n._("дефект SAST готовится только с рекомендацией оператора (ADR-0092)"))
    if legacy_0910 or legacy_0911:
        # прежние форматы – только узнавание отметок, поставленных до dev38: русский текст при любом языке интерфейса
        with i18n.use("ru"):
            return _sast_body(outcome, comment, fix, team, legacy_0910, legacy_0911)
    return _sast_body(outcome, comment, fix, team, False, False)


def _sast_body(outcome: str, comment: str, fix: str, team: str, legacy_0910: bool, legacy_0911: bool) -> str:
    if legacy_0910:
        reason = reason_text(comment, clean=True, legacy=True)
        items = recommendation_points(fix, _LIST_ITEM_0910, clean=True)[0]
    elif legacy_0911:
        reason, items = sast_reason(comment, legacy=True), fix_items(fix, clean=True)
    else:
        reason, items = sast_reason(comment), fix_items(fix)
    parts = [_phrase(team, outcome), "", defect_where.head("reason"), reason or i18n._(NO_INFO), "",
             defect_where.head("recommendation")]
    parts += [_point(n, item) for n, item in enumerate(items, 1)]
    return _finish("\n".join(parts), clean=legacy_0910 or legacy_0911)


def _point(n: int, item: str) -> str:
    """Пункт рекомендации с номером: отступ строки оператора – в начале строки, перед номером (ADR-0149 п. 5), чтобы
    он остался виден в Hub (command_html переводит в неразрывные пробелы отступ в начале строки)."""
    text = item.lstrip(" ")
    return f"{item[:len(item) - len(text)]}{n}) {text}"


# ============================================================================ SCA

def fmt_cvss(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return i18n._(NO_INFO)
    return f"{number:.1f}"


def sca_conclusion(rows: list[Finding], outcome: str, kapo_state: str, *, ids_text: str, area: str = "",
                   catalog: Mapping[str, Mapping[str, Any]] | None = None,
                   capec_names: Mapping[str, str] | None = None) -> str:
    """Заключение AppSec для дефекта SCA по группе (одна библиотека и версия, одинаковые итог и уточнение у всех
    участников): статус по ГОСТ Р КАПО, критичность, область, что обнаружено (пути зависимости по выгрузке), что не
    установлено и что требуется, нормативная опора, справка по CWE. Обоснования участников – в их блоках
    («Объяснение»), поэтому текст одинаков, из какой бы карточки группы его ни открыли."""
    first = rows[0]
    ids_text = hub_clean(one_line(ids_text, 600)) or "уязвимость"
    # короткое имя пакета, как у заголовка и тела дефекта SCA (ADR-0150): у Maven по сведениям Hub – artifactId
    component = hub_clean(one_line(first.package_display_name, 200)) or "компонент"
    named = f"{component} {hub_clean(one_line(first.version, 100))}".strip()
    state = effective_kapo(outcome, kapo_state if kapo_state in KAPO_LABELS else "")
    if outcome == "false_positive":
        head = f"Заключение AppSec: ложноположительное срабатывание (ГОСТ Р КАПО, п. 6.12): {ids_text} в {named} не подтверждена."
    else:
        head = (f"Заключение AppSec: по выгрузке Hub в продукте используется компонент {named} с известной уязвимостью "
                f"{ids_text}. Статус уязвимости по ГОСТ Р КАПО: {KAPO_LABELS.get(state, 'не указан')}.")
    lines = [head]
    scores = [r.cvss for r in rows if r.cvss is not None]
    if outcome == "false_positive":
        lines.append("Критичность: не оценивалась – уязвимость в компоненте не подтверждена.")
    elif scores:
        lines.append("Критичность: не определена – оценка по регламенту КАПО не выполнена; CVSS по выгрузке Hub – до "
                     f"{cvss.number(max(scores))} (версия CVSS и источник в выгрузке не указаны).")
    else:
        lines.append("Критичность: не определена – оценки CVSS в выгрузке нет, оценка по регламенту КАПО не выполнена.")
    if area:
        lines.append(area)
    paths = [f"- {hub_clean(one_line(r.hub_id, 40))}: {hub_clean(one_line(r.dep_path, 400))}" for r in rows
             if one_line(r.dep_path)]
    if paths:
        lines += ["Что обнаружено (пути зависимости по выгрузке Hub):", *paths]
    if outcome == "true_positive" and state == "actual":
        lines.append("Требуется от разработчика – принять компенсирующие меры: 1) применить обновление безопасности – "
                     f"обновить {component} до безопасной версии (см. рекомендации ниже); 2) если обновить нельзя – "
                     "обратиться к поставщику, заменить компонент или доработать его самостоятельно; 3) если обновить "
                     "сейчас нельзя – описать организационно-технические меры (временные ограничения или условия "
                     "эксплуатации) и срок устранения. После мер статус уязвимости уточняется: нейтрализована или "
                     "устранена. " + DEADLINE_SCA)
    elif outcome == "true_positive":
        lines.append("Что не установлено: используется ли в продукте уязвимый код компонента и может ли нарушитель "
                     "влиять на его входные данные.")
        lines.append("Требуется от разработчика – выбрать одно: 1) применить обновление безопасности – обновить "
                     f"{component} до безопасной версии (см. рекомендации ниже); 2) если обновить нельзя – обратиться к "
                     "поставщику, заменить компонент или доработать его самостоятельно; 3) представить обоснование "
                     "неактуальности уязвимости; 4) если уязвимость актуальна, а обновить сейчас нельзя – описать "
                     "организационно-технические меры (временные ограничения или условия эксплуатации) и срок "
                     "устранения. " + DEADLINE_SCA)
        lines.append(NOT_ACTUAL_PROOF)
    lines.append(GOST_KAPO_BASIS)
    reference = reference_block([c for r in rows for c in r.cwe], catalog or {}, capec_names)
    if reference:
        lines += ["", reference]
    return "\n".join(lines)
