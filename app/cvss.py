"""Оценка CVSS: версия, диапазоны, отбор и сортировка для таблицы SCA.

Модуль чистый: ни базы, ни запросов, ни шаблонов. Разбирает сохранённые сведения об оценке (балл и прочие
колонки выгрузки в пакете от app/db.py) и работает со списком пакетов, который собирает app/sca.py.

Версия оценки отдельным полем не хранится: у находки есть только балл (Finding.cvss, app/models.py) и
прочие колонки выгрузки (Finding.extra). Поэтому версия определяется только по тому, что действительно есть
в этих данных: по вектору оценки («CVSS:3.1/AV:N/AC:L/...», у второй версии вектор идёт без префикса) и по
отдельной колонке, где версия записана своим значением («CVSS version», «Версия CVSS»). Вектор принимается
только целиком корректный, а из колонки берётся только значение, целиком равное версии: «3.1» – версия
оценки, «3.1.5» – версия компонента, а не оценки. Если указания противоречат друг другу или ничего похожего
нет, версия неизвестна: объявлять 3.1 там, где её нет, нельзя, и пересчитывать 3.1 в 4.0 тоже – метрики
разных версий считаются по-разным правилам, молчаливая подмена искажает балл. Распознаются 2.0, 3.0, 3.1
и 4.0; появление новой версии потребует описать её здесь (VERSIONS, _METRICS, _EXTRA) и в списке выбора.
"""

from __future__ import annotations

import math
import re
from typing import Any, Iterable, Mapping

from app import i18n

UNKNOWN = ""  # версия оценки не указана (ключ в сохранённых данных)
UNKNOWN_CHOICE = "?"  # значение параметра cvss_version для отбора «только оценки без версии»
# Порядок для показа и разбора: 3.1 – основная версия пользователя, дальше остальные известные; в выпадающем
# списке и в разборе баллов пакета оценки идут именно в таком порядке
VERSIONS = ("3.1", "3.0", "4.0", "2.0")
VERSION_LABELS = i18n.Labels({UNKNOWN: "версия не указана", UNKNOWN_CHOICE: "версия не указана", "3.1": "CVSS 3.1",
                              "3.0": "CVSS 3.0", "4.0": "CVSS 4.0", "2.0": "CVSS 2.0"})
CHOICES = (*VERSIONS, UNKNOWN_CHOICE)  # значения параметра cvss_version; "" – все версии вместе
SORTS = ("cvss_asc", "cvss_desc")
SORT_LABELS = i18n.Labels({UNKNOWN: "как в отчёте", "cvss_asc": "CVSS: по возрастанию",
                           "cvss_desc": "CVSS: по убыванию"})
EPS = 1e-9  # балл CVSS – число с одним знаком: сравниваем с допуском, чтобы 3,9 не уехало за границу

# Базовые метрики версии и их допустимые значения (FIRST: спецификации 3.1, 4.0 и второй версии). Имя метрики
# сравнивается без учёта регистра, значение – в верхнем регистре
_METRICS: dict[str, dict[str, tuple[str, ...]]] = {
    "2.0": {"AV": ("N", "A", "L"), "AC": ("H", "M", "L"), "AU": ("M", "S", "N"),
            "C": ("N", "P", "C"), "I": ("N", "P", "C"), "A": ("N", "P", "C")},
    "3.1": {"AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "PR": ("N", "L", "H"), "UI": ("N", "R"),
            "S": ("U", "C"), "C": ("H", "L", "N"), "I": ("H", "L", "N"), "A": ("H", "L", "N")},
    "4.0": {"AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"), "PR": ("N", "L", "H"),
            "UI": ("N", "P", "A"), "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
            "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N")},
}
_METRICS["3.0"] = _METRICS["3.1"]  # имена и значения метрик у 3.0 и 3.1 совпадают
# Дополнительные метрики тоже проверяются по значениям. Это распознавание формата, не расчёт балла.
# Источники: FIRST CVSS 2, раздел 2.4; CVSS 3.1, раздел 6; CVSS 4.0, раздел 7.
# https://www.first.org/cvss/v2/guide
# https://www.first.org/cvss/v3-1/specification-document
# https://www.first.org/cvss/v4.0/specification-document
_EXTRA: dict[str, dict[str, tuple[str, ...]]] = {
    "2.0": {
        "E": ("ND", "U", "POC", "F", "H"), "RL": ("ND", "OF", "TF", "W", "U"),
        "RC": ("ND", "UC", "UR", "C"), "CDP": ("ND", "N", "L", "LM", "MH", "H"),
        "TD": ("ND", "N", "L", "M", "H"), "CR": ("ND", "L", "M", "H"),
        "IR": ("ND", "L", "M", "H"), "AR": ("ND", "L", "M", "H"),
    },
    "3.1": {
        "E": tuple("XUPFH"), "RL": tuple("XOTWU"), "RC": tuple("XURC"),
        "CR": tuple("XLMH"), "IR": tuple("XLMH"), "AR": tuple("XLMH"),
        "MAV": tuple("XNALP"), "MAC": tuple("XLH"), "MPR": tuple("XNLH"), "MUI": tuple("XNR"),
        "MS": tuple("XUC"), "MC": tuple("XNLH"), "MI": tuple("XNLH"), "MA": tuple("XNLH"),
    },
    "4.0": {
        "E": tuple("XAPU"), "CR": tuple("XHML"), "IR": tuple("XHML"), "AR": tuple("XHML"),
        "MAV": tuple("XNALP"), "MAC": tuple("XLH"), "MAT": tuple("XNP"), "MPR": tuple("XNLH"),
        "MUI": tuple("XNPA"), "MVC": tuple("XNLH"), "MVI": tuple("XNLH"), "MVA": tuple("XNLH"),
        "MSC": tuple("XNLH"), "MSI": tuple("XNLHS"), "MSA": tuple("XNLHS"),
        "S": tuple("XNP"), "AU": tuple("XNY"), "R": tuple("XAUI"), "V": tuple("XDC"),
        "RE": tuple("XLMH"), "U": ("X", "CLEAR", "GREEN", "AMBER", "RED"),
    },
}
_EXTRA["3.0"] = _EXTRA["3.1"]
# Вектор с префиксом версии: «CVSS:3.1/AV:N/…», «CVSS:4.0/AT:N/…»
_VECTOR = re.compile(r"^\s*CVSS\s*:\s*v?([234][.][0-9])\s*/", re.IGNORECASE)
# Одна метрика вектора: «AV:N»
_METRIC = re.compile(r"^([A-Za-z]{1,3})\s*:\s*([A-Za-z0-9]{1,5})$")
# Заголовок колонки, где версия оценки записана своим значением: «CVSS version», «Версия CVSS», «CVSS»
_HEAD_VERSION = re.compile(r"верси|version", re.IGNORECASE)
_HEAD_CVSS = re.compile(r"cvss", re.IGNORECASE)
# Чужая версия: версия компонента, библиотеки, пакета и тому подобного – это не версия оценки
_HEAD_SUBJECT = re.compile(r"компонент|component|библиотек|библиотека|library|пакет|package|модул|module|"
                           r"зависимост|dependency|плагин|plugin|приложен|application|сервис|service",
                           re.IGNORECASE)
# Значение, целиком равное версии: «3.1», «v4.0», «CVSS 3.0». Без десятых («3») не берём: 3.0 и 3.1 –
# разные шкалы, а «3.1.5» – это уже версия компонента
_VERSION_TEXT = re.compile(r"(?:cvss[\s\-]*)?v?([234])[.](\d)", re.IGNORECASE)

# Диапазоны CVSS 3.x и 4.0 совпадают. У второй версии верхняя граница «высокого» – 10, а «критического» нет:
# пометка «Критический» у оценки 2.0 была бы баллом по чужой шкале. Подписи – msgid, перевод в bands()
_ZERO, _LOW, _MEDIUM = i18n.N_("Нулевой"), i18n.N_("Низкий"), i18n.N_("Средний")
_HIGH, _CRITICAL = i18n.N_("Высокий"), i18n.N_("Критический")
_BANDS = {
    UNKNOWN: (("zero", _ZERO, 0.0, 0.0), ("low", _LOW, 0.1, 3.9), ("medium", _MEDIUM, 4.0, 6.9),
              ("high", _HIGH, 7.0, 8.9), ("critical", _CRITICAL, 9.0, 10.0)),
    UNKNOWN_CHOICE: (("zero", _ZERO, 0.0, 0.0), ("low", _LOW, 0.1, 3.9), ("medium", _MEDIUM, 4.0, 6.9),
                     ("high", _HIGH, 7.0, 8.9), ("critical", _CRITICAL, 9.0, 10.0)),
    "2.0": (("low", _LOW, 0.0, 3.9), ("medium", _MEDIUM, 4.0, 6.9), ("high", _HIGH, 7.0, 10.0)),
}
_CASES = ("cvss", "cvss_min", "cvss_max", "cvss_version", "sort")


def _supported(value: str) -> str:
    return value if value in VERSIONS else UNKNOWN


def _complete_vector(body: str, version: str) -> str:
    """Версия, если тело вектора этой версии корректно: все базовые метрики на месте со своими значениями,
    дополнительные допустимы, повторов и постороннего текста нет."""
    metrics = _METRICS.get(version) or {}
    extra = _EXTRA.get(version) or {}
    seen: set[str] = set()
    order = {name: i for i, name in enumerate((*metrics, *extra))}
    previous = -1
    for part in body.split("/"):
        pair = _METRIC.match(part.strip())
        if not pair:
            return UNKNOWN
        metric, value = pair.group(1).upper(), pair.group(2).upper()
        if metric in seen:
            return UNKNOWN  # повтор метрики: вектор невалиден
        seen.add(metric)
        if value not in metrics.get(metric, extra.get(metric, ())):
            return UNKNOWN
        # В отличие от 3.x, CVSS 4.0 прямо запрещает другой порядок (FIRST, таблица 23).
        if version == "4.0":
            current = order[metric]
            if current <= previous:
                return UNKNOWN
            previous = current
    return version if seen.issuperset(metrics) else UNKNOWN


def _vector_version(text: str) -> str:
    """Версия оценки из вектора – только из вектора, целиком соответствующего своей версии. Обрывок вроде
    «CVSS:3.1garbage», вектор без обязательных метрик и вектор с чужим значением версией не считаются."""
    match = _VECTOR.match(text)
    if match:
        version = _supported(match.group(1))
        return _complete_vector(text[match.end():], version) if version else UNKNOWN
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()  # распространённая обёртка вектора 2.0 в выгрузках
    return _complete_vector(text, "2.0")  # вектор второй версии идёт без префикса CVSS


def clean_version(text: Any) -> str:
    """Версия оценки из текста, если значение целиком версия: «3.1», «v4.0», «CVSS 3.0». «3.1.5» – версия
    компонента, а не оценки; без десятых («3») и несуществующие версии тоже не подходят."""
    match = _VERSION_TEXT.fullmatch(str(text or "").strip())
    return _supported(f"{match.group(1)}.{match.group(2)}") if match else UNKNOWN


def version_from_column(header: Any, value: Any) -> str:
    """Версия только из явно обозначенной колонки CVSS. Голое «Version» и число в «CVSS»
    неоднозначны: это может быть версия компонента или сам балл, поэтому их не используем."""
    head = str(header or "")
    text = str(value or "").strip()
    if _HEAD_SUBJECT.search(head):
        return UNKNOWN
    if _HEAD_CVSS.search(head) and _HEAD_VERSION.search(head):
        return clean_version(text)
    if head.strip().casefold() == "cvss" and text.casefold().startswith("cvss"):
        return clean_version(text)  # «CVSS 3.1» явно обозначает версию, число 3.1 – нет
    return UNKNOWN


def version_from_extra(extra: Mapping[str, Any] | None) -> str:
    """Версия оценки по прочим колонкам выгрузки находки: вектор с префиксом версии, вектор второй версии
    или колонка, где версия записана целиком. Порядок колонок в файле ничего не решает: если указания
    противоречат друг другу (версия 3.1 в колонке и корректный вектор 4.0), версия остаётся неизвестной –
    одному сохранённому баллу произвольную версию присваивать нельзя."""
    pairs = [(str(head or ""), str(value or "").strip()) for head, value in (extra or {}).items()]
    found = {version for _, text in pairs for version in (_vector_version(text),) if version}
    found |= {version for head, text in pairs for version in (version_from_column(head, text),) if version}
    return found.pop() if len(found) == 1 else UNKNOWN


def version_of(finding: Mapping[str, Any] | None) -> str:
    """Версия оценки находки (её saved-сведения: extra с прочими колонками выгрузки)."""
    return version_from_extra((finding or {}).get("extra"))


def number(value: float) -> str:
    """Балл в виде подписи: 9.8 -> «9,8», 7.0 -> «7»."""
    return f"{value:g}".replace(".", ",")


def bands(version: str = UNKNOWN) -> list[dict]:
    """Готовые диапазоны для версии: у 2.0 своя разметка, у 3.x и 4.0 – общая. Подпись границ выводится из
    самих границ диапазона, поэтому у второй версии «высокий» – это 7–10, а не 7–8,9 от другой шкалы."""
    return [{"key": key, "label": i18n._(label), "min": low, "max": high, "title": _band_title(low, high)}
            for key, label, low, high in _BANDS.get(version, _BANDS[UNKNOWN])]


def _band_title(low: float, high: float) -> str:
    return number(low) if low == high else f"{number(low)}–{number(high)}"


def version_title(version: str) -> str:
    """Как подписать версию в подсказке ячейки балла: у известной – «CVSS 3.1», у неизвестной – честно, что
    версия не указана; без выбора версии подписи нет вовсе (балл тогда наибольший из всех версий)."""
    if not version:
        return ""
    return f"CVSS {version}" if version in VERSIONS else i18n._("без указания версии")


def presets(version: str = UNKNOWN) -> list[dict]:
    """Готовые отборы: диапазоны версии, «строго больше 7» и «7 и выше» отдельно друг от друга, оценка
    без балла. Пороги организационного правила (строго больше 7) и шкалы (7 и выше) не смешиваются."""
    items = bands(version)
    items.append({"key": "above7", "label": i18n._("Строго больше 7"), "min": 7.0, "max": 10.0, "open_min": True,
                  "title": i18n._("больше 7")})
    items.append({"key": "from7", "label": i18n._("7 и выше"), "min": 7.0, "max": 10.0, "title": "7–10"})
    items.append({"key": "no_score", "label": i18n._("Без оценки"), "min": None, "max": None,
                  "title": i18n._("оценки нет")})
    return items


def preset(version: str, key: str) -> dict | None:
    """Готовый отбор по ключу для версии; None – такого отбора для этой версии нет."""
    for item in presets(version):
        if item["key"] == key:
            return item
    return None


def matches(score: float | None, item: Mapping[str, Any]) -> bool:
    """Балл попадает в отбор: «Без оценки» ловит только отсутствие балла, остальное – границы включительно,
    кроме «строго больше 7», где нижняя граница открыта."""
    if item.get("key") == "no_score":
        return score is None
    if score is None:
        return False
    if item.get("open_min"):
        return score > float(item["min"]) + EPS and score <= float(item["max"]) + EPS
    return float(item["min"]) - EPS <= score <= float(item["max"]) + EPS


def score_of(group: Mapping[str, Any], version: str = UNKNOWN) -> float | None:
    """Балл пакета для выбранной версии: без выбора – наибольший из всех оценок пакета, с выбором – только
    оценки этой версии (у UNKNOWN_CHOICE – оценки с неизвестной версией). Оценки других версий вместо неё не
    подставляются, поэтому под выбранной версией пакет без оценок этой версии не показывается вовсе."""
    scores = group.get("cvss_versions") or {}
    if version:
        return scores.get(UNKNOWN if version == UNKNOWN_CHOICE else version)
    known = [value for value in scores.values() if value is not None]
    return max(known) if known else None


def breakdown(group: Mapping[str, Any]) -> list[dict]:
    """Разбор баллов пакета по версиям: [{version, label, score, count}], известные версии по порядку
    VERSIONS, оценки с неизвестной версией – последними. Пустой список – баллов у пакета нет."""
    counts = group.get("cvss_counts") or {}
    items = [{"version": version, "label": VERSION_LABELS[version], "score": score,
              "count": int(counts.get(version) or 0)}
             for version, score in (group.get("cvss_versions") or {}).items()]
    order = {version: i for i, version in enumerate((*VERSIONS, UNKNOWN))}
    return sorted(items, key=lambda item: order.get(item["version"], len(order)))


def select(views: Iterable[Mapping[str, Any]], version: str = UNKNOWN,
           item: Mapping[str, Any] | None = None) -> list[dict]:
    """Отбор пакетов по баллу выбранной версии. Выбрана версия – отбор идёт по её баллу, и без отбора по баллу
    остаются пакеты, у которых такая оценка есть; «Без оценки» под выбранной версией означает «нет оценки этой
    версии». item – готовый отбор или свои границы, None – отбора по баллу нет."""
    views = list(views)
    if item is None:
        return [view for view in views if score_of(view, version) is not None] if version else views
    return [view for view in views if matches(score_of(view, version), item)]


def sort_views(views: Iterable[Mapping[str, Any]], version: str = UNKNOWN, sort: str = "") -> list[dict]:
    """Числовая сортировка по баллу выбранной версии: пакеты без балла в конце, при равных баллах – по
    названию. Пустой sort – порядок как в отчёте (срочные, затем по баллу, app/db.py)."""
    views = list(views)
    if sort not in SORTS:
        return views
    sign = 1.0 if sort == "cvss_asc" else -1.0
    def key(view: Mapping[str, Any]) -> tuple:
        score = score_of(view, version)
        return (score is None, (score or 0.0) * sign, str(view.get("component") or "").casefold(),
                str(view.get("version") or ""), str(view.get("ecosystem") or ""))
    return sorted(views, key=key)


def bound(value: Any, name: str, label: str) -> tuple[float | None, str]:
    """Граница диапазона из адреса страницы: число от 0 до 10, запятая как в русском Excel тоже; пусто –
    границы нет. Второе значение – сообщение об ошибке, оно пустое, когда всё в порядке."""
    text = str(value or "").strip().replace(",", ".")
    if not text:
        return None, ""
    try:
        score = float(text)
    except ValueError:
        return None, i18n._("«{name}» – {label} должна быть числом от 0 до 10, получено «{value}».", name=name,
                            label=i18n._(label), value=text)
    if not math.isfinite(score):
        return None, i18n._("«{name}» – {label} должна быть числом от 0 до 10.", name=name, label=i18n._(label))
    if not 0.0 <= score <= 10.0:
        return None, i18n._("«{name}» – {label} должна быть от 0 до 10, получено {value}.", name=name,
                            label=i18n._(label), value=number(score))
    if not math.isclose(score, round(score, 1), rel_tol=0, abs_tol=1e-12):
        return None, i18n._("«{name}» – {label} должна задаваться с шагом 0,1.", name=name, label=i18n._(label))
    return round(score, 1), ""


def parse(params: Mapping[str, str]) -> dict:
    """Разбор адреса страницы SCA: {"preset", "min", "max", "version", "sort", "active", "errors", "raw"}.
    Неверное значение не превращается в молчаливый отбор: параметр отбрасывается, а в errors – что
    показать человеку. Порядок разбора постоянный, поэтому список ошибок не зависит от порядка в адресе."""
    errors: list[str] = []
    raw = {name: str(params.get(name, "") or "").strip() for name in _CASES}
    version = raw["cvss_version"]
    if version and version not in CHOICES:
        errors.append(i18n._("Версия оценки «{version}» неизвестна – доступны: {choices}.", version=version,
                             choices=", ".join(VERSION_LABELS[v] for v in CHOICES)))
        version = UNKNOWN
    item = None
    preset_key = raw["cvss"]
    if preset_key:
        item = preset(version, preset_key)
        if item is None:
            known = preset(UNKNOWN, preset_key)  # отбор, который есть в шкале 3.x и 4.0
            if known:
                errors.append(i18n._("Отбор «{preset}» не применим к {version} – у этой версии такой шкалы нет.",
                                     preset=known["label"], version=VERSION_LABELS[version]))
            else:
                errors.append(i18n._("Отбор «{preset}» неизвестен – доступны: {choices}.", preset=preset_key,
                                     choices=", ".join(band["label"] for band in presets(version))))
            preset_key = UNKNOWN
    low, low_error = bound(raw["cvss_min"], "cvss_min", i18n.N_("нижняя граница"))
    high, high_error = bound(raw["cvss_max"], "cvss_max", i18n.N_("верхняя граница"))
    errors.extend(error for error in (low_error, high_error) if error)
    if low_error or high_error:
        # половину неверного диапазона применять нельзя: обе границы и готовый отбор из той же формы
        # отбрасываются, список показывается целиком, а что именно не так – в errors
        low, high, item, preset_key = None, None, None, UNKNOWN
    elif low is not None and high is not None and low > high:
        errors.append(i18n._("Нижняя граница {low} больше верхней {high} – такой отбор ничего не найдёт.",
                             low=number(low), high=number(high)))
        low, high, item, preset_key = None, None, None, UNKNOWN
    sort = raw["sort"]
    if sort and sort not in SORTS:
        errors.append(i18n._("Сортировка «{sort}» неизвестна – доступны: {choices}.", sort=sort,
                             choices=", ".join(SORT_LABELS[s] for s in SORTS)))
        sort = UNKNOWN
    return {"preset": preset_key, "item": item, "min": low, "max": high, "version": version, "sort": sort,
            "active": bool(preset_key or low is not None or high is not None or version), "errors": errors,
            "raw": raw}


def bounds_item(low: float | None, high: float | None) -> dict | None:
    """Свои границы как обычный отбор; ни одной границы – отбора нет."""
    if low is None and high is None:
        return None
    return {"key": "range", "min": 0.0 if low is None else low, "max": 10.0 if high is None else high}


def field_number(text: Any) -> str:
    """Значение границы для поля формы: десятичная запятая меняется на точку. Поле типа number запятую не
    показывает, и введённое значение пропало бы из формы молча, поэтому адрес и форма говорят одно и то же."""
    return str(text or "").strip().replace(",", ".")
