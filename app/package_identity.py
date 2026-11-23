"""Идентичность пакета SCA – из сведений Hub о библиотеке (бэклог 92, план dev17, п. 3 и 4.2).

Эффективная идентичность пакета – тройка (экосистема, имя, версия). Экосистема и имя определяются по объекту
`detail.library = {groupId, name, version, …}` из принятого состояния Hub текущего назначения; колонка Type и имя
компонента выгрузки – запасной источник. Версия всегда из находки: она входит в ключи и задание, расхождение с
`library.version` только отмечается.

Правило – чистая функция `resolve`. Строки таблицы правила (T – экосистема по Type, G – groupId с раскрытым `%40`,
N – library.name, C – компонент выгрузки):

1. нет `library` – (T, C), источник `file`;
2. N пусто – (T, C), `file`, пометка `no_name`;
3. T ∈ {пусто, maven, npm}, G – область npm (`@…`) – npm: N без области → G/N; N с той же областью → N; с другой
   областью → N как есть и `scope_conflict:G`;
4. T ∈ {пусто, maven, npm}, G непусто и не область – maven: N без «:» → G:N; N, начинающееся с «G:», → N; N с
   другой группой → N как есть и `group_conflict:G`;
5. T ∈ {пусто, maven, npm}, G пусто – (T, N), `hub`; при N ≠ C – `name_replaced:C`;
6. T – другая известная экосистема – (T, C), `file`; при непустом G – `rule_missing:T:G`;
у всех строк с `library`: непустая `library.version`, не равная версии находки, – `version_mismatch:<версия>`.

Пустое имя не синтезируется в `@scope/` или `G:`; имя, уже содержащее область или группу, повторно не дополняется.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import unquote

from app import i18n
from app.ecosystem import canon_ecosystem

SOURCES = ("", "file", "hub")
# экосистемы, для которых правило проверено на данных (план dev17, п. 2)
RULED = frozenset(("", "maven", "npm"))


@dataclass(frozen=True)
class Package:
    """Итог правила: экосистема и имя пакета, источник (`file` | `hub`) и пометки (коды, порядок – по правилу)."""

    ecosystem: str
    name: str
    source: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        """Пометки для колонки `findings.pkg_note` – через «;»."""
        return ";".join(self.notes)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def resolve(build_type: Any, component: Any, version: Any, library: Mapping[str, Any] | None) -> Package:
    """Правило п. 3 плана dev17 – по Type выгрузки, компоненту и версии находки и объекту `library` Hub (или None)."""
    t = canon_ecosystem(build_type)
    c = _text(component)
    if not isinstance(library, Mapping):
        return Package(t, c, "file")
    g = unquote(_text(library.get("groupId")))
    n = _text(library.get("name"))
    lib_version = _text(library.get("version"))
    tail = (f"version_mismatch:{lib_version}",) if lib_version and lib_version != _text(version) else ()
    if not n:
        return Package(t, c, "file", ("no_name",) + tail)
    if t not in RULED:
        return Package(t, c, "file", ((f"rule_missing:{t}:{g}",) if g else ()) + tail)
    if g.startswith("@"):
        if not n.startswith("@"):
            return Package("npm", f"{g}/{n}", "hub", tail)
        if n.split("/", 1)[0] == g:
            return Package("npm", n, "hub", tail)
        return Package("npm", n, "hub", (f"scope_conflict:{g}",) + tail)
    if g:
        if ":" not in n:
            return Package("maven", f"{g}:{n}", "hub", tail)
        if n.startswith(f"{g}:"):
            return Package("maven", n, "hub", tail)
        return Package("maven", n, "hub", (f"group_conflict:{g}",) + tail)
    return Package(t, n, "hub", ((f"name_replaced:{c}",) if n != c else ()) + tail)


def of(data: Mapping[str, Any] | None) -> tuple[str, str, str]:
    """Эффективная тройка (экосистема, имя, версия) по данным находки с ключом `package` (`with_package`): источник
    `hub` – колонки `pkg_*`; иначе – Type и компонент выгрузки."""
    data = data or {}
    pkg = data.get("package") or {}
    # строки выгрузки – как их читал прежний код (str без обрезки): без сведений Hub тройка, ключи и отпечатки
    # байт в байт прежние (ревью Kimi, шаг 3)
    version = str(data.get("version") or "")
    if pkg.get("source") == "hub":
        return _text(pkg.get("ecosystem")), _text(pkg.get("name")), version
    return canon_ecosystem(data.get("build_type")), str(data.get("component") or ""), version


def name_of(data: Mapping[str, Any] | None) -> str:
    """Эффективное имя пакета."""
    return of(data)[1]


def marks(data: Mapping[str, Any] | None) -> list[str]:
    """Коды пометок `pkg_note` находки (пусто – пометок нет)."""
    note = _text(((data or {}).get("package") or {}).get("note"))
    return [part for part in note.split(";") if part]


MARK_LABELS = i18n.Labels({"ecosystem": "экосистема уточнена по Hub", "coordinates": "координаты дополнены по Hub",
                           "name": "имя по Hub", "conflict": "область (группа) не совпадает с groupId Hub",
                           "rule_missing": "правило для экосистемы не задано", "no_name": "нет имени библиотеки",
                           "version": "версия по Hub другая"})


def mark_items(data: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """Пометки для оператора (план dev17, п. 4.6) – пары (вид из MARK_LABELS, текст): чем эффективная идентичность
    отличается от выгрузки и что сказано в `pkg_note`. Без сведений Hub и без пометок – пустой список."""
    data = data or {}
    pkg = data.get("package") or {}
    codes = marks(data)
    out: list[tuple[str, str]] = []
    if pkg.get("source") == "hub":
        exported_eco, exported = canon_ecosystem(data.get("build_type")), _text(data.get("component"))
        eco, name = _text(pkg.get("ecosystem")), _text(pkg.get("name"))
        if eco != exported_eco:
            out.append(("ecosystem", i18n._("экосистема уточнена по Hub: в выгрузке – {value}",
                                            value=exported_eco or i18n._("не указана"))))
        replaced = any(code.startswith("name_replaced:") for code in codes)
        if name != exported and not replaced:
            if exported and name.endswith((f":{exported}", f"/{exported}")):
                out.append(("coordinates", i18n._("координаты дополнены по Hub: в выгрузке – {value}", value=exported)))
            else:  # имя по Hub другое и при непустом groupId (ревью Codex, круг 3)
                out.append(("name", i18n._("имя по Hub: в выгрузке – {value}", value=exported or i18n._("не указано"))))
    for code in codes:
        kind, _, rest = code.partition(":")
        if kind == "name_replaced":
            out.append(("name", i18n._("имя по Hub: в выгрузке – {value}", value=rest)))
        elif kind in ("scope_conflict", "group_conflict"):
            out.append(("conflict", i18n._("область (группа) в имени не совпадает с groupId Hub ({value})", value=rest)))
        elif kind == "rule_missing":
            eco, _, group = rest.partition(":")
            out.append(("rule_missing", i18n._("у Hub есть groupId ({group}), правило для {ecosystem} не задано",
                                               group=group, ecosystem=eco)))
        elif kind == "no_name":
            out.append(("no_name", i18n._("в сведениях Hub нет имени библиотеки")))
        elif kind == "version_mismatch":
            out.append(("version", i18n._("версия по Hub – {value}", value=rest)))
    return out


def mark_texts(data: Mapping[str, Any] | None) -> list[str]:
    """Тексты пометок для оператора (план dev17, п. 4.6)."""
    return [text for _, text in mark_items(data)]


PKG_COLUMNS = ("pkg_ecosystem", "pkg_name", "pkg_source", "pkg_note", "pkg_scope")


def package_of_row(row: Mapping[str, Any]) -> dict[str, str]:
    """Колонки `pkg_*` строки `findings` -> словарь `package` (ключи без префикса); колонок нет – пустые значения."""
    return {col[len("pkg_"):]: _text(row.get(col)) for col in PKG_COLUMNS}


def with_package(row: Mapping[str, Any], data: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Данные находки с ключом `package` по колонкам `pkg_*` строки (план dev17, п. 4.2: `with_package(row) -> data`):
    для чтений с явным SELECT. Данные – `data`, иначе разобранный `row["data"]` или `row["data_json"]`. Исходные
    словари не меняются."""
    if data is None:
        raw = row.get("data")
        if raw is None:
            raw = row.get("data_json")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = {}
        data = raw if isinstance(raw, Mapping) else {}
    return {**data, "package": package_of_row(row)}


def display_name(data: Mapping[str, Any] | None) -> str:
    """Короткое имя для текстов Hub (заголовок дефекта – прежний): у Maven с
    координатами – artifactId без группы (`spring-core`), у остальных – эффективное имя (`@angular/core`)."""
    ecosystem, name, _ = of(data)
    # без сведений Hub – компонент выгрузки как есть: заголовки и тексты существующих дефектов не меняются
    if ((data or {}).get("package") or {}).get("source") != "hub":
        return name
    if ecosystem == "maven" and ":" in name:
        return name.rsplit(":", 1)[1] or name
    return name
