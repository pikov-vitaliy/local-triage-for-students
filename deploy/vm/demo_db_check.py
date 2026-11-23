# -*- coding: utf-8 -*-
"""Последняя проверка состава базы для образа ВМ: в базе только демо-проект на выдуманных данных.

Саму базу строит заново demo_db_build.py – только из демо-данных examples/demo (готовую базу не чистят
и не копируют). Эта проверка – последняя страховка перед упаковкой: она смотрит весь состав базы и отвергает
всё постороннее:

* ровно один проект, и его имя начинается с «Демо:»;
* во всех таблицах с колонкой project_id – только этот проект, у строк очереди прогонов – только его прогоны;
* таблицы – только из схемы приложения (неизвестная таблица в любой схеме базы – отказ);
* ID находок совпадают с ID из демо-выгрузки examples/demo (ни одной лишней и ни одной недостающей);
* выгрузки проекта – только демо-выгрузки examples/demo;
* ответы модели (verdicts) – только те, на которые ссылается демо-проект;
* соответствия AST → CVE – только для идентификаторов уязвимостей демо-находок;
* служебные значения (meta) – версия схемы и значения демо-проекта; настройки – только ключи интерфейса.

Принадлежность строки демо-проекту не доказывает, что её текст взят из демо: поэтому содержимое таблиц
не переносится из готовой базы, а создаётся заново (demo_db_build.py).

  python demo_db_check.py <src приложения> <строка подключения PostgreSQL>

Пароль – в переменной PGPASSWORD. Код возврата 0 – база принята (печатает состав в JSON); иначе – список причин
отказа. База только читается (соединение в режиме чтения).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEMO_PREFIX = "Демо:"
DEMO_DIR = ("examples", "demo")
# служебная таблица миграций: создаётся вместе со схемой, в манифест таблиц приложения не входит
SERVICE_TABLES = {"storage_migrations"}


class DemoDataError(ValueError):
    """База не годится для образа: problems – причины по-русски."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def demo_reports(src: Path) -> list[Path]:
    """Демо-выгрузки приложения: examples/demo/demo-hub-report*.xlsx."""
    return sorted(Path(src, *DEMO_DIR).glob("demo-hub-report*.xlsx"))


def expected_hub_ids(src: Path, report: str = "demo-hub-report.xlsx") -> set[str]:
    """ID находок демо-выгрузки (ту же выгрузку загружает кнопка «Создать демо-проект»)."""
    from app.hub_import import parse_workbook

    return {f.hub_id for f in parse_workbook(Path(src, *DEMO_DIR, report)).findings}


def connect(conninfo: str, *, read_only: bool = False) -> Any:
    """Соединение как у приложения: те же «?», строки результата и типы значений, что у Database."""
    from app.storage import postgresql

    conn = postgresql.Connection.connect(conninfo, cursor_factory=postgresql.Cursor, row_factory=postgresql.row_factory)
    postgresql._configure(conn)
    conn.commit()
    conn.read_only = read_only
    return conn


# ADR-0133: справочники и ключи – таблицы приложения вне схемы public
LOCAL_STATE_TABLES = {"app_state.secrets", "feeds.feed_meta"} | {
    f"{schema}.{table}" for schema in ("feeds", "feeds_imp")
    for table in ("bdu", "bdu_cve", "cwe_ru", "cwe", "cwe_refs", "cwe_links", "cwe_index", "cwe_capec",
                  "capec", "capec_index", "capec_refs", "capec_links", "capec_cwe", "capec_meta")}


def table_names(con: Any) -> list[str]:
    """Таблицы базы: в схеме public – по имени, в других схемах – со схемой (приложению они не принадлежат)."""
    return [row[0] if row[1] == "public" else f"{row[1]}.{row[0]}" for row in con.execute(
        "SELECT table_name, table_schema FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
        " AND table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY table_schema, table_name")]


def _layout() -> set[str]:
    from app.db import _expected_layout

    return set(_expected_layout())


def _settings_keys() -> set[str]:
    from app.config import EDITABLE_SETTINGS, STORED_SETTINGS

    # STORED_SETTINGS – профили провайдеров по умолчанию (ADR-0102): их пишет запуск вместе с профилем 1
    return set(EDITABLE_SETTINGS) | set(STORED_SETTINGS)


def _columns(con: Any, table: str) -> set[str]:
    return {row[0] for row in con.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ?", (table,))}


def _ids_of(data_json: str) -> set[str]:
    try:
        data = json.loads(data_json or "{}")
    except ValueError:
        return set()
    return {str(x).strip().casefold() for key in ("cve", "vuln_ids") for x in data.get(key) or [] if str(x).strip()}


def composition_problems(con: Any, expected_ids: set[str], report_names: set[str],
                         known_tables: set[str] | None = None, settings_keys: set[str] | None = None) -> list[str]:
    """Причины, по которым база не годится для образа; пустой список – годится."""
    known_tables = _layout() if known_tables is None else known_tables
    settings_keys = _settings_keys() if settings_keys is None else settings_keys
    problems: list[str] = []
    tables = table_names(con)
    unknown = sorted(t for t in tables if t not in known_tables and t not in SERVICE_TABLES and t not in LOCAL_STATE_TABLES)
    if unknown:
        problems.append(f"таблицы не из схемы приложения: {', '.join(unknown)}")
    if "app_state.secrets" in tables and not con.execute("SELECT 1 FROM app_state.secrets WHERE name = 'mask_key'").fetchone():
        problems.append("в базе нет ключа маскирования: вердикты демо разошлись бы с новым ключом")
    projects = con.execute("SELECT id, name FROM projects ORDER BY id").fetchall()
    demo = [p for p in projects if str(p[1]).startswith(DEMO_PREFIX)]
    if len(projects) != 1 or len(demo) != 1:
        problems.append(f"проектов в базе: {len(projects)}, демо-проектов: {len(demo)}; нужен ровно один "
                        "демо-проект и больше ничего")
        return problems
    pid = int(demo[0][0])
    for table in tables:
        if table in SERVICE_TABLES or table not in known_tables or table == "projects":
            continue
        if "project_id" in _columns(con, table):
            n = con.execute(f'SELECT COUNT(*) FROM "{table}" WHERE project_id IS DISTINCT FROM ?', (pid,)).fetchone()[0]
            if n:
                problems.append(f"в таблице {table} строки не демо-проекта: {n}")
    for child in ('run_items', 'run_journal'):
        if child not in tables:
            continue
        n = con.execute(f"SELECT COUNT(*) FROM {child} WHERE run_id NOT IN (SELECT id FROM runs WHERE project_id = ?)",
                        (pid,)).fetchone()[0]
        if n:
            problems.append(f"в очереди/журнале {child} строки чужих прогонов: {n}")
    found = {row[0] for row in con.execute("SELECT hub_id FROM findings WHERE project_id = ?", (pid,))}
    if found != expected_ids:
        extra, missing = sorted(found - expected_ids), sorted(expected_ids - found)
        problems.append("находки не совпадают с демо-выгрузкой"
                        + (f": лишние {', '.join(extra[:10])}" if extra else "")
                        + (f"; нет {', '.join(missing[:10])}" if missing else ""))
    names = {row[0] for row in con.execute("SELECT filename FROM imports")}
    if names - report_names:
        problems.append(f"выгрузки не из демо: {len(names - report_names)}")
    refs = set()
    for sql in ("SELECT verdict_id FROM cases", "SELECT verdict_id FROM reviews", "SELECT verdict_id FROM questions",
                "SELECT verdict_id FROM run_items"):
        refs |= {row[0] for row in con.execute(sql) if row[0] is not None}
    stray = [row[0] for row in con.execute("SELECT id FROM verdicts") if row[0] not in refs]
    if stray:
        problems.append(f"ответы модели, на которые демо-проект не ссылается: {len(stray)}")
    if "ast_map" in tables:
        ids = set()
        for (data_json,) in con.execute("SELECT data_json FROM findings WHERE project_id = ?", (pid,)):
            ids |= _ids_of(data_json)
        n = sum(1 for (ast_id,) in con.execute("SELECT ast_id FROM ast_map")
                if str(ast_id).strip().casefold() not in ids)
        if n:
            problems.append(f"соответствия AST → CVE не для демо-находок: {n}")
    allowed_meta = {"schema_version", "journal_installation", f"notice:{pid}", f"codechange:{pid}"}
    identity = con.execute("SELECT value FROM meta WHERE key='journal_installation'").fetchone()
    if identity and (len(identity[0]) != 32 or any(c not in '0123456789abcdef' for c in identity[0])):
        problems.append('неверный идентификатор журнала')
    odd_meta = [k for (k,) in con.execute("SELECT key FROM meta")
                if k not in allowed_meta and not str(k).startswith(f"rev:{pid}:")]
    if odd_meta:
        problems.append(f"служебные значения не демо-проекта: {len(odd_meta)}")
    # язык интерфейса и язык прогонов демо-проекта (ADR-0158) – тоже настройки приложения
    run_langs = {f"run_lang:{rid}" for (rid,) in con.execute("SELECT id FROM runs WHERE project_id = ?", (pid,))}
    odd_settings = sorted(k for (k,) in con.execute("SELECT key FROM settings")
                          if k not in settings_keys and k != "ui_language" and k not in run_langs)
    if odd_settings:
        problems.append(f"настройки не из интерфейса: {', '.join(odd_settings[:10])}")
    problems += profile_problems(con, tables)
    return problems


VM_OLLAMA = "http://ollama:11434"  # Ollama внутри ВМ – единственный адрес сервера модели в образе
BUILD_NOTE = "адрес сборки не сохраняется"
_URL = re.compile(r"https?://[^\s\"'<>]+")


def vm_url(url: str) -> bool:
    """Адрес – Ollama ВМ: схема, узел и порт те же, без имени пользователя (http://ollama:11434@10.0.0.1 – адрес
    10.0.0.1, не ВМ); знаки препинания после адреса в тексте не мешают."""
    vm = urlsplit(VM_OLLAMA)
    try:
        part = urlsplit(url.rstrip(".,;:)]}"))
        return (part.scheme, part.hostname, part.port, part.username) == (vm.scheme, vm.hostname, vm.port, None)
    except ValueError:
        return False


def profile_problems(con: Any, tables: list[str]) -> list[str]:
    """Профили и снимки исполнителя в образе (раздел 0.3 плана 0.9.12, ADR-0102 п. 6): включён один профиль – local
    на Ollama ВМ; остальные (сборочный) выключены и без адреса; у снимков – адрес ВМ или пустой с пометкой «адрес
    сборки не сохраняется»; ключей нет; ни в профилях, ни в снимках, ни в журнале прогонов нет других адресов."""
    problems: list[str] = []
    if "llm_providers" not in tables:
        return problems
    rows = con.execute("SELECT id, trust, base_url, enabled, auth FROM llm_providers ORDER BY id").fetchall()
    enabled = [r for r in rows if r[3]]
    if [(r[1], r[2]) for r in enabled] != [("local", VM_OLLAMA)]:
        problems.append(f"включённые профили: {len(enabled)}; нужен ровно один – local на {VM_OLLAMA}")
    if any(not r[3] and r[2] for r in rows):
        problems.append("у выключенного профиля остался адрес сервера")
    if any(r[4] != "none" for r in rows):
        problems.append("у профиля задан вход по ключу: ключей в образе быть не должно")
    if "llm_executions" in tables:
        bad = con.execute("SELECT COUNT(*) FROM llm_executions WHERE NOT (base_url = ? OR (base_url = '' AND note = ?))",
                          (VM_OLLAMA, BUILD_NOTE)).fetchone()[0]
        if bad:
            problems.append(f"снимки исполнителя с адресом не ВМ: {bad}")
    for table, column in (("run_journal", "payload_json"), ("llm_executions", "options_json"),
                          ("llm_providers", "generation_json")):
        if table not in tables:
            continue
        for (text,) in con.execute(f"SELECT {column} FROM {table}"):
            others = {u for u in _URL.findall(str(text or "")) if not vm_url(u)}
            if others:
                problems.append(f"в {table} есть адрес не ВМ")
                break
    return problems


def summary(con: Any) -> dict:
    """Состав принятой базы для журнала сборки: проект, версия схемы, число находок и отпечаток их ID, ответы модели."""
    pid, name = con.execute("SELECT id, name FROM projects").fetchone()
    ids = sorted(row[0] for row in con.execute("SELECT hub_id FROM findings WHERE project_id = ?", (pid,)))
    count = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
             for t in ("findings", "verdicts", "reviews", "questions", "sca_answers", "ast_map")}
    schema = con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    return {"project": pid, "name": name, "schema_version": schema[0] if schema else None,
            "hub_ids_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(), "counts": count}


def check(conninfo: str, expected_ids: set[str], report_names: set[str]) -> dict:
    """Проверяет состав базы (только чтение). DemoDataError – база не годится; иначе summary."""
    con = connect(conninfo, read_only=True)
    try:
        problems = composition_problems(con, expected_ids, report_names)
        if problems:
            raise DemoDataError(problems)
        return summary(con)
    finally:
        con.close()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("src", help="чистая копия приложения (git archive)")
    p.add_argument("conninfo", help="строка подключения к базе образа; пароль – в PGPASSWORD")
    a = p.parse_args()
    sys.path.insert(0, a.src)
    reports = demo_reports(Path(a.src))
    if not reports:
        print(json.dumps({"error": "в копии приложения нет examples/demo/demo-hub-report.xlsx"}, ensure_ascii=False))
        return 1
    try:
        result = check(a.conninfo, expected_hub_ids(Path(a.src)), {r.name for r in reports})
    except DemoDataError as e:
        print(json.dumps({"error": "база не годится для образа", "problems": e.problems}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
