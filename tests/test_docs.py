"""Проверка документации: шапки YAML, номера ADR, относительные ссылки, запрещённые символы и слова,
обязательные разделы файла состояния.

Работает без сети и без сторонних библиотек: шапка YAML разбирается простым построчным разбором (ключ: значение,
списки в квадратных скобках или строками «- значение»). Правила – в AGENTS.md, раздел «Правила документации».

Дополнительный список запрещённых слов можно держать вне репозитория: путь к нему передаётся переменной окружения
DOCS_STOP_WORDS_FILE (UTF-8, одно слово или регулярное выражение в строке, «#» – комментарий). Без переменной
проверяются только общие признаки.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
ADR_DIR = DOCS / "adr"
STATE_DIR = DOCS / "state"
HISTORY_DIR = STATE_DIR / "history"
HISTORY_INDEX = HISTORY_DIR / "README.md"
PROJECT_STATE = STATE_DIR / "PROJECT-STATE.md"

# Журналы, ADR и инструкции разработки есть в закрытом репозитории; в публичный учебный снимок они не входят – там
# эти проверки пропускаются (раздел 6 задания на открытие)
PRIVATE_DOCS = STATE_DIR.is_dir()
private_docs = pytest.mark.skipif(not PRIVATE_DOCS, reason="журналы и ADR разработки в публичный снимок не входят")
REQUIRED_FILES = ["CHANGELOG.md", "docs/README.md"] + ([
    "AGENTS.md",
    "docs/adr/README.md",
    "docs/state/PROJECT-STATE.md",
    "docs/state/history/README.md",
] if PRIVATE_DOCS else [])

REQUIRED_FIELDS = ("title", "type", "status", "date", "tags")
DOC_TYPES = {"adr", "state", "milestone", "index", "guide"}
# статусы ADR и остальных документов (правила – AGENTS.md, «Формат файлов»)
DOC_STATUSES = {"proposed", "accepted", "superseded", "rejected", "active", "deferred", "done", "complete"}

STATE_SECTIONS = ("Что работает", "В работе", "Ближайшие шаги", "Журнал изменений состояния")

LONG_DASH = "\u2014"
# Общие признаки текста, подготовленного инструментами: служебные строки соавторства и пометки о генерации.
STOP_WORDS = re.compile(r"(?i)сгенерирова|co-authored-by|generated (with|by)\b")
# Документы проекта не называют место работы владельца и не обсуждают людей, кроме владельца продукта: правило общее
# со стражем пакета npm (scripts/hygiene_rules.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from hygiene_rules import PLACE_WORDS  # noqa: E402


def extra_stop_words() -> re.Pattern[str] | None:
    """Дополнительный список из файла вне репозитория (DOCS_STOP_WORDS_FILE); нет переменной или файла – None."""
    name = os.environ.get("DOCS_STOP_WORDS_FILE", "").strip()
    if not name or not Path(name).is_file():
        return None
    words = [line.strip() for line in Path(name).read_text(encoding="utf-8").splitlines()]
    words = [w for w in words if w and not w.startswith("#")]
    return re.compile("(?i)" + "|".join(f"(?:{w})" for w in words)) if words else None


EXTRA_STOP_WORDS = extra_stop_words()
# Личные пути с компьютеров разработчиков.
PERSONAL_PATHS = re.compile(r"(?i)\b[a-z]:[\\/]+(tmp|users)\b|scratchpad")

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)|!\[[^\]]*\]\(\s*<?([^)\s>]+)>?")
WIKI_LINK = re.compile(r"\[\[[^\]]+\]\]")
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`]*`")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def checked_files() -> list[Path]:
    """Файлы, к которым применяются проверки ссылок и текста: AGENTS.md, CHANGELOG.md и всё в docs/**."""
    files = [ROOT / name for name in ("AGENTS.md", "CHANGELOG.md") if (ROOT / name).is_file()]
    files += sorted(DOCS.rglob("*.md"))
    return files


def front_matter_files() -> list[Path]:
    """Файлы, которым обязательна шапка YAML: все документы docs/ во всех папках (Obsidian и поиск по смыслу
    находят документ по шапке)."""
    return sorted(DOCS.rglob("*.md"))


def adr_files() -> list[Path]:
    return [p for p in sorted(ADR_DIR.glob("*.md")) if p.name != "README.md"]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_front_matter(text: str) -> dict[str, object] | None:
    """Шапка YAML верхнего уровня: строки «ключ: значение», списки «[a, b]» и «- a». Нет шапки – None."""
    lines = text.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return None
    data: dict[str, object] = {}
    key = None
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        item = re.match(r"^\s+-\s*(.*)$", line)
        if item and key is not None:
            current = data.get(key)
            if not isinstance(current, list):
                current = []
            current.append(_scalar(item.group(1)))
            data[key] = current
            continue
        pair = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", line)
        if not pair:
            continue
        key, value = pair.group(1), pair.group(2)
        value = re.sub(r"\s+#.*$", "", value) if not value.strip().startswith(("\"", "'")) else value
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            data[key] = [_scalar(v) for v in inner.split(",") if v.strip()] if inner else []
        elif value == "":
            data[key] = []
        else:
            data[key] = _scalar(value)
    return data


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Строки вне блоков кода, с убранным встроенным кодом: ссылки ищутся только в тексте."""
    result = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        result.append((number, INLINE_CODE.sub("", line)))
    return result


def is_external(target: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target)) or target.startswith("//")


def local_links(path: Path) -> list[tuple[int, str]]:
    links = []
    for number, line in prose_lines(read(path)):
        for match in LINK.finditer(line):
            target = match.group(1) or match.group(2)
            if not target or target.startswith("#") or is_external(target):
                continue
            links.append((number, target))
    return links


def resolve_link(path: Path, target: str) -> Path:
    target = unquote(target.split("#", 1)[0].split("?", 1)[0])
    return (path.parent / target).resolve()


# --- наличие --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_required_file_exists(name: str) -> None:
    assert (ROOT / name).is_file(), f"нет обязательного файла документации {name}"


@private_docs
def test_history_has_snapshots() -> None:
    snapshots = sorted(HISTORY_DIR.glob("*.md")) if HISTORY_DIR.is_dir() else []
    snapshots = [p for p in snapshots if p.name != "README.md"]
    assert snapshots, "в docs/state/history нет ни одного снимка вехи"


def snapshot_files() -> list[Path]:
    return [p for p in sorted(HISTORY_DIR.glob("*.md")) if p.name != "README.md"] if HISTORY_DIR.is_dir() else []


@private_docs
def test_history_index_lists_every_snapshot() -> None:
    if not HISTORY_INDEX.is_file():
        pytest.fail("нет docs/state/history/README.md – указателя снимков вех")
    text = read(HISTORY_INDEX)
    missing = [p.name for p in snapshot_files() if p.name not in text]
    assert not missing, f"docs/state/history/README.md не ссылается на {', '.join(missing)}"


@pytest.mark.parametrize("path", snapshot_files(), ids=rel)
def test_history_snapshot_name(path: Path) -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9.-]*-[0-9a-f]{7,40}\.md", path.name), (
        f"{rel(path)}: имя снимка – <ГГГГ-ММ-ДД>-<веха>-<короткий хеш коммита>.md"
    )


# --- шапки YAML -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", front_matter_files(), ids=rel)
def test_front_matter(path: Path) -> None:
    meta = parse_front_matter(read(path))
    assert meta is not None, f"{rel(path)}: нет шапки YAML между строками ---"
    missing = [field for field in REQUIRED_FIELDS if not meta.get(field)]
    assert not missing, f"{rel(path)}: в шапке нет полей {', '.join(missing)}"
    assert meta["type"] in DOC_TYPES, f"{rel(path)}: type «{meta['type']}» не из {sorted(DOC_TYPES)}"
    assert meta["status"] in DOC_STATUSES, f"{rel(path)}: status «{meta['status']}» не из {sorted(DOC_STATUSES)}"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(meta["date"])), f"{rel(path)}: date – в виде ГГГГ-ММ-ДД"
    assert isinstance(meta["tags"], list), f"{rel(path)}: tags – список"
    related = meta.get("related") or []
    assert isinstance(related, list), f"{rel(path)}: related – список относительных путей"
    for target in related:
        assert not is_external(target), f"{rel(path)}: related – только относительные пути, а не {target}"
        assert resolve_link(path, target).exists(), f"{rel(path)}: related ведёт на несуществующий {target}"


@pytest.mark.parametrize("path", adr_files(), ids=rel)
def test_adr_type(path: Path) -> None:
    meta = parse_front_matter(read(path)) or {}
    assert meta.get("type") == "adr", f"{rel(path)}: у ADR type: adr"


# --- номера ADR -----------------------------------------------------------------------------------------------

def test_adr_numbers_sequential() -> None:
    files = adr_files()
    numbers = []
    for path in files:
        match = re.fullmatch(r"(\d{4})-[a-z0-9][a-z0-9-]*\.md", path.name)
        assert match, f"{rel(path)}: имя ADR – NNNN-краткое-имя.md, латиница через дефис"
        numbers.append(int(match.group(1)))
    assert len(numbers) == len(set(numbers)), f"номера ADR повторяются: {sorted(numbers)}"
    assert sorted(numbers) == list(range(1, len(numbers) + 1)), (
        f"номера ADR должны идти подряд с 0001: {sorted(numbers)}"
    )


@pytest.mark.parametrize("path", adr_files(), ids=rel)
def test_adr_title_matches_file(path: Path) -> None:
    number = path.name[:4]
    meta = parse_front_matter(read(path)) or {}
    title = str(meta.get("title", ""))
    in_title = re.findall(r"(?<!\d)(\d{4})(?!\d)", title)
    assert in_title and in_title[0] == number, f"{rel(path)}: в title должен стоять номер {number}, а не «{title}»"


def test_adr_refinements_are_paired() -> None:
    """Частичное уточнение решения (docs/adr/README.md, «Правила»): поля refines и refined_by – парные, уточнённая
    запись остаётся accepted и называет уточнение строкой «Уточнено: [ADR-NNNN]», уточняющая – строкой
    «Уточняет: [ADR-NNNN]». Пункт «Связь с ADR-NNNN» в решении новой записи тест не требует: у записи, которую
    отметили уточняющей позже, текст решения уже принят и не правится."""
    def as_list(value) -> list:
        return (value if isinstance(value, list) else [value]) if value else []

    meta = {path.name: (parse_front_matter(read(path)) or {}, read(path)) for path in adr_files()}
    for name, (head, text) in meta.items():
        for refines in as_list(head.get("refines")):  # одна запись может уточнять несколько (с 0.9.21)
            assert refines in meta, f"{name}: refines ссылается на несуществующий {refines}"
            older_head, older_text = meta[refines]
            assert name in as_list(older_head.get("refined_by")), f"{refines}: нет refined_by: {name}"
            assert older_head.get("status") == "accepted", f"{refines}: уточнённая запись остаётся accepted"
            assert f"Уточнено: [ADR-{name[:4]}]" in older_text, f"{refines}: нет строки «Уточнено: [ADR-{name[:4]}]»"
            assert f"Уточняет: [ADR-{refines[:4]}]" in text, f"{name}: нет строки «Уточняет: [ADR-{refines[:4]}]»"
        for newer in as_list(head.get("refined_by")):
            assert newer in meta, f"{name}: refined_by ссылается на несуществующий {newer}"
            assert name in as_list(meta[newer][0].get("refines")), f"{newer}: нет refines: {name}"


@private_docs
def test_adr_index_lists_every_adr() -> None:
    index = ADR_DIR / "README.md"
    if not index.is_file():
        pytest.fail("нет docs/adr/README.md")
    text = read(index)
    missing = [p.name for p in adr_files() if p.name not in text]
    assert not missing, f"docs/adr/README.md не ссылается на {', '.join(missing)}"


# --- ссылки и текст -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_relative_links_exist(path: Path) -> None:
    broken = [f"строка {n}: {t}" for n, t in local_links(path) if not resolve_link(path, t).exists()]
    assert not broken, f"{rel(path)}: ссылки на несуществующие файлы:\n" + "\n".join(broken)


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_no_wiki_links(path: Path) -> None:
    found = [f"строка {n}" for n, line in prose_lines(read(path)) if WIKI_LINK.search(line)]
    assert not found, f"{rel(path)}: вики-ссылки в двойных скобках, нужны обычные ссылки Markdown: {found}"


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_no_long_dash(path: Path) -> None:
    found = [n for n, line in enumerate(read(path).splitlines(), start=1) if LONG_DASH in line]
    assert not found, f"{rel(path)}: длинное тире в строках {found}, нужно «–»"


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_no_tool_traces(path: Path) -> None:
    patterns = [STOP_WORDS] + ([EXTRA_STOP_WORDS] if EXTRA_STOP_WORDS else [])
    found = [f"строка {n}: {m.group(0)}" for n, line in enumerate(read(path).splitlines(), start=1)
             for pattern in patterns for m in pattern.finditer(line)]
    assert not found, f"{rel(path)}: следы инструментов разработки:\n" + "\n".join(found)


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_no_customer_or_people(path: Path) -> None:
    found = [f"строка {n}: {m.group(0)}" for n, line in enumerate(read(path).splitlines(), start=1)
             for m in PLACE_WORDS.finditer(line)]
    assert not found, f"{rel(path)}: упоминание места работы, города или людей:\n" + "\n".join(found)


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_no_personal_paths(path: Path) -> None:
    found = [f"строка {n}: {m.group(0)}" for n, line in enumerate(read(path).splitlines(), start=1)
             for m in PERSONAL_PATHS.finditer(line)]
    assert not found, f"{rel(path)}: личные пути:\n" + "\n".join(found)


@pytest.mark.parametrize("path", checked_files(), ids=rel)
def test_fstec_full_name(path: Path) -> None:
    text = read(path)
    found = [text.count("\n", 0, m.start()) + 1 for m in re.finditer(r"ФСТЭК(?!\s+России)", text)]
    assert not found, f"{rel(path)}: регулятор пишется «ФСТЭК России», строки {found}"


# --- файл состояния -------------------------------------------------------------------------------------------

@private_docs
def test_project_state_sections() -> None:
    if not PROJECT_STATE.is_file():
        pytest.fail("нет docs/state/PROJECT-STATE.md")
    # Заголовок может уточнять раздел («Что в работе: этап 2»), поэтому ищется вхождение без учёта регистра.
    headings = [line.lstrip("#").strip().casefold() for _, line in prose_lines(read(PROJECT_STATE))
                if line.startswith("#")]
    missing = [s for s in STATE_SECTIONS if not any(s.casefold() in h for h in headings)]
    assert not missing, f"в PROJECT-STATE.md нет разделов: {', '.join(missing)}"


def test_changelog_has_current_version() -> None:
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.is_file():
        pytest.fail("нет CHANGELOG.md")
    match = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", read(ROOT / "app" / "__init__.py"))
    assert match, "в app/__init__.py нет __version__"
    assert match.group(1) in read(changelog), f"в CHANGELOG.md нет записи о версии {match.group(1)}"


# --- ссылки корневых документов, список версий, журнал, указатель ----------------------------------------------

@pytest.mark.parametrize("name", ["README.md", "examples/demo/README.md"])
def test_root_document_links_exist(name: str) -> None:
    path = ROOT / name
    broken = [f"строка {n}: {t}" for n, t in local_links(path) if not resolve_link(path, t).exists()]
    assert not broken, f"{name}: ссылки на несуществующие файлы:\n" + "\n".join(broken)


def changelog_versions() -> list[str]:
    return re.findall(r"^## \[(\d+\.\d+\.\d+(?:\.dev\d+)?)\]", read(ROOT / "CHANGELOG.md"), re.M)


def version_key(version: str) -> tuple[int, int, int, int, int]:
    """Порядок версий: промежуточная сборка X.Y.Z.devN – раньше выпуска X.Y.Z (0.9.12 < 0.9.13.dev1 < 0.9.13)."""
    main, _, dev = version.partition(".dev")
    a, b, c = (int(x) for x in main.split("."))
    return (a, b, c, 0 if dev else 1, int(dev or 0))


def test_version_order_with_dev_builds() -> None:
    assert sorted(["0.9.13", "0.9.12", "0.9.13.dev1", "0.9.13.dev2"], key=version_key) == [
        "0.9.12", "0.9.13.dev1", "0.9.13.dev2", "0.9.13"]


def test_changelog_has_every_version_once_newest_first() -> None:
    """Единый вид списка версий: по заголовку на версию, без дублей и пропусков патч-версий, от новой к старой; верхняя –
    текущая версия приложения."""
    versions = changelog_versions()
    assert len(versions) == len(set(versions)), f"версии в CHANGELOG.md повторяются: {versions}"
    as_tuples = [version_key(v) for v in versions]
    assert as_tuples == sorted(as_tuples, reverse=True), "версии в CHANGELOG.md идут не от новой к старой"
    match = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", read(ROOT / "app" / "__init__.py"))
    assert match and versions[0] == match.group(1), f"верхняя версия CHANGELOG.md {versions[0]} не равна версии приложения"
    if not PRIVATE_DOCS:
        return  # публичный снимок начинает историю с первой публичной версии
    third = [t[2] for t in as_tuples if t[:2] == (0, 3)]
    assert third == list(range(max(third), -1, -1)), f"в серии 0.3.x пропущены версии: {third}"
    for needed in ("0.1.0", "0.2.0"):
        assert needed in versions


@private_docs
def test_project_state_journal_has_hashes_except_the_newest_row() -> None:
    """В журнале состояния «этот коммит» стоит не больше чем в последней строке: у остальных – хеши."""
    text = read(PROJECT_STATE)
    journal = text.split("## Журнал изменений состояния", 1)[1]
    rows = [line for line in journal.splitlines() if re.match(r"^\| \d{4}-\d{2}-\d{2} \|", line)]
    assert rows, "в журнале нет строк"
    marked = [i for i, line in enumerate(rows) if re.match(r"^\| [\d-]+ \| этот коммит \|", line)]
    assert marked in ([], [len(rows) - 1]), f"«этот коммит» не только в последней строке журнала: {marked}"
    for line in rows[:-1]:
        assert re.match(r"^\| [\d-]+ \| (`[0-9a-f]{7,40}`(, `[0-9a-f]{7,40}`)*|коммит [0-9a-f]{7,40}) \|", line), line[:80]
    assert text.count("этот коммит –") <= 1, "в таблице «Коротко» «этот коммит» не больше одного раза"


def test_docs_index_lists_every_top_level_document() -> None:
    index = read(DOCS / "README.md")
    names = [p.name for p in DOCS.glob("*.md") if p.name != "README.md"] + (["audit-2026-10-15.md"] if PRIVATE_DOCS else [])
    missing = [name for name in names if name not in index]
    assert not missing, f"docs/README.md не упоминает: {', '.join(missing)}"
    if PRIVATE_DOCS:
        assert "codex/README.md" in index


# --- самопроверка разбора -------------------------------------------------------------------------------------

@private_docs
def test_current_version_schema_modules_and_component_routes_are_documented():
    from app import __version__
    from app.db import SCHEMA_VERSION
    architecture=read(DOCS/'ARCHITECTURE.md');readme=read(ROOT/'README.md')
    assert f'Текущая версия: {__version__}' in architecture
    assert f'Текущая схема: {SCHEMA_VERSION}' in architecture
    assert f'| {__version__} | {SCHEMA_VERSION} |' in readme
    for name in ('sca_research.py','sca_contract.py','routes/components.py'):
        assert name in architecture
    from app.routes.components import router
    for route in router.routes:
        assert route.path.replace('{project_id}','{id}') in architecture,route.path
    assert '410' in architecture and 'Схема 13' in architecture
    assert '## Исследование компонентов' in read(DOCS/'DEMO.md')

def test_documented_sca_error_codes_match_validator():
    source=read(ROOT/'app/sca_contract.py')
    codes=set(re.findall(r"SCA-[MTCEDLA]\d{3}",source))
    documented=set(re.findall(r'\| (SCA-[A-Z]\d{3}) \|',read(DOCS/'sca-evidence-contract.md')))
    assert documented==codes

def test_parser_self_check() -> None:
    meta = parse_front_matter("---\ntitle: \"ADR-0002: Пример\"\ntype: adr  # тип\ntags: [a, b]\nrelated:\n"
                              "  - ../x.md\n---\n# Текст\n")
    assert meta == {"title": "ADR-0002: Пример", "type": "adr", "tags": ["a", "b"], "related": ["../x.md"]}
    assert parse_front_matter("# Без шапки\n") is None
    sample = "[a](x.md) `[b](y.md)` ![c](img.png) [d](https://e.example) [f](#g)\n```\n[h](z.md)\n```\n"
    links = []
    for _, line in prose_lines(sample):
        links += [m.group(1) or m.group(2) for m in LINK.finditer(line)]
    assert links == ["x.md", "img.png", "https://e.example", "#g"]
    assert STOP_WORDS.search(LONG_DASH) is None
    assert STOP_WORDS.search("Co-Authored-By: x") and STOP_WORDS.search("Текст сгенерирован")
    assert STOP_WORDS.search("языковая модель") is None
    assert PERSONAL_PATHS.search("C:/Users/someone") and PERSONAL_PATHS.search("v:\\tmp\\x")
