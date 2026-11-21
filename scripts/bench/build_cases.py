"""Сборщик эталонного набора для замера моделей: 80 тестов OWASP Benchmark (Java) и 15 демо-находок приложения.

Код и ожидаемые ответы OWASP Benchmark (лицензия GPL-2.0) в репозитории не хранятся. В репозитории – только список
отобранных тестов (номера и категории, owasp-selection.json рядом с этим файлом). Сборщик берёт код и ответы из
клона OWASP Benchmark: готового (--owasp ПАПКА) или скачанного им самим (--clone, git clone и переход на коммит
из списка). Демо-находки – из examples/demo этого репозитория (5 из них – на Python, отдельного источника у них нет).

Набор (cases.json) и сведения о сборке (cases_meta.json) пишутся в results/bench/ (папка в .gitignore): в наборе
есть строки кода OWASP Benchmark и абсолютные пути к клонам, в репозиторий он не кладётся.

Запуск из корня репозитория:
    .venv\\Scripts\\python -I -B scripts/bench/build_cases.py --clone
    .venv\\Scripts\\python -I -B scripts/bench/build_cases.py --owasp ПАПКА_КЛОНА
    .venv\\Scripts\\python -I -B scripts/bench/build_cases.py --demo-only

-I и -B: модули приложения импортируются только на чтение, байт-код рядом с ними не пишется.
Коды выхода: 0 – набор собран без замечаний; 1 – есть замечания (набор записан, замечания – в cases_meta.json);
2 – набор не собран (нет клона, git, не тот список и т. п.).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import csv  # noqa: E402
import datetime as dt  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from collections import Counter, defaultdict  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_OUT = REPO / "results" / "bench"
SELECTION_FILE = HERE / "owasp-selection.json"

TESTCODE = "src/main/java/org/owasp/benchmark/testcode"


class BuildError(Exception):
    """Набор собрать нельзя: текст – по-русски, код выхода 2."""


def load_selection(path: Path = SELECTION_FILE) -> dict:
    """Список отобранных тестов OWASP Benchmark: адрес, коммит, категории, правило отбора, номера и категории."""
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("url", "commit", "expected_results", "categories", "per_group", "tests"):
        if key not in data:
            raise BuildError(f"{path.name}: нет поля {key}")
    return data


SELECTION = load_selection()
CATEGORIES: list[str] = list(SELECTION["categories"])
PER_GROUP: int = int(SELECTION["per_group"])

RULES_RU = {
    "sqli": "Внедрение SQL-кода",
    "cmdi": "Внедрение команд ОС",
    "pathtraver": "Обход пути",
    "xss": "Межсайтовый скриптинг",
    "ldapi": "Внедрение в запросы LDAP",
    "xpathi": "Внедрение в выражения XPath",
    "trustbound": "Нарушение границы доверия",
    "weakrand": "Слабый генератор случайных чисел",
}

# Категории демо-выгрузки (колонка Category отчёта Hub) -> короткий код, как у OWASP.
DEMO_CATEGORY = {
    "Внедрение SQL-кода": "sqli",
    "Обход пути": "pathtraver",
    "Межсайтовый скриптинг": "xss",
    "Слабый генератор случайных чисел": "weakrand",
    "Слабый алгоритм хеширования": "hash",
    "Пароль в исходном коде": "hardcoded_password",
    "Внедрение команд ОС": "cmdi",
    "Небезопасная десериализация": "deserialization",
    "Подделка серверных запросов": "ssrf",
}

# Шаблоны строки срабатывания. Ищутся в тексте, где комментарии и строковые литералы заменены пробелами
# (app.context.blank_code), начиная со строки «public void doPost(». Ярусы – по порядку: берётся самое раннее
# совпадение первого яруса, где совпадение есть. «\(\s*[^\s)]» – у вызова есть аргумент не из одних литералов.
# Номер строки – по началу группы m (имя вызываемого метода), иначе по началу совпадения.
_ARG = r"\s*\(\s*[^\s)]"
PATTERNS: dict[str, list[list[tuple[str, str]]]] = {
    "sqli": [[
        ("jdbc/spring-вызов с запросом",
         r"\b(?P<m>prepareCall|prepareStatement|executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|"
         r"batchUpdate|queryForObject|queryForList|queryForMap|queryForRowSet|queryForLong|queryForInt|query|update|"
         r"createQuery|createSQLQuery|createNativeQuery)" + _ARG),
    ]],
    "cmdi": [[
        ("Runtime.exec", r"\.\s*(?P<m>exec)" + _ARG),
        ("new ProcessBuilder(аргументы)", r"\bnew\s+(?:java\.lang\.)?(?P<m>ProcessBuilder)" + _ARG),
        ("ProcessBuilder.command", r"\.\s*(?P<m>command)" + _ARG),
    ], [
        ("new ProcessBuilder()", r"\bnew\s+(?:java\.lang\.)?(?P<m>ProcessBuilder)\s*\("),
    ]],
    "pathtraver": [[
        ("new File/FileInputStream/FileOutputStream",
         r"\bnew\s+(?:java\.io\.)?(?P<m>File|FileInputStream|FileOutputStream|FileReader|FileWriter|"
         r"RandomAccessFile)\s*\("),
        ("Paths.get", r"\b(?:java\.nio\.file\.)?Paths\s*\.\s*(?P<m>get)\s*\("),
        ("Path.of", r"\b(?:java\.nio\.file\.)?Path\s*\.\s*(?P<m>of)\s*\("),
        ("Files.*", r"\b(?:java\.nio\.file\.)?Files\s*\.\s*(?P<m>newInputStream|newOutputStream|newBufferedReader|"
                    r"newBufferedWriter|readAllBytes|readAllLines|lines|write|copy|delete|exists)\s*\("),
    ]],
    "xss": [[
        ("getWriter().print/println/printf/format/write/append",
         r"\bgetWriter\s*\(\s*\)\s*\.\s*(?P<m>print|println|printf|format|write|append)" + _ARG),
    ]],
    "ldapi": [[("search", r"\.\s*(?P<m>search)" + _ARG)]],
    "xpathi": [[("evaluate/compile", r"\.\s*(?P<m>evaluate|compile)" + _ARG)]],
    "trustbound": [[("setAttribute/putValue", r"\.\s*(?P<m>setAttribute|putValue)" + _ARG)]],
    "weakrand": [[
        ("new java.util.Random", r"\bnew\s+(?:java\.util\.)?(?P<m>Random)\s*\("),
        ("Math.random", r"\b(?:java\.lang\.)?Math\s*\.\s*(?P<m>random)\s*\("),
        ("ThreadLocalRandom", r"\b(?:java\.util\.concurrent\.)?(?P<m>ThreadLocalRandom)\s*\.\s*current\s*\("),
    ], [
        ("SecureRandom", r"\b(?:java\.security\.)?(?P<m>SecureRandom)\s*\.\s*getInstance(?:Strong)?\s*\("
                         r"|\bnew\s+(?:java\.security\.)?(?P<m2>SecureRandom)\s*\("),
    ]],
}
DOPOST = re.compile(r"\bpublic\s+void\s+doPost\s*\(")

# Подсказки генератора OWASP Benchmark: комментарии в коде теста, которые прямо говорят, доходит ли до строки
# срабатывания значение из запроса (поток «безопасен», переменной присвоена константа, «получить значение
# параметра» и т. п.). Отмечаются только в категориях, где вердикт зависит от потока данных; в weakrand вердикт
# решает тип генератора, и такие комментарии к ответу не относятся.
HINT_COMMENT = re.compile(
    r"whole flow is 'safe'|is static so|assigns constant to|assigns param to|which is safe|"
    r"get the param value|'safe' value|safe value|\bunsafe\b|\btainted\b|\bsanitiz",
    re.I)
HINT_CATEGORIES = {"sqli", "cmdi", "pathtraver", "xss", "ldapi", "xpathi", "trustbound"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str | None:
    """Вывод git в папке repo; не репозиторий git или нет git – None."""
    exe = shutil.which("git")
    if not exe or not (repo / ".git").exists():
        return None
    out = subprocess.run([exe, "-C", str(repo), *args], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


def clone_owasp(dest: Path, url: str, commit: str) -> Path:
    """Скачать OWASP Benchmark в dest (git clone) и перейти на коммит из списка. Уже скачан – только переход."""
    exe = shutil.which("git")
    if not exe:
        raise BuildError("Для --clone нужен git: установите его или укажите готовый клон через --owasp.")
    if not (dest / ".git").exists():
        if dest.exists() and any(dest.iterdir()):
            raise BuildError(f"{dest} не пуста и не клон git: укажите другую папку (--owasp) или очистите её.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"Скачиваю {url} в {dest} ...", flush=True)
        done = subprocess.run([exe, "clone", "--quiet", url, str(dest)])
        if done.returncode != 0:
            raise BuildError(f"git clone {url} не удался (код {done.returncode}).")
    if git(dest, "rev-parse", "HEAD") != commit:
        done = subprocess.run([exe, "-C", str(dest), "checkout", "--quiet", "--detach", commit])
        if done.returncode != 0:
            subprocess.run([exe, "-C", str(dest), "fetch", "--quiet", "origin"])
            done = subprocess.run([exe, "-C", str(dest), "checkout", "--quiet", "--detach", commit])
        if done.returncode != 0:
            raise BuildError(f"В клоне {dest} нет коммита {commit}.")
    return dest


def inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError:
        return False
    return True


def check_out_dir(out_dir: Path, app: Path) -> None:
    """Сборщик пишет внутри репозитория приложения только в results/: код, данные и документы не трогаются."""
    if inside(out_dir, app) and not inside(out_dir, app / "results"):
        raise BuildError(f"{out_dir} – внутри приложения, но не в results/: набор туда не пишется.")


def load_app(app: Path):
    """Модули приложения – на чтение: app.context, app.models и сценарий демо-выгрузки."""
    if str(app) not in sys.path:
        sys.path.insert(0, str(app))
    from app import context, models  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("make_demo_xlsx_ro", app / "scripts" / "make_demo_xlsx.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    return context, models, demo


def read_source(context, path: Path) -> str:
    text = context.decode_source(path.read_bytes())
    if text is None:
        raise ValueError(f"{path}: двоичный файл")
    return text


# ============================================================================ OWASP

def read_expected(owasp: Path, name: str = SELECTION["expected_results"]) -> list[dict]:
    path = owasp / name
    if not path.is_file():
        raise BuildError(f"В {owasp} нет {name}: это не клон OWASP Benchmark (BenchmarkJava)?")
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        for rec in csv.reader(fh):
            if not rec or rec[0].lstrip().startswith("#"):
                continue
            name, category, real, cwe = (x.strip() for x in rec[:4])
            rows.append({"name": name, "category": category, "real": real == "true", "cwe": int(cwe)})
    return rows


def select(rows: list[dict]) -> list[dict]:
    """В каждой категории – первые PER_GROUP настоящих и первые PER_GROUP ложных по номеру теста."""
    picked = []
    for category in CATEGORIES:
        for real in (True, False):
            group = sorted((r for r in rows if r["category"] == category and r["real"] is real),
                           key=lambda r: r["name"])
            if len(group) < PER_GROUP:
                raise ValueError(f"{category}/{real}: в группе {len(group)} тестов, нужно {PER_GROUP}")
            picked.extend(group[:PER_GROUP])
    return picked


def check_selection(picked: list[dict], tests: list[dict]) -> list[str]:
    """Отбор по правилу на ответах клона должен совпасть со списком из репозитория (номера и категории)."""
    got = {(r["name"], r["category"]) for r in picked}
    want = {(str(t["id"]), str(t["category"])) for t in tests}
    problems = [f"{n} ({c}): есть в списке owasp-selection.json, но не отобран по ответам клона"
                for n, c in sorted(want - got)]
    problems += [f"{n} ({c}): отобран по ответам клона, но его нет в owasp-selection.json"
                 for n, c in sorted(got - want)]
    return problems


def find_sink(context, text: str, category: str) -> tuple[int, str, str]:
    """(номер строки, how_line, шаблон) – строка срабатывания в тесте OWASP."""
    blank = context.blank_code(text, "java")
    dopost = DOPOST.search(blank)
    if dopost is None:
        raise ValueError("нет объявления doPost")
    for tier in PATTERNS[category]:
        best = None
        for name, rx in tier:
            for m in re.finditer(rx, blank[dopost.start():]):
                group = next((g for g in ("m", "m2") if g in m.groupdict() and m.group(g)), None)
                pos = dopost.start() + (m.start(group) if group else m.start())
                if best is None or pos < best[0]:
                    best = (pos, name)
                break  # у каждого шаблона – только первое совпадение
        if best is not None:
            return blank.count("\n", 0, best[0]) + 1, "pattern", best[1]
    return blank.count("\n", 0, dopost.start()) + 1, "fallback", "объявление doPost"


def comments_after_package(context, text: str) -> list[tuple[int, str]]:
    """Комментарии после строки package (заголовок с лицензией не считается): (номер строки, текст)."""
    package = re.search(r"^package\s", text, re.M)
    start = package.start() if package else 0
    result = []
    for m in context._LEXERS["java"].finditer(text, start):
        token = m.group(0)
        if token.startswith(("//", "/*")):
            result.append((text.count("\n", 0, m.start()) + 1, " ".join(token.split())))
    return result


def owasp_cases(context, owasp: Path, dump_comments: bool) -> tuple[list[dict], dict]:
    rows = read_expected(owasp)
    picked = select(rows)
    mismatch = check_selection(picked, SELECTION["tests"])
    if mismatch:
        raise BuildError("Отбор по клону расходится со списком owasp-selection.json (другая версия OWASP "
                         "Benchmark?):\n  " + "\n  ".join(mismatch))
    cases, comments_seen = [], defaultdict(Counter)
    for r in picked:
        rel = f"{TESTCODE}/{r['name']}.java"
        text = read_source(context, owasp / rel)
        lines = context._split_lines(text)
        line, how, pattern = find_sink(context, text, r["category"])
        comments = comments_after_package(context, text)
        hints = ([c for _, c in comments if HINT_COMMENT.search(c)]
                 if r["category"] in HINT_CATEGORIES else [])
        for _, c in comments:
            comments_seen[c]["true" if r["real"] else "false"] += 1
        depends = None
        also_ok: list[str] = []
        if re.search(r"\bgetTheValue\s*\(", context.blank_code(text, "java")):
            depends = ("org.owasp.benchmark.helpers.SeparateClassRequest.getTheValue() – возвращает константу "
                       "\"bar\"; код метода в другом файле, в срезе его не видно")
            also_ok = ["uncertain"]
        cases.append({
            "id": r["name"],
            "source": "owasp",
            "category": r["category"],
            "cwe": f"CWE-{r['cwe']}",
            "rule": RULES_RU[r["category"]],
            "language": "Java",
            "repo_root": owasp.as_posix(),
            "file": rel,
            "line": line,
            "snippet": lines[line - 1].strip(),
            "expected": "true_positive" if r["real"] else "false_positive",
            "how_line": how,
            "also_ok": also_ok,
            "expected_note": None,
            "depends_on": depends,
            "hint_comment": bool(hints),
            "hint_comments": hints,
            "sink_pattern": pattern,
            "codebase": "BenchmarkJava",
            "hub_file": None,
        })
    if dump_comments:
        print("\n=== Комментарии в отобранных тестах OWASP (после package): число в настоящих / ложных")
        for c, n in sorted(comments_seen.items(), key=lambda kv: -sum(kv[1].values())):
            flag = "HINT " if HINT_COMMENT.search(c) else "     "
            print(f"{flag}{n['true']:3d} / {n['false']:3d}  {c[:150]}")
    meta = {"rows_in_csv": len(rows), "picked": len(picked)}
    return cases, meta


# ============================================================================ демо

VERDICT_RU = (("истинная", "true_positive"), ("ложная", "false_positive"), ("неясно", "uncertain"))


def parse_demo_readme(readme: Path) -> dict[str, dict]:
    """Таблица «Какой ответ задуман» из examples/demo/README.md -> {id: {expected, also_ok, where, why, raw}}."""
    result = {}
    in_section = False
    for raw in readme.read_text(encoding="utf-8").splitlines():
        if raw.startswith("## "):
            in_section = raw.strip() == "## Какой ответ задуман"
            continue
        if not in_section or not raw.startswith("|"):
            continue
        cells = [c.strip() for c in raw.strip().strip("|").split("|")]
        if len(cells) < 4 or not re.fullmatch(r"\d{6}", cells[0]):
            continue
        hub_id, where, answer, why = cells[0], cells[1], cells[2], " | ".join(cells[3:])
        expected = next((code for ru, code in VERDICT_RU if answer.casefold().startswith(ru)), None)
        also_ok = ["uncertain"] if expected and expected != "uncertain" and "допустимо «неясно»" in answer else []
        result[hub_id] = {"expected": expected, "also_ok": also_ok, "where": where.strip("`"), "why": why,
                          "raw": answer}
    return result


def read_xlsx_sast(path: Path) -> dict[str, dict]:
    import openpyxl  # noqa: PLC0415

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        ws = wb["SAST"]
        rows = list(ws.iter_rows(values_only=True))
    finally:
        wb.close()
    head = [str(h) for h in rows[0]]
    return {str(r[head.index("Issue id")]): {h: ("" if v is None else str(v)) for h, v in zip(head, r)}
            for r in rows[1:] if r and r[0] is not None}


def demo_cases(context, demo, app: Path) -> tuple[list[dict], dict]:
    demo_dir = app / "examples" / "demo"
    repos = demo_dir / "repos"
    readme = parse_demo_readme(demo_dir / "README.md")
    computed = {row["Issue id"]: row for row in demo.sast_rows(repos)}
    xlsx = read_xlsx_sast(demo_dir / "demo-hub-report.xlsx")
    mismatches = []
    cols = ("Category", "File", "Line number", "Source code", "CWE ID", "Codebase", "Language")
    for hub_id, row in computed.items():
        other = xlsx.get(hub_id)
        if other is None:
            mismatches.append(f"{hub_id}: нет в demo-hub-report.xlsx")
            continue
        for col in cols:
            if str(row[col]) != str(other.get(col, "")):
                mismatches.append(f"{hub_id}: {col}: сценарий «{row[col]}» / xlsx «{other.get(col)}»")
    for hub_id in xlsx:
        if hub_id not in computed:
            mismatches.append(f"{hub_id}: есть в xlsx, нет в сценарии")

    cases = []
    for spec in demo.SAST_FINDINGS:
        hub_id = spec["id"]
        row = xlsx.get(hub_id) or computed[hub_id]
        folder = demo.FOLDERS[spec["codebase"]]
        line = int(row["Line number"])
        source_code = row["Source code"]
        snippet = re.sub(r"\s*:\s*\d+\s*$", "", source_code)  # как Finding.snippet: без хвоста « : N»
        answer = readme.get(hub_id, {})
        hub_file = row["File"] if row["File"] != spec["file"] else None
        cases.append({
            "id": hub_id,
            "source": "demo",
            "category": DEMO_CATEGORY.get(row["Category"], row["Category"]),
            "cwe": f"CWE-{int(row['CWE ID'])}",
            "rule": row["Category"],
            "language": row["Language"],
            "repo_root": (repos / folder).as_posix() if folder else None,
            "file": spec["file"],
            "line": line,
            "snippet": snippet,
            "expected": answer.get("expected"),
            "how_line": "export",
            "also_ok": answer.get("also_ok", []),
            "expected_note": (f"{answer['raw']}: {answer['why']}" if answer else None),
            "depends_on": None,
            "hint_comment": False,
            "hint_comments": [],
            "sink_pattern": None,
            "codebase": row["Codebase"],
            "hub_file": hub_file,
        })
    meta = {
        "readme_sha256": sha256(demo_dir / "README.md"),
        "xlsx_sha256": sha256(demo_dir / "demo-hub-report.xlsx"),
        "make_demo_xlsx_sha256": sha256(app / "scripts" / "make_demo_xlsx.py"),
        "script_vs_xlsx_mismatches": mismatches,
        "readme_ids": sorted(readme),
        "readme_without_answer": sorted(k for k, v in readme.items() if v["expected"] is None),
        "findings_without_readme_row": sorted(c["id"] for c in cases if c["id"] not in readme),
    }
    return cases, meta


# ============================================================================ проверка через приложение

def validate(context, models, cases: list[dict]) -> list[dict]:
    """Каждая запись – через app.context.build_context, как это делает приложение (без маскирования)."""
    report = []
    for c in cases:
        f = models.Finding(hub_id=c["id"], kind="SAST", rule=c["rule"], cwe=[c["cwe"]], codebase=c["codebase"],
                           file=c["hub_file"] or c["file"], line=c["line"], snippet=c["snippet"],
                           language=c["language"])
        ctx = context.build_context(Path(c["repo_root"]) if c["repo_root"] else None, f)
        report.append({"id": c["id"], "status": ctx.status, "export_line_check": ctx.export_line_check,
                       "file": ctx.file, "target_line": ctx.target_line, "start_line": ctx.start_line,
                       "end_line": ctx.end_line, "enclosing": ctx.enclosing, "note": ctx.note})
    return report


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Эталонный набор для замера моделей: OWASP Benchmark и демо приложения.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--owasp", type=Path, help="папка готового клона OWASP Benchmark (BenchmarkJava)")
    src.add_argument("--clone", nargs="?", const="", metavar="ПАПКА",
                     help="скачать OWASP Benchmark (git clone) и перейти на коммит из owasp-selection.json; "
                          "по умолчанию – в results/bench/owasp")
    src.add_argument("--demo-only", action="store_true", help="только 15 демо-находок, без OWASP Benchmark")
    ap.add_argument("--url", default=SELECTION["url"], help="адрес репозитория OWASP Benchmark для --clone")
    ap.add_argument("--app", type=Path, default=REPO, help="папка приложения (по умолчанию – этот репозиторий)")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT,
                    help="куда записать cases.json и cases_meta.json (по умолчанию results/bench)")
    ap.add_argument("--dump-comments", action="store_true", help="показать комментарии в отобранных тестах OWASP")
    ap.add_argument("--secrets", action="store_true",
                    help="добавить выдуманные случаи CWE-259/CWE-798 (secret_cases.py; файлы – в out-dir/secrets)")
    return ap.parse_args(argv)


def owasp_meta(owasp: Path) -> tuple[dict, list[str]]:
    """Сведения о клоне и предупреждения: коммит не тот, что в списке, или неизвестен; файл ответов другой."""
    warnings = []
    commit = git(owasp, "rev-parse", "HEAD")
    if commit is None:
        warnings.append(f"коммит клона {owasp} неизвестен (не репозиторий git): сверить с {SELECTION['commit'][:12]} "
                        "нельзя")
    elif commit != SELECTION["commit"]:
        warnings.append(f"клон на коммите {commit[:12]}, а набор отбирался на {SELECTION['commit'][:12]}")
    csv_sha = sha256(owasp / SELECTION["expected_results"])
    if SELECTION.get("expected_results_sha256") and csv_sha != SELECTION["expected_results_sha256"]:
        warnings.append(f"{SELECTION['expected_results']} отличается от того, на котором отбирался набор")
    meta = {
        "url": SELECTION["url"],
        "commit": commit,
        "commit_date": git(owasp, "log", "-1", "--format=%cI") if commit else None,
        "pinned_commit": SELECTION["commit"],
        "expected_results": SELECTION["expected_results"],
        "expected_results_sha256": csv_sha,
        "selection": SELECTION.get("rule"),
    }
    return meta, warnings


def load_secret_cases():
    """secret_cases.py рядом – по пути: с -I папка скрипта в sys.path не попадает."""
    spec = importlib.util.spec_from_file_location("bench_secret_cases", HERE / "secret_cases.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(args: argparse.Namespace) -> int:
    app = args.app.resolve()
    out_dir = args.out_dir.resolve()
    check_out_dir(out_dir, app)
    if not (app / "app" / "context.py").is_file():
        raise BuildError(f"В {app} нет приложения (app/context.py): укажите --app.")
    owasp = None
    if args.clone is not None:
        dest = Path(args.clone).resolve() if args.clone else (DEFAULT_OUT / "owasp").resolve()
        check_out_dir(dest, app)
        owasp = clone_owasp(dest, args.url, SELECTION["commit"])
    elif args.owasp is not None:
        owasp = args.owasp.resolve()
        if not owasp.is_dir():
            raise BuildError(f"Папки {owasp} нет: укажите клон OWASP Benchmark или используйте --clone.")

    context, models, demo = load_app(app)
    o_cases, o_meta, warnings = [], {}, []
    if owasp is not None:
        o_cases, o_meta = owasp_cases(context, owasp, args.dump_comments)
        clone_info, warnings = owasp_meta(owasp)
        o_meta = {**clone_info, **o_meta}
    d_cases, d_meta = demo_cases(context, demo, app)
    s_cases = load_secret_cases().write_cases(out_dir / "secrets") if args.secrets else []
    cases = o_cases + d_cases + s_cases
    checks = validate(context, models, cases)

    # ---- проверки
    problems = []
    by_id = {c["id"]: c for c in cases}
    if len(by_id) != len(cases):
        problems.append("повторяющиеся id")
    for chk in checks:
        c = by_id[chk["id"]]
        if c["source"] == "owasp":
            want = ("ok", "match")
        elif c["repo_root"] is None:
            want = ("export_line_only", "n/a")
        elif c["id"] == "100105":
            want = ("ok", "differs")
        else:
            want = ("ok", "match")
        got = (chk["status"], chk["export_line_check"])
        if got != want:
            problems.append(f"{c['id']}: build_context {got}, ожидалось {want}")
        if chk["status"] == "ok" and chk["target_line"] != c["line"]:
            problems.append(f"{c['id']}: строка срабатывания {c['line']} не попала в срез ({chk['target_line']})")
    expected_demo = Counter(c["expected"] for c in d_cases)
    if (expected_demo["true_positive"], expected_demo["false_positive"], expected_demo["uncertain"]) != (9, 5, 1):
        problems.append(f"демо: задуманные ответы {dict(expected_demo)}, в README заявлено 9 / 5 / 1")
    if d_meta["script_vs_xlsx_mismatches"]:
        problems.append("демо: сценарий и xlsx расходятся: " + "; ".join(d_meta["script_vs_xlsx_mismatches"]))

    # Что из doPost и кода после него (вложенные классы) не попало в срез приложения (±40 строк).
    coverage = []
    by_check = {chk["id"]: chk for chk in checks}
    for c in o_cases:
        chk = by_check[c["id"]]
        lines = context._split_lines(read_source(context, Path(c["repo_root"]) / c["file"]))
        dopost = next(i for i, text in enumerate(lines, 1) if DOPOST.search(text))
        outside = [i for i, text in enumerate(lines, 1)
                   if i >= dopost and not chk["start_line"] <= i <= chk["end_line"] and text.strip()
                   and not re.fullmatch(r"[\s{}();]*", text) and not text.strip().startswith("//")]
        if dopost < chk["start_line"] or outside:
            coverage.append({"id": c["id"], "dopost_line": dopost, "window": [chk["start_line"], chk["end_line"]],
                             "outside": [f"{i}: {lines[i - 1].strip()}" for i in outside]})

    how = Counter((c["category"], c["expected"], c["how_line"]) for c in o_cases)
    by_cat = Counter((c["source"], c["category"], c["expected"]) for c in cases)
    hints = Counter((c["category"], c["expected"]) for c in o_cases if c["hint_comment"])

    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "cases.json"
    out.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    owasp_block = None
    if owasp is not None:
        owasp_block = {
            **o_meta,
            "how_line": {f"{k[0]}/{k[1]}/{k[2]}": v for k, v in sorted(how.items())},
            "hint_comment_cases": {f"{k[0]}/{k[1]}": v for k, v in sorted(hints.items())},
            "depends_on_cases": [c["id"] for c in o_cases if c["depends_on"]],
            "window_not_covering_dopost_and_after": coverage,
        }
    meta = {
        "created": dt.datetime.now().isoformat(timespec="seconds"),
        "cases_file": out.as_posix(),
        "count": len(cases),
        "owasp": owasp_block,
        "demo": d_meta,
        "by_category": {f"{k[0]}/{k[1]}/{k[2]}": v for k, v in sorted(by_cat.items())},
        "validation": checks,
        "warnings": warnings,
        "problems": problems,
    }
    (out_dir / "cases_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Записано: {out} ({len(cases)} случаев: OWASP {len(o_cases)}, демо {len(d_cases)}, "
          f"секреты {len(s_cases)})")
    if o_cases:
        print("how_line OWASP:", dict(Counter(c["how_line"] for c in o_cases)))
        print("Подсказки в комментариях (OWASP):", {f"{k[0]}/{k[1]}": v for k, v in sorted(hints.items())})
        print("Зависят от другого файла:", owasp_block["depends_on_cases"])
        print("doPost и код после него не целиком в срезе ±40:",
              [(x["id"], len(x["outside"]), x["dopost_line"] < x["window"][0]) for x in coverage])
    print("Демо, задуманные ответы:", dict(expected_demo))
    for w in warnings:
        print("Предупреждение:", w)
    print("Проблемы:" if problems else "Проблем нет.")
    for p in problems:
        print("  -", p)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    try:
        return build(args)
    except BuildError as e:
        print(str(e), file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
