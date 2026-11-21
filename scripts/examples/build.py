"""Сборщик каталога учебных примеров (план стенда, разделы 4.2–4.3).

Шаги для каждого примера каталога examples/catalog/sources.json:
  fetch    – архив по коммиту с codeload.github.com в кэш вне репозитория, распаковка без корня, хеш дерева;
  sast     – собственные учебные правила Semgrep CE (examples/rules), Bandit (Python), gosec (Go) в контейнерах,
             код подключается только для чтения; сырые отчёты – в кэше (в них строки кода, в git не идут);
  sca      – снимки разрешения зависимостей и OSV-Scanner с лицензиями; сырые отчёты – в кэше;
  inputs   – входы без кода в examples/catalog/<id>/inputs (sast.json, sca.json, licenses.json);
  export   – выгрузка формата Hub examples/catalog/<id>/export.xlsx из входов, без кода; catalog.json.

Запуск по порядку: fetch, sast, sca, inputs, export (python scripts/examples/build.py <шаг> [<id> ...]); кэш –
переменная LT_EXAMPLES_CACHE (по умолчанию C:/lt-examples на Windows, ~/.cache/lt-examples иначе). Сеть нужна шагам
fetch, sca и sast (у примеров на Python Bandit ставится в контейнер из PyPI); inputs и export работают без сети."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import unicodedata
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.example_tree import tree_hash_of_dir  # noqa: E402
from app.examples import MAX_ARCHIVE_BYTES, MAX_BYTES_ANY, MAX_FILES_ANY, _name_ok  # noqa: E402 – правила загрузчика

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog_step  # noqa: E402
import sca_step  # noqa: E402
from make_hub_from_sast import ECOSYSTEM_TYPE, HEADERS, MITRE, language_of  # noqa: E402
from osv_sca_csv import cvss_score, fixed_version  # noqa: E402

CATALOG = ROOT / "examples" / "catalog"
SOURCES = CATALOG / "sources.json"


def cache_root() -> Path:
    env = os.environ.get("LT_EXAMPLES_CACHE", "").strip()
    if env:
        return Path(env)
    return Path("C:/lt-examples") if os.name == "nt" else Path.home() / ".cache" / "lt-examples"


def sources() -> list[dict]:
    return json.loads(SOURCES.read_text(encoding="utf-8"))["examples"]


def tree_dir(src: dict) -> Path:
    return cache_root() / "trees" / f"{src['id']}-{src['commit'][:7]}"


def fetch(src: dict) -> dict:
    """Архив по полному коммиту, распаковка с фильтром data без корня архива; повторно – из кэша."""
    target = tree_dir(src)
    archive = cache_root() / "archives" / f"{src['id']}-{src['commit']}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        owner_repo = src["repo_url"].removeprefix("https://github.com/")
        url = f"https://codeload.github.com/{owner_repo}/tar.gz/{src['commit']}"
        request = urllib.request.Request(url, headers={"User-Agent": "local-triage-catalog-build"})
        part = archive.with_name(archive.name + ".part")
        size = 0
        with urllib.request.urlopen(request, timeout=300) as response, open(part, "wb") as out:  # noqa: S310
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    out.close()
                    part.unlink(missing_ok=True)
                    raise SystemExit(f"{src['id']}: архив больше {MAX_ARCHIVE_BYTES // 2**20} МБ – стенд его не скачает")
                out.write(chunk)
        archive_tree(src, part)  # проверка по правилам загрузчика до публикации в кэш
        part.replace(archive)
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise SystemExit(f"{src['id']}: архив больше {MAX_ARCHIVE_BYTES // 2**20} МБ – стенд его не скачает")
    from_archive = archive_tree(src, archive)  # эталон новой ревизии – из архива, не из кэша дерева
    if not target.exists():
        tmp = target.with_name(target.name + ".tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode="r:gz") as tar:
            members = []
            seen_names: set[str] = set()
            for m in tar.getmembers():
                parts = m.name.split("/", 1)
                if len(parts) < 2 or not parts[1]:
                    continue
                if not (m.isfile() or m.isdir()):
                    # те же правила допустимости, что у приложения (app/examples.py): иначе студенту откажут
                    raise SystemExit(f"{src['id']}: в архиве ссылка или особый файл {m.name} – пример не годится")
                if m.name.startswith("/"):
                    raise SystemExit(f"{src['id']}: абсолютный путь {m.name[:120]} – стенд его не примет")
                rel = parts[1].rstrip("/")
                key = unicodedata.normalize("NFC", rel).casefold()
                if "\\" in m.name or not _name_ok(rel) or key in seen_names:
                    raise SystemExit(f"{src['id']}: имя {rel[:120]} стенд не примет (имена Windows, совпадения без "
                                     "учёта регистра) – пример не годится")
                seen_names.add(key)
                m.name = parts[1]
                members.append(m)
            tar.extractall(tmp, members=members, filter="data")
        tmp.rename(target)
    digest, files, total, longest = tree_hash_of_dir(target)
    if digest != from_archive:
        raise SystemExit(f"{src['id']}: дерево в кэше {target} не совпадает с архивом – удалите кэш дерева")
    if files > MAX_FILES_ANY or total > MAX_BYTES_ANY:
        raise SystemExit(f"{src['id']}: файлов {files}, байт {total} – больше пределов загрузчика стенда")
    saved = tree_info_file(src)
    if saved.is_file():  # кэш распакованного дерева – тот же, что закреплён во входах каталога для этого коммита
        known = json.loads(saved.read_text(encoding="utf-8"))
        if known.get("commit") == src["commit"] and known.get("tree_sha256") != digest:
            raise SystemExit(f"{src['id']}: дерево в кэше {target} не совпадает с закреплённым – удалите кэш дерева")
    tar_bytes = 0
    with gzip.open(archive, "rb") as gz:  # размер распакованного TAR – потоком, без распаковки в память
        while block := gz.read(1024 * 1024):
            tar_bytes += len(block)
    max_dir = max((len(p.relative_to(target).as_posix()) for p in target.rglob("*") if p.is_dir()), default=0)
    info = {"commit": src["commit"], "archive_bytes": archive.stat().st_size, "tree_sha256": digest, "files": files,
            "unpacked_bytes": total, "max_relpath": longest, "max_dirpath": max_dir, "tar_bytes": tar_bytes}
    dump(saved, info)
    return info


def archive_tree(src: dict, archive: Path) -> str:
    """Хеш дерева прямо из архива по правилам загрузчика стенда (app/examples.py): первая запись – общий корень,
    все остальные – внутри него, только файлы и папки, допустимые имена; иначе пример не годится."""
    from app.example_tree import tree_hash

    entries = []
    with tarfile.open(archive, mode="r|gz") as tar:  # потоком: записи и объём считаются до чтения содержимого
        root: str | None = None
        names: set[str] = set()
        count = total = 0
        for m in tar:
            count += 1
            total += m.size if m.isfile() else 0
            if count > MAX_FILES_ANY + 50_000 or total > MAX_BYTES_ANY:
                raise SystemExit(f"{src['id']}: в архиве больше записей или байт, чем принимает загрузчик стенда")
            if root is None:
                if not m.isdir() or "/" in m.name.strip("/"):
                    raise SystemExit(f"{src['id']}: первая запись архива – не общая папка исходников")
                root = m.name.strip("/")
                continue
            parts = m.name.split("/", 1)
            if parts[0] != root or len(parts) < 2 or not parts[1].strip("/") or m.name.startswith("/"):
                raise SystemExit(f"{src['id']}: запись {m.name[:120]} вне общей папки архива")
            if not (m.isfile() or m.isdir()):
                raise SystemExit(f"{src['id']}: в архиве ссылка или особый файл {m.name[:120]}")
            rel = parts[1].rstrip("/")
            folded = unicodedata.normalize("NFC", rel).casefold()
            if "\\" in m.name or not _name_ok(rel) or folded in names:
                raise SystemExit(f"{src['id']}: имя {rel[:120]} стенд не примет (имена Windows, совпадения без учёта "
                                 "регистра)")
            names.add(folded)
            if m.isfile():
                entries.append((parts[1], tar.extractfile(m).read()))  # type: ignore[union-attr]
    return tree_hash(entries)


def reports_dir(src: dict) -> Path:
    """Сырые отчёты анализаторов – по примеру и полному коммиту: отчёты прежней ревизии с новой не смешиваются."""
    return cache_root() / "reports" / f"{src['id']}-{src['commit']}"


def required_reports(src: dict) -> list[str]:
    """Отчёты, без которых входы SAST неполны: Semgrep (если есть правила языка), Bandit (Python), gosec (Go)."""
    names = ["semgrep.json"] if rule_files(src) else []
    langs = " ".join(cb["languages"].lower() for cb in src["codebases"])
    if "python" in langs:
        names.append("bandit.json")
    names += [f"gosec-{cb['name']}.json" for cb in src["codebases"]
              if "go" in cb["languages"].lower().split(", ") or cb["languages"].lower().startswith("go")]
    return names


def tree_info_file(src: dict) -> Path:
    """Сведения о дереве закреплённой ревизии – во входах каталога: экспорт работает без кэша и сети."""
    return CATALOG / src["id"] / "inputs" / "tree.json"


SEMGREP_IMAGE = "semgrep/semgrep:1.181.1"
GOSEC_IMAGE = "securego/gosec:2.22.10"
BANDIT_IMAGE = "python:3.12-slim"
EXCLUDES = ["node_modules", "vendor", "*.min.js", "frontend/src/assets", "data/static/codefixes", "test", "tests", "spec", "e2e", "cypress",
            "migrations", "dist", "build", ".github"]
RULES_BY_LANGUAGE = {"javascript": "javascript.yml", "typescript": "javascript.yml", "python": "python.yml",
                     "java": "java.yml", "php": "php.yml", "ruby": "ruby.yml", "go": "go.yml", "csharp": "csharp.yml"}


def _docker(args: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "run", "--rm", *args], capture_output=True, timeout=timeout)


def rule_files(src: dict) -> list[str]:
    langs = {lang.strip().lower() for cb in src["codebases"] for lang in re.split(r"[,/()]", cb["languages"]) if lang.strip()}
    found = set()
    for lang in langs:
        for key, file in RULES_BY_LANGUAGE.items():
            if lang.startswith(key) or (key == "csharp" and lang.startswith("c#")):
                found.add(file)
    return sorted(f for f in found if (ROOT / "examples" / "rules" / f).exists())


def sast(src: dict) -> dict:
    """Учебные правила Semgrep CE по языкам примера, Bandit для Python, gosec для Go; отчёты – в кэше."""
    tree = tree_dir(src)
    out = reports_dir(src)
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    configs = rule_files(src)
    if configs:
        args = ["-v", f"{tree}:/src:ro", "-v", f"{ROOT / 'examples' / 'rules'}:/rules:ro", SEMGREP_IMAGE, "semgrep", "scan",
                "--metrics=off", "--disable-version-check", "--json", "--quiet", "--timeout", "30"]
        for c in configs:
            args += ["--config", f"/rules/{c}"]
        for e in EXCLUDES:
            args += ["--exclude", e]
        run = _docker(args + ["/src"])
        data = _report(run, "Semgrep", "results", ok_codes=(0, 1))
        (out / "semgrep.json").write_bytes(run.stdout)
        summary["semgrep"] = dict(Counter(r["check_id"].rsplit(".", 1)[-1] for r in data.get("results", [])))
        summary["semgrep_errors"] = [str(e.get("message"))[:200] for e in data.get("errors", [])][:3]
    langs = " ".join(cb["languages"].lower() for cb in src["codebases"])
    if "python" in langs:
        run = _docker(["-v", f"{tree}:/src:ro", BANDIT_IMAGE, "sh", "-c",
                       "pip install -q bandit==1.8.6 >/dev/null 2>&1 && bandit -q -r /src -f json -x "
                       "/src/tests,/src/test,/src/node_modules,/src/migrations"])
        data = _report(run, "Bandit", "results", ok_codes=(0, 1))
        (out / "bandit.json").write_bytes(run.stdout)
        summary["bandit"] = dict(Counter(r["test_id"] for r in data.get("results", [])))
    if " go" in f" {langs}":
        for cb in src["codebases"]:
            if "go" not in cb["languages"].lower().split(", ") and not cb["languages"].lower().startswith("go"):
                continue
            mount = tree / cb["path"] if cb["path"] else tree
            run = _docker(["-v", f"{mount}:/src:ro", "-w", "/src", GOSEC_IMAGE, "-fmt", "json", "-quiet", "-no-fail", "./..."])
            name = f"gosec-{cb['name']}.json"
            data = _report(run, "gosec", "Issues", ok_codes=(0,))
            (out / name).write_bytes(run.stdout)
            summary[name] = dict(Counter(i["rule_id"] for i in data.get("Issues") or []))
    return summary


def _report(run: subprocess.CompletedProcess, tool: str, key: str, ok_codes: tuple[int, ...]) -> dict:
    """Отчёт анализатора только при штатном завершении и с ожидаемой структурой; иначе сборка останавливается, а
    прежний отчёт и входы каталога не заменяются (ревью сборки Б, круг 2)."""
    if run.returncode not in ok_codes:
        raise SystemExit(f"{tool}: код выхода {run.returncode}: " + run.stderr.decode("utf-8", "replace")[-300:])
    try:
        data = json.loads(run.stdout.decode("utf-8"))
    except ValueError:
        raise SystemExit(f"{tool}: отчёт не JSON: " + run.stderr.decode("utf-8", "replace")[-300:]) from None
    if not isinstance(data, dict) or key not in data:
        raise SystemExit(f"{tool}: в отчёте нет раздела {key}")
    return data


def sca(src: dict, build_date: str) -> dict:
    """Снимки по перечню манифестов и OSV-Scanner; сырой вывод – в кэше, снимки – во входы каталога."""
    tree = tree_dir(src)
    out = reports_dir(src)
    out.mkdir(parents=True, exist_ok=True)
    lock_root = CATALOG / src["id"] / "inputs" / "lock"
    summary, entries, licenses, excluded, excluded_modules = {}, [], [], [], []
    for m in src["manifests"]:
        snap, reason = sca_step.make_snapshot(tree, m, lock_root / sca_step.slug(m["path"]), build_date)
        if snap is None:
            shutil.rmtree(lock_root / sca_step.slug(m["path"]), ignore_errors=True)  # снимок прежней ревизии не остаётся
            excluded.append({"manifest": m["path"], "codebase": m["codebase"], "reason": reason})
            summary[m["path"]] = "исключён: " + reason[:120]
            continue
        report = sca_step.osv_scan(snap)
        (out / f"osv-{sca_step.slug(m['path'])}.json").write_text(json.dumps(report, ensure_ascii=False),
                                                                 encoding="utf-8")
        # все разрешённые пары «компонент – версия» снимка (у Maven – разрешение deps.dev): по ним тест сверяет строки
        dump(snap.parent / "resolved.json", sca_step.resolved_pairs(report))
        local = snap.parent / "local-replace.txt"
        if local.is_file():
            for module in local.read_text(encoding="utf-8").split():
                excluded_modules.append({"manifest": m["path"], "codebase": m["codebase"], "module": module,
                                         "reason": "replace на локальную папку без версии – уязвимости не проверены"})
        rows, lic = sca_step.osv_entries(report, m["codebase"], m["path"], fixed_version, cvss_score)
        entries += rows
        licenses += lic
        summary[m["path"]] = f"уязвимостей {len(rows)}, лицензий вне перечня {len(lic)}"
    inputs = CATALOG / src["id"] / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    dump(inputs / "sca.json", {"build_date": build_date, "osv_date": __import__("datetime").date.today().isoformat(),
                               "commit": src["commit"], "tool": sca_step.OSV_IMAGE, "entries": entries,
                               "excluded_manifests": excluded, "excluded_modules": excluded_modules})
    dump(inputs / "licenses.json", {"build_date": build_date, "commit": src["commit"], "tool": sca_step.OSV_IMAGE,
                                    "allowed": sca_step.ALLOWED_LICENSES, "entries": licenses})
    return summary


TOOLS = {"semgrep": f"Semgrep CE {SEMGREP_IMAGE.split(':')[1]}, учебные правила examples/rules",
         "bandit": "Bandit 1.8.6", "gosec": f"gosec {GOSEC_IMAGE.split(':')[1]}",
         "osv-scanner": f"OSV-Scanner {sca_step.OSV_IMAGE.split(':')[1].lstrip('v')}"}


def publish(records: list[dict], build_date: str, full: bool) -> None:
    """Книги, catalog.json и NOTICE.md – комплектом: всё готовится заранее (.new), затем замена; при сбое замены
    прежние файлы возвращаются из копий (.bak), и комплект остаётся согласованным."""
    catalog_text, notice_text = catalog_texts(records, build_date, full)
    staged = [(CATALOG / (r["export"]["file"] + ".new"), CATALOG / r["export"]["file"]) for r in records]
    for name, text in (("catalog.json", catalog_text), ("NOTICE.md", notice_text)):
        (CATALOG / (name + ".new")).write_text(text, encoding="utf-8", newline="\n")
        staged.append((CATALOG / (name + ".new"), CATALOG / name))
    journal = CATALOG / "publish.journal.json"
    part = journal.with_name(journal.name + ".part")
    part.write_text(json.dumps([str(final) for _, final in staged], ensure_ascii=False), encoding="utf-8")
    part.replace(journal)  # журнал появляется целиком, до первой замены
    backups = []
    try:
        for new, final in staged:
            if final.exists():
                bak = final.with_name(final.name + ".bak")
                part = final.with_name(final.name + ".bak.part")
                shutil.copyfile(final, part)  # неполная копия не получает имя .bak и не вернётся при откате
                part.replace(bak)
                backups.append((bak, final))
            new.replace(final)
    except BaseException:
        for bak, final in backups:
            bak.replace(final)
        raise
    journal.unlink(missing_ok=True)  # комплект заменён целиком
    for bak, _ in backups:
        bak.unlink(missing_ok=True)


def recover_publish() -> None:
    """Публикация оборвалась жёстко (журнал остался): прежний согласованный комплект возвращается из копий .bak."""
    journal = CATALOG / "publish.journal.json"
    (CATALOG / "publish.journal.json.part").unlink(missing_ok=True)  # журнал не был опубликован – замен не было
    if not journal.is_file():
        return
    try:
        finals = json.loads(journal.read_text(encoding="utf-8"))
    except ValueError:
        finals = []
    for final in finals:
        bak = Path(final).with_name(Path(final).name + ".bak")
        if bak.is_file():
            bak.replace(final)
    journal.unlink(missing_ok=True)
    print("прерванная публикация каталога откатана к прежнему комплекту")


def catalog_texts(records: list[dict], build_date: str, full: bool) -> tuple[str, str]:
    demo = {"id": "demo-library", "number": 0, "title": "Demo Library (выдуманная)",
            "description": "Выдуманная библиотека из двух кодовых баз на Java и Python: тот же демо-проект, что "
                           "кнопка «Создать демо-проект».", "level": "начальный", "languages": ["Java", "Python"],
            "cwe": [], "source": None, "builtin": "demo",
            "codebases": [{"name": "billing-core", "path": "", "languages": "Java"},
                          {"name": "catalog-api", "path": "", "languages": "Python"}],
            "sca_inputs": [], "excluded_manifests": [], "export": None, "expected_missing": []}
    # адресный экспорт обновляет только свои записи; полная пересборка – только примеры из sources.json
    previous = {}
    if not full and (CATALOG / "catalog.json").is_file():
        previous = {r["id"]: r for r in json.loads((CATALOG / "catalog.json").read_text(encoding="utf-8"))["examples"]
                    if r.get("source")}
    previous.update({r["id"]: r for r in records})
    records = sorted(previous.values(), key=lambda r: r["number"])
    catalog_text = json.dumps({"schema": 1, "build_date": build_date, "tools": TOOLS, "examples": [demo] + records},
                              ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    return catalog_text, notice(records, build_date)


# Лицензии источников данных OSV – по таблице «Current data sources» страницы https://google.github.io/osv.dev/data/
# (проверено 21.11.2026); тексты лицензий GHSA и PYSEC – в LICENSE репозиториев github/advisory-database и
# pypa/advisory-database
OSV_SOURCES = {
    "GHSA": ("GitHub Advisory Database, https://github.com/github/advisory-database", "CC-BY 4.0"),
    "PYSEC": ("PyPI Advisory Database, https://github.com/pypa/advisory-database", "CC-BY 4.0"),
    "GO": ("Go Vulnerability Database, https://pkg.go.dev/vuln/", "CC-BY 4.0"),
    "MAL": ("OpenSSF Malicious Packages, https://github.com/ossf/malicious-packages", "Apache 2.0"),
}


def _osv_prefixes(example_id: str) -> list[str]:
    doc = json.loads((CATALOG / example_id / "inputs" / "sca.json").read_text(encoding="utf-8"))
    return sorted({str(e["osv_id"]).split("-")[0] for e in doc["entries"]})


def notice(records: list[dict], build_date: str) -> str:
    lines = ["# Каталог учебных примеров: источники и лицензии", "",
             f"Дата снимков зависимостей: {build_date}; данные OSV и deps.dev – на дату сборки выгрузок (osv_date в catalog.json). Код примеров в пакет и в репозиторий не входит: каталог хранит адрес "
             "репозитория и полный коммит, исходники скачиваются с GitHub при первом запуске стенда и сверяются по "
             "хешу дерева. Выгрузки `*/export.xlsx` содержат только номера находок, правила, пути, номера строк, "
             "компоненты и версии; колонка Source code пустая и заполняется на компьютере студента из скачанных файлов.",
             "", "## Примеры", "", "| № | Пример | Репозиторий и коммит | Лицензия | SAST | SCA | Лицензии |",
             "|---|---|---|---|---|---|---|"]
    for r in records:
        s, x = r["source"], r["export"]
        lines.append(f"| {r['number']} | {r['title']} | {s['repo_url']} (`{s['commit']}`) | {s['license']} | "
                     f"{x['sast']} | {x['sca']} | {x['compliance']} |")
    lines += ["", "Лицензия каждого примера установлена по файлу LICENSE и разделу о лицензии README закреплённой "
              "ревизии. Примеры распространяют их авторы; стенд скачивает их с GitHub по запросу.", "",
              "## Анализаторы", "",
              f"- SAST: {TOOLS['semgrep']} – движок Semgrep CE (LGPL-2.1, https://github.com/semgrep/semgrep) с "
              "собственными учебными правилами репозитория (`examples/rules`, лицензия MIT); правила реестра Semgrep "
              "не используются.",
              f"- SAST Python: {TOOLS['bandit']} (Apache-2.0, https://github.com/PyCQA/bandit).",
              f"- SAST Go: {TOOLS['gosec']} (Apache-2.0, https://github.com/securego/gosec).",
              f"- SCA и лицензии компонентов: {TOOLS['osv-scanner']} (Apache-2.0, https://github.com/google/osv-scanner)."
              " Уязвимости – из базы OSV (https://osv.dev), лицензии компонентов – из deps.dev (https://deps.dev) на "
              "дату сборки.", "",
              "## Данные OSV", "",
              "Префиксы идентификаторов записей OSV, вошедших во входы каталога, по примерам (источник записи – по "
              "префиксу: GHSA – GitHub Advisory Database, PYSEC – PyPI Advisory Database, GO – Go Vulnerability "
              "Database и т. д.):", ""]
    used: set[str] = set()
    for r in records:
        prefixes = _osv_prefixes(r["id"])
        used.update(prefixes)
        lines.append(f"- {r['title']}: {', '.join(prefixes) or 'записей нет'}")
    lines += ["", "Условия использования данных – по таблице источников OSV (https://google.github.io/osv.dev/data/):", "",
              "| Префикс | Источник | Лицензия данных |", "|---|---|---|"]
    for prefix in sorted(used):
        name, lic = OSV_SOURCES.get(prefix, ("не установлен", "не установлена – см. страницу источников OSV"))
        lines.append(f"| {prefix} | {name} | {lic} |")
    lines += ["", "## Учебная политика лицензий", "",
              "Находка листа SCA Compliance – компонент, лицензия которого не входит в перечень разрешительных "
              "лицензий учебной политики (`scripts/examples/sca_step.py`, ALLOWED_LICENSES). Сильный копилефт "
              "(GPL, AGPL и др.) – High, слабый копилефт (LGPL, MPL, EPL, OFL и др.) – Medium, прочие и компоненты "
              "без сведений о лицензии – Low. У экосистем, по которым deps.dev сведений о лицензиях не даёт "
              "(RubyGems, Packagist), отсутствие лицензии находкой не считается.", "",
              "## Что не вошло в выгрузки", ""]
    for r in records:
        d = r["export"]["dropped"]
        label = {"sast": "SAST", "sca": "SCA", "licenses": "лицензии"}
        parts = [f"{label[group]}, {k} – {v}" for group in ("sast", "sca", "licenses")
                 for k, v in (d.get(group) or {}).items() if v]
        for m in r.get("excluded_manifests") or []:
            parts.append(f"манифест {m['manifest']} – {m['reason']}")
        for m in r.get("excluded_modules") or []:
            parts.append(f"модуль {m['module']} ({m['manifest']}) – {m['reason']}")
        lines.append(f"- {r['title']}: " + ("; ".join(parts) if parts else "ничего"))
    lines += ["", "Предел выгрузки: до 80 находок SAST (по кругу между правилами), до 60 строк SCA (сначала рабочие "
              "зависимости и больший CVSS), до 30 находок о лицензиях. Строка SCA без разрешённой версии в "
              "выгрузку не идёт: снимки разрешения зависимостей лежат во входах `*/inputs/lock/`.", ""]
    return "\n".join(lines)


def dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8",
                    newline="\n")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    step, ids = argv[0], set(argv[1:])
    recover_publish()
    build_date = json.loads(SOURCES.read_text(encoding="utf-8"))["build_date"]
    records: list[dict] = []
    selected = [s for s in sources() if not ids or s["id"] in ids]
    state_file = cache_root() / "state.json"
    state = {}
    if step != "export" and state_file.exists():  # экспорт – только из входов каталога, без кэша сборки
        state = json.loads(state_file.read_text(encoding="utf-8"))
    for src in selected:
        if step == "fetch":
            info = fetch(src)
            state.setdefault(src["id"], {})["tree"] = info
            print(f"{src['id']}: файлов {info['files']}, {info['unpacked_bytes'] // 1024} КБ, дерево {info['tree_sha256'][:12]}")
        elif step == "inputs":
            missing = [n for n in required_reports(src) if not (reports_dir(src) / n).is_file()]
            if missing:
                raise SystemExit(f"{src['id']}: нет отчётов {', '.join(missing)} – сначала шаг sast; входы не заменены")
            n = catalog_step.write_sast_inputs(src, CATALOG, tree_dir(src), reports_dir(src),
                                               build_date, TOOLS)
            print(f"{src['id']}: входы SAST – {n} находок")
        elif step == "export":
            tree = json.loads(tree_info_file(src).read_text(encoding="utf-8"))
            if tree.get("commit") != src["commit"]:
                raise SystemExit(f"{src['id']}: входы дерева – другого коммита: сначала fetch, sca, inputs")
            src["tree"] = {k: v for k, v in tree.items() if k != "commit"}
            record = catalog_step.build_example(src, CATALOG, HEADERS, MITRE, ECOSYSTEM_TYPE, language_of, build_date,
                                                TOOLS)
            records.append(record)
            x = record["export"]
            print(f"{src['id']}: SAST {x['sast']}, SCA {x['sca']}, лицензии {x['compliance']}, {x['sha256'][:12]}")
        elif step == "sca":
            info = sca(src, json.loads(SOURCES.read_text(encoding="utf-8"))["build_date"])
            state.setdefault(src["id"], {})["sca"] = info
            print(f"{src['id']}: {json.dumps(info, ensure_ascii=False)}")
        elif step == "sast":
            info = sast(src)
            state.setdefault(src["id"], {})["sast"] = info
            total = sum(sum(v.values()) for k, v in info.items() if isinstance(v, dict) and "ошибка" not in v)
            print(f"{src['id']}: находок {total} – {json.dumps(info, ensure_ascii=False)[:600]}")
        else:
            print(f"неизвестный шаг {step}")
            return 2
    if step == "export":
        publish(records, build_date, full=not ids)
    if step != "export":
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
