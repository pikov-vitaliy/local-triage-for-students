"""Список компонентов проекта с известными уязвимостями – CSV для `make_hub_from_sast.py --sca` (лист «SCA Security»
демонстрационной выгрузки). Источник сведений – открытый API OSV (https://api.osv.dev, POST /v1/query по паре
«экосистема, имя, версия»); в запрос уходят только экосистема, имя и версия компонента – запускать только для
тестовых проектов с GitHub.

Поддерживаются манифесты: `requirements.txt` (PyPI, строки `имя==версия`), `package-lock.json` (npm, раздел
`packages`), `package.json` (npm: диапазон `^x.y.z`, `~x.y.z`, `>=x.y.z` или точная версия – берётся нижняя граница и
это отмечается в колонке note; другие диапазоны пропускаются), `pom.xml` (Maven, `<dependency>` вне комментариев,
`<dependencyManagement>`, `<profiles>` и `<build>`, версия явная или из `<properties>`; нерешённое свойство – пропуск с
сообщением). Колонки CSV: ecosystem,component,version,cve,cvss,fixed,note – по строке на уязвимость; у уязвимости без
CVE в колонке cve – идентификатор OSV/GHSA; note – предположение о версии или отметка «ещё N уязвимостей не
включены» (предел `--limit`). Запрос к OSV не удался – компонент пропущен, об этом строка в stderr и код выхода 2:
такой CSV неполон.

Запуск из корня репозитория:
    .venv\\Scripts\\python scripts/osv_sca_csv.py --requirements test-projects/pygoat/requirements.txt --out test-projects/pygoat-sca.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
from pathlib import Path

OSV = "https://api.osv.dev/v1/query"
COLUMNS = ["ecosystem", "component", "version", "cve", "cvss", "fixed", "note", "osv_id", "osv_aliases", "osv_modified"]
Component = tuple[str, str, str, str]  # экосистема, имя, версия, примечание («» – версия точная)


def requirements(path: Path) -> list[Component]:
    found = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
        if m:
            found.append(("PyPI", m.group(1), m.group(2), ""))
    return found


def package_lock(path: Path) -> list[Component]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    found = []
    for key, item in (data.get("packages") or {}).items():
        name = key.rsplit("node_modules/", 1)[-1]
        if name and item.get("version") and not item.get("dev"):
            found.append(("npm", name, str(item["version"]), ""))
    return sorted(set(found))


_NPM_RANGE = re.compile(r"^(\^|~|>=|=)?\s*v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)$")


def package_json(path: Path) -> list[Component]:
    """Зависимости package.json без файла блокировки. Поддерживаются `^x.y.z`, `~x.y.z`, `>=x.y.z` и точная версия:
    берётся нижняя граница, в примечании – исходный диапазон. Другие записи (`*`, `<2.0.0`, `1.x`, `a || b`, адреса
    git, `latest`) версии не дают – пропускаются с сообщением в stderr."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    found = []
    for name, spec in (data.get("dependencies") or {}).items():
        m = _NPM_RANGE.match(str(spec).strip())
        if not m:
            print(f"npm {name} {spec}: диапазон не поддерживается – пропуск", file=sys.stderr)
            continue
        note = f"версия – нижняя граница диапазона {str(spec).strip()}" if m.group(1) and m.group(1) != "=" else ""
        found.append(("npm", name, m.group(2), note))
    return sorted(set(found))


def pom(path: Path) -> list[Component]:
    """Зависимости pom.xml – без разбора XML как документа (внешние сущности не раскрываются). Из текста убираются
    комментарии, `<profiles>`, `<build>` и `<reporting>` (неактивные профили, плагины); `<dependencyManagement>` даёт
    только управляемые версии для зависимостей, объявленных без `<version>`; свойства ${…} – из <properties>, одна
    подстановка; нерешённое свойство или зависимость без версии (родительский BOM) – пропуск с сообщением."""
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    for tag in ("profiles", "build", "reporting"):
        text = re.sub(rf"<{tag}>.*?</{tag}>", "", text, flags=re.S)
    props: dict[str, str] = {}
    if "<properties>" in text:
        inner = text.split("<properties>", 1)[1].split("</properties>", 1)[0]
        for name, value in re.findall(r"<([A-Za-z0-9_.\-]+)>\s*([^<\s][^<]*?)\s*</\1>", inner):
            props[name] = value

    def resolve(raw: str) -> str:
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), raw)

    def entries(chunk: str) -> list[tuple[str, str]]:
        out = []
        for block in re.findall(r"<dependency>(.*?)</dependency>", chunk, re.S):
            g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", block)
            a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
            v = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
            if g and a:
                out.append((f"{resolve(g.group(1))}:{resolve(a.group(1))}", resolve(v.group(1)) if v else ""))
        return out

    managed: dict[str, str] = {}
    for m in re.finditer(r"<dependencyManagement>(.*?)</dependencyManagement>", text, re.S):
        managed.update({k: v for k, v in entries(m.group(1)) if v})
    text = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", text, flags=re.S)
    found = []
    for key, version in entries(text):
        version = version or managed.get(key, "")
        if not version:
            print(f"Maven {key}: версия не задана (родительский BOM?) – пропуск", file=sys.stderr)
            continue
        if "${" in version:
            print(f"Maven {key} {version}: свойство не разрешено – пропуск", file=sys.stderr)
            continue
        found.append(("Maven", key, version, ""))
    return sorted(set(found))


_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
          "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}, "I": {"H": 0.56, "L": 0.22, "N": 0.0},
          "A": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(value: float) -> float:
    """Округление вверх до десятых по спецификации CVSS 3.1 (целочисленно, без ошибок плавающей точки)."""
    whole = int(round(value * 100000))
    return whole / 100000.0 if whole % 10000 == 0 else (whole // 10000 + 1) / 10.0


def cvss_base_score(vector: str) -> str:
    """Базовая оценка по вектору CVSS 3.0/3.1 (формула спецификации FIRST, раздел 7.1); не вектор 3.x – пусто."""
    m = re.match(r"^CVSS:3\.[01]/(.+)$", str(vector or "").strip())
    if not m:
        return ""
    parts = dict(p.split(":", 1) for p in m.group(1).split("/") if ":" in p)
    try:
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _CVSS3["C"][parts["C"]]) * (1 - _CVSS3["I"][parts["I"]]) * (1 - _CVSS3["A"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _CVSS3["AV"][parts["AV"]] * _CVSS3["AC"][parts["AC"]] * pr * _CVSS3["UI"][parts["UI"]]
    except KeyError:
        return ""
    if impact <= 0:
        return "0.0"
    score = _roundup(min(1.08 * (impact + exploit), 10)) if scope_changed else _roundup(min(impact + exploit, 10))
    return f"{score:.1f}"


def cvss_score(vuln: dict) -> str:
    """Оценка CVSS записи OSV: число из database_specific, иначе базовая оценка по вектору 3.x в severity."""
    ds = vuln.get("database_specific") or {}
    for key in ("cvss_score", "severity"):
        value = ds.get(key)
        if isinstance(value, (int, float)):
            return f"{float(value):.1f}"
    for sev in vuln.get("severity") or []:
        score = cvss_base_score(str(sev.get("score") or ""))
        if score:
            return score
    return ""


_RELEASE_WORDS = {"final", "ga", "release", "sp"}


def _vkey(version: str, ecosystem: str = "") -> tuple:
    """Ключ версии с порядком своей экосистемы (ревью сборки Б): PyPI – по PEP 440 (packaging), прочие – как SemVer:
    предварительный выпуск (1.0.0-rc.1, 1.0rc1) раньше выпуска; без цифр – пустой ключ."""
    text = str(version or "").strip()
    if not re.search(r"\d", text):
        return ()
    if ecosystem.lower() == "pypi":
        try:
            from packaging.version import Version

            v = Version(text)
            return (0, v)
        except Exception:  # noqa: BLE001 – не по PEP 440: общий разбор ниже
            pass
    text = text.split("+", 1)[0]  # метаданные сборки (SemVer 2.0.0, п. 10) на порядок версий не влияют
    core, _, pre = text.lstrip("vV").partition("-")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", core)
    if not m:
        return ()
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (6 - len(nums)) if len(nums) < 6 else nums
    semver = ecosystem.lower() in ("npm", "go", "cargo", "nuget")  # SemVer: любой суффикс – предварительный выпуск
    if semver:
        tail = pre if pre else m.group(2).lstrip(".")  # SemVer: идентификаторы как есть, с концевым «-» и регистром
        if ecosystem.lower() == "nuget":
            tail = tail.lower()  # NuGet сравнивает метки предварительного выпуска без учёта регистра
    else:
        # прочие экосистемы: обозначения без учёта регистра (RC, Final)
        tail = (m.group(2).lstrip(".") + ("-" + pre if pre else "")).strip("-.").lower()
    if not tail or (not semver and tail in _RELEASE_WORDS):
        return (1, nums, 1, ())
    if semver:
        pieces = tail.split(".")  # SemVer: «alpha-1» – один идентификатор
    else:  # Maven и др.: «rc10» – «rc» и 10, числа внутри квалификатора сравниваются как числа
        pieces = [p for chunk in re.split(r"[.\-+_]", tail) for p in re.findall(r"\d+|[^\d]+", chunk)]
    parts = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pieces if x)
    return (1, nums, 0, parts)


def fixed_version(vuln: dict, ecosystem: str, name: str, version: str) -> str:
    """Версия исправления для исследуемой версии: из диапазонов записи OSV по этому пакету и экосистеме, кроме
    диапазонов GIT (там хеши коммитов, не версии). События диапазона разбираются по парам: каждое introduced открывает
    интервал, ближайшее fixed или last_affected его закрывает. Исправление берётся только из интервала, в который
    попадает версия; этот интервал открыт (`[2.0, …)`) или закрыт last_affected – исправления нет, пусто, даже если у
    другого интервала оно есть. Версия не попала ни в один интервал – пусто (неоднозначность не угадывается; было до
    изменения: перезапись introduced и fixed до конца массива событий и подстановка единственного исправления
    записи)."""
    key = _vkey(version, ecosystem)
    if not key:
        return ""
    found: set[str] = set()
    open_hit = False
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if str(package.get("name") or "").lower() != name.lower():
            continue
        if package.get("ecosystem") and str(package["ecosystem"]).lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges") or []:
            if str(rng.get("type") or "").upper() == "GIT":
                continue
            start: str | None = None
            for event in list(rng.get("events") or []) + [{"end": True}]:
                if event.get("introduced") is not None:
                    if start is not None and _after(start, key, ecosystem):  # прежний интервал так и не закрылся
                        open_hit = True
                    start = str(event["introduced"])
                    continue
                if start is None:
                    continue
                end = event.get("fixed") or event.get("last_affected")
                if event.get("end"):
                    if _after(start, key, ecosystem):
                        open_hit = True  # [start, …) без закрытия
                    start = None
                    continue
                if end is None:
                    continue
                if event.get("fixed"):
                    if _after(start, key, ecosystem) and key < _vkey(str(end), ecosystem):
                        found.add(str(end))
                elif _after(start, key, ecosystem) and key <= _vkey(str(end), ecosystem):
                    open_hit = True  # last_affected: исправленной версии нет
                start = None
    if open_hit or len(found) != 1:
        return ""
    return next(iter(found))


def _after(start: str, key: tuple, ecosystem: str = "") -> bool:
    """Версия не раньше начала интервала («0» – с самого начала)."""
    return start == "0" or _vkey(start, ecosystem) <= key


def osv_json_rows(path: Path) -> list[dict]:
    """Строки CSV из сохранённого вывода OSV-Scanner (JSON, без сети): одна строка на группу псевдонимов, запись группы
    – GHSA раньше остальных, затем по ID; колонки происхождения osv_id, osv_aliases, osv_modified."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "examples"))
    import sca_step

    report = json.loads(path.read_text(encoding="utf-8"))
    entries, _ = sca_step.osv_entries(report, "", "", fixed_version, cvss_score)
    return [{"ecosystem": e["ecosystem"].lower(), "component": e["name"], "version": e["version"], "cve": e["cve"],
             "cvss": e["cvss"], "fixed": e["fixed"], "note": "", "osv_id": e["osv_id"],
             "osv_aliases": " ".join(e["osv_aliases"]), "osv_modified": e["osv_modified"]} for e in entries]


def alias_groups(vulns: list[dict]) -> dict[str, list[dict]]:
    """Записи OSV, связанные общими идентификаторами или псевдонимами, – одна группа (объединение по всем
    псевдонимам, независимо от их порядка); ключ группы – наименьший CVE группы, иначе наименьший ID."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in vulns:
        ids = [str(v.get("id") or "")] + [str(a) for a in v.get("aliases") or []]
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
    groups: dict[str, list[dict]] = {}
    for v in vulns:
        groups.setdefault(find(str(v.get("id") or "")), []).append(v)
    out = {}
    for members in groups.values():
        ids = {str(i) for m in members for i in [m.get("id")] + list(m.get("aliases") or []) if i}
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        out[cves[0] if cves else sorted(ids)[0]] = members
    return out


def merge_rows(rows: list[dict]) -> list[dict]:
    """Строки одного компонента из разных входов: связанные общими ID, CVE или псевдонимами – одна уязвимость.
    Одна запись в двух редакциях – более поздняя (osv_modified); выбор записи группы – GHSA раньше, затем по ID;
    результат не зависит от порядка входов."""
    latest: dict[str, dict] = {}
    for row in rows:
        old = latest.get(row["osv_id"])
        if old is None or str(row.get("osv_modified") or "") > str(old.get("osv_modified") or ""):
            latest[row["osv_id"]] = row
    pseudo = [{"id": r["osv_id"], "aliases": r["osv_aliases"].split() + ([r["cve"]] if r["cve"] else [])}
              for r in latest.values()]
    out = []
    for _key, members in alias_groups(pseudo).items():
        group_rows = [latest[m["id"]] for m in members]
        chosen = min(group_rows, key=_row_key)
        ids = {i for r in group_rows for i in [r["osv_id"], r["cve"], *r["osv_aliases"].split()] if i}
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        out.append({**chosen, "cve": cves[0] if cves else chosen["cve"],
                    "osv_aliases": " ".join(sorted(i for i in ids if i != chosen["osv_id"]))})
    return sorted(out, key=lambda r: r["cve"])


def _row_key(row: dict) -> tuple:
    osv_id = str(row.get("osv_id") or "")
    return (0 if osv_id.startswith("GHSA-") else 1, osv_id)


def _pick(vulns: list[dict]) -> dict:
    """Одна запись на CVE в обоих режимах: GHSA раньше остальных, затем по ID (план стенда, раздел 4.2)."""
    return sorted(vulns, key=lambda v: (0 if str(v.get("id", "")).startswith("GHSA-") else 1, str(v.get("id", ""))))[0]


def query(ecosystem: str, name: str, version: str) -> list[dict]:
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}, "version": version}).encode("utf-8")
    req = urllib.request.Request(OSV, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 – адрес фиксирован
        return (json.loads(resp.read().decode("utf-8")) or {}).get("vulns") or []


def collect(components: list[Component], limit: int) -> tuple[list[dict], int, int]:
    """Строки CSV по компонентам: (строки, компонентов с ошибкой запроса, компонентов с усечением по limit)."""
    rows: list[dict] = []
    failed = truncated = 0
    for ecosystem, name, version, note in components:
        try:
            vulns = query(ecosystem, name, version)
        except Exception as e:  # noqa: BLE001 – сетевой сбой одного запроса не останавливает сбор, но считается
            print(f"{ecosystem} {name} {version}: запрос не удался ({type(e).__name__}) – компонент пропущен",
                  file=sys.stderr)
            failed += 1
            continue
        groups = alias_groups(vulns)  # одна уязвимость – одна строка: записи с общими псевдонимами – одна группа
        by_cve = {cve: _pick(members) for cve, members in sorted(groups.items())}
        for cve, vuln in list(by_cve.items())[:limit]:
            members = groups[cve]
            rows.append({"ecosystem": ecosystem.lower(), "component": name, "version": version, "cve": cve,
                         "cvss": cvss_score(vuln), "fixed": fixed_version(vuln, ecosystem, name, version),
                         "note": note, "osv_id": vuln.get("id", ""),
                         "osv_aliases": " ".join(sorted({a for m in members for a in [m.get("id")] + list(m.get("aliases") or [])
                                                         if a and a != vuln.get("id")})),
                         "osv_modified": vuln.get("modified", "")})
        if len(by_cve) > limit:
            truncated += 1
            cut = f"ещё {len(by_cve) - limit} уязвимостей не включены (предел --limit {limit})"
            rows[-1]["note"] = "; ".join(x for x in (rows[-1]["note"], cut) if x)
        print(f"{ecosystem} {name} {version}: уязвимостей {len(by_cve)}"
              + (f", включено {limit}" if len(by_cve) > limit else ""))
    return rows, failed, truncated


def main() -> int:
    ap = argparse.ArgumentParser(description="Уязвимости компонентов по OSV – CSV для демонстрационной выгрузки")
    ap.add_argument("--requirements", type=Path)
    ap.add_argument("--package-lock", type=Path)
    ap.add_argument("--package-json", type=Path, help="без файла блокировки: нижняя граница диапазона версии")
    ap.add_argument("--pom", type=Path)
    ap.add_argument("--osv-json", type=Path, action="append", default=[],
                    help="сохранённый вывод OSV-Scanner --format json (повторяемый, без сети)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=5, help="уязвимостей на компонент, не больше (усечение отмечается в note)")
    args = ap.parse_args()
    if args.limit < 1:  # до любых запросов: предел 0 оставлял бы пустой срез
        ap.error("--limit: нужно целое число не меньше 1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # вывод по-русски и в канале с другой кодировкой
    components: list[Component] = []
    if args.requirements:
        components += requirements(args.requirements)
    if args.package_lock:
        components += package_lock(args.package_lock)
    if args.package_json:
        components += package_json(args.package_json)
    if args.pom:
        components += pom(args.pom)
    rows, failed, truncated = collect(components, args.limit) if components else ([], 0, 0)
    per: dict[tuple, list[dict]] = {}
    gathered: dict[tuple, list[dict]] = {}
    for path in args.osv_json:  # все входы вместе: компонент из двух JSON – один компонент и один общий предел
        for row in osv_json_rows(path):
            gathered.setdefault((row["ecosystem"], row["component"], row["version"]), []).append(row)
    for coord, found in gathered.items():
        per[coord] = merge_rows(found)
    if per:
        components += [(eco, name, ver, "") for eco, name, ver in per]  # счёт компонентов – и для офлайн-входа
        for group in per.values():
            if len(group) > args.limit:
                truncated += 1
                cut = f"ещё {len(group) - args.limit} уязвимостей не включены (предел --limit {args.limit})"
                group = group[:args.limit]
                group[-1] = {**group[-1], "note": "; ".join(x for x in (group[-1]["note"], cut) if x)}
            rows += group
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, restval="")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{args.out}: компонентов {len(components)}, строк {len(rows)}, усечено по пределу {truncated}, "
          f"запросов не удалось {failed}" + (" – CSV НЕПОЛОН" if failed else ""))
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
