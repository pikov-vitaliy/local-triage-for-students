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
COLUMNS = ["ecosystem", "component", "version", "cve", "cvss", "fixed", "note"]
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


def _vkey(version: str) -> tuple[int, ...]:
    """Числовой ключ версии для сравнения границ диапазона (1.4.5 → (1, 4, 5)); без цифр – пустой."""
    return tuple(int(x) for x in re.findall(r"\d+", str(version or "")))


def fixed_version(vuln: dict, ecosystem: str, name: str, version: str) -> str:
    """Версия исправления для исследуемой версии: из диапазонов записи OSV по этому пакету и экосистеме, кроме
    диапазонов GIT (там хеши коммитов, не версии); берётся исправление того диапазона, в который попадает версия
    (introduced ≤ версия < fixed по числовому ключу); не попала ни в один – единственное исправление записи, иначе
    пусто (неоднозначность не угадывается)."""
    candidates: list[tuple[bool, str]] = []
    key = _vkey(version)
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if str(package.get("name") or "").lower() != name.lower():
            continue
        if package.get("ecosystem") and str(package["ecosystem"]).lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges") or []:
            if str(rng.get("type") or "").upper() == "GIT":
                continue
            introduced, fixed = "0", ""
            for event in rng.get("events") or []:
                if event.get("introduced") is not None:
                    introduced = str(event["introduced"])
                if event.get("fixed"):
                    fixed = str(event["fixed"])
            if not fixed:
                continue
            inside = bool(key) and (introduced == "0" or _vkey(introduced) <= key) and key < _vkey(fixed)
            candidates.append((inside, fixed))
    matching = sorted({f for inside, f in candidates if inside})
    if len(matching) == 1:
        return matching[0]
    if not matching and len({f for _, f in candidates}) == 1:
        return candidates[0][1]
    return ""


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
        by_cve: dict[str, dict] = {}  # одна уязвимость – одна строка: OSV отдаёт записи GHSA и PYSEC с общим CVE
        for vuln in vulns:
            cve = next((a for a in vuln.get("aliases") or [] if str(a).startswith("CVE-")), vuln.get("id", ""))
            by_cve.setdefault(cve, vuln)
        for cve, vuln in list(by_cve.items())[:limit]:
            rows.append({"ecosystem": ecosystem.lower(), "component": name, "version": version, "cve": cve,
                         "cvss": cvss_score(vuln), "fixed": fixed_version(vuln, ecosystem, name, version),
                         "note": note})
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
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=5, help="уязвимостей на компонент, не больше (усечение отмечается в note)")
    args = ap.parse_args()
    components: list[Component] = []
    if args.requirements:
        components += requirements(args.requirements)
    if args.package_lock:
        components += package_lock(args.package_lock)
    if args.package_json:
        components += package_json(args.package_json)
    if args.pom:
        components += pom(args.pom)
    rows, failed, truncated = collect(components, args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{args.out}: компонентов {len(components)}, строк {len(rows)}, усечено по пределу {truncated}, "
          f"запросов не удалось {failed}" + (" – CSV НЕПОЛОН" if failed else ""))
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
