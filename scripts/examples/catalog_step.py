"""Сведение каталога: входы SAST, строки выгрузки, книга, запись catalog.json, NOTICE.md."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import export_step
import sca_step
import yaml

DESCRIPTIONS = {
    "juice-shop": ("Интернет-магазин на Node.js и Angular с десятками учебных уязвимостей OWASP Top 10.", "средний"),
    "webgoat": ("Учебное приложение OWASP на Java (Spring Boot): уроки по инъекциям, XSS, XXE, десериализации.",
                "средний"),
    "pygoat": ("Учебное приложение на Django с лабораторными по OWASP Top 10.", "начальный"),
    "nodegoat": ("Учебное приложение OWASP на Node.js и MongoDB: внедрение кода, NoSQL-инъекции, XSS.", "начальный"),
    "dvwa": ("Классическое уязвимое веб-приложение на PHP: SQL-инъекции, XSS, включение файлов, команды.", "начальный"),
    "railsgoat": ("Учебное приложение OWASP на Ruby on Rails: SQL-инъекции, XSS, IDOR, массовое присваивание.",
                  "средний"),
    "dvga": ("Уязвимое приложение GraphQL на Python: SSRF, внедрение команд, обход авторизации.", "средний"),
    "go-test-bench": ("Набор уязвимых обработчиков на Go для проверки анализаторов: команды, SQL, пути, SSRF.",
                      "начальный"),
    "vulnerablelightapp": ("Небольшое уязвимое приложение на C# (.NET): пути, XXE, десериализация, SSRF.",
                           "начальный"),
    "crapi": ("Уязвимое API автосервиса OWASP из нескольких сервисов (Java, Go, Python, TypeScript).", "продвинутый"),
}
FOUND_BY = {"semgrep": "semgrep", "bandit": "bandit", "gosec": "gosec"}


def rules_meta(rules_dir: Path) -> dict:
    meta = {}
    for f in sorted(rules_dir.glob("*.yml")):
        for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            meta[r["id"]] = {"message": r["message"], "cwe": (r.get("metadata") or {}).get("cwe") or [],
                             "file": f.name}
    return meta


def _severity_by_cvss(cvss: str) -> tuple[str, str]:
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "Medium", "Уязвимость компонента"
    if score >= 9:
        return "Critical", "Политика: CVSS выше 6"
    if score >= 7:
        return "High", "Политика: CVSS выше 6"
    return ("Medium", "Политика: CVSS выше 6") if score > 6 else ("Medium", "Уязвимость компонента")


def write_sast_inputs(src: dict, catalog: Path, tree: Path, reports: Path, build_date: str, tools: dict) -> int:
    """Входы SAST без кода из сырых отчётов анализаторов (кэш сборки): каждый файл находки – в своей кодовой базе."""
    meta = rules_meta(catalog.parent / "rules")
    sast, sast_dropped = export_step.sast_entries(reports, src["codebases"], meta)
    paths = {cb["name"]: cb["path"].strip("/") for cb in src["codebases"]}
    missing = [f"{e['codebase']}:{e['file']}" for e in sast
               if not ((tree / paths[e["codebase"]] if paths[e["codebase"]] else tree) / e["file"]).is_file()]
    if missing:
        raise RuntimeError(f"{src['id']}: файлов SAST нет в дереве: {missing[:5]}")
    export_step_dump(catalog / src["id"] / "inputs" / "sast.json",
                     {"build_date": build_date, "commit": src["commit"], "tools": tools, "entries": sast,
                      "dropped": sast_dropped})
    return len(sast)


def build_example(src: dict, catalog: Path, headers: dict, mitre: str, eco_type: dict, language_of, build_date: str,
                  tools: dict) -> dict:
    """Книга и запись каталога – только из сохранённых входов (без кэша, анализаторов и сети)."""
    out_dir = catalog / src["id"]
    inputs = out_dir / "inputs"
    sast_doc = json.loads((inputs / "sast.json").read_text(encoding="utf-8"))
    sast, sast_dropped = sast_doc["entries"], sast_doc.get("dropped") or {}
    for name in ("sast.json", "sca.json", "licenses.json"):  # все входы – той же ревизии
        doc = sast_doc if name == "sast.json" else json.loads((inputs / name).read_text(encoding="utf-8"))
        if doc.get("commit") != src["commit"]:
            raise RuntimeError(f"{src['id']}: {name} – другого коммита ({doc.get('commit')}); пересоберите входы")
    sca_doc = json.loads((inputs / "sca.json").read_text(encoding="utf-8"))
    excluded_paths = {x["manifest"] for x in sca_doc.get("excluded_manifests") or []}
    for m in src["manifests"]:
        snap = inputs / "lock" / sca_step.slug(m["path"]) / sca_step.LOCK_NAMES.get(m["ecosystem"], "-")
        if m["path"] not in excluded_paths and not snap.is_file():
            raise RuntimeError(f"{src['id']}: нет снимка зависимостей {m['path']} – пересоберите шаг sca")
    lic_doc = json.loads((inputs / "licenses.json").read_text(encoding="utf-8"))
    sca, sca_dropped = export_step.sca_selected(sca_doc["entries"])
    lic_rows = []
    lic_skipped = 0
    for e in lic_doc["entries"]:
        if e["ecosystem"].lower() == "go" and e["name"] in ("stdlib", "toolchain"):
            lic_skipped += 1  # версия Go из директивы go – не компонент
            continue
        cls = sca_step.license_class(e["licenses"], e["ecosystem"])
        if cls is None:
            lic_skipped += 1
            continue
        lic_rows.append({**e, "severity": cls[0], "category": cls[1]})
    lic_rows.sort(key=lambda e: ({"High": 0, "Medium": 1, "Low": 2}[e["severity"]],
                                 "dev" in (e.get("dependency_groups") or []), e["codebase"], e["name"], e["version"]))
    lic_over = max(0, len(lic_rows) - export_step.LICENSE_LIMIT)
    lic_rows = lic_rows[:export_step.LICENSE_LIMIT]
    number = int(f"9{src['number']}0000") + 1
    start = number
    app = src["title"]
    sast_rows, sca_rows, comp_rows = [], [], []
    for e in sast:
        cwe = e["cwe"]
        sast_rows.append({"Issue id": str(number), "Application": app, "Severity": e["severity"],
                          "Category": e["category"][:300], "File": e["file"], "Line number": str(e["line"]),
                          "Source code": "-", "Status": "To verify", "Type": "source", "Found By": FOUND_BY[e["tool"]],
                          "CWE ID": ", ".join(cwe) or "-", "CWE link": ", ".join(mitre.format(c) for c in cwe) or "-",
                          "Codebase": e["codebase"], "Artifact": "-", "Language": language_of(e["file"], "-")})
        number += 1
    for e in sca:
        sev, cat = _severity_by_cvss(e.get("cvss"))
        sca_rows.append({"Issue id": str(number), "Application": app, "Severity": sev, "CVSS score": e.get("cvss") or "-",
                         "Category": cat, "Component name": e["name"], "Component version": e["version"],
                         "CVE id": e["cve"] or e["osv_id"], "Status": "To verify",
                         "Type": eco_type.get(e["ecosystem"].lower(), e["ecosystem"].lower()), "Found By": "osv-scanner",
                         "Non-vulnerable versions": e.get("fixed") or "-", "Path": e["manifest"], "CWE ID": "-",
                         "CWE link": "-", "Codebase": e["codebase"], "Artifact": "-", "Proxy": "-"})
        number += 1
    for e in lic_rows:
        comp_rows.append({"Issue id": str(number), "Application": app, "Severity": e["severity"],
                          "Category": e["category"], "Component name": e["name"], "Component version": e["version"],
                          "Licenses": ", ".join(e["licenses"]) or "UNKNOWN", "Status": "To verify",
                          "Type": eco_type.get(e["ecosystem"].lower(), e["ecosystem"].lower()),
                          "Found By": "osv-scanner", "Non-vulnerable versions": "-", "Path": e["manifest"],
                          "Codebase": e["codebase"], "Artifact": "-", "Proxy": "-"})
        number += 1
    book = out_dir / "export.xlsx.new"  # замена действующей книги – комплектом в build.py, вместе с catalog.json
    export_step.write_book(book, app, sast_rows, sca_rows, comp_rows, headers, build_date)
    cwes = sorted({c for e in sast for c in e["cwe"]}, key=int)
    desc, level = DESCRIPTIONS[src["id"]]
    return {
        "id": src["id"], "number": src["number"], "title": src["title"], "description": desc, "level": level,
        "languages": list(dict.fromkeys(x.strip() for cb in src["codebases"] for x in cb["languages"].split(","))), "cwe": cwes,
        "source": {"repo_url": src["repo_url"], "commit": src["commit"], "commit_date": src["commit_date"],
                   "license": src["license"],
                   "archive_url": src["repo_url"].replace("https://github.com/", "https://codeload.github.com/")
                   + "/tar.gz/" + src["commit"], **src["tree"]},
        "codebases": [{"name": cb["name"], "path": cb["path"].strip("/"), "languages": cb["languages"]}
                      for cb in src["codebases"]],
        "sca_inputs": [{"manifest": m["path"], "codebase": m["codebase"], "ecosystem": m["ecosystem"],
                        "excluded": any(x["manifest"] == m["path"] for x in sca_doc.get("excluded_manifests") or []),
                        "snapshot": (f"inputs/lock/{sca_step.slug(m['path'])}/"
                                     f"{sca_step.LOCK_NAMES.get(m['ecosystem'], '')}")
                        if (inputs / "lock" / sca_step.slug(m["path"]) /
                            sca_step.LOCK_NAMES.get(m["ecosystem"], "-")).is_file()
                        and not any(x["manifest"] == m["path"] for x in sca_doc.get("excluded_manifests") or [])
                        else ""}
                       for m in src["manifests"]],
        "excluded_manifests": sca_doc.get("excluded_manifests") or [],
        "excluded_modules": sca_doc.get("excluded_modules") or [],
        "export": {"file": f"{src['id']}/export.xlsx", "sha256": hashlib.sha256(book.read_bytes()).hexdigest(),
                   "sast": len(sast_rows), "sca": len(sca_rows), "compliance": len(comp_rows), "start_id": start,
                   "tools": tools, "osv_date": sca_doc.get("osv_date", build_date),
                   "dropped": {"sast": sast_dropped, "sca": sca_dropped,
                               "licenses": {"нет данных о лицензиях экосистемы": lic_skipped,
                                            "сверх предела": lic_over}}},
        "expected_missing": [],
    }


def export_step_dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8",
                    newline="\n")
