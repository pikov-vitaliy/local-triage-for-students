"""Шаг SCA сборщика каталога: снимки разрешения зависимостей по перечню манифестов и OSV-Scanner с лицензиями.

Снимок – файл блокировки с разрешёнными версиями (никаких диапазонов): готовый файл блокировки репозитория – как есть,
npm – `npm install --package-lock-only --ignore-scripts --before=<дата>`, Python – `uv pip compile --exclude-newer
<дата>`, .NET – `dotnet restore --use-lock-file` в контейнере SDK, Go – go.mod закреплённой ревизии (с Go 1.17 в нём
перечислены все модули сборки с точными версиями), Maven – разрешение OSV-Scanner через deps.dev, сохранённое как
CycloneDX. Снимки – входы каталога (examples/catalog/<id>/inputs/lock/), в них только имена и версии компонентов."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

OSV_IMAGE = "ghcr.io/google/osv-scanner:v2.2.4"
DOTNET_IMAGE = "mcr.microsoft.com/dotnet/sdk:10.0"
# учебный перечень разрешённых лицензий (разрешительные); остальное – находка SCA Compliance
ALLOWED_LICENSES = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "BlueOak-1.0.0", "CC0-1.0",
                    "Unlicense", "Python-2.0", "PSF-2.0", "Zlib", "CC-BY-4.0", "BSD-3-Clause-Clear", "X11", "MIT-0",
                    "HPND", "Artistic-2.0", "Ruby", "BSL-1.0", "Unicode-DFS-2016", "Unicode-3.0", "W3C"]
# экосистемы, по которым deps.dev отдаёт лицензии; у прочих UNKNOWN – пробел данных, а не находка
LICENSE_DATA = {"npm", "pypi", "maven", "go", "nuget", "cargo"}
LOCK_NAMES = {"npm": "package-lock.json", "pypi": "requirements.txt", "nuget": "packages.lock.json", "go": "go.mod",
              "packagist": "composer.lock", "rubygems": "Gemfile.lock", "maven": "pom.xml"}


def slug(manifest: str) -> str:
    return manifest.replace("/", "__")


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, env=env)


def make_snapshot(tree: Path, manifest: dict, out_dir: Path, build_date: str) -> tuple[Path | None, str]:
    """Снимок разрешения одного манифеста в out_dir; (путь снимка, '') или (None, причина отказа)."""
    src = tree / manifest["path"]
    folder = src.parent
    eco = manifest["ecosystem"]
    if eco not in LOCK_NAMES:
        return None, f"экосистема {eco} не поддерживается сборщиком (нет файла блокировки)"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / LOCK_NAMES[eco]
    if eco == "npm":
        lock = folder / "package-lock.json"
        if lock.is_file():
            shutil.copyfile(lock, target)
            return target, ""
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(src, Path(tmp) / "package.json")
            npm = shutil.which("npm") or "npm"
            run = _run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                        f"--before={build_date}"], cwd=Path(tmp))
            if run.returncode != 0 or not (Path(tmp) / "package-lock.json").is_file():
                return None, "npm не разрешил зависимости: " + run.stderr.decode("utf-8", "replace")[-200:]
            shutil.copyfile(Path(tmp) / "package-lock.json", target)
        return target, ""
    if eco == "pypi":
        uv = shutil.which("uv") or "uv"
        run = _run([uv, "pip", "compile", str(src), "--exclude-newer", build_date, "--python-version", "3.11",
                    "--no-header", "--no-annotate", "--quiet", "-o", str(target)])
        if run.returncode != 0 or not target.is_file():
            return None, "uv не разрешил зависимости: " + run.stderr.decode("utf-8", "replace")[-300:]
        return target, ""
    if eco == "go":
        return go_snapshot(folder, target)
    if eco in ("packagist", "rubygems"):
        name = {"packagist": "composer.lock", "rubygems": "Gemfile.lock"}[eco]
        lock = folder / name
        if not lock.is_file():
            return None, f"нет файла {name} рядом с манифестом"
        shutil.copyfile(lock, target)
        return target, ""
    if eco == "nuget":
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(src, Path(tmp) / src.name)
            run = _run(["docker", "run", "--rm", "-v", f"{tmp}:/w", "-w", "/w", DOTNET_IMAGE, "dotnet", "restore",
                        "--use-lock-file"], timeout=1800)
            lock = Path(tmp) / "packages.lock.json"
            if run.returncode != 0 or not lock.is_file():
                return None, "dotnet restore не создал packages.lock.json: " + run.stdout.decode("utf-8", "replace")[-300:]
            shutil.copyfile(lock, target)
        return target, ""
    if eco == "maven":
        shutil.copyfile(src, target)  # разрешение – OSV-Scanner через deps.dev; итог сохраняется как CycloneDX
        return target, ""
    return None, f"экосистема {eco} не поддерживается сборщиком (нет файла блокировки)"


def go_snapshot(folder: Path, target: Path) -> tuple[Path | None, str]:
    """Go: полный состав модулей сборки (`go list -m all` по go.mod и go.sum ревизии) – go.mod с перечнем require.
    У go.mod до Go 1.17 косвенных зависимостей в файле нет, поэтому копия go.mod снимком не годится (ревью сборки Б)."""
    import tempfile

    go = shutil.which("go")
    if not go or not (folder / "go.mod").is_file():
        return None, "нет Go или go.mod для разрешения модулей"
    with tempfile.TemporaryDirectory() as tmp:
        # копия всей закреплённой ревизии: относительные replace разрешаются, исходное дерево кэша не меняется
        tree_root = folder
        while tree_root.parent != tree_root and not (tree_root.parent.name == "trees"):
            tree_root = tree_root.parent
        work = Path(tmp) / "src"
        shutil.copytree(tree_root, work)
        cwd = work / folder.relative_to(tree_root)
        env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
        run = subprocess.run([go, "list", "-m", "-json", "all"], cwd=cwd, capture_output=True, timeout=900, env=env)
        if run.returncode != 0:
            return None, "go list -m -json all не разрешил модули: " + run.stderr.decode("utf-8", "replace")[-300:]
    decoder, text, pos, mods = json.JSONDecoder(), run.stdout.decode("utf-8"), 0, []
    while pos < len(text.rstrip()):
        obj, pos = decoder.raw_decode(text, pos)
        mods.append(obj)
        while pos < len(text) and text[pos].isspace():
            pos += 1
    module = next((m["Path"] for m in mods if m.get("Main")), "")
    requires, local = [], []
    for m in mods:
        if m.get("Main"):
            continue
        rep = m.get("Replace") or {}
        if rep and not rep.get("Version"):
            local.append(m["Path"])  # замена на локальную папку: версии нет – в снимок не входит, причина ниже
            continue
        path, version = (rep["Path"], rep["Version"]) if rep else (m["Path"], m.get("Version", ""))
        if version:
            requires.append(f"{path} {version}")
    if local:  # модули с заменой на локальную папку версии не имеют: в снимок не входят, список – рядом со снимком
        (target.parent / "local-replace.txt").write_text("\n".join(sorted(local)) + "\n", encoding="utf-8",
                                                         newline="\n")
    lines = [module] + sorted(set(requires))
    module = lines[0].strip()
    directive = next((ln.split()[1] for ln in (folder / "go.mod").read_text(encoding="utf-8").splitlines()
                      if ln.startswith("go ") and len(ln.split()) > 1), "")
    requires = sorted(ln.strip() for ln in lines[1:] if len(ln.split()) == 2)
    text = f"module {module}\n\n" + (f"go {directive}\n\n" if directive else "") + "require (\n" + "".join(
        f"\t{r}\n" for r in requires) + ")\n"
    target.write_text(text, encoding="utf-8", newline="\n")
    return target, ""


def resolved_pairs(report: dict) -> list[dict]:
    """Все пакеты снимка из вывода OSV-Scanner --all-packages: [{ecosystem, name, version}]."""
    out = set()
    for result in report.get("results") or []:
        for pkg in result.get("packages") or []:
            p = pkg.get("package") or {}
            if p.get("name") and p.get("version"):
                out.add((str(p.get("ecosystem") or ""), str(p["name"]), str(p["version"])))
    return [{"ecosystem": e, "name": n, "version": v} for e, n, v in sorted(out)]


def osv_scan(snapshot: Path, fmt: str = "json") -> dict:
    """OSV-Scanner по одному снимку: JSON со всеми пакетами (--all-packages), уязвимостями и нарушениями лицензий."""
    args = ["docker", "run", "--rm", "-v", f"{snapshot.parent}:/in:ro", OSV_IMAGE, "scan", "source", "-L",
            f"/in/{snapshot.name}", "--format", "cyclonedx-1-5" if fmt == "cdx" else "json"]
    if fmt == "json":
        args += ["--all-packages", "--licenses=" + ",".join(ALLOWED_LICENSES)]
    run = _run(args)
    if run.returncode not in (0, 1):
        raise RuntimeError(f"OSV-Scanner {snapshot}: код {run.returncode}: " +
                           run.stderr.decode("utf-8", "replace")[-300:])
    return json.loads(run.stdout.decode("utf-8") or "{}")


def _cve_of(vuln: dict, group: dict | None) -> str:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases") or []) + list((group or {}).get("aliases") or [])
    cves = sorted({i for i in ids if str(i).startswith("CVE-")})
    return cves[0] if cves else str(vuln.get("id") or "")


def _pick(vulns: list[dict]) -> dict:
    """Одна запись на группу псевдонимов: GHSA раньше остальных, затем по ID (план, раздел 4.2)."""
    return sorted(vulns, key=lambda v: (0 if str(v.get("id", "")).startswith("GHSA-") else 1, str(v.get("id", ""))))[0]


def osv_entries(report: dict, codebase: str, manifest: str, fixed_version, cvss_score) -> tuple[list[dict], list[dict]]:
    """Сокращённые записи SCA и лицензий из JSON OSV-Scanner."""
    sca, licenses = [], []
    for result in report.get("results") or []:
        for pkg in result.get("packages") or []:
            p = pkg.get("package") or {}
            name, version, eco = str(p.get("name") or ""), str(p.get("version") or ""), str(p.get("ecosystem") or "")
            if not name or not version:
                continue
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            for group in pkg.get("groups") or [{"ids": [i]} for i in vulns]:
                members = [vulns[i] for i in group.get("ids") or [] if i in vulns]
                if not members:
                    continue
                vuln = _pick(members)
                score = str(group.get("max_severity") or "") or cvss_score(vuln)
                sca.append({"codebase": codebase, "manifest": manifest, "ecosystem": eco, "name": name,
                            "version": version, "osv_id": vuln.get("id"),
                            "osv_aliases": sorted({a for m in members for a in [m.get("id")] + list(m.get("aliases") or [])
                                                   if a and a != vuln.get("id")}),
                            "cve": _cve_of(vuln, group), "cvss": score,
                            "fixed": fixed_version(vuln, eco, name, version), "osv_modified": vuln.get("modified", ""),
                            "dependency_groups": pkg.get("dependency_groups") or []})
            if pkg.get("license_violations"):
                licenses.append({"codebase": codebase, "manifest": manifest, "ecosystem": eco, "name": name,
                                 "version": version, "licenses": pkg.get("licenses") or [],
                                 "violations": pkg.get("license_violations") or [],
                                 "dependency_groups": pkg.get("dependency_groups") or []})
    return sca, licenses


STRONG = ("GPL", "AGPL", "SSPL", "EUPL", "OSL")
WEAK = ("LGPL", "MPL", "EPL", "CDDL", "CPL", "OFL", "CC-BY-SA", "MS-RL")


def license_class(licenses: list[str], ecosystem: str) -> tuple[str, str] | None:
    """(Severity, Category) находки SCA Compliance или None – не находка (нет данных о лицензиях экосистемы)."""
    names = [str(x) for x in licenses]
    upper = " ".join(names).upper()
    if all(n.upper() == "UNKNOWN" for n in names) or not names:
        if ecosystem.lower() not in LICENSE_DATA:
            return None
        return "Low", "Лицензия не установлена: компонент без сведений о лицензии"
    if any(tok in upper.replace("LGPL", "") for tok in STRONG):
        return "High", "Лицензия: сильный копилефт (условия распространения производного ПО)"
    if any(tok in upper for tok in WEAK):
        return "Medium", "Лицензия: слабый копилефт (условия для изменённых файлов или библиотеки)"
    return "Low", "Лицензия вне разрешённого перечня учебной политики"
