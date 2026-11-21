"""Сценарии демонстрации без AppSec.Hub (docs/demo-projects.md): выгрузка формата Hub из отчётов Bandit и Semgrep
(`scripts/make_hub_from_sast.py`) читается разборщиком выгрузок приложения; компоненты по манифестам и базовая оценка
CVSS 3.x (`scripts/osv_sca_csv.py`) – без сети. Данные выдуманы."""
from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load(name: str, folder: Path = SCRIPTS):
    spec = importlib.util.spec_from_file_location(name, folder / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_bench(name: str):
    return load(name, SCRIPTS / "bench")


def test_hub_export_from_bandit_and_semgrep_is_readable_by_the_app(tmp_path: Path):
    from app.hub_import import parse_workbook
    bandit = {"results": [
        {"filename": "test-projects\\demo\\app\\views.py", "line_number": 12, "issue_severity": "HIGH", "issue_confidence": "HIGH",
         "issue_text": "Possible SQL injection vector through string-based query construction.", "test_id": "B608",
         "test_name": "hardcoded_sql_expressions", "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
         "code": "11 def find(name):\n12     cursor.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n13     return cursor.fetchall()\n"},
        {"filename": "demo/settings.py", "line_number": 3, "issue_severity": "LOW", "issue_confidence": "MEDIUM",
         "issue_text": "Possible hardcoded password: 'x'", "test_id": "B105", "test_name": "hardcoded_password_string",
         "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"}, "code": "3 PASSWORD = 'x'\n"},
        {"filename": "/abs/clones/demo/infrastructure/deploy.py", "line_number": 1, "issue_severity": "HIGH",
         "issue_confidence": "HIGH", "issue_text": "subprocess", "test_id": "B404", "test_name": "import_subprocess",
         "issue_cwe": {"id": 78}, "code": "1 import subprocess\n"},
    ]}
    semgrep = {"results": [
        {"check_id": "python.django.security.injection.sql.sql-injection-db-cursor-execute", "path": "app/views.py",
         "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "User data flows into SQL.",
                                          "lines": "    cursor.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)",
                                          "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements"]}}},
        {"check_id": "yaml.github-actions.security.mutable-tag", "path": ".github/workflows/ci.yml", "start": {"line": 2},
         "extra": {"severity": "WARNING", "message": "mutable tag", "lines": "uses: a/b@main", "metadata": {"cwe": "CWE-1357"}}},
        {"check_id": "python.flask.security.debug", "path": "app/run.py", "start": {"line": 5},
         "extra": {"severity": "MEDIUM", "message": "debug", "lines": "app.run(debug=True)", "metadata": {}}},
    ]}
    (tmp_path / "bandit.json").write_text(json.dumps(bandit), encoding="utf-8")
    (tmp_path / "semgrep.json").write_text(json.dumps(semgrep), encoding="utf-8")
    with (tmp_path / "sca.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ecosystem", "component", "version", "cve", "cvss", "fixed", "note"])
        writer.writeheader()
        writer.writerow({"ecosystem": "pypi", "component": "demo-lib", "version": "1.0.0", "cve": "CVE-2099-0001",
                         "cvss": "9.8", "fixed": "1.0.1", "note": "версия – нижняя граница диапазона ^1.0.0"})
    out = tmp_path / "hub.xlsx"
    r = subprocess.run([sys.executable, str(SCRIPTS / "make_hub_from_sast.py"), "--app", "Demo", "--codebase", "demo",
                        "--bandit", str(tmp_path / "bandit.json"), "--semgrep", str(tmp_path / "semgrep.json"),
                        "--sca", str(tmp_path / "sca.csv"), "--out", str(out)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    result = parse_workbook(out)
    kinds = [f.kind for f in result.findings]
    # Bandit (путь test-projects/demo/…) и Semgrep (app/…) по одной строке файла – одна находка; .github и
    # infrastructure (абсолютный путь) не берутся; MEDIUM Semgrep – Medium
    assert kinds.count("SAST") == 3 and kinds.count("SCA") == 1, kinds
    sast = {f.file: f for f in result.findings if f.kind == "SAST"}
    assert set(sast) == {"app/views.py", "settings.py", "app/run.py"}
    view = sast["app/views.py"]
    assert view.line == 12 and view.severity.lower() == "high" and "89" in " ".join(view.cwe)
    assert "cursor.execute" in view.snippet
    assert sast["app/run.py"].severity.lower() == "medium" and sast["settings.py"].severity.lower() == "low"
    sca = next(f for f in result.findings if f.kind == "SCA")
    assert sca.component == "demo-lib" and sca.version == "1.0.0" and sca.cve == ["CVE-2099-0001"]
    assert "нижняя граница диапазона ^1.0.0" in sca.rule, "предположение о версии видно в выгрузке"
    assert result.summary.get("application") == "Demo"


def test_semgrep_placeholder_line_is_taken_from_the_clone_and_language_follows_the_file(tmp_path: Path):
    """Semgrep без входа в учётную запись пишет в extra.lines «requires login» – в выгрузку шла
    заглушка, модели сообщалось «фрагмент не найден»; у Dockerfile и шаблонов стоял язык всей выгрузки (Python)."""
    hub = load("make_hub_from_sast")
    clone = tmp_path / "demo"
    (clone / "labs").mkdir(parents=True)
    (clone / "labs" / "Dockerfile").write_text("FROM python:3.9\nCMD [\"flask\", \"run\"]\n", encoding="utf-8")
    (clone / "labs" / "login.html").write_text("<html>\n  <form method=\"post\">\n", encoding="utf-8")
    report = {"results": [
        {"check_id": "dockerfile.security.missing-user", "path": "labs/Dockerfile", "start": {"line": 2},
         "extra": {"severity": "ERROR", "message": "no USER", "lines": "requires login", "metadata": {}}},
        {"check_id": "html.django.no-csrf", "path": "labs/login.html", "start": {"line": 2},
         "extra": {"severity": "WARNING", "message": "csrf", "lines": "requires login", "metadata": {}}},
        {"check_id": "python.x", "path": "labs/gone.py", "start": {"line": 9},
         "extra": {"severity": "INFO", "message": "x", "lines": "requires login", "metadata": {}}},
    ]}
    rows = {r["File"]: r for r in hub.semgrep_rows(report, "demo", "Python", clone)}
    assert rows["labs/Dockerfile"]["Source code"] == 'CMD ["flask", "run"]'
    assert rows["labs/Dockerfile"]["Language"] == "Dockerfile"
    assert rows["labs/login.html"]["Source code"] == '<form method="post">' and rows["labs/login.html"]["Language"] == "HTML"
    assert rows["labs/gone.py"]["Source code"] == "-" and rows["labs/gone.py"]["Language"] == "Python"
    assert all(r["Source code"] != "requires login" for r in rows.values())
    # без папки клона – не заглушка, а «-»
    assert {r["Source code"] for r in hub.semgrep_rows(report, "demo", "Python")} == {"-"}
    assert hub.language_of("src/App.tsx", "Java") == "TypeScript" and hub.language_of("Makefile", "Java") == "Java"
    # имя клона – и папка пакета внутри проекта (WebGoat: org/owasp/webgoat): путь сверяется с клоном
    wg = tmp_path / "webgoat"
    java = wg / "src/main/java/org/owasp/webgoat/lessons/A.java"
    java.parent.mkdir(parents=True)
    java.write_text("class A {}\n", encoding="utf-8")
    deep = "src/main/java/org/owasp/webgoat/lessons/A.java"
    assert hub._norm_path(deep, "webgoat", wg) == deep, "файл есть по полному пути – путь не обрезается"
    assert hub._norm_path("/abs/clones/webgoat/" + deep, "webgoat", wg) == deep
    assert hub._norm_path("test-projects\\webgoat\\" + deep.replace("/", "\\"), "webgoat", wg) == deep
    assert hub._norm_path(deep, "webgoat") == "lessons/A.java", "без клона – прежнее правило"
    # регистр имени клона и абсолютный путь внутри папки клона с другим именем (ревью Codex, круг 18)
    assert hub._norm_path("/x/WebGoat/" + deep, "webgoat", wg) == deep
    other = tmp_path / "clone-dir"
    (other / "src").mkdir(parents=True)
    (other / "src" / "B.java").write_text("class B {}\n", encoding="utf-8")
    assert hub._norm_path(str(other / "src" / "B.java"), "webgoat", other) == "src/B.java"


def test_osv_script_parses_manifests_and_scores_cvss(tmp_path: Path, capsys):
    osv = load("osv_sca_csv")
    (tmp_path / "requirements.txt").write_text("Django==4.2  # web\nrequests>=2.0\n-e .\nPyYAML==5.1\n", encoding="utf-8")
    assert osv.requirements(tmp_path / "requirements.txt") == [("PyPI", "Django", "4.2", ""), ("PyPI", "PyYAML", "5.1", "")]
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {
        "express": "^4.17.1", "lodash": "~4.17.21", "x": "*", "old": "<2.0.0", "exact": "1.2.3", "ge": ">=3.0.0",
        "git": "github:a/b", "mixed": "1.x", "either": "1.0.0 || 2.0.0"}}), encoding="utf-8")
    got = osv.package_json(tmp_path / "package.json")
    assert got == [("npm", "exact", "1.2.3", ""), ("npm", "express", "4.17.1", "версия – нижняя граница диапазона ^4.17.1"),
                   ("npm", "ge", "3.0.0", "версия – нижняя граница диапазона >=3.0.0"),
                   ("npm", "lodash", "4.17.21", "версия – нижняя граница диапазона ~4.17.21")]
    err = capsys.readouterr().err
    assert "old <2.0.0" in err and "x *" in err and "either" in err, "неподдерживаемые диапазоны названы, а не угаданы"
    (tmp_path / "pom.xml").write_text(
        "<project><properties><jackson.version>2.15.2</jackson.version></properties>"
        "<dependencyManagement><dependencies><dependency><groupId>org.managed</groupId><artifactId>bom-only</artifactId>"
        "<version>9.9</version></dependency></dependencies></dependencyManagement>"
        "<!-- <dependency><groupId>org.commented</groupId><artifactId>out</artifactId><version>1.0</version></dependency> -->"
        "<profiles><profile><dependencies><dependency><groupId>org.profile</groupId><artifactId>inactive</artifactId>"
        "<version>1.0</version></dependency></dependencies></profile></profiles>"
        "<build><plugins><plugin><dependencies><dependency><groupId>org.plugin</groupId><artifactId>dep</artifactId>"
        "<version>1.0</version></dependency></dependencies></plugin></plugins></build>"
        "<dependencies>"
        "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>"
        "<version>${jackson.version}</version></dependency>"
        "<dependency><groupId>org.x</groupId><artifactId>managed</artifactId></dependency>"
        "<dependency><groupId>org.managed</groupId><artifactId>bom-only</artifactId></dependency>"
        "<dependency><groupId>org.y</groupId><artifactId>unresolved</artifactId><version>${missing}.1</version></dependency>"
        "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]></dependencies></project>", encoding="utf-8")
    # управляемая версия действует только для объявленной зависимости без <version> (bom-only), сама по себе
    # запись в dependencyManagement, комментарий, профиль и плагин – не состав; без версии (org.x) – пропуск
    assert osv.pom(tmp_path / "pom.xml") == [("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.15.2", ""),
                                             ("Maven", "org.managed:bom-only", "9.9", "")]
    err = capsys.readouterr().err
    assert "org.y:unresolved ${missing}.1: свойство не разрешено" in err and "org.x:managed: версия не задана" in err
    assert osv.cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "9.8"
    assert osv.cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == "7.2"
    assert osv.cvss_base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == "5.5"
    assert osv.cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == "0.0"
    assert osv.cvss_base_score("CVSS:4.0/AV:N") == "" and osv.cvss_base_score("") == ""
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "affected": [{"package": {"name": "django", "ecosystem": "PyPI"}, "ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "0abc1234deadbeef"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.20"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}, {"fixed": "4.2.1"}]}]}]}
    assert osv.cvss_score(vuln) == "5.9"
    assert osv.fixed_version(vuln, "PyPI", "Django", "4.2") == "4.2.1", "исправление того диапазона, где версия"
    assert osv.fixed_version(vuln, "PyPI", "Django", "3.1") == "3.2.20"
    assert osv.fixed_version(vuln, "PyPI", "Django", "5.0") == "", "ни в одном диапазоне и исправлений несколько – пусто"
    assert osv.fixed_version(vuln, "npm", "Django", "4.2") == "", "другая экосистема"
    git_only = {"affected": [{"package": {"name": "a"}, "ranges": [{"type": "GIT", "events": [{"fixed": "abc"}]}]}]}
    assert osv.fixed_version(git_only, "npm", "a", "1.0") == "", "хеш коммита – не версия исправления"


def test_osv_script_marks_truncation_and_fails_on_network_errors(tmp_path: Path, monkeypatch, capsys):
    osv = load("osv_sca_csv")
    answers = {"a": [{"id": f"GHSA-{i}", "aliases": [f"CVE-2099-{i:04d}"], "affected": []} for i in range(1, 8)],
               "b": [{"id": "GHSA-b", "aliases": ["CVE-2099-0100"], "affected": []},
                     {"id": "PYSEC-b", "aliases": ["CVE-2099-0100"], "affected": []}]}

    def fake_query(ecosystem, name, version):
        if name == "c":
            raise OSError("no network")
        return answers[name]
    monkeypatch.setattr(osv, "query", fake_query)
    rows, failed, truncated = osv.collect([("npm", "a", "1.0", ""), ("npm", "b", "1.0", "нижняя граница"),
                                           ("npm", "c", "1.0", "")], limit=5)
    assert failed == 1 and truncated == 1
    assert [r["cve"] for r in rows if r["component"] == "b"] == ["CVE-2099-0100"], "GHSA и PYSEC с одним CVE – одна строка"
    assert rows[4]["note"] == "ещё 2 уязвимостей не включены (предел --limit 5)" and rows[0]["note"] == ""
    assert rows[5]["note"] == "нижняя граница"
    assert "c 1.0: запрос не удался (OSError)" in capsys.readouterr().err
    (tmp_path / "requirements.txt").write_text("c==1.0\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["osv_sca_csv.py", "--requirements", str(tmp_path / "requirements.txt"),
                                      "--out", str(tmp_path / "out.csv")])
    assert osv.main() == 2, "неполный CSV – ненулевой код выхода"
    assert "CSV НЕПОЛОН" in capsys.readouterr().out
    assert (tmp_path / "out.csv").read_text(encoding="utf-8").splitlines() == ["ecosystem,component,version,cve,cvss,fixed,note"]


def test_known_answers_builder_reads_markers_and_checks_manual_rows(tmp_path: Path, capsys):
    """Эталон по тестовым проектам: метки авторов Juice Shop дают случаи с известным ответом
    (vuln-line – истинная, neutral-line – ложная с допустимым «неясно»), ручной список сверяется с файлом клона."""
    builder = load_bench("build_cases_projects")
    clone = tmp_path / "juice-shop"
    (clone / "data" / "static").mkdir(parents=True)
    (clone / "data" / "static" / "challenges.yml").write_text(
        "---\n-\n  name: 'Login Admin'\n  category: 'Injection'\n  difficulty: 2\n  key: loginAdminChallenge\n"
        "-\n  name: 'Access Log'\n  category: 'Observability Failures'\n  difficulty: 4\n  key: accessLogChallenge\n",
        encoding="utf-8")
    (clone / "routes").mkdir()
    (clone / "routes" / "login.ts").write_text(
        "const q = 1\nmodels.query(`SELECT ${req.body.email}`) // vuln-code-snippet vuln-line loginAdminChallenge loginJimChallenge\n"
        "  .then(() => {}) // vuln-code-snippet neutral-line loginAdminChallenge\n", encoding="utf-8")
    (clone / "node_modules").mkdir()
    (clone / "node_modules" / "x.js").write_text("a() // vuln-code-snippet vuln-line loginAdminChallenge\n", encoding="utf-8")
    cases, meta = builder.juice_shop_cases(clone)
    assert meta["vuln_lines"] == 1 and meta["neutral_lines"] == 1 and meta["unknown_keys"] == []
    vuln = next(c for c in cases if c["expected"] == "true_positive")
    assert (vuln["file"], vuln["line"], vuln["cwe"], vuln["hint_comment"]) == ("routes/login.ts", 2, "CWE-89", True)
    assert "vuln-code-snippet" not in vuln["snippet"] and vuln["snippet"].startswith("models.query(")
    assert "loginJimChallenge" in vuln["expected_note"] and vuln["severity"] == "Low"
    neutral = next(c for c in cases if c["expected"] == "false_positive")
    assert neutral["line"] == 3 and neutral["also_ok"] == ["uncertain"]
    pygoat = tmp_path / "pygoat"
    (pygoat / "introduction").mkdir(parents=True)
    (pygoat / "introduction" / "views.py").write_text("x = 1\ncursor.execute(\"SELECT %s\" % name)\n", encoding="utf-8")
    known = tmp_path / "known.json"
    known.write_text(json.dumps([
        {"project": "pygoat", "lesson": "SQL", "file": "introduction/views.py", "line": 2, "code": "cursor.execute",
         "cwe": "CWE-89", "cwe_name": "SQL Injection", "why": "строка с вводом", "confidence": "high"},
        {"project": "pygoat", "lesson": "нет строки", "file": "introduction/views.py", "line": 9, "cwe": "CWE-78"},
        {"project": "pygoat", "lesson": "не тот текст", "file": "introduction/views.py", "line": 1, "code": "os.system",
         "cwe": "CWE-78"},
        {"project": "webgoat", "lesson": "без клона", "file": "A.java", "line": 1, "cwe": "CWE-89"},
    ], ensure_ascii=False), encoding="utf-8")
    manual, kmeta = builder.known_cases(known, {"pygoat": pygoat})
    assert kmeta["accepted"] == 1 and len(kmeta["problems"]) == 3, kmeta
    assert manual[0]["expected"] == "true_positive" and manual[0]["snippet"].startswith("cursor.execute")
    assert manual[0]["also_ok"] == [] and manual[0]["codebase"] == "pygoat"
    out = tmp_path / "hub"
    written = builder.write_hub(cases + manual, out)
    assert len(written) == 2 and (out / "juice-shop-known-hub.xlsx").exists() and (out / "pygoat-known-hub.xlsx").exists()
    from app.hub_import import parse_workbook
    parsed = parse_workbook(out / "juice-shop-known-hub.xlsx")
    assert [f.kind for f in parsed.findings] == ["SAST", "SAST"] and parsed.findings[0].file == "routes/login.ts"
