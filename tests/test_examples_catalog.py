"""Каталог учебных примеров (ADR-0156, сборка Б): состав каталога и выгрузок, распаковка, скачивание без сети,
заполнение строк кода, создание проекта из примера."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import openpyxl
import pytest
from fastapi.testclient import TestClient

from app import examples as ex
from app.config import Settings
from app.example_tree import MARKER, tree_hash, tree_hash_of_dir
from app.hub_import import parse_workbook
from app.main import create_app

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "catalog"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "examples"))
BASE = "http://127.0.0.1:8765"


def catalog() -> dict:
    return json.loads((CATALOG / "catalog.json").read_text(encoding="utf-8"))


# ============================================================================ каталог и выгрузки

def test_catalog_schema_and_export_hashes():
    data = catalog()
    assert data["schema"] == 1 and data["build_date"]
    ids = [e["id"] for e in data["examples"]]
    assert ids[0] == "demo-library" and len(ids) == 11 and len(set(ids)) == 11
    for e in data["examples"][1:]:
        src = e["source"]
        assert len(src["commit"]) == 40 and src["license"] and src["tree_sha256"]
        assert src["archive_url"] == (src["repo_url"].replace("https://github.com/", "https://codeload.github.com/")
                                      + "/tar.gz/" + src["commit"])
        ex.archive_url_ok(e)
        book = CATALOG / e["export"]["file"]
        assert hashlib.sha256(book.read_bytes()).hexdigest() == e["export"]["sha256"], e["id"]
        assert e["export"]["start_id"] == int(f"9{e['number']}0001")
        for snap in e["sca_inputs"]:
            if snap["snapshot"]:
                assert (CATALOG / e["id"] / snap["snapshot"]).is_file(), (e["id"], snap)
            else:
                assert any(x["manifest"] == snap["manifest"] for x in e["excluded_manifests"]), snap


def test_exports_carry_no_source_code_and_parse_with_all_three_practices():
    kinds_seen = set()
    for e in catalog()["examples"][1:]:
        book = CATALOG / e["export"]["file"]
        wb = openpyxl.load_workbook(book)
        sast = wb["SAST"]
        header = [c.value for c in sast[1]]
        col = header.index("Source code")
        assert all(row[col].value == "-" for row in sast.iter_rows(min_row=2)), e["id"]
        result = parse_workbook(book)
        kinds = {f.kind for f in result.findings}
        kinds_seen |= kinds
        assert len([f for f in result.findings if f.kind == "SAST"]) == e["export"]["sast"]
        assert len([f for f in result.findings if f.kind == "SCA"]) == e["export"]["sca"]
        assert len([f for f in result.findings if f.kind == "SCA-license"]) == e["export"]["compliance"]
        hub_ids = [f.hub_id for f in result.findings]
        assert len(hub_ids) == len(set(hub_ids))
    assert {"SAST", "SCA", "SCA-license"} <= kinds_seen


def test_sca_and_license_rows_are_exact_pairs_of_their_manifest_snapshot():
    """Каждая строка SCA и лицензий выгрузки – точная пара «компонент, версия» из разрешения своего манифеста
    (resolved.json – все пакеты снимка по OSV-Scanner); у Juice Shop есть строки клиентской части."""
    for e in catalog()["examples"][1:]:
        snaps = {(s["codebase"], s["manifest"]): s["snapshot"] for s in e["sca_inputs"]}
        book = openpyxl.load_workbook(CATALOG / e["export"]["file"], read_only=True)
        for sheet, name_col, ver_col in (("SCA Security", "Component name", "Component version"),
                                         ("SCA Compliance", "Component name", "Component version")):
            if sheet not in book.sheetnames:
                continue
            rows = book[sheet].iter_rows(values_only=True)
            header = list(next(rows))
            for row in rows:
                manifest = row[header.index("Path")]
                snap = snaps[(row[header.index("Codebase")], manifest)]
                assert snap, (e["id"], manifest)
                pairs = json.loads((CATALOG / e["id"] / Path(snap).parent / "resolved.json").read_text(encoding="utf-8"))
                assert {"name": row[header.index(name_col)], "version": row[header.index(ver_col)]} in \
                    [{"name": x["name"], "version": x["version"]} for x in pairs], (e["id"], sheet, row[:8])
        book.close()
    juice = json.loads((CATALOG / "juice-shop" / "inputs" / "sca.json").read_text(encoding="utf-8"))
    assert any(r["manifest"] == "frontend/package.json" for r in juice["entries"])


def test_book_is_byte_identical_across_time_and_timezone(tmp_path, monkeypatch):
    import export_step
    from make_hub_from_sast import HEADERS

    row = {"Issue id": "910001", "Application": "A", "Severity": "High", "Category": "lt.x: y", "File": "a.py",
           "Line number": "1", "Source code": "-", "Status": "To verify", "Type": "source", "Found By": "semgrep",
           "CWE ID": "89", "CWE link": "-", "Codebase": "a", "Artifact": "-", "Language": "Python"}
    export_step.write_book(tmp_path / "1.xlsx", "A", [row], [], [], HEADERS, "2026-11-20")
    monkeypatch.setenv("TZ", "Asia/Vladivostok")
    if hasattr(__import__("time"), "tzset"):
        __import__("time").tzset()
    __import__("time").sleep(1.1)
    export_step.write_book(tmp_path / "2.xlsx", "A", [row], [], [], HEADERS, "2026-11-20")
    one, two = (tmp_path / "1.xlsx").read_bytes(), (tmp_path / "2.xlsx").read_bytes()
    if one != two:
        a, b = zipfile.ZipFile(io.BytesIO(one)), zipfile.ZipFile(io.BytesIO(two))
        diff = [n for n in a.namelist() if a.read(n) != b.read(n)]
        pytest.fail(f"различаются записи ZIP: {diff}")


@pytest.mark.parametrize(("ranges", "version", "fixed"), [
    ([[{"introduced": "0"}, {"fixed": "1.2"}], [{"introduced": "2.0"}, {"fixed": "2.1"}]], "1.0", "1.2"),
    ([[{"introduced": "0"}, {"fixed": "1.2"}], [{"introduced": "2.0"}]], "2.1", ""),
    ([[{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.1"}]], "2.0.5", "2.1"),
    ([[{"introduced": "0"}, {"last_affected": "1.5"}]], "1.0", ""),
    ([[{"introduced": "1.0"}, {"fixed": "1.2"}]], "0.9", ""),
])
def test_fixed_version_takes_only_the_interval_with_the_version(ranges, version, fixed):
    from osv_sca_csv import fixed_version

    vuln = {"affected": [{"package": {"name": "p", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM", "events": r} for r in ranges]}]}
    assert fixed_version(vuln, "PyPI", "p", version) == fixed


@pytest.mark.parametrize(("eco", "version", "fixed", "expected"), [
    ("PyPI", "1.0rc1", "1.0", "1.0"),            # предварительный выпуск раньше выпуска (PEP 440)
    ("npm", "1.0.0", "1.0.0-rc.1", ""),          # 1.0.0 уже после 1.0.0-rc.1 – вне интервала
    ("npm", "1.0.0-beta.2", "1.0.0-rc.1", "1.0.0-rc.1"),
    ("Maven", "2.13.4", "2.13.4.2", "2.13.4.2"),
])
def test_fixed_version_orders_prereleases_by_ecosystem(eco, version, fixed, expected):
    from osv_sca_csv import fixed_version

    vuln = {"affected": [{"package": {"name": "p", "ecosystem": eco},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    assert fixed_version(vuln, eco, "p", version) == expected


def test_osv_json_to_csv_to_sca_sheet_offline(tmp_path):
    """OSV-Scanner JSON → CSV (без сети, колонки происхождения) → лист SCA Security."""
    import subprocess

    from make_hub_from_sast import sca_rows

    report = {"results": [{"packages": [{"package": {"name": "lib", "version": "1.0.0", "ecosystem": "npm"},
                                         "groups": [{"ids": ["GHSA-aaaa", "CVE-2099-1"], "aliases": ["CVE-2099-1"],
                                                     "max_severity": "7.5"}],
                                         "vulnerabilities": [
                                             {"id": "GHSA-aaaa", "aliases": ["CVE-2099-1"], "modified": "2026-01-01T00:00:00Z",
                                              "affected": [{"package": {"name": "lib", "ecosystem": "npm"},
                                                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
                                             {"id": "CVE-2099-1", "aliases": ["GHSA-aaaa"], "modified": "2026-01-02T00:00:00Z"}]}]}]}
    src = tmp_path / "osv.json"
    src.write_text(json.dumps(report), encoding="utf-8")
    out = tmp_path / "rows.csv"
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "osv_sca_csv.py"), "--osv-json", str(src),
                          "--out", str(out)], capture_output=True, timeout=120)
    assert run.returncode == 0, run.stderr
    text = out.read_text(encoding="utf-8")
    assert "osv_id,osv_aliases,osv_modified" in text and "GHSA-aaaa" in text and "CVE-2099-1" in text
    rows = sca_rows(out, "lib-app")
    assert len(rows) == 1 and rows[0]["CVE id"] == "CVE-2099-1" and rows[0]["Non-vulnerable versions"] == "-"


# ============================================================================ распаковка

def _archive(files: dict[str, bytes], root: str = "repo-abc", extra=None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        d = tarfile.TarInfo(root)
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        for name, data in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for member in extra or []:
            tar.addfile(member)
    return buf.getvalue()


FILES = {"app.py": b"import os\nos.system(cmd)\n", "src/util.js": b"eval(x)\n=begin\nconst n = ok ? 1 : 0\n"}


def _entry(files: dict[str, bytes] = FILES) -> dict:
    digest = tree_hash(files.items())
    return {"id": "toy", "number": 1, "title": "Toy", "codebases": [{"name": "toy", "path": "", "languages": "Python"}],
            "source": {"commit": "a" * 40, "tree_sha256": digest, "files": len(files),
                       "unpacked_bytes": sum(len(v) for v in files.values()), "max_relpath": 11, "license": "MIT",
                       "repo_url": "https://github.com/o/toy",
                       "archive_url": "https://codeload.github.com/o/toy/tar.gz/" + "a" * 40},
            "export": {"file": "toy/export.xlsx", "sha256": ""}}


def test_unpack_checks_hash_writes_marker_and_tree_hash_matches(tmp_path):
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(FILES))
    entry = _entry()
    target = ex.unpack(arch, entry, tmp_path / "repos" / "examples" / ex.folder_name(entry))
    assert (target / "src" / "util.js").read_bytes() == FILES["src/util.js"]
    assert json.loads((target / MARKER).read_text(encoding="utf-8"))["commit"] == "a" * 40
    assert tree_hash_of_dir(target)[0] == entry["source"]["tree_sha256"]
    assert ex.status(entry, tmp_path / "repos")["phase"] == "downloaded"


def _bad(tmp_path, data: bytes, entry: dict, match: str):
    arch = tmp_path / "bad.tar.gz"
    arch.write_bytes(data)
    target = tmp_path / "out" / "toy"
    with pytest.raises(ex.ExampleError, match=match):
        ex.unpack(arch, entry, target)
    assert not target.exists()
    assert not [p for p in (tmp_path / "out").iterdir()], "временная папка удалена"


def test_unpack_refuses_traversal_links_case_twins_wrong_hash_and_overflow(tmp_path):
    entry = _entry()
    _bad(tmp_path, _archive({"../evil.py": b"x"}), entry, "Недопустимое имя")
    link = tarfile.TarInfo("repo-abc/link")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    _bad(tmp_path, _archive(FILES, extra=[link]), entry, "ссылка")
    _bad(tmp_path, _archive({"A.py": b"1", "a.py": b"2"}), _entry({"A.py": b"1", "a.py": b"2"}), "регистра")
    _bad(tmp_path, _archive({**FILES, "app.py": b"changed!"}), entry, "Хеш дерева")
    big = {**FILES, "big.bin": b"0" * 5000}
    _bad(tmp_path, _archive(big), entry, "больше")
    many = {f"d{i}/f": b"" for i in range(5)}
    _bad(tmp_path, _archive(many), entry, "больше")


def test_unpack_refuses_huge_pax_header_and_cleans_up(tmp_path):
    entry = _entry()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo("repo-abc/app.py")
        info.pax_headers = {"comment": "x" * 3_000_000}
        info.size = len(FILES["app.py"])
        tar.addfile(info, io.BytesIO(FILES["app.py"]))
    _bad(tmp_path, buf.getvalue(), entry, "больше")


def test_student_edits_survive_and_fetch_again_makes_a_new_folder(tmp_path):
    entry = _entry()
    data = _archive(FILES)

    class Conn:
        def __init__(self, status=200, body=data, headers=None):
            self.status, self.body, self.headers = status, io.BytesIO(body), headers or {}

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return self

        def getheader(self, name):
            return self.headers.get(name)

        def read1(self, n):
            return self.body.read(n)

        def close(self):
            pass

    class Dog:
        def cancel(self):
            pass

    connect = lambda host, deadline: (Conn(), Dog())  # noqa: E731
    repos = tmp_path / "repos"
    first = ex.download(entry, repos, tmp_path / "tmp", connect=connect)
    (first / "app.py").write_text("исправлено студентом", encoding="utf-8")
    assert ex.download(entry, repos, tmp_path / "tmp", connect=connect) == first
    assert (first / "app.py").read_text(encoding="utf-8") == "исправлено студентом"
    second = ex.download(entry, repos, tmp_path / "tmp", again=True, connect=connect)
    assert second.name.endswith("-2") and (first / "app.py").read_text(encoding="utf-8") == "исправлено студентом"
    # перенаправление и лишний байт – отказ, временный файл не остаётся
    other = _entry()
    other["id"] = "toy2"
    with pytest.raises(ex.ExampleError, match="302"):
        ex.download(other, repos, tmp_path / "tmp", connect=lambda h, d: (Conn(302), Dog()))
    big = ex.MAX_ARCHIVE_BYTES + 1
    with pytest.raises(ex.ExampleError, match="МБ"):
        ex.download(other, repos, tmp_path / "tmp",
                    connect=lambda h, d: (Conn(headers={"Content-Length": str(big)}), Dog()))
    assert not list((tmp_path / "tmp").glob("example-*"))


def test_fetch_refuses_foreign_host_and_private_address(monkeypatch):
    entry = _entry()
    entry["source"]["archive_url"] = "https://example.org/o/toy/tar.gz/" + "a" * 40
    with pytest.raises(ex.ExampleError, match="codeload"):
        ex.archive_url_ok(entry)
    from app import llm_net

    monkeypatch.setattr(llm_net, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(ex.ExampleError, match="Не удалось соединиться"):
        ex.fetch_archive(_entry(), Path(os.environ.get("TMP", ".")))


def test_external_models_switch_does_not_gate_example_download(monkeypatch):
    """Скачивание открытого примера не зависит от LLM_EXTERNAL: соединение строится без _resolve с классом external."""
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    from app import llm_net

    calls = {}
    monkeypatch.setattr(llm_net, "_getaddrinfo", lambda host, port, t, trust="local": calls.setdefault("h", host) and
                        [(2, 1, 6, "", ("140.82.112.10", 443))])
    conn, dog = ex._connection(ex.HOST, __import__("time").monotonic() + 5)
    dog.cancel()
    assert calls["h"] == ex.HOST and conn.host == ex.HOST


# ============================================================================ выгрузка с кодом и проект

def _toy_catalog(tmp_path: Path, monkeypatch) -> dict:
    import export_step
    from make_hub_from_sast import HEADERS

    entry = _entry()
    rows = []
    for i, (file, line) in enumerate([("app.py", 2), ("src/util.js", 2), ("src/util.js", 3), ("missing.py", 1)]):
        rows.append({"Issue id": str(910001 + i), "Application": "Toy", "Severity": "High", "Category": "lt.x: y",
                     "File": file, "Line number": str(line), "Source code": "-", "Status": "To verify",
                     "Type": "source", "Found By": "semgrep", "CWE ID": "78", "CWE link": "-", "Codebase": "toy",
                     "Artifact": "-", "Language": "Python"})
    book = tmp_path / "catalog" / "toy" / "export.xlsx"
    export_step.write_book(book, "Toy", rows, [], [], HEADERS, "2026-11-20")
    entry["export"]["sha256"] = hashlib.sha256(book.read_bytes()).hexdigest()
    entry["export"].update({"sast": 4, "sca": 0, "compliance": 0})
    data = {"schema": 1, "examples": [entry]}
    (tmp_path / "catalog" / "catalog.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_DIR", tmp_path / "catalog")
    monkeypatch.setattr(ex, "CATALOG_FILE", tmp_path / "catalog" / "catalog.json")
    return entry


def test_filled_export_keeps_text_cells_and_line_tail(tmp_path, monkeypatch):
    entry = _toy_catalog(tmp_path, monkeypatch)
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(FILES))
    tree = ex.unpack(arch, entry, tmp_path / "repos" / "examples" / ex.folder_name(entry))
    path, warnings = ex.filled_export(entry, tree, tmp_path / "tmp")
    ws = openpyxl.load_workbook(path)["SAST"]
    values = [r[6].value for r in ws.iter_rows(min_row=2)]
    assert values[0] == "os.system(cmd) : 2"
    assert values[1] == "=begin : 2" and ws.cell(row=3, column=7).data_type == "s", "строка с «=» – не формула"
    assert values[2] == "const n = ok ? 1 : 0 : 3"
    assert values[3] == "-" and any("missing.py" in w for w in warnings)
    result = parse_workbook(path)
    codes = {f.file: f.snippet for f in result.findings if f.line == 3}
    assert codes["src/util.js"].endswith("ok ? 1 : 0"), "конец строки с « : » сохранён"


def test_create_project_from_example_and_repeat_does_not_import_twice(tmp_path, monkeypatch):
    entry = _toy_catalog(tmp_path, monkeypatch)
    repos = tmp_path / "repos"
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, ex.examples_root(repos) / ex.folder_name(entry))
    settings = Settings(data_dir=tmp_path / "data", repos_root=repos)
    with TestClient(create_app(settings), base_url=BASE) as client:
        page = client.get("/examples")
        assert page.status_code == 200 and "Toy" in page.text and "Создать проект" in page.text
        r = client.post("/examples/toy/project", headers={"Origin": BASE}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/projects/"), r.headers.get("location")
        pid = int(r.headers["location"].split("/")[2].split("?")[0])
        db = client.app.state.db
        project = db.get_project(pid)
        assert project["repos_dir"] == "examples" and project["name"] == "Пример: Toy"
        imports = db._all("SELECT id FROM imports WHERE project_id = ?", (pid,))
        assert len(imports) == 1
        again = client.post("/examples/toy/project", headers={"Origin": BASE}, follow_redirects=False)
        assert again.headers["location"].startswith(f"/projects/{pid}")
        assert len(db._all("SELECT id FROM imports WHERE project_id = ?", (pid,))) == 1
        page = client.get("/examples")
        assert f"/projects/{pid}" in page.text and "Открыть проект" in page.text
        db.delete_project(pid) if hasattr(db, "delete_project") else None


def test_revision_of_monorepo_subfolders_comes_from_the_example_marker(tmp_path):
    from app.context import clone_revision

    tree = tmp_path / "examples" / "crapi-bbbbbbb"
    (tree / "services" / "web").mkdir(parents=True)
    (tree / MARKER).write_text(json.dumps({"id": "crapi", "commit": "b" * 40}), encoding="utf-8")
    root = tmp_path / "examples"
    assert clone_revision(tree / "services" / "web", root) == "b" * 40
    assert clone_revision(tree, root) == "b" * 40
    assert clone_revision(tree / "services" / "web") == "", "проект не из каталога – маркер не читается"
    assert clone_revision(tmp_path / "examples", root) == "", "выше маркера ревизии нет"
    other = tmp_path / "examples" / "mine"
    (other / "sub").mkdir(parents=True)
    (other / MARKER).write_text(json.dumps({"id": "crapi", "commit": "b" * 40}), encoding="utf-8")
    assert clone_revision(other / "sub", root) == "", "маркер в папке с чужим именем не принимается"


def test_build_refuses_inputs_of_another_commit_and_incomplete_reports(tmp_path, monkeypatch):
    import build
    import catalog_step

    src = json.loads((CATALOG / "sources.json").read_text(encoding="utf-8"))["examples"][7]  # go-test-bench
    assert build.required_reports(src) == ["semgrep.json", "gosec-go-test-bench.json"]
    other = {**src, "commit": "f" * 40, "tree": {}}
    with pytest.raises(RuntimeError, match="другого коммита"):
        catalog_step.build_example(other, CATALOG, {}, "", {}, lambda f, d: d, "2026-11-20", {})
