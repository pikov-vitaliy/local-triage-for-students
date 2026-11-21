"""Обёртка npm учебного стенда (ADR-0155): тесты чистых функций на Node
(tests/npm/launcher.test.js), синтаксис всех модулей, перечень состава пакета, версия пакета и приложения, страж
пакета на синтетических архивах. Без Node тесты обёртки пропускаются."""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from app import __version__

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="нет Node.js")
sys.path.insert(0, str(ROOT / "scripts"))
import npm_package_guard as guard  # noqa: E402


@needs_node
def test_node_unit_tests_pass():
    run = subprocess.run([NODE, "--test", str(ROOT / "tests" / "npm" / "launcher.test.js")], capture_output=True,
                         text=True, encoding="utf-8", timeout=300)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-2000:]


@needs_node
def test_every_launcher_module_parses():
    for file in [ROOT / "npm" / "cli.js", *sorted((ROOT / "npm" / "lib").glob("*.js"))]:
        run = subprocess.run([NODE, "--check", str(file)], capture_output=True, text=True, timeout=60)
        assert run.returncode == 0, f"{file.name}: {run.stderr}"


@needs_node
def test_package_manifest_matches_rules():
    run = subprocess.run([NODE, str(ROOT / "npm" / "pack.mjs"), "check"], capture_output=True, text=True,
                         encoding="utf-8", timeout=120)
    assert run.returncode == 0, run.stderr


@needs_node
def test_host_metrics_follow_app_contract(tmp_path: Path):
    """Снимок держателя стенда читается приложением как свежий: тот же контракт, что у scripts/host-metrics.ps1."""
    from app.telemetry import host_snapshot
    script = ("const m = require(process.argv[1]); const stop = m.startCollector(process.argv[2]); "
              "setTimeout(() => { stop(); }, 200);")
    run = subprocess.run([NODE, "-e", script, str(ROOT / "npm" / "lib" / "metrics.js"), str(tmp_path)], capture_output=True,
                         text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    snap = host_snapshot(tmp_path / "telemetry" / "host.json")
    assert snap["status"] == "fresh" and snap["scope"] == "ollama_host"
    assert snap["memory"]["total_bytes"] > 0 and isinstance(snap["addresses"], list)


def test_package_version_follows_app_version():
    """0.10.0.devNN в приложении – 0.10.0-dev.NN в package.json (раздел 3.1)."""
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    main, _, dev = __version__.partition(".dev")
    assert package["version"] == (f"{main}-dev.{dev}" if dev else main)
    assert package["bin"] == {"local-triage": "npm/cli.js"}
    assert set(package["optionalDependencies"].values()) == {"17.12.0-beta.19"}
    shrink = json.loads((ROOT / "npm-shrinkwrap.json").read_text(encoding="utf-8"))
    for name in package["optionalDependencies"]:
        entry = shrink["packages"][f"node_modules/{name}"]
        assert entry["version"] == "17.12.0-beta.19" and entry["integrity"].startswith("sha512-")


def test_requirements_are_hashed_for_every_package():
    text = (ROOT / "npm" / "requirements.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([a-z0-9-]+)==", text, re.M)
    assert len(pins) >= 20
    for block in re.split(r"\n(?=[a-z0-9-]+==)", text.strip()):
        if "==" in block.splitlines()[0]:
            assert "--hash=sha256:" in block, block.splitlines()[0]


# ---------------------------------------------------------------- страж пакета


def make_tgz(tmp_path: Path, files: dict[str, bytes], name: str = "pkg.tgz") -> Path:
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as archive:
        for rel, data in files.items():
            info = tarfile.TarInfo(f"package/{rel}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def manifest(tmp_path: Path, names: list[str]) -> Path:
    path = tmp_path / "files.manifest"
    path.write_text("# перечень\n" + "\n".join(names) + "\n", encoding="utf-8")
    return path


def test_guard_accepts_clean_package(tmp_path: Path):
    files = {"package.json": b"{}", "app/x.py": "print('ok')\n".encode(), "app/llm_net.py": b'_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8",\n'}
    assert guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))) == []


def test_guard_refuses_extra_missing_and_no_package_json(tmp_path: Path):
    files = {"app/x.py": b"x = 1\n", "app/templates/extra.html": b"<p>x</p>\n"}
    problems = guard.check(make_tgz(tmp_path, files), manifest(tmp_path, ["app/x.py", "app/gone.py"]))
    text = "\n".join(problems)
    assert "app/templates/extra.html: файла нет в перечне" in text
    assert "app/gone.py: в перечне есть, в пакете нет" in text
    assert "нет package.json" in text


def test_guard_exceptions_do_not_hide_stand_subnet(tmp_path: Path, monkeypatch):
    """Разрешённый частный адрес из перечня не прячет подсеть стенда владельца в том же файле, а в другом файле тот
    же адрес – нарушение."""
    lan = "198.51.100." + "7"
    monkeypatch.setattr(guard, "STAND_LAN", re.compile(r"198\.51\.100\.\d+"))  # правило – из файла вне репозитория
    files = {"package.json": b"{}", "app/llm_net.py": f'_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8",\nHOME = "{lan}"\n'.encode(),
             "app/other.py": b'X = "10.0.0.0"\n'}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "подсети стенда" in text and "app/other.py:1: частный адрес 10.0.0.0" in text


def test_guard_checks_emails_but_not_in_license_texts(tmp_path: Path):
    files = {"package.json": b"{}", "app/a.py": b"# person@company.org\n# ok@example.com\n# https://u:pw@host.org/\n",
             "THIRD-PARTY-NOTICES.md": b"Copyright author@zlib.net\n"}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "person@company.org" in text
    assert "example.com" not in text and "zlib.net" not in text and "pw@host" not in text


def test_guard_exceptions_are_narrow(tmp_path: Path):
    """Исключения – только в своём контексте: адрес после «mailto:», числовой ящик без «узел:порт» и разрешённый
    частный адрес вне строки-примера – нарушения (ревью сборки А, В16)."""
    files = {"package.json": b"{}",
             "app/a.py": b"# mailto:person@corp.org\n# 123@corp.org\n# host.example.org:443@osv.dev ok\n",
             "app/llm_chat.py": ('HINT = "нужен адрес сервера в сети организации, например http://10.0.0.5:8000/v1")\n'
                                 'SERVER = "10.0.0.5"\n'
                                 '# например http://10.0.0.5:8000/v1 – посторонний комментарий\n').encode(),
             "app/llm_net.py": b'_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8",\nGATEWAY = "10.0.0.0"\n'}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "person@corp.org" in text and "123@corp.org" in text and "osv.dev" not in text
    assert "app/llm_chat.py:2: частный адрес 10.0.0.5" in text and "app/llm_chat.py:1" not in text
    assert "app/llm_chat.py:3: частный адрес 10.0.0.5" in text  # слово и адрес вне самой подсказки (ревью круга 4)
    assert "app/llm_net.py:2: частный адрес 10.0.0.0" in text and "app/llm_net.py:1" not in text


def test_guard_reads_workbook_cells_properties_and_link_targets(tmp_path: Path, monkeypatch):
    """Книга: ячейка с подсетью стенда, свойство с личным путём и цель гиперссылки вида file: – три нарушения (Д21)."""
    lan = "198.51.100." + "7"
    monkeypatch.setattr(guard, "STAND_LAN", re.compile(r"198\.51\.100\.\d+"))  # правило – из файла вне репозитория
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w") as z:
        z.writestr("xl/sharedStrings.xml", f"<sst><si><t>{lan}</t></si></sst>")
        z.writestr("docProps/core.xml", '<cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc"><dc:creator>'
                   + "V" + ":&#92;work</dc:creator></cp:coreProperties>")  # &#92; – обратная косая черта ссылкой
        z.writestr("xl/worksheets/_rels/sheet1.xml.rels",
                   '<Relationships><Relationship Target="file:///secret/report.xlsx" TargetMode="External"/></Relationships>')
    files = {"package.json": b"{}", "examples/demo/demo-hub-report.xlsx": book.getvalue()}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "подсети стенда" in text and "путь с диска" in text and "цель ссылки не http(s)" in text


def test_guard_checks_split_cell_and_network_outside_declaration(tmp_path: Path):
    """Ячейка из двух фрагментов с разным оформлением проверяется целиком; сеть с маской в постороннем комментарии
    llm_net.py – нарушение, в объявлении – нет (ревью сборки А, круг 2)."""
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w") as z:
        z.writestr("xl/sharedStrings.xml", "<sst><si><r><t>10.2.</t></r><r><t>3.4</t></r></si></sst>")
    files = {"package.json": b"{}", "examples/demo/demo-hub-report.xlsx": book.getvalue(),
             "app/llm_net.py": b'_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8",\n'
                               b'# 10.0.0.0/16 - other comment\n'}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "10.2.3.4" in text
    assert "app/llm_net.py:2: частный адрес 10.0.0.0" in text and "app/llm_net.py:1" not in text


def test_guard_refuses_unknown_binary(tmp_path: Path):
    files = {"package.json": b"{}", "app/static/blob.bin": b"\0\1\2"}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "двоичный файл" in text


def test_guard_refuses_repeated_member_name(tmp_path: Path):
    """Два члена архива с одним именем: второй заменил бы первый в проверке – нарушение (ревью круга 4)."""
    import tarfile
    tgz = tmp_path / "dup.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        for body in (b'{"name": "x"}', b"{}"):
            info = tarfile.TarInfo("package/package.json")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    text = "\n".join(guard.check(tgz, manifest(tmp_path, ["package.json"])))
    assert "package.json: имя повторяется в архиве" in text


def test_guard_round5_classes(tmp_path: Path):
    """Ревью круга 5: одноимённые части книги, внешняя относительная ссылка, частный IPv6, почта с кириллическим
    доменом, разрешённое поле внутри многострочного HTML-комментария – нарушения."""
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w") as z:
        z.writestr("docProps/core.xml", "<p>person@corp.org</p>")
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            z.writestr("docProps/core.xml", "<p>чисто</p>")
        z.writestr("xl/worksheets/_rels/sheet1.xml.rels",
                   '<Relationships><Relationship Target="../other/report.xlsx" TargetMode="External"/>'
                   '<Relationship Target="../sharedStrings.xml"/></Relationships>')
    html = ('<!--\n<input type="text" class="input-mono" name="base_url" placeholder="http://10.0.0.5:11434">\n-->\n'
            '<input type="text" class="input-mono" name="base_url" placeholder="http://10.0.0.5:11434">\n')
    files = {"package.json": b"{}", "examples/demo/book.xlsx": book.getvalue(),
             "app/a.py": "# fd12:3456:789a::1 и кто@почта.рф\n".encode(),
             "app/templates/settings/provider.html": html.encode()}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "имя части повторяется" in text
    assert "../other/report.xlsx" in text and "../sharedStrings.xml" not in text
    assert "частный адрес IPv6 fd12:3456:789a::1" in text and "почта.рф" in text
    assert "provider.html:2: частный адрес 10.0.0.5" in text and "provider.html:4" not in text


def test_guard_backlog_137(tmp_path: Path):
    """Бэклог 137: статическая цель HYPERLINK в формуле книги и частный IPv6 любой записью (с сокращением в конце) –
    нарушения; сеть fc00::/7 и публичный IPv6 – нет."""
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w") as z:
        z.writestr("xl/worksheets/sheet1.xml", '<worksheet><sheetData><row><c r="A1"><f>HYPERLINK("other.xlsx","x")</f>'
                   '</c><c r="A2"><f>HYPERLINK("https://example.org/a","ok")</f></c></row></sheetData></worksheet>')
    files = {"package.json": b"{}", "examples/demo/book.xlsx": book.getvalue(),
             "app/a.py": b"# fd12:3456:: fd00:1:2::5 2001:db8::1 fc00::/7 fc00::/70\n"}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "other.xlsx" in text and "example.org" not in text
    assert "IPv6 fd12:3456::" in text and "IPv6 fd00:1:2::5" in text and "2001:db8" not in text
    assert text.count("IPv6 fc00::") == 1  # /70 – не сеть fc00::/7


def test_guard_hyperlink_argument_forms(tmp_path: Path):
    """HYPERLINK: склейка литералов https проходит, ссылка на ячейку – цель статически не проверить (ревью круга 8)."""
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w") as z:
        z.writestr("xl/worksheets/sheet1.xml", '<worksheet><sheetData><row><c r="A1"><f>HYPERLINK("https"&amp;"://example.org/a","o")'
                   '</f></c><c r="A2"><f>HYPERLINK(B1,"o")</f></c></row></sheetData></worksheet>')
    files = {"package.json": b"{}", "examples/demo/book.xlsx": book.getvalue()}
    text = "\n".join(guard.check(make_tgz(tmp_path, files), manifest(tmp_path, list(files))))
    assert "example.org" not in text and "статически не проверить «B1»" in text  # B1 пустая – цель не определить
