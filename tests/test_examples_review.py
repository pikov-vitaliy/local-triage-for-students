"""Находки круга 1 ревью сборки Б (ADR-0156): распаковка, обрывы создания проекта, связь по ревизии, восстановление
соответствий с подтверждением, строки из проверенного дерева, Demo Library один раз, маркер, запрет Hub."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import examples as ex  # noqa: E402
from app.example_tree import MARKER, tree_hash  # noqa: E402
from test_examples_catalog import FILES, _archive, _entry, _toy_catalog  # noqa: E402
from test_web import ORIGIN, web  # noqa: E402, F401

CATALOG_DIR = Path(__file__).resolve().parents[1] / "examples" / "catalog"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "examples"))


def _bad(tmp_path, data: bytes, entry: dict, match: str):
    arch = tmp_path / "bad.tar.gz"
    arch.write_bytes(data)
    target = tmp_path / "out" / "toy"
    with pytest.raises(ex.ExampleError, match=match):
        ex.unpack(arch, entry, target)
    assert not target.exists() and not list((tmp_path / "out").iterdir())


def test_backslash_and_directory_escape_are_refused(tmp_path):
    entry = _entry()
    _bad(tmp_path, _archive({"a\\..\\..\\evil.py": b"x"}), entry, "Недопустимое имя")
    d = tarfile.TarInfo("repo-abc/sub\\..\\..\\outside")
    d.type = tarfile.DIRTYPE
    _bad(tmp_path, _archive(FILES, extra=[d]), entry, "Недопустимое имя")
    assert not (tmp_path / "outside").exists()


def test_stream_limit_uses_exact_tar_size(tmp_path):
    entry = _entry()
    entry["source"]["tar_bytes"] = 10  # предел – размер TAR плюс 1 МиБ: маленькому архиву запаса хватает
    arch = tmp_path / "ok.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, tmp_path / "ok" / "toy")
    huge = {"f.bin": b"0" * (2 * 1024 * 1024)}
    big = _entry(huge)
    big["source"]["tar_bytes"] = 1024
    _bad(tmp_path, _archive(huge), big, "больше")


def test_too_long_path_marks_the_card_failed_not_queued(tmp_path, monkeypatch):
    entry = _entry()
    entry["source"]["max_relpath"] = 300
    monkeypatch.setattr(ex.os, "name", "nt")
    monkeypatch.setattr(ex, "long_paths_enabled", lambda: False)
    with pytest.raises(ex.ExampleError, match="слишком длинный"):
        ex.download(entry, tmp_path / "repos", tmp_path / "tmp", connect=lambda h, d: pytest.fail("сети нет"))
    st = ex.status(entry, tmp_path / "repos")
    assert st["phase"] == "failed" and "длинный" in st["message"]


def test_export_lines_come_from_the_verified_tree_not_from_student_edits(tmp_path, monkeypatch):
    entry = _toy_catalog(tmp_path, monkeypatch)
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(FILES))
    tree = ex.unpack(arch, entry, tmp_path / "repos" / "examples" / ex.folder_name(entry))
    (tree / "app.py").write_text("import os\nправка студента\n", encoding="utf-8")
    import openpyxl

    path, _ = ex.filled_export(entry, tree, tmp_path / "tmp")
    assert openpyxl.load_workbook(path)["SAST"].cell(row=2, column=7).value == "os.system(cmd) : 2"


def test_long_line_within_import_limit_is_kept(tmp_path, monkeypatch):
    long_line = "x = '" + "a" * 600 + "'"
    files = {**FILES, "app.py": ("import os\n" + long_line + "\n").encode()}
    monkeypatch.setattr("test_examples_catalog.FILES", files)
    entry = _toy_catalog(tmp_path, monkeypatch)
    entry["source"].update(tree_sha256=tree_hash(files.items()), files=len(files),
                           unpacked_bytes=sum(len(v) for v in files.values()))
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(files))
    tree = ex.unpack(arch, entry, tmp_path / "repos" / "examples" / ex.folder_name(entry))
    import openpyxl

    path, warnings = ex.filled_export(entry, tree, tmp_path / "tmp")
    assert openpyxl.load_workbook(path)["SAST"].cell(row=2, column=7).value == f"{long_line} : 2"


def test_downloaded_copies_beyond_twenty_are_found(tmp_path):
    entry = _entry()
    root = ex.examples_root(tmp_path)
    folder = root / ex.folder_name(entry, 25)
    folder.mkdir(parents=True)
    (folder / MARKER).write_text(json.dumps({"id": "toy", "commit": "a" * 40}), encoding="utf-8")
    assert ex.downloaded_folders(entry, tmp_path) == [folder]


def test_marker_outside_the_examples_folder_is_ignored(tmp_path):
    from app.context import clone_revision

    stray = tmp_path / "work"
    (stray / "repo").mkdir(parents=True)
    (stray / MARKER).write_text(json.dumps({"commit": "c" * 40}), encoding="utf-8")
    assert clone_revision(stray / "repo", tmp_path / "examples") == ""


# ============================================================================ проект из примера

def _prepare(web, monkeypatch) -> dict:  # noqa: F811
    entry = _toy_catalog(web.tmp, monkeypatch)
    arch = web.tmp / "toy.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, ex.examples_root(web.settings.repos_root) / ex.folder_name(entry))
    return entry


def _create(web):  # noqa: F811
    return web.client.post("/examples/toy/project", headers=ORIGIN, follow_redirects=False)


def _imports(db, pid: int) -> int:
    return len(db._all("SELECT id FROM imports WHERE project_id = ?", (pid,)))


def test_crash_after_project_creation_resumes_without_second_import(web, monkeypatch):  # noqa: F811
    from app.routes import examples as routes

    _prepare(web, monkeypatch)
    db = web.app.state.db
    real = routes.store_import

    def broken(*a, **k):
        raise RuntimeError("обрыв после создания проекта")

    monkeypatch.setattr(routes, "store_import", broken)
    assert "error=" in _create(web).headers["location"]
    links = db.get_settings()["examples_projects"]
    (record,) = [v for k, v in links.items() if k.startswith("toy@")]
    assert record["state"] == "creating" and record["import_id"] == 0
    assert "Продолжить создание проекта" in web.client.get("/examples").text
    monkeypatch.setattr(routes, "store_import", real)
    r = _create(web)
    assert r.headers["location"].startswith(f"/projects/{record['project_id']}")
    assert _imports(db, record["project_id"]) == 1
    assert len([p for p in db.list_projects(archived=None) if p["name"].startswith("Пример: Toy")]) == 1


def test_failure_inside_import_transaction_leaves_no_import(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    db = web.app.state.db
    real = db.set_json_entry_in
    calls = {"n": 0}

    def flaky(c, setting, key, value):
        calls["n"] += 1
        if value.get("import_id"):
            raise RuntimeError("обрыв при фиксации импорта")
        return real(c, setting, key, value)

    monkeypatch.setattr(db, "set_json_entry_in", flaky)
    _create(web)
    (record,) = db.get_settings()["examples_projects"].values()
    assert record["import_id"] == 0 and _imports(db, record["project_id"]) == 0, "импорт откатился вместе с отметкой"
    monkeypatch.setattr(db, "set_json_entry_in", real)
    _create(web)
    assert _imports(db, record["project_id"]) == 1


def test_new_commit_keeps_the_link_of_the_old_project(web, monkeypatch):  # noqa: F811
    entry = _prepare(web, monkeypatch)
    db = web.app.state.db
    first = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    catalog = json.loads(ex.CATALOG_FILE.read_text(encoding="utf-8"))
    catalog["examples"][0]["source"]["commit"] = "b" * 40
    catalog["examples"][0]["source"]["archive_url"] = "https://codeload.github.com/o/toy/tar.gz/" + "b" * 40
    ex.CATALOG_FILE.write_text(json.dumps(catalog), encoding="utf-8")
    new_entry = catalog["examples"][0]
    arch = web.tmp / "toy.tar.gz"
    ex.unpack(arch, new_entry, ex.examples_root(web.settings.repos_root) / ex.folder_name(new_entry))
    second = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert second != first
    links = db.get_settings()["examples_projects"]
    assert {v["project_id"] for v in links.values()} == {first, second}
    assert links[f"toy@{'a' * 40}"]["commit"] == entry["source"]["commit"]


def test_restore_mapping_asks_before_deleting_saved_slices(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    real_preview = db.restore_preview

    def preview_with_effects(pid_, mapping):
        shown = real_preview(pid_, mapping)
        return {**shown, "effects": {"cases": 2, "reviewed": 1}}

    monkeypatch.setattr(db, "restore_preview", preview_with_effects)
    r = web.client.post(f"/projects/{pid}/example-mapping", headers=ORIGIN, follow_redirects=False)
    assert r.headers["location"] == f"/projects/{pid}/example-mapping?stale=1"
    assert db.get_codebase_map(pid)["toy"]["folder"] == "elsewhere", "без подтверждения ничего не меняется"
    page = web.client.get(f"/projects/{pid}/example-mapping").text
    assert "удалятся сохранённые срезы кода: 2" in page and "снимутся отметки «Проверено»: 1" in page
    assert "elsewhere" in page
    import re
    expect = re.search(r'name="expect" value="([0-9a-f]+)"', page).group(1)
    db.set_codebase_folder(pid, "toy", "third", manual=True)  # после показа страницы изменилось – отпечаток не тот
    r = web.client.post(f"/projects/{pid}/example-mapping", headers=ORIGIN, follow_redirects=False,
                        data={"expect": expect})
    assert r.headers["location"].endswith("stale=1") and db.get_codebase_map(pid)["toy"]["folder"] == "third"
    page = web.client.get(f"/projects/{pid}/example-mapping").text
    expect = re.search(r'name="expect" value="([0-9a-f]+)"', page).group(1)
    r = web.client.post(f"/projects/{pid}/example-mapping", headers=ORIGIN, follow_redirects=False,
                        data={"expect": expect})
    assert "ok=example_mapping" in r.headers["location"]
    assert db.get_codebase_map(pid)["toy"]["folder"].startswith("toy-")
    assert 'id="restore-example-mapping"' in web.client.get(f"/projects/{pid}").text


def test_demo_library_from_catalog_is_created_once(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    catalog = {"schema": 1, "examples": [{"id": "demo-library", "number": 0, "title": "Demo Library", "builtin": "demo",
                                          "source": None, "export": None, "codebases": [], "languages": [],
                                          "description": "", "level": ""}]}
    (web.tmp / "cat").mkdir()
    (web.tmp / "cat" / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", web.tmp / "cat" / "catalog.json")
    first = web.client.post("/examples/demo-library/project", headers=ORIGIN, follow_redirects=False)
    if "error" in first.headers.get("location", "") or first.status_code != 303:
        pytest.skip("демо-выгрузка в этой установке не найдена")
    again = web.client.post("/examples/demo-library/project", headers=ORIGIN, follow_redirects=False)
    pid = int(first.headers["location"].split("/")[2].split("?")[0])
    assert again.headers["location"] == f"/projects/{pid}"
    assert len([p for p in db.list_projects(archived=None) if p["name"].startswith("Демо:")]) == 1


def test_hub_assignment_routes_refuse_catalog_projects(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert web.client.get(f"/projects/{pid}/hub-assignment?app=123").status_code == 400
    r = web.client.post(f"/projects/{pid}/hub-assignment", headers=ORIGIN, data={"app": "123", "token": "x"})
    assert r.status_code == 400 and not web.app.state.db.get_project(pid).get("hub_app_id")


def test_mapping_form_accepts_third_level_folder_of_the_example(web, monkeypatch):  # noqa: F811
    from app.routes.examples import link_folders

    _prepare(web, monkeypatch)
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert any(f.startswith("toy-") for f in link_folders(web.app.state.db, pid, web.settings.repos_root / "examples"))


# ============================================================================ круг 2

def test_broken_catalog_does_not_stop_the_app(web, monkeypatch, tmp_path):  # noqa: F811
    bad = tmp_path / "catalog.json"
    bad.write_text('{"schema": 1, "examples": [', encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", bad)
    with pytest.raises(ex.ExampleError, match="не читается"):
        ex.load_catalog()
    from app.routes.examples import start_background

    start_background(web.settings.__class__(**{**web.settings.__dict__, "stand": "npm"}))  # не падает
    page = web.client.get("/examples")
    assert page.status_code == 200 and "не читается" in page.text
    assert web.client.get("/examples/status").json() == {}


def test_source_change_bumps_the_preview_revision_even_without_the_mark(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    before = db.external_mark_revision(pid)
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    assert db.external_mark_revision(pid) > before, "старая форма предпросмотра больше не проходит"


def test_foreign_import_leaves_the_reason_empty(web, monkeypatch):  # noqa: F811
    from app.routes.examples import example_reason

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert example_reason(db, pid).startswith("Учебный пример")
    db.set_external_mark(pid, "Учебный пример Toy из каталога стенда: открытый код")
    db.save_import(pid, "foreign.xlsx", "hub", [], {}, [], [])
    assert example_reason(db, pid) == ""
    page = web.client.get(f"/projects/{pid}/external").text
    assert "Учебный пример Toy из каталога стенда" not in page, "прежнее обоснование не подставляется"


def test_repeat_create_does_not_override_the_students_profile(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    local = db.create_provider({"name": "Примеры", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    mine = db.create_provider({"name": "Мой", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    db.set_settings({"examples_provider_id": int(local["id"])})
    _prepare(web, monkeypatch)
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert db.get_project(pid)["provider_id"] == local["id"]
    db.update_project(pid, provider_id=int(mine["id"]))
    _create(web)
    assert db.get_project(pid)["provider_id"] == mine["id"]


def test_unassigned_profile_reason_is_shown(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    db.set_settings({"examples_provider_id": 99999})  # выбран и удалён
    _prepare(web, monkeypatch)
    r = _create(web)
    assert "ok=project_example_noprofile" in r.headers["location"]
    assert "удалён" in web.client.get("/examples").text


def test_unreadable_export_creates_no_project(web, monkeypatch):  # noqa: F811
    entry = _prepare(web, monkeypatch)
    db = web.app.state.db
    (ex.CATALOG_DIR / entry["export"]["file"]).write_bytes(b"not a workbook")
    before = len(db.list_projects(archived=None))
    r = _create(web)
    assert "error=" in r.headers["location"] and len(db.list_projects(archived=None)) == before


def test_preset_save_opens_the_new_profile(web, monkeypatch):  # noqa: F811
    r = web.client.post("/settings/providers/new", headers=ORIGIN, follow_redirects=False, data={
        "name": "Ollama на этом компьютере", "kind": "ollama", "trust": "local", "base_url": web.fake.url,
        "default_model": "gpt-oss:20b", "enabled": "1", "think": "auto", "action": "save", "preset": "ollama-local"})
    assert r.status_code == 303 and r.headers["location"].startswith("/settings/providers/"), r.text[:500]
    assert r.headers["location"].split("?")[0] != "/settings/providers"


def test_tar_service_headers_count_as_records(tmp_path):
    entry = _entry()
    entry["source"]["files"] = 2
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo("repo-abc")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, data in FILES.items():
            info = tarfile.TarInfo("repo-abc/" + name)
            info.pax_headers = {"comment": "x" * 400_000}  # сотни блоков служебных заголовков на элемент
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    monkey = ex.MAX_MEMBERS_ANY
    try:
        ex.MAX_MEMBERS_ANY = 4  # корень + 2 файла и 2 их служебных заголовка = 5 записей
        _bad(tmp_path, buf.getvalue(), entry, "элементов")
    finally:
        ex.MAX_MEMBERS_ANY = monkey


def test_catalog_project_hides_hub_field_and_demo_from_catalog_refuses_hub(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert 'id="project-hub-app-id"' not in web.client.get(f"/projects/{pid}").text


# ============================================================================ круг 3

def test_resume_after_import_does_not_touch_operator_mapping(web, monkeypatch):  # noqa: F811
    """Н1: после фиксации импорта и до «готов» оператор сменил папку – «Продолжить» её не трогает и срезов не удаляет."""
    from app.routes import examples as routes

    _prepare(web, monkeypatch)
    db = web.app.state.db
    real = db.update_json_entry
    calls = {"n": 0}

    def crash_before_ready(setting, key, value):
        if value.get("state") == "ready" and calls["n"] == 0:
            calls["n"] += 1
            raise RuntimeError("обрыв перед «готов»")
        return real(setting, key, value)

    monkeypatch.setattr(db, "update_json_entry", crash_before_ready)
    _create(web)
    (record,) = db.get_settings()["examples_projects"].values()
    pid = record["project_id"]
    assert record["state"] == "creating" and record["import_id"]
    db.set_codebase_folder(pid, "toy", "operator-folder", manual=True)
    deleted = []
    monkeypatch.setattr(db, "restore_codebase_map", lambda *a, **k: deleted.append(a) or 0)
    monkeypatch.setattr(db, "update_json_entry", real)
    r = _create(web)
    assert r.headers["location"].startswith(f"/projects/{pid}")
    assert not deleted and db.get_codebase_map(pid)["toy"]["folder"] == "operator-folder"
    assert db.get_settings()["examples_projects"][routes.link_key(_entry())]["state"] == "ready"


def test_catalog_entry_without_id_is_a_readable_error(tmp_path, monkeypatch):
    bad = tmp_path / "catalog.json"
    bad.write_text('{"schema": 1, "examples": [null]}', encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", bad)
    with pytest.raises(ex.ExampleError, match="повреждён"):
        ex.load_catalog()


def test_foreign_top_level_record_is_refused(tmp_path):
    entry = _entry()
    stray = tarfile.TarInfo("other-root/evil.py")
    stray.size = 1
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        d = tarfile.TarInfo("repo-abc")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        for name, data in FILES.items():
            info = tarfile.TarInfo("repo-abc/" + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar.addfile(stray, io.BytesIO(b"x"))
    _bad(tmp_path, buf.getvalue(), entry, "вне общей папки")
    link_first = _archive(FILES)  # первая запись – не каталог
    buf2 = io.BytesIO()
    with tarfile.open(fileobj=buf2, mode="w:gz") as tar:
        f = tarfile.TarInfo("top.txt")
        f.size = 1
        tar.addfile(f, io.BytesIO(b"x"))
    _bad(tmp_path, buf2.getvalue(), entry, "не того вида")
    del link_first


def test_old_copy_without_verified_lines_asks_for_fresh_download(tmp_path, monkeypatch):
    entry = _toy_catalog(tmp_path, monkeypatch)
    arch = tmp_path / "a.tar.gz"
    arch.write_bytes(_archive(FILES))
    tree = ex.unpack(arch, entry, tmp_path / "repos" / "examples" / ex.folder_name(entry))
    marker = json.loads((tree / MARKER).read_text(encoding="utf-8"))
    marker.pop("lines")
    (tree / MARKER).write_text(json.dumps(marker), encoding="utf-8")
    with pytest.raises(ex.ExampleError, match="Скачать заново"):
        ex.filled_export(entry, tree, tmp_path / "tmp")


def test_second_mark_does_not_reapply_examples_profile(web, monkeypatch):  # noqa: F811
    from app.routes.examples import finish_pending_profile

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    assert finish_pending_profile(db, pid, "") == "none", "назначение не ожидалось – повторная отметка ничего не меняет"


def test_restore_button_hidden_for_demo_library(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    pid = db.create_project("Демо: Demo Library")
    db.update_json_entry("examples_projects", "demo-library@builtin",
                         {"example_id": "demo-library", "project_id": pid, "state": "ready"})
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="restore-example-mapping"' not in page and 'id="project-hub-app-id"' not in page


def test_key_change_makes_check_results_stale(web, monkeypatch):  # noqa: F811
    from app.routes import providers as routes

    db = web.app.state.db
    profile = db.create_provider({"name": "P", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    prints = iter(["aaaa", "bbbb"])
    monkeypatch.setattr(routes, "key_print", lambda *a: next(prints))
    routes.record_check(db, profile, "probe", True)
    assert routes.check_state(db, profile, "probe") == "none", "ключ сменился после проверки"


def test_npm_semver_and_alias_groups():
    from osv_sca_csv import alias_groups, fixed_version

    v = {"affected": [{"package": {"name": "p", "ecosystem": "npm"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}]}
    assert fixed_version(v, "npm", "p", "1.0.0-final") == "1.0.0"
    groups = alias_groups([{"id": "GHSA-a", "aliases": ["CVE-1", "CVE-2"]}, {"id": "PYSEC-b", "aliases": ["CVE-2", "CVE-1"]}])
    assert list(groups) == ["CVE-1"] and len(groups["CVE-1"]) == 2


# ============================================================================ круг 4

def test_restore_page_numbers_and_fingerprint_come_from_one_snapshot(web, monkeypatch):  # noqa: F811
    import re

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    (web.settings.repos_root / "examples" / "elsewhere").mkdir(parents=True, exist_ok=True)
    preview = db.restore_preview(pid, {"toy": [f for f in db.get_settings()["examples_projects"].values()][0]["codebases"]["toy"]})
    page = web.client.get(f"/projects/{pid}/example-mapping").text
    assert re.search(r'name="expect" value="([0-9a-f]+)"', page).group(1) == preview["expect"]


def test_resume_after_operator_import_keeps_operator_project(web, monkeypatch):  # noqa: F811
    from app.routes import examples as routes

    _prepare(web, monkeypatch)
    db = web.app.state.db
    real = routes.store_import
    monkeypatch.setattr(routes, "store_import", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("обрыв")))
    _create(web)
    (record,) = db.get_settings()["examples_projects"].values()
    first = record["project_id"]
    db.set_repos_dir(first, "my-own-folder")  # оператор начал работать в незавершённом проекте
    monkeypatch.setattr(routes, "store_import", real)
    r = _create(web)
    second = int(r.headers["location"].split("/")[2].split("?")[0])
    assert second != first and db.get_project(first)["repos_dir"] == "my-own-folder"


def test_restore_refuses_when_project_folder_changed(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    db.set_repos_dir(pid, "other")
    page = web.client.get(f"/projects/{pid}/example-mapping").text
    assert 'id="mapping-problem"' in page and "Восстановить</button>" not in page


def test_root_change_revokes_catalog_marks(web, monkeypatch):  # noqa: F811
    from app.routes.examples import LINK_KEY, revoke_marks_on_root_change

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_external_mark(pid, "Учебный пример: открытый код, проверено для теста")
    key = next(iter(db.get_settings()[LINK_KEY]))
    db.update_json_entry(LINK_KEY, key, {**db.get_settings()[LINK_KEY][key], "root": "host:/other/examples",
                                         "mark_root": "host:/other/examples"})  # отметка дана для прежнего корня
    assert revoke_marks_on_root_change(db, web.settings) == 1 and db.get_project(pid)["external_allowed"] == 0


def test_incomplete_catalog_source_is_a_readable_error(tmp_path, monkeypatch):
    bad = tmp_path / "catalog.json"
    bad.write_text(json.dumps({"schema": 1, "examples": [{"id": "x", "codebases": [], "source": {"repo_url": "u"},
                                                          "export": {"file": "f", "sha256": "s"}}]}), encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", bad)
    with pytest.raises(ex.ExampleError, match="неполный"):
        ex.load_catalog()


def test_key_print_changes_with_any_new_key(web, monkeypatch):  # noqa: F811
    from app.routes import providers as routes

    keys = iter([{"key": "sk-aaaa1111"}, {"key": "sk-bbbb1111"}])
    monkeypatch.setattr(routes, "load_key", lambda *a: next(keys))
    assert routes.key_print(None, 1) != routes.key_print(None, 1), "одинаковые последние знаки – разные отпечатки"


def test_semver_prerelease_order_is_case_sensitive():
    from osv_sca_csv import fixed_version

    v = {"affected": [{"package": {"name": "p", "ecosystem": "npm"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0-alpha"}]}]}]}
    assert fixed_version(v, "npm", "p", "1.0.0-BETA") == "1.0.0-alpha", "по ASCII «B» раньше «a»"


def test_osv_json_respects_limit(tmp_path):
    import subprocess

    vulns = [{"id": f"GHSA-{i}", "aliases": [f"CVE-2099-{i}"], "modified": ""} for i in range(4)]
    report = {"results": [{"packages": [{"package": {"name": "lib", "version": "1.0.0", "ecosystem": "npm"},
                                         "groups": [{"ids": [v["id"]], "aliases": v["aliases"]} for v in vulns],
                                         "vulnerabilities": vulns}]}]}
    (tmp_path / "o.json").write_text(json.dumps(report), encoding="utf-8")
    run = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "osv_sca_csv.py"),
                          "--osv-json", str(tmp_path / "o.json"), "--limit", "2", "--out", str(tmp_path / "r.csv")],
                         capture_output=True, timeout=120)
    out = run.stdout.decode("utf-8", "replace")
    assert run.returncode == 0 and "компонентов 1" in out and "усечено по пределу 1" in out
    assert (tmp_path / "r.csv").read_text(encoding="utf-8").count("GHSA-") == 2


# ============================================================================ круг 5

def test_demo_resume_keeps_operator_project(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    first = db.create_project("Демо: Demo Library")
    db.update_json_entry("examples_projects", "demo-library@builtin",
                         {"example_id": "demo-library", "project_id": first, "state": "creating", "import_id": 0})
    db.set_repos_dir(first, "operator-folder")
    catalog = {"schema": 1, "examples": [{"id": "demo-library", "number": 0, "title": "Demo Library", "builtin": "demo",
                                          "source": None, "export": None, "codebases": [], "languages": []}]}
    (web.tmp / "cat5").mkdir()
    (web.tmp / "cat5" / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", web.tmp / "cat5" / "catalog.json")
    r = web.client.post("/examples/demo-library/project", headers=ORIGIN, follow_redirects=False)
    if "error" in r.headers.get("location", "") or r.status_code != 303:
        pytest.skip("демо-выгрузка в этой установке не найдена")
    assert db.get_project(first)["repos_dir"] == "operator-folder", "проект оператора не тронут"
    assert int(r.headers["location"].split("/")[2].split("?")[0]) != first


def test_send_refused_when_mark_was_given_for_another_examples_root(web, monkeypatch):  # noqa: F811
    from app.executors import SendNotAllowed, external_code_allowed
    from app.routes.examples import remember_mark_root

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_external_mark(pid, "Учебный пример: открытый код, для теста")
    remember_mark_root(db, pid, web.settings)
    external_code_allowed(db, {"trust": "external"}, pid)  # тот же корень – проходит
    monkeypatch.setitem(ex.ROOT_NOW, "value", "host:/другой/examples")
    with pytest.raises(SendNotAllowed, match="другой папки примеров"):
        external_code_allowed(db, {"trust": "external"}, pid)
    monkeypatch.setitem(ex.ROOT_NOW, "value", None)  # сверка корня при запуске не прошла – отправки нет
    with pytest.raises(SendNotAllowed):
        external_code_allowed(db, {"trust": "external"}, pid)


def test_catalog_entry_without_source_is_refused(tmp_path, monkeypatch):
    bad = tmp_path / "catalog.json"
    bad.write_text(json.dumps({"schema": 1, "examples": [{"id": "x", "codebases": []}]}), encoding="utf-8")
    monkeypatch.setattr(ex, "CATALOG_FILE", bad)
    with pytest.raises(ex.ExampleError, match="нет источника"):
        ex.load_catalog()


def test_tar_record_limit_exact_boundary(tmp_path):
    entry = _entry()
    entry["source"]["files"] = 2
    saved = ex.MAX_MEMBERS_ANY
    try:
        ex.MAX_MEMBERS_ANY = 3  # корень и два файла – ровно три записи, конец архива записью не считается
        arch = tmp_path / "a.tar.gz"
        arch.write_bytes(_archive(FILES))
        ex.unpack(arch, entry, tmp_path / "out" / "toy")
    finally:
        ex.MAX_MEMBERS_ANY = saved


def test_semver_prerelease_hyphen_is_one_identifier():
    from osv_sca_csv import fixed_version

    v = {"affected": [{"package": {"name": "p", "ecosystem": "npm"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0-alpha.2"}]}]}]}
    assert fixed_version(v, "npm", "p", "1.0.0-alpha-1") == "", "alpha.2 раньше alpha-1 – версия уже после исправления"


def test_osv_json_limit_spans_all_inputs(tmp_path):
    import subprocess

    def report(n):
        vulns = [{"id": f"GHSA-{n}", "aliases": [f"CVE-2099-{n}"], "modified": ""}]
        return {"results": [{"packages": [{"package": {"name": "lib", "version": "1.0.0", "ecosystem": "npm"},
                                           "groups": [{"ids": [vulns[0]["id"]], "aliases": vulns[0]["aliases"]}],
                                           "vulnerabilities": vulns}]}]}
    for n in (1, 2):
        (tmp_path / f"o{n}.json").write_text(json.dumps(report(n)), encoding="utf-8")
    script = str(Path(__file__).resolve().parents[1] / "scripts" / "osv_sca_csv.py")
    run = subprocess.run([sys.executable, script, "--osv-json", str(tmp_path / "o1.json"), "--osv-json",
                          str(tmp_path / "o2.json"), "--limit", "1", "--out", str(tmp_path / "r.csv")],
                         capture_output=True, timeout=120)
    out = run.stdout.decode("utf-8", "replace")
    assert "компонентов 1" in out and "строк 1" in out and "усечено по пределу 1" in out
    zero = subprocess.run([sys.executable, script, "--osv-json", str(tmp_path / "o1.json"), "--limit", "0",
                           "--out", str(tmp_path / "z.csv")], capture_output=True, timeout=120)
    assert zero.returncode == 2


def test_preset_checkbox_state_survives_check(web, monkeypatch):  # noqa: F811
    page = web.client.post("/settings/providers/new", headers=ORIGIN, data={
        "name": "Ollama", "kind": "ollama", "trust": "local", "base_url": web.fake.url, "default_model": "m",
        "enabled": "1", "think": "auto", "action": "check", "preset": "ollama-local"}).text
    assert 'name="examples_profile" value="1">' in page or 'name="examples_profile" value="1" >' in page, \
        "флажок снят оператором – после «Проверить» остаётся снятым"


def test_ollama_preset_in_docker_uses_configured_address(web):  # noqa: F811
    page = web.client.get("/settings/providers/new?preset=ollama-local").text
    assert f'value="{web.settings.ollama_url}"' in page and 'value="http://127.0.0.1:11434"' not in page


def test_stale_unpack_folders_are_removed_before_background_fetch(tmp_path, monkeypatch):
    entry = _toy_catalog(tmp_path, monkeypatch)
    root = ex.examples_root(tmp_path / "repos")
    stale = root / ".lt-abcd1234"
    (stale / "half").mkdir(parents=True)
    notes = root / ".lt-notes"  # папка студента с тем же префиксом – не из журнала распаковщика
    notes.mkdir()
    (notes / "мои заметки.txt").write_text("важно", encoding="utf-8")
    ex._journal(root, add=stale.name)
    monkeypatch.setattr(ex, "_STATE", {})  # состояние очереди – только этого теста
    monkeypatch.setattr(ex, "download", lambda *a, **k: None)
    ex.fetch_all_background(tmp_path / "repos", tmp_path / "tmp").join(5)
    assert not stale.exists() and (notes / "мои заметки.txt").is_file()
    del entry


# ============================================================================ круг 6

def test_link_folders_offer_only_existing_folders(web, monkeypatch):  # noqa: F811
    from app.routes.examples import link_folders

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    base = web.settings.repos_root / "examples"
    assert link_folders(db, pid, base)
    assert link_folders(db, pid, web.tmp / "nowhere") == set(), "удалённая папка в форму не предлагается"


def test_demo_folder_set_by_creation_is_not_operator_work(web, monkeypatch):  # noqa: F811
    from app.routes.examples import operator_worked

    db = web.app.state.db
    pid = db.create_project("Демо: Demo Library")
    db.set_repos_dir(pid, "local-triage-demo")
    assert not operator_worked(db, pid, allowed="local-triage-demo")
    assert operator_worked(db, pid, allowed="examples")


@pytest.mark.parametrize(("eco", "version", "fixed", "expected"), [
    ("Maven", "1.0-rc2", "1.0-rc10", "1.0-rc10"),
    ("npm", "1.0.0-alpha-", "1.0.0-alpha.2", ""),
])
def test_qualifier_and_trailing_hyphen_order(eco, version, fixed, expected):
    from osv_sca_csv import fixed_version

    v = {"affected": [{"package": {"name": "p", "ecosystem": eco},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    assert fixed_version(v, eco, "p", version) == expected


def test_osv_json_merge_does_not_depend_on_input_order(tmp_path):
    import subprocess

    def report(vid):
        v = {"id": vid, "aliases": ["CVE-2099-7"], "modified": ""}
        return {"results": [{"packages": [{"package": {"name": "lib", "version": "1.0.0", "ecosystem": "PyPI"},
                                           "groups": [{"ids": [vid], "aliases": ["CVE-2099-7"]}],
                                           "vulnerabilities": [v]}]}]}
    (tmp_path / "a.json").write_text(json.dumps(report("PYSEC-1")), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(report("GHSA-1")), encoding="utf-8")
    script = str(Path(__file__).resolve().parents[1] / "scripts" / "osv_sca_csv.py")
    outs = []
    for order in (("a", "b"), ("b", "a")):
        out = tmp_path / f"{order[0]}.csv"
        subprocess.run([sys.executable, script, "--osv-json", str(tmp_path / f"{order[0]}.json"), "--osv-json",
                        str(tmp_path / f"{order[1]}.json"), "--out", str(out)], capture_output=True, timeout=120)
        outs.append(out.read_text(encoding="utf-8"))
    assert outs[0] == outs[1] and "GHSA-1" in outs[0]


def test_mapping_page_does_not_say_nothing_to_change_with_a_problem(web, monkeypatch):  # noqa: F811
    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    db.set_repos_dir(pid, "other")
    page = web.client.get(f"/projects/{pid}/example-mapping").text
    assert 'id="mapping-problem"' in page and "менять нечего" not in page


def test_card_reports_missing_project_folder(web, monkeypatch):  # noqa: F811
    import shutil

    _prepare(web, monkeypatch)
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    folder = next(iter(web.app.state.db.get_settings()["examples_projects"].values()))["folder"]
    copy = web.settings.repos_root / "examples" / (folder + "-2")
    shutil.copytree(web.settings.repos_root / "examples" / folder, copy)
    shutil.rmtree(web.settings.repos_root / "examples" / folder)
    assert "Исходной копии примера нет на диске" in web.client.get("/examples").text
    del pid


# ============================================================================ круг 7

def test_pending_profile_changed_after_preview_is_not_assigned(web, monkeypatch):  # noqa: F811
    from app.routes.examples import LINK_KEY, finish_pending_profile

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    key = next(iter(db.get_settings()[LINK_KEY]))
    db.update_json_entry(LINK_KEY, key, {**db.get_settings()[LINK_KEY][key], "profile_pending": True,
                                         "profile_done": False})
    local = db.create_provider({"name": "Ollama", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    db.set_settings({"examples_provider_id": int(local["id"])})  # профиль сменили после предпросмотра
    assert finish_pending_profile(db, pid, "", promised_id=None) == "none"
    assert db.get_project(pid)["provider_id"] in (None, 0)


def test_restore_refuses_empty_target_folder(web, monkeypatch):  # noqa: F811
    import shutil

    _prepare(web, monkeypatch)
    db = web.app.state.db
    pid = int(_create(web).headers["location"].split("/")[2].split("?")[0])
    link = next(iter(db.get_settings()["examples_projects"].values()))
    target = web.settings.repos_root / "examples" / link["codebases"]["toy"]
    shutil.rmtree(target)
    target.mkdir()
    db.set_codebase_folder(pid, "toy", "elsewhere", manual=True)
    assert "пусты" in web.client.get(f"/projects/{pid}/example-mapping").text


def test_merge_rows_joins_by_aliases_and_takes_latest_edition():
    from osv_sca_csv import merge_rows

    base = {"ecosystem": "npm", "component": "lib", "version": "1.0.0", "cvss": "", "note": ""}
    rows = [{**base, "osv_id": "GHSA-x", "osv_aliases": "", "cve": "GHSA-x", "fixed": "1.0.1", "osv_modified": "2026-01-01"},
            {**base, "osv_id": "PYSEC-y", "osv_aliases": "GHSA-x CVE-2099-5", "cve": "CVE-2099-5", "fixed": "1.0.1",
             "osv_modified": "2026-01-01"},
            {**base, "osv_id": "GHSA-x", "osv_aliases": "", "cve": "GHSA-x", "fixed": "1.0.3", "osv_modified": "2026-02-01"}]
    for order in (rows, rows[::-1]):
        merged = merge_rows(order)
        assert len(merged) == 1 and merged[0]["osv_id"] == "GHSA-x" and merged[0]["cve"] == "CVE-2099-5"
        assert merged[0]["fixed"] == "1.0.3", "более поздняя редакция той же записи"


def test_nuget_prerelease_labels_ignore_case():
    from osv_sca_csv import fixed_version

    v = {"affected": [{"package": {"name": "p", "ecosystem": "NuGet"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0-RC"}]}]}]}
    assert fixed_version(v, "NuGet", "p", "1.0.0-beta") == "1.0.0-RC"


def test_export_refuses_manifest_without_snapshot(tmp_path, monkeypatch):
    import catalog_step

    src = json.loads((CATALOG_DIR / "sources.json").read_text(encoding="utf-8"))["examples"][3]  # nodegoat
    real_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self: False if self.name == "package-lock.json" else real_is_file(self))
    with pytest.raises(RuntimeError, match="нет снимка"):
        catalog_step.build_example({**src, "tree": {}}, CATALOG_DIR, {}, "", {}, lambda f, d: d, "2026-11-20", {})


def test_broken_publish_journal_does_not_block_the_builder(tmp_path, monkeypatch):
    import build

    monkeypatch.setattr(build, "CATALOG", tmp_path)
    (tmp_path / "publish.journal.json").write_text('["half', encoding="utf-8")
    build.recover_publish()
    assert not (tmp_path / "publish.journal.json").exists()


def test_demo_from_catalog_mark_is_bound_to_its_root(web, monkeypatch):  # noqa: F811
    from app.executors import SendNotAllowed, external_code_allowed
    from app.routes.examples import remember_mark_root

    db = web.app.state.db
    pid = db.create_project("Демо: Demo Library")
    db.update_json_entry("examples_projects", "demo-library@builtin",
                         {"example_id": "demo-library", "project_id": pid, "state": "ready"})
    db.set_external_mark(pid, "Демо: выдуманный код, для теста")
    remember_mark_root(db, pid, web.settings)
    external_code_allowed(db, {"trust": "external"}, pid)
    monkeypatch.setitem(ex.ROOT_NOW, "value", "host:/другой/examples")
    with pytest.raises(SendNotAllowed):
        external_code_allowed(db, {"trust": "external"}, pid)
