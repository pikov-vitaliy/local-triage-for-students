"""Проекты: список с ходом разбора и «Продолжить», архив и удаление с подтверждением, параметры проекта (название,
модель), обзор папок внутри корня и выбор папки проекта, повторная загрузка выгрузки (решения и отметки
сохраняются, пропавшие находки помечаются), демо-проект, одна загрузка выгрузки за раз, ограничение просмотра
папок; создание .env сценарием start.ps1."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db as db_module
from app import metrics
from app.config import Settings
from app.main import create_app
from app.routes import projects
from app.routes.projects import (_rel_inside, check_project_folder, find_demo, list_codebase_dirs, resolve_folder,
                                 unique_name)
from fake_ollama import FakeOllama
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_web import BASE, ORIGIN, create_project, prepared, upload, web, write_repos  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
AS_HTML = {**ORIGIN, "Accept": "text/html"}


def hub_id_of(web, pid: int, hub_id: str) -> int:
    return web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]


def post(web, url: str, data: dict | None = None):
    return web.client.post(url, data=data or {}, headers=AS_HTML, follow_redirects=False)


# ============================================================================ список проектов

def test_projects_list_shows_progress_activity_and_continue(web):
    pid = prepared(web)
    db = web.app.state.db
    db.set_reviewed(pid, "510001", True)
    db.set_reviewed(pid, "73001", True)
    db.mark_entered(pid, "510001")
    empty = create_project(web.client, "Пустой проект")
    page = web.client.get("/").text
    row = page[page.index(f'href="/projects/{pid}"'):]
    row = row[:row.index("</li>")]
    assert "Проверено <strong>2</strong> из 7" in row  # SAST 4 и SCA 3
    assert "Внесено в Hub <strong>1</strong>" in row and "SAST 1 из 4 · SCA 1 из 3" in row
    assert f'href="/projects/{pid}/continue"' in row and "Продолжить</a>" in row
    assert re.search(r'<time datetime="\d{4}-\d\d-\d\dT[^"]+" data-relative>', row)
    empty_row = page[page.index(f'href="/projects/{empty}"'):]
    assert "Выгрузка не загружена" in empty_row[:empty_row.index("</li>")]
    assert 'action="/projects/demo"' in page and "Создать демо-проект" in page
    assert 'href="/settings"' in page
    assert 'Действующие <span class="tab-count">2</span>' in page and 'Архив <span class="tab-count">0</span>' in page


def test_list_is_sorted_by_last_activity(web, monkeypatch):
    clock = iter(f"2026-10-15T08:{minute:02d}:00+00:00" for minute in range(60))
    monkeypatch.setattr(db_module, "now_iso", lambda: next(clock))  # время в базе – с точностью до секунды
    first = create_project(web.client, "Первый")
    second = create_project(web.client, "Второй")
    page = web.client.get("/").text
    assert page.index(f'href="/projects/{second}"') < page.index(f'href="/projects/{first}"')
    r = post(web, f"/projects/{first}/params", {"name": "Первый", "model": ""})
    assert r.status_code == 303
    page = web.client.get("/").text
    assert page.index(f'href="/projects/{first}"') < page.index(f'href="/projects/{second}"')


def test_empty_list_explains_first_steps(web):
    page = web.client.get("/").text
    assert 'class="empty-state"' in page and "Проектов пока нет" in page
    assert page.count('id="create-demo"') == 1 and 'href="#new-project"' in page and 'id="new-project"' in page


def test_archive_and_restore(web):
    pid = create_project(web.client, "Старый")
    r = post(web, f"/projects/{pid}/archive", {"action": "archive"})
    assert r.status_code == 303 and r.headers["location"] == "/?ok=project_archived"
    page = web.client.get("/?ok=project_archived").text
    assert "Проект убран в архив" in page and f'href="/projects/{pid}"' not in page
    assert 'Архив <span class="tab-count">1</span>' in page and "В архиве пусто" not in page
    archive = web.client.get("/projects/archive")
    assert archive.status_code == 200 and f'href="/projects/{pid}"' in archive.text and "Вернуть" in archive.text
    assert "в архиве с" in archive.text
    assert "Проект в архиве" in web.client.get(f"/projects/{pid}").text
    r = post(web, f"/projects/{pid}/archive", {"action": "restore"})
    assert r.status_code == 303 and r.headers["location"] == "/?ok=project_restored"
    assert f'href="/projects/{pid}"' in web.client.get("/").text
    assert web.app.state.db.get_project(pid)["archived"] == 0
    assert post(web, "/projects/424242/archive", {"action": "archive"}).status_code == 404


def test_delete_needs_confirmation_and_removes_project(web):
    pid = prepared(web)
    db = web.app.state.db
    db.set_reviewed(pid, "510001", True)
    db.mark_entered(pid, "510001")
    page = web.client.get(f"/projects/{pid}/delete")
    assert page.status_code == 200
    assert "Удалить проект «Demo Library»?" in page.text and "находки из загруженных выгрузок – 7" in page.text
    assert "отмечено «Внесено в Hub» – 1" in page.text and "Убрать в архив" in page.text
    r = post(web, f"/projects/{pid}/delete")
    assert r.status_code == 400 and db.get_project(pid) is not None  # без подтверждения не удаляется
    r = post(web, f"/projects/{pid}/delete", {"confirm": "yes"})
    assert r.status_code == 303 and r.headers["location"] == "/?ok=project_deleted"
    assert db.get_project(pid) is None and db.get_review(pid, "510001") is None
    assert "Проект удалён." in web.client.get(r.headers["location"]).text
    assert web.client.get(f"/projects/{pid}/delete").status_code == 404


def test_delete_is_refused_while_run_is_running(web):
    web.app.state.runner.shutdown()  # прогон не должен начаться на самом деле
    pid = prepared(web)
    db = web.app.state.db
    run_id = db.create_run(pid, "qwen2.5-coder:14b", "all", "sast-v2", ["510001"])
    db.set_run_state(run_id, "running")
    page = web.client.get(f"/projects/{pid}/delete").text
    assert "У проекта идёт прогон" in page
    assert '<button type="submit" class="btn btn-danger" disabled>' in page
    r = post(web, f"/projects/{pid}/delete", {"confirm": "yes"})
    assert r.status_code == 409 and "остановите его" in r.text and db.get_project(pid) is not None


# ============================================================================ «Продолжить» и параметры

def test_continue_walks_sast_then_sca_then_project(web):
    pid = create_project(web.client)
    r = web.client.get(f"/projects/{pid}/continue", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}#step1"
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    db = web.app.state.db
    r = web.client.get(f"/projects/{pid}/continue", follow_redirects=False)
    assert r.headers["location"] == f"/projects/{pid}/findings/{hub_id_of(web, pid, '510004')}"  # критическая
    for row in SAST_ROWS:
        db.set_reviewed(pid, row["Issue id"], True)
    r = web.client.get(f"/projects/{pid}/continue", follow_redirects=False)
    assert r.headers["location"] == f"/projects/{pid}/sca/findings/{hub_id_of(web, pid, '73001')}"  # срочная SCA
    for hub_id in ("73001", "73002", "73003"):
        db.set_reviewed(pid, hub_id, True)
    r = web.client.get(f"/projects/{pid}/continue", follow_redirects=False)
    assert r.headers["location"] == f"/projects/{pid}?ok=project_all_reviewed"
    assert "Непроверенных находок SAST и SCA в проекте нет" in web.client.get(r.headers["location"]).text
    assert web.client.get("/projects/424242/continue", follow_redirects=False).status_code == 404


def test_project_model_comes_from_the_chosen_profile(web):
    """Проверка стенда 22.11: у проекта без своей модели шапка, «Модель проекта», список проектов и список находок
    показывают модель профиля, которым пойдёт разбор, а не модель из «Настроек»."""
    pid = prepared(web)
    db = web.app.state.db
    prof = db.create_provider({"name": "Профиль QA", "kind": "ollama", "base_url": web.fake.url, "trust": "local",
                               "default_model": "qwen2.5-coder:14b", "enabled": 1})
    db.update_project(pid, provider_id=prof["id"])
    page = web.client.get(f"/projects/{pid}").text.replace("</span>", "")
    assert "qwen2.5-coder:14b – из профиля «Профиль QA»" in page and "Как в профиле: qwen2.5-coder:14b" in page
    assert "из профиля «Профиль QA»" in web.client.get("/").text
    found = web.client.get(f"/projects/{pid}/findings").text
    assert re.search(r'<option value="qwen2.5-coder:14b"[^>]*selected', found), "по умолчанию – модель профиля"
    counts = db.count_findings(pid)
    assert "sca_license" in counts


def test_project_params_name_and_model(web):
    pid = prepared(web)
    db = web.app.state.db
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="params"' in page and "Как в настройках: gpt-oss:20b" in page
    r = post(web, f"/projects/{pid}/params", {"name": "  Demo   Library  2 ", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}?ok=project_saved"
    project = db.get_project(pid)
    assert project["name"] == "Demo Library 2" and project["model"] == "qwen2.5-coder:14b"
    page = web.client.get(r.headers["location"]).text
    assert "Параметры проекта сохранены." in page
    assert re.search(r'<select name="model" id="project-model">\s*<option value="">[^<]*</option>\s*(?:<option value="[^"]*">[^<]*</option>\s*)*<option value="qwen2.5-coder:14b" selected>',
                     page)
    # модель проекта – выбрана и в запуске триажа
    assert re.search(r'<option value="qwen2.5-coder:14b" data-info="[^"]*" selected>', page)
    r = post(web, f"/projects/{pid}/params", {"name": "Demo", "model": "старая-модель:7b"})
    assert r.status_code == 303
    assert "старая-модель:7b – нет на сервере профиля" in web.client.get(f"/projects/{pid}").text
    assert post(web, f"/projects/{pid}/params", {"name": "   ", "model": ""}).status_code == 400
    r = post(web, f"/projects/{pid}/params", {"name": "Demo", "model": "bad\x01name"})
    assert r.status_code == 400 and "неверное имя модели" in r.text
    r = post(web, f"/projects/{pid}/params", {"name": "Demo", "model": ""})
    assert r.status_code == 303 and db.get_project(pid)["model"] == ""


def test_project_header_counts_review_and_hub_marks(web):
    pid = prepared(web)
    db = web.app.state.db
    for hub_id in ("510001", "510002", "73002"):
        db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="Проверено.",
                       reviewed=True)
    db.mark_entered(pid, "510001")
    page = web.client.get(f"/projects/{pid}").text
    assert '<span class="stat-label">Проверено SAST</span><span class="stat-value">2 из 4</span>' in page
    assert '<span class="stat-label">Проверено SCA</span><span class="stat-value">1 из 3</span>' in page
    assert '<span class="stat-label">Внесено в Hub</span><span class="stat-value">1</span>' in page
    assert "из 3 проверенных" in page and "Проверено <strong>3</strong> из 7" in page
    assert f'href="/projects/{pid}/continue"' in page and "Продолжить разбор</a>" in page
    # вкладки проекта: обзор, находки, SCA
    assert f'href="/projects/{pid}" aria-current="page">Обзор</a>' in page
    assert f'href="/projects/{pid}/findings">Находки <span class="tab-count">7</span>' in page
    assert f'href="/projects/{pid}/sca">SCA <span class="tab-count">3</span>' in page


# ============================================================================ обзор папок и выбор папки

def add_folders(root: Path) -> None:
    """Кроме папки team: группа с вложенной папкой, клон git прямо в корне и служебные папки Windows."""
    (root / "group" / "sub").mkdir(parents=True)
    (root / "clone-at-root" / ".git").mkdir(parents=True)
    for name in ("$RECYCLE.BIN", "System Volume Information"):
        (root / name).mkdir()
    if os.name == "nt":  # скрытая папка Windows
        (root / "win-hidden").mkdir()
        subprocess.run(["attrib", "+h", str(root / "win-hidden")], check=True, capture_output=True)


def test_folder_browser_lists_plain_folders_and_marks_clones(web):
    add_folders(web.tmp / "repos")
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    page = web.client.get(f"/projects/{pid}/folders").text
    names = re.findall(r'class="folder-name">([^<]+)</span>', page)
    assert names == ["clone-at-root", "group", "team"]  # без скрытых, по имени
    assert ".hidden" not in page
    assert "клон git" in page and 'name="repos_dir" value=""' in page and "Выбрать эту папку" in page
    assert "Найдено здесь по именам: 2 из 2 кодовых баз выгрузки" in page
    team = web.client.get(f"/projects/{pid}/folders?path=team").text
    assert team.count("кодовая база из выгрузки") == 2 and team.count("исходники") == 2
    assert 'name="repos_dir" value="team"' in team and "на уровень выше</span>" in team
    assert f'<a href="/projects/{pid}/folders?path=">' in team  # хлебные крошки: к корню
    clone = web.client.get(f"/projects/{pid}/folders?path=team/billing-core").text
    assert "Это клон одной кодовой базы" in clone and 'name="repos_dir"' not in clone
    assert 'folders?path=team">на уровень выше</a>' in clone


@pytest.mark.parametrize("bad", ["..", "../x", "/etc", "C:/Windows", ".hidden", "team/../..", "no-such-folder"])
def test_folder_browser_shows_root_for_bad_path(web, bad):
    pid = create_project(web.client)
    r = web.client.get(f"/projects/{pid}/folders", params={"path": bad})
    assert r.status_code == 200 and "flash-err" in r.text
    assert 'name="repos_dir" value=""' in r.text  # показан корень


def test_choosing_folders_inside_root(web):
    add_folders(web.tmp / "repos")
    pid = create_project(web.client)
    db = web.app.state.db
    for raw, stored in (("group/sub", "group/sub"), ("./team/", "team"), ("team\\", "team"), ("", "")):
        r = post(web, f"/projects/{pid}/repos", {"repos_dir": raw})
        assert r.status_code == 303, raw
        assert db.get_project(pid)["repos_dir"] == stored
    for bad, text in (("team/billing-core", "Это папка одного клона"), ("clone-at-root", "Это папка одного клона"),
                      ("Team", "Такой папки нет"), ("no-such-folder", "Такой папки нет"),
                      ("group/.git", "Скрытые папки"), ("x" * 1200, "Слишком длинный")):
        r = post(web, f"/projects/{pid}/repos", {"repos_dir": bad})
        assert r.status_code == 400 and text in r.text, bad
    assert db.get_project(pid)["repos_dir"] == ""


def make_dir_link(link: Path, target: Path) -> bool:
    """Ссылка на папку: символическая или точка соединения Windows. False – создать нельзя (нет прав)."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return True
    except (ImportError, OSError, AttributeError):
        return False


def test_links_are_not_listed_or_chosen(web):
    root = web.tmp / "repos"
    if not make_dir_link(root / "alias", root / "team"):
        pytest.skip("ссылку на папку здесь создать нельзя")
    pid = create_project(web.client)
    page = web.client.get(f"/projects/{pid}/folders").text
    assert "alias" not in page
    r = post(web, f"/projects/{pid}/repos", {"repos_dir": "alias"})
    assert r.status_code == 400 and web.app.state.db.get_project(pid)["repos_dir"] == ""
    assert resolve_folder(web.settings, "alias")[0] is None


def test_resolve_and_check_project_folder(tmp_path: Path):
    write_repos(tmp_path)
    settings = Settings(repos_root=tmp_path)
    assert resolve_folder(settings, "team/billing-core")[0] == "team/billing-core"
    assert check_project_folder(settings, "team") == ("team", "")
    assert check_project_folder(settings, "team/billing-core")[0] is None
    assert check_project_folder(settings, "")[0] == ""
    missing = Settings(repos_root=tmp_path / "missing", repos_root_host="D:")
    rel, path, error = resolve_folder(missing, "team")
    assert rel is None and "не подключена" in error and "D:/" in error


def test_project_page_without_folder_points_to_browser(web):
    shutil.rmtree(web.tmp / "repos" / "team")  # в корне клонов нет
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    page = web.client.get(f"/projects/{pid}").text
    assert f'<a class="btn btn-primary" href="/projects/{pid}/folders?path=">' in page and "Выбрать папку…" in page
    assert "Клонировать только эти" in page


# ============================================================================ повторная загрузка

def test_reimport_keeps_marks_and_flags_missing(web):
    pid = prepared(web)
    db = web.app.state.db
    db.set_reviewed(pid, "510001", True)
    db.mark_entered(pid, "510001")
    db.set_reviewed(pid, "510004", True)
    smaller = make_hub_xlsx(web.tmp / "smaller.xlsx", sast=[row for row in SAST_ROWS if row["Issue id"] != "510004"])
    assert upload(web.client, pid, smaller).status_code == 303
    review = db.get_review(pid, "510001")
    assert review["reviewed"] == 1 and review["entered_hub"] == 1
    page = web.client.get(f"/projects/{pid}").text
    assert "исчезло 1" in page and "Решения и отметки по совпадающим ID находок сохранены" in page
    assert "Нет в новой выгрузке – 1" in page and f'href="/projects/{pid}/findings?missing=yes"' in page
    assert '<span class="stat-label">Нет в новой выгрузке</span><span class="stat-value">1</span>' in page
    assert "Находки проекта заменятся" not in page and "останутся в проекте с пометкой" in page
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "full.xlsx")).status_code == 303
    page = web.client.get(f"/projects/{pid}").text
    assert "вернулось 1" in page and "Нет в новой выгрузке – " not in page
    assert db.get_review(pid, "510004")["reviewed"] == 1  # вернулась той же – отметка осталась


def test_one_import_at_a_time(web):
    pid = create_project(web.client)
    assert projects._IMPORT_SLOT.acquire(blocking=False)
    try:
        r = upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx"))
        assert r.status_code == 409 and "загружается другая выгрузка" in r.text
        r = post(web, "/projects/demo")
        assert r.status_code == 409 and "загружается другая выгрузка" in r.text
    finally:
        projects._IMPORT_SLOT.release()
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    assert list(web.settings.tmp_dir.iterdir()) == []


def test_codebase_scan_is_bounded(tmp_path: Path, monkeypatch):
    write_repos(tmp_path)
    (tmp_path / "other").mkdir()
    assert list_codebase_dirs(tmp_path) == ["other", "team", "team/billing-core", "team/Catalog_API"]
    monkeypatch.setattr(projects, "MAX_CHECKS", 2)
    assert list_codebase_dirs(tmp_path) == ["other", "team"]  # без проверки вложенных папок


# ============================================================================ демо-проект

def make_demo(app_dir: Path) -> Path:
    """Папка приложения с демо: examples/demo/demo-hub-report.xlsx и клоны billing-core, catalog-api."""
    demo = app_dir / "examples" / "demo"
    write_repos(demo / "tmp-repos")
    (demo / "repos").mkdir(parents=True)
    (demo / "tmp-repos" / "team" / "billing-core").rename(demo / "repos" / "billing-core")
    (demo / "tmp-repos" / "team" / "Catalog_API").rename(demo / "repos" / "catalog-api")
    shutil.rmtree(demo / "tmp-repos")
    make_hub_xlsx(demo / "demo-hub-report.xlsx")
    return demo


@contextmanager
def app_with_root(tmp_path: Path, repos_root: Path):
    fake = FakeOllama()
    settings = Settings(data_dir=tmp_path / "data", repos_root=repos_root, ollama_url=fake.url)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            yield client
    finally:
        fake.close()


def create_demo(client: TestClient):
    return client.post("/projects/demo", headers=AS_HTML, follow_redirects=False)


@pytest.mark.parametrize(("layout", "expected"), [
    ("demo-repos", ""),  # корень – сами демо-репозитории (REPOS_ROOT=examples/demo/repos)
    ("demo", "repos"),  # корень – examples/demo
    ("app", "examples/demo/repos"),  # корень – папка приложения
    ("disk", "work/app/examples/demo/repos"),  # корень – диск, приложение – в его папке
])
def test_demo_project_finds_demo_inside_root(tmp_path: Path, monkeypatch, layout, expected):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    app_dir = tmp_path / "disk" / "work" / "app"
    demo = make_demo(app_dir)
    roots = {"demo-repos": demo / "repos", "demo": demo, "app": app_dir, "disk": tmp_path / "disk"}
    # при корне-диске приложение запущено из образа: рядом с ним демо нет, оно находится в корне
    monkeypatch.setattr(projects, "APP_ROOT", tmp_path / "image" if layout == "disk" else app_dir)
    with app_with_root(tmp_path, roots[layout]) as client:
        r = create_demo(client)
        assert r.status_code == 303 and r.headers["location"].endswith("?ok=project_demo")
        pid = int(r.headers["location"].split("/")[2].split("?")[0])
        db = client.app.state.db
        project = db.get_project(pid)
        assert project["name"] == "Демо: Demo Library" and project["repos_dir"] == expected
        assert db.count_findings(pid)["total"] == 7
        cmap = db.get_codebase_map(pid)
        assert cmap["billing-core"]["folder"] == "billing-core" and cmap["catalog-api"]["folder"] == "catalog-api"
        page = client.get(r.headers["location"]).text
        assert "Демо-проект создан" in page and "Клонировать только эти" not in page
        r = create_demo(client)
        assert db.get_project(int(r.headers["location"].split("/")[2].split("?")[0]))["name"] == \
            "Демо: Demo Library (2)"


def test_demo_outside_root_creates_project_without_code(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    app_dir = tmp_path / "app"
    make_demo(app_dir)
    monkeypatch.setattr(projects, "APP_ROOT", app_dir)
    write_repos(tmp_path / "repos")
    with app_with_root(tmp_path, tmp_path / "repos") as client:
        r = create_demo(client)
        assert r.status_code == 303 and r.headers["location"].endswith("?ok=project_demo_nocode")
        pid = int(r.headers["location"].split("/")[2].split("?")[0])
        assert client.app.state.db.count_findings(pid)["total"] == 7
        assert "демо-репозитории лежат вне корня" in client.get(r.headers["location"]).text


def test_demo_without_report_is_explained(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    monkeypatch.setattr(projects, "APP_ROOT", tmp_path / "image")
    write_repos(tmp_path / "repos")
    with app_with_root(tmp_path, tmp_path / "repos") as client:
        r = create_demo(client)
        assert r.status_code == 404 and "Демо-выгрузка examples/demo/demo-hub-report.xlsx" in r.text
        assert client.app.state.db.list_projects(archived=None) == []


def test_find_demo_with_repos_root_as_demo_repos_in_container(tmp_path: Path, monkeypatch):
    """В контейнере корень – сами демо-репозитории, а выгрузка лежит в образе рядом с приложением."""
    image = tmp_path / "image"
    demo = make_demo(tmp_path / "host")
    (demo / "demo-hub-report.xlsx").unlink()  # выгрузки рядом с репозиториями в контейнере не видно
    image_demo = image / "examples" / "demo"
    image_demo.mkdir(parents=True)
    make_hub_xlsx(image_demo / "demo-hub-report.xlsx")
    monkeypatch.setattr(projects, "APP_ROOT", image)
    found = find_demo(Settings(repos_root=demo / "repos"))
    assert found == {"report": image_demo / "demo-hub-report.xlsx", "repos_dir": ""}


def test_real_demo_data_creates_working_project(tmp_path: Path, monkeypatch):
    report = ROOT / "examples" / "demo" / "demo-hub-report.xlsx"
    if not report.is_file():
        pytest.skip("демо-выгрузки нет: scripts/make_demo_xlsx.py")
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    with app_with_root(tmp_path, ROOT / "examples" / "demo" / "repos") as client:
        r = create_demo(client)
        assert r.status_code == 303 and r.headers["location"].endswith("?ok=project_demo")
        pid = int(r.headers["location"].split("/")[2].split("?")[0])
        db = client.app.state.db
        assert db.get_project(pid)["repos_dir"] == "" and db.count_findings(pid)["sast"] > 0
        cmap = db.get_codebase_map(pid)
        assert cmap["Catalog_API"]["folder"] == "catalog-api" and cmap["billing-core"]["folder"] == "billing-core"
        assert cmap["notify-gateway"]["folder"] == ""  # клона нарочно нет


def test_helpers_for_demo_and_names(tmp_path: Path, web):
    (tmp_path / "a" / "b").mkdir(parents=True)
    assert _rel_inside(tmp_path, tmp_path / "a" / "b") == "a/b"
    assert _rel_inside(tmp_path, tmp_path) == ""
    assert _rel_inside(tmp_path / "a", tmp_path) is None
    db = web.app.state.db
    assert unique_name(db, "Демо") == "Демо"
    create_project(web.client, "Демо")
    assert unique_name(db, "Демо") == "Демо (2)"


# ============================================================================ start.ps1

POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


@pytest.mark.skipif(not POWERSHELL, reason="нет PowerShell")
def test_start_script_creates_env_with_repos_folder(tmp_path: Path):
    """start.ps1 сам создаёт .env: корень – папка repos в корне диска с папкой приложения (не весь диск), порт 8765;
    -ReposRoot меняет только REPOS_ROOT. Сценарий подключается через «.» – так он только объявляет функции и Docker
    не трогает."""
    shutil.copy(ROOT / ".env.example", tmp_path / ".env.example")
    script = ROOT / "start.ps1"
    command = (f". '{script}'; "
               f"$first = Initialize-EnvFile '{tmp_path}' ''; "
               f"$again = Initialize-EnvFile '{tmp_path}' ''; "
               "Write-Output ('first=' + $first.Created + ' ' + $first.Root); "
               "Write-Output ('again=' + $again.Changed); "
               "Write-Output ('drive=' + (Get-DefaultReposRoot 'E:\\work\\local-triage')); "
               f"$other = Initialize-EnvFile '{tmp_path}' 'D:\\my repos\\'; "
               "Write-Output ('other=' + $other.Root)")
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    lines = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    drive = os.path.splitdrive(str(tmp_path))[0]
    assert lines["first"] == f"True {drive}/repos" and lines["again"] == "False" and lines["drive"] == "E:/repos"
    assert lines["other"] == "D:/my repos"
    env = (tmp_path / ".env").read_bytes()
    assert not env.startswith(b"\xef\xbb\xbf")
    text = env.decode("utf-8")
    assert 'REPOS_ROOT="D:/my repos"' in text and text.count("REPOS_ROOT=") == 1
    assert "TRIAGE_PORT=8765" in text and "OLLAMA_URL=" in text  # прочие строки образца сохранены


SHELLS = [shell for shell in (shutil.which("pwsh"), shutil.which("powershell")) if shell]


def _db_password(shell: str, tmp_path: Path, env_line: str, process_value: str, volumes: str) -> tuple[subprocess.CompletedProcess, str]:
    """Настоящая функция start.ps1 при $ErrorActionPreference = 'Stop', как в самом сценарии; docker – заглушка с выводом имён томов."""
    (tmp_path / ".env").write_text(env_line, encoding="utf-8")
    script = ROOT / "start.ps1"
    command = (f". '{script}'; $ErrorActionPreference = 'Stop'; "
               f"function docker {{ {volumes}; $global:LASTEXITCODE = 0 }}; "
               f"$env:POSTGRES_PASSWORD = '{process_value}'; "
               f"$r = Initialize-DbPassword '{tmp_path}'; "
               "Write-Output ('result=' + $r); Write-Output ('process=' + $env:POSTGRES_PASSWORD)")
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    return out, (tmp_path / ".env").read_text(encoding="utf-8")


NO_VOLUME = "'local-triage_pgdata_other'"
VOLUME = "'local-triage_pgdata'"


@pytest.mark.parametrize("shell", SHELLS)
def test_db_password_has_one_source(shell: str, tmp_path: Path):
    """Compose берёт окружение процесса раньше .env: значение остаётся только в .env, и разбирает его только Compose."""
    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\n", "from-process", NO_VOLUME)
    assert out.returncode == 0, out.stderr
    assert "result=True" in out.stdout and "process=\n" in out.stdout + "\n" and "POSTGRES_PASSWORD=from-process" in env

    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\"abc'\"\n", "from-process", VOLUME)
    assert out.returncode == 0, out.stderr
    assert "result=False" in out.stdout and "from-process" not in out.stdout
    assert env == "POSTGRES_PASSWORD=\"abc'\"\n", "значение с кавычкой не переписывается"

    for line in ("POSTGRES_PASSWORD=#abc\n", "POSTGRES_PASSWORD=\nPOSTGRES_PASSWORD=abc\n", "export POSTGRES_PASSWORD=abc\n",
                 "POSTGRES_PASSWORD: abc\n"):  # как их понимает Compose
        out, env = _db_password(shell, tmp_path, line, "", VOLUME)
        assert out.returncode == 0 and "result=False" in out.stdout and env == line, (line, out.stderr)

    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\"'\"\n", "", VOLUME)  # пароль из одного апострофа
    assert out.returncode == 0, out.stderr
    assert "result=False" in out.stdout and env == "POSTGRES_PASSWORD=\"'\"\n"

    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\n", "", NO_VOLUME)
    assert out.returncode == 0, out.stderr
    assert len(env.split("POSTGRES_PASSWORD=")[1].strip()) == 48

    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\nexport POSTGRES_PASSWORD=\nOTHER=1\n", "abc123", NO_VOLUME)
    assert out.returncode == 0, out.stderr
    assert env.count("POSTGRES_PASSWORD") == 1 and "POSTGRES_PASSWORD=abc123" in env and "OTHER=1" in env, "пустая строка не перекрывает"


@pytest.mark.parametrize("shell", SHELLS)
def test_db_password_is_not_invented_for_existing_volume(shell: str, tmp_path: Path):
    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\n", "", VOLUME)
    assert out.returncode == 1 and "result=" not in out.stdout
    assert env == "POSTGRES_PASSWORD=\n", "новый пароль к существующему тому не подойдёт и в .env не пишется"


@pytest.mark.parametrize("shell", SHELLS)
def test_db_password_is_not_invented_when_docker_does_not_answer(shell: str, tmp_path: Path):
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=\n", encoding="utf-8")
    script = ROOT / "start.ps1"
    command = (f". '{script}'; $ErrorActionPreference = 'Stop'; function docker {{ $global:LASTEXITCODE = 1 }}; "
               f"$env:POSTGRES_PASSWORD = ''; $r = Initialize-DbPassword '{tmp_path}'; Write-Output ('result=' + $r)")
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 1 and "result=" not in out.stdout
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "POSTGRES_PASSWORD=\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_db_password_with_special_signs_is_not_written(shell: str, tmp_path: Path):
    out, env = _db_password(shell, tmp_path, "POSTGRES_PASSWORD=\n", "a b", NO_VOLUME)
    assert out.returncode == 1 and env == "POSTGRES_PASSWORD=\n"


@pytest.mark.skipif(not shutil.which("docker"), reason="нет Docker")
def test_compose_reads_every_allowed_password_sign_as_is(tmp_path: Path):
    """Знаки, которые start.ps1 принимает из окружения, Compose читает из .env без изменений."""
    import json as json_module
    value = "aZ09_.~+/=:@-x"
    env_file = tmp_path / "test.env"
    env_file.write_text(f"POSTGRES_PASSWORD={value}\n", encoding="utf-8")
    clean = {k: v for k, v in os.environ.items() if k.upper() != "POSTGRES_PASSWORD"}
    out = subprocess.run([shutil.which("docker"), "compose", "--env-file", str(env_file), "-f", str(ROOT / "docker-compose.yml"),
                          "config", "--format", "json"], capture_output=True, text=True, encoding="utf-8", timeout=60, env=clean)
    assert out.returncode == 0, out.stderr
    services = json_module.loads(out.stdout)["services"]
    assert services["db"]["environment"]["POSTGRES_PASSWORD"] == value == services["triage"]["environment"]["PGPASSWORD"]


@pytest.mark.skipif(not POWERSHELL, reason="нет PowerShell")
@pytest.mark.parametrize("value", ["{app}/examples/demo/repos", "./examples/demo/repos", '"{app}\\examples\\demo\\repos\\"',
                                   "D:/", "d:", '"E:\\"'])
def test_start_script_suggests_repos_folder_instead_of_drive_or_demo(tmp_path: Path, value: str):
    """.env прежних этапов, где корнем – весь диск или демо-репозитории этой же папки приложения: start.ps1
    предлагает папку для клонов, а сам .env не меняет; другой корень не трогает. Замена – Set-ReposRoot."""
    (tmp_path / ".env").write_text("OLLAMA_URL=http://host.docker.internal:11434\nREPOS_ROOT="
                                   + value.format(app=str(tmp_path).replace("\\", "/")) + "\nTRIAGE_PORT=8765\n",
                                   encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    (other / ".env").write_text("REPOS_ROOT=D:/work\n", encoding="utf-8")
    script = ROOT / "start.ps1"
    command = (f". '{script}'; "
               f"$s = Initialize-EnvFile '{tmp_path}' ''; "
               f"$o = Initialize-EnvFile '{other}' ''; "
               "Write-Output ('state=' + $s.Changed + ' ' + $s.Root + ' ' + $s.Suggest); "
               "Write-Output ('other=' + $o.Changed)")
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    lines = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    drive = os.path.splitdrive(str(tmp_path))[0]
    assert lines["state"] == f"False  {drive}/repos" and lines["other"] == "False"
    before = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "REPOS_ROOT=" + value.format(app=str(tmp_path).replace("\\", "/")) in before  # .env не тронут
    assert (other / ".env").read_text(encoding="utf-8") == "REPOS_ROOT=D:/work\n"
    # согласие человека: замена только строки REPOS_ROOT
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                          f". '{script}'; Set-ReposRoot '{tmp_path}' 'D:\\repos\\'"],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "REPOS_ROOT=D:/repos" in text and text.count("REPOS_ROOT=") == 1 and "TRIAGE_PORT=8765" in text


@pytest.mark.skipif(not POWERSHELL, reason="нет PowerShell")
def test_start_script_copies_demo_repos_once(tmp_path: Path):
    """Копия демо-репозиториев в папку для клонов: один раз, существующая папка не трогается."""
    app_dir = tmp_path / "deep" / "Documents" / "local-triage"
    make_demo(app_dir)
    root = tmp_path / "repos"
    root.mkdir()
    command = (f". '{ROOT / 'start.ps1'}'; "
               f"Write-Output ('first=' + (Copy-DemoRepos '{app_dir}' '{root}')); "
               f"Write-Output ('again=' + (Copy-DemoRepos '{app_dir}' '{root}'))")
    out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    lines = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    assert lines["first"].endswith("local-triage-demo") and lines["again"] == ""
    assert (root / "local-triage-demo" / "billing-core").is_dir() and (root / "local-triage-demo" / "catalog-api").is_dir()


def test_demo_copy_in_repos_folder_is_found_for_deep_app_path(tmp_path: Path, monkeypatch):
    """Приложение лежит глубоко (в папке документов пользователя), корень – отдельная папка для клонов: демо
    находится по копии local-triage-demo, а выгрузка – из образа."""
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    image = tmp_path / "image"
    (image / "examples" / "demo").mkdir(parents=True)
    make_hub_xlsx(image / "examples" / "demo" / "demo-hub-report.xlsx")
    monkeypatch.setattr(projects, "APP_ROOT", image)
    root = tmp_path / "repos"
    demo = make_demo(tmp_path / "profile" / "Documents" / "local-triage")
    shutil.copytree(demo / "repos", root / "local-triage-demo")
    assert find_demo(Settings(repos_root=root)) == {"report": image / "examples" / "demo" / "demo-hub-report.xlsx",
                                                    "repos_dir": "local-triage-demo"}
    with app_with_root(tmp_path, root) as client:
        r = create_demo(client)
        assert r.status_code == 303 and r.headers["location"].endswith("?ok=project_demo")
        pid = int(r.headers["location"].split("/")[2].split("?")[0])
        cmap = client.app.state.db.get_codebase_map(pid)
        assert cmap["billing-core"]["folder"] == "billing-core" and cmap["catalog-api"]["folder"] == "catalog-api"


def test_start_script_keeps_bom_for_windows_powershell():
    raw = (ROOT / "start.ps1").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    long_dash = chr(0x2014)  # в текстах – только «–»
    assert long_dash not in text and "Initialize-EnvFile" in text and "-ReposRoot" in text
