"""Ссылка «Открыть в VS Code» и путь к файлу в карточке находки (app.routes.findings.editor_target)."""
from __future__ import annotations

from types import SimpleNamespace

from app.routes.findings import editor_target


def ctx(**kw):
    base = {"status": "ok", "file": "src/app/db.py", "target_line": 42, "start_line": 20}
    base.update(kw)
    return SimpleNamespace(**base)


def test_link_points_to_the_target_line_inside_the_clone(tmp_path):
    repos = tmp_path / "repos"
    (repos / "shop").mkdir(parents=True)
    settings = SimpleNamespace(repos_root=str(repos), repos_root_host="")
    got = editor_target(settings, repos / "shop", ctx(), from_db=False)
    assert got is not None
    assert got["path"].replace("\\", "/").endswith("/repos/shop/src/app/db.py")
    assert got["url"].startswith("vscode://file/") and got["url"].endswith("/repos/shop/src/app/db.py:42")


def test_docker_install_uses_the_host_path_and_encodes_spaces(tmp_path):
    repos = tmp_path / "repos"
    (repos / "shop").mkdir(parents=True)
    settings = SimpleNamespace(repos_root=str(repos), repos_root_host="D:\\Учёба\\my repos")
    got = editor_target(settings, repos / "shop", ctx(), from_db=False)
    assert got["path"] == "D:\\Учёба\\my repos\\shop\\src\\app\\db.py"
    assert " " not in got["url"] and "%20" in got["url"] and got["url"].endswith(":42")


def test_no_link_without_a_file_from_the_clone(tmp_path):
    repos = tmp_path / "repos"
    (repos / "shop").mkdir(parents=True)
    settings = SimpleNamespace(repos_root=str(repos), repos_root_host="")
    assert editor_target(settings, repos / "shop", ctx(), from_db=True) is None
    assert editor_target(settings, repos / "shop", ctx(status="missing"), from_db=False) is None
    assert editor_target(settings, None, ctx(), from_db=False) is None
    assert editor_target(settings, tmp_path / "elsewhere", ctx(), from_db=False) is None
