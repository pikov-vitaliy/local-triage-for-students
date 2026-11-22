"""Профиль для примеров и граница отправки у проектов из каталога (ADR-0157, сборка В): заготовки профилей, назначение
профиля только после отметки студента, снятие отметки при смене источника кода, проект из каталога без Hub."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import examples as ex  # noqa: E402
from test_examples_catalog import FILES, _archive, _toy_catalog  # noqa: E402
from test_external_code_mark import external_loopback, external_profile, mark  # noqa: E402, F401
from test_web import ORIGIN, web  # noqa: E402, F401


def example_project(web, monkeypatch) -> int:  # noqa: F811
    entry = _toy_catalog(web.tmp, monkeypatch)
    arch = web.tmp / "toy.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, ex.examples_root(web.settings.repos_root) / ex.folder_name(entry))
    r = web.client.post("/examples/toy/project", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text[:500]
    return int(r.headers["location"].split("/")[2].split("?")[0])


def test_presets_fill_the_new_profile_form(web):  # noqa: F811
    page = web.client.get("/settings/providers/new?preset=deepseek").text
    assert 'value="https://api.deepseek.com"' in page and 'value="deepseek-flash"' in page
    assert "/v1/tools/search" in page and "вставьте свой ключ API" in page
    local = web.client.get("/settings/providers/new?preset=ollama-local").text
    assert f'value="{web.settings.ollama_url}"' in local and 'value="gpt-oss:20b"' in local  # не стенд – адрес из настроек
    assert "заготовка" not in web.client.get("/settings/providers/new?preset=unknown").text.lower()


def test_deepseek_preset_fills_recommended_advanced_values_with_hints(web, monkeypatch):  # noqa: F811
    """Слово владельца 22.11.2026: заготовка DeepSeek сразу заполняет «Дополнительно» рекомендуемыми значениями, у полей
    – подсказки; кнопка «Подставить рекомендуемые значения DeepSeek» – для уже созданных профилей."""
    import html
    import json
    import re

    from app.providers import ADVANCED_HINTS, DEEPSEEK_RECOMMENDED, read_form

    page = web.client.get("/settings/providers/new?preset=deepseek").text
    for name in ("context_window", "max_output", "tool_steps", "chat_timeout_s"):
        assert f'name="{name}" value="{DEEPSEEK_RECOMMENDED[name]}"' in page, name
    assert '<option value="enabled" selected>' in page and '<option value="high" selected>' in page
    assert re.search(r'name="retry_on_drop" value="1" checked', page)
    for hint in ADVANCED_HINTS.values():
        assert html.escape(hint, quote=False) in page or html.escape(hint) in page
    raw = re.search(r'data-fill-fields="([^"]+)"', page).group(1)
    assert json.loads(html.unescape(raw)) == DEEPSEEK_RECOMMENDED
    # рекомендуемые значения проходят проверку формы без ошибок
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    form = {"name": "DeepSeek", "kind": "chat_completions", "trust": "external", "base_url": "https://api.deepseek.com",
            "default_model": "deepseek-flash", "enabled": "1",
            **{k: ("1" if v is True else v) for k, v in DEEPSEEK_RECOMMENDED.items()}}
    parsed = read_form(form, None)
    assert not parsed.errors, parsed.errors


def test_deepseek_preset_without_key_sends_nothing(web, monkeypatch):  # noqa: F811
    """«Проверить» у заготовки без ключа не обращается к провайдеру: сразу просьба ввести ключ."""
    from app import llm_net
    from app.routes.providers import NO_KEY

    monkeypatch.setenv("LLM_EXTERNAL", "1")
    calls = []
    monkeypatch.setattr(llm_net, "_getaddrinfo", lambda *a, **k: calls.append(a) or [])
    r = web.client.post("/settings/providers/new", headers=ORIGIN, follow_redirects=False, data={
        "name": "DeepSeek", "kind": "chat_completions", "trust": "external", "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-flash", "requires_key": "1", "enabled": "1", "response_mode": "json_object",
        "action": "check"})
    assert NO_KEY[:40] in r.text and not calls, "без ключа запросов к провайдеру нет"


def test_local_examples_profile_is_assigned_at_creation_and_not_made_default(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    local = db.create_provider({"name": "Ollama примеров", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    default_before = db.get_settings().get("default_provider_id")
    r = web.client.post("/examples/profile", headers=ORIGIN, follow_redirects=False, data={"provider_id": str(local["id"])})
    assert r.status_code == 303 and "examples_profile" in r.headers["location"]
    pid = example_project(web, monkeypatch)
    assert db.get_project(pid)["provider_id"] == local["id"]
    assert db.get_settings().get("default_provider_id") == default_before, "общий профиль по умолчанию не меняется"


def test_disabled_examples_profile_is_not_assigned(web, monkeypatch):  # noqa: F811
    db = web.app.state.db
    local = db.create_provider({"name": "Выключенный", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    db.set_settings({"examples_provider_id": int(local["id"])})
    db.update_provider(local["id"], {"enabled": False})
    pid = example_project(web, monkeypatch)
    assert db.get_project(pid)["provider_id"] in (None, 0)


def test_external_examples_profile_is_assigned_with_the_default_mark(web, monkeypatch, external_loopback):  # noqa: F811
    """Учебный пример – открытый код: отметка «код не секретный» ставится при создании (слово владельца 21.11.2026),
    внешний профиль примеров назначается сразу."""
    db = web.app.state.db
    profile = external_profile(web, "https://external-test.example:9", name="DeepSeek учебный")
    db.set_settings({"examples_provider_id": int(profile["id"])})
    entry = _toy_catalog(web.tmp, monkeypatch)
    arch = web.tmp / "toy.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, ex.examples_root(web.settings.repos_root) / ex.folder_name(entry))
    r = web.client.post("/examples/toy/project", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "ok=project_example_profile" in r.headers["location"], r.headers["location"]
    pid = int(r.headers["location"].split("/")[2].split("?")[0])
    project = db.get_project(pid)
    assert project["external_allowed"] == 1 and project["provider_id"] == profile["id"]


def test_local_only_stand_does_not_assign_the_external_examples_profile(web, monkeypatch, external_loopback):  # noqa: F811
    """Бэклог 140: стенд запущен с --local-only (внешние модели выключены), а «Профиль для примеров» – внешний, выбранный
    раньше. Новый проект из примера его не получает: профиль по умолчанию и сообщение о причине."""
    db = web.app.state.db
    profile = external_profile(web, "https://external-test.example:9", name="DeepSeek учебный")
    db.set_settings({"examples_provider_id": int(profile["id"])})
    monkeypatch.setenv("LLM_EXTERNAL", "0")
    entry = _toy_catalog(web.tmp, monkeypatch)
    arch = web.tmp / "toy.tar.gz"
    arch.write_bytes(_archive(FILES))
    ex.unpack(arch, entry, ex.examples_root(web.settings.repos_root) / ex.folder_name(entry))
    r = web.client.post("/examples/toy/project", headers=ORIGIN, follow_redirects=False)
    location = r.headers["location"]
    assert r.status_code == 303 and "ok=project_example_noprofile_external_off" in location, location
    pid = int(location.split("/")[2].split("?")[0])
    project = db.get_project(pid)
    assert project["provider_id"] is None and project["research_provider_id"] is None, "наследует общий профиль"
    assert "--local-only" in web.client.get(location).text


@pytest.mark.parametrize("change", ["folder", "codebase", "import"])
def test_source_change_clears_the_mark_only_for_catalog_projects(web, monkeypatch, external_loopback, change):  # noqa: F811
    db = web.app.state.db
    pid = example_project(web, monkeypatch)
    other = db.create_project("Обычный проект")
    for project_id in (pid, other):
        db.set_external_mark(project_id, "Открытый код, проверено вручную для теста")
    rev = db.external_mark_revision(pid)
    for project_id in (pid, other):
        if change == "folder":
            db.set_repos_dir(project_id, "elsewhere")
        elif change == "codebase":
            db.set_codebase_folder(project_id, "toy", "other-folder", manual=True)
        else:
            db.save_import(project_id, "x.xlsx", "hub", [], {}, [], [])
    assert db.get_project(pid)["external_allowed"] == 0 and db.external_mark_revision(pid) > rev
    assert db.get_project(other)["external_allowed"] == 1, "у проектов не из каталога поведение прежнее"


def test_catalog_project_is_not_linked_with_hub(web, monkeypatch):  # noqa: F811
    pid = example_project(web, monkeypatch)
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                        data={"name": "Пример: Toy", "hub_app_id": "123", "model": ""})
    assert r.status_code == 400 and "с Hub не" in r.text
    assert not web.app.state.db.get_project(pid).get("hub_app_id")


def test_changed_link_blocks_the_examples_profile(web, monkeypatch):  # noqa: F811
    from app.routes.examples import apply_examples_profile, link_intact

    db = web.app.state.db
    pid = example_project(web, monkeypatch)
    assert link_intact(db, pid) is not None
    db.set_codebase_folder(pid, "toy", "something-else", manual=True)
    assert link_intact(db, pid) is None
    local = db.create_provider({"name": "Ollama", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    db.set_settings({"examples_provider_id": int(local["id"])})
    assert apply_examples_profile(db, pid) == "link"


def test_help_page_has_contents_and_glossary_and_opens_in_new_tab(web):  # noqa: F811
    page = web.client.get("/help")
    assert page.status_code == 200 and 'id="help-glossary"' in page.text and 'href="#help-sast"' in page.text
    home = web.client.get("/examples").text
    assert 'href="/help" target="_blank"' in home


def test_start_panel_shows_probe_and_search_results(web):  # noqa: F811
    from app.routes.providers import check_state, record_check

    db = web.app.state.db
    local = db.create_provider({"name": "Ollama примеров", "kind": "ollama", "base_url": web.fake.url, "trust": "local"})
    db.set_settings({"examples_provider_id": int(local["id"])})
    page = web.client.get("/examples").text
    assert "Пробный ответ: не проверялся" in page and "Проверка поиска" not in page
    record_check(db, local, "probe", True)
    assert check_state(db, local, "probe") == "passed"
    assert "Пробный ответ: прошёл" in web.client.get("/examples").text
    changed = db.update_provider(local["id"], {"name": "Переименован"})
    assert check_state(db, changed, "probe") == "none", "после правки профиля итог устаревает"
