"""Ревью выпуска 0.10.0.dev36: /api/ollama о внешнем профиле, модель профиля с точным именем у удалённого API."""
from __future__ import annotations

from types import SimpleNamespace

from app.routes.projects import fallback_model, model_listed
from app.settings_store import ollama_report
from test_web import ORIGIN, web  # noqa: F401


def test_api_ollama_names_external_profile_internet():
    settings = SimpleNamespace(ollama_url="http://127.0.0.1:11434", default_model="gpt-oss:20b")
    report = ollama_report(settings, {"models": [{"name": "deepseek-flash"}], "version": ""},
                           {"name": "DeepSeek", "trust": "external", "kind": "chat_completions",
                            "base_url": "https://api.deepseek.com", "default_model": "deepseek-flash"})
    assert report["profile"]["where"] == "интернет" and report["profile"]["kind"] == "chat_completions"
    assert report["default_model_found"]
    beta = ollama_report(settings, {"models": [{"name": "alpha"}, {"name": "beta"}], "version": ""},
                         {"name": "API", "trust": "external", "kind": "chat_completions", "default_model": "Beta"})
    assert beta["default_model_found"] is False  # у удалённого API «Beta» и «beta» – разные модели
    local = ollama_report(settings, {"models": [], "version": "0.1"}, {"name": "O", "trust": "local", "kind": "ollama"})
    assert local["profile"]["where"] == "этот компьютер" and local["profile"]["kind"] == "ollama"


def test_remote_profile_model_must_match_exactly():
    """У удалённого API «Beta» и «beta» – разные модели: шапка не считает «Beta» доступной, если сервер отдал «beta»."""
    remote = {"kind": "chat_completions", "default_model": "Beta", "id": 7, "name": "API"}
    models = [{"name": "alpha"}, {"name": "beta"}]
    assert not model_listed("Beta", models, remote)
    assert model_listed("beta", models, remote)
    assert model_listed("Gemma3:4B", [{"name": "gemma3:4b"}], {"kind": "ollama"})  # Ollama – без учёта регистра
    settings = SimpleNamespace(default_model="gpt-oss:20b")
    assert fallback_model(settings, remote) == ("Beta", "из профиля «API»")
    assert fallback_model(settings, {"id": 1, "default_model": "gpt-oss:20b"}) == ("gpt-oss:20b", "из настроек")


def test_empty_explanation_is_not_called_non_russian_but_other_alphabets_are():
    """Проверка стенда 22.11: «CVE-…:» без текста – не «не на русском» (пустоту ловит проверка полноты); ревью dev36:
    строка на другом алфавите (греческий) – по-прежнему предупреждение."""
    from app import sca_text as t

    vulns = [t.Vuln(ids=["CVE-2099-0001"])]
    assert t.non_russian_lines("CVE-2099-0001:", vulns) == []
    greek = ("CVE-2099-0001: Подробное русское объяснение уязвимости компонента и условий её срабатывания.\n"
             "CVE-2099-0001: Ελληνική περιγραφή της ευπάθειας")
    assert t.non_russian_lines(greek, vulns) == ["CVE-2099-0001"]


def test_demo_library_gets_the_code_not_secret_mark(web):  # noqa: F811
    """Слово владельца 22.11.2026: код Demo Library выдуманный – отметка «код не секретный» при создании, и из списка
    проектов, и из «Примеров» (там – с корнем примеров, как у каталога)."""
    from app.routes.examples import DEMO_KEY, project_link
    from app.routes.projects import DEMO_MARK_REASON

    db = web.app.state.db
    r = web.client.post("/projects/demo", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    pid = int(r.headers["location"].split("/")[2].split("?")[0])
    project = db.get_project(pid)
    assert project["external_allowed"] and project["external_reason"] == DEMO_MARK_REASON
    r = web.client.post("/examples/demo-library/project", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    pid2 = int(r.headers["location"].split("/")[2].split("?")[0])
    assert pid2 != pid and db.get_project(pid2)["external_allowed"]
    assert (project_link(db, DEMO_KEY) or {}).get("mark_root"), "корень, для которого дана отметка"
