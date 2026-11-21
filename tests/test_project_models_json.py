"""«Параметры проекта»: список «Модель проекта» по профилю, выбранному до сохранения (прежде при
выборе внешнего профиля список оставался списком прежнего профиля, пока не нажать «Сохранить»). Адрес
/projects/{id}/models.json проверяет профиль так же, как сохранение, и ничего не меняет. Сервер моделей подменён;
данные выдуманы."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.routes import projects as projects_routes  # noqa: E402
from test_providers_chat_ui import post  # noqa: E402
from test_web import prepared, web  # noqa: E402, F401

REASON = "Демонстрационный проект: код открытый"


def fake_models(request, fresh=False, profile=None):  # noqa: ARG001
    name = "deepseek-flash" if profile and str(profile.get("trust")) == "external" else "qwen-local"
    return {"models": [{"name": name}], "version": "", "error": ""}


def external_profile(web, monkeypatch) -> int:  # noqa: F811
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    r = post(web, "/settings/providers/new", name="Внешний DeepSeek", trust="external",
             base_url="https://api.example.com", action="save")
    assert r.status_code == 303
    return next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Внешний DeepSeek")


def test_models_follow_the_chosen_profile_without_saving(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(projects_routes, "models_of", fake_models)
    ext = external_profile(web, monkeypatch)
    pid = prepared(web)
    db = web.app.state.db
    assert db.set_external_mark(pid, REASON)
    page = web.client.get(f"/projects/{pid}").text
    assert f'data-models="/projects/{pid}/models.json"' in page and 'id="project-model"' in page
    answer = web.client.get(f"/projects/{pid}/models.json", params={"provider_id": str(ext)}).json()
    assert answer["profile"] == "Внешний DeepSeek" and answer["error"] == ""
    assert [o["value"] for o in answer["options"]] == ["", "deepseek-flash"]
    assert answer["options"][0]["label"].startswith("Как в настройках")
    default = web.client.get(f"/projects/{pid}/models.json", params={"provider_id": ""}).json()
    assert [o["value"] for o in default["options"]] == ["", "qwen-local"]
    assert db.get_project(pid)["provider_id"] is None, "просмотр списка профиль проекта не меняет"


def test_refusals_match_saving(web, monkeypatch):  # noqa: F811
    monkeypatch.setattr(projects_routes, "models_of", fake_models)
    ext = external_profile(web, monkeypatch)
    pid = prepared(web)
    r = web.client.get(f"/projects/{pid}/models.json", params={"provider_id": str(ext)})
    assert r.status_code == 400 and "не разбирает код" in r.json()["detail"], "без отметки «код не секретный»"
    for bogus in ("abc", "99999", "\u00b2", "9223372036854775808"):
        r = web.client.get(f"/projects/{pid}/models.json", params={"provider_id": bogus})
        assert r.status_code == 400 and "выберите включённый профиль" in r.json()["detail"]
    assert web.client.get("/projects/99999/models.json").status_code == 404
    from test_web import ORIGIN
    for bogus in ("\u00b2", "9223372036854775808"):
        r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                            data={"name": "Проект", "model": "", "provider_id": bogus})
        assert r.status_code == 400 and "выберите включённый профиль" in r.text, "не 500"
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": bogus})
        assert r.status_code == 400
