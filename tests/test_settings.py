"""Страница «Настройки» и GET /api/ollama: показ и сохранение настроек, проверка адреса Ollama без сохранения,
отказ в чужом хосте и пустом статусе Hub, пересчёт срочности SCA после смены порога, работа без Ollama,
сведения о корне папок с репозиториями; разбор формы и вспомогательные функции app/settings_store.py."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import metrics
from app.config import DEFAULT_STATUS_MAP, Settings
from app.main import create_app
from app.settings_store import (STATUS_FIELDS, check_ollama_url, fmt_cvss, folder_display, form_values,
                                ollama_report, read_form, repos_display, save)
from fake_ollama import FakeOllama
from test_web import BASE, ORIGIN, create_project, upload, web, write_repos  # noqa: F401
from hub_fixtures import make_hub_xlsx

AS_HTML = {**ORIGIN, "Accept": "text/html"}


def form_of(web, **changes) -> dict:
    """Форма страницы настроек с текущими значениями и правками."""
    values = form_values(web.app.state.web.base.with_stored(web.app.state.db.get_settings()))
    return {**values, "action": "save", **changes}


def post_settings(web, **changes):
    return web.client.post("/settings", data=form_of(web, **changes), headers=AS_HTML, follow_redirects=False)


# ============================================================================ страница

def test_settings_page_shows_current_values_and_environment(web):
    page = web.client.get("/settings")
    assert page.status_code == 200
    text = page.text
    assert f'name="ollama_url" value="{web.fake.url}"' in text
    assert 'name="sca_urgent_cvss" value="9,0"' in text
    for _, name, _ in STATUS_FIELDS:
        assert f'name="{name}"' in text
    assert 'value="Подтверждено"' in text and 'value="Ложное срабатывание"' in text
    assert 'value="Не подтверждено"' in text and 'value="Риск принят"' in text
    assert "буква в букву" in text and "HUB_STATUS_MAP" not in text
    assert 'name="team_name"' in text and 'name="sca_internal_prefixes"' in text
    assert 'name="affiliation_words"' in text
    # модели Ollama – списком, выбрана модель по умолчанию
    assert re.search(r'<option value="gpt-oss:20b" selected>', text)
    assert "Ollama 0." in text and "моделей для разбора – 2" in text
    # что видно приложению: корень папок с репозиториями и папка данных
    assert "Что видно приложению" in text and str(web.settings.repos_root).replace("\\", "/") in text
    assert 'href="http' not in text and 'src="http' not in text
    # Enter в поле формы сохраняет: первая кнопка формы – «Сохранить», а не «Проверить»
    form = text[text.index('<form method="post" action="/settings"'):]
    first = re.search(r'<button type="submit" name="action" value="(\w+)"', form).group(1)
    assert first == "save"


def test_saving_settings_changes_what_the_app_uses(web):
    r = post_settings(web, status_false_positive="Not an issue", default_model="qwen2.5-coder:14b",
                      sca_urgent_cvss="9,0")
    assert r.status_code == 303 and r.headers["location"] == "/settings?ok=settings_saved"
    stored = web.app.state.db.get_settings()
    assert stored["hub_status_map"] == {**DEFAULT_STATUS_MAP, "false_positive": "Not an issue"}
    assert stored["default_model"] == "qwen2.5-coder:14b"
    page = web.client.get(r.headers["location"]).text
    assert "Настройки сохранены." in page and 'value="Not an issue"' in page
    assert re.search(r'<option value="qwen2.5-coder:14b" selected>', page)
    # новый проект предлагает модель из настроек
    pid = create_project(web.client)
    assert "qwen2.5-coder:14b – из настроек" in web.client.get(f"/projects/{pid}").text.replace("</span>", "")


@pytest.mark.parametrize(("field", "value", "message"), [
    ("ollama_url", "ftp://127.0.0.1:11434", "ожидается адрес вида"),
    ("ollama_url", "http://192.0.2.10:11434", "не входит в разрешённые"),
    ("ollama_url", "http://user:secret@127.0.0.1:11434", "имени пользователя и пароля"),
    ("default_model", "", "выберите модель"),
    ("status_true_positive", "", "Укажите статус Hub для вердикта «истинная»"),
    ("status_uncertain", "x" * 101, "до 100 знаков"),
    ("sca_urgent_cvss", "11", "от 0 до 10"),
    ("sca_urgent_cvss", "высокий", "от 0 до 10"),
])
def test_invalid_values_are_refused_and_kept_in_form(web, field, value, message):
    before = web.app.state.db.get_settings()
    r = post_settings(web, **{field: value, "status_false_positive": "Черновик статуса"})
    assert r.status_code == 400
    assert message in r.text and "Настройки не сохранены" in r.text
    assert f'aria-invalid="true" aria-describedby="{field}-error"' in r.text
    assert 'value="Черновик статуса"' in r.text  # введённое не пропадает
    assert web.app.state.db.get_settings() == before


def test_check_shows_entered_address_without_saving(web):
    other = FakeOllama(models=["mistral-small3.2:24b"], version="0.40.9")
    try:
        before = web.app.state.db.get_settings()
        r = web.client.post("/settings", data=form_of(web, ollama_url=other.url, action="check"), headers=AS_HTML)
        assert r.status_code == 200
        assert "Проверено: Ollama 0.40.9, моделей для разбора – 1" in r.text and "ещё не сохранён" in r.text
        # подпись модели – как во всех списках: имя (объём, параметры, рассуждение)
        assert re.search(r'id="ollama-models"><span class="mono">mistral-small3\.2:24b \([^)]*\)</span></p>', r.text)
        assert '<option value="mistral-small3.2:24b"' in r.text  # список моделей – с проверенного адреса
        assert f'name="ollama_url" value="{other.url}"' in r.text
        assert web.app.state.db.get_settings() == before
        assert "/api/version" in other.paths()
    finally:
        other.close()


def test_check_of_foreign_host_sends_nothing(web):
    calls = len(web.fake.paths())
    r = web.client.post("/settings", data=form_of(web, ollama_url="http://192.0.2.10:11434", action="check"),
                        headers=AS_HTML)
    assert r.status_code == 200 and "не входит в разрешённые" in r.text
    assert "Проверено:" not in r.text
    assert len(web.fake.paths()) == calls


def test_check_of_silent_address_shows_error(web):
    r = web.client.post("/settings", data=form_of(web, ollama_url="http://127.0.0.1:9", action="check"),
                        headers=AS_HTML)
    assert r.status_code == 200 and "callout-err" in r.text and "Ollama" in r.text
    assert 'name="default_model" value="gpt-oss:20b"' in r.text  # без списка моделей – поле ввода


def test_threshold_change_reorders_sca_in_every_project(web):
    db = web.app.state.db
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    archived = create_project(web.client, "Старый проект")
    assert upload(web.client, archived, make_hub_xlsx(web.tmp / "hub2.xlsx")).status_code == 303
    db.set_project_archived(archived, True)

    def urgent(project_id: int) -> set[str]:
        rows, _ = db.list_findings(project_id, kind="SCA", urgent=True)
        return {row["hub_id"] for row in rows}

    assert urgent(pid) == {"73001"}  # CVSS 9,8 при пороге 9,0
    r = post_settings(web, sca_urgent_cvss="8,5")
    assert r.status_code == 303 and r.headers["location"] == "/settings?ok=settings_reordered"
    assert db.get_settings()["sca_urgent_cvss"] == 8.5
    assert urgent(pid) == {"73001", "73003"} and urgent(archived) == {"73001", "73003"}
    assert "порядок разбора находок во всех проектах пересчитан" in web.client.get(r.headers["location"]).text
    # тот же порог – без пересчёта
    r = post_settings(web, sca_urgent_cvss="8.5")
    assert r.headers["location"] == "/settings?ok=settings_saved"


def test_page_and_saving_work_without_ollama(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url="http://127.0.0.1:9")
    with TestClient(create_app(settings), base_url=BASE) as client:
        page = client.get("/settings")
        assert page.status_code == 200 and "callout-err" in page.text
        assert 'name="default_model" value="gpt-oss:20b"' in page.text
        form = {**form_values(settings), "default_model": "qwen2.5-coder:14b", "action": "save"}
        r = client.post("/settings", data=form, headers=AS_HTML, follow_redirects=False)
        assert r.status_code == 303
        assert client.app.state.db.get_settings()["default_model"] == "qwen2.5-coder:14b"
        page = client.get("/settings")
        assert 'name="default_model" value="qwen2.5-coder:14b"' in page.text


def test_missing_repos_root_is_explained(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "missing", ollama_url="http://127.0.0.1:9",
                        repos_root_host="D:/work")
    with TestClient(create_app(settings), base_url=BASE) as client:
        page = client.get("/settings").text
        assert "D:/work" in page and "не найден" in page


def test_settings_form_requires_same_origin(web):
    r = web.client.post("/settings", data=form_of(web), follow_redirects=False)
    assert r.status_code == 403


# ============================================================================ GET /api/ollama

def test_api_ollama_reports_versions_and_default_model(web):
    data = web.client.get("/api/ollama").json()
    assert set(data) == {"url", "version", "models", "default_model", "default_model_found", "error", "profile"}
    assert data["profile"] == {"name": "Ollama из «Настроек»", "trust": "local", "where": "этот компьютер"}
    assert data["url"] == web.fake.url and data["version"] and data["error"] == ""
    assert data["models"] == ["gpt-oss:20b", "qwen2.5-coder:14b"]  # без эмбеддингов и облачных моделей
    assert data["default_model"] == "gpt-oss:20b" and data["default_model_found"] is True
    web.app.state.db.set_settings({"default_model": "llama3"})
    data = web.client.get("/api/ollama").json()
    assert data["default_model"] == "llama3" and data["default_model_found"] is False
    web.app.state.db.set_settings({"default_model": "QWEN2.5-coder:14b "})  # имена сравниваются как в Ollama
    assert web.client.get("/api/ollama").json()["default_model_found"] is True


def test_api_ollama_reports_problem_in_contract_shape(web):
    web.app.state.db.set_settings({"ollama_url": "http://127.0.0.1:9"})
    data = web.client.get("/api/ollama").json()
    assert data["url"] == "http://127.0.0.1:9" and data["error"]
    assert data["version"] == "" and data["models"] == [] and data["default_model_found"] is False


# ============================================================================ функции

def test_read_form_collects_clean_values_and_errors():
    form = {"ollama_url": " http://127.0.0.1:11434/ ", "default_model": "qwen2.5-coder:14b",
            "status_true_positive": " Confirmed ", "status_false_positive": "False  Positive",
            "status_uncertain": "To verify", "status_risk_accepted": "Риск  принят", "sca_urgent_cvss": "8,5",
            "team_name": "  Команда   сервиса ", "sca_internal_prefixes": "org.example., @example/ ,org.example.",
            "affiliation_words": "Exampletown, ACME*; exampletown\nКонтора"}
    parsed = read_form(form)
    assert parsed.errors == {}
    assert parsed.clean == {"ollama_url": "http://127.0.0.1:11434", "default_model": "qwen2.5-coder:14b",
                            "hub_status_map": {"true_positive": "Confirmed", "false_positive": "False Positive",
                                               "uncertain": "To verify", "risk_accepted": "Риск принят"},
                            "sca_urgent_cvss": 8.5, "team_name": "Команда сервиса",
                            "sca_internal_prefixes": ("org.example.", "@example/"), "hub_url": "",
                            "affiliation_words": ("Exampletown", "ACME*", "Контора")}
    bad = read_form({**form, "team_name": "x" * 101, "sca_internal_prefixes": "a" * 101,
                     "affiliation_words": "Example, x"})
    assert set(bad.errors) == {"team_name", "sca_internal_prefixes", "affiliation_words"}
    assert read_form({**form, "affiliation_words": "example.org"}).errors["affiliation_words"].startswith(
        "Слова принадлежности: «example.org»")
    # 200 слов не влезают в обычное поле (1000 знаков) – у списка свой предел, превышение – ошибка, не усечение
    many = ", ".join("w" + "".join("abcdefghij"[int(d)] for d in f"{i:03d}") + "*" for i in range(200))
    assert len(many) > 1000
    assert len(read_form({**form, "affiliation_words": many}).clean["affiliation_words"]) == 200
    too_long = read_form({**form, "affiliation_words": "x" * 12001})
    assert too_long.errors["affiliation_words"].startswith("Слова принадлежности: не больше 12000")
    assert "affiliation_words" not in too_long.clean
    # «Риск принят» без статуса – ошибка, как и у вердиктов
    assert "status_risk_accepted" in read_form({**form, "status_risk_accepted": ""}).errors
    parsed = read_form({**form, "status_false_positive": "", "ollama_url": "http://ollama.example:11434"})
    assert set(parsed.errors) == {"status_false_positive", "ollama_url"}
    assert "hub_status_map" not in parsed.clean and parsed.clean["sca_urgent_cvss"] == 8.5


def test_check_ollama_url_needs_no_network():
    assert check_ollama_url("http://host.docker.internal:11434/") == "http://host.docker.internal:11434"
    with pytest.raises(Exception, match="не входит в разрешённые"):
        check_ollama_url("http://10.0.0.5:11434")


def test_save_reports_changed_keys(tmp_path: Path):
    from app.db import Database

    db = Database(tmp_path / "triage.db")
    try:
        current = Settings()
        result = save(db, current, {"ollama_url": current.ollama_url, "default_model": "qwen2.5-coder:14b",
                                    "hub_status_map": dict(DEFAULT_STATUS_MAP), "sca_urgent_cvss": 9.0})
        assert result == {"changed": ["default_model"], "reordered": 0}
        assert db.get_settings()["default_model"] == "qwen2.5-coder:14b"
    finally:
        db.close()


def test_repos_display_and_folder_display():
    assert repos_display(Settings(repos_root_host="D:")) == "D:/"
    assert repos_display(Settings(repos_root_host="D:/")) == "D:/"
    assert repos_display(Settings(repos_root_host="D:\\work\\repos\\")) == "D:/work/repos"
    assert repos_display(Settings(repos_root=Path("/repos"))) == "/repos"
    assert folder_display(Settings(repos_root_host="D:"), "team/sub") == "D:/team/sub"
    assert folder_display(Settings(repos_root_host="D:/work"), "") == "D:/work"
    assert folder_display(Settings(repos_root_host="D:/work"), "team") == "D:/work/team"


def test_ollama_report_and_cvss_format():
    settings = Settings(ollama_url="http://127.0.0.1:11434", default_model="qwen2.5-coder")
    state = {"models": [{"name": "qwen2.5-coder:latest"}], "version": "0.40.4", "error": ""}
    report = ollama_report(settings, state)
    assert report["models"] == ["qwen2.5-coder:latest"] and report["default_model_found"] is True
    broken = ollama_report(settings, {"models": [{"name": "x"}], "version": "1", "error": "нет связи"})
    assert broken["models"] == [] and broken["version"] == "" and broken["default_model_found"] is False
    assert fmt_cvss(9) == "9,0" and fmt_cvss("x") == "x"


def test_saving_while_profile_1_is_busy_too_long_keeps_the_form(web, monkeypatch):
    """Блокировка профиля 1 не освободилась за срок ожидания (app/profile_gate.py): понятный отказ с формой, а не 500."""
    from app import profile_gate

    class Busy(profile_gate.ProfileGate):
        def write(self, timeout: float = 0):
            raise TimeoutError("профиль занят отправкой запросов слишком долго")

    busy = Busy()
    monkeypatch.setattr(profile_gate, "gate", lambda provider_id: busy)
    r = post_settings(web, default_model="qwen2.5-coder:14b", status_false_positive="Not an issue")
    assert r.status_code == 503 and "Настройки не сохранены" in r.text and "Повторите сохранение" in r.text
    assert 'value="Not an issue"' in r.text, "введённые значения остались в форме"
    assert web.app.state.db.get_settings().get("hub_status_map", {}).get("false_positive") != "Not an issue"


def test_api_ollama_takes_the_profile_once(web, monkeypatch):
    """Модели и подпись /api/ollama – одного профиля: умолчание сменили между вызовами – ответ не смешивается."""
    from app.routes import settings as route
    calls = []
    real = route.profile_for

    def counted(request, project=None):
        calls.append(1)
        return real(request, project)

    monkeypatch.setattr(route, "profile_for", counted)
    data = web.client.get("/api/ollama").json()
    assert len(calls) == 1 and data["models"]


# ============================================================================ копии базы перед обновлением (Э9)

# ============================================================================ адрес Hub (ADR-0114)

@pytest.mark.parametrize("raw,stored", [("https://hub.example.org", "https://hub.example.org"),
                                        ("https://hub.example.org/", "https://hub.example.org"),
                                        ("https://hub.example.org:8443", "https://hub.example.org:8443"),
                                        ("", "")])
def test_hub_url_saved(web, raw, stored):
    r = post_settings(web, hub_url=raw)
    assert r.status_code == 303, r.text
    assert web.app.state.db.get_settings()["hub_url"] == stored


@pytest.mark.parametrize("raw", ["http://hub.example.org", "https://hub.example.org/hub", "https://hub.example.org?x=1",
                                 "https://hub.example.org#a", "https://user@hub.example.org", "hub.example.org",
                                 "https://"])
def test_hub_url_refused(web, raw):
    r = post_settings(web, hub_url=raw)
    assert r.status_code == 400 and "Адрес Hub" in r.text
    assert web.app.state.db.get_settings().get("hub_url", "") == ""
