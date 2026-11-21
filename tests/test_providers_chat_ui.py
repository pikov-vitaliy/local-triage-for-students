"""«Провайдеры моделей» для API чат-завершений (0.9.13, шаг A5): протокол, класс «Интернет» только при LLM_EXTERNAL=1,
поля формата ответа и рассуждения, окно и предел, поиск; «Проверить», «Пробный ответ», «Проверить поиск»; ключ –
«задан, …последние 4 знака»; внешний профиль не бывает умолчанием для разбора кода. Поддельный сервер – на loopback
(класс «этот компьютер»); внешний профиль сохраняется без сети. Данные выдуманы."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app.provider_keys import load_key  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402
from test_web import ORIGIN, web  # noqa: E402, F401

KEY = "chat-ui-key-" + "Wq3" * 6


def post(web, url: str, **data):  # noqa: F811
    fields = {"name": "Провайдер", "kind": "chat_completions", "trust": "local", "think": "auto", "enabled": "1",
              "response_mode": "json_object", **data}
    return web.client.post(url, headers=ORIGIN, follow_redirects=False, data=fields)


def test_external_is_off_without_the_installation_switch(web, monkeypatch):  # noqa: F811
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    page = web.client.get("/settings/providers/new").text
    assert 'id="external-off"' in page and 'value="external" disabled' in page
    count = len(web.app.state.db.list_providers())
    r = post(web, "/settings/providers/new", trust="external", base_url="https://api.example.com", action="save")
    assert r.status_code == 400 and "LLM_EXTERNAL=1" in r.text
    assert len(web.app.state.db.list_providers()) == count


def test_external_profile_is_saved_with_key_and_settings(web, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    db = web.app.state.db
    page = web.client.get("/settings/providers/new").text
    assert 'id="external-off"' not in page and 'id="provider-chat"' in page
    r = post(web, "/settings/providers/new", name="Внешний провайдер", trust="external",
             base_url="https://api.example.com", default_model="flash-model", requires_key="1", key=KEY,
             response_mode="json_object", thinking="enabled", effort="high", context_window="1000000",
             max_output="8192", tool_steps="12", chat_timeout_s="600", search_on="1",
             search_path="/v1/tools/search", fetch_path="/v1/tools/fetch", action="save")
    assert r.status_code == 303, r.text[:2000]
    profile = next(p for p in db.list_providers() if p["name"] == "Внешний провайдер")
    assert (profile["kind"], profile["trust"], profile["auth"]) == ("chat_completions", "external", "bearer")
    assert json.loads(profile["generation_json"]) == {"context_window": 1000000, "max_output": 8192,
                                                      "timeout_s": 600, "tool_steps": 12}
    caps = json.loads(profile["capabilities_json"])
    assert caps["response_mode"] == "json_object" and caps["thinking"] == "enabled" and caps["effort"] == "high"
    assert caps["search"] == {"search_path": "/v1/tools/search", "fetch_path": "/v1/tools/fetch"}
    assert caps["supports_ps"] is False and caps["allows_unload"] is False
    entry = load_key(web.app.state.db, profile["id"])
    assert entry["key"] == KEY and entry["base_url"] == "https://api.example.com"
    listing = web.client.get("/settings/providers").text
    assert "интернет" in listing and "API чат-завершений" in listing and "задан, …" + KEY[-4:] in listing
    assert KEY not in listing and KEY not in web.client.get(f"/settings/providers/{profile['id']}").text
    form = web.client.get(f"/settings/providers/{profile['id']}").text
    assert 'value="chat_completions" checked' in form and 'id="provider-search-check"' in form


def test_external_cannot_be_the_default_for_code(web, monkeypatch):  # noqa: F811
    """Галочки у профиля API чат-завершений на странице нет: отметка, оставшаяся от Ollama
    при смене протокола, не действует – профиль сохраняется, но умолчанием для разбора кода не становится."""
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    before = web.app.state.settings.default_provider_id
    r = post(web, "/settings/providers/new", name="Внешний", trust="external", base_url="https://api.example.com",
             default_code="1", action="save")
    assert r.status_code == 303, r.text[:1500]
    db = web.app.state.db
    pid = next(p["id"] for p in db.list_providers() if p["name"] == "Внешний")
    stored = db.get_settings().get("default_provider_id")
    assert stored != pid and web.app.state.settings.default_provider_id == before
    page = web.client.get(f"/settings/providers/{pid}").text
    assert 'id="provider-code-default-note"' in page


@pytest.mark.parametrize("fields, text", [
    ({"search_on": "1", "search_path": "v1/tools/search", "fetch_path": "/v1/tools/fetch"}, "Путь от корня"),
    ({"context_window": "8192", "max_output": "8192"}, "меньше окна"),
    ({"tool_steps": "99"}, "Шагов поиска"),
    ({"response_mode": "xml"}, "формат ответа"),
    ({"kind": "ollama", "trust": "external", "base_url": "https://api.example.com"}, "только по API"),
])
def test_field_errors(web, monkeypatch, fields, text):  # noqa: F811
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    base = {"base_url": "http://127.0.0.1:9/v1", "action": "save"}
    r = post(web, "/settings/providers/new", **{**base, **fields})
    assert r.status_code == 400 and text in r.text


def test_local_chat_server_check_probe_and_search(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        fake.search_results = [{"url": "https://advisories.example/x", "title": "x"}]
        r = post(web, "/settings/providers/new", base_url=fake.url, action="check")
        assert r.status_code == 200 and "API чат-завершений, моделей: 1" in r.text and "flash-model" in r.text
        r = post(web, "/settings/providers/new", name="Сервер чат-завершений", base_url=fake.url,
                 default_model="flash-model", thinking="disabled", effort="low", max_output="512", search_on="1",
                 search_path="/v1/tools/search", fetch_path="/v1/tools/fetch", action="save")
        assert r.status_code == 303, r.text[:2000]
        pid = next(p["id"] for p in db.list_providers() if p["name"] == "Сервер чат-завершений")
        full = {"name": "Сервер чат-завершений", "base_url": fake.url, "default_model": "flash-model",
                "thinking": "disabled", "effort": "low", "max_output": "512", "search_on": "1"}
        r = post(web, f"/settings/providers/{pid}", **full, action="probe")  # пустые пути поиска – стандартные
        assert "ответила за" in r.text and 'id="provider-saved-first"' in r.text, r.text[:3000]
        body = fake.chats()[-1]
        assert body["model"] == "flash-model" and body["thinking"] == {"type": "disabled"}
        assert body["reasoning_effort"] == "low" and body["response_format"] == {"type": "json_object"}
        r = post(web, f"/settings/providers/{pid}", **full, action="search_check")
        assert "Поиск ответил: результатов – 1" in r.text
        search = [x for x in fake.requests if x["path"] == "/v1/tools/search"]
        assert search and search[0]["body"]["query"] and search[0]["body"]["count"] == 1


def test_project_cannot_pick_a_non_code_profile(web, monkeypatch):  # noqa: F811
    """До отметки «код не секретный» внешний профиль (и любой не-Ollama) для разбора кода не выбирается – ни в списке
    (виден неактивным с причиной), ни запросом в обход формы (К9 плана 0.9.13)."""
    from test_web import prepared
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    db = web.app.state.db
    r = post(web, "/settings/providers/new", name="Внешний для проекта", trust="external",
             base_url="https://api.example.com", action="save")
    assert r.status_code == 303
    ext = next(p["id"] for p in db.list_providers() if p["name"] == "Внешний для проекта")
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}").text
    assert f'value="{ext}" disabled>Внешний для проекта (интернет) – нужна отметка «код не секретный»' in page
    assert f'value="{ext}" selected' not in page and 'id="run-provider-not-for-code"' in page
    for url, data in ((f"/projects/{pid}/provider", {"provider_id": str(ext)}),
                      (f"/projects/{pid}/params", {"name": "Проект", "model": "", "provider_id": str(ext)})):
        r = web.client.post(url, headers=ORIGIN, follow_redirects=False, data=data)
        assert r.status_code == 400 and "не разбирает код" in r.text
    assert db.get_project(pid)["provider_id"] is None


def test_check_says_when_the_model_is_missing(web):  # noqa: F811
    with FakeChatApi(models=["flash-model"]) as fake:
        r = post(web, "/settings/providers/new", base_url=fake.url, default_model="flash-modle", action="check")
        assert 'id="model-missing"' in r.text and "flash-modle – нет в списке сервера" in r.text


def test_chat_snapshot_timeout_defaults_to_600():
    import json as _json
    from app.executors import execution_values
    profile = {"id": 3, "version": 1, "kind": "chat_completions", "base_url": "https://api.example.com",
               "trust": "external", "auth": "bearer", "generation_json": "{}", "capabilities_json": "{}",
               "confirmed_addresses_json": "[]"}
    data = _json.loads(execution_values(profile, "m", "triage", 16384, "")["options_json"])
    assert data["timeout_s"] == 600.0


def test_ollama_model_name_is_normalized_in_check(web):  # noqa: F811
    """Ревью A6, мелкое: у Ollama «m» и «m:latest» – одна модель; предупреждения нет."""
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).parent))
    from fake_ollama import FakeOllama
    fake = FakeOllama(models=["solo-model:latest"])
    try:
        r = web.client.post("/settings/providers/new", headers=ORIGIN, follow_redirects=False,
                            data={"name": "o", "kind": "ollama", "trust": "local", "think": "auto", "enabled": "1",
                                  "base_url": fake.url, "default_model": "solo-model", "action": "check"})
        assert 'id="model-missing"' not in r.text and "Проверено" in r.text
    finally:
        fake.close()


def test_ollama_default_model_stays_selected_with_latest(web):  # noqa: F811
    """Ревью A6, круг 2: «solo-model» и список [alpha:latest, solo-model:latest] – выбран solo-model:latest."""
    import re as _re
    from fake_ollama import FakeOllama
    fake = FakeOllama(models=["alpha:latest", "solo-model:latest"])
    try:
        r = web.client.post("/settings/providers/new", headers=ORIGIN, follow_redirects=False,
                            data={"name": "o", "kind": "ollama", "trust": "local", "think": "auto", "enabled": "1",
                                  "base_url": fake.url, "default_model": "solo-model", "action": "check"})
        assert _re.search(r'<option value="solo-model:latest" selected>', r.text)
        assert not _re.search(r'<option value="alpha:latest" selected>', r.text)
    finally:
        fake.close()


def test_probe_drop_says_result_unknown(web):  # noqa: F811
    with FakeChatApi(models=["flash-model"]) as fake:
        r = post(web, "/settings/providers/new", name="Обрыв", base_url=fake.url, default_model="flash-model",
                 action="save")
        assert r.status_code == 303
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Обрыв")
        fake.answers.append(("drop",))
        r = post(web, f"/settings/providers/{pid}", name="Обрыв", base_url=fake.url, default_model="flash-model",
                 action="probe")
        # свой контур (здесь – сервер на этом компьютере): обрыв – обычная ошибка, о платном запросе речи нет;
        # у внешнего провайдера – «Результат неизвестен» (ревью A6, круг 3)
        assert "Пробный ответ не получен" in r.text and "Результат неизвестен" not in r.text
        assert len(fake.chats()) == 1


def test_external_probe_drop_says_result_unknown(web, monkeypatch):  # noqa: F811
    """Внешний профиль по https (тестовый удостоверяющий центр, 127.0.0.1 в тесте считается публичным): обрыв после
    отправки – «Результат неизвестен: запрос мог быть принят и оплачен»."""
    import socket
    import ssl
    from app import llm_net
    from fake_chat_api import CERTS
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    monkeypatch.setattr(llm_net, "external_address_ok", lambda ip, hosts=None: str(ip) == "127.0.0.1")
    monkeypatch.setattr(llm_net, "_tls_context", lambda: ssl.create_default_context(cafile=str(CERTS / "ca.pem")))
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host == "external-test.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", getaddrinfo)
    with FakeChatApi(models=["flash-model"], tls=True) as fake:
        r = post(web, "/settings/providers/new", name="Внешний обрыв", trust="external", base_url=fake.url,
                 default_model="flash-model", action="save")
        assert r.status_code == 303, r.text[:1500]
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Внешний обрыв")
        fake.answers.append(("drop",))
        r = post(web, f"/settings/providers/{pid}", name="Внешний обрыв", trust="external", base_url=fake.url,
                 default_model="flash-model", action="probe")
        assert "Результат неизвестен" in r.text and len(fake.chats()) == 1


def test_external_probe_known_cut_off_is_not_unknown(web, monkeypatch):  # noqa: F811
    """Ревью круг 15, находка 2: пробный ответ – общий классификатор. Ответ получен, но оборван по длине – обычная
    ошибка, а не «Результат неизвестен»; обрыв соединения – по-прежнему неизвестен (тест выше)."""
    import socket
    import ssl
    from app import llm_net
    from fake_chat_api import CERTS
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    monkeypatch.setattr(llm_net, "external_address_ok", lambda ip, hosts=None: str(ip) == "127.0.0.1")
    monkeypatch.setattr(llm_net, "_tls_context", lambda: ssl.create_default_context(cafile=str(CERTS / "ca.pem")))
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host == "external-test.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", getaddrinfo)
    with FakeChatApi(models=["flash-model"], tls=True) as fake:
        r = post(web, "/settings/providers/new", name="Внешний обрез", trust="external", base_url=fake.url,
                 default_model="flash-model", action="save")
        assert r.status_code == 303, r.text[:1500]
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Внешний обрез")
        fake.answers.append(("message", {"role": "assistant", "content": '{"ok": tr'}, "length"))
        r = post(web, f"/settings/providers/{pid}", name="Внешний обрез", trust="external", base_url=fake.url,
                 default_model="flash-model", action="probe")
        assert "Пробный ответ не получен" in r.text and "оборван" in r.text
        assert "Результат неизвестен" not in r.text and len(fake.chats()) == 1


def test_probe_uses_the_profile_timeout(web, monkeypatch):  # noqa: F811
    """Ревью круг 16: пробный ответ идёт со сроком одного обращения из профиля, а не с конструкторскими 600 с."""
    from app.routes import providers as providers_route
    seen = []
    monkeypatch.setattr(providers_route, "probe_generation", lambda client, model: seen.append(client.timeout) or 1.0)
    with FakeChatApi(models=["flash-model"]) as fake:
        r = post(web, "/settings/providers/new", name="Срок", base_url=fake.url, default_model="flash-model",
                 chat_timeout_s="45", action="save")
        assert r.status_code == 303, r.text[:1500]
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Срок")
        post(web, f"/settings/providers/{pid}", name="Срок", base_url=fake.url, default_model="flash-model",
             chat_timeout_s="45", action="probe")
    assert seen == [45.0]
