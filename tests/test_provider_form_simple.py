"""Форма профиля проще (разделы «Основное» и «Дополнительно», замечания по работе с внешним провайдером):
формат, рассуждение, пределы и поиск – в свёрнутом «Дополнительно»; галочка поиска без путей – стандартные пути;
ключ, введённый перед «Проверить», запоминается в памяти до «Сохранить»; без ключа «Проверить» к серверу не
обращается; «Пробный ответ» и «Проверить поиск» сначала сохраняют форму; сбой службы имён описан точно, совет про
Ollama – только своему классу. Данные выдуманы."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.llm import LlmError  # noqa: E402
from app.provider_keys import PendingKeys, load_key  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from test_providers_ui import SECRET, lan_loopback, post  # noqa: E402, F401
from test_web import ORIGIN, web  # noqa: E402, F401


def chat(web, url: str, **data):  # noqa: F811
    fields = {"name": "Сервер чат-завершений", "kind": "chat_completions", "trust": "local", "think": "auto",
              "enabled": "1", "response_mode": "json_object", **data}
    return web.client.post(url, headers=ORIGIN, follow_redirects=False, data=fields)


def test_advanced_fields_are_folded_until_one_of_them_is_wrong(web):  # noqa: F811
    page = web.client.get("/settings/providers/new").text
    assert '<details class="panel provider-chat provider-advanced" id="provider-chat">' in page, "свёрнуто"
    r = chat(web, "/settings/providers/new", base_url="http://127.0.0.1:9", max_output="99999999", action="save")
    assert r.status_code == 400
    assert '<details class="panel provider-chat provider-advanced" id="provider-chat" open>' in r.text


def test_search_box_without_paths_takes_the_standard_ones(web):  # noqa: F811
    r = chat(web, "/settings/providers/new", base_url="http://127.0.0.1:9", default_model="m", search_on="1",
             action="save")
    assert r.status_code == 303, r.text[:2000]
    profile = next(p for p in web.app.state.db.list_providers() if p["name"] == "Сервер чат-завершений")
    caps = json.loads(profile["capabilities_json"])
    assert caps["search"] == {"search_path": "/v1/tools/search", "fetch_path": "/v1/tools/fetch"}


def test_check_without_any_key_sends_nothing(web, lan_loopback):  # noqa: F811
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 requires_key="1")
        assert "Введите ключ" in r.text and "Запрос не отправлен" in r.text
        assert other.paths() == [], "без ключа сервер не спрашивали (у внешнего провайдера это был бы отказ 401)"
    finally:
        other.close()


def test_key_from_check_is_saved_without_typing_it_again(web, lan_loopback):  # noqa: F811
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", name="Сервер с ключом", base_url=other.url, action="check",
                 confirm=["127.0.0.1"], key=SECRET, requires_key="1")
        assert "Проверено: Ollama" in r.text and SECRET not in r.text
        assert other.headers[-1].get("Authorization") == f"Bearer {SECRET}"
        handle = r.text.split('name="key_handle" value="', 1)[1].split('"', 1)[0]
        draft = r.text.split('name="key_draft" value="', 1)[1].split('"', 1)[0]
        assert handle and handle not in SECRET
        # повторная проверка с пустым полем – тем же ключом из памяти
        again = post(web, "/settings/providers/new", name="Сервер с ключом", base_url=other.url, action="check",
                     confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        assert "Проверено: Ollama" in again.text and other.headers[-1].get("Authorization") == f"Bearer {SECRET}"
        # чужой черновик с той же меткой ключа не получает
        foreign = post(web, "/settings/providers/new", name="Чужой", base_url=other.url, action="check",
                       confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft="other-draft")
        assert "Введите ключ" in foreign.text
        # отказ сохранения (ошибка поля) ключ не стирает
        bad = post(web, "/settings/providers/new", name="", base_url=other.url, action="save",
                   confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        assert bad.status_code == 400 and 'name="key_handle"' in bad.text
        saved = post(web, "/settings/providers/new", name="Сервер с ключом", base_url=other.url, action="save",
                     confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        assert saved.status_code == 303, saved.text[:2000]
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Сервер с ключом")
        assert load_key(web.app.state.db, pid)["key"] == SECRET
        # после сохранения метка забыта: второй профиль по ней ключа не получит
        post(web, "/settings/providers/new", name="Второй", base_url=other.url, action="save",
             confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        second = next((p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Второй"), None)
        assert second is None or load_key(web.app.state.db, second) is None
    finally:
        other.close()


def test_pending_key_is_bound_to_owner_address_and_confirmed_addresses(monkeypatch):
    keys = PendingKeys()
    handle = keys.remember(SECRET, "draft:a", "https://api.example.com/", ["10.0.0.5"])
    assert keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET
    assert keys.peek(handle, "draft:b", "https://api.example.com", ["10.0.0.5"]) == "", "чужой черновик"
    assert keys.peek(handle, "draft:a", "https://other.example.com", ["10.0.0.5"]) == "", "другой адрес"
    assert keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.6"]) == "", "другие подтверждённые адреса"
    assert keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET, "без изъятия"
    keys.forget(handle, "draft:b")  # чужой владелец метку не стирает (ревью A8, круг 2)
    assert keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET
    foreign = keys.remember("x" * 20, "draft:b", "https://api.example.com", previous=handle)  # и не заменяет
    assert foreign != handle and keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET
    # резервирование на время сохранения: вторая попытка ключа не получает; отказ возвращает метку
    assert keys.claim(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET
    assert keys.claim(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == ""
    keys.release(handle, "draft:a")
    assert keys.claim(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == SECRET
    keys.forget(handle, "draft:a")
    assert keys.peek(handle, "draft:a", "https://api.example.com", ["10.0.0.5"]) == ""
    import time as clock
    handle = keys.remember(SECRET, "profile:1", "https://api.example.com")
    now = clock.monotonic()
    monkeypatch.setattr("app.provider_keys.time.monotonic", lambda: now + PendingKeys.TTL_S + 1)
    assert keys.peek(handle, "profile:1", "https://api.example.com") == ""
    monkeypatch.undo()
    for _ in range(PendingKeys.LIMIT + 5):
        keys.remember(SECRET, "profile:1", "https://api.example.com")
    assert len(keys._items) <= PendingKeys.LIMIT


def test_pending_key_follows_requires_key_and_confirmed_addresses(web, lan_loopback):  # noqa: F811
    """Ревью A8: снято «Сервер требует ключ» – ключ из памяти не отправляется и забывается; другие подтверждённые
    адреса – ключ не выдаётся."""
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key=SECRET, requires_key="1")
        handle = r.text.split('name="key_handle" value="', 1)[1].split('"', 1)[0]
        draft = r.text.split('name="key_draft" value="', 1)[1].split('"', 1)[0]
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key_handle=handle, key_draft=draft)  # галочка снята: проверка без ключа, ключ из памяти забыт
        assert "Проверено: Ollama" in r.text and "Authorization" not in other.headers[-1]
        assert 'name="key_handle"' not in r.text, "ключ забыт"
        sent = len(other.headers)
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key_handle=handle, key_draft=draft, requires_key="1")
        assert "Введите ключ" in r.text and len(other.headers) == sent, "без ключа запрос не ушёл"
    finally:
        other.close()


def test_probe_and_search_save_the_form_first(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        fake.search_results = [{"url": "https://advisories.example/x", "title": "x"}]
        r = chat(web, "/settings/providers/new", base_url=fake.url, default_model="flash-model", action="save")
        assert r.status_code == 303
        pid = next(p["id"] for p in db.list_providers() if p["name"] == "Сервер чат-завершений")
        # поиск включён только в форме, профиль ещё без него: кнопка сохраняет форму и проверяет по сохранённому
        r = chat(web, f"/settings/providers/{pid}", base_url=fake.url, default_model="flash-model", search_on="1",
                 thinking="disabled", action="search_check")
        assert 'id="provider-saved-first"' in r.text and "Поиск ответил: результатов – 1" in r.text, r.text[:2000]
        assert json.loads(db.get_provider(pid)["capabilities_json"])["thinking"] == "disabled"
        # форма с ошибкой – не сохраняется и ничего не отправляет
        sent = len(fake.chats())
        r = chat(web, f"/settings/providers/{pid}", base_url=fake.url, default_model="flash-model",
                 max_output="1", action="probe")
        assert r.status_code == 400 and "Профиль не сохранён" in r.text and len(fake.chats()) == sent


def test_existing_profile_check_says_changes_are_not_saved(web):  # noqa: F811
    with FakeChatApi(models=["flash-model"]) as fake:
        chat(web, "/settings/providers/new", base_url=fake.url, default_model="flash-model", action="save")
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Сервер чат-завершений")
        r = chat(web, f"/settings/providers/{pid}", base_url=fake.url, default_model="flash-model", action="check")
        assert "Проверка не сохраняет изменения формы" in r.text and "Профиль ещё не сохранён" not in r.text


@pytest.mark.parametrize("trust, errno, wanted, unwanted", [
    ("external", "EAI_AGAIN", "временно не ответила", "Ollama"),
    ("external", "EAI_NONAME", "не найдено службой имён", "Ollama"),
    ("lan", "EAI_AGAIN", "временно не ответила", "Ollama"),
    ("local", "EAI_NONAME", "укажите адрес Ollama", "службой имён (DNS): проверьте"),
])
def test_name_service_failure_is_described_by_class(monkeypatch, trust, errno, wanted, unwanted):
    code = getattr(socket, errno)

    def failing(*args, **kwargs):
        raise socket.gaierror(code, "сбой службы имён")
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", failing)
    with pytest.raises(LlmError) as info:
        llm_net._getaddrinfo("api.example.com", 443, 2.0, trust)
    assert wanted in str(info.value) and unwanted not in str(info.value)


def test_parallel_saves_by_one_handle_write_the_key_once(web, lan_loopback):  # noqa: F811
    """Ревью A8, круг 2: два одновременных сохранения одного черновика – ключ получает только одно."""
    import threading
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key=SECRET, requires_key="1")
        handle = r.text.split('name="key_handle" value="', 1)[1].split('"', 1)[0]
        draft = r.text.split('name="key_draft" value="', 1)[1].split('"', 1)[0]
        keys = web.app.state.pending_keys
        owner = f"draft:{draft}"
        # имитация гонки: первое сохранение уже зарезервировало метку – второе ключа не получает
        assert keys.claim(handle, owner, other.url, ["127.0.0.1"]) == SECRET
        second = post(web, "/settings/providers/new", name="Второй одновременно", base_url=other.url, action="save",
                      confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        assert second.status_code == 400 and "Введите ключ ещё раз" in second.text
        assert not [p for p in web.app.state.db.list_providers() if p["name"] == "Второй одновременно"]
        keys.release(handle, owner)
        results = []

        def save(name):
            results.append(post(web, "/settings/providers/new", name=name, base_url=other.url, action="save",
                                confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft))
        threads = [threading.Thread(target=save, args=(f"Параллельный {i}",)) for i in range(2)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        with_key = [p["id"] for p in web.app.state.db.list_providers() if p["name"].startswith("Параллельный")
                    and load_key(web.app.state.db, p["id"])]
        assert len(with_key) == 1, [r.status_code for r in results]
    finally:
        other.close()


def test_check_with_delete_key_sends_no_saved_key(web, lan_loopback):  # noqa: F811
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", name="С ключом", base_url=other.url, action="save",
                 confirm=["127.0.0.1"], key=SECRET, requires_key="1")
        assert r.status_code == 303
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "С ключом")
        post(web, f"/settings/providers/{pid}", name="С ключом", base_url=other.url, action="check",
             confirm=["127.0.0.1"], requires_key="1")
        assert other.headers[-1].get("Authorization") == f"Bearer {SECRET}", "сохранённый ключ в обычной проверке"
        post(web, f"/settings/providers/{pid}", name="С ключом", base_url=other.url, action="check",
             confirm=["127.0.0.1"], requires_key="1", delete_key="1")
        assert "Authorization" not in other.headers[-1], "«Удалить ключ» – проверка без сохранённого ключа"
        post(web, f"/settings/providers/{pid}", name="С ключом", base_url=other.url, action="check",
             confirm=["127.0.0.1"])
        assert "Authorization" not in other.headers[-1], "галочка снята – без ключа"
    finally:
        other.close()


def test_save_failure_before_and_after_key_write_handles_the_pending_key(web, lan_loopback, monkeypatch):  # noqa: F811
    """Ревью A8, круг 3: сбой сохранения до записи ключа – метка возвращается (ключ остаётся в памяти); сбой после
    записи ключа (умолчание) – метка погашена, ключ на диске."""
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key=SECRET, requires_key="1")
        handle = r.text.split('name="key_handle" value="', 1)[1].split('"', 1)[0]
        draft = r.text.split('name="key_draft" value="', 1)[1].split('"', 1)[0]
        keys, owner = web.app.state.pending_keys, f"draft:{draft}"
        db = web.app.state.db
        real_create, real_settings = db.create_provider, db.set_settings

        def fail(*a, **k):
            raise OSError("диск")
        # до записи ключа: create_provider падает (подмены возвращаются вручную: undo снял бы и lan_loopback)
        monkeypatch.setattr(db, "create_provider", fail)
        r = post(web, "/settings/providers/new", name="Сбой до ключа", base_url=other.url, action="save",
                 confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft)
        assert r.status_code == 500  # необработанная ошибка – страница 500 (logsafe), ключ не записан
        monkeypatch.setattr(db, "create_provider", real_create)
        assert keys.peek(handle, owner, other.url, ["127.0.0.1"]) == SECRET, "метка возвращена, ключ в памяти"
        assert keys.claim(handle, owner, other.url, ["127.0.0.1"]) == SECRET
        keys.release(handle, owner)
        # после записи ключа: set_settings (умолчание) падает
        monkeypatch.setattr(db, "set_settings", fail)
        r = post(web, "/settings/providers/new", name="Сбой после ключа", base_url=other.url, action="save",
                 confirm=["127.0.0.1"], requires_key="1", key_handle=handle, key_draft=draft, default_code="1")
        assert r.status_code == 500, r.text[:500]
        monkeypatch.setattr(db, "set_settings", real_settings)
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "Сбой после ключа")
        assert load_key(web.app.state.db, pid)["key"] == SECRET, "ключ на диске"
        assert keys.peek(handle, owner, other.url, ["127.0.0.1"]) == "", "метка погашена"
    finally:
        other.close()


def test_check_sends_no_key_when_the_field_is_filled_but_the_key_is_declined(web, lan_loopback):  # noqa: F811
    """Ревью A8, круг 3: ключ в поле вместе с «Удалить ключ» или без «Сервер требует ключ» – не отправляется."""
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", name="С ключом", base_url=other.url, action="save",
                 confirm=["127.0.0.1"], key=SECRET, requires_key="1")
        assert r.status_code == 303
        pid = next(p["id"] for p in web.app.state.db.list_providers() if p["name"] == "С ключом")
        before = len(other.headers)
        post(web, f"/settings/providers/{pid}", name="С ключом", base_url=other.url, action="check",
             confirm=["127.0.0.1"], requires_key="1", delete_key="1", key="another-key-" + "Z9q" * 5)
        post(web, f"/settings/providers/{pid}", name="С ключом", base_url=other.url, action="check",
             confirm=["127.0.0.1"], key="another-key-" + "Z9q" * 5)
        assert all("Authorization" not in h for h in other.headers[before:]), "ни один новый запрос без ключа"
        assert len(other.headers) > before
    finally:
        other.close()
