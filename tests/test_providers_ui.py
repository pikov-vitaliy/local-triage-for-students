"""«Настройки → Провайдеры моделей» (0.9.12, шаг 7): список профилей, форма с проверкой сервера, подтверждение
адресов сервера в сети, ключ (только «задан, …последние 4 знака»), умолчание для разбора кода, несколько профилей без
сброса друг друга, пробный ответ, окно контекста профиля в снимке прогона. Поддельный сервер слушает loopback: в
тестах сервера в сети loopback считается частной сетью (подмена llm_net.LAN_NETWORKS)."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.provider_keys import load_key  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: E402, F401

SECRET = "ui-test-key-" + "Q7w" * 5


@pytest.fixture
def lan_loopback(monkeypatch):
    monkeypatch.setattr(llm_net, "LAN_NETWORKS", (*llm_net.LAN_NETWORKS, ipaddress.ip_network("127.0.0.0/8")))


def post(web, url: str, **data):
    """Форма профиля; confirm – список подтверждённых адресов (повторяющееся поле)."""
    fields = {"name": "Сервер в сети", "trust": "lan", "think": "auto", "enabled": "1", **data}
    return web.client.post(url, headers=ORIGIN, follow_redirects=False, data=fields)


def test_list_shows_the_settings_profile(web):
    page = web.client.get("/settings/providers").text
    assert "Ollama из «Настроек»" in page and "по умолчанию" in page and "этот компьютер" in page
    settings = web.client.get("/settings").text
    assert 'href="/settings/providers"' in settings
    # кнопка в шапке «Настроек», а не только ссылка в тексте блока
    assert 'id="providers-button" href="/settings/providers"' in settings


def test_new_lan_profile_check_confirm_save_with_key(web, lan_loopback):
    other = FakeOllama(models=["other-model:7b"])
    try:
        # 1. «Проверить» без подтверждения: адреса показаны, к серверу запросов нет
        r = post(web, "/settings/providers/new", base_url=other.url, action="check")
        assert r.status_code == 200 and "Отметьте адреса сервера" in r.text and other.paths() == []
        assert 'name="confirm" value="127.0.0.1"' in r.text
        # 2. с подтверждённым адресом – версия и модели
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"])
        assert "Проверено: Ollama" in r.text and "other-model:7b" in r.text
        # 3. сохранение с ключом
        r = post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"],
                 default_model="other-model:7b", key=SECRET, requires_key="1", num_ctx="32768")
        assert r.status_code == 303 and r.headers["location"].endswith("ok=provider_saved")
        db = web.app.state.db
        profile = [p for p in db.list_providers() if p["name"] == "Сервер в сети"][0]
        assert profile["trust"] == "lan" and profile["auth"] == "bearer"
        assert json.loads(profile["confirmed_addresses_json"]) == ["127.0.0.1"]
        assert json.loads(profile["generation_json"]) == {"num_ctx": 32768}
        data_dir = web.app.state.db
        assert load_key(data_dir, profile["id"])["key"] == SECRET
        page = web.client.get("/settings/providers").text
        assert SECRET not in page and "задан, …" + SECRET[-4:] in page
        form = web.client.get(f"/settings/providers/{profile['id']}").text
        assert SECRET not in form and 'type="password"' in form
        assert db.get_provider(1)["name"] == "Ollama из «Настроек»", "другие профили не тронуты"
    finally:
        other.close()


def test_changing_the_address_drops_the_key_and_says_so(web, lan_loopback):
    other = FakeOllama()
    try:
        post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"], key=SECRET,
             requires_key="1")
        db = web.app.state.db
        pid = max(p["id"] for p in db.list_providers())
        r = post(web, f"/settings/providers/{pid}", base_url=other.url.replace("127.0.0.1", "localhost"),
                 action="save", confirm=["127.0.0.1"], requires_key="1")
        assert r.headers["location"].endswith("ok=provider_key_dropped")
        assert load_key(web.app.state.db, pid) is None
    finally:
        other.close()


def test_default_profile_choice_and_disabling(web, lan_loopback):
    other = FakeOllama()
    try:
        post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"],
             default_code="1")
        db = web.app.state.db
        pid = max(p["id"] for p in db.list_providers())
        assert db.get_settings()["default_provider_id"] == pid
        r = post(web, f"/settings/providers/{pid}", base_url=other.url, action="save", confirm=["127.0.0.1"],
                 enabled="")
        assert r.status_code == 400 and "не выключается" in r.text and db.get_provider(pid)["enabled"] == 1
    finally:
        other.close()


def test_errors_are_shown_and_nothing_is_saved(web):
    count = len(web.app.state.db.list_providers())
    r = post(web, "/settings/providers/new", name="", trust="lan", base_url="http://8.8.8.8:11434",
             num_ctx="12", think="much", action="save")
    assert r.status_code == 400
    for text in ("Назовите профиль", "не частная сеть", "Окно контекста: целое число", "Выберите режим рассуждения"):
        assert text in r.text, text
    r = post(web, "/settings/providers/new", trust="local", base_url="http://10.0.0.5:11434", action="save")
    assert r.status_code == 400 and "не входит в разрешённые" in r.text
    r = post(web, "/settings/providers/new", trust="external", base_url="https://api.example", action="save")
    assert r.status_code == 400 and "только по API внешнего провайдера" in r.text  # Ollama в интернет – нет
    r = post(web, "/settings/providers/new", trust="cloud", base_url="https://api.example", action="save")
    assert r.status_code == 400 and "Выберите, где работает модель" in r.text
    assert len(web.app.state.db.list_providers()) == count


def test_settings_profile_keeps_address_and_model_from_settings(web):
    r = post(web, "/settings/providers/1", name="Ollama из «Настроек»", trust="lan", base_url="http://10.0.0.9:1",
             default_model="x", think="off", num_ctx="8192", action="save", default_code="1")
    assert r.status_code == 303
    profile = web.app.state.db.get_provider(1)
    assert profile["trust"] == "local" and profile["base_url"] == web.fake.url
    assert json.loads(profile["generation_json"]) == {"num_ctx": 8192, "think": "off"}


def test_probe_answers_through_the_saved_profile(web):
    r = post(web, "/settings/providers/1", name="Ollama из «Настроек»", action="probe")
    assert r.status_code == 200 and re.search(r"ответила за \d+,\d с", r.text), r.text[-2000:]
    assert web.fake.chats()[-1]["options"]["num_predict"] == 8


def test_profile_window_goes_into_the_run_snapshot(web):
    post(web, "/settings/providers/1", name="Ollama из «Настроек»", num_ctx="12288", action="save")
    pid = prepared(web)
    run = wait_run(web, start_run(web, pid))
    snapshot = web.app.state.db.get_execution(run["execution_id"])
    assert json.loads(snapshot["options_json"])["options"]["num_ctx"] == 12288
    assert web.fake.chats()[-1]["options"]["num_ctx"] == 12288


def test_project_chooses_its_profile(web):
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = prepared(web)
        db = web.app.state.db
        second = db.create_provider({"name": "Второй сервер", "kind": "ollama", "base_url": other.url,
                                     "trust": "local"})["id"]
        page = web.client.get(f"/projects/{pid}").text
        assert 'id="project-provider"' in page and "Второй сервер (этот компьютер)" in page
        r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                            data={"name": "Проект", "model": "", "provider_id": str(second)})
        assert r.status_code == 303 and db.get_project(pid)["provider_id"] == second
        page = web.client.get(f"/projects/{pid}").text
        assert "Профиль модели: Второй сервер" in page and "other-model:7b (" in page
        run = wait_run(web, start_run(web, pid, model="other-model:7b"))
        assert run["state"] == "done" and other.chats(), "прогон ушёл на сервер профиля проекта"
        db.update_provider(second, {"enabled": 0})
        r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                            data={"name": "Проект", "model": "", "provider_id": "999"})
        assert r.status_code == 400 and "выберите включённый профиль" in r.text
        r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                            data={"name": "Проект", "model": "", "provider_id": ""})
        assert r.status_code == 303 and db.get_project(pid)["provider_id"] is None
    finally:
        other.close()


def test_project_profile_is_switched_in_the_triage_step(web):
    """Профиль проекта меняется прямо в шаге «Триаж»: адрес в шаге – сервера профиля
    проекта, а не «Адрес Ollama» из «Настроек»; список моделей – с нового сервера; подсказка о готовых вердиктах."""
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = prepared(web)
        db = web.app.state.db
        settings_url = web.app.state.settings.ollama_url
        second = db.create_provider({"name": "Второй сервер", "kind": "ollama", "base_url": other.url,
                                     "trust": "local"})["id"]
        page = web.client.get(f"/projects/{pid}").text
        assert 'id="run-provider"' in page and 'id="project-provider-form"' in page
        assert "Триаж SAST моделью" in page and "локальной моделью" not in page
        assert f'id="run-server">{settings_url}<' in page
        assert "Спросить модель заново" in page and 'id="run-provider-hint"' in page
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": str(second)})
        assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}?ok=provider_changed#step3"
        project = db.get_project(pid)
        assert project["provider_id"] == second and project["name"] and project["model"] == ""
        page = web.client.get(f"/projects/{pid}?ok=provider_changed").text
        assert "Профиль модели проекта изменён" in page
        assert f'id="run-server">{other.url}<' in page and settings_url not in page.split('id="run-server">')[1][:200]
        assert "other-model:7b (" in page and "Профиль модели: Второй сервер" in page
        assert re.search(rf'<select name="provider_id" id="run-provider">.*?<option value="{second}" selected>',
                         page, re.S)
        # чужой номер и выключенный профиль не принимаются, «как в настройках» – снимает профиль проекта
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": "999"})
        assert r.status_code == 400 and "выберите включённый профиль" in r.text
        assert db.get_project(pid)["provider_id"] == second
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": ""})
        assert r.status_code == 303 and db.get_project(pid)["provider_id"] is None
    finally:
        other.close()


# ============================================================================ прогрев модели ВМ (шаг 8)

def test_warmup_loads_the_default_local_model(web):
    r = web.client.post("/api/model/warmup", headers=ORIGIN)
    assert r.status_code == 200 and r.json()["state"] == "warm"
    generated = [body for _, path, body in web.fake.requests if path == "/api/generate"]
    assert generated and generated[-1]["keep_alive"] == "24h" and "prompt" not in generated[-1]


def test_warmup_skips_lan_and_disabled_and_waits_for_nobody(web):
    from app.llm import GENERATION
    db = web.app.state.db
    assert GENERATION.try_acquire("triage")
    try:
        assert web.client.post("/api/model/warmup", headers=ORIGIN).json()["state"] == "busy"
    finally:
        GENERATION.release()
    lan = db.create_provider({"name": "Сеть", "kind": "ollama", "base_url": "http://10.0.0.5:11434", "trust": "lan"})
    db.set_settings({"default_provider_id": lan["id"]})
    assert web.client.post("/api/model/warmup", headers=ORIGIN).json()["state"] == "skipped"
    db.set_settings({"default_provider_id": 1})
    db.update_provider(1, {"enabled": 0})
    assert web.client.post("/api/model/warmup", headers=ORIGIN).json()["state"] == "skipped"
    assert web.client.post("/api/model/warmup").status_code == 403, "POST – только со своей страницы (ADR-0015)"


def test_vm_start_script_warms_through_the_application():
    text = (Path(__file__).resolve().parents[1] / "deploy" / "vm" / "guest" / "start.sh").read_text(encoding="utf-8")
    assert "ollama:11434" not in text and "/api/generate" not in text
    assert '-H "Origin: http://127.0.0.1:${PORT}"' in text and "/api/model/warmup" in text



# ============================================================================ по ревью: круг 1 шага 7

def test_entered_key_is_used_for_check_and_must_be_entered_again(web, lan_loopback):
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 key=SECRET, requires_key="1")
        assert "Проверено: Ollama" in r.text and 'id="key-not-saved"' in r.text and SECRET not in r.text
        assert other.headers[-1].get("Authorization") == f"Bearer {SECRET}"
        bad = post(web, "/settings/providers/new", base_url=other.url, action="check", confirm=["127.0.0.1"],
                   key="плохой ключ", requires_key="1")
        assert "Ключ – от 16 до 4096 знаков" in bad.text and len(other.paths()) == 2, "ключ с ошибкой не отправлен"
        lost = post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"],
                    key=SECRET)
        assert lost.status_code == 400 and "«Сервер требует ключ» не отмечено" in lost.text
    finally:
        other.close()


def test_saved_key_is_sent_by_check_only_with_matching_binding(web, lan_loopback):
    other = FakeOllama()
    try:
        post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"], key=SECRET,
             requires_key="1")
        pid = max(p["id"] for p in web.app.state.db.list_providers())
        post(web, f"/settings/providers/{pid}", base_url=other.url, action="check", confirm=["127.0.0.1"],
             requires_key="1")
        assert other.headers[-1].get("Authorization") == f"Bearer {SECRET}"
        before = len(other.headers)
        post(web, f"/settings/providers/{pid}", base_url=other.url.replace("127.0.0.1", "localhost"),
             action="check", confirm=["127.0.0.1", "::1"], requires_key="1")
        assert all("Authorization" not in h for h in other.headers[before:]), \
            "ключ привязан к прежнему адресу – не отправлен"
    finally:
        other.close()


def test_profile_default_model_is_offered_in_the_project(web):
    other = FakeOllama(models=["alpha:7b", "beta:7b"])
    try:
        pid = prepared(web)
        db = web.app.state.db
        second = db.create_provider({"name": "Второй", "kind": "ollama", "base_url": other.url, "trust": "local",
                                     "default_model": "beta:7b"})["id"]
        db.update_project(pid, provider_id=second)
        page = web.client.get(f"/projects/{pid}").text
        assert re.search(r'<option value="beta:7b"[^>]*selected', page), "модель профиля – по умолчанию"
    finally:
        other.close()


def test_errors_of_radio_and_checkbox_are_announced(web):
    r = post(web, "/settings/providers/new", trust="external", base_url="http://x", action="save")
    assert 'name="trust" value="lan" aria-invalid="true" aria-describedby="trust-error"' in r.text
    r = post(web, "/settings/providers/1", name="Ollama из «Настроек»", enabled="", action="save")
    assert r.status_code == 400 and 'name="enabled" value="1" aria-invalid="true"' in r.text


def test_journal_passport_shows_thinking_state(web):
    analysed_pid = prepared(web)
    run = wait_run(web, start_run(web, analysed_pid))
    page = web.client.get(f"/journal/{run['id']}").text
    assert "рассуждение: поле не передаётся" in page or "рассуждение: выключено" in page \
        or "рассуждение: low" in page


# ============================================================================ по ревью: круг 2 шага 7

def test_card_asks_a_build_answer_with_the_project_profile(web):
    """Ответ получен при сборке образа ВМ (сборочный профиль выключен, адрес не сохраняется): форма вопроса в карточке
    – с моделями профиля проекта, по тому же правилу, что и обработка вопроса (ask.answer_execution)."""
    pid = prepared(web)
    wait_run(web, start_run(web, pid))
    db = web.app.state.db
    build = db.create_provider({"name": "Сервер сборки образа", "kind": "ollama", "base_url": web.fake.url,
                                "trust": "local"})["id"]
    with db._tx() as c:
        c.execute("UPDATE llm_providers SET base_url = '', enabled = 0 WHERE id = ?", (build,))
        c.execute("UPDATE llm_executions SET provider_id = ?, base_url = '', note = 'адрес сборки не сохраняется'",
                  (build,))
    links = sorted(set(re.findall(rf'href="(/projects/{pid}/findings/\d+)', web.client.get(
        f"/projects/{pid}/findings").text)))
    cards = [web.client.get(link).text for link in links]
    asked = [card for card in cards if 'id="ask-btn"' in card and "адрес сборки не сохраняется" in card]
    assert asked, "карточка с ответом сборки и формой вопроса"
    button = re.search(r'<button[^>]*id="ask-btn"[^>]*>', asked[0]).group(0)
    assert "disabled" not in button, "вопрос по ответу сборки задаётся профилю проекта"
    assert '<option value="qwen2.5-coder:14b"' in asked[0]


def test_disabled_profile_gets_no_key_and_check_sends_none(web, lan_loopback):
    """Выключение удаляет ключ: выключенному профилю новый ключ не записывается (ни при создании, ни при правке),
    а «Проверить» не отправляет сохранённый ключ профиля, выключенного в базе или в форме."""
    other = FakeOllama()
    try:
        data = web.app.state.db
        r = post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"], key=SECRET,
                 requires_key="1", enabled="")
        assert r.status_code == 400 and "Ключ не сохраняется у выключенного профиля" in r.text
        assert 'name="key"' in r.text and 'aria-describedby="key-error"' in r.text
        post(web, "/settings/providers/new", base_url=other.url, action="save", confirm=["127.0.0.1"], key=SECRET,
             requires_key="1")
        pid = max(p["id"] for p in web.app.state.db.list_providers())
        assert load_key(data, pid) is not None
        r = post(web, f"/settings/providers/{pid}", base_url=other.url, action="save", confirm=["127.0.0.1"],
                 key=SECRET, requires_key="1", enabled="")
        assert r.status_code == 400 and load_key(data, pid) is not None, "отказ – правка не записана, ключ прежний"
        r = post(web, f"/settings/providers/{pid}", base_url=other.url, action="check", confirm=["127.0.0.1"],
                 requires_key="1", enabled="")
        assert "Проверено: Ollama" in r.text and "Authorization" not in other.headers[-1], "выключен в форме"
        with web.app.state.db._tx() as c:  # выключен в базе (ключ остался бы, если бы его не удалили)
            c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (pid,))
        post(web, f"/settings/providers/{pid}", base_url=other.url, action="check", confirm=["127.0.0.1"],
             requires_key="1")
        assert "Authorization" not in other.headers[-1], "выключен в базе"
    finally:
        other.close()


def test_key_field_reset_is_announced_before_addresses_are_confirmed(web, lan_loopback):
    other = FakeOllama()
    try:
        r = post(web, "/settings/providers/new", base_url=other.url, action="check", key=SECRET, requires_key="1")
        assert "Отметьте адреса сервера" in r.text and other.paths() == []
        assert 'id="key-not-saved"' in r.text and "запомнен до «Сохранить»" in r.text and SECRET not in r.text
        assert 'name="key_handle"' in r.text, "ключ – в памяти приложения по метке формы, не в странице"
    finally:
        other.close()


def test_key_field_reset_is_announced_on_form_errors(web, lan_loopback):
    """Поле ключа возвращается пустым и при ошибках формы (адрес, сохранение): подсказка о повторном вводе есть."""
    r = post(web, "/settings/providers/new", base_url="не адрес", action="check", key=SECRET, requires_key="1")
    assert 'id="key-not-saved"' in r.text and SECRET not in r.text
    r = post(web, "/settings/providers/new", base_url="не адрес", action="save", key=SECRET, requires_key="1")
    assert r.status_code == 400 and 'id="key-not-saved"' in r.text and SECRET not in r.text


def test_journal_pages_name_the_profile(web):
    """Журнал прогонов – список и страница прогона – называет профиль, которым получены ответы (как CSV и JSON)."""
    run = wait_run(web, start_run(web, prepared(web)))
    listing = web.client.get("/journal").text
    page = web.client.get(f"/journal/{run['id']}").text
    assert "Ollama из «Настроек» (этот компьютер)" in listing
    assert 'id="journal-executor">профиль: Ollama из «Настроек» (этот компьютер)' in page


def test_footer_tells_where_code_goes(web):
    """Подвал: без включённого сервера в сети – «код не покидает компьютер»; с ним – куда именно уходит код."""
    assert "Код находок не покидает компьютер" in web.client.get("/settings").text
    other = web.app.state.db.create_provider({"name": "Сервер", "kind": "ollama", "base_url": "http://10.0.0.5:11434",
                                              "trust": "lan"})["id"]
    page = web.client.get("/settings").text
    assert "Код находок не покидает компьютер" not in page and "подтверждённые адреса сервера в сети" in page
    with web.app.state.db._tx() as c:
        c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (other,))
    assert "Код находок не покидает компьютер" in web.client.get("/settings").text


def test_footer_names_the_internet_when_an_external_profile_is_on(web, monkeypatch):
    """Раньше при включённом внешнем профиле подвал говорил «внешних запросов интерфейс не делает», хотя
    код проекта с отметкой уходил провайдеру в интернет. Теперь подвал называет интернет и условие отметки."""
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    db = web.app.state.db
    pid = db.create_provider({"name": "Внешний", "kind": "chat_completions", "base_url": "https://api.example.test",
                              "trust": "external"})["id"]
    page = web.client.get("/settings").text
    assert "внешних запросов интерфейс не делает" not in page
    assert "внешнему провайдеру через интернет" in page and "код не секретный" in page
    with db._tx() as c:
        c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (pid,))
    assert "Код находок не покидает компьютер" in web.client.get("/settings").text
