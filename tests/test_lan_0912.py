"""Класс доверия lan, ключ в заголовке и журнал обмена без заголовка авторизации (0.9.12, шаг 6, ADR-0102 п. 7, 8, 12).

lan – только частные адреса, подтверждённые в профиле: имя разрешилось в другой адрес – запрос не уходит, прогон на
паузе до нового подтверждения. Ключ – файл в папке данных с привязкой к адресу снимка: привязка не совпала – запрос не
отправляется вовсе; ротация при прежнем адресе действует для незавершённого исполнения; смена адреса или
подтверждённых адресов удаляет ключ. Заголовок авторизации не попадает ни в одну ветвь журнала обмена. Поддельный
сервер слушает loopback: в этих тестах loopback считается сетью организации (подмена llm_net.LAN_NETWORKS)."""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
import sys
from keys_support import keys_for  # noqa: E402
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net, model_traffic  # noqa: E402
from app.db import now_iso  # noqa: E402
from app.executors import ProbeBusy, ProfileError, choose_profile, probe_generation  # noqa: E402
from app.llm import GENERATION, LlmError, SendNotAllowed  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402
from app.model_traffic import Recorder, redact_headers, redact_wire  # noqa: E402
from app.provider_keys import (KEY_NOTE_OTHER, KeyRejected, auth_headers, delete_key, key_hint,  # noqa: E402
                               load_key, save_key)
from app.providers import ProfileInvalid, update_profile  # noqa: E402
from app.triage import PROMPT_VERSION  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from run_helpers import run_execution  # noqa: E402
from test_executors_0912 import MODEL, started  # noqa: E402
from test_triage import sast, wait_state  # noqa: E402

SECRET = "test-key-" + "Zx9" * 6  # ключ, созданный тестом: не настоящий
MESSAGES = [{"role": "user", "content": "x"}]


@pytest.fixture
def lan_loopback(monkeypatch):
    monkeypatch.setattr(llm_net, "LAN_NETWORKS", (*llm_net.LAN_NETWORKS, ipaddress.ip_network("127.0.0.0/8")))


def lan_profile(db, base_url: str, *, confirmed=("127.0.0.1",), auth: str = "none") -> int:
    ts = now_iso()
    with db._tx() as c:
        return int(c.execute("INSERT INTO llm_providers(name, kind, base_url, trust, auth, default_model,"
                             " confirmed_addresses_json, created_at, updated_at)"
                             " VALUES ('Сервер в сети', 'ollama', ?, 'lan', ?, ?, ?, ?, ?)" " RETURNING id",
                             (base_url, auth, MODEL, json.dumps(list(confirmed)), ts, ts)).fetchone()[0])


def use(db, project_id: int, provider_id: int) -> None:
    with db._tx() as c:
        c.execute("UPDATE projects SET provider_id = ? WHERE id = ?", (provider_id, project_id))


def lan_client(url: str, confirmed=("127.0.0.1",)) -> OllamaClient:
    client = OllamaClient(url)
    client.trust = "lan"
    client.confirmed = tuple(confirmed)
    return client


# ============================================================================ адреса класса lan

def test_lan_refuses_a_public_address_literal():
    client = lan_client("http://8.8.8.8:11434", confirmed=("8.8.8.8",))
    with pytest.raises(LlmError, match="не частная сеть"):
        client.version()


def test_lan_refuses_a_name_resolving_outside_private_networks(monkeypatch):
    def fake_getaddrinfo(host, port, timeout, trust="local"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", port))]

    monkeypatch.setattr(llm_net, "_getaddrinfo", fake_getaddrinfo)
    with pytest.raises(LlmError, match="не частная сеть"):
        lan_client("http://ollama.corp.example:11434", confirmed=("203.0.113.7",)).version()


def test_lan_requires_confirmed_addresses(lan_loopback):
    fake = FakeOllama()
    try:
        with pytest.raises(SendNotAllowed, match="не подтверждены") as e:
            lan_client(fake.url, confirmed=()).version()
        assert e.value.note == llm_net.CONFIRM_NOTE and fake.paths() == []
        with pytest.raises(SendNotAllowed, match="подтверждены 10.1.1.1"):
            lan_client(fake.url, confirmed=("10.1.1.1",)).version()
        assert fake.paths() == []
        assert lan_client(fake.url).version() == fake.version
    finally:
        fake.close()


def test_unknown_trust_class_is_refused_by_client_and_profile_choice(tmp_path: Path, mask_key: bytes):
    client = OllamaClient("http://127.0.0.1:9")
    client.trust = "external"
    with pytest.raises(LlmError, match="Класс доверия «external» не поддерживается"):
        client.version()
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.db.ensure_default_profile(fake.url, MODEL)
        with env.db._tx() as c:
            c.execute("UPDATE llm_providers SET trust = 'external' WHERE id = 1")
        with pytest.raises(ProfileError, match="не поддерживаются"):
            choose_profile(env.db, env.settings)
        with pytest.raises(ProfileInvalid):
            update_profile(env.db, 1, {"trust": "external"})
    finally:
        env.close()
        fake.close()


def test_local_trust_is_unchanged():
    client = OllamaClient("http://10.0.0.5:11434")  # local: адрес другого компьютера – отказ, как в ADR-0001
    with pytest.raises(LlmError, match="не входит в разрешённые"):
        client.version()


# ============================================================================ ключ

def test_key_file_binding_and_hint(tmp_path: Path):
    with pytest.raises(KeyRejected):
        save_key(keys_for(tmp_path), 2, "с пробелом и кириллицей", "http://10.0.0.5:11434", ["10.0.0.5"])
    save_key(keys_for(tmp_path), 2, SECRET, "http://10.0.0.5:11434/", ["10.0.0.5"])
    assert load_key(keys_for(tmp_path), 2)["base_url"] == "http://10.0.0.5:11434"
    assert key_hint(keys_for(tmp_path), 2) == "задан, …" + SECRET[-4:]
    assert auth_headers(keys_for(tmp_path), 2, "http://10.0.0.5:11434", ["10.0.0.5"]) == {"Authorization": f"Bearer {SECRET}"}
    with pytest.raises(SendNotAllowed) as e:
        auth_headers(keys_for(tmp_path), 2, "http://10.0.0.6:11434", ["10.0.0.6"])
    assert e.value.note == KEY_NOTE_OTHER
    with pytest.raises(SendNotAllowed, match="не задан"):
        auth_headers(keys_for(tmp_path), 3, "http://10.0.0.5:11434", ["10.0.0.5"])
    assert delete_key(keys_for(tmp_path), 2) and load_key(keys_for(tmp_path), 2) is None and key_hint(keys_for(tmp_path), 2) == ""
    assert not list((tmp_path / "providers").glob("*.tmp")), "временных файлов не остаётся"


def test_profile_changes_delete_the_key(tmp_path: Path, mask_key: bytes, lan_loopback):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        pid = lan_profile(env.db, fake.url, auth="bearer")
        data = env.db
        save_key(data, pid, SECRET, fake.url, ["127.0.0.1"])
        update_profile(env.db, pid, {"name": "Другое имя"})
        assert load_key(data, pid), "имя – не адрес: ключ остаётся"
        update_profile(env.db, pid, {"confirmed_addresses": ["127.0.0.1", "10.0.0.9"]})
        assert load_key(data, pid) is None, "сменились подтверждённые адреса – ключ удалён"
        save_key(data, pid, SECRET, fake.url, ["127.0.0.1", "10.0.0.9"])
        update_profile(env.db, pid, {"base_url": fake.url.replace("127.0.0.1", "localhost")})
        assert load_key(data, pid) is None, "сменился адрес – ключ удалён"
        save_key(data, pid, SECRET, fake.url, ["127.0.0.1"])
        before = env.db.get_provider(pid)["version"]
        update_profile(env.db, pid, {"enabled": 0})
        assert load_key(data, pid) is None and env.db.get_provider(pid)["version"] == before + 1
    finally:
        env.close()
        fake.close()


def test_lan_run_sends_the_key_and_the_journal_never_keeps_it(tmp_path: Path, mask_key: bytes, lan_loopback):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(env.db, pid, SECRET, fake.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        run = env.run(MODEL)
        assert run["state"] == "done", run["last_error"]
        assert fake.headers and all(h.get("Authorization") == f"Bearer {SECRET}" for h in fake.headers)
        events = [json.loads(line) for f in journal_dir.glob("*.jsonl") for line in f.read_text("utf-8").splitlines()]
        assert events and any(e.get("request_wire") for e in events)
        text = json.dumps(events, ensure_ascii=False)
        assert SECRET not in text and base64.b64encode(SECRET.encode()).decode()[:16] not in text
        assert "authorization" not in text.lower()
        requests = [e for e in events if e["event"] == "request"]
        assert all(e.get("provider", {}).get("id") == pid and e["provider"]["trust"] == "lan" for e in requests)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from model_traffic import verify_events  # scripts/model_traffic.py: длины и контрольные суммы
        assert verify_events(events) == []
    finally:
        model_traffic.set_recorder(None)
        env.close()
        fake.close()


def test_journal_redacts_the_key_in_error_stream_and_partial_branches(tmp_path: Path):
    """Ошибка HTTP, обрыв соединения и потоковый ответ: в журнале нет ни заголовка, ни ключа; контрольные суммы
    сходятся по очищенным байтам."""
    fake = FakeOllama(answers=[("http", 500, {"error": "boom"}), ("drop",)])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {SECRET}"}
        for _ in range(2):
            with pytest.raises(LlmError):
                client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {}, progress=lambda event: None)
        events = [json.loads(line) for f in journal_dir.glob("*.jsonl") for line in f.read_text("utf-8").splitlines()]
        kinds = {e["event"] for e in events}
        assert {"request", "response", "error"} <= kinds
        text = json.dumps(events, ensure_ascii=False)
        assert SECRET not in text and "authorization" not in text.lower()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from model_traffic import verify_events
        assert verify_events(events) == []
    finally:
        model_traffic.set_recorder(None)
        fake.close()


def test_redact_wire_handles_partial_requests():
    full = (b"POST /api/chat HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + SECRET.encode()
            + b"\r\nContent-Type: application/json\r\n\r\n{\"a\": \"Authorization: in body\"}")
    cleaned = redact_wire(full)
    assert SECRET.encode() not in cleaned and b"Authorization: in body" in cleaned, "тело не трогается"
    assert cleaned.startswith(b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Type")
    cut = full[:full.index(SECRET.encode()) + 5]  # запрос оборвался посреди ключа
    assert SECRET.encode()[:5] not in redact_wire(cut)
    assert redact_wire(b"POST / HTTP/1.1\r\nAuthoriz") == b"POST / HTTP/1.1"  # оборвался на имени заголовка
    assert redact_headers({"Authorization": "x", "Proxy-Authorization": "y", "Accept": "z"}) == {"Accept": "z"}


# ============================================================================ привязка ключа и подтверждение в прогоне

def test_snapshot_of_server_a_does_not_send_the_key_of_server_b(tmp_path: Path, mask_key: bytes, lan_loopback):
    """Снимок прогона указывает на сервер А; профиль перевели на Б и задали ключ Б: исполнение по снимку А ключ Б не
    отправляет и останавливается с причиной; «Продолжить» – новый прогон на Б."""
    fake_a, fake_b = FakeOllama(), FakeOllama()
    env = started(tmp_path, fake_a, mask_key)
    try:
        env.load([sast("A", 15)])
        data = env.db
        pid = lan_profile(env.db, fake_a.url, auth="bearer")
        save_key(data, pid, SECRET, fake_a.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        run_id = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"],
                                   execution=run_execution(env.db, env.settings, MODEL,
                                                           env.db.get_project(env.project_id)))
        env.db.set_run_state(run_id, "paused")
        update_profile(env.db, pid, {"base_url": fake_b.url})
        save_key(data, pid, SECRET + "B", fake_b.url, ["127.0.0.1"])
        assert env.runner.resume(run_id)
        env.runner.start()
        run = wait_state(env.db, run_id, ("paused", "done", "error"))
        assert run["state"] == "paused" and fake_a.paths() == [] and fake_b.paths() == []
        assert "Адрес профиля" in env.runner.continuation_reason(run) or "другого адреса" in run["last_error"]
        new_id = env.runner.continue_as_new(run_id)
        assert wait_state(env.db, new_id, ("done", "error", "paused"))["state"] == "done"
        assert fake_b.headers and all(h.get("Authorization") == f"Bearer {SECRET}B" for h in fake_b.headers)
        assert fake_a.paths() == []
    finally:
        env.close()
        fake_a.close()
        fake_b.close()


def test_key_rotation_applies_to_an_unfinished_execution(tmp_path: Path, mask_key: bytes, lan_loopback):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        data = env.db
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(data, pid, SECRET, fake.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        run_id = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"],
                                   execution=run_execution(env.db, env.settings, MODEL,
                                                           env.db.get_project(env.project_id)))
        env.db.set_run_state(run_id, "paused")
        save_key(data, pid, SECRET + "R", fake.url, ["127.0.0.1"])  # ротация при прежнем адресе
        assert env.runner.resume(run_id)
        env.runner.start()
        assert wait_state(env.db, run_id, ("done", "error", "paused"))["state"] == "done"
        assert fake.headers and all(h.get("Authorization") == f"Bearer {SECRET}R" for h in fake.headers)
    finally:
        env.close()
        fake.close()


def test_unconfirmed_address_pauses_and_new_confirmation_continues_as_a_new_run(tmp_path: Path, mask_key: bytes,
                                                                                 lan_loopback):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url, confirmed=("10.1.1.1",))
        use(env.db, env.project_id, pid)
        run = env.run(MODEL)
        assert run["state"] == "paused" and llm_net.CONFIRM_NOTE in run["last_error"] and fake.chats() == []
        update_profile(env.db, pid, {"confirmed_addresses": ["127.0.0.1"]})
        assert "Подтверждённые адреса" in env.runner.continuation_reason(env.db.get_run(run["id"]))
        with pytest.raises(Exception, match="Подтверждённые адреса"):
            env.runner.retry_errors(run["id"], ["A"])
        new_id = env.runner.continue_as_new(run["id"])
        assert wait_state(env.db, new_id, ("done", "error", "paused"))["state"] == "done"
    finally:
        env.close()
        fake.close()


def test_withdrawn_confirmation_stops_an_unfinished_execution(tmp_path: Path, mask_key: bytes, lan_loopback):
    """Оператор снял подтверждение адреса: незавершённое исполнение по прежнему снимку туда больше не отправляет."""
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url)
        use(env.db, env.project_id, pid)
        run_id = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"],
                                   execution=run_execution(env.db, env.settings, MODEL,
                                                           env.db.get_project(env.project_id)))
        env.db.set_run_state(run_id, "paused")
        with env.db._tx() as c:  # подтверждение снято (без новой версии – проверяется сам запрос)
            c.execute("UPDATE llm_providers SET confirmed_addresses_json = '[]' WHERE id = ?", (pid,))
        assert env.runner.resume(run_id)
        env.runner.start()
        run = wait_state(env.db, run_id, ("paused", "done", "error"))
        assert run["state"] == "paused" and fake.chats() == []
    finally:
        env.close()
        fake.close()


# ============================================================================ пробная генерация

def test_probe_generation_takes_the_generation_right():
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)
        assert GENERATION.try_acquire("triage")
        try:
            with pytest.raises(ProbeBusy):
                probe_generation(client, MODEL)
            assert fake.chats() == []
        finally:
            GENERATION.release()
        seconds = probe_generation(client, MODEL)
        assert seconds >= 0 and len(fake.chats()) == 1 and GENERATION.busy() == ""
        assert fake.chats()[0]["options"]["num_predict"] == 8
    finally:
        fake.close()



# ============================================================================ по ревью шага 6

def test_profile_edit_waits_for_a_request_that_was_already_admitted(tmp_path: Path, mask_key: bytes, lan_loopback,
                                                                     monkeypatch):
    """Запрос прошёл допуск и разрешает имя; оператор в это время снимает подтверждение: правка ждёт, пока запрос
    допишет байты (он был допущен до правки), а следующий запрос видит правку целиком и не уходит."""
    import threading

    from app import profile_gate
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        pid = lan_profile(env.db, fake.url)
        client = OllamaClient(fake.url)
        client.trust = "lan"
        client.confirmed = lambda: tuple(json.loads(env.db.get_provider(pid)["confirmed_addresses_json"]))
        client.gate = profile_gate.gate(pid).read
        resolving, release = threading.Event(), threading.Event()
        real = llm_net._getaddrinfo

        def slow(host, port, timeout, trust="local"):
            resolving.set()
            release.wait(5)
            return real(host, port, timeout, trust)

        monkeypatch.setattr(llm_net, "_getaddrinfo", slow)
        result = {}
        worker = threading.Thread(target=lambda: result.update(v=client.version()))
        worker.start()
        assert resolving.wait(5)
        done = threading.Event()
        editor = threading.Thread(target=lambda: (update_profile(env.db, pid,
                                                                  {"confirmed_addresses": []}), done.set()))
        editor.start()
        assert not done.wait(0.3), "правка ждёт допущенный запрос"
        release.set()
        worker.join(5)
        editor.join(5)
        assert result.get("v") == fake.version and done.is_set()
        monkeypatch.setattr(llm_net, "_getaddrinfo", real)
        before = len(fake.paths())
        with pytest.raises(SendNotAllowed):
            client.version()
        assert len(fake.paths()) == before, "после правки запрос не ушёл"
    finally:
        env.close()
        fake.close()


def test_request_started_during_an_edit_sees_the_edit(tmp_path: Path, mask_key: bytes, lan_loopback):
    import threading

    from app import profile_gate
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        pid = lan_profile(env.db, fake.url)
        client = OllamaClient(fake.url)
        client.trust = "lan"
        client.confirmed = lambda: tuple(json.loads(env.db.get_provider(pid)["confirmed_addresses_json"]))
        client.gate = profile_gate.gate(pid).read
        outcome = {}
        with profile_gate.gate(pid).write():  # правка идёт
            worker = threading.Thread(target=lambda: outcome.update(e=_try(client.version)))
            worker.start()
            worker.join(0.3)
            assert worker.is_alive(), "запрос ждёт конца правки"
            with env.db._tx() as c:
                c.execute("UPDATE llm_providers SET confirmed_addresses_json = '[]' WHERE id = ?", (pid,))
        worker.join(5)
        assert isinstance(outcome["e"], SendNotAllowed) and fake.paths() == []
    finally:
        env.close()
        fake.close()


def _try(call):
    try:
        return call()
    except Exception as e:  # noqa: BLE001 – тест сравнивает тип отказа
        return e


def test_key_reflected_by_the_server_is_scrubbed_in_the_app_and_kept_in_the_journal(tmp_path: Path):
    """Шлюз возвращает переданный ключ в тексте ошибки или в ответе: ключа нет ни в исключении, ни в разобранном
    ответе; журнал обмена хранит обмен байт в байт – отражённый ключ в теле ответа есть, а
    заголовка авторизации запроса нет."""
    fake = FakeOllama(answers=[("http", 401, {"error": f"invalid token {SECRET}"}),
                               ("http", 200, {"model": MODEL, "message": {"role": "assistant",
                                                                          "content": f"echo Bearer {SECRET}"},
                                              "done": True})])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {SECRET}"}
        with pytest.raises(LlmError) as e:
            client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        assert SECRET not in str(e.value) and SECRET not in e.value.detail
        echoed = client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        assert SECRET not in json.dumps(echoed) and "***" in echoed["message"]["content"]
        events = [json.loads(line) for f in journal_dir.glob("*.jsonl") for line in f.read_text("utf-8").splitlines()]
        responses = [e for e in events if e["event"] == "response"]
        assert responses and all(SECRET in e["body"] for e in responses), "ответ сервера – байт в байт"
        assert not any("Authorization" in e.get("request_headers", {}) or "Authorization" in e.get("request_wire", "")
                       for e in events), "заголовок авторизации запроса вырезан"
        assert all(SECRET not in json.dumps(e.get("request_headers", {})) + e.get("request_wire", "") for e in events)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from model_traffic import verify_events
        assert verify_events(events) == []
    finally:
        model_traffic.set_recorder(None)
        fake.close()


def test_page_and_background_clients_keep_lan_rules_key_and_admission(tmp_path: Path, mask_key: bytes, lan_loopback):
    """Служебные запросы страниц и наблюдения к профилю lan: ключ с привязкой, действующие подтверждения, допуск;
    сервер, запрошенный страницей, остаётся сервером (Server), а не кортежем."""
    from app.executors import Server, server_of
    from app.routes.common import compute_metrics, compute_models
    from app.telemetry import Telemetry
    fake = FakeOllama(loaded=[MODEL])
    env = started(tmp_path, fake, mask_key)
    try:
        data = env.db
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(data, pid, SECRET, fake.url, ["127.0.0.1"])
        server = server_of(env.db.get_provider(pid))
        models = compute_models(OllamaClient, server, env.db)
        assert models["error"] == "" and fake.headers[-1].get("Authorization") == f"Bearer {SECRET}"
        observer = Telemetry(tmp_path / "obs", lambda: {})
        observer.want(server)
        assert all(isinstance(k, Server) for k in observer.wanted()), "очередь хранит сервер целиком"
        observer.close()
        with env.db._tx() as c:  # подтверждение снято: служебный опрос туда больше не идёт
            c.execute("UPDATE llm_providers SET confirmed_addresses_json = '[]' WHERE id = ?", (pid,))
        before = len(fake.paths())
        assert compute_metrics(OllamaClient, server, env.db)["error"]
        assert compute_models(OllamaClient, server, env.db)["error"]
        assert len(fake.paths()) == before
        with env.db._tx() as c:
            c.execute("UPDATE llm_providers SET confirmed_addresses_json = '[\"127.0.0.1\"]', enabled = 0"
                      " WHERE id = ?", (pid,))
        assert "выключен" in compute_models(OllamaClient, server, env.db)["error"]
        assert len(fake.paths()) == before
    finally:
        env.close()
        fake.close()


def test_failed_key_deletion_keeps_the_profile_unchanged(tmp_path: Path, mask_key: bytes, lan_loopback, monkeypatch):
    from app import providers
    from app.providers import set_key
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        data = env.db
        pid = lan_profile(env.db, fake.url, auth="bearer")
        set_key(env.db, pid, SECRET)
        assert load_key(data, pid)["base_url"] == fake.url, "ключ привязан к адресу профиля"
        version = env.db.get_provider(pid)["version"]

        def broken(*args, **kwargs):
            raise PermissionError("занято")

        monkeypatch.setattr(providers, "delete_key", broken)
        with pytest.raises(ProfileInvalid, match="не удалось удалить"):
            update_profile(env.db, pid, {"confirmed_addresses": ["127.0.0.1", "10.0.0.7"]})
        assert env.db.get_provider(pid)["version"] == version and load_key(data, pid), "правка не записана"
    finally:
        env.close()
        fake.close()


@pytest.mark.parametrize("answer", [("http", 200, {"error": "model failed"}), ("http", 200, {}),
                                    ("http", 200, {"message": {"role": "assistant", "content": ""}})])
def test_probe_fails_without_a_model_answer(answer):
    fake = FakeOllama(answers=[answer])
    try:
        with pytest.raises(LlmError, match="Пробная генерация не удалась"):
            probe_generation(OllamaClient(fake.url), MODEL)
        assert GENERATION.busy() == ""
    finally:
        fake.close()


def test_probe_checks_admission():
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)

        def refuse():
            raise SendNotAllowed("выключен")

        client.before_send = refuse
        with pytest.raises(SendNotAllowed):
            probe_generation(client, MODEL)
        assert fake.paths() == []
    finally:
        fake.close()



# ============================================================================ по ревью шага 6, круг 2

def test_key_charset_is_token68():
    from app.provider_keys import KeyRejected, save_key
    for bad in ('demo"key123', "demo\\key123", "ключ12345678", "has space 1"):
        with pytest.raises(KeyRejected):
            save_key(Path("unused"), 9, bad, "http://10.0.0.5:11434", ["10.0.0.5"])


def test_escaped_and_stream_split_key_is_scrubbed(tmp_path: Path):
    """Ключ с «/»: шлюз возвращает его экранированным «\\/»; потоковый ответ дробит ключ между строками NDJSON. Ключа
    нет ни в исключении, ни в собранном ответе (журнал обмена хранит обмен байт в байт)."""
    key = "abc/def+ghi/jkl_mno~pqr=" * 2
    escaped = key.replace("/", "\\/")
    fake = FakeOllama(answers=[("http", 401, '{"error":"invalid token ' + escaped + '"}'), "echo " + key])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        with pytest.raises(LlmError) as e:
            client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        assert key not in str(e.value) and key not in e.value.detail
        result = client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": True},
                                 progress=lambda event: None)
        assert key not in json.dumps(result) and "***" in result["message"]["content"]
        text = "".join(f.read_text("utf-8") for f in journal_dir.glob("*.jsonl"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from model_traffic import verify_events
        assert verify_events([json.loads(line) for line in text.splitlines()]) == []
    finally:
        model_traffic.set_recorder(None)
        fake.close()


def test_settings_save_decides_inside_the_gate(tmp_path: Path, mask_key: bytes):
    """Сохранение «Настроек» со снимком, где адрес «не менялся», а профиль 1 в базе уже на другом адресе: решение – по
    базе внутри блокировки, ключ профиля 1 удаляется, профиль получает адрес из формы."""
    from app import settings_store
    from app.provider_keys import save_key as store_key
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.db.ensure_default_profile(fake.url, MODEL)
        data = env.db
        env.db.update_provider(1, {"base_url": "http://127.0.0.1:9"})  # другое сохранение успело сменить адрес
        store_key(data, 1, SECRET, "http://127.0.0.1:9", [])
        current = env.settings.with_stored(env.db.get_settings())
        clean = {"ollama_url": current.ollama_url, "default_model": current.default_model}
        settings_store.save(env.db, current, clean)
        assert env.db.get_provider(1)["base_url"] == current.ollama_url and load_key(data, 1) is None
    finally:
        env.close()
        fake.close()


def test_send_and_handshake_use_a_short_timeout():
    from app.llm_net import SEND_TIMEOUT_S, _PinnedHTTPConnection, _Watchdog
    import time as _time

    class Sock:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, value):
            self.timeouts.append(value)

        def sendall(self, data):
            pass

    deadline = _time.monotonic() + 2400
    watchdog = _Watchdog(deadline)
    conn = _PinnedHTTPConnection("127.0.0.1", 9, [], deadline, watchdog)
    conn.sock = Sock()
    conn.send(b"x")
    watchdog.cancel()
    assert conn.sock.timeouts and conn.sock.timeouts[-1] <= SEND_TIMEOUT_S


def test_question_preflight_respects_a_disabled_profile(tmp_path: Path, mask_key: bytes, monkeypatch):
    """Профиль выключили после выбора профиля вопроса: предварительный запрос сведений о модели не уходит."""
    from app import ask
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run(MODEL)["state"] == "done"
        before = len(fake.paths())
        real = ask.question_profile

        def chosen_then_disabled(*args, **kwargs):
            profile = real(*args, **kwargs)
            with env.db._tx() as c:
                c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (profile["id"],))
            return profile

        monkeypatch.setattr(ask, "question_profile", chosen_then_disabled)
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        assert q["state"] == "error" and "выключен" in q["error"] and len(fake.paths()) == before
    finally:
        env.close()
        fake.close()


@pytest.mark.parametrize("answer", [("http", 200, {"message": {"content": 1}, "done": True}),
                                    ("http", 200, {"message": {"content": "да"}, "done": False})])
def test_probe_rejects_malformed_answers(answer):
    fake = FakeOllama(answers=[answer])
    try:
        with pytest.raises(LlmError, match="Пробная генерация не удалась"):
            probe_generation(OllamaClient(fake.url), MODEL)
    finally:
        fake.close()


def test_remember_without_point_keeps_the_series_to_record(tmp_path: Path):
    from app.telemetry import Telemetry
    observer = Telemetry(tmp_path, lambda: {})
    server = ("http://127.0.0.1:11434", True)
    observer.remember(server, {"gpu": None, "models": [], "vram_used_mb": 5}, point=False)
    assert observer.history("15m") == [] and observer.server_snapshot(server)
    observer.record({"gpu": None, "models": [], "vram_used_mb": 6, "server": {"base_url": server[0], "local": True}})
    assert [p["vram"] for p in observer.history("15m")] == [6]
    observer.close()



# ============================================================================ по ревью: круг 4 шага 6

def test_key_in_unicode_escapes_inner_json_and_broken_stream_is_scrubbed(tmp_path: Path):
    """Сервер с ключом отражает ключ: в \\uXXXX тела ошибки; во внутреннем JSON ответа модели под экранированием; в
    оборванных потоках (части ключа в одном канале с текстом другого канала между ними, недописанная строка с
    экранированным именем поля, одноимённое постороннее поле); в успешном потоке, разбитым между строками. Ни в
    исключении, ни в ответе приложению ключа нет; журнал обмена хранит обмен байт в байт."""
    key = "demoKey123abcXYZ789"
    escaped = "\\u0064" + key[1:]
    several = "".join(f"\\u{ord(c):04x}" for c in key[:3]) + key[3:]  # несколько знаков в экранировании
    inner = '{"verdict": "' + several + '"}'  # модель вернула JSON, в котором ключ экранирован
    first = json.dumps({"message": {"content": key[:4], "thinking": "x"}, "done": False})
    second = json.dumps({"message": {"content": key[4:]}, "done": False})
    foreign = json.dumps({"message": {"content": key[:4]}, "content": "x", "done": False})
    fake = FakeOllama(answers=[
        ("http", 401, '{"error":"invalid token ' + escaped + '"}'), inner, inner,
        ("ndjson", first + "\n" + second + "\n"),
        ("ndjson", first + "\n" + '{"message":{"\\u0063ontent":"' + key[4:]),
        ("ndjson", foreign + "\n" + second + "\n"),
        ("ndjson", first + "\n" + second + "\n" + json.dumps({"message": {"content": ""}, "done": True}) + "\n"),
    ])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        with pytest.raises(LlmError) as e:
            client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        assert key not in str(e.value) and key not in e.value.detail
        # текст ответа с ключом скрывается целиком – не JSON, обе попытки не по формату: ошибка без ключа
        with pytest.raises(LlmError) as e2:
            client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {})
        assert key not in str(e2.value) and key not in (e2.value.raw or "") and key not in e2.value.detail
        for _ in range(3):  # оборванные потоки
            with pytest.raises(LlmError) as e3:
                client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {}, progress=lambda event: None)
            assert key not in str(e3.value) and key not in (e3.value.detail or "")
        done = client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": True},
                               progress=lambda event: None)
        assert key not in json.dumps(done, ensure_ascii=False), "успешный поток: собранный текст без ключа"
        assert len(fake.chats()) == 7
        # журнал обмена – байт в байт: оборванные потоки – с принятыми байтами
        text = "".join(f.read_text("utf-8") for f in journal_dir.glob("*.jsonl"))
        events = [json.loads(line) for line in text.splitlines()]
        assert len([ev for ev in events if ev["event"] == "error" and ev.get("received")]) == 3
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from model_traffic import verify_events
        assert verify_events(events) == []
    finally:
        model_traffic.set_recorder(None)
        fake.close()
    assert model_traffic.scrub_text("x " + escaped, [key]).startswith("[текст скрыт")


def _layered(text: str, times: int) -> str:
    for _ in range(times):
        text = json.dumps(text)
    return text


@pytest.mark.parametrize("body", [
    lambda k: json.dumps({"message": {"content": json.dumps({"v": "\\u0064" + k[1:]})}}),  # JSON в строке JSON
    lambda k: json.dumps(json.dumps({"v": "\\u0064\\u0065" + k[2:]})),
    # строка JSON в строке JSON шесть раз, внутри – экранирование: каждое вложение раскрывается
    lambda k: json.dumps({"message": {"content": _layered("\\u0064\\u0065" + k[2:], 6)}, "done": True}),
    lambda k: json.dumps({"message": {"content": "\\u0064" + k[1:]}}, indent=2),  # JSON на нескольких строках
    lambda k: "<html>token=\\\\u0064" + k[1:] + "</html>",  # не JSON: слои экранирования
    lambda k: json.dumps({"\\u0064" + k[1:]: 1}),  # имя поля
])
def test_contains_secret_finds_the_key_after_decoding(body):
    key = "demoKey123abcXYZ789"
    assert model_traffic.contains_secret(body(key).encode(), [key])
    assert not model_traffic.contains_secret(body("otherVal123abcXYZ7").encode(), [key])


def test_contains_secret_does_not_join_unrelated_fields_and_fails_closed_when_too_deep(monkeypatch):
    """Разные поля не склеиваются; вложений больше предела – ключ считается видимым (на пределе 3: строки JSON в
    строке JSON удваивают экранирование, на пределе 32 такой текст огромен)."""
    key = "demoKey123"
    assert not model_traffic.contains_secret(json.dumps({"a": "demo", "b": "Key123"}), [key]), \
        "значения разных полей не склеиваются: ложного скрытия нет"
    monkeypatch.setattr(model_traffic, "DECODE_DEPTH", 3)
    assert not model_traffic.contains_secret(_layered("ничего", 2), [key])
    assert model_traffic.contains_secret(_layered("ничего", 6), [key]), "глубже предела – ключ считается видимым"
    assert not model_traffic.contains_secret(_layered("ничего", 6), []), "без ключа проверка не нужна"


def test_contains_secret_is_cheap_on_large_bodies():
    import time as _time
    key = "demoKey123abcXYZ789"
    started = _time.perf_counter()
    for body in (b"\n" * (1 << 20), json.dumps({"message": {"content": "строка\n" * 150_000}}).encode(),
                 ("\\u0041" * 200_000).encode()):
        assert not model_traffic.contains_secret(body, [key])
    # раскрытие, которое снимает по слою и почти не укорачивает текст, и тысячи мелких разборов – упираются в бюджет
    # работы: ключ считается видимым (тело не сохраняется), без долгой работы и без удержания промежуточных строк
    chain = "\\u005c" + "u005c" * 33 + "x" * (1 << 20)
    assert model_traffic.contains_secret(chain, [key])
    assert model_traffic.contains_secret("[" + ",".join(['"[]"'] * 209_715) + "]", [key])
    assert _time.perf_counter() - started < 5, "мегабайтные тела – в пределах бюджета работы"


def test_connect_and_tls_set_the_short_send_timeout(monkeypatch):
    """HTTP: соединение и передача запроса – с коротким сроком. HTTPS: рукопожатие – со сроком соединения, затем
    передача – с коротким сроком (подменённые сокет и TLS-обёртка, без настоящего TLS)."""
    import time as _time
    from app.llm_net import CONNECT_TIMEOUT_S, SEND_TIMEOUT_S, _PinnedHTTPConnection, _PinnedHTTPSConnection, _Watchdog

    class Sock:
        def __init__(self):
            self.timeouts = []
            self.handshakes = 0

        def settimeout(self, value):
            self.timeouts.append(value)

        def do_handshake(self):
            self.handshakes += 1

    sock, tls = Sock(), Sock()

    class Context:
        def wrap_socket(self, raw, server_hostname, do_handshake_on_connect):
            assert raw is sock and server_hostname == "model.lan" and do_handshake_on_connect is False
            return tls

    monkeypatch.setattr(llm_net, "_connect_any", lambda entries, deadline: sock)
    monkeypatch.setattr(llm_net.ssl, "create_default_context", lambda: Context())
    deadline = _time.monotonic() + 2400
    watchdog = _Watchdog(deadline)
    try:
        _PinnedHTTPConnection("127.0.0.1", 9, [], deadline, watchdog).connect()
        assert sock.timeouts and sock.timeouts[-1] <= SEND_TIMEOUT_S
        https = _PinnedHTTPSConnection("model.lan", 443, [], deadline, watchdog)
        https.connect()
    finally:
        watchdog.cancel()
    assert https.sock is tls and tls.handshakes == 1
    assert tls.timeouts == [CONNECT_TIMEOUT_S, SEND_TIMEOUT_S], "рукопожатие – срок соединения, передача – короткий"


def test_waiting_for_the_profile_gate_is_bounded():
    import threading
    from app.profile_gate import ProfileGate
    gate = ProfileGate()
    held, release = threading.Event(), threading.Event()

    def writer():
        with gate.write():
            held.set()
            release.wait(5)

    worker = threading.Thread(target=writer)
    worker.start()
    assert held.wait(5)
    with pytest.raises(TimeoutError):
        with gate.read(timeout=0.1):
            pass
    release.set()
    worker.join(5)
    with gate.read(timeout=0.1):
        pass
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)

        class Busy:
            def __enter__(self):
                raise TimeoutError

            def __exit__(self, *args):
                return False

        client.gate = Busy
        with pytest.raises(LlmError, match="слишком долго правится"):
            client.version()
        assert fake.paths() == []
    finally:
        fake.close()


def test_save_profile_binds_the_key_to_what_it_wrote(tmp_path: Path, mask_key: bytes, lan_loopback):
    from app.providers import save_profile
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        data = env.db
        saved, dropped = save_profile(env.db, None, {"name": "П", "trust": "lan", "base_url": fake.url,
                                                           "confirmed_addresses": ["127.0.0.1"]},
                                      key=SECRET, requires_key=True)
        assert saved["auth"] == "bearer" and load_key(data, saved["id"])["base_url"] == fake.url and not dropped
        moved, dropped = save_profile(env.db, saved["id"],
                                      {"base_url": fake.url.replace("127.0.0.1", "localhost")}, requires_key=True)
        assert dropped and load_key(data, saved["id"]) is None and moved["auth"] == "bearer"
        plain, _ = save_profile(env.db, saved["id"], {}, requires_key=False)
        assert plain["auth"] == "none", "ключ больше не нужен – вход без ключа"
    finally:
        env.close()
        fake.close()


@pytest.mark.parametrize("listed", [[], "thinking", 7, None])
def test_capabilities_not_a_list_fall_back_to_show_everywhere(listed):
    """Пустой список или иной вид capabilities в /api/tags: и сведения о модели, и список моделей берут возможности
    из /api/show – одно правило (capability_list)."""
    from fake_ollama import model_entry
    entry = model_entry("thinker:1b", capabilities=())
    entry["capabilities"] = listed
    entry["show_capabilities"] = ["completion", "thinking"]
    fake = FakeOllama(models=[entry])
    try:
        client = OllamaClient(fake.url)
        info = client.model_info("thinker:1b")["capabilities"]
        listed_caps = next(m for m in client.list_models() if m["name"] == "thinker:1b")["capabilities"]
        assert info == listed_caps == ["completion", "thinking"]
    finally:
        fake.close()


def test_probe_requires_a_finished_answer():
    fake = FakeOllama(answers=[("http", 200, {"message": {"content": "да"}})])
    try:
        with pytest.raises(LlmError, match="Пробная генерация не удалась"):
            probe_generation(OllamaClient(fake.url), MODEL)
    finally:
        fake.close()


@pytest.mark.parametrize(("reply", "warm"), [({}, False), ({"error": "out of memory"}, False),
                                             ({"done": False}, False), ({"done": True, "done_reason": "load"}, True)])
def test_warmup_requires_a_confirmed_load(monkeypatch, reply, warm):
    """Прогрев засчитывается только по ответу с done = true без ошибки: HTTP 200 с пустым объектом или ошибкой – не
    «warm»."""
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)
        real = client._request
        monkeypatch.setattr(client, "_request", lambda path, body=None, **kw: reply if path == "/api/generate"
                            else real(path, body, **kw))
        if warm:
            client.warm_model(MODEL, 8192)
        else:
            with pytest.raises(LlmError, match="не прогрета"):
                client.warm_model(MODEL, 8192)
    finally:
        fake.close()


# ============================================================================ по ревью: круг 7 шага 6

def test_server_with_key_answer_to_the_app_is_cleaned(tmp_path: Path):
    """Сервер с ключом: повторяющееся поле с экранированным ключом проверка видит; имя поля с ключом скрыто в ответе
    приложению; имя модели не строкой из /api/tags не уходит в следующий запрос /api/show."""
    key = "demoKey123abcXYZ789"
    escaped = "\\u0064" + key[1:]
    duplicate = '{"message":{"content":"' + escaped + '","content":"ok"},"done":true}'
    odd = {"name": {key: 1}, "model": "x", "details": {}}  # имя – объект: старая Ollama без capabilities
    fake = FakeOllama(models=[odd, "qwen2.5-coder:14b"],
                      answers=[("http", 200, duplicate), ("http", 200, {escaped: 1, "done": True})])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        assert model_traffic.contains_secret(duplicate, [key]), "повторяющееся поле не теряется при проверке"
        chat = {"model": MODEL, "messages": MESSAGES, "stream": False}
        assert client._request("/api/chat", chat)["message"]["content"] == "ok"
        assert model_traffic.HIDDEN_NAME in client._request("/api/chat", chat)
        assert [m["name"] for m in client.list_models()] == ["qwen2.5-coder:14b"], "имя модели не строкой отброшено"
        assert all(key not in json.dumps(b or {}, ensure_ascii=False) for _, path, b in fake.requests
                   if path == "/api/show")
    finally:
        model_traffic.set_recorder(None)
        fake.close()




def test_server_without_key_journal_is_unchanged(tmp_path: Path):
    """Ollama этого компьютера (без ключа): журнал – байт в байт, как прежде."""
    recorder = Recorder(tmp_path)
    raw = b'{"version":"\\u0030.40.4","version":"0.40.4"}'
    event_id, ts = recorder.request(method="GET", url="http://127.0.0.1:11434/api/version")
    recorder.response(event_id=event_id, request_ts=ts, duration_ms=1, status=200, headers={"X-A": "b"}, body=raw)
    event = json.loads(next(tmp_path.glob("*.jsonl")).read_text("utf-8").splitlines()[1])
    assert event["body"] == raw.decode() and event["headers"] == {"X-A": "b"}


# ============================================================================ по ревью: круг 8 шага 6

def test_digit_key_in_counters_does_not_reach_stats_or_answer(tmp_path: Path):
    """Ключ из одних цифр (задан в обход проверки формата) в числовом поле завершающего кадра потока: ни в статистике
    ответа, ни в ответе приложению его нет."""
    key = "12345678"
    lines = [json.dumps({"message": {"content": '{"verdict": "ok"}'}, "done": False}),
             json.dumps({"message": {"content": ""}, "done": True, "eval_count": int(key), "prompt_eval_count": 10})]
    fake = FakeOllama(answers=[("ndjson", "\n".join(lines) + "\n")])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        obj, stats = client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {}, progress=lambda event: None)
        assert obj["verdict"] == "ok" and key not in json.dumps(stats.to_dict())
    finally:
        model_traffic.set_recorder(None)
        fake.close()
    assert model_traffic.clean_value({"n": 12345678, "m": 7, "f": 1.5, "b": True}, [key]) == \
        {"n": None, "m": 7, "f": 1.5, "b": True}


def test_lone_surrogate_in_answer_breaks_neither_exchange_nor_journal(tmp_path: Path):
    """Одиночный суррогат в ответе сервера с ключом: журнал пишет тело как прочитано, обмен не прерывается."""
    key = "demoKey123abcXYZ789"
    fake = FakeOllama(answers=[("http", 200, '{"message":{"content":"ok"},"extra":"\\ud800","done":true}')])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        answer = client._request("/api/chat", {"model": MODEL, "messages": MESSAGES, "stream": False})
        assert answer["message"]["content"] == "ok"
        events = [json.loads(line) for f in journal_dir.glob("*.jsonl") for line in f.read_text("utf-8").splitlines()]
        assert [e["event"] for e in events] == ["request", "response"] and "\\ud800" in events[1]["body"]
    finally:
        model_traffic.set_recorder(None)
        fake.close()


def test_cleaning_a_large_body_has_one_budget(tmp_path: Path):
    """Тело из тысяч мелких строк JSON: очистка для журнала и для ответа приложению – с общим бюджетом на тело, не
    по бюджету на каждую строку; оставшиеся после исчерпания строки скрываются без разбора."""
    import time as _time
    key = "demoKey123abcXYZ789"
    body = ("[" + ",".join(['"[]"'] * 209_715) + "]").encode()
    started = _time.perf_counter()
    cleaned = model_traffic.clean_value(json.loads(body), [key])
    assert _time.perf_counter() - started < 5
    assert model_traffic.HIDDEN_TEXT in cleaned
    assert model_traffic.clean_value(["[]", "ok"], [key]) == ["[]", "ok"], "малое тело – без скрытия"


# ============================================================================ по ревью: круг 9 шага 6

def test_non_finite_numbers_do_not_carry_the_key(tmp_path: Path):
    """Ключ «Infinity» (8 знаков – допустим проверкой формата): не конечное число в ответе сервера с ключом
    очищается до null – в журнале потока литерала нет."""
    key = "Infinity"
    lines = [json.dumps({"message": {"content": '{"verdict": "ok"}'}, "done": False}),
             '{"message":{"content":""},"done":true,"eval_count":Infinity,"prompt_eval_count":NaN}']
    fake = FakeOllama(answers=[("ndjson", "\n".join(lines) + "\n")])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        obj, _ = client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {}, progress=lambda event: None)
        assert obj["verdict"] == "ok"
    finally:
        model_traffic.set_recorder(None)
        fake.close()
    assert model_traffic.clean_value([float("inf"), float("nan"), 1e16], ["demoKey123"]) == [None, None, 1e16]




# ============================================================================ по ревью: круг 10 шага 6





# ============================================================================ по ревью: круг 11 шага 6

def test_key_shorter_than_16_is_refused(tmp_path: Path):
    """Ключ короче 16 знаков не принимается: короткий ключ совпадал бы со словами ответов модели, и проверка ответа
    перед сохранением отвергала бы обычные ответы."""
    with pytest.raises(KeyRejected, match="от 16 до 4096"):
        save_key(keys_for(tmp_path), 7, "response", "http://10.0.0.5:11434", ["10.0.0.5"])
    save_key(keys_for(tmp_path), 7, "x" * 16, "http://10.0.0.5:11434", ["10.0.0.5"])
    assert load_key(keys_for(tmp_path), 7)["key"] == "x" * 16






# ============================================================================ по финальному ревью выпуска 0.9.12

def test_key_does_not_form_when_the_answer_is_serialized_or_cleaned(tmp_path: Path):
    """Ответ модели, где ключ собрался бы при сохранении: управляющий знак, который запись JSON вернёт как «\\u0001»,
    и невидимый знак между частями ключа, который уберёт очистка текста. Ни в разобранном ответе, ни в его записи JSON
    (как в базе: ensure_ascii=False и True) ключа нет."""
    key = "u0001xyzABCDEFGHIJ"  # 18 знаков – допустим проверкой формата
    content = json.dumps({"answer": "Ответ: \x01xyz\x41BCDEFGHIJ", "verdict_changes": "нет"})
    fake = FakeOllama(answers=[content, content])
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        client = OllamaClient(fake.url)
        client.auth = lambda: {"Authorization": f"Bearer {key}"}
        try:
            obj = client.chat_json(MODEL, MESSAGES, {"answer": "", "verdict_changes": ""}, ["answer"], {})[0]
        except LlmError as e:  # текст с ключом скрыт целиком – ответ не по формату: сохраняется только ошибка
            obj = {"error": str(e), "detail": e.detail, "raw": e.raw}
        for stored in (json.dumps(obj, ensure_ascii=False, sort_keys=True), json.dumps(obj)):
            assert key not in stored
    finally:
        model_traffic.set_recorder(None)
        fake.close()
    joined = "abcdefghijklmnop"
    assert model_traffic.scrub_text("x abcdefgh\u200bijklmnop", [joined]) == model_traffic.HIDDEN_TEXT, \
        "невидимый знак между частями ключа: очистка текста сомкнула бы их"
    assert model_traffic.scrub_text("обычный текст", [joined]) == "обычный текст"




def test_question_answer_stored_in_the_database_never_holds_the_key(tmp_path: Path, mask_key: bytes, lan_loopback):
    """Вопрос по находке профилем сервера с ключом, ответ модели с управляющим и невидимым знаком между частями
    ключа («\\u0001xyzAB\\u200bCDEFGHIJ»): очистка ответа (parse_ask) убирает невидимый знак, запись JSON в базе
    превращает управляющий в «\\u0001». В базе (questions) ключа нет."""
    from app import ask
    key = "u0001xyzABCDEFGHIJ"  # 18 знаков – допустим проверкой формата
    reply = {"answer": "Ответ: \x01xyzAB\u200bCDEFGHIJ", "verdict_changes": "нет"}
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(env.db, pid, key, fake.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        assert env.run(MODEL)["state"] == "done"  # разбор – сервером с ключом: вопрос пойдёт его профилем
        before = len(fake.headers)
        fake.answers.extend([json.dumps(reply)] * 2)  # текст ответа модели – JSON с экранированием знаков
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        assert fake.headers[before:] and all(h.get("Authorization") == f"Bearer {key}" for h in fake.headers[before:])
        rows = [dict(r) for r in env.db._all("SELECT * FROM questions ORDER BY 1, 2")]
        assert rows and q["state"] in ("done", "error")
        stored = json.dumps(rows, ensure_ascii=False) + json.dumps(rows)
        assert key not in stored, "ни в ответе, ни в тексте ошибки вопроса ключа нет"
    finally:
        model_traffic.set_recorder(None)
        env.close()
        fake.close()


@pytest.mark.parametrize("text", ["abcdefgh\u3164ijklmnop", "abcdefgh<b>ijklmnop", "abcdefgh\u200b\x01ijklmnop"])
def test_cleaning_that_would_join_the_key_is_seen_in_advance(text):
    """Заполнитель Хангыль (печатаем, но невидим), тег HTML (его снимает очистка для Hub), невидимый и управляющий
    знаки вместе: части ключа, которые сомкнёт очистка текста, находятся заранее."""
    key = "abcdefghijklmnop"
    assert model_traffic.scrub_text(text, [key]) == model_traffic.HIDDEN_TEXT


@pytest.mark.parametrize(("key", "said"), [("abcdefghijklmnop", "Ответ: abcdefgh**ijkl**mnop"),
                                           ("abcdefgh-ijklmnop", "Ответ: abcdefgh\u2010ijklmnop")])
def test_answer_normalized_into_the_key_is_not_stored(tmp_path: Path, mask_key: bytes, lan_loopback, key, said):
    """Нормализация ответа (снятие **…**, замена U+2010 на дефис) собрала бы ключ: последняя проверка перед
    сохранением – после неё; в базе (questions) ключа нет, вопрос – с ошибкой про ключ."""
    from app import ask
    reply = json.dumps({"answer": said, "verdict_changes": "нет"})
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    journal_dir = tmp_path / "traffic"
    model_traffic.set_recorder(Recorder(journal_dir))
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(env.db, pid, key, fake.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        assert env.run(MODEL)["state"] == "done"
        fake.answers.extend([reply] * 2)
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда?", MODEL)
        rows = [dict(r) for r in env.db._all("SELECT * FROM questions ORDER BY 1, 2")]
        stored = json.dumps(rows, ensure_ascii=False) + json.dumps(rows)
        assert key not in stored and q["state"] == "error" and model_traffic.KEY_IN_ANSWER in q["error"]
    finally:
        model_traffic.set_recorder(None)
        env.close()
        fake.close()


def test_verdict_normalized_into_the_key_is_not_stored(tmp_path: Path, mask_key: bytes, lan_loopback):
    """Вердикт, где снятие **…** собрало бы ключ: находка – с ошибкой про ключ, в базе (verdicts, run_items) ключа
    нет."""
    from fake_ollama import verdict_answer
    key = "abcdefghijklmnop"
    fake = FakeOllama(default_answer=verdict_answer("true_positive", summary="Сводка: abcdefgh**ijkl**mnop"))
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        pid = lan_profile(env.db, fake.url, auth="bearer")
        save_key(env.db, pid, key, fake.url, ["127.0.0.1"])
        use(env.db, env.project_id, pid)
        env.run(MODEL)
        dump = json.dumps([dict(r) for r in env.db._all("SELECT * FROM verdicts ORDER BY 1, 2")]
                          + [dict(r) for r in env.db._all("SELECT * FROM run_items ORDER BY 1, 2")], ensure_ascii=False)
        assert key not in dump and model_traffic.KEY_IN_ANSWER in dump
    finally:
        env.close()
        fake.close()


def test_unknown_outcome_of_key_write_keeps_form_from_creating_second_profile(tmp_path: Path, mask_key: bytes, lan_loopback, monkeypatch):
    """Ответ на COMMIT записи ключа потерян: ключ мог записаться, метка формы гасится, ошибка видна оператору."""
    from app.providers import save_profile
    from app.storage.postgresql import CommitUnknown
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        def lost(*_args):
            raise CommitUnknown("ответ потерян")

        monkeypatch.setattr(env.db, "put_secret", lost)
        written = []
        with pytest.raises(CommitUnknown):
            save_profile(env.db, None, {"name": "П", "trust": "lan", "base_url": fake.url, "confirmed_addresses": ["127.0.0.1"]},
                         key=SECRET, requires_key=True, key_written=lambda: written.append(1))
        assert written == [1]
    finally:
        env.close()  # поток прогонов останавливается до закрытия базы (бэклог 125)
        fake.close()
