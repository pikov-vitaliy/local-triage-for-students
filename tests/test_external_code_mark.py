"""Отметка проекта «код не секретный» (план 0.9.13, C1; ADR-0104 п. 3, К9, К2): без отметки код проекта внешнему
провайдеру не уходит ни одним путём (выбор профиля, допуск перед отправкой); отметка – только со страницы предпросмотра,
с обоснованием и подтверждением; снятие – под исключительной блокировкой проекта: начатая отправка дописывает байты,
следующая не проходит, прогон встаёт на паузу. Данные выдуманы; внешний сервер – поддельный API на loopback по https
с тестовым сертификатом."""

from __future__ import annotations

import re
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import llm_net  # noqa: E402
from app.executors import (EXTERNAL_MARK_NOTE, ProfileError, SendNotAllowed, choose_profile, client_for,  # noqa: E402
                           code_profile_fits, execution_values, send_guard)
from fake_chat_api import CERTS, FakeChatApi  # noqa: E402
from fake_ollama import verdict_answer  # noqa: E402
from test_providers_chat_ui import post as post_profile  # noqa: E402
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: E402, F401

REASON = "Демонстрационный проект: код открытый, секретов и персональных данных нет"


@pytest.fixture
def external_loopback(monkeypatch):
    """Класс external на loopback: https, имя → 127.0.0.1, сертификат тестового центра, LLM_EXTERNAL=1."""
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


def external_profile(web, base_url: str, name: str = "Внешний") -> dict:  # noqa: F811
    r = post_profile(web, "/settings/providers/new", name=name, trust="external", base_url=base_url,
                     default_model="flash-model", thinking="disabled", max_output="4096", action="save")
    assert r.status_code == 303, r.text[:1500]
    return next(p for p in web.app.state.db.list_providers() if p["name"] == name)


def preview_fields(web, pid: int) -> dict:  # noqa: F811
    """Одноразовый номер и серверная метка со страницы предпросмотра – без неё отметку не поставить."""
    page = web.client.get(f"/projects/{pid}/external").text
    return {name: re.search(rf'name="{name}" value="([^"]*)"', page).group(1) for name in ("nonce", "token")}


def mark(web, pid: int, reason: str = REASON, **override):  # noqa: F811
    data = {**preview_fields(web, pid), "confirm": "1", "reason": reason, **override}
    return web.client.post(f"/projects/{pid}/external", headers=ORIGIN, follow_redirects=False, data=data)


# ============================================================================ правила и допуск

def test_code_profile_fits_the_project_only_with_the_mark():
    ollama = {"kind": "ollama", "trust": "local"}
    chat_ext = {"kind": "chat_completions", "trust": "external"}
    assert code_profile_fits(ollama, None) and code_profile_fits({"kind": "ollama", "trust": "lan"}, {})
    assert not code_profile_fits(chat_ext, None) and not code_profile_fits(chat_ext, {"external_allowed": 0})
    assert code_profile_fits(chat_ext, {"external_allowed": 1})
    assert not code_profile_fits({"kind": "chat_completions", "trust": "local"}, {"external_allowed": 1})
    assert not code_profile_fits({"kind": "ollama", "trust": "external"}, {"external_allowed": 1})


def test_send_guard_refuses_external_code_without_the_mark(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    pid = prepared(web)
    profile = external_profile(web, "https://external-test.example:8443/v1")
    execution = execution_values(profile, "flash-model", "triage", 16384, "always")
    guard = send_guard(db, execution, project_id=pid)
    with pytest.raises(SendNotAllowed, match="отметки «код не секретный» нет") as caught:
        guard()
    assert caught.value.note == EXTERNAL_MARK_NOTE
    with pytest.raises(SendNotAllowed):  # снимок без проекта – тоже отказ
        send_guard(db, execution)()
    assert db.set_external_mark(pid, REASON)
    guard()  # отметка есть – допуск
    db.clear_external_mark(pid)
    with pytest.raises(SendNotAllowed):
        guard()
    # профиль своего контура отметки не требует; служебные запросы (снимок без класса доверия) – тоже
    local = execution_values(db.get_provider(1), "qwen2.5-coder:14b", "triage", 16384, "always")
    send_guard(db, local, project_id=pid)()
    send_guard(db, {"provider_id": 1})()
    with pytest.raises(ProfileError, match="отметкой «код не секретный»"):
        choose_profile(db, web.app.state.settings, db.get_project(pid), profile["id"])
    db.set_external_mark(pid, REASON)
    assert choose_profile(db, web.app.state.settings, db.get_project(pid), profile["id"])["id"] == profile["id"]


def test_clearing_the_mark_waits_for_a_started_send(web, external_loopback):  # noqa: F811
    """К2: снятие отметки берёт исключительную блокировку проекта – начатая отправка (общая блокировка до передачи
    байтов) заканчивается, снятие ждёт её, после него допуск – отказ."""
    db = web.app.state.db
    pid = prepared(web)
    profile = external_profile(web, "https://external-test.example:8443/v1")
    db.set_external_mark(pid, REASON)
    execution = execution_values(profile, "flash-model", "triage", 16384, "always")
    guard = send_guard(db, execution, project_id=pid)
    client = client_for(web.app.state.web.make_client, execution, guard, db=db,
                        project_id=pid)
    done = threading.Event()

    def clear():
        r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303 and "ok=external_cleared" in r.headers["location"], r.text[:300]
        done.set()
    with client.gate():  # «отправка идёт»: допуск под блокировкой проходит
        guard()
        worker = threading.Thread(target=clear)
        worker.start()
        time.sleep(0.3)
        assert not done.is_set() and db.get_project(pid)["external_allowed"] == 1, "снятие ждёт конца отправки"
    worker.join(10)
    assert done.is_set() and db.get_project(pid)["external_allowed"] == 0
    with pytest.raises(SendNotAllowed):
        guard()


# ============================================================================ страница и маршруты

def test_project_page_and_params_follow_the_mark(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    pid = prepared(web)
    profile = external_profile(web, "https://external-test.example:8443/v1")
    page = web.client.get(f"/projects/{pid}").text
    assert f'value="{profile["id"]}" disabled>Внешний (интернет) – нужна отметка «код не секретный»' in page
    assert 'id="external-mark"' in page and "Предпросмотр и отметка…" in page
    for url, data in ((f"/projects/{pid}/provider", {"provider_id": str(profile["id"])}),
                      (f"/projects/{pid}/params", {"name": "Проект", "model": "", "provider_id": str(profile["id"])})):
        r = web.client.post(url, headers=ORIGIN, follow_redirects=False, data=data)
        assert r.status_code == 400 and "не разбирает код" in r.text
    # предпросмотр: промпт первой находки целиком, с маскированием, как в прогоне
    preview = web.client.get(f"/projects/{pid}/external").text
    assert "Отметка «код не секретный»" in preview and 'id="external-system"' in preview and 'id="external-user"' in preview
    assert "Внешний" in preview and "external-test.example" in preview
    hub_id = re.search(r'первая находка очереди SAST \(<span class="mono">([^<]+)</span>\)', preview).group(1)
    assert hub_id == db.sast_queue(pid, "all")[0]
    # без подтверждения, с коротким обоснованием, без метки страницы предпросмотра (прямой POST) – отказ
    r = mark(web, pid, confirm="")
    assert "err=external_confirm" in r.headers["location"]
    r = mark(web, pid, reason="коротко")
    assert "err=external_reason" in r.headers["location"]
    for forged in ({"token": ""}, {"token": "0" * 64}, {"nonce": ""}, {"nonce": "abcd"}):
        r = mark(web, pid, **forged)
        assert "err=external_preview" in r.headers["location"], forged
    assert db.get_project(pid)["external_allowed"] == 0
    # метка подписывает показанный промпт: та же форма после новой выгрузки (другая первая находка) – отказ
    from hub_fixtures import make_hub_xlsx
    from test_web import upload
    fields = preview_fields(web, pid)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub2.xlsx")).status_code == 303
    assert "ok=external_marked" in mark(web, pid, **fields).headers["location"], "та же выгрузка – промпт тот же"
    assert "ok=external_cleared" in web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN,
                                                    follow_redirects=False).headers["location"]
    r = mark(web, pid, **fields)
    assert "err=external_preview" in r.headers["location"], "после снятия отметки старая форма недействительна"
    assert db.get_project(pid)["external_allowed"] == 0
    # форма, открытая, пока отметка стояла, после снятия тоже недействительна
    assert "ok=external_marked" in mark(web, pid).headers["location"]
    during = preview_fields(web, pid)
    assert "ok=external_cleared" in web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN,
                                                    follow_redirects=False).headers["location"]
    r = mark(web, pid, **during)
    assert "err=external_preview" in r.headers["location"], "форма времени отметки после снятия недействительна"
    assert db.get_project(pid)["external_allowed"] == 0
    # ревизия отметки растёт при каждой постановке и снятии: два цикла в одну секунду не возвращают прежнее состояние
    rev = db.external_mark_revision(pid)
    stale = preview_fields(web, pid)
    for _ in range(2):
        assert "ok=external_marked" in mark(web, pid).headers["location"]
        assert "ok=external_cleared" in web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN,
                                                        follow_redirects=False).headers["location"]
    assert db.external_mark_revision(pid) == rev + 4
    r = mark(web, pid, **stale)
    assert "err=external_preview" in r.headers["location"] and db.get_project(pid)["external_allowed"] == 0
    assert "обоснование – от 10 до 1000 знаков" in web.client.get(f"/projects/{pid}/external?err=external_reason").text
    # отметка поставлена: обоснование и время видны, профиль выбирается
    r = mark(web, pid)
    assert r.status_code == 303 and "ok=external_marked" in r.headers["location"]
    project = db.get_project(pid)
    assert project["external_allowed"] == 1 and project["external_reason"] == REASON and project["external_confirmed_at"]
    page = web.client.get(f"/projects/{pid}").text
    assert "Отметка «код не секретный» стоит с" in page and REASON in page and "Снять отметку" in page
    assert f'value="{profile["id"]}">Внешний (интернет)</option>' in page
    r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                        data={"provider_id": str(profile["id"])})
    assert r.status_code == 303 and db.get_project(pid)["provider_id"] == profile["id"]
    # снятие: профиль остаётся выбранным, но негодным; сохранить параметры с ним снова нельзя
    r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
    assert "ok=external_cleared" in r.headers["location"] and db.get_project(pid)["external_allowed"] == 0
    page = web.client.get(f"/projects/{pid}").text
    assert f'value="{profile["id"]}" selected disabled>Внешний (интернет) – нужна отметка «код не секретный»' in page
    r = web.client.post(f"/projects/{pid}/params", headers=ORIGIN, follow_redirects=False,
                        data={"name": "Проект", "model": "", "provider_id": str(profile["id"])})
    assert r.status_code == 400


def test_mark_needs_the_installation_switch(web, monkeypatch):  # noqa: F811
    monkeypatch.delenv("LLM_EXTERNAL", raising=False)
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}/external").text
    assert "Отправка в интернет в этой установке выключена" in page and 'id="external-mark-btn" disabled' in page
    r = mark(web, pid)
    assert "err=external_off" in r.headers["location"] and web.app.state.db.get_project(pid)["external_allowed"] == 0
    assert "Предпросмотр и отметка…" not in web.client.get(f"/projects/{pid}").text


def test_mark_needs_a_sast_finding_to_preview(web, external_loopback):  # noqa: F811
    """К9: без находки SAST промпт показать не из чего – отметка не ставится."""
    from test_web import create_project
    pid = create_project(web.client)
    page = web.client.get(f"/projects/{pid}/external").text
    assert "нет находок SAST текущей выгрузки" in page and 'id="external-user"' not in page
    assert 'id="external-mark-btn" disabled' in page and 'name="token" value=""' in page
    r = web.client.post(f"/projects/{pid}/external", headers=ORIGIN, follow_redirects=False,
                        data={"confirm": "1", "reason": REASON, "nonce": "abcd", "token": "0" * 64})
    assert "err=external_preview" in r.headers["location"]
    assert web.app.state.db.get_project(pid)["external_allowed"] == 0


def test_clearing_the_mark_waits_for_the_real_send_path(web, external_loopback, monkeypatch):  # noqa: F811
    """К2 через настоящий транспорт: барьер в разрешении имени (под общей блокировкой проекта, до передачи байтов) –
    снятие отметки ждёт; снятая во время первого ответа отметка – повтор не по формату и следующая находка не уходят;
    вопрос к модели без отметки – тоже отказ до сети."""
    from fake_ollama import ask_answer, verdict_answer
    from test_findings_ui import AS_JSON, card_of
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid = prepared(web)
        profile = external_profile(web, fake.url)
        assert "ok=external_marked" in mark(web, pid).headers["location"]
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": str(profile["id"])})
        assert r.status_code == 303
        from app import llm_chat
        inside, hold, cleared, in_chat = threading.Event(), threading.Event(), threading.Event(), threading.Event()
        resolving = llm_net.socket.getaddrinfo
        posting = llm_chat.ChatCompletionsClient._post

        def chat_post(self, body, budget):  # отправка кода модели (не служебный список моделей)
            in_chat.set()
            return posting(self, body, budget)

        def slow_resolve(host, port, *args, **kwargs):  # разрешение имени первой отправки кода ждёт барьер
            if host == "external-test.example" and in_chat.is_set() and not inside.is_set():
                inside.set()
                hold.wait(10)
            return resolving(host, port, *args, **kwargs)
        monkeypatch.setattr(llm_chat.ChatCompletionsClient, "_post", chat_post)
        monkeypatch.setattr(llm_net.socket, "getaddrinfo", slow_resolve)

        def clear():
            r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
            assert r.status_code == 303, r.text[:300]
            cleared.set()
        fake.answers += ["не JSON", verdict_answer("false_positive")]  # первый ответ не по формату – будет повтор
        run_id = start_run(web, pid, model="flash-model")
        assert inside.wait(10), "прогон вошёл в разрешение имени под блокировкой проекта"
        worker = threading.Thread(target=clear)
        worker.start()
        time.sleep(0.4)
        assert not cleared.is_set() and db.get_project(pid)["external_allowed"] == 1, "снятие ждёт конца отправки"
        hold.set()
        worker.join(10)
        assert cleared.is_set()
        run = wait_run(web, run_id)
        assert run["state"] == "paused" and EXTERNAL_MARK_NOTE in run["last_error"], run
        assert len(fake.chats()) == 1, "повтор не по формату после снятия отметки не отправлен"
        items = db._all("SELECT state, sending_at FROM run_items WHERE run_id = ? ORDER BY seq", (run_id,))
        assert items[0]["state"] == "pending" and items[0]["sending_at"] is None, "метка снята – исход известен"
        # вопрос к модели по разбору внешнего профиля без отметки – отказ до сети
        assert "ok=external_marked" in mark(web, pid).headers["location"]
        fake.answers += [verdict_answer("false_positive")]
        fake.default_answer = verdict_answer("false_positive")
        r = web.client.post(f"/runs/{run_id}/resume", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303 and wait_run(web, run_id)["state"] == "done"
        hub_id = db.sast_queue(pid, "all")[0]
        fid, _card = card_of(web, pid, hub_id)
        assert "ok=external_cleared" in web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN,
                                                        follow_redirects=False).headers["location"]
        sent = len(fake.chats())
        fake.answers += [ask_answer("Нет.", "нет")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                            data={"question": "А если из сессии?", "model": "flash-model"})
        assert r.status_code in (200, 409), r.text[:300]
        assert len(fake.chats()) == sent, "вопрос без отметки не ушёл"
        body = r.json()
        text = str(body.get("detail") or (body.get("question") or {}).get("error") or "")
        assert "код не секретный" in text, body


# ============================================================================ прогон на внешнем профиле

def test_run_sends_code_only_with_the_mark_and_pauses_after_clearing(web, external_loopback):  # noqa: F811
    """Код уходит внешнему провайдеру только при отметке; снятие отметки во время прогона – следующая находка не
    отправляется, прогон на паузе с подсказкой; первая – с вердиктом."""
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid = prepared(web)
        profile = external_profile(web, fake.url)
        assert "ok=external_marked" in mark(web, pid).headers["location"]
        r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                            data={"provider_id": str(profile["id"])})
        assert r.status_code == 303, r.text[:500]

        def first(body):  # первая отправка ушла; оператор снимает отметку, пока модель «думает»
            r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
            assert r.status_code == 303, r.text[:300]
            return verdict_answer("false_positive")
        fake.answers += [first]
        run_id = start_run(web, pid, model="flash-model")
        run = wait_run(web, run_id)
        assert run["state"] == "paused" and EXTERNAL_MARK_NOTE in run["last_error"], run
        assert len(fake.chats()) == 1, "после снятия отметки вторая находка не отправлена"
        assert db.get_project(pid)["external_allowed"] == 0
        done = [hub for hub in db.sast_queue(pid, "all") if (db.get_case(pid, hub) or {}).get("verdict")]
        assert len(done) == 1
        # без отметки новый прогон на внешнем профиле не ставится в очередь вовсе
        r = web.client.post(f"/projects/{pid}/runs", data={"model": "flash-model", "scope": "all"}, headers=ORIGIN,
                            follow_redirects=False)
        assert r.status_code == 400 and "отметкой «код не секретный»" in r.text
        # «Продолжить» прогон на паузе – допуск перед отправкой снова отказывает, в сеть ничего не уходит
        r = web.client.post(f"/runs/{run_id}/resume", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303, r.text[:300]
        resumed = wait_run(web, int(r.headers["location"].rsplit("/", 1)[1].split("?")[0]))
        assert resumed["state"] == "paused" and EXTERNAL_MARK_NOTE in resumed["last_error"], resumed
        assert len(fake.chats()) == 1
