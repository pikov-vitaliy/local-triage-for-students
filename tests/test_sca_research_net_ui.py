"""Исследование провайдером в интерфейсе (план 0.9.13, B4; К7): «Компоненты» – выбор профиля исследования и кнопка
предпросмотра; предпросмотр показывает строки, инструкции и первое сообщение целиком; запуск – только с отметкой
согласия и совпавшим отпечатком; страница хода, статус, «Остановить», «Продолжить», «Доисследовать оставшиеся»;
карточка компонента называет источник ревизии; профиль Ollama исследование не исполняет. Поддельный сервер на этом
компьютере. Данные выдуманы."""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fake_chat_api import FakeChatApi  # noqa: E402
from test_providers_chat_ui import post as post_profile  # noqa: E402
from test_sca_research_net import good_row, make_profile, manifest_rows  # noqa: E402
from test_sca_research_routes import AST_ID, CODEBASE, build_task, project_with_sca  # noqa: E402
from test_web import ORIGIN, web  # noqa: E402, F401


def wait_run(web, run_id: int, timeout: float = 20.0) -> dict:  # noqa: F811
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = web.app.state.db.research_run(run_id)
        if run["state"] != "running":
            return run
        time.sleep(0.05)
    raise AssertionError("получение не закончилось")


def preview(web, pid: int, selection: str = "all"):  # noqa: F811
    return web.client.post(f"/projects/{pid}/components/research/preview", headers=ORIGIN, follow_redirects=False,
                           data={"selection": selection})


def hidden(page: str, name: str) -> str:
    return re.search(rf'name="{name}" value="([^"]*)"', page).group(1)


def start(web, pid: int, page: str, confirm: bool = True, fingerprint: str | None = None,  # noqa: F811
          token: str | None = None, nonce: str | None = None):
    """Форма согласия со страницы предпросмотра: отпечаток, одноразовый номер и серверная метка предпросмотра."""
    fp = fingerprint if fingerprint is not None else hidden(page, "fingerprint")
    data = {"selection": hidden(page, "selection"), "fingerprint": fp,
            "nonce": nonce if nonce is not None else hidden(page, "nonce"),
            "token": token if token is not None else hidden(page, "token")}
    if confirm:
        data["confirm"] = "1"
    return web.client.post(f"/projects/{pid}/components/research/start", headers=ORIGIN, follow_redirects=False,
                           data=data)


def requeue(web, pid: int, run_id: int, include_unknown: bool = False, **override):  # noqa: F811
    """«Доисследовать оставшиеся» со страницы хода: одноразовый номер и метка страницы (форма только с неё)."""
    page = web.client.get(f"/projects/{pid}/components/research/{run_id}").text
    data = {"nonce": hidden(page, "nonce"), "token": hidden(page, "token"), **override}
    if include_unknown:
        data["include_unknown"] = "1"
    return web.client.post(f"/projects/{pid}/components/research/{run_id}/requeue", headers=ORIGIN,
                           follow_redirects=False, data=data)


def test_components_page_offers_research_only_with_a_fit_profile(web):  # noqa: F811
    pid = project_with_sca(web)
    build_task(web, pid)
    page = web.client.get(f"/projects/{pid}/components").text
    assert 'id="research-no-profile"' in page and 'id="research-preview"' not in page, "профиль 1 (Ollama) не годится"
    assert "исследование только профилем удалённого API" in page  # чат-завершения или Messages (0.9.14)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        r = web.client.post(f"/projects/{pid}/components/research-provider", headers=ORIGIN, follow_redirects=False,
                            data={"research_provider_id": str(profile["id"])})
        assert r.status_code == 303 and "ok=research_provider_saved" in r.headers["location"]
        assert web.app.state.db.get_project(pid)["research_provider_id"] == profile["id"]
        page = web.client.get(f"/projects/{pid}/components").text
        assert 'id="research-preview"' in page and f'value="{profile["id"]}" selected' in page
        # профиль Ollama выбрать нельзя
        r = web.client.post(f"/projects/{pid}/components/research-provider", headers=ORIGIN, follow_redirects=False,
                            data={"research_provider_id": "1"})
        assert "err=research_profile_unfit" in r.headers["location"]


def test_preview_shows_everything_and_start_requires_consent_and_same_fingerprint(web):  # noqa: F811
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        r = preview(web, pid)
        assert r.status_code == 200
        page = r.text
        for piece in ("Исследование компонента программного обеспечения", "Схема строки ответа", "flash-model",
                      fake.url, 'cutoff_date', "example-parser", "CVE-2099-10001", "/v1/tools/search",
                      'id="research-confirm"'):
            assert piece in page, piece
        for secret in (CODEBASE, "catalog-api", AST_ID):
            assert secret not in page.split('id="research-consent"')[0].split("<h2 id=\"system-title\"")[1], secret
        # без отметки согласия – отказ
        r = start(web, pid, page, confirm=False)
        assert "err=research_confirm" in r.headers["location"] and db.latest_research_run(pid) is None
        # чужой отпечаток – отказ
        r = start(web, pid, page, fingerprint="0" * 64)
        assert "err=research_changed" in r.headers["location"] and db.latest_research_run(pid) is None
        assert fake.chats() == []


def test_full_flow_run_page_status_stop_resume_requeue_and_card_source(web):  # noqa: F811
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        page = preview(web, pid).text
        r = start(web, pid, page)
        assert r.status_code == 303, r.text[:500]
        run_id = int(r.headers["location"].rsplit("/", 1)[1])
        run = wait_run(web, run_id)
        assert run["state"] == "done" and run["rows_saved"] == 1 and run["rows_failed"] == 1
        page = web.client.get(f"/projects/{pid}/components/research/{run_id}").text
        assert "Получение №" in page and "сохранена" in page and "не получена" in page and "Доисследовать оставшиеся" in page
        assert "Исследователь" in page and "flash-model" in page
        status = web.client.get(f"/projects/{pid}/components/research/{run_id}/status").json()
        assert status["run"]["state"] == "done" and {r["state"] for r in status["rows"]} == {"saved", "failed"}
        # карточка компонента: источник ревизии – провайдер
        card = web.client.get(f"/projects/{pid}/components/{rows[0]['input_ref']}").text
        assert 'id="research-source"' in card and "провайдер «Исследователь»" in card and "flash-model" in card
        # источник – по фактическим вызовам: модель ответила без поиска, хотя он был доступен (ревью B4)
        assert "без поиска по источникам: поиск был доступен" in card
        assert status["rows"][0]["tools_text"] == "обращений к модели 1" and status["live"] is None
        # «Компоненты» показывают последнее получение
        listing = web.client.get(f"/projects/{pid}/components").text
        assert f"№{run_id}" in listing and "сохранено 1" in listing
        # доисследовать не получившуюся строку – успех со второй попытки
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        r = web.client.post(f"/projects/{pid}/components/research/{run_id}/requeue", headers=ORIGIN,
                            follow_redirects=False, data={})
        assert "err=research_changed" in r.headers["location"], "без метки страницы хода доисследование не идёт"
        page = web.client.get(f"/projects/{pid}/components/research/{run_id}").text
        form = {"nonce": hidden(page, "nonce"), "token": hidden(page, "token")}
        r = web.client.post(f"/projects/{pid}/components/research/{run_id}/requeue", headers=ORIGIN,
                            follow_redirects=False, data=form)
        assert "ok=research_requeued&n=1" in r.headers["location"], r.headers["location"]
        follow_id = int(r.headers["location"].split("/research/", 1)[1].split("?", 1)[0])
        assert follow_id != run_id, "доисследование – новое получение, прежнее остаётся историей"
        follow = wait_run(web, follow_id)
        assert follow["state"] == "done" and follow["rows_saved"] == 1 and follow["rows_total"] == 1
        assert db.research_run(run_id)["rows_failed"] == 1, "история прежнего получения не переписана"
        # повтор той же формы – прежнее дочернее получение, а не второе (ревью, круг 3)
        sent = len(fake.chats())
        r = web.client.post(f"/projects/{pid}/components/research/{run_id}/requeue", headers=ORIGIN,
                            follow_redirects=False, data=form)
        assert r.headers["location"].split("?")[0].endswith(f"/research/{follow_id}"), r.headers["location"]
        time.sleep(0.2)
        assert len(fake.chats()) == sent
        # повторное доисследование завершённого без остатка – нечего
        r = requeue(web, pid, follow_id)
        assert "err=research_nothing" in r.headers["location"]
        # второй запуск по проекту при завершённом – новое согласие и получение
        page = preview(web, pid, "all").text
        r = start(web, pid, page)
        assert r.status_code == 303
        run2 = int(r.headers["location"].rsplit("/", 1)[1])
        assert run2 != run_id
        wait_run(web, run2)


def test_stop_and_resume(web):  # noqa: F811
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        slow = {"gate": True}

        def first(body):  # первый ответ ждёт, пока оператор не нажмёт «Остановить»
            deadline = time.monotonic() + 10
            while slow["gate"] and time.monotonic() < deadline:
                time.sleep(0.05)
            return ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")
        fake.answers += [first]
        page = preview(web, pid).text
        run_id = int(start(web, pid, page).headers["location"].rsplit("/", 1)[1])
        time.sleep(0.3)
        r = web.client.post(f"/projects/{pid}/components/research/{run_id}/stop", headers=ORIGIN, follow_redirects=False)
        assert "ok=research_stopping" in r.headers["location"]
        slow["gate"] = False
        run = wait_run(web, run_id)
        assert run["state"] == "stopped" and run["rows_saved"] == 1, run  # текущая строка дошла до конца
        states = {x["input_ref"]: x["state"] for x in db.research_run_rows(run_id)}
        assert states[rows[1]["input_ref"]] == "queued"
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        r = web.client.post(f"/projects/{pid}/components/research/{run_id}/resume", headers=ORIGIN, follow_redirects=False)
        assert "ok=research_resumed" in r.headers["location"]
        run = wait_run(web, run_id)
        assert run["state"] == "done" and run["rows_saved"] == 2
        assert len(fake.chats()) == 2


def test_start_needs_the_server_preview_token(web):  # noqa: F811
    """Ревью B4 (блокирующее 1): отпечаток можно пересчитать, метку предпросмотра – нет: прямой POST без страницы, с
    чужим одноразовым номером или с подделанной меткой – «состав изменился»."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        page = preview(web, pid).text
        for bad in ({"token": ""}, {"token": "0" * 64}, {"nonce": "ffff"}, {"nonce": ""}):
            r = start(web, pid, page, **bad)
            assert r.status_code == 303 and "err=research_changed" in r.headers["location"], bad
        assert db.latest_research_run(pid) is None and not fake.chats()
        # та же форма с настоящей меткой – запускается
        r = start(web, pid, page)
        assert "/components/research/" in r.headers["location"], r.headers["location"]
        wait_run(web, int(r.headers["location"].rsplit("/", 1)[1]))


def test_profile_change_between_preview_and_start_is_caught(web):  # noqa: F811
    """Снимок исполнителя – в отпечатке: смена параметров профиля при тех же модели и поиске – новое согласие."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        page = preview(web, pid).text
        r = post_profile(web, f"/settings/providers/{profile['id']}", name="Исследователь", base_url=fake.url,
                         default_model="flash-model", thinking="disabled", max_output="2048", tool_steps="3",
                         search_on="1", search_path="/v1/tools/search", fetch_path="/v1/tools/fetch", action="save")
        assert r.status_code == 303, r.text[:800]
        r = start(web, pid, page)
        assert "err=research_changed" in r.headers["location"]
        assert db.latest_research_run(pid) is None and not fake.chats()


def test_repeated_confirmation_returns_the_same_run(web):  # noqa: F811
    """Ревью B4 (блокирующее 2): повтор той же формы (обновление страницы после POST) – прежнее согласие и получение,
    второго нет – и после конца первого тоже."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("drop",), ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        page = preview(web, pid).text
        first = start(web, pid, page).headers["location"]
        run_id = int(first.rsplit("/", 1)[1])
        assert start(web, pid, page).headers["location"] == first, "повтор – то же получение"
        run = wait_run(web, run_id)
        assert run["rows_unknown"] == 1 and run["rows_saved"] == 1
        sent = len(fake.chats())
        again = start(web, pid, page)
        assert again.headers["location"] == first, "после конца получения повтор формы тоже не создаёт новое"
        time.sleep(0.3)
        assert len(fake.chats()) == sent, "строка с неизвестным результатом не отправлена повторно"
        assert len(db._all("SELECT id FROM sca_research_consents WHERE project_id = ?", (pid,))) == 1
        # отозванное согласие по той же метке – отказ: нужен новый предпросмотр
        db.revoke_research_consent(run["consent_id"])
        r = start(web, pid, page)
        assert "err=research_running" in r.headers["location"] or "err=research_changed" in r.headers["location"]
        assert len(db._all("SELECT id FROM sca_research_consents WHERE project_id = ?", (pid,))) == 1


def test_status_shows_the_live_step_and_tool_calls(web):  # noqa: F811
    """B4: страница хода и status показывают текущую строку и вызовы инструментов с исходом каждого шага."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        hold = threading.Event()

        def second(body):
            hold.wait(10)
            return ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "search", "arguments": json.dumps({"query": "q"})}}]}, "tool_calls"), second,
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        page = preview(web, pid).text
        run_id = int(start(web, pid, page).headers["location"].rsplit("/", 1)[1])
        deadline = time.monotonic() + 5
        live = None
        while time.monotonic() < deadline:
            live = web.client.get(f"/projects/{pid}/components/research/{run_id}/status").json()["live"]
            if live and "выполнен" in live["text"]:  # запись шага появляется до его конца – ждать законченного
                break
            time.sleep(0.05)
        assert live and live["input_ref"] == rows[0]["input_ref"] and "шаг 1: поиск – выполнен (1)" in live["text"], live
        page = web.client.get(f"/projects/{pid}/components/research/{run_id}").text
        assert 'id="run-live"' in page and "шаг 1: поиск – выполнен (1)" in page
        hold.set()
        wait_run(web, run_id)
        status = web.client.get(f"/projects/{pid}/components/research/{run_id}/status").json()
        assert status["live"] is None
        texts = {r["input_ref"]: r["tools_text"] for r in status["rows"]}
        assert texts[rows[0]["input_ref"]] == "обращений к модели 2; шаг 1: поиск – выполнен (1)"
        card = web.client.get(f"/projects/{pid}/components/{rows[0]['input_ref']}").text
        assert "поиск по источникам: запросов 1, страниц 0" in card


def test_fingerprint_binds_the_project_and_the_task(web):  # noqa: F811
    """Ревью круга 3: форма согласия проекта А не подходит проекту Б с теми же строками, профилем и датой."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        a, b = project_with_sca(web), project_with_sca(web)
        build_task(web, a)
        build_task(web, b)
        db.update_project(a, research_provider_id=profile["id"])
        db.update_project(b, research_provider_id=profile["id"])
        page_a = preview(web, a).text
        r = start(web, b, page_a)
        assert "err=research_changed" in r.headers["location"], "форма проекта А – проекту Б не годится"
        assert db.latest_research_run(b) is None and not fake.chats()


def test_active_research_bar_on_any_page(web):  # noqa: F811
    """Полоса «идёт получение»: идущее получение видно на любой странице со ссылкой на ход;
    закончилось – итог отдаётся только по номеру, который страница уже показывала (last), иначе полосы нет."""
    from test_sca_research_net import start_run as start_research
    db = web.app.state.db
    assert 'id="active-research-bar"' in web.client.get("/").text and 'id="active-research-bar"' in         web.client.get("/settings").text
    assert web.client.get("/api/research/active").json() == {"run": None}
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_research(web, fake)
        data = web.client.get("/api/research/active").json()
        assert data["run"]["id"] == run["id"] and data["run"]["state"] == "running"
        assert data["run"]["state_label"] == "идёт" and data["url"] == f"/projects/{pid}/components/research/{run['id']}"
        assert data["run"]["rows_total"] == run["rows_total"] and data["project_name"]
        db.finish_research_run(run["id"], "done", "")
        assert web.client.get("/api/research/active").json() == {"run": None}
        last = web.client.get(f"/api/research/active?last={run['id']}").json()
        assert last["run"]["state"] == "done" and last["run"]["state_label"] == "завершено"


def test_requeue_button_counts_unknown_rows_when_only_they_are_left(web):  # noqa: F811
    """Не получившихся строк нет, одна – «результат неизвестен». Кнопка
    «Доисследовать оставшиеся» показывала «(0)», отметка была снята – нажатие давало отказ. Теперь: отметка стоит
    по умолчанию, кнопка называет 1, форма без JS отправляет include_unknown=1; при нуле строк кнопка недоступна;
    сообщение об отказе на странице – один раз."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        r = start(web, pid, preview(web, pid).text)
        run_id = int(r.headers["location"].rsplit("/", 1)[1])
        run = wait_run(web, run_id)
        assert run["rows_failed"] == 1
        with db._tx() as c:  # та же строка – «результат неизвестен», как после обрыва без ответа
            c.execute("UPDATE sca2_research_run_rows SET state = 'unknown' WHERE run_id = ? AND state = 'failed'", (run_id,))
            c.execute("UPDATE sca2_research_runs SET rows_failed = 0, rows_unknown = 1 WHERE id = ?", (run_id,))
        page = web.client.get(f"/projects/{pid}/components/research/{run_id}").text
        assert 'name="include_unknown" value="1" id="include-unknown" checked' in page
        assert 'Доисследовать оставшиеся (<span data-count="leftover">1</span>)' in page
        assert 'id="research-requeue-button" disabled' not in page
        r = requeue(web, pid, run_id)  # без отметки – отказ, и сообщение на странице один раз
        assert r.status_code == 303 and "err=research_nothing" in r.headers["location"]
        page = web.client.get(r.headers["location"]).text
        assert page.count("Строк для доисследования нет") == 1
        r = requeue(web, pid, run_id, include_unknown=True)
        assert r.status_code == 303 and "ok=research_requeued&n=1" in r.headers["location"]
        # у получения без остатка кнопка недоступна, отметка скрыта
        follow_id = int(r.headers["location"].split("/research/")[1].split("?")[0])
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        wait_run(web, follow_id)
        page = web.client.get(f"/projects/{pid}/components/research/{follow_id}").text
        assert 'id="research-requeue-button" disabled' in page and 'data-count="leftover">0<' in page


def test_requeue_skips_rows_already_saved_by_a_later_run(web):  # noqa: F811
    """Строка «результат неизвестен» уже добрана следующим получением, но страница старого
    получения снова предлагала её и запускала платное обращение. Теперь такая строка в доисследование не идёт:
    счётчики кнопки её не считают, отбор возвращает «строк нет», в списке – пометка «исследована позже»."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        r = start(web, pid, preview(web, pid).text)
        first = int(r.headers["location"].rsplit("/", 1)[1])
        wait_run(web, first)
        with db._tx() as c:
            c.execute("UPDATE sca2_research_run_rows SET state = 'unknown' WHERE run_id = ? AND state = 'failed'", (first,))
            c.execute("UPDATE sca2_research_runs SET rows_failed = 0, rows_unknown = 1 WHERE id = ?", (first,))
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        r = requeue(web, pid, first, include_unknown=True)
        second = int(r.headers["location"].split("/research/")[1].split("?")[0])
        wait_run(web, second)
        assert db.research_run(second)["rows_saved"] == 1
        # страница старого получения: строка помечена, кнопка – ноль, отметка скрыта
        page = web.client.get(f"/projects/{pid}/components/research/{first}").text
        assert "исследована позже" in page and 'data-count="leftover">0<' in page
        assert 'id="research-requeue-button" disabled' in page
        status = web.client.get(f"/projects/{pid}/components/research/{first}/status").json()
        assert [x["later_saved"] for x in status["rows"] if x["state"] == "unknown"] == [True]
        r = requeue(web, pid, first, include_unknown=True)
        assert r.status_code == 303 and "err=research_nothing" in r.headers["location"], "повторного платного обращения нет"
        assert db.research_run(second)["rows_saved"] == 1 and db.active_research_run(pid) is None


def test_later_unchanged_counts_and_pending_states_do_not(web):  # noqa: F811
    """Ревью Codex, круг 29: годный ответ позднего получения, совпавший с прежней ревизией («без изменений»), тоже
    закрывает строку для доисследования; строки «в очереди» и «отправлено» позднего получения – нет."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        r = start(web, pid, preview(web, pid).text)
        first = int(r.headers["location"].rsplit("/", 1)[1])
        wait_run(web, first)
        with db._tx() as c:
            c.execute("UPDATE sca2_research_run_rows SET state = 'unknown' WHERE run_id = ? AND state = 'failed'", (first,))
            c.execute("UPDATE sca2_research_runs SET rows_failed = 0, rows_unknown = 1 WHERE id = ?", (first,))
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        r = requeue(web, pid, first, include_unknown=True)
        second = int(r.headers["location"].split("/research/")[1].split("?")[0])
        wait_run(web, second)
        ref = rows[1]["input_ref"]

        def set_state(state: str) -> None:
            with db._tx() as c:
                c.execute("UPDATE sca2_research_run_rows SET state = ? WHERE run_id = ? AND input_ref = ?", (state, second, ref))

        def leftover() -> tuple[int, bool]:
            page = web.client.get(f"/projects/{pid}/components/research/{first}").text
            n = int(re.search(r'data-count="leftover">(\d+)<', page).group(1))
            return n, "исследована позже" in page
        set_state("unchanged")
        assert leftover() == (0, True) and db.followup_research_consent(first, include_unknown=True) is None
        for state in ("queued", "sending", "failed", "unknown"):
            set_state(state)
            assert leftover() == (1, False), state
        set_state("saved")
        assert leftover() == (0, True)


def test_followup_consent_without_a_run_is_rechecked(web):  # noqa: F811
    """Ревью Codex, круг 29: согласие на доисследование создано, но его получение не запустилось (другое получение
    успело раньше) – повтор той же формы не возвращает устаревший список: отбор проверяется заново."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        db.update_project(pid, research_provider_id=profile["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        r = start(web, pid, preview(web, pid).text)
        first = int(r.headers["location"].rsplit("/", 1)[1])
        wait_run(web, first)
        stale = db.followup_research_consent(first, consent_key="form-1")
        assert stale and stale["rows"] == [rows[1]["input_ref"]]
        # пока запуск A не состоялся, другое получение того же задания (другая форма) добирает эту строку
        fresh, run_b = db.start_followup_research(first, consent_key="form-2")
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        web.app.state.research.start(run_b["id"])
        wait_run(web, run_b["id"])
        assert db.research_run(run_b["id"])["rows_saved"] == 1
        assert db.followup_research_consent(first, consent_key="form-1") is None, "устаревшее согласие без получения не возвращается"
        assert db.followup_research_consent(first, consent_key="form-2")["id"] == fresh["id"], "согласие с получением – идемпотентно"
        # отдельный запуск followup-согласия по номеру не выполняется: только вместе с отбором (круг 31)
        with pytest.raises(RuntimeError, match="вместе с отбором"):
            db.start_research_run(stale["id"])
        assert db.start_followup_research(first, consent_key="form-1") is None
        again = db.start_followup_research(first, consent_key="form-2")
        assert again and again[0]["id"] == fresh["id"] and again[1]["id"] == run_b["id"], "та же форма – те же согласие и получение"


def test_later_unchanged_through_a_real_save(web):  # noqa: F811
    """П. 26: «без изменений» настоящим сохранением – позднее получение вернуло ту же строку, что уже сохранена;
    страница прежнего неудачного получения показывает «исследована позже», кнопка – «(0)»."""
    from test_sca_research_net import runner_for, start_run
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run1 = start_run(web, fake)
        rows = manifest_rows(web, task)
        x = rows[0]["input_ref"]
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run1["id"])
        assert db.research_run(run1["id"])["rows_saved"] == 2
        _, _, _, run2 = start_run(web, fake, rows=[x], project=(pid, task))
        fake.answers += [("http", 500, {"error": {"message": "boom"}}), ("http", 500, {"error": {"message": "boom"}})]
        runner_for(web).run(run2["id"])
        assert db.research_run(run2["id"])["rows_failed"] == 1
        page = web.client.get(f"/projects/{pid}/components/research/{run2['id']}").text
        assert 'data-count="leftover">1<' in page and "исследована позже" not in page
        consent, run3 = db.start_followup_research(run2["id"])
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run3["id"])
        done = db.research_run(run3["id"])
        assert done["rows_unchanged"] == 1 and done["rows_saved"] == 0, "та же строка – «без изменений»"
        page = web.client.get(f"/projects/{pid}/components/research/{run2['id']}").text
        assert 'data-count="leftover">0<' in page and "исследована позже" in page and 'id="research-requeue-button" disabled' in page
        assert db.start_followup_research(run2["id"]) is None


def test_preview_names_the_osv_query(web):  # noqa: F811
    """ADR-0112 п. 4: предпросмотр согласия называет адрес и состав запроса OSV, первое сообщение показывает место
    ответа (status pending); с OSV_URL=off – сказано, что запроса нет."""
    from dataclasses import replace
    pid = project_with_sca(web)
    build_task(web, pid)
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        web.app.state.db.update_project(pid, research_provider_id=profile["id"])
        base = web.app.state.web.base  # настройки маршрутов – settings_of(request): web.base со значениями из базы
        web.app.state.web.base = replace(base, osv_url="https://api.osv.dev")
        try:
            page = preview(web, pid).text
            assert "Запрос OSV" in page and "https://api.osv.dev" in page and "POST /v1/query" in page
            assert '&#34;status&#34;: &#34;pending&#34;' in page or '"status": "pending"' in page
            web.app.state.web.base = replace(base, osv_url="")
            page = preview(web, pid).text
            assert "выключен (OSV_URL=off)" in page and "pending" not in page
        finally:
            web.app.state.web.base = base
