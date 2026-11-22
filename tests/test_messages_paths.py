"""Anthropic Messages API во всех путях приложения (план 0.9.14, шаг 5; ADR-0106): форма профиля через настоящие
маршруты («Проверить», сохранение, повторное открытие, «Пробный ответ», «Проверить поиск»), снимок исполнителя и
клиент из него, резервное имя модели при недоступном /models и ключ кэша списка моделей, точное имя модели, прогон,
вопрос, пересмотр, известные ошибки и неизвестный результат, исследование компонентов. Поддельный сервер – Messages
API на loopback по https с тестовым удостоверяющим центром (класс «Интернет»); данные выдуманы."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import sca_research_net as net  # noqa: E402
from app.db import UNKNOWN_RESULT_NOTE  # noqa: E402
from app.executors import (RESPONSE_MODES, client_for, execution_values, same_model, server_of,  # noqa: E402
                           service_client)
from app.llm_messages import RESPONSE_MODES as CLIENT_MODES, MessagesClient  # noqa: E402
from app.provider_keys import load_key  # noqa: E402
from app.providers import MESSAGES_RESPONSE_LABELS, RESPONSE_LABELS  # noqa: E402
from fake_messages_api import FakeMessagesApi  # noqa: E402
from fake_ollama import ask_answer, verdict_answer  # noqa: E402
from test_external_code_mark import external_loopback, mark  # noqa: E402, F401
from test_findings_ui import AS_JSON, card_of  # noqa: E402
from test_sca_research_net import CUTOFF, good_row, manifest_rows  # noqa: E402
from test_sca_research_routes import build_task, project_with_sca  # noqa: E402
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: E402, F401

KEY = "messages-key-" + "Zr7" * 6
VERSION = "2023-06-01"


def post(web, url: str, **data):  # noqa: F811
    """Форма профиля Messages API: внешний провайдер с ключом (поддельный сервер без x-api-key отвечает 401)."""
    fields = {"name": "Провайдер Messages", "kind": "messages", "trust": "external", "think": "auto", "enabled": "1",
              "messages_response_mode": "tool", "requires_key": "1", **data}
    return web.client.post(url, headers=ORIGIN, follow_redirects=False, data=fields)


def lower(headers: dict) -> dict:
    return {str(k).lower(): v for k, v in headers.items()}


def profile_named(web, name: str) -> dict:  # noqa: F811
    return next(p for p in web.app.state.db.list_providers() if p["name"] == name)


def messages_project(web, fake, **fields) -> tuple[int, dict]:  # noqa: F811
    """Проект с выгрузкой, отметкой «код не секретный» и профилем Messages как профилем модели проекта."""
    pid = prepared(web)
    values = {"name": "Внешний Messages", "base_url": fake.url, "key": KEY, "default_model": "flash-model",
              "max_output": "4096", "thinking": "enabled", "effort": "high", "action": "save", **fields}
    r = post(web, "/settings/providers/new", **values)
    assert r.status_code == 303, r.text[:1500]
    profile = profile_named(web, "Внешний Messages")
    assert "ok=external_marked" in mark(web, pid).headers["location"]
    r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                        data={"provider_id": str(profile["id"])})
    assert r.status_code == 303, r.text[:500]
    return pid, profile


# ============================================================================ форма профиля

def test_response_modes_match_the_client_and_the_form():
    assert RESPONSE_MODES["messages"] == CLIENT_MODES == tuple(MESSAGES_RESPONSE_LABELS)
    assert RESPONSE_MODES["chat_completions"] == tuple(RESPONSE_LABELS)


def test_messages_profile_is_checked_saved_reopened_and_listed(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    page = web.client.get("/settings/providers/new").text
    assert 'value="messages"' in page and "Anthropic Messages API" in page and 'name="messages_response_mode"' in page
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        r = post(web, "/settings/providers/new", base_url=fake.url, key=KEY, action="check")
        assert r.status_code == 200 and "Messages API, моделей: 1" in r.text and "flash-model" in r.text, r.text[:3000]
        sent = lower(fake.requests[-1]["headers"])
        assert sent["x-api-key"] == KEY and sent["anthropic-version"] == VERSION and "authorization" not in sent
        # поля рассуждения от другого протокола и галочка умолчания не сохраняются (ADR-0106 п. 10, ADR-0104 п. 3)
        r = post(web, "/settings/providers/new", name="Messages", base_url=fake.url, key=KEY,
                 default_model="flash-model", messages_response_mode="tool_strict", response_mode="json_schema",
                 thinking="enabled", effort="high", context_window="200000", max_output="4096", tool_steps="5",
                 chat_timeout_s="300", search_on="1", default_code="1", action="save")
        assert r.status_code == 303, r.text[:2000]
    profile = profile_named(web, "Messages")
    assert (profile["kind"], profile["trust"], profile["auth"]) == ("messages", "external", "bearer")
    caps = json.loads(profile["capabilities_json"])
    assert caps["response_mode"] == "tool_strict" and caps["thinking"] == "" and caps["effort"] == ""
    assert caps["search"] == {"search_path": "/v1/tools/search", "fetch_path": "/v1/tools/fetch"}
    assert json.loads(profile["generation_json"]) == {"context_window": 200000, "max_output": 4096, "timeout_s": 300,
                                                      "tool_steps": 5}
    assert load_key(web.app.state.db, profile["id"])["key"] == KEY
    assert int(db.get_settings().get("default_provider_id") or 1) == profile["id"]  # решение владельца 21.11: внешний – умолчанием можно
    form = web.client.get(f"/settings/providers/{profile['id']}").text
    assert 'value="messages" checked' in form and 'value="tool_strict" selected' in form
    assert 'id="provider-search-check"' in form and "(расходует токены)" in form
    assert 'id="provider-code-default-note"' in form and "код не секретный" in form
    listing = web.client.get("/settings/providers").text
    assert "Anthropic Messages API" in listing and "задан, …" + KEY[-4:] in listing and KEY not in listing


@pytest.mark.parametrize("fields, text", [
    ({"trust": "local", "base_url": "http://127.0.0.1:9/v1", "requires_key": ""}, "«этот компьютер»"),
    ({"messages_response_mode": "json_object", "key": KEY}, "формат ответа"),
    ({"base_url": "http://api.example.com/v1", "key": KEY}, "https"),
])
def test_messages_field_errors(web, external_loopback, fields, text):  # noqa: F811
    r = post(web, "/settings/providers/new", **{"base_url": "https://api.example.com/v1", "action": "save", **fields})
    assert r.status_code == 400 and text in r.text, r.text[:3000]


def test_check_without_a_models_list_uses_the_entered_name(web, external_loopback):  # noqa: F811
    with FakeMessagesApi(tls=True) as fake:
        fake.models_mode = 404
        r = post(web, "/settings/providers/new", base_url=fake.url, key=KEY, default_model="gateway-model",
                 action="check")
        assert "список моделей недоступен" in r.text and "не отдаёт список моделей" in r.text, r.text[:3000]
        assert 'value="gateway-model" selected' in r.text and 'id="model-missing"' not in r.text
        r = post(web, "/settings/providers/new", base_url=fake.url, key=KEY, default_model="", action="check")
        assert "имя модели не задано" in r.text
        fake.models_mode = 401
        r = post(web, "/settings/providers/new", base_url=fake.url, key=KEY, default_model="gateway-model",
                 action="check")
        assert "callout-err" in r.text and "моделей:" not in r.text


def test_probe_and_search_check_on_a_saved_profile(web, external_loopback):  # noqa: F811
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        full = {"name": "Messages проба", "base_url": fake.url, "default_model": "flash-model", "max_output": "2048",
                "search_on": "1"}
        r = post(web, "/settings/providers/new", **full, key=KEY, action="save")
        assert r.status_code == 303, r.text[:1500]
        pid = profile_named(web, "Messages проба")["id"]
        r = post(web, f"/settings/providers/{pid}", **full, action="probe")
        assert "ответила за" in r.text and 'id="provider-saved-first"' in r.text, r.text[:3000]
        body = fake.messages_calls()[-1]
        assert body["max_tokens"] == 2048 and body["tool_choice"] == {"type": "tool", "name": "answer"}
        assert "thinking" not in body and not fake.violations
        r = post(web, f"/settings/providers/{pid}", **full, action="search_check")
        assert "Поиск ответил: результатов – 1" in r.text, r.text[:3000]
        assert [x for x in fake.requests if x["path"] == "/v1/tools/search"]


def test_probe_refusal_is_known_and_drop_is_unknown(web, external_loopback):  # noqa: F811
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        full = {"name": "Messages отказ", "base_url": fake.url, "default_model": "flash-model"}
        assert post(web, "/settings/providers/new", **full, key=KEY, action="save").status_code == 303
        pid = profile_named(web, "Messages отказ")["id"]
        fake.answers.append(("blocks", [{"type": "text", "text": "нет"}], "refusal"))
        r = post(web, f"/settings/providers/{pid}", **full, action="probe")
        assert "Пробный ответ не получен" in r.text and "отказалась" in r.text and "Результат неизвестен" not in r.text
        fake.answers.append(("drop",))
        r = post(web, f"/settings/providers/{pid}", **full, action="probe")
        assert "Результат неизвестен" in r.text


# ============================================================================ снимок, клиент, имена, кэш

def test_snapshot_restores_a_messages_client_with_the_run_model():
    profile = {"id": 7, "version": 3, "kind": "messages", "base_url": "https://api.example.com/v1",
               "trust": "external", "auth": "bearer", "default_model": "profile-model",
               "confirmed_addresses_json": "[]",
               "generation_json": json.dumps({"max_output": 4096, "context_window": 200000}),
               "capabilities_json": json.dumps({"response_mode": "tool_strict", "thinking": "enabled",
                                                "effort": "high"})}
    execution = execution_values(profile, "run-model", "triage", 16384, "always")
    data = json.loads(execution["options_json"])
    assert data["timeout_s"] == 600 and data["chat"]["response_mode"] == "tool_strict"
    assert data["chat"]["thinking"] == "" and data["chat"]["effort"] == "" and data["chat"]["max_output"] == 4096
    client = client_for(lambda url: None, execution)
    assert isinstance(client, MessagesClient) and client.response_mode == "tool_strict"
    assert client.max_output == 4096 and client.context_window == 200000 and client.timeout == 600
    assert client.fallback_model == "run-model", "резервное имя – модель прогона, а не профиля"
    assert server_of(profile).model == "profile-model" and server_of(execution).model == "run-model"
    assert service_client(lambda url: None, server_of(profile)).fallback_model == "profile-model"
    # снимок с форматом другого протокола – формат по умолчанию Messages, рассуждение не передаётся
    old = {**execution, "options_json": json.dumps({**data, "chat": {**data["chat"], "response_mode": "json_object",
                                                                     "thinking": "enabled"}})}
    restored = client_for(lambda url: None, old)
    assert restored.response_mode == "tool" and restored.thinking == ""
    # у других протоколов имени в ключе сервера нет – ключи кэшей и наблюдения прежние
    assert server_of({**profile, "kind": "chat_completions"}).model == ""
    assert server_of({**profile, "kind": "ollama"}).model == ""


def test_fit_options_follow_the_server_of_the_request():
    """KIMI-01: срез подгоняется под окно и предел ответа того сервера, куда уйдёт запрос."""
    from app.executors import fit_options
    from app.llm import prompt_fits
    ollama = {"kind": "ollama", "options_json": "{}"}
    assert fit_options(ollama, {"num_ctx": 16384, "num_predict": 3072}) == {"num_ctx": 16384, "num_predict": 3072}
    remote = {"kind": "messages", "options_json": json.dumps({"chat": {"context_window": 6000, "max_output": 1024}})}
    assert fit_options(remote, {"num_ctx": 16384, "num_predict": 3072}) == {"num_ctx": 6000, "num_predict": 1024}
    huge = [{"role": "user", "content": "x " * 60000}]
    assert not prompt_fits(huge, {"num_ctx": 16384, "num_predict": 3072})
    unlimited = {"kind": "chat_completions", "options_json": json.dumps({"chat": {"max_output": 65536}})}
    assert prompt_fits(huge, fit_options(unlimited, {"num_ctx": 16384, "num_predict": 3072})), \
        "окно в профиле не задано – подгонки нет, как и проверки у клиента"


def _sent_user_chars(fake) -> list[int]:
    """Длина первого сообщения user каждого запроса (строка или блоки text протокола Messages)."""
    def text(content) -> str:
        return content if isinstance(content, str) else "".join(b.get("text", "") for b in content)
    return [len(text(c["messages"][0]["content"])) for c in fake.messages_calls()]


@pytest.mark.parametrize("window, trimmed", [("", False), ("7800", True)])
def test_slice_is_fitted_to_the_profile_window(web, external_loopback, window, trimmed):  # noqa: F811
    """KIMI-01: срез подгоняется под окно и предел ответа профиля. Без окна в профиле срез не сокращается (у Ollama
    16384 – тоже); при окне 7800 и пределе ответа 1024 самый длинный срез демо-проекта (оценка промпта ~5,6 тыс.
    токенов при запасе 15 %) сокращается до отправки, а прежняя подгонка по окну Ollama его не трогала."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, context_window=window, max_output="1024")
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        items = db._all("SELECT state, error FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))
        assert run["state"] == "done" and run["failed"] == 0, [i["error"][:160] for i in items if i["error"]]
        assert all(c["max_tokens"] == 1024 for c in fake.messages_calls())
        longest = max(_sent_user_chars(fake))
        assert (longest < 2200) == trimmed, longest  # полный срез самой длинной находки – около 2276 знаков


def test_window_too_small_for_any_slice_says_what_to_change(web, external_loopback):  # noqa: F811
    """Даже наименьший срез не помещается в окно профиля: запрос не уходит, текст – про профиль провайдера, а не про
    MODEL_NUM_CTX Ollama."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, context_window="5000")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        errors = [row["error"] for row in db.run_errors(run["id"])]
        assert errors and all("«Окно контекста модели»" in e and "MODEL_NUM_CTX" not in e for e in errors), errors
        assert not fake.messages_calls(), "запрос, не поместившийся в окно профиля, не отправлен"


def test_model_names_are_exact_for_remote_protocols():
    for kind in ("messages", "chat_completions"):
        name_of = same_model(kind)
        assert name_of("Model") != name_of("model") and name_of("m:latest") != name_of("m")
    ollama = same_model("ollama")
    assert ollama("m:latest") == ollama("m")


def test_models_cache_follows_the_profile_model_name(web, external_loopback):  # noqa: F811
    """/models недоступен: список – имя из профиля; смена имени в профиле меняет ключ кэша (ADR-0106 п. 7)."""
    db = web.app.state.db
    cache = web.app.state.web.models_cache
    with FakeMessagesApi(tls=True) as fake:
        fake.models_mode = 404
        fields = {"name": "Шлюз", "base_url": fake.url}
        assert post(web, "/settings/providers/new", **fields, key=KEY, default_model="first-model",
                    action="save").status_code == 303
        pid = profile_named(web, "Шлюз")["id"]
        assert [m["name"] for m in cache.get(server_of(db.get_provider(pid)), False)["models"]] == ["first-model"]
        assert post(web, f"/settings/providers/{pid}", **fields, default_model="second-model",
                    action="save").status_code == 303
        assert [m["name"] for m in cache.get(server_of(db.get_provider(pid)), False)["models"]] == ["second-model"]


# ============================================================================ прогон, вопрос, пересмотр

def test_run_question_and_reanalysis_go_through_messages_api(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        fake.default_answer = verdict_answer("false_positive")
        models_before = sum(1 for p in fake.paths() if p.endswith("/models"))
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["done"] == total and run["failed"] == 0, run
        models_during = sum(1 for p in fake.paths() if p.endswith("/models")) - models_before
        # список моделей – одна сверка перед прогоном, не по запросу на находку
        assert total >= 3 and models_during <= 2, (models_during, total)
        calls = fake.messages_calls()
        assert len(calls) == total and not fake.violations, fake.violations
        first = calls[0]
        assert first["model"] == "flash-model" and first["max_tokens"] == 4096 and first["system"]
        assert first["tool_choice"] == {"type": "tool", "name": "answer"} and "thinking" not in first
        sent = lower(next(r for r in fake.requests if r["path"].endswith("/messages"))["headers"])
        assert sent["x-api-key"] == KEY and sent["anthropic-version"] == VERSION and "authorization" not in sent
        page = web.client.get(f"/runs/{run['id']}").text
        assert "(интернет)" in page
        # модель у провайдера: вместо видеокарты и памяти этого компьютера – где работает модель и скорость ответа
        assert "Где работает модель" in page and "у внешнего провайдера (интернет)" in page
        assert "RAM компьютера с Ollama" not in page and 'id="obs-window"' not in page
        status = web.client.get(f"/runs/{run['id']}/status").json()
        assert status["remote_executor"] is True and status["tps_avg"] and status["tps_last"] == status["tps_avg"]
        hub_id = db.sast_queue(pid, "all")[0]
        fid, card = card_of(web, pid, hub_id)
        assert 'id="ask-paid"' in card and 'id="reanalyze-paid"' in card
        fake.answers += [ask_answer("Нет: параметр проверяется на строке 12.", "нет")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                            data={"question": "А если параметр из сессии?", "model": "flash-model"})
        answer = r.json()
        assert r.status_code == 200 and answer["ok"] and answer["answered"], answer
        assert answer["question"]["answer"].startswith("Нет:")
        sent_count = len(fake.messages_calls())
        fake.answers += [verdict_answer("true_positive")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=ORIGIN, follow_redirects=False,
                            data={"model": "flash-model", "fresh": "1"})
        assert r.status_code == 303 and "ok=reanalyze" in r.headers["location"], r.headers["location"]
        rerun = db.list_runs(pid, 1)[0]["id"]
        assert wait_run(web, rerun)["state"] == "done" and len(fake.messages_calls()) == sent_count + 1
        assert db.get_case(pid, hub_id)["verdict"]["data"]["verdict"] == "true_positive"
        assert not fake.violations, fake.violations


def test_card_keeps_the_verdict_model_when_the_server_lists_no_models(web, external_loopback):  # noqa: F811
    """Ревью Codex, круг 17: сервер без /models, вердикт моделью A, затем имя в профиле сменили на B – в карточке
    модель A остаётся (с пометкой «модель прежнего разбора») и выбрана для вопроса; вопрос уходит моделью A."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["first-model", "second-model"]) as fake:
        fake.models_mode = 404
        pid, profile = messages_project(web, fake, default_model="first-model")
        fake.default_answer = verdict_answer("false_positive")
        assert wait_run(web, start_run(web, pid, model="first-model"))["state"] == "done"
        values = {"name": profile["name"], "base_url": fake.url, "default_model": "second-model", "max_output": "4096",
                  "action": "save"}
        assert post(web, f"/settings/providers/{profile['id']}", **values).status_code == 303
        hub_id = db.sast_queue(pid, "all")[0]
        fid, card = card_of(web, pid, hub_id)
        assert "second-model – имя из профиля, список моделей сервер не отдаёт" in card
        assert 'value="first-model" selected>first-model – модель прежнего разбора' in card, card[card.find("ask"):][:3000]
        fake.answers += [ask_answer("Нет: тестовый код.", "нет")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                            data={"question": "Почему?", "model": "first-model"})
        assert r.json()["answered"], r.json()
        assert fake.messages_calls()[-1]["model"] == "first-model"


def test_run_without_a_models_list_and_with_an_inexact_name(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="Flash-Model"))
        assert run["state"] == "error" and "сравнивается точно" in run["last_error"], run
        assert "ollama pull" not in run["last_error"] and not fake.messages_calls()
        fake.models_mode = 404  # шлюз без /models: список – модель прогона (ADR-0106 п. 7)
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["done"] == total and run["failed"] == 0, run


@pytest.mark.parametrize("stop", ["refusal", "model_context_window_exceeded", "something_new"])
def test_known_stop_reasons_finish_the_finding_and_retry_normally(web, external_loopback, monkeypatch, stop):  # noqa: F811
    """Известный исход (ADR-0106 п. 8): находка – ошибка с причиной до служебного опроса сервера, расход ответа
    записан, «Продолжить» её не отправляет, повтор – «Повторить ошибочные» без флажка неизвестных."""
    from app import triage as triage_module
    db = web.app.state.db
    monkeypatch.setattr(triage_module.TriageRunner, "_server_alive", lambda self, client: False)
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("blocks", [{"type": "text", "text": "нет"}], stop)]
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["failed"] == 1 and run["done"] == total, run
        first = web.app.state.db._all("SELECT * FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))[0]
        assert first["state"] == "error" and not first["error"].startswith(UNKNOWN_RESULT_NOTE), first["error"]
        assert [row["unknown"] for row in db.run_errors(run["id"])] == [False]
        # ответ получен целиком – замеры полные (KIMI-05: признак ставился по пустому тексту ответа)
        assert first["stats_partial"] == 0 and run["partial_stats"] == 0, (first["stats_partial"], run["partial_stats"])
        assert run["output_tokens"] == 40 * total, "расход ответа с известной ошибкой вошёл в расход прогона"
        assert len(fake.messages_calls()) == total
        monkeypatch.setattr(triage_module.TriageRunner, "_server_alive", lambda self, client: True)
        r = web.client.post(f"/runs/{run['id']}/retry-errors", headers=ORIGIN, follow_redirects=False, data={})
        assert r.status_code == 303 and "error=" not in r.headers["location"], r.headers.get("location")
        retry = int(r.headers["location"].split("/runs/")[1].split("?")[0])
        assert wait_run(web, retry)["state"] == "done" and len(fake.messages_calls()) == total + 1


def test_drop_after_sending_is_an_unknown_result_without_resend(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("drop",)]
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["failed"] == 1, run
        first = db._all("SELECT * FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))[0]
        assert first["error"].startswith(UNKNOWN_RESULT_NOTE) and len(fake.messages_calls()) == total
        r = web.client.post(f"/runs/{run['id']}/retry-errors", headers=ORIGIN, follow_redirects=False, data={})
        assert len(fake.messages_calls()) == total, "без флажка неизвестных повтора нет"
        assert r.status_code == 303
        # повтор с отметкой разобрал находку ...
        r = web.client.post(f"/runs/{run['id']}/retry-errors", headers=ORIGIN, follow_redirects=False,
                            data={"include_unknown": "1"})
        retry = int(r.headers["location"].rsplit("/", 1)[1])
        assert wait_run(web, retry)["state"] == "done" and len(fake.messages_calls()) == total + 1
        # ... и прежний прогон её больше не предлагает: второе нажатие – ни одного платного запроса
        r = web.client.post(f"/runs/{run['id']}/retry-errors", headers=ORIGIN, follow_redirects=False,
                            data={"include_unknown": "1"})
        assert r.status_code == 303 and "error=" in r.headers["location"], r.headers["location"]
        assert len(fake.messages_calls()) == total + 1, "разобранная позже находка повторно не отправлена"
        errors = web.client.get(f"/runs/{run['id']}/status").json()["errors"]
        assert errors["unknown"] == 0 and errors["resolved"] == 1 and errors["retryable"] == 0
        assert f"уже разобрана в прогоне №{retry}" in web.client.get(f"/runs/{run['id']}").text
        assert "1 уже разобраны более поздним прогоном" in errors["note"]


def test_without_the_mark_nothing_is_sent(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake)
        r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        fake.default_answer = verdict_answer("false_positive")
        r = web.client.post(f"/projects/{pid}/runs", data={"model": "flash-model", "scope": "all"}, headers=ORIGIN,
                            follow_redirects=False)
        assert r.status_code == 400 and "код не секретный" in r.text, (r.status_code, r.text[:1500])
        assert not fake.messages_calls()
        assert db.get_project(pid)["external_allowed"] in (0, None)


# ============================================================================ исследование компонентов

def test_component_research_goes_through_messages_api(web, external_loopback):  # noqa: F811
    """Исследование провайдером через Messages API (ADR-0106, ADR-0105): поиск инструментом, ответ инструментом answer,
    результаты одного хода – одним сообщением user из блоков tool_result."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid = project_with_sca(web)
        build_task(web, pid)
        task = db.current_task(pid)
        r = post(web, "/settings/providers/new", name="Исследователь Messages", base_url=fake.url, key=KEY,
                 default_model="flash-model", max_output="4096", tool_steps="3", search_on="1", action="save")
        assert r.status_code == 303, r.text[:1500]
        profile = profile_named(web, "Исследователь Messages")
        from app.routes.components import research_profile_ok
        assert research_profile_ok(profile)
        execution = execution_values(profile, "flash-model", "ask", 16384, "always", purpose="research")
        system = net.instructions(True)
        refs = [row["input_ref"] for row in db.task_rows(task["id"])]
        consent = db.create_research_consent(pid, task["id"], execution, {
            "components_sha256": task["components_sha256"] or task["manifest_sha256"], "cutoff_date": CUTOFF,
            "instructions": system, "instructions_sha256": net.sha256(system), "rows": refs, "selection": "all",
            "model": "flash-model", "search_mode": "tools", "tool_steps": 3})
        run = db.start_research_run(consent["id"])
        rows = manifest_rows(web, task)
        fake.answers += [("tools", [("search", {"query": "example-parser advisory"})]),
                         ("tools", [("answer", {"row": good_row(rows[0], task)})])]
        fake.answers += [("tools", [("answer", {"row": good_row(row, task)})]) for row in rows[1:]]
        net.ResearchRunner(db, lambda e: client_for(web.app.state.web.make_client, e, db=db)).run(run["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "done" and done["rows_saved"] == len(rows), done
        calls = fake.messages_calls()
        assert calls[0]["tool_choice"] == {"type": "auto"} and {t["name"] for t in calls[0]["tools"]} >= {"search",
                                                                                                          "answer"}
        assert calls[0]["system"] == consent["instructions"] and "thinking" not in calls[0]
        results = calls[1]["messages"][-1]["content"]
        assert results[0]["type"] == "tool_result", "результат поиска – блоком tool_result в сообщении user"
        assert not fake.violations, fake.violations
        assert [x for x in fake.requests if x["path"] == "/v1/tools/search"]


def test_research_through_the_routes_with_a_messages_profile(web, external_loopback):  # noqa: F811
    """Ревью Codex, круг 17: исследование профилем Messages через настоящие маршруты – выбор профиля исследования
    проекта, предпросмотр, согласие, запуск; страница хода, статус и полоса «идёт получение» – тем же путём, что у
    чат-завершений."""
    from test_sca_research_net_ui import preview, start
    from test_sca_research_net_ui import wait_run as wait_research
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid = project_with_sca(web)
        build_task(web, pid)
        task = db.current_task(pid)
        r = post(web, "/settings/providers/new", name="Исследователь Messages", base_url=fake.url, key=KEY,
                 default_model="flash-model", max_output="4096", tool_steps="3", search_on="1", action="save")
        assert r.status_code == 303, r.text[:1500]
        profile = profile_named(web, "Исследователь Messages")
        r = web.client.post(f"/projects/{pid}/components/research-provider", headers=ORIGIN, follow_redirects=False,
                            data={"research_provider_id": str(profile["id"])})
        assert "ok=research_provider_saved" in r.headers["location"], r.headers["location"]
        rows = manifest_rows(web, task)
        fake.answers += [("tools", [("answer", {"row": good_row(row, task)})]) for row in rows]
        page = preview(web, pid).text
        assert "flash-model" in page and "Исследователь Messages" in page
        r = start(web, pid, page)
        assert r.status_code == 303, r.text[:800]
        run_id = int(r.headers["location"].rsplit("/", 1)[1])
        run = wait_research(web, run_id)
        assert run["state"] == "done" and run["rows_saved"] == len(rows), run
        status = web.client.get(f"/projects/{pid}/components/research/{run_id}/status").json()
        assert {row["state"] for row in status["rows"]} == {"saved"}
        assert web.client.get(f"/api/research/active?last={run_id}").json()["run"]["state"] == "done"
        assert not fake.violations, fake.violations
        sent = lower(next(x for x in fake.requests if x["path"].endswith("/messages"))["headers"])
        assert sent["x-api-key"] == KEY and sent["anthropic-version"] == VERSION


# ============================================================================ повтор после обрыва

def test_drop_is_retried_once_when_the_profile_allows_it(web, external_loopback):  # noqa: F811
    """Отметка профиля «Повторять после обрыва без ответа»: обрыв – один повтор, ответ повтора – вердикт; карточка
    говорит «повтор после обрыва связи»; без отметки – прежнее «результат неизвестен» (тест выше)."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, profile = messages_project(web, fake, retry_on_drop="1")
        assert json.loads(profile["capabilities_json"])["retry_on_drop"] is True
        assert 'name="retry_on_drop" value="1" checked' in web.client.get(f"/settings/providers/{profile['id']}").text
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("drop",)]
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["failed"] == 0 and run["done"] == total, run
        assert len(fake.messages_calls()) == total + 1, "ровно один повтор"
        hub_id = db._all("SELECT hub_id FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))[0]["hub_id"]
        stats = db.get_case(pid, hub_id)["verdict"]["stats"]
        assert stats["drop_retries"] == 1 and stats["attempts"] >= 2, stats
        assert "повтор после обрыва связи" in card_of(web, pid, hub_id)[1]


def test_second_drop_stays_unknown_and_is_not_resent(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, retry_on_drop="1")
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("drop",), ("drop",)]
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "done" and run["failed"] == 1, run
        first = db._all("SELECT * FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))[0]
        assert first["error"].startswith(UNKNOWN_RESULT_NOTE) and "тоже остался без ответа" in first["error"]
        assert len(fake.messages_calls()) == total + 1, "второй обрыв – без третьей отправки"


def test_a_cascade_of_drops_pauses_the_run(web, external_loopback):  # noqa: F811
    """Три находки подряд с обрывом – прогон на паузе с причиной, оставшиеся не отправляются; «Продолжить» – счёт
    заново, оборванные находки сами не отправляются."""
    from app.executors import DROP_STREAK_PAUSE
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, retry_on_drop="1")
        total = len(db.sast_queue(pid, "all"))
        assert total > DROP_STREAK_PAUSE
        fake.answers += [("drop",)] * (2 * DROP_STREAK_PAUSE)  # каждая находка: обрыв и обрыв повтора
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "paused" and "обрывает соединения" in run["last_error"], run
        assert run["failed"] == DROP_STREAK_PAUSE and len(fake.messages_calls()) == 2 * DROP_STREAK_PAUSE
        r = web.client.post(f"/runs/{run['id']}/resume", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        run = wait_run(web, run["id"])
        assert run["state"] == "done" and run["done"] == total, run
        assert len(fake.messages_calls()) == 2 * DROP_STREAK_PAUSE + total - DROP_STREAK_PAUSE, \
            "после «Продолжить» – только оставшиеся находки"


def _messages_research(web, fake, **profile_fields):  # noqa: F811
    """Проект с SCA, задание, профиль Messages с поиском, согласие и получение (как в тесте исследования выше)."""
    db = web.app.state.db
    pid = project_with_sca(web)
    build_task(web, pid)
    task = db.current_task(pid)
    r = post(web, "/settings/providers/new", name="Исследователь Messages", base_url=fake.url, key=KEY,
             default_model="flash-model", max_output="4096", tool_steps="3", search_on="1", action="save",
             **profile_fields)
    assert r.status_code == 303, r.text[:1500]
    profile = profile_named(web, "Исследователь Messages")
    execution = execution_values(profile, "flash-model", "ask", 16384, "always", purpose="research")
    system = net.instructions(True)
    refs = [row["input_ref"] for row in db.task_rows(task["id"])]
    consent = db.create_research_consent(pid, task["id"], execution, {
        "components_sha256": task["components_sha256"] or task["manifest_sha256"], "cutoff_date": CUTOFF,
        "instructions": system, "instructions_sha256": net.sha256(system), "rows": refs, "selection": "all",
        "model": "flash-model", "search_mode": "tools", "tool_steps": 3})
    run = db.start_research_run(consent["id"])
    runner = net.ResearchRunner(db, lambda e: client_for(web.app.state.web.make_client, e, db=db))
    return db, task, run, runner


def test_research_turn_is_retried_once_after_a_drop(web, external_loopback):  # noqa: F811
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake, retry_on_drop="1")
        rows = manifest_rows(web, task)
        fake.answers += [("drop",), ("tools", [("answer", {"row": good_row(rows[0], task)})])]
        fake.answers += [("tools", [("answer", {"row": good_row(row, task)})]) for row in rows[1:]]
        runner.run(run["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "done" and done["rows_saved"] == len(rows) and done["rows_unknown"] == 0, done
        assert len(fake.messages_calls()) == len(rows) + 1


def test_research_without_the_mark_keeps_unknown_and_counts_its_usage(web, external_loopback):  # noqa: F811
    """Без отметки обрыв хода – «результат неизвестен» без повтора; расход этой строки входит в итог получения."""
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("drop",)]
        fake.answers += [("tools", [("answer", {"row": good_row(row, task)})]) for row in rows[1:]]
        runner.run(run["id"])
        done = db.research_run(run["id"])
        assert done["rows_unknown"] == 1 and done["rows_saved"] == len(rows) - 1, done
        assert len(fake.messages_calls()) == len(rows)
        usage = json.loads(done["usage_json"] or "{}")
        assert usage.get("sends", 0) == len(rows), ("отправка оборванной строки – в итоге получения", usage)


def test_research_stops_after_a_streak_of_drops(web, external_loopback, monkeypatch):  # noqa: F811
    """Серия строк с обрывом – получение остановлено с причиной, следующие строки не отправляются. В демо-задании
    строк две – порог серии в тесте 1 (в работе DROP_STREAK_PAUSE = 3)."""
    monkeypatch.setattr(net, "DROP_STREAK_PAUSE", 1)
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake, retry_on_drop="1")
        rows = manifest_rows(web, task)
        assert len(rows) >= 2, len(rows)
        fake.answers += [("drop",)] * 2  # первая строка: обрыв и обрыв повтора
        runner.run(run["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "обрывает соединения" in (done["reason"] or ""), done
        assert done["rows_unknown"] == 1 and len(fake.messages_calls()) == 2, "следующая строка не отправлена"


# ============================================================================ ревью Codex, круг 18

def test_retry_without_a_model_answer_keeps_the_unknown_result(web, external_loopback):  # noqa: F811
    """Обрыв, повтор получил 402 (ответа модели нет): находка – «результат неизвестен» первого запроса, а не очередь;
    «Продолжить» её не отправит (блокирующее круга 18)."""
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, retry_on_drop="1")
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("drop",), ("http", 402, {"type": "error", "error": {"type": "billing_error",
                                                                             "message": "insufficient balance"}})]
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        first = db._all("SELECT * FROM run_items WHERE run_id = ? ORDER BY seq", (run["id"],))[0]
        assert first["state"] == "error" and first["error"].startswith(UNKNOWN_RESULT_NOTE), first
        assert "не получил ответа модели" in first["error"] and first["sending_at"] is None
        # 402 повтора – следующие находки провайдер тоже не примет: пауза по оплате (ревью Codex, круг 19, находка 2)
        assert run["state"] == "paused" and "оплат" in (run["last_error"] or "").casefold(), run
        assert len(fake.messages_calls()) == 2 and total > 1, "следующая находка не отправлена"
        assert first["stats_partial"], "расход оборванной попытки неизвестен – замеры неполные"


def test_deadline_before_the_retry_keeps_the_unknown_result():
    """Круг 19, находка 1: срок обращения истёк до повторной отправки – запрос не ушёл, ответа модели нет; исход
    оборванной попытки остаётся неизвестным (reason="deadline" – не ответ модели)."""
    from app.llm import LlmError, model_answered
    assert not model_answered(LlmError("срок", reason="deadline"))
    assert not model_answered(LlmError("предел", reason="budget"))
    assert model_answered(LlmError("отказ", reason="refusal"))
    assert not model_answered(LlmError("обрыв"))


def test_refusal_after_a_drop_has_partial_stats():
    """Круг 19, находка 3: обрыв, затем известный отказ повтора – расход оборванной попытки неизвестен."""
    from app.llm import LlmError
    from app.triage import _stats_partial
    e = LlmError("отказ", reason="refusal")
    assert not _stats_partial(e)
    e.drop_retries = 1
    assert _stats_partial(e)


def test_known_refusals_after_drops_still_count_as_a_streak(web, external_loopback):  # noqa: F811
    """Обрыв, затем известный отказ повтора – тоже обрыв: три такие находки подряд – пауза (круг 18, находка 2)."""
    from app.executors import DROP_STREAK_PAUSE
    db = web.app.state.db
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = messages_project(web, fake, retry_on_drop="1")
        assert len(db.sast_queue(pid, "all")) > DROP_STREAK_PAUSE
        refusal = ("blocks", [{"type": "text", "text": "нет"}], "refusal")
        fake.answers += [("drop",), refusal] * DROP_STREAK_PAUSE
        fake.default_answer = verdict_answer("false_positive")
        run = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run["state"] == "paused" and "обрывает соединения" in run["last_error"], run


def test_merged_stats_add_up_both_attempts():
    from app.models import LlmStats
    from app.triage import _merged_stats
    first = LlmStats(model="m", prompt_tokens=100, output_tokens=40, eval_tps=0.0, prompt_tps=0.0, total_s=3.0,
                     load_s=0.0, attempts=2, think="-", reasoning_tokens=10, cache_hit_tokens=50)
    second = LlmStats(model="m", prompt_tokens=120, output_tokens=60, eval_tps=0.0, prompt_tps=0.0, total_s=5.0,
                      load_s=0.0, attempts=1, think="-", reasoning_tokens=20, cache_hit_tokens=70)
    merged = _merged_stats(first, second)
    assert (merged.prompt_tokens, merged.output_tokens, merged.attempts, merged.total_s, merged.reasoning_tokens,
            merged.cache_hit_tokens) == (220, 100, 3, 8.0, 30, 120)
    assert _merged_stats(None, second) is second and _merged_stats(first, None) is first


def test_fit_measures_like_the_remote_client():
    """Круг 18, находка 4: текст с кавычками – по тексту помещается, а клиент удалённого API считает JSON сообщения с
    экранированием и отказал бы; подгонка для удалённого API меряет так же, как клиент."""
    from app.executors import prompt_size
    from app.llm import prompt_fits
    messages = [{"role": "user", "content": '"' * 2000}]
    options = {"num_ctx": 4096, "num_predict": 1024}
    assert prompt_fits(messages, options), "по тексту – помещается"
    remote = prompt_size({"kind": "messages"})
    assert remote is not None and not prompt_fits(messages, options, remote), "по JSON сообщения – нет"
    assert prompt_size({"kind": "ollama"}) is None


def test_research_stopped_after_a_drop_keeps_the_row_unknown(web, external_loopback, monkeypatch):  # noqa: F811
    """Обрыв хода, затем остановка получения до повтора: строка «результат неизвестен», а не очередь (круг 18)."""
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake, retry_on_drop="1")
        fake.answers += [("drop",)]
        monkeypatch.setattr(runner, "_stopped", lambda run_id: len(fake.messages_calls()) >= 1)
        runner.run(run["id"])
        rows = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        states = sorted(r["state"] for r in rows.values())
        assert "unknown" in states and len(fake.messages_calls()) == 1, states
        unknown = next(r for r in rows.values() if r["state"] == "unknown")
        assert "повтор не отправлен" in unknown["reason"]


def test_messages_dns_after_a_http_retry_spends_the_only_retry(web, external_loopback, monkeypatch):  # noqa: F811
    """ADR-0113 (ревью круга 52): 429 → повтор транспорта → сбой службы имён (запрос не ушёл) → повтор хода после паузы →
    429: второго повтора транспорта в строке нет – счётчик http_retries передаётся и у Messages API. Отправок две (429
    и 429), сбой службы имён не считается и не делает строку «результат неизвестен»."""
    from app.llm import ResolveError
    busy = ("http", 429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}},
            {"retry-after": "0"})
    monkeypatch.setattr(net, "_sleep", lambda seconds: None)
    real = MessagesClient._request
    seen: list[str] = []

    def flaky(self, path, payload=None, **kwargs):
        if path == self.generate_path:
            seen.append(path)
            if len(seen) == 2:  # второй запрос генерации – повтор транспорта после 429
                raise ResolveError("Имя сервера «api.example.invalid» не найдено службой имён (DNS) (3 попытки подряд).")
        return real(self, path, payload, **kwargs)
    monkeypatch.setattr(MessagesClient, "_request", flaky)
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake)
        fake.answers += [busy, busy, busy]
        runner.run(run["id"])
        first = db.research_run_rows(run["id"])[0]
        assert first["state"] == "failed" and "429" in first["reason"] and "Результат неизвестен" not in first["reason"], first
        assert int(first["usage"]["sends"]) == 2, (seen, first)  # 429 и 429; сбой службы имён не считается
        assert len(seen) >= 3, "429, сбой службы имён на повторе транспорта, 429 после паузы (дальше – другие строки)"


def test_research_allows_one_http_retry_per_row_even_after_a_drop(web, external_loopback):  # noqa: F811
    """429 → повтор транспорта → обрыв → автоповтор хода → 429: второго повтора транспорта нет (круг 18, находка 5)."""
    busy = ("http", 429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}},
            {"retry-after": "0"})
    with FakeMessagesApi(tls=True, models=["flash-model"]) as fake:
        db, task, run, runner = _messages_research(web, fake, retry_on_drop="1")
        fake.answers += [busy, ("drop",), busy, busy]
        runner.run(run["id"])
        first = db.research_run_rows(run["id"])[0]
        assert first["state"] in ("failed", "unknown"), first
        sends = int((first.get("usage") or {}).get("sends") or 0)
        assert sends == 3, ("429, повтор с обрывом, автоповтор с 429 – без второго повтора 429", sends, first)
