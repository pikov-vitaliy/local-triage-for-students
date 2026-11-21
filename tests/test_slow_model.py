"""Медленный режим модели: распознавание по скорости ответов, выгрузка между находками, предупреждение после
двух перезагрузок, оценка времени по медиане и строка оператору на странице прогона."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import journal  # noqa: E402
from app.prompts import PROMPT_VERSION  # noqa: E402
from fake_ollama import DEFAULT_STATS, verdict_answer  # noqa: E402
from run_helpers import run_execution  # noqa: E402
from test_triage import Env, env, sast  # noqa: E402, F401
from test_web import ORIGIN, prepared, web  # noqa: E402, F401

MODEL = "qwen2.5-coder:14b"


def answer(tps: float, *, delay: float = 0.0, verdict: str = "false_positive"):
    """Ответ поддельной Ollama с заданной скоростью вывода: eval_count / eval_duration. delay – пауза до ответа,
    чтобы различать время модели в оценке оставшегося времени."""
    tokens = int(DEFAULT_STATS["eval_count"])
    reply = ("reply", verdict_answer(verdict), {"eval_duration": int(round(tokens / tps * 1e9))})
    return ("sleep", delay, reply) if delay else reply


def findings(count: int) -> list:
    """Находки с одинаковым кодом, но разным правилом: отпечаток случая у них разный, модель вызывается для каждой."""
    return [sast(f"F{index}", 15, rule=f"Правило {index}") for index in range(count)]


def request_indexes(fake, path: str) -> list[int]:
    return [index for index, (_, current, _) in enumerate(fake.requests) if current == path]


def generates(fake) -> list[dict]:
    return [body for _, path, body in fake.requests if path == "/api/generate"]


def test_two_slow_answers_reload_model_once_between_findings(env: Env):
    env.fake.delay = 0.3
    env.fake.answers = [answer(100, delay=0.0), answer(100), answer(100),
                        answer(10, delay=0.7), answer(10, delay=0.7), answer(100)]
    env.load(findings(6))
    run = env.run()
    assert (run["state"], run["done"], run["failed"], run["model_calls"]) == ("done", 6, 0, 6)

    unloads = generates(env.fake)
    assert len(unloads) == 1 and unloads[0]["keep_alive"] == 0 and unloads[0]["model"] == MODEL
    chats, calls = request_indexes(env.fake, "/api/chat"), request_indexes(env.fake, "/api/generate")
    assert chats[4] < calls[0] < chats[5], "выгрузка – после пятого ответа и до следующего запроса к модели"

    status = env.runner.run_status(run["id"])
    slow = status["slow_model"]
    assert slow and slow["reloads"] == 1 and not slow["warning"]
    assert slow["text"] == "Модель работала медленно (10 ток/с при обычных 100) – перезагружена"
    assert slow["tps"] == 10 and slow["baseline"] == 100

    saved = journal.detail(env.db, run["id"])["snapshot"]["slow_model"]
    assert [event["action"] for event in saved["events"]] == ["reload"]
    # Медленные ответы и первый после загрузки модели в оценку времени не входят: остались три быстрых.
    durations = journal.detail(env.db, run["id"])["snapshot"]["model_durations"]
    # медленные ответы шли не меньше 1,0 с (0,7 + 0,3), быстрые – около 0,3 с; порог между ними – с запасом на
    # нагрузку машины во время полного прогона
    assert len(durations) == 3 and max(durations) < 0.95


def test_single_slow_answer_changes_nothing(env: Env):
    env.fake.answers = [answer(100), answer(100), answer(100), answer(10), answer(100)]
    env.load(findings(5))
    run = env.run()
    assert (run["state"], run["done"], run["model_calls"]) == ("done", 5, 5)
    assert not generates(env.fake)
    assert env.runner.run_status(run["id"])["slow_model"] is None


def test_warning_after_two_reloads_without_third(env: Env):
    env.fake.answers = [answer(100), answer(100), answer(100), answer(10), answer(10), answer(100),
                        answer(10), answer(10), answer(100), answer(10), answer(10)]
    env.load(findings(11))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 11, 0)
    assert len(generates(env.fake)) == 2, "больше двух перезагрузок за прогон не делается"

    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow and slow["warning"] and slow["reloads"] == 2
    assert "перезагрузка не помогла" in slow["text"]
    assert "закройте программы, использующие видеокарту" in slow["text"]
    assert "«Пауза» → «Продолжить»" in slow["text"]
    saved = journal.detail(env.db, run["id"])["snapshot"]["slow_model"]
    assert [event["action"] for event in saved["events"]] == ["reload", "reload", "warning"]


def test_absolute_threshold_without_reference_but_known_fast_model(env: Env):
    """Ориентира ещё нет (меньше трёх ответов), но модель раньше давала больше 80 ток/с: два первых ответа
    подряд ниже 30 ток/с – медленный режим."""
    prior = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["H"],
                              execution=run_execution(env.db, env.settings, MODEL))
    prior_item = env.db.next_pending_item(prior)
    env.db.finish_item(prior, prior_item["id"], "done", seconds=2.0, model_call=True, model_seconds=2.0,
                       eval_tps=150.0, output_tokens=300, eval_seconds=2.0)
    assert env.db.set_run_state(prior, "done", only_from=("queued",))

    env.fake.answers = [answer(20), answer(20), answer(100)]
    env.load(findings(3))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 3, 0)
    assert len(generates(env.fake)) == 1
    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow and slow["text"] == "Модель работала медленно (20 ток/с при обычных 150) – перезагружена"


def prior_fast_run(env: Env, execution: dict | None) -> None:
    """Прошлый прогон той же модели с одним быстрым ответом (150 ток/с): снимок исполнителя – execution."""
    prior = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["H"], execution=execution)
    prior_item = env.db.next_pending_item(prior)
    env.db.finish_item(prior, prior_item["id"], "done", seconds=2.0, model_call=True, model_seconds=2.0,
                       eval_tps=150.0, output_tokens=300, eval_seconds=2.0)
    assert env.db.set_run_state(prior, "done", only_from=("queued",))


def test_history_of_another_server_or_legacy_runs_is_not_a_reference(env: Env):
    """Статистика скорости – по конфигурации исполнителя (ADR-0102, П24): быстрые ответы той же модели на другом
    сервере и прогоны без снимка (до 0.9.12, адрес не установлен) не делают текущие ответы «медленными»."""
    other = run_execution(env.db, env.settings, MODEL)
    other["base_url"] = "http://192.0.2.10:11434"
    prior_fast_run(env, other)
    prior_fast_run(env, None)
    assert env.db.model_tps_samples(MODEL) == [150.0, 150.0]  # без исполнителя – вся история модели
    mine = run_execution(env.db, env.settings, MODEL)
    assert env.db.model_tps_samples(MODEL, executor=(mine["kind"], mine["base_url"])) == []
    assert env.db.model_tps_samples(MODEL, executor=(other["kind"], other["base_url"])) == [150.0]

    env.fake.answers = [answer(20), answer(20), answer(20)]
    env.load(findings(3))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 3, 0)
    assert len(generates(env.fake)) == 0  # ориентира нет – модель не перезагружается
    assert not env.runner.run_status(run["id"])["slow_model"]


def test_slow_model_on_a_shared_server_is_not_unloaded_without_permission(env: Env, monkeypatch):
    """Сервер профиля lan может выполнять чужие задачи: выгружать модель медленный режим не вправе, пока профиль этого
    не разрешил (ADR-0102 п. 9). Вместо перезагрузки – предупреждение с причиной."""
    shared = run_execution(env.db, env.settings, MODEL)
    assert '"allows_unload": true' in shared["options_json"]
    prior_fast_run(env, shared)
    import ipaddress

    from app import llm_net
    # поддельный сервер слушает loopback: для теста он – «сеть организации» с подтверждённым адресом
    monkeypatch.setattr(llm_net, "LAN_NETWORKS", (*llm_net.LAN_NETWORKS, ipaddress.ip_network("127.0.0.0/8")))
    with env.db._tx() as c:  # профиль приложения – общий сервер в сети (trust lan), выгрузка не разрешена
        c.execute("UPDATE llm_providers SET trust = 'lan', capabilities_json = '{}', version = version + 1,"
                  " confirmed_addresses_json = '[\"127.0.0.1\"]' WHERE id = 1")

    env.fake.answers = [answer(20)] * 4
    env.load(findings(4))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 4, 0)
    execution = env.db.get_execution(env.db.get_run(run["id"])["execution_id"])
    assert '"allows_unload": false' in execution["options_json"]
    assert '"host_metrics": false' in execution["options_json"]
    assert len(generates(env.fake)) == 0  # ни одной выгрузки и загрузки модели
    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow and slow["warning"] and slow["reloads"] == 0
    assert "Выгрузка модели на этом сервере не разрешена профилем." in slow["text"]


def test_reloads_and_warning_when_the_model_stays_slow_without_reference(env: Env):
    """Модель раньше была быстрой, а теперь все ответы медленные: перезагрузка не восстанавливает ориентир,
    поэтому после второй перезагрузки оператор получает предупреждение, а не новую попытку."""
    prior = env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["H"],
                              execution=run_execution(env.db, env.settings, MODEL))
    prior_item = env.db.next_pending_item(prior)
    env.db.finish_item(prior, prior_item["id"], "done", seconds=2.0, model_call=True, model_seconds=2.0,
                       eval_tps=150.0, output_tokens=300, eval_seconds=2.0)
    assert env.db.set_run_state(prior, "done", only_from=("queued",))

    env.fake.answers = [answer(20)] * 8
    env.load(findings(8))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 8, 0)
    assert len(generates(env.fake)) == 2
    slow = env.runner.run_status(run["id"])["slow_model"]
    assert slow and slow["warning"] and slow["reloads"] == 2
    assert "перезагрузка не помогла" in slow["text"]


def test_absolute_threshold_requires_a_model_that_was_fast(env: Env):
    """Без единого прошлого замера нельзя утверждать, что модель вообще быстрая: двух ответов по 20 ток/с мало."""
    env.fake.answers = [answer(20), answer(20), answer(100)]
    env.load(findings(3))
    run = env.run()
    assert (run["state"], run["done"], run["failed"]) == ("done", 3, 0)
    assert not generates(env.fake)
    assert env.runner.run_status(run["id"])["slow_model"] is None


def test_eta_uses_median_not_mean(tmp_path: Path):
    from app.db import Database

    db = Database(tmp_path / "eta.db")
    try:
        project = db.create_project("Оценка")
        run = db.create_run(project, "m", "all", "p", [])
        with db._tx() as connection:
            for seconds in (10, 10, 30, 30, 30):
                journal.call_sample(connection, run, seconds)
        assert journal.eta_median(db, run) == 30, "медиана, а не среднее 22"
        assert journal.eta_average(db, run) == 30
    finally:
        db.close()


def test_run_page_shows_slow_model_text(web):
    project_id = prepared(web)
    db = web.app.state.db
    run_id = db.create_run(project_id, MODEL, "all", PROMPT_VERSION, [])
    assert db.set_run_state(run_id, "paused", only_from=("queued",))
    text = "Модель работала медленно (10 ток/с при обычных 100) – перезагружена"
    journal.slow_model_event(db, run_id, action="reload", tps=10, baseline=100, text=text, reloads=1)

    page = web.client.get(f"/runs/{run_id}")
    assert page.status_code == 200
    assert text in page.text
    assert 'id="slow-model"' in page.text
    status = web.client.get(f"/runs/{run_id}/status").json()
    assert status["slow_model"]["text"] == text and status["slow_model"]["reloads"] == 1

    journal_page = web.client.get(f"/journal/{run_id}")
    assert journal_page.status_code == 200 and "Медленный режим модели" in journal_page.text
    assert "при обычных 100" in journal_page.text
