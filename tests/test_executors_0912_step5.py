"""Исполнитель прогона, часть 2 (0.9.12, ADR-0102): допуск профиля проверяется до любых обращений попытки и снова
после сбоя предварительного обращения; перенос снимка проверяется в транзакции записи прогона (гонка с выключением
профиля не трогает прежний прогон); уровень рассуждения вычисляется на каждую отправку и попадает в статистику ответа;
ключ кэша вердиктов, списки моделей и метрики – по профилю; страницы показывают модели того профиля, которым пойдёт
работа."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import metrics  # noqa: E402
from app.db import DEFAULT_PROVIDER_ID, ProfileChanged, now_iso  # noqa: E402
from app.executors import SendNotAllowed, provider_key  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402
from app.prompts import request_key  # noqa: E402
from app.routes.common import Cached, compute_metrics  # noqa: E402
from app.triage import DISABLED_PROFILE_NOTE, PROMPT_VERSION, TriageError  # noqa: E402
from fake_ollama import FakeOllama, model_entry  # noqa: E402
from test_executors_0912 import MODEL, disable, started  # noqa: E402
from test_findings_ui import analysed, card_of  # noqa: E402
from test_triage import sast, wait_state  # noqa: E402
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: E402, F401

MESSAGES = [{"role": "user", "content": "x"}]


def add_profile(db, base_url: str, *, trust: str = "local", model: str = "other-model:7b") -> int:
    """Второй профиль Ollama (до формы профилей шага 7 – прямой записью). Поддельный сервер слушает loopback, поэтому
    по умолчанию – класс local; класс lan проверяется в tests/test_lan_0912.py."""
    ts = now_iso()
    with db._tx() as c:
        return int(c.execute("INSERT INTO llm_providers(name, kind, base_url, trust, default_model, created_at,"
                             " updated_at) VALUES ('Сервер в сети', 'ollama', ?, ?, ?, ?, ?)" " RETURNING id",
                             (base_url, trust, model, ts, ts)).fetchone()[0])


def use_profile(db, project_id: int, provider_id: int) -> None:
    with db._tx() as c:
        c.execute("UPDATE projects SET provider_id = ? WHERE id = ?", (provider_id, project_id))


# ============================================================================ допуск перед отправкой

def test_admission_is_rechecked_after_a_preliminary_failure():
    """Модели нет (сбой предварительной проверки модели) и профиль за это время выключили: причина – выключенный
    профиль, а не «модель не найдена»; запрос с кодом не уходит."""
    fake = FakeOllama(models=[])
    try:
        calls = []

        def check():
            calls.append(1)
            if len(calls) > 1:
                raise SendNotAllowed("Профиль провайдера модели «П» выключен: запрос к модели не отправлен.")

        client = OllamaClient(fake.url)
        client.before_send = check
        with pytest.raises(SendNotAllowed) as e:
            client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {})
        assert len(calls) == 2 and fake.chats() == [] and e.value.stats is not None
    finally:
        fake.close()


def test_admission_is_checked_before_the_model_list():
    """Выключенный профиль – ни одного обращения к серверу: даже к списку моделей."""
    fake = FakeOllama()
    try:
        client = OllamaClient(fake.url)

        def refuse():
            raise SendNotAllowed("выключен")

        client.before_send = refuse
        with pytest.raises(SendNotAllowed):
            client.chat_json(MODEL, MESSAGES, {"verdict": ""}, ["verdict"], {})
        assert fake.paths() == []
    finally:
        fake.close()


def test_model_gone_and_profile_disabled_between_attempts_pauses(tmp_path: Path, mask_key: bytes):
    """Между попытками и модель пропала с сервера, и профиль выключили: прогон на паузе с причиной про профиль,
    находка не помечена ошибочной, второй запрос не отправлен."""
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])

        def first(body):
            disable(env.db)
            fake.models = []
            return "не JSON"

        fake.answers = [first]
        run = env.run(MODEL)
        assert run["state"] == "paused" and DISABLED_PROFILE_NOTE in run["last_error"]
        assert len(fake.chats()) == 1 and env.db.pending_hub_ids(run["id"]) == ["A"]
        assert env.db.run_errors(run["id"]) == []
    finally:
        env.close()
        fake.close()


# ============================================================================ перенос снимка в транзакции

def test_carried_snapshot_is_checked_inside_the_write(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run = env.run(MODEL)
        count = len(env.db._all("SELECT id FROM runs"))
        snap = run["execution_id"]
        env.db.set_settings({"ollama_url": "http://127.0.0.1:9"})  # адрес профиля 1 сменился
        with pytest.raises(ProfileChanged, match="Адрес профиля"):
            env.db.create_run(env.project_id, MODEL, "selected", PROMPT_VERSION, ["A"], execution_id=snap)
        env.db.set_settings({"ollama_url": fake.url})
        disable(env.db)
        with pytest.raises(ProfileChanged, match="выключен"):
            env.db.create_run(env.project_id, MODEL, "selected", PROMPT_VERSION, ["A"], execution_id=snap)
        with pytest.raises(ProfileChanged, match="выключен"):  # новый снимок выключенного профиля – тоже отказ
            env.db.create_run(env.project_id, MODEL, "all", PROMPT_VERSION, ["A"],
                              execution={k: v for k, v in env.db.get_execution(snap).items()
                                         if k not in ("id", "created_at")})
        assert len(env.db._all("SELECT id FROM runs")) == count, "ничего не записано"
    finally:
        env.close()
        fake.close()


def test_retry_race_with_disabling_keeps_the_paused_run(tmp_path: Path, mask_key: bytes, monkeypatch):
    """Профиль выключили между проверкой «Повторить ошибочные» и записью нового прогона: отказ с причиной,
    прежний прогон остаётся на паузе, нового прогона нет."""
    fake = FakeOllama(answers=["не JSON", "не JSON"])
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run = env.run(MODEL)
        assert [r["hub_id"] for r in env.db.run_errors(run["id"])] == ["A"]
        with env.db._tx() as c:  # прогон на паузе с ошибочной находкой (как после «Пауза» посреди прогона)
            c.execute("UPDATE runs SET state = 'paused' WHERE id = ?", (run["id"],))
        count = len(env.db._all("SELECT id FROM runs"))
        original = env.db.create_run

        def racing(*args, **kwargs):
            disable(env.db)
            return original(*args, **kwargs)

        monkeypatch.setattr(env.db, "create_run", racing)
        with pytest.raises(TriageError, match="выключен"):
            env.runner.retry_errors(run["id"], ["A"])
        assert env.db.get_run(run["id"])["state"] == "paused"
        assert len(env.db._all("SELECT id FROM runs")) == count
    finally:
        env.close()
        fake.close()


# ============================================================================ уровень рассуждения

def test_think_is_computed_per_send_and_recorded():
    """Уровень – функция от записи модели на сервере в момент отправки: модель под тем же именем сменилась между
    попытками – второй запрос уходит без уровня; ушедшие уровни – в статистике ответа."""
    fake = FakeOllama(models=[model_entry("my-alias", family="gptoss")])
    try:
        def first(body):
            fake.models = [model_entry("my-alias", family="qwen2")]
            return "не JSON"

        fake.answers = [first, json.dumps({"verdict": "да"})]
        client = OllamaClient(fake.url)
        obj, stats = client.chat_json(
            "my-alias", MESSAGES, {"verdict": ""}, ["verdict"], {},
            think=lambda info: "high" if (info.get("details") or {}).get("family") == "gptoss" else None)
        assert obj["verdict"] == "да"
        sent = fake.chats()
        assert sent[0]["think"] == "high" and "think" not in sent[1]
        assert stats.think == "high,-"
    finally:
        fake.close()


def test_triage_answer_records_the_sent_think_level(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run("gpt-oss:20b")["state"] == "done"
        assert fake.chats()[-1]["think"] == "low"
        verdict_id = env.db.get_case(env.project_id, "A")["verdict_id"]
        stats = json.loads(env.db._one("SELECT stats_json FROM verdicts WHERE id = ?", (verdict_id,))["stats_json"])
        assert stats["think"] == "low"
    finally:
        env.close()
        fake.close()


# ============================================================================ кэш и метрики по профилю

def test_request_key_depends_on_the_profile_version():
    base = request_key(MODEL, MESSAGES, {"num_ctx": 8192}, None, PROMPT_VERSION)
    assert request_key(MODEL, MESSAGES, {"num_ctx": 8192}, None, PROMPT_VERSION, provider=None) == base
    one = request_key(MODEL, MESSAGES, {"num_ctx": 8192}, None, PROMPT_VERSION, provider=(1, 1))
    assert one != base
    assert request_key(MODEL, MESSAGES, {"num_ctx": 8192}, None, PROMPT_VERSION, provider=(1, 2)) != one
    assert request_key(MODEL, MESSAGES, {"num_ctx": 8192}, None, PROMPT_VERSION, provider=(2, 1)) != one
    assert provider_key(None) is None and provider_key({"provider_id": 3, "provider_version": 4}) == (3, 4)


def test_cache_of_another_profile_is_not_reused(tmp_path: Path, mask_key: bytes):
    """Кэш по запросу (ADR-0027) – в пределах профиля: тот же запрос через тот же профиль берётся из кэша, через
    другой профиль (другой сервер) – отправляется заново: модель на другом сервере может быть иной. (Вердикт по тому
    же коду, уже привязанный к находке, обычный прогон не заменяет – этот случай здесь исключён отвязкой.)"""
    fake, other = FakeOllama(), FakeOllama()
    env = started(tmp_path, fake, mask_key)

    def detach_and_run() -> int:
        with env.db._tx() as c:
            c.execute("UPDATE cases SET verdict_id = NULL WHERE project_id = ?", (env.project_id,))
        run_id = env.runner.enqueue(env.project_id, MODEL, "all", fresh=False)
        assert wait_state(env.db, run_id, ("done", "error", "paused"))["state"] == "done"
        return env.db.get_case(env.project_id, "A")["verdict_id"]

    try:
        env.load([sast("A", 15)])
        assert env.run(MODEL)["state"] == "done"
        first = env.db.get_case(env.project_id, "A")["verdict_id"]
        assert detach_and_run() == first and len(fake.chats()) == 1, "тот же профиль – ответ из кэша"
        use_profile(env.db, env.project_id, add_profile(env.db, other.url))
        assert detach_and_run() != first
        assert len(other.chats()) == 1 and len(fake.chats()) == 1, "запрос ушёл на сервер профиля проекта"
    finally:
        env.close()
        fake.close()
        other.close()


def test_cached_keeps_values_per_key_and_evicts_the_oldest():
    computed = []

    def compute(key):
        computed.append(key)
        return f"v{key}"

    cache = Cached(60.0, compute, max_keys=2)
    assert cache.get("a") == "va" and cache.get("b") == "vb" and cache.get("a") == "va"
    assert computed == ["a", "b"], "второй ключ не вытесняет первый"
    cache.get("c")  # третий ключ вытесняет самый старый по записи («a»)
    cache.get("b")
    cache.get("a")
    assert computed == ["a", "b", "c", "a"]
    cache.get("a", fresh=True)
    assert computed[-1] == "a" and len(computed) == 5


def test_metrics_of_a_lan_server_have_no_local_gpu(monkeypatch):
    marker = "Видеокарта этого компьютера"
    monkeypatch.setattr(metrics, "gpu_stats", lambda: {"name": marker, "memory_total_mb": 16000,
                                                       "memory_used_mb": 1000, "utilization": 5})
    fake = FakeOllama(loaded=[MODEL])
    try:
        local = compute_metrics(OllamaClient, (fake.url, True))
        remote = compute_metrics(OllamaClient, (fake.url, False))
        assert marker in json.dumps(local, ensure_ascii=False)
        assert marker not in json.dumps(remote, ensure_ascii=False)
        assert marker in json.dumps(compute_metrics(OllamaClient, fake.url), ensure_ascii=False), \
            "адрес строкой – как раньше, с данными этого компьютера"
    finally:
        fake.close()


# ============================================================================ страницы по профилю

def test_project_page_lists_models_of_the_project_profile(web):
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = prepared(web)
        db = web.app.state.db
        assert "other-model:7b" not in web.client.get(f"/projects/{pid}").text
        use_profile(db, pid, add_profile(db, other.url))
        assert "other-model:7b" in web.client.get(f"/projects/{pid}").text
    finally:
        other.close()


def test_question_models_follow_the_verdict_profile(web):
    """Вопрос идёт профилем разбора: в карточке – модели того сервера, который дал ответ, даже если у проекта уже
    другой профиль; у ответа без снимка (до 0.9.12) – модели профиля проекта."""
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = analysed(web)
        db = web.app.state.db
        use_profile(db, pid, add_profile(db, other.url))
        _, card = card_of(web, pid, "510001")
        ask = re.search(r'<select name="model" id="ask-model".*?</select>', card, re.S).group(0)
        assert 'value="qwen2.5-coder:14b"' in ask and 'value="other-model:7b"' not in ask
        verdict_id = db.get_case(pid, "510001")["verdict_id"]
        with db._tx() as c:
            c.execute("UPDATE verdicts SET execution_id = NULL WHERE id = ?", (verdict_id,))
        _, card = card_of(web, pid, "510001")
        ask = re.search(r'<select name="model" id="ask-model".*?</select>', card, re.S).group(0)
        assert 'value="other-model:7b"' in ask and "qwen2.5-coder:14b" not in ask
    finally:
        other.close()


def test_routes_fill_execution_id(web):
    """Прогон, поставленный со страницы, и вопрос из карточки – со снимком исполнителя."""
    pid = analysed(web)
    db = web.app.state.db
    runs = db._all("SELECT execution_id FROM runs")
    assert runs and all(r["execution_id"] for r in runs)
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=ORIGIN, follow_redirects=False,
                        data={"question": "Откуда значение?", "model": "qwen2.5-coder:14b"})
    assert r.status_code == 303
    rows = db._all("SELECT execution_id FROM questions")
    assert rows and all(q["execution_id"] for q in rows)
    snap = db.get_execution(rows[0]["execution_id"])
    assert snap["provider_id"] == DEFAULT_PROVIDER_ID and json.loads(snap["options_json"])["operation"] == "ask"
    assert wait_run(web, start_run(web, pid, fresh="1"))["execution_id"]



# ============================================================================ по ревью шагов 4–5

def test_profile_disabled_while_the_model_disappears_before_the_first_send(tmp_path: Path, mask_key: bytes):
    """Допуск проверен при старте прогона, затем профиль выключили и модель пропала, пока приложение спрашивало список
    моделей: прогон на паузе с причиной про профиль, а не ошибка «модели нет»."""
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])

        class Racing(OllamaClient):
            def list_models(self):
                disable(env.db)
                return []

        env.runner._client_factory = Racing
        run = env.run(MODEL)
        assert run["state"] == "paused" and DISABLED_PROFILE_NOTE in run["last_error"], run["last_error"]
        assert fake.chats() == [] and env.db.pending_hub_ids(run["id"]) == ["A"]
    finally:
        env.close()
        fake.close()


def test_flags_of_older_snapshots_follow_the_trust_class():
    """Снимки промежуточной 0.9.12 без признаков allows_unload и host_metrics: у lan отсутствие признака – запрет, у
    local и прогона без снимка – как раньше."""
    from app.executors import host_metrics_of, unload_allowed_of
    old_lan = {"trust": "lan", "options_json": json.dumps({"options": {}, "think": "auto"})}
    old_local = {"trust": "local", "options_json": json.dumps({"options": {}})}
    assert not host_metrics_of(old_lan) and not unload_allowed_of(old_lan)
    assert host_metrics_of(old_local) and unload_allowed_of(old_local)
    assert host_metrics_of(None) and unload_allowed_of(None)
    granted = {"trust": "lan", "options_json": json.dumps({"allows_unload": True, "host_metrics": False})}
    assert unload_allowed_of(granted) and not host_metrics_of(granted)


def test_think_is_recorded_only_for_requests_that_left():
    """Отказ допуска непосредственно перед отправкой – уровень не записан; повтор без схемы после HTTP 400 – оба
    ушедших запроса записаны, а допуск проверен до повторной проверки модели."""
    fake = FakeOllama()
    try:
        calls = []

        def refuse_second():
            calls.append(len(fake.paths()))
            if len(calls) == 2:
                raise SendNotAllowed("выключен")

        client = OllamaClient(fake.url)
        client.before_send = refuse_second
        with pytest.raises(SendNotAllowed) as e:
            client.chat_json("gpt-oss:20b", MESSAGES, {"verdict": ""}, ["verdict"], {}, think="low")
        assert fake.chats() == [] and e.value.stats.think == ""

        fake.answers = [("http", 400, {"error": "unsupported format"}), json.dumps({"verdict": "да"})]
        order = []
        client = OllamaClient(fake.url)
        client.before_send = lambda: order.append(("admit", len(fake.paths())))
        _, stats = client.chat_json("gpt-oss:20b", MESSAGES, {"verdict": ""}, ["verdict"], {}, think="low",
                                    json_schema="always")
        assert stats.think == "low,low" and len(fake.chats()) == 2
        assert "format" in fake.chats()[0] and "format" not in fake.chats()[1]
        paths = fake.paths()
        resend_admit = [n for what, n in order][2]  # допуск повтора без схемы – до его проверки модели
        assert paths[resend_admit] != "/api/chat" and paths[resend_admit - 1] == "/api/chat"
    finally:
        fake.close()


def test_telemetry_keeps_host_data_only_for_a_local_server(tmp_path: Path, monkeypatch):
    from app import telemetry
    fresh = {"status": "fresh", "memory": {"used_bytes": 8 * 1024 ** 3, "total_bytes": 32 * 1024 ** 3},
             "cpu_pct": 12.0, "scope": "ollama_host", "sampled_at": 1e12}
    monkeypatch.setattr(telemetry, "host_snapshot", lambda path, now=None: dict(fresh))
    observer = telemetry.Telemetry(tmp_path, lambda: {})
    observer.record({"gpu": None, "models": [], "server": {"base_url": "http://192.168.1.5:11434", "local": False}})
    snap = observer.snapshot()
    assert snap["host"]["status"] == "remote" and snap["host"]["memory"] is None
    assert observer.history()[-1]["ram"] is None and observer.history()[-1]["cpu"] is None
    observer.record({"gpu": None, "models": [], "server": {"base_url": "http://127.0.0.1:11434", "local": True}})
    assert observer.snapshot()["host"]["memory"] and observer.history()[-1]["ram"] == 8.0
    observer.remember(("http://192.168.1.5:11434", False), {"gpu": None, "models": [{"name": "m"}]})
    remembered = observer.server_snapshot(("http://192.168.1.5:11434", False))
    assert remembered["host"]["status"] == "remote" and remembered["resource_status"] == "fresh"
    assert observer.server_snapshot(("http://192.168.1.5:11434", False), now=time.time() + 60) is None
    assert observer.server_snapshot(("http://192.168.1.6:11434", False)) is None


def test_metrics_after_switching_the_app_profile_are_not_of_the_old_server(web):
    """Снимок наблюдения прежнего сервера не выдаётся за метрики нового: после смены профиля приложения страница
    берёт метрики нового сервера, пока наблюдение его не измерило."""
    other = FakeOllama(models=["other-model:7b"], loaded=["other-model:7b"])
    try:
        db = web.app.state.db
        observer = web.app.state.telemetry
        observer.record(compute_metrics(OllamaClient, web.fake.url))
        assert [m["name"] for m in web.client.get("/api/metrics").json()["models"]] == ["qwen2.5-coder:14b"]
        second = add_profile(db, other.url, trust="local")
        db.set_settings({"default_provider_id": second})
        first = web.client.get("/api/metrics").json()  # прежний снимок чужой: «ещё не измерено», без опроса сети
        assert first["pending"] and first["models"] == [] and first["resource_status"] == "unavailable"
        assert first["host"]["status"] != "remote", "данные этого компьютера у local – из сборщика хоста"
        observer.record(compute_metrics(OllamaClient, other.url))  # цикл наблюдения измерил новый сервер
        names = [m["name"] for m in web.client.get("/api/metrics").json()["models"]]
        assert names == ["other-model:7b"], names
    finally:
        other.close()


def test_reanalysis_offers_models_of_the_project_profile(web):
    """Вопрос идёт профилем разбора, а пересмотр – новым прогоном на профиле проекта: у каждой формы свой список."""
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = analysed(web)
        db = web.app.state.db
        use_profile(db, pid, add_profile(db, other.url, trust="local"))
        _, card = card_of(web, pid, "510001")
        ask = re.search(r'<select name="model" id="ask-model".*?</select>', card, re.S).group(0)
        rerun = re.search(r'<select name="model" id="reanalyze-model".*?</select>', card, re.S).group(0)
        assert 'value="qwen2.5-coder:14b"' in ask and "other-model:7b" not in ask
        assert 'value="other-model:7b"' in rerun and "qwen2.5-coder:14b" not in rerun
    finally:
        other.close()


def test_profiles_of_one_server_share_the_speed_history(tmp_path: Path, mask_key: bytes):
    """Статистика скорости – по (протокол, адрес): два профиля одного сервера дают общую историю."""
    fake = FakeOllama()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run(MODEL)["state"] == "done"
        twin = add_profile(env.db, fake.url, trust="local")
        use_profile(env.db, env.project_id, twin)
        second = env.runner.enqueue(env.project_id, MODEL, "all", fresh=True)
        assert wait_state(env.db, second, ("done", "error", "paused"))["state"] == "done"
        assert env.db.get_execution(env.db.get_run(second)["execution_id"])["provider_id"] == twin
        assert len(env.db.model_tps_samples(MODEL, executor=("ollama", fake.url))) == 2
    finally:
        env.close()
        fake.close()



def test_history_is_kept_per_server(tmp_path: Path):
    """История ресурсов – по серверу модели: ряд другого сервера (прогон lan) не смешивается с рядом этого компьютера
    ни в 15-минутных точках, ни в поминутных средних."""
    from app import telemetry
    observer = telemetry.Telemetry(tmp_path, lambda: {})
    local = {"base_url": "http://127.0.0.1:11434", "local": True}
    observer.record({"gpu": {"util_pct": 40}, "models": [], "vram_used_mb": 1000, "server": local})
    observer.remember(("http://192.168.1.5:11434", False), {"gpu": None, "models": [{"name": "m"}], "vram_used_mb": 7000})
    here = observer.history("15m", server=observer.server_tag(local))
    there = observer.history("15m", server=observer.server_tag(("http://192.168.1.5:11434", False)))
    assert [p["vram"] for p in here] == [1000] and [p["vram"] for p in there] == [7000]
    assert there[0]["ram"] is None and there[0]["source_epoch"] != here[0]["source_epoch"]
    day_here = observer.history("24h", server=observer.server_tag(local))
    day_there = observer.history("24h", server=observer.server_tag(("http://192.168.1.5:11434", False)))
    assert [p["vram"] for p in day_here] == [1000] and [p["vram"] for p in day_there] == [7000]
    assert len(observer.history("15m")) == 2  # без сервера – все ряды, как до 0.9.12
    observer.close()


def test_run_page_history_is_of_the_run_server(web):
    """/api/metrics/history?run=N – ряд сервера исполнителя прогона; без прогона – профиля приложения."""
    pid = analysed(web)
    db = web.app.state.db
    observer = web.app.state.telemetry
    run_id = db._all("SELECT id FROM runs ORDER BY id DESC LIMIT 1")[0]["id"]
    observer.record(compute_metrics(OllamaClient, web.fake.url))
    other_server = ("http://192.168.1.5:11434", False)
    observer.remember(other_server, {"gpu": None, "models": [], "vram_used_mb": 7000})
    mine = web.client.get(f"/api/metrics/history?window=15m&run={run_id}").json()["points"]
    assert mine and all(p["server"] == observer.server_tag((web.fake.url, True)) for p in mine)
    assert all(p["server"] != observer.server_tag(other_server) for p in
               web.client.get("/api/metrics/history?window=15m").json()["points"])
    assert pid


def test_reanalysis_goes_to_the_project_profile_server(web):
    other = FakeOllama(models=["other-model:7b"])
    try:
        pid = analysed(web)
        db = web.app.state.db
        use_profile(db, pid, add_profile(db, other.url, trust="local"))
        fid = db.get_finding_by_hub_id(pid, "510001")["id"]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=ORIGIN, follow_redirects=False,
                            data={"model": "other-model:7b", "fresh": "1"})
        assert r.status_code == 303, r.text
        run_id = db._all("SELECT id FROM runs ORDER BY id DESC LIMIT 1")[0]["id"]
        assert wait_run(web, run_id)["state"] == "done"
        assert len(other.chats()) == 1, "пересмотр ушёл на сервер профиля проекта"
    finally:
        other.close()



def test_background_loop_measures_a_server_asked_by_a_page(web, caplog):
    """Страница прогона на паузе другого сервера: сначала «ещё не измерено» без опроса сети, затем цикл фонового
    наблюдения измеряет этот сервер, и страница получает его снимок; сбор ресурсов при этом не падает."""
    from app.executors import execution_values
    other = FakeOllama(models=["other-model:7b"], loaded=["other-model:7b"])
    try:
        pid = analysed(web)
        db = web.app.state.db
        second = add_profile(db, other.url)
        run_id = db.create_run(pid, "other-model:7b", "all", PROMPT_VERSION, [],
                               execution=execution_values(db.get_provider(second), "other-model:7b", "triage", 8192, ""))
        db.set_run_state(run_id, "paused")
        first = web.client.get(f"/runs/{run_id}/status").json()["metrics"]
        assert first["pending"] and first["models"] == [] and other.paths() == []
        page = web.client.get(f"/runs/{run_id}").text
        assert "ещё не измерено" in page and "не загружена" not in page
        observer = web.app.state.telemetry
        with caplog.at_level("WARNING"):
            observer.record(observer.compute())  # один цикл фонового наблюдения
        assert "Статистика ресурсов прогона не сохранена" not in caplog.text
        metrics = web.client.get(f"/runs/{run_id}/status").json()["metrics"]
        assert [m["name"] for m in metrics["models"]] == ["other-model:7b"] and not metrics.get("pending")
        tag = observer.server_tag((other.url, True))
        points = web.client.get(f"/api/metrics/history?window=15m&run={run_id}").json()["points"]
        assert points and all(p["server"] == tag for p in points)
    finally:
        other.close()


def test_history_of_an_unknown_or_legacy_run(web):
    """Нет такого прогона – 404; прогон до 0.9.12 – ряд без метки сервера (история до обновления)."""
    db = web.app.state.db
    observer = web.app.state.telemetry
    assert web.client.get("/api/metrics/history?window=15m&run=999999").status_code == 404
    pid = analysed(web)
    legacy = db.create_run(pid, "qwen2.5-coder:14b", "all", PROMPT_VERSION, [])  # без снимка – как до 0.9.12
    db.set_run_state(legacy, "stopped")
    observer.record({"gpu": {"util_pct": 7}, "models": [], "vram_used_mb": 321})  # точка без метки сервера
    points = web.client.get(f"/api/metrics/history?window=15m&run={legacy}").json()["points"]
    assert points and all(p["server"] == "" for p in points) and points[-1]["vram"] == 321


def test_day_history_filters_the_server_before_the_limit(tmp_path: Path):
    """Сутки: ряд сервера не вытесняется более частым рядом другого сервера – фильтр до предела строк; у каждого ряда
    краткой истории своё окно."""
    from app import telemetry
    observer = telemetry.Telemetry(tmp_path, lambda: {})
    origin = time.time() - 86000
    lan = ("http://192.168.1.5:11434", False)
    observer.remember(lan, {"gpu": None, "models": [], "vram_used_mb": 7000}, now=origin)
    local = {"base_url": "http://127.0.0.1:11434", "local": True}
    for i in range(1500):
        observer.record({"gpu": {"util_pct": 1}, "models": [], "vram_used_mb": 1, "server": local}, origin + 60 + i * 50)
    there = observer.history("24h", server=observer.server_tag(lan))
    assert [p["vram"] for p in there] == [7000]
    assert len(observer.history("15m", server=observer.server_tag(local))) <= 180
    assert observer.history("15m", server=observer.server_tag(lan)) == [], "15 минут – от текущего времени"
    observer.remember(lan, {"gpu": None, "models": [], "vram_used_mb": 7100})
    observer.remember(lan, {"gpu": None, "models": [], "vram_used_mb": 7200})  # тот же цикл – точка одна
    assert [p["vram"] for p in observer.history("15m", server=observer.server_tag(lan))] == [7100]
    observer.close()
