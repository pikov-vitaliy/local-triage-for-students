"""Рассуждение моделей (0.9.12): моделям, которые умеют рассуждать
(capabilities thinking), кроме gpt-oss, рассуждение включается явно (think: true), «выкл» в профиле – think: false;
у рассуждающего запроса свой предел ответа (авто – половина окна, не больше 8192 у разбора и 4096 у вопроса) и свой
срок обращения; gpt-oss – уровни, как раньше; модели без рассуждения поле не получают. В списках моделей – объём и
пометка «с рассуждением» / «без рассуждения»."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import ask  # noqa: E402
from app.executors import (ASK_THINK_PREDICT, THINK_TIMEOUT_S, TRIAGE_THINK_PREDICT, applied_think,  # noqa: E402
                           execution_values, fit_thinking, generation, thinking_limit, thinking_predict)
from app.llm import prompt_fits  # noqa: E402
from app.llm_ollama import OllamaClient  # noqa: E402
from app.view import model_option  # noqa: E402
from fake_ollama import FakeOllama, model_entry  # noqa: E402
from test_executors_0912 import started  # noqa: E402
from test_triage import sast  # noqa: E402

THINKER = "qwen36-test:latest"
THINKING = ("completion", "tools", "thinking")


def thinker_fake() -> FakeOllama:
    return FakeOllama(models=[model_entry(THINKER, family="qwen35moe", capabilities=THINKING),
                             model_entry("plain:7b", family="qwen2"),
                             model_entry("gpt-oss:20b", family="gptoss", capabilities=THINKING)])


def test_think_rule_matrix():
    thinker = {"capabilities": list(THINKING), "details": {"family": "qwen35moe"}}
    plain = {"capabilities": ["completion", "tools"], "details": {"family": "qwen2"}}
    gptoss = {"capabilities": list(THINKING), "details": {"family": "gptoss"}}
    assert applied_think("auto", THINKER, thinker) is True
    assert applied_think("high", THINKER, thinker) is True
    assert applied_think("off", THINKER, thinker) is False
    assert applied_think("auto", "plain:7b", plain) is None
    assert applied_think("off", "plain:7b", plain) is None
    assert applied_think("auto", THINKER, None) is None, "сведений нет – поле не передаётся, как раньше"
    assert applied_think("auto", "gpt-oss:20b", gptoss) == "low"
    assert applied_think("off", "gpt-oss:20b", gptoss) == "low", "у gpt-oss рассуждение не выключается"
    assert applied_think("high", "gpt-oss:20b", gptoss) == "high"


def test_thinking_limit_from_the_snapshot():
    profile = {"id": 1, "version": 1, "kind": "ollama", "base_url": "http://127.0.0.1:11434", "trust": "local",
               "generation_json": "{}"}
    execution = execution_values(profile, THINKER, "triage", 16384, "always")
    assert thinking_limit(execution, True) == (TRIAGE_THINK_PREDICT, THINK_TIMEOUT_S) == (8192, 2400.0)
    assert thinking_limit(execution, None) == (None, 900.0) and thinking_limit(execution, "low") == (None, 900.0)
    assert thinking_limit(execution_values(profile, THINKER, "triage", 8192, "always"), True)[0] == 4096,         "не больше половины окна"
    assert thinking_limit(execution_values(profile, THINKER, "ask", 16384, "always"), True)[0] == ASK_THINK_PREDICT
    explicit = {**profile, "generation_json": json.dumps({"think_num_predict": 6000, "think_timeout_s": 3600,
                                                          "think": "off"})}
    assert generation(explicit) == {"think_num_predict": 6000, "think_timeout_s": 3600.0, "think": "off"}
    assert thinking_limit(execution_values(explicit, THINKER, "triage", 16384, "always"), True) == (6000, 3600.0)
    assert thinking_predict("triage", 32768, {}) == 8192
    legacy = {**execution, "options_json": json.dumps({k: v for k, v in json.loads(execution["options_json"]).items()
                                                       if k not in ("think_options", "think_timeout_s")})}
    assert thinking_limit(legacy, True)[0] == 8192, "снимок без отдельного предела – авто от окна"


def test_fit_thinking_takes_the_room_left_after_the_prompt():
    """Предел рассуждающего ответа – остаток окна после промпта, не больше предела; места нет – обычный предел."""
    options = {"num_ctx": 16384, "num_predict": 3072, "temperature": 0.1, "seed": 42}
    short = [{"role": "user", "content": "x" * 400}]
    assert fit_thinking(options, 8192, short)["num_predict"] == 8192
    words = 100  # промпт, который помещается с обычным пределом, но не с пределом рассуждения
    while prompt_fits([{"role": "user", "content": "слово " * (words + 100)}], {**options, "num_predict": 8192}):
        words += 100
    long = [{"role": "user", "content": "слово " * (words + 400)}]
    assert prompt_fits(long, options) and not prompt_fits(long, {**options, "num_predict": 8192})
    fitted = fit_thinking(options, 8192, long)
    assert 3072 <= fitted["num_predict"] < 8192 and prompt_fits(long, fitted)
    assert not prompt_fits(long, {**fitted, "num_predict": fitted["num_predict"] + 65})
    assert fit_thinking(options, None, short) == options
    assert fit_thinking(options, 1000, short)["num_predict"] == 1000, "меньший предел рассуждения – верхняя граница"


class Recording(OllamaClient):
    """Клиент, запоминающий срок обращения в момент запроса к модели."""
    timeouts: list[float] = []

    def chat_json(self, *args, **kwargs):
        Recording.timeouts.append(self.timeout)
        return super().chat_json(*args, **kwargs)


def test_run_with_a_thinking_model_enables_thinking_with_its_own_limit(tmp_path: Path, mask_key: bytes):
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)
    Recording.timeouts = []
    env.runner._client_factory = Recording
    try:
        env.load([sast("A", 15)])
        run = env.run(THINKER)
        assert run["state"] == "done", run["last_error"]
        body = fake.chats()[-1]
        assert body["think"] is True
        regular = min(3072, env.settings.num_ctx // 4)
        sent = body["options"]["num_predict"]
        assert regular <= sent <= min(TRIAGE_THINK_PREDICT, env.settings.num_ctx // 2)
        assert sent == regular or prompt_fits(body["messages"], body["options"]), "рассуждение не вытесняет промпт"
        assert Recording.timeouts == [THINK_TIMEOUT_S]
        verdict_id = env.db.get_case(env.project_id, "A")["verdict_id"]
        stats = json.loads(env.db._one("SELECT stats_json FROM verdicts WHERE id = ?", (verdict_id,))["stats_json"])
        assert stats["think"] == "on"
    finally:
        env.close()
        fake.close()


def test_profile_can_switch_thinking_off(tmp_path: Path, mask_key: bytes):
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        env.db.ensure_default_profile(fake.url, THINKER)
        with env.db._tx() as c:
            c.execute("UPDATE llm_providers SET generation_json = ?, version = version + 1 WHERE id = 1",
                      (json.dumps({"think": "off"}),))
        assert env.run(THINKER)["state"] == "done"
        body = fake.chats()[-1]
        assert body["think"] is False and body["options"]["num_predict"] == min(3072, env.settings.num_ctx // 4)
    finally:
        env.close()
        fake.close()


def test_models_without_thinking_get_no_field(tmp_path: Path, mask_key: bytes):
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run("plain:7b")["state"] == "done"
        assert "think" not in fake.chats()[-1]
    finally:
        env.close()
        fake.close()


def test_question_to_a_thinking_model(tmp_path: Path, mask_key: bytes):
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run(THINKER)["state"] == "done"
        q = ask.ask_question(env.db, env.settings, OllamaClient, mask_key, env.project_id, "A", "Откуда значение?",
                             THINKER)
        assert q["state"] == "done", q
        body = fake.chats()[-1]
        assert body["think"] is True
        regular, sent = min(1536, env.settings.num_ctx // 4), body["options"]["num_predict"]
        assert regular <= sent <= ASK_THINK_PREDICT
        assert sent == regular or prompt_fits(body["messages"], body["options"])
    finally:
        env.close()
        fake.close()


@pytest.mark.parametrize("model, text", [
    ({"name": "qwen36:latest", "size": 13_200_000_000, "params": "34.7B", "capabilities": list(THINKING)},
     "qwen36:latest (12,3 ГБ, 34.7B, с рассуждением)"),
    ({"name": "gemma3:12b", "size": 8_100_000_000, "params": "12.2B", "capabilities": ["completion", "vision"]},
     "gemma3:12b (7,5 ГБ, 12.2B, без рассуждения)"),
    ({"name": "old:7b", "size": 4_000_000_000, "params": "", "capabilities": None}, "old:7b (3,7 ГБ)"),
    ({"name": "bare"}, "bare"),
])
def test_model_option_label(model: dict, text: str):
    assert model_option(model) == text



# ============================================================================ по ревью, круг 2

def test_request_key_tells_false_from_absent():
    from app.prompts import request_key
    messages = [{"role": "user", "content": "x"}]
    keys = {request_key(THINKER, messages, {"num_ctx": 8192}, value) for value in (None, False, True, "low")}
    assert len(keys) == 4


def test_changed_model_info_before_sending_stops_the_request(tmp_path: Path, mask_key: bytes):
    """Предварительные сведения – модель рассуждает (по ним выбраны предел, срок и ключ), к отправке – уже нет:
    запрос не уходит, находка – с ошибкой, которую снимает повторный разбор."""
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)

    class Changing(OllamaClient):
        """К отправке (внутри chat_json) модель под тем же именем уже не рассуждает."""
        sending = False

        def chat_json(self, *args, **kwargs):
            self.sending = True
            return super().chat_json(*args, **kwargs)

        def model_info(self, model):
            entry = dict(super().model_info(model))
            if self.sending:
                entry["capabilities"] = ["completion"]
            return entry

    env.runner._client_factory = Changing
    try:
        env.load([sast("A", 15)])
        run = env.run(THINKER)
        assert run["failed"] == 1 and fake.chats() == []
        errors = env.db.run_errors(run["id"])
        assert errors and "изменились во время разбора" in errors[0]["error"]
    finally:
        env.close()
        fake.close()


def test_capabilities_from_show_drive_thinking(tmp_path: Path, mask_key: bytes):
    """Старая Ollama: возможностей нет в /api/tags, есть в /api/show – рассуждение включается и при исполнении."""
    entry = model_entry(THINKER, family="qwen35moe", capabilities=None)
    entry["show_capabilities"] = list(THINKING)
    fake = FakeOllama(models=[entry])
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        assert env.run(THINKER)["state"] == "done"
        assert fake.chats()[-1]["think"] is True
    finally:
        env.close()
        fake.close()


def test_passport_records_thinking(tmp_path: Path, mask_key: bytes):
    from app import journal
    fake = thinker_fake()
    env = started(tmp_path, fake, mask_key)
    try:
        env.load([sast("A", 15)])
        run = env.run(THINKER)
        passport = journal.detail(env.db, run["id"])["snapshot"]["environments"][-1]["data"]
        assert passport["think"] is True and passport["think_limit"] == min(8192, env.settings.num_ctx // 2)
    finally:
        env.close()
        fake.close()
