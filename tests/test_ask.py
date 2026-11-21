"""«Спросить модель»: вопрос по находке и ответ локальной модели (app/ask.py) – что получает модель (тот же срез
кода, прежний разбор, история вопросов), что сохраняется, отказы и сбои, журнал без текста вопроса и ответа."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import ask, prompts  # noqa: E402
from app.ask import AskError, ask_question, clean_question, fit_messages, history_for  # noqa: E402
from app.config import Settings  # noqa: E402
from app.llm import OllamaClient  # noqa: E402
from app.models import CodeContext, Finding, Verdict  # noqa: E402
from fake_ollama import ask_answer, verdict_answer  # noqa: E402
from test_triage import JAVA, REL, SECRET, Env, env, sast, wait_state  # noqa: E402, F401

QUESTION_MARK = "QUESTION_TEXT_7731"
ANSWER_MARK = "ANSWER_TEXT_7731"


def analysed(env: Env, hub_id: str = "A", line: int = 15, answer=None) -> dict:
    """Находка, разобранная моделью: срез и вердикт сохранены."""
    if answer is not None:
        env.fake.answers.append(answer)
    env.load([sast(hub_id, line)])
    assert env.run()["state"] == "done"
    case = env.db.get_case(env.project_id, hub_id)
    assert case and case["verdict"]
    return case


def asked(env: Env, question: str, hub_id: str = "A", model: str = "qwen2.5-coder:14b", key: bytes | None = None,
          settings: Settings | None = None) -> dict:
    return ask_question(env.db, settings or env.settings, OllamaClient(env.fake.url), key or env.runner._mask_key,
                        env.project_id, hub_id, question, model)


def last_chat(env: Env) -> dict:
    return env.fake.chats()[-1]


# ============================================================================ что получает модель

def test_question_and_answer_are_saved_with_speed(env: Env):
    case = analysed(env)
    q = asked(env, "  Откуда приходит `owner`?\r\n\r\n\r\nИ что дальше?  ")
    assert q["state"] == "done" and q["error"] == ""
    assert q["question"] == "Откуда приходит `owner`?\n\nИ что дальше?"  # переводы строк и пробелы приведены
    assert q["answer"].startswith("Значение id приходит из запроса")
    assert q["answer_data"] == {"answer": q["answer"], "verdict_changes": "нет", "prompt_version": prompts.ASK_VERSION}
    assert q["stats"]["eval_tps"] == pytest.approx(100.0) and q["stats"]["attempts"] == 1
    assert (q["model"], q["case_hash"], q["verdict_id"]) == ("qwen2.5-coder:14b", case["case_hash"],
                                                             case["verdict_id"])
    assert [x["id"] for x in env.db.list_questions(env.project_id, "A")] == [q["id"]]


def test_model_gets_the_same_slice_masked_and_the_question_outside_data(env: Env):
    analysed(env)
    asked(env, "Почему строка 15 опасна?")
    chat = last_chat(env)
    system, user = chat["messages"][0]["content"], chat["messages"][1]["content"]
    assert system == prompts.ASK_SYSTEM_PROMPT
    assert chat["options"]["num_predict"] == min(ask.ASK_NUM_PREDICT, env.settings.num_ctx // 4)
    assert chat["options"]["num_ctx"] == env.settings.num_ctx and "think" not in chat
    end = user.index(prompts.DATA_END)
    assert ">>   15| " in user[:end] and "Твой прежний разбор этой находки:" in user[:end]
    assert "Вопрос специалиста:\nПочему строка 15 опасна?" in user[end:]
    assert SECRET not in user and "<SECRET_" in user  # строка 7 с паролем – в срезе, но скрыта
    for identity in ("Demo Library", "billing-core", "\nA\n"):
        assert identity not in user


def test_model_sees_the_code_it_analysed_not_the_edited_file(env: Env):
    analysed(env)
    path = env.settings.repos_root / "billing-core" / REL
    path.write_text(JAVA.replace("byOwner", "changedAfterTriage"), encoding="utf-8")
    asked(env, "Что делает метод?")
    user = last_chat(env)["messages"][1]["content"]
    assert "byOwner" in user and "changedAfterTriage" not in user


def test_history_of_the_same_verdict_goes_into_the_prompt(env: Env):
    analysed(env)
    env.fake.answers.append(ask_answer("Первый ответ про строку 15."))
    first = asked(env, "Первый вопрос?")
    asked(env, "Второй вопрос?")
    user = last_chat(env)["messages"][1]["content"]
    data = user[:user.index(prompts.DATA_END)]
    assert "Вопрос: Первый вопрос?\nОтвет: Первый ответ про строку 15." in data
    # новый разбор находки: вопросы к прежнему ответу модели в историю не идут
    env.fake.answers.append(verdict_answer("true_positive", 90))
    rerun = env.runner.enqueue(env.project_id, "qwen2.5-coder:14b", "all", fresh=True)
    wait_state(env.db, rerun, ("done",))
    asked(env, "Третий вопрос?")
    user = last_chat(env)["messages"][1]["content"]
    assert "Первый вопрос?" not in user and "Второй вопрос?" not in user
    assert history_for(env.db.list_questions(env.project_id, "A"), first["verdict_id"]) == [
        ("Первый вопрос?", "Первый ответ про строку 15."), ("Второй вопрос?", ask_answer()["answer"])]


def test_gpt_oss_gets_low_reasoning(env: Env):
    analysed(env)
    asked(env, "Вопрос?", model="gpt-oss:20b")
    assert last_chat(env)["think"] == "low" and last_chat(env)["model"] == "gpt-oss:20b"


# ============================================================================ отказы и сбои

@pytest.mark.parametrize("question, model, text", [
    ("   \n ", "qwen2.5-coder:14b", "Напишите вопрос."),
    ("x" * (ask.MAX_QUESTION + 1), "qwen2.5-coder:14b", "Вопрос слишком длинный"),
    ("Вопрос?", "", "Не выбрана модель."),
    ("Вопрос?", "qwen\n2.5", "Не выбрана модель."),
])
def test_bad_question_is_refused_and_not_saved(env: Env, question, model, text):
    analysed(env)
    with pytest.raises(AskError) as e:
        asked(env, question, model=model)
    assert text in str(e.value) and e.value.status == 400
    assert env.db.list_questions(env.project_id, "A") == []


def test_finding_without_analysis_is_refused(env: Env):
    env.load([sast("A", 15)])
    with pytest.raises(AskError) as e:
        asked(env, "Вопрос?")
    assert e.value.status == 409 and "ещё не разбирала" in str(e.value)
    with pytest.raises(AskError) as e:
        asked(env, "Вопрос?", hub_id="нет такой")
    assert e.value.status == 404


def test_second_question_while_model_answers_is_refused(env: Env):
    analysed(env)
    assert ask.GENERATION.try_acquire("ask")  # право на генерацию у другого вопроса (ADR-0099)
    try:
        assert ask.busy()
        with pytest.raises(AskError) as e:
            asked(env, "Вопрос?")
        assert e.value.status == 409 and "предыдущий вопрос" in str(e.value)
    finally:
        ask.GENERATION.release()
    assert not ask.busy() and env.db.list_questions(env.project_id, "A") == []


def test_answer_not_in_format_is_saved_as_error(env: Env):
    analysed(env)
    env.fake.answers += ["не JSON", '{"answer": " – ", "verdict_changes": "нет"}']
    q = asked(env, "Вопрос?")
    assert q["state"] == "error" and "дважды ответила не по формату" in q["error"]
    assert q["stats"]["attempts"] == 2 and q["answer"] == ""
    assert not ask.busy()  # замок отпущен и после ошибки


def test_cloud_model_and_foreign_server_are_refused(env: Env):
    analysed(env)
    q = asked(env, "Вопрос?", model="gpt-oss:120b-cloud")
    assert q["state"] == "error" and "облачная" in q["error"]
    before = len(env.fake.chats())
    q = ask_question(env.db, env.settings, OllamaClient("http://example.org:11434"), env.runner._mask_key,
                     env.project_id, "A", "Вопрос?", "qwen2.5-coder:14b")
    assert q["state"] == "error" and "не входит в разрешённые" in q["error"]
    assert len(env.fake.chats()) == before  # запрос никуда не ушёл


def test_unexpected_failure_is_logged_without_question_or_answer(env: Env, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    analysed(env)
    env.fake.answers.append(ask_answer(ANSWER_MARK))

    def broken(obj):
        raise RuntimeError(f"ответ: {obj['answer']}")

    monkeypatch.setattr(ask, "parse_ask", broken)
    q = asked(env, f"Вопрос {QUESTION_MARK}?")
    assert q["state"] == "error" and re.fullmatch(r"Не удалось получить ответ модели: RuntimeError "
                                                  r"\(ошибка [0-9a-f]{8}\)", q["error"])
    assert ANSWER_MARK not in caplog.text and QUESTION_MARK not in caplog.text
    assert "RuntimeError" in caplog.text


# ============================================================================ окно контекста

def _parts(lines: int = 81):
    f = Finding(hub_id="X", kind="SAST", rule="Внедрение SQL-кода", cwe=["CWE-89"], file=REL, line=40)
    ctx = CodeContext(status="ok", file=REL, language="java", start_line=1, end_line=lines, target_line=40,
                      lines=[f"    value_{n} = compute(value_{n - 1}) + 'x' * 100;  // строка {n}" for n in
                             range(1, lines + 1)])
    v = prompts.parse_verdict(verdict_answer("true_positive", 90, fix="Пример:\n```java\n" + "x();\n" * 40 + "```"))
    return f, ctx, v


def test_prompt_is_trimmed_to_fit_the_window():
    f, ctx, v = _parts()
    history = [(f"Вопрос {n}?", "Ответ " + "слово " * 300) for n in range(3)]
    wide = {"num_ctx": 16384, "num_predict": 1536}
    full = fit_messages(f, ctx, v, "Вопрос?", history, None, wide)
    assert "Вопрос: Вопрос 0?" in full[1]["content"] and "Как исправить:" in full[1]["content"]
    narrow = {"num_ctx": 4096, "num_predict": 1024}
    fitted = fit_messages(f, ctx, v, "Вопрос?", history, None, narrow)
    user = fitted[1]["content"]
    assert "Вопрос: Вопрос 0?" not in user and "Как исправить:" not in user  # сначала история и подробности
    assert ">>   40| " in user  # строка срабатывания остаётся
    assert prompts.ASK_SYSTEM_PROMPT == fitted[0]["content"]
    with pytest.raises(AskError) as e:
        fit_messages(f, ctx, v, "Вопрос " * 5000, [], None, narrow)
    assert "не помещается в окно контекста" in str(e.value) and "в настройках" in str(e.value)
    # удалённый API (size задан): совет – про профиль провайдера, а не настройки Ollama (ревью Codex, круг 19)
    from app.executors import prompt_size
    with pytest.raises(AskError) as e:
        fit_messages(f, ctx, v, "Вопрос " * 5000, [], None, narrow, prompt_size({"kind": "messages"}))
    assert "в профиле провайдера" in str(e.value) and "в настройках" not in str(e.value)


def test_masking_pass_runs_over_the_whole_user_message(mask_key: bytes):
    f, ctx, v = _parts(lines=5)
    ctx = CodeContext(**{**ctx.to_dict(), "target_line": 3})
    v = Verdict.from_dict({**v.to_dict(), "summary": "Пароль password = \"Qw3rtyQw3rty!\" в коде."})
    user = fit_messages(f, ctx, v, "А что с паролем?", [], mask_key, {"num_ctx": 16384, "num_predict": 1536})[1]
    assert "Qw3rtyQw3rty" not in user["content"] and "<SECRET_" in user["content"]


def test_clean_question():
    assert clean_question(None) == ""
    # пустые строки подряд – одна, пробелы в конце строк и по краям вопроса убираются, отступы внутри остаются
    assert clean_question(" a \r\n\r\n\r\n b\r c ") == "a\n\n b\n c"
