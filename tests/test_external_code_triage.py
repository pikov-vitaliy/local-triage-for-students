"""Разбор кода внешней моделью (план 0.9.13, C2; ADR-0104, К11, П4): прогон, вопрос и пересмотр через профиль API
чат-завершений класса «Интернет»; обращение, ушедшее без ответа, – «результат неизвестен» без повторной отправки
(и после перезапуска – по метке sending_at); 402 – пауза с причиной; кэша по ключу у внешнего провайдера нет;
паспорт прогона и карточка говорят про интернет и платные запросы. Данные выдуманы; сервер – поддельный API на
loopback по https."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.db import QUESTION_UNKNOWN, UNKNOWN_AFTER_RESTART, UNKNOWN_BEFORE_RESUME, UNKNOWN_RESULT_NOTE  # noqa: E402
from app.triage import PAUSE_PROVIDER_NOTE, PAYMENT_NOTE  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402
from fake_ollama import ask_answer, verdict_answer  # noqa: E402
from test_external_code_mark import external_loopback, external_profile, mark  # noqa: E402, F401
from test_findings_ui import AS_JSON, card_of  # noqa: E402
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: E402, F401


def external_project(web, fake) -> tuple[int, dict]:  # noqa: F811
    """Проект с выгрузкой и папкой, отметкой «код не секретный» и внешним профилем как профилем модели проекта."""
    pid = prepared(web)
    profile = external_profile(web, fake.url)
    assert "ok=external_marked" in mark(web, pid).headers["location"]
    r = web.client.post(f"/projects/{pid}/provider", headers=ORIGIN, follow_redirects=False,
                        data={"provider_id": str(profile["id"])})
    assert r.status_code == 303, r.text[:500]
    return pid, profile


def items_of(web, run_id: int) -> list[dict]:  # noqa: F811
    return web.app.state.db._all("SELECT * FROM run_items WHERE run_id = ? ORDER BY seq", (run_id,))


def test_unknown_result_is_recorded_once_and_never_resent(web, external_loopback):  # noqa: F811
    """К11: обрыв после отправки – находка «результат неизвестен», прогон идёт дальше, метка снята; «Повторить
    ошибочные» без отдельной отметки её не берёт, с отметкой – новый платный запрос; новый обычный прогон (явный запуск
    оператора) разбирает её как находку без вердикта; «заново» (fresh) – новый запрос по каждой находке: кэша по ключу
    нет (П4)."""
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = external_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        assert total >= 2
        fake.answers += [("drop",)]
        fake.default_answer = verdict_answer("false_positive")
        run_id = start_run(web, pid, model="flash-model")
        run = wait_run(web, run_id)
        assert run["state"] == "done" and run["failed"] == 1 and run["done"] == total, run
        items = items_of(web, run_id)
        first = items[0]
        assert first["state"] == "error" and first["error"].startswith(UNKNOWN_RESULT_NOTE)
        assert all(i["sending_at"] is None for i in items), "метка снята вместе с результатом"
        assert len(fake.chats()) == total
        page = web.client.get(f"/runs/{run_id}").text
        assert "результат неизвестен" in page and "(интернет)" in page and 'id="run-executor"' in page
        # обычный прогон: готовые вердикты по тому же коду не перезапрашиваются, неизвестная – тоже не отправляется
        # автоматически (она «ошибка» прежнего прогона, а новый прогон – только по решению оператора)
        run2 = wait_run(web, start_run(web, pid, model="flash-model"))
        assert run2["state"] == "done" and run2["cached"] == total - 1 and run2["done"] == total
        assert len(fake.chats()) == total + 1, "неизвестную находку новый прогон разбирает как любую без вердикта"
        # «заново»: у внешнего провайдера нет кэша по ключу запроса – каждая находка уходит снова
        run3 = wait_run(web, start_run(web, pid, model="flash-model", fresh="1"))
        assert run3["state"] == "done" and run3["cached"] == 0
        assert len(fake.chats()) == 2 * total + 1


def test_restart_with_a_sending_mark_gives_unknown_result_without_resend(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = external_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        fake.answers += [("http", 402, {"error": {"message": "insufficient balance"}})]
        fake.default_answer = verdict_answer("false_positive")
        run_id = start_run(web, pid, model="flash-model")
        run = wait_run(web, run_id)
        assert run["state"] == "paused" and PAYMENT_NOTE in run["last_error"] and PAUSE_PROVIDER_NOTE in run["last_error"]
        items = items_of(web, run_id)
        assert items[0]["state"] == "pending" and items[0]["sending_at"] is None, "402 – запрос не принят, метка снята"
        # как будто приложение остановилось после отправки первой находки: метка стоит – при старте «результат неизвестен»
        assert db.mark_item_sending(run_id, items[0]["id"])
        db.recover_interrupted()
        items = items_of(web, run_id)
        assert items[0]["state"] == "error" and items[0]["error"] == UNKNOWN_AFTER_RESTART and items[0]["sending_at"] is None
        assert items[0]["stats_partial"] == 1
        run = db.get_run(run_id)
        assert run["state"] == "paused" and run["failed"] == 1 and run["done"] == 1 and run["partial_stats"] == 1
        # метка без результата на второй находке (ответ не записан – база была занята): «Продолжить» её не отправляет
        assert db.mark_item_sending(run_id, items[1]["id"])
        sent = len(fake.chats())
        r = web.client.post(f"/runs/{run_id}/resume", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        run = wait_run(web, run_id)
        items = items_of(web, run_id)
        assert items[1]["state"] == "error" and items[1]["error"] == UNKNOWN_BEFORE_RESUME
        assert run["state"] == "done" and run["done"] == total and run["failed"] == 2
        assert len(fake.chats()) == sent + total - 2, "находки с меткой повторно не отправлены"
        page = web.client.get(f"/runs/{run_id}").text
        assert "результат неизвестен" in page and 'id="retry-unknown"' in page
        # «Повторить ошибочные»: без отметки – нечего (все ошибки – «результат неизвестен»), с отметкой – новый прогон
        r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False, data={})
        assert "повторять нечего" in r.headers["location"] or "%D0%BD%D0%B5%D1%87%D0%B5%D0%B3%D0%BE" in r.headers["location"], r.headers["location"]
        assert len(fake.chats()) == sent + total - 2
        r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False,
                            data={"include_unknown": "1"})
        assert r.status_code == 303 and "error=" not in r.headers["location"], r.headers["location"]
        retry = wait_run(web, int(r.headers["location"].rsplit("/", 1)[1]))
        assert retry["state"] == "done" and retry["total"] == 2 and len(fake.chats()) == sent + total


def test_question_on_the_external_profile_and_unknown_answer(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = external_project(web, fake)
        fake.default_answer = verdict_answer("false_positive")
        assert wait_run(web, start_run(web, pid, model="flash-model"))["state"] == "done"
        hub_id = db.sast_queue(pid, "all")[0]
        fid, card = card_of(web, pid, hub_id)
        assert 'id="ask-paid"' in card and 'id="reanalyze-paid"' in card and "платный запрос" in card
        assert "Внешний" in card and "(интернет)" in card
        fake.answers += [ask_answer("Нет: параметр проверяется на строке 12.", "нет")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                            data={"question": "А если параметр из сессии?", "model": "flash-model"})
        answer = r.json()
        assert r.status_code == 200 and answer["ok"] and answer["answered"], answer
        assert answer["question"]["answer"].startswith("Нет:")
        # обрыв после отправки вопроса – «результат неизвестен», повторной отправки нет
        fake.answers += [("drop",)]
        sent = len(fake.chats())
        r = web.client.post(f"/projects/{pid}/findings/{fid}/ask", headers=AS_JSON,
                            data={"question": "Ещё вопрос?", "model": "flash-model"})
        answer = r.json()
        assert r.status_code == 200 and not answer["answered"], answer
        assert answer["question"]["error"].startswith(QUESTION_UNKNOWN)
        assert len(fake.chats()) == sent + 1
        questions = db.list_questions(pid, hub_id)
        assert [q["state"] for q in questions] == ["done", "error"]


def test_reanalysis_on_the_external_profile_is_a_new_paid_request(web, external_loopback):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = external_project(web, fake)
        fake.default_answer = verdict_answer("false_positive")
        assert wait_run(web, start_run(web, pid, model="flash-model"))["state"] == "done"
        hub_id = db.sast_queue(pid, "all")[0]
        fid, _card = card_of(web, pid, hub_id)
        sent = len(fake.chats())
        fake.answers += [verdict_answer("true_positive")]
        r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=ORIGIN, follow_redirects=False,
                            data={"model": "flash-model", "fresh": "1"})
        assert r.status_code == 303 and "ok=reanalyze" in r.headers["location"], r.headers["location"]
        run_id = db.list_runs(pid, 1)[0]["id"]  # пересмотр – новый прогон по одной находке, карточка ведёт к себе
        assert wait_run(web, run_id)["state"] == "done" and len(fake.chats()) == sent + 1
        assert db.get_case(pid, hub_id)["verdict"]["data"]["verdict"] == "true_positive"
        # отметка снята – пересмотр внешним профилем не ставится в очередь, в сеть ничего не уходит
        r = web.client.post(f"/projects/{pid}/external/clear", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303
        r = web.client.post(f"/projects/{pid}/findings/{fid}/reanalyze", headers=ORIGIN, follow_redirects=False,
                            data={"model": "flash-model", "fresh": "1"})
        assert r.status_code == 409 and "отметкой «код не секретный»" in r.text
        assert len(fake.chats()) == sent + 1


def test_known_cut_off_is_finished_before_the_server_check(web, external_loopback, monkeypatch):  # noqa: F811
    """Ревью круг 15, находка 1: ответ получен, но оборван по длине – известная ошибка находки
    сразу, с расходом ответа, до служебного опроса сервера. Даже если опрос /models после этого не удался, находка
    не остаётся в очереди, прогон не встаёт на паузу и «Продолжить» её заново не отправляет; повтор – обычной кнопкой
    «Повторить ошибочные» без флажка неизвестных."""
    from app import triage as triage_module
    db = web.app.state.db
    monkeypatch.setattr(triage_module.TriageRunner, "_server_alive", lambda self, client: False)
    with FakeChatApi(tls=True, models=["flash-model"]) as fake:
        pid, _profile = external_project(web, fake)
        total = len(db.sast_queue(pid, "all"))
        cut = {"role": "assistant", "content": '{"verdict": "true_pos'}
        fake.answers += [("message", cut, "length")]
        fake.default_answer = verdict_answer("false_positive")
        run_id = start_run(web, pid, model="flash-model")
        run = wait_run(web, run_id)
        assert run["state"] == "done" and run["failed"] == 1 and run["done"] == total, run
        first = items_of(web, run_id)[0]
        assert first["state"] == "error" and "оборван" in first["error"]
        assert not first["error"].startswith(UNKNOWN_RESULT_NOTE), "ответ получен – исход известен"
        assert run["output_tokens"] == 40 * total, "расход оборванного ответа вошёл в расход прогона"
        assert len(fake.chats()) == total, "оборванная находка заново не отправлялась"
        assert [row["unknown"] for row in db.run_errors(run_id)] == [False]
        monkeypatch.setattr(triage_module.TriageRunner, "_server_alive", lambda self, client: True)
        r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False, data={})
        assert r.status_code == 303 and "error=" not in r.headers["location"], r.headers.get("location")
        retry = int(r.headers["location"].split("/runs/")[1].split("?")[0])
        assert wait_run(web, retry)["state"] == "done"
        assert len(fake.chats()) == total + 1, "обычный повтор берёт известную ошибку без флажка неизвестных"
