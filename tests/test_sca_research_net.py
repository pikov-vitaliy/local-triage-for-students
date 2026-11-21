"""Исследование компонентов провайдером (план 0.9.13, B3; ADR-0105, К7, К11) на поддельном сервере API чат-завершений
(tests/fake_chat_api.py). Годная строка – ревизия с execution_id получения; негодная после повторов – без изменений с
причиной; ограничитель цикла считает фактические вызовы (и несколько tool_calls в одном ответе); 402 – остановка;
неизвестный результат – строка «результат неизвестен», «Продолжить» и перезапуск её не отправляют; отзыв согласия –
отказ до отправки; состав запроса – только перечень К7; reasoning_content возвращается в историю; конец цикла – и
content, и инструментом answer; ревизия от провайдера даёт текст дефекта SCA по эталону теми же правилами, что
файловый ответ. Данные выдуманы."""

from __future__ import annotations

import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import sca_research_net as net  # noqa: E402
from app.executors import client_for, execution_values  # noqa: E402
from fake_chat_api import FakeChatApi  # noqa: E402
from test_providers_chat_ui import post as post_profile  # noqa: E402
from test_sca import sca_card, shown_fields  # noqa: E402
from test_sca_research_routes import AS_JSON, AST_ID, CODEBASE, HUB_ID, build_task, kit_answer, project_with_sca  # noqa: E402
from test_web import ORIGIN, web  # noqa: E402, F401

CUTOFF = "2026-10-25"


# ------------------------------------------------------------------ заготовка: профиль, задание, согласие, получение

def make_profile(web, fake, search: bool = True) -> dict:  # noqa: F811
    fields = {"name": "Исследователь", "base_url": fake.url, "default_model": "flash-model", "thinking": "disabled",
              "max_output": "4096", "tool_steps": "3", "action": "save"}
    if search:
        fields.update(search_on="1", search_path="/v1/tools/search", fetch_path="/v1/tools/fetch")
    r = post_profile(web, "/settings/providers/new", **fields)
    assert r.status_code == 303, r.text[:1500]
    return next(p for p in web.app.state.db.list_providers() if p["name"] == "Исследователь")


def start_run(web, fake, *, search: bool = True, rows: list[str] | None = None,
              project: tuple[int, dict] | None = None, osv_url: str = "") -> tuple[int, dict, dict, dict]:  # noqa: F811
    """Проект с SCA, задание /3, профиль, согласие и получение; возвращает (проект, задание, согласие, получение).
    project=(pid, task) – ещё одно получение в том же проекте по тому же заданию и профилю; osv_url – адрес OSV в
    инструкциях согласия (ADR-0112; пусто – запроса OSV нет, как у согласий до 0.9.18)."""
    db = web.app.state.db
    if project is None:
        pid = project_with_sca(web)
        build_task(web, pid)
        task = db.current_task(pid)
        profile = make_profile(web, fake, search=search)
    else:
        pid, task = project
        profile = next(p for p in db.list_providers() if p["name"] == "Исследователь")
    execution = execution_values(profile, "flash-model", "ask", 16384, "always", purpose="research")
    system = net.instructions(search, osv_url)
    refs = rows or [r["input_ref"] for r in db.task_rows(task["id"])]
    consent = db.create_research_consent(pid, task["id"], execution, {
        "components_sha256": task["components_sha256"] or task["manifest_sha256"], "cutoff_date": CUTOFF,
        "instructions": system, "instructions_sha256": net.sha256(system), "rows": refs, "selection": "all",
        "model": "flash-model", "search_mode": "tools" if search else "none", "tool_steps": 3})
    run = db.start_research_run(consent["id"])
    return pid, task, consent, run


def runner_for(web) -> net.ResearchRunner:  # noqa: F811
    db = web.app.state.db
    return net.ResearchRunner(db, lambda execution: client_for(web.app.state.web.make_client, execution, db=db))


def osv_base(fake: FakeChatApi) -> str:
    """Адрес OSV для фальшивого API: корень без /v1 – запрос уходит на POST /v1/query."""
    return fake.url[:-len(fake.prefix)] if fake.prefix and fake.url.endswith(fake.prefix) else fake.url


def good_row(manifest_row: dict, task: dict) -> dict:
    """Годная строка ответа – из той же заготовки, что файловый ответ (kit_answer), первая строка уязвима."""
    rows = json.loads(kit_answer({"task_id": task["task_id"], "manifest_sha256": task["manifest_sha256"],
                                  "rows": [manifest_row]}))["rows"]
    return rows[0]


def clean_row(manifest_row: dict, task: dict, other: dict) -> dict:
    """Годная строка «уязвимостей нет» (в заготовке kit_answer уязвима только первая строка манифеста – ставим
    нужную строку второй)."""
    rows = json.loads(kit_answer({"task_id": task["task_id"], "manifest_sha256": task["manifest_sha256"],
                                  "rows": [other, manifest_row]}))["rows"]
    return rows[1]


def osv_failed_row(manifest_row: dict, task: dict, status: str = "error") -> dict:
    """Годная строка ответа, у которой покрытие OSV честно отражает неудачный или неполный запрос OSV (ADR-0112):
    status error/partial, complete false."""
    answer = good_row(manifest_row, task)
    for item in answer.get("research_coverage") or []:
        if str(item.get("source") or "").upper() == "OSV":
            item["status"], item["complete"], item["note"] = status, False, "OSV: запрос не дал полного ответа"
    return answer


def manifest_rows(web, task) -> list[dict]:  # noqa: F811
    return [{"input_ref": r["input_ref"], "ecosystem": r["ecosystem"], "component": r["name"], "version": r["version"],
             "identity_kind": r["identity_kind"]} for r in web.app.state.db.task_rows(task["id"])]


# ------------------------------------------------------------------ тесты

def test_good_row_becomes_a_revision_with_execution_id_and_request_carries_only_k7(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_results = [{"url": "https://advisories.example/x", "title": "x", "snippet": "s"}]
        # первая строка: поиск (один вызов) и ответ в content с reasoning_content; вторая – ответ инструментом answer
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "reasoning_content": "думаю",
                         "tool_calls": [{"id": "c1", "type": "function", "function": {
                             "name": "search", "arguments": json.dumps({"query": "example-parser advisory"})}}]},
             "tool_calls"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False),
                         "reasoning_content": "готово"}, "stop"),
            ("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c2", "type": "function", "function": {
                "name": "answer", "arguments": json.dumps({"row": good_row(rows[1], task)}, ensure_ascii=False)}}]},
             "tool_calls"),
        ]
        runner_for(web).run(run["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "done" and done["rows_saved"] == 2, done
        for row in rows:
            research = db.research_row(pid, row["input_ref"])
            assert research and research["execution_id"] == run["execution_id"] and research["revision"] == 1
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["tool"] == "search" and first["tools"][0]["results"] == 1
        assert first["usage"]["search_calls"] == 1 and first["sending_at"] is None
        # история: ответ ассистента вернулся целиком (reasoning_content), результат инструмента – сообщением tool
        chats = fake.chats()
        second_turn = chats[1]["messages"]
        assert second_turn[2]["reasoning_content"] == "думаю" and second_turn[3]["role"] == "tool"
        assert chats[0]["tools"][0]["function"]["name"] == "search" and chats[0]["tool_choice"] == "auto"
        # состав запроса – только перечень К7: нет названия системы, кодовых баз, номеров Hub, AST, решений
        wire = json.dumps(chats, ensure_ascii=False)
        for secret in (CODEBASE, "catalog-api", HUB_ID, AST_ID, "Demo Library"):
            assert secret not in wire, secret
        user = json.loads(chats[0]["messages"][1]["content"])
        assert user == {"cutoff_date": CUTOFF, "row": {
            "input_ref": rows[0]["input_ref"], "ecosystem": rows[0]["ecosystem"], "component": rows[0]["component"],
            "version": rows[0]["version"], "identity_kind": rows[0]["identity_kind"],
            "hub_fix_candidate": "1.4.9", "vulnerability_ids": ["CVE-2099-10001"]}}
        assert chats[0]["messages"][0]["content"] == consent["instructions"]
        search_calls = [r for r in fake.requests if r["path"] == "/v1/tools/search"]
        assert search_calls and search_calls[0]["body"] == {"query": "example-parser advisory", "count": 5}


def test_bad_row_after_retries_is_left_unchanged_with_a_reason(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        broken = {**good_row(rows[0], task), "current_version": "0.0.0-чужая"}
        fake.answers += [json.dumps(broken, ensure_ascii=False)] * 3 + ["это не JSON"] * 3
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "failed"
        assert "не прошёл проверку" in states[rows[0]["input_ref"]]["reason"]
        assert "current_version" in states[rows[0]["input_ref"]]["reason"]
        assert states[rows[1]["input_ref"]]["state"] == "failed"
        assert db.research_row(pid, rows[0]["input_ref"]) is None, "негодная строка ревизии не получает"
        assert db.research_run(run["id"])["state"] == "done"


def test_correction_gets_extra_search_steps_after_the_limit(web):  # noqa: F811
    """После замечания проверки модель может дочитать источник – ещё
    CORRECTION_TOOL_STEPS шага сверх исчерпанного предела; замечание говорит об этом."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        refs = [r["input_ref"] for r in rows]

        def searches(prefix: str, n: int) -> tuple:
            calls = [{"id": f"{prefix}{i}", "type": "function",
                      "function": {"name": "search", "arguments": json.dumps({"query": f"{prefix}{i}"})}} for i in range(n)]
            return ("message", {"role": "assistant", "content": "", "tool_calls": calls}, "tool_calls")
        broken = {**good_row(rows[0], task), "current_version": "0.0.0-чужая"}
        fake.answers += [
            searches("a", 3),  # предел профиля – 3 шага: исчерпан
            ("message", {"role": "assistant", "content": json.dumps(broken, ensure_ascii=False)}, "stop"),
            searches("b", 2),  # после замечания – ещё 2 шага выполняются
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)},
             "stop"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)},
             "stop"),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[refs[0]]
        assert first["state"] == "saved" and len(first["tools"]) == 5, first["tools"]
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 5
        correction = fake.chats()[2]["messages"][-1]["content"]
        assert correction.startswith("Проверка строки нашла замечания") and f"ещё {net.CORRECTION_TOOL_STEPS} шага" in correction


def test_correction_promises_only_the_steps_it_gives(web):  # noqa: F811
    """Круг 19 Codex, находка 6: остался один шаг – замечание обещает два, и оба выполняются."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        refs = [r["input_ref"] for r in rows]

        def searches(prefix: str, n: int) -> tuple:
            calls = [{"id": f"{prefix}{i}", "type": "function",
                      "function": {"name": "search", "arguments": json.dumps({"query": f"{prefix}{i}"})}} for i in range(n)]
            return ("message", {"role": "assistant", "content": "", "tool_calls": calls}, "tool_calls")
        broken = {**good_row(rows[0], task), "current_version": "0.0.0-чужая"}
        fake.answers += [
            searches("a", 2),  # из трёх шагов профиля остался один
            ("message", {"role": "assistant", "content": json.dumps(broken, ensure_ascii=False)}, "stop"),
            searches("b", 2),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)},
             "stop"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)},
             "stop"),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[refs[0]]
        assert first["state"] == "saved" and len(first["tools"]) == 4, first["tools"]
        assert fake.chats()[2]["messages"][-1]["content"].endswith("доступно ещё 2 шага поиска.")


def test_calls_estimate_covers_the_correction_steps():
    """Круг 19 Codex, находка 4: три поиска, плохая строка, два поиска, плохая строка, два поиска, плохая строка –
    10 обращений к модели и 7 поисков на строку; оценка предпросмотра этого не меньше."""
    assert net.EXTRA_STEPS_MAX == net.ROW_RETRIES * net.CORRECTION_TOOL_STEPS
    assert net.calls_estimate(1, 3) >= 10 + 7
    steps = 3 + net.EXTRA_STEPS_MAX
    assert net.calls_estimate(2, 3) == 2 * (steps + net.ROW_SENDS_MAX + 2 * steps)


def test_answer_tool_carries_the_row_schema_and_the_coverage_rule():
    """Схема строки – в параметрах инструмента answer; правило research_coverage[].query.version – в инструкции."""
    from app.sca_contract import ROW_SCHEMA
    answer = next(t for t in net.TOOLS if t["function"]["name"] == "answer")
    assert answer["function"]["parameters"]["properties"]["row"] == ROW_SCHEMA
    assert net.TOOLS_NO_SEARCH[0] is answer
    text = net.instructions(True)
    assert "research_coverage[].query" in text and "version = current_version" in text and "version_checks" in text
    # координаты – из разрешённой идентичности, а не из задания: у короткого имени их устанавливает исследование, и
    # проверка сверяет query.coordinates с identity_resolution.coordinates (ревью Codex, круг 19, находка 5)
    assert "те же, что в identity_resolution.coordinates" in text and "ecosystem и version – ровно из задания" in text


def test_tool_step_limit_counts_every_call_including_several_in_one_answer(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake, rows=None)
        rows = manifest_rows(web, task)
        refs = [r["input_ref"] for r in rows]
        calls = [{"id": f"c{i}", "type": "function", "function": {"name": "search", "arguments": json.dumps({"query": f"q{i}"})}}
                 for i in range(4)]  # 4 вызова при пределе 3
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": calls}, "tool_calls"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop"),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[refs[0]]
        assert first["state"] == "saved" and len(first["tools"]) == 3, first["tools"]
        tool_messages = [m for m in fake.chats()[1]["messages"] if m.get("role") == "tool"]
        assert len(tool_messages) == 4 and "предел шагов исчерпан" in tool_messages[3]["content"]
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 3


def test_402_stops_the_run_and_leaves_the_rest_queued(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("http", 402, {"error": {"message": "insufficient balance"}})]
        runner_for(web).run(run["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "402" in done["reason"]
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]] == "failed" and states[rows[1]["input_ref"]] == "queued"
        assert len(fake.chats()) == 1, "после 402 обращений нет"


def test_unknown_result_is_never_resent(web):  # noqa: F811
    """Обрыв после отправки – «результат неизвестен»; перезапуск её не отправляет; «Доисследовать оставшиеся» – новое
    согласие и получение только на не получившиеся строки, неизвестные – лишь по явной отметке (К11)."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("drop",), ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "unknown" and "мог быть принят и оплачен" in first["reason"]
        assert states[rows[1]["input_ref"]]["state"] == "saved"
        done = db.research_run(run["id"])
        assert done["state"] == "done" and done["rows_unknown"] == 1 and done["rows_saved"] == 1
        sent = len(fake.chats())
        assert db.interrupt_research_runs() == 0  # перезапуск: идущих нет, ничего не отправляется
        assert db.followup_research_consent(run["id"]) is None, "без отметки неизвестную строку не берут"
        assert db.start_research_run(consent["id"])["id"] == run["id"], "одно получение на согласие"
        with pytest.raises(RuntimeError):
            db.resume_research_run(run["id"])  # завершённое не возобновляется
        assert len(fake.chats()) == sent
        # по явной отметке – новое согласие с теми же текстом и датой, только на эту строку
        follow = db.followup_research_consent(run["id"], include_unknown=True)
        assert follow and follow["rows"] == [rows[0]["input_ref"]] and follow["selection"] == "followup"
        assert follow["instructions"] == consent["instructions"] and follow["cutoff_date"] == consent["cutoff_date"]
        with pytest.raises(RuntimeError, match="вместе с отбором"):
            db.start_research_run(follow["id"])  # отдельный запуск followup-согласия по номеру не выполняется (круг 31)
        follow, fresh = db.start_followup_research(run["id"], include_unknown=True)
        assert fresh["id"] != run["id"] and fresh["consent_id"] == follow["id"]
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(fresh["id"])
        assert db.research_run(fresh["id"])["rows_saved"] == 1 and len(fake.chats()) == sent + 1
        assert db.research_run(run["id"])["rows_unknown"] == 1, "история прежнего получения не переписана"


def test_interrupted_run_marks_sending_rows_unknown_and_resume_skips_them(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        taken = db.take_research_row(run["id"])  # строка «отправлено» – приложение «упало» до результата
        assert taken["state"] == "sending" and taken["sending_at"]
        assert db.interrupt_research_runs() == 1
        assert db.research_run(run["id"])["state"] == "interrupted"
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[taken["input_ref"]] == "unknown" and states[rows[1]["input_ref"]] == "queued"
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        db.resume_research_run(run["id"])
        runner_for(web).run(run["id"])
        assert db.research_run(run["id"])["state"] == "done"
        assert len(fake.chats()) == 1, "строка с неизвестным результатом не отправлялась"
        assert json.loads(fake.chats()[0]["messages"][1]["content"])["row"]["input_ref"] == rows[1]["input_ref"]


def test_revoked_consent_refuses_before_sending(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        db.revoke_research_consent(consent["id"])
        runner_for(web).run(run["id"])
        assert fake.chats() == [] and db.research_run(run["id"])["state"] == "stopped"
        with pytest.raises(RuntimeError):
            db.resume_research_run(run["id"])


def test_no_search_mode_offers_only_answer_tool(web):  # noqa: F811
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake, search=False)
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(r, task), ensure_ascii=False)}, "stop")
                         for r in rows]
        runner_for(web).run(run["id"])
        assert [t["function"]["name"] for t in fake.chats()[0]["tools"]] == ["answer"]
        assert "без поиска по источникам" in consent["instructions"]


def test_consent_requires_current_task_and_one_running_per_project(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        profile = next(p for p in db.list_providers() if p["name"] == "Исследователь")
        execution = execution_values(profile, "flash-model", "ask", 16384, "always", purpose="research")
        with pytest.raises(RuntimeError):  # второе идущее получение проекта
            db.create_research_consent(pid, task["id"], execution, {
                "components_sha256": "c", "cutoff_date": CUTOFF, "instructions": "и", "instructions_sha256": "i",
                "rows": [], "model": "m"})


def test_provider_revision_gives_expert_defect_text(web):  # noqa: F811
    """Ревизия от провайдера даёт текст SCA для Hub по тем же
    правилам, что файловый ответ – «Описание», «Объяснение», «Рекомендации» с одной целевой версией без известных
    уязвимостей, «Источники» для человека без служебных адресов."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        row = good_row(rows[0], task)
        row["evidence"].append({"evidence_ref": "ev-api", "url": "https://api.github.com/repos/x/y/releases",
                                "checked_at": "2026-10-16", "source_type": "registry",
                                "justification": "Запрос к API", "quote": "9.0.99", "level": "primary"})
        row["package_advice"]["source_refs"] = ["ev-registry", "ev-api"]
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(row, ensure_ascii=False)}, "stop"),
                         ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        assert db.research_run(run["id"])["rows_saved"] == 2
        # карточка находки 73002 (CVE-2099-10001 у example-parser): решение «Обновить», текст набора – готов
        fid, card = sca_card(web, pid, "73002")
        url = f"/projects/{pid}/sca/findings/{fid}"
        import re
        fields = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
                  for name in ("finding_version", "answer_id", "review_revision")}
        r = web.client.post(url + "/review", headers=AS_JSON, data={**fields, "decision": "disagree",
                                                                   "final_verdict": "true_positive",
                                                                   "comment": "Обновить: компонент уязвим.",
                                                                   "action": "save"})
        assert r.status_code == 200, r.text[:800]
        page = web.client.get(url).text
        # целевая версия – из исследования провайдера (A5, A9): подсказка поля, ручной ввод не нужен
        target = re.search(r'id="package-target"[^>]*placeholder="([^"]*)"', page)
        assert target and target.group(1) == "9.0.99", page[page.find("package-target") - 200:][:400]
        found = re.search(r'name="text_revision" value="(\d+)"', page)
        explanation = "CVE-2099-10001: Обход аутентификации позволяет нарушителю получить доступ без проверки."
        second = web.client.post(url + "/package-text", headers=AS_JSON, data={
            **shown_fields(page), "text_revision": found.group(1) if found else "0", "explanation": explanation})
        assert second.status_code == 200 and second.json()["ready"] is True, second.text[:800]
        full = web.client.post(url + "/defect", headers=AS_JSON, data={"number": "1"})
        assert full.status_code == 200, full.text[:800]
        body = full.json()["body"]
        assert body.startswith("Описание\n") and "\nОбъяснение\n" in body and "\nРекомендации\n" in body \
            and "\nИсточники\n" in body
        assert "CVE-2099-10001 (https://nvd.nist.gov/vuln/detail/CVE-2099-10001)" in body
        assert body.count("Обновление ") == 1 and "до версии 9.0.99" in body  # одна целевая версия (A7)
        assert "api.github.com" not in body and "registry.example.invalid" not in body  # источники – для человека (A8)
        assert AST_ID not in body and "advisories.example.invalid/CVE-2099-10001" in body
        assert full.json()["title"].startswith("ID1 - ")


def test_tool_failure_with_unknown_outcome_continues_the_row_without_retry(web):  # noqa: F811
    """Ревью B3, пересмотрено ADR-0111: сбой инструмента после отправки с неизвестным
    исходом не обрывает строку – модель получает «результат неизвестен» и завершает строку по собранному; повторного
    вызова инструмента нет; шаг помечен «unknown»."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 502, {"error": {"message": "bad gateway"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "search", "arguments": json.dumps({"query": "q"})}}]}, "tool_calls"),
                         ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "unknown"
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 1, "повторного запроса инструмента нет"
        first_chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == rows[0]["input_ref"]]
        assert len(first_chats) == 2, "второй ход – ответ по собранному"
        tool_msg = next(m for m in first_chats[1]["messages"] if m.get("role") == "tool")
        assert "результат неизвестен" in tool_msg["content"] and "не повторяя запрос" in tool_msg["content"]
        assert first["usage"].get("search_calls") == 1, "расход инструмента учтён: запрос мог быть оплачен"


def test_tool_arguments_are_validated_and_search_retries_once(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 429, {"error": {"message": "slow down"}}, {"Retry-After": "1"})]
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "search", "arguments": json.dumps({"query": "q", "count": "abc"})}}]}, "tool_calls"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop"),
        ]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "ok"
        searches = [r for r in fake.requests if r["path"] == "/v1/tools/search"]
        assert len(searches) == 2 and searches[0]["body"]["count"] == 5, "count=abc → 5; 429 → один повтор"
        assert first["usage"]["search_calls"] == 2, "расход – по фактическим попыткам (ревью круга 2)"


def test_length_without_valid_row_is_not_retried_and_send_budget_holds(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        broken = {**good_row(rows[0], task), "current_version": "0.0.0-чужая"}
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(broken, ensure_ascii=False)}, "length")]
        fake.default_answer = "не JSON"
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "failed" and "оборван по длине" in states[rows[0]["input_ref"]]["reason"]
        def ref_of(c):
            return json.loads(c["messages"][1]["content"])["row"]["input_ref"]
        assert len([c for c in fake.chats() if ref_of(c) == rows[0]["input_ref"]]) == 1, "после length повтора нет"
        assert len([c for c in fake.chats() if ref_of(c) == rows[1]["input_ref"]]) == 1 + net.ROW_RETRIES


def test_mixed_answer_and_tool_calls_close_every_call(web):  # noqa: F811
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [
                {"id": "s1", "type": "function", "function": {"name": "search", "arguments": json.dumps({"query": "q"})}},
                {"id": "a1", "type": "function", "function": {"name": "answer", "arguments": json.dumps({"row": good_row(rows[0], task)}, ensure_ascii=False)}},
            ]}, "tool_calls"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop"),
        ]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]] == "saved"
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 1, "инструмент рядом с answer выполнен"


def test_revoke_during_send_waits_and_blocks_the_next_send(web, monkeypatch):  # noqa: F811
    """К2: отзыв согласия берёт исключительную блокировку – начатая отправка (барьер внутри общей блокировки
    согласия, то есть до передачи байтов) уходит один раз, отзыв ждёт её конца, следующая строка не отправляется."""
    import threading
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hold, inside = threading.Event(), threading.Event()
        real_gate = net.consent_gate(consent["id"])

        class Holding:  # блокировка согласия с барьером внутри общей части: «отправка» ещё не закончена
            @contextmanager
            def read(self, timeout: float = 120.0):
                with real_gate.read(timeout):
                    if not inside.is_set():
                        inside.set()
                        hold.wait(5)
                    yield

            def write(self, *args, **kwargs):
                return real_gate.write(*args, **kwargs)
        monkeypatch.setattr(net, "consent_gate", lambda consent_id: Holding())
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
                         ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        worker = threading.Thread(target=lambda: runner_for(web).run(run["id"]))
        worker.start()
        try:
            assert inside.wait(5), "исполнитель вошёл в блокировку отправки"
            revoked = threading.Thread(target=lambda: db.revoke_research_consent(consent["id"]))
            revoked.start()
            time.sleep(0.3)
            assert revoked.is_alive(), "отзыв ждёт конца начатой отправки"
            assert db.research_consent(consent["id"])["state"] == "active"
        finally:
            hold.set()
        worker.join(10)
        revoked.join(10)
        assert not revoked.is_alive() and db.research_consent(consent["id"])["state"] == "revoked"
        assert len(fake.chats()) == 1, "после отзыва вторая строка не отправлена"
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]] == "saved" and states[rows[1]["input_ref"]] == "queued"
        assert db.research_run(run["id"])["state"] == "stopped"


def test_repeated_start_does_not_cancel_a_stop(web):  # noqa: F811
    import threading
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        runner = runner_for(web)
        gate = threading.Event()
        runner._threads[run["id"]] = threading.Thread(target=gate.wait, daemon=True)
        runner._threads[run["id"]].start()
        runner.stop(run["id"])
        runner.start(run["id"])
        assert runner._stopped(run["id"]), "повторный start при живом потоке стоп не снимает"
        gate.set()


def test_tool_only_turns_exhaust_the_row_budget(web):  # noqa: F811
    """К3 (ревью круга 2): один бюджет отправок на строку – ходы только с вызовами инструментов тоже расходуют его;
    модель, которая всё время ищет и не отвечает, останавливается по бюджету, а не крутится бесконечно."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.default_answer = ("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c", "type": "function", "function": {
            "name": "search", "arguments": json.dumps({"query": "ещё"})}}]}, "tool_calls")
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        limit = 3 + net.ROW_SENDS_MAX  # tool_steps профиля – 3
        assert first["state"] == "failed" and f"исчерпан бюджет отправок на строку ({limit})" in first["reason"]
        assert first["usage"]["sends"] == limit
        def ref_of(c):
            return json.loads(c["messages"][1]["content"])["row"]["input_ref"]
        assert len([c for c in fake.chats() if ref_of(c) == rows[0]["input_ref"]]) == limit
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 3 * len(rows), "шагов – не больше предела"


def test_length_on_tool_calls_is_not_continued(web):  # noqa: F811
    """Ответ, оборванный по длине на вызовах инструментов (и с текстом тоже), не продолжается: аргументы могли не
    дописаться, инструменты не выполняются."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": "ищу сведения…", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "search", "arguments": json.dumps({"query": "q"})}}]}, "length"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "failed" and "оборван по длине" in states[rows[0]["input_ref"]]["reason"]
        assert not [r for r in fake.requests if r["path"] == "/v1/tools/search"], "инструмент оборванного ответа не вызван"
        assert len(fake.chats()) == 2


def test_composition_change_is_caught_before_the_next_send(web):  # noqa: F811
    """Ревью круга 2 (блокирующее 3): новая выгрузка меняет состав, но не номер задания – допуск сверяет отпечаток
    состава перед каждой отправкой, следующая строка не уходит."""
    from hub_fixtures import SCA_ROWS, make_hub_xlsx
    from test_web import upload
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        assert db.task_composition_current(pid, task["id"])

        def first(body):
            newer = [dict(row) for row in SCA_ROWS if row["Component name"] != "demo-xml"]
            assert upload(web.client, pid, make_hub_xlsx(web.tmp / "newer.xlsx", sast=(), sca=newer)).status_code == 303
            return ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")
        fake.answers += [first]
        runner_for(web).run(run["id"])
        assert not db.task_composition_current(pid, task["id"])
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "устарело" in done["reason"], done
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[1]["input_ref"]] == "queued" and len(fake.chats()) == 1, "вторая строка не отправлена"


def test_crash_after_a_saved_row_does_not_rewrite_it(web):  # noqa: F811
    """Ревью круга 2: сбой при взятии следующей строки – сохранённая строка не переписывается в «неизвестно»."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")]
        real = db.take_research_row
        calls = {"n": 0}

        def flaky(run_id):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("база недоступна")
            return real(run_id)
        db.take_research_row = flaky
        try:
            runner_for(web).run(run["id"])
        finally:
            db.take_research_row = real
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "saved" and states[rows[0]["input_ref"]]["reason"] == ""
        assert states[rows[1]["input_ref"]]["state"] == "queued"
        done = db.research_run(run["id"])
        assert done["state"] == "interrupted" and done["rows_saved"] == 1 and done["rows_unknown"] == 0


def test_interrupt_recounts_runs_stopped_with_a_sending_row(web):  # noqa: F811
    """Ревью круга 2: при перезапуске строка «отправлено» остановленного отзывом получения становится «неизвестно»
    и его счётчики пересчитываются."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        taken = db.take_research_row(run["id"])
        assert taken and taken["state"] == "sending"
        db.revoke_research_consent(consent["id"])
        assert db.research_run(run["id"])["state"] == "stopped"
        assert db.interrupt_research_runs() == 0, "идущих нет"
        rows = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert rows[taken["input_ref"]]["state"] == "unknown" and rows[taken["input_ref"]]["sending_at"] is None
        assert db.research_run(run["id"])["rows_unknown"] == 1


def test_turn_budget_and_deadline_are_shared_with_the_transport(web):  # noqa: F811
    """К3 (ревью круга 3): остаток бюджета строки уходит внутрь хода – при одной оставшейся отправке повтор после
    429 не делается; отправки сорвавшегося хода учитываются (LlmError.sends)."""
    from app.llm import LlmError
    from app.llm_chat import ChatCompletionsClient
    with FakeChatApi(models=["flash-model"]) as fake:
        client = ChatCompletionsClient(fake.url, timeout=30)
        client.trust = "local"  # поддельный сервер – http на loopback
        fake.answers += [("http", 429, {"error": {"message": "slow"}}, {"Retry-After": "1"})]
        with pytest.raises(LlmError) as caught:
            client.chat_turn("flash-model", [{"role": "user", "content": "x"}], max_sends=1)
        assert len(fake.chats()) == 1 and caught.value.sends == 1
        fake.answers += [("http", 429, {"error": {"message": "slow"}}, {"Retry-After": "1"}),
                         ("message", {"role": "assistant", "content": "ok"}, "stop")]
        turn = client.chat_turn("flash-model", [{"role": "user", "content": "x"}], max_sends=2)
        assert turn.sends == 2 and len(fake.chats()) == 3
        with pytest.raises(LlmError, match="срок"):
            client.chat_turn("flash-model", [{"role": "user", "content": "x"}], deadline=time.monotonic() - 1)
        assert len(fake.chats()) == 3


def test_composition_change_waits_for_a_started_send(web, monkeypatch):  # noqa: F811
    """Ревью круга 3 (блокирующее 5): запись новой выгрузки ждёт конца начатой отправки исследования (общая блокировка
    состава держится до передачи байтов), а следующая отправка видит новый состав."""
    import threading
    from hub_fixtures import SCA_ROWS, make_hub_xlsx
    from test_web import upload
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        hold, inside, imported = threading.Event(), threading.Event(), threading.Event()
        real_gate = net.composition_gate

        class Holding:  # барьер внутри общей блокировки состава: «отправка» строки ещё не закончена
            @contextmanager
            def read(self, timeout: float = 120.0):
                with real_gate.read(timeout):
                    if not inside.is_set():
                        inside.set()
                        hold.wait(5)
                    yield

            def write(self, *args, **kwargs):
                return real_gate.write(*args, **kwargs)
        monkeypatch.setattr(net, "composition_gate", Holding())
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop")]
        fake.default_answer = ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")

        def change():
            newer = [dict(row) for row in SCA_ROWS if row["Component name"] != "demo-xml"]
            assert upload(web.client, pid, make_hub_xlsx(web.tmp / "newer.xlsx", sast=(), sca=newer)).status_code == 303
            imported.set()
        worker = threading.Thread(target=lambda: runner_for(web).run(run["id"]))
        worker.start()
        try:
            assert inside.wait(5)
            changer = threading.Thread(target=change)
            changer.start()
            time.sleep(0.3)
            assert not imported.is_set(), "выгрузка ждёт конца начатой отправки"
        finally:
            hold.set()
        worker.join(15)
        changer.join(15)
        assert imported.is_set()
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "устарело" in done["reason"], done
        assert len(fake.chats()) == 1, "после смены состава вторая строка не отправлена"


def test_length_with_a_complete_valid_row_is_accepted(web):  # noqa: F811
    """Ревью круга 4: закрытый годный объект строки в тексте ответа, оборванного по длине, принимается (К3, К7);
    инструменты из такого ответа не выполняются."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False),
                                      "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "search", "arguments": "{\"query\": \"q"}}]}, "length"),
                         ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]] == "saved" and states[rows[1]["input_ref"]] == "saved"
        assert not [r for r in fake.requests if r["path"] == "/v1/tools/search"]


def test_row_budget_allows_one_transport_retry_and_bounds_answer_repairs(web):  # noqa: F811
    """К3 (ревью круга 6): повтор транспорта на строку – один, бюджет без инструментов – ROW_SENDS_MAX: цепочка
    429 → не по формату → 429 → … не перемножает бюджеты."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        bad = ("message", {"role": "assistant", "content": "не JSON"}, "stop")
        slow = ("http", 429, {"error": {"message": "slow"}}, {"Retry-After": "1"})
        fake.answers += [slow, bad, slow, bad, slow]
        fake.default_answer = ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "failed" and first["usage"]["sends"] == 3, first
        def ref_of(c):
            return json.loads(c["messages"][1]["content"])["row"]["input_ref"]
        assert len([c for c in fake.chats() if ref_of(c) == rows[0]["input_ref"]]) == 3, "второй 429 без повтора"


def test_tool_404_is_reported_as_the_provider_refusal(web):  # noqa: F811
    """Провайдер ответил 404 на fetch («failed to fetch URL») – текст про отказ получить
    страницу, а не «адрес или модель не найдены – проверьте адрес профиля»."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.fetch_answers += [("http", 404, {"error": {"message": "failed to fetch URL"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "fetch", "arguments": json.dumps({"url": "https://example.org/page"})}}]}, "tool_calls"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[0], task), ensure_ascii=False)}, "stop"),
            ("message", {"role": "assistant", "content": json.dumps(good_row(rows[1], task), ensure_ascii=False)}, "stop")]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "error"
        assert "не смог получить страницу" in first["tools"][0]["error"] and "проверьте адрес профиля" not in first["tools"][0]["error"]
        tool_message = fake.chats()[1]["messages"][3]
        assert tool_message["role"] == "tool" and "не смог получить страницу" in tool_message["content"]


def _tool_call(cid: str, name: str, **args) -> dict:
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _answer(row: dict) -> tuple:
    return ("message", {"role": "assistant", "content": json.dumps(row, ensure_ascii=False)}, "stop")


def test_same_tool_request_is_not_resent_after_unknown_outcome(web):  # noqa: F811
    """ADR-0111 п. 1 (ревью Codex, круг 29): после неизвестного исхода тот же запрос инструмента – второй вызов в том же
    ответе модели (с лишними пробелами) и вызов в следующем ходе (с другим count) – не отправляется, модель получает
    отказ «повтор не отправлен»; отказ считается шагом (предел шагов – 3)."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 504, {"error": {"message": "gateway timeout"}})]
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [
                _tool_call("c1", "search", query="zod  advisory"), _tool_call("c2", "search", query="zod advisory")]}, "tool_calls"),
            ("message", {"role": "assistant", "content": "", "tool_calls": [
                _tool_call("c3", "search", query="zod advisory", count=3)]}, "tool_calls"),
            _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        searches = [r for r in fake.requests if r["path"] == "/v1/tools/search"]
        assert [s["body"]["query"] for s in searches] == ["zod advisory"], "один сетевой запрос на отпечаток"
        assert [t["status"] for t in first["tools"]] == ["unknown", "error", "error"]
        assert first["tools"][1]["error"] == "повтор запроса с неизвестным исходом не отправлен"
        assert first["state"] == "saved" and first["usage"]["search_calls"] == 1
        chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == rows[0]["input_ref"]]
        tool_msgs = [m["content"] for m in chats[-1]["messages"] if m.get("role") == "tool"]
        assert sum("повтор не отправлен" in m for m in tool_msgs) == 2


def test_fetch_unknown_outcome_continues_the_row(web):  # noqa: F811
    """ADR-0111: 504 у fetch – шаг «unknown» с ошибкой, fetch_calls учтён, строка завершается ответом."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.fetch_answers += [("http", 504, {"error": {"message": "gateway timeout"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [
            _tool_call("c1", "fetch", url="https://example.invalid/advisory")]}, "tool_calls"), _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["usage"]["fetch_calls"] == 1
        assert first["tools"][0]["tool"] == "fetch" and first["tools"][0]["status"] == "unknown" and "504" in first["tools"][0]["error"]
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/fetch"]) == 1


def test_stop_after_tool_unknown_outcome_marks_the_row_unknown(web):  # noqa: F811
    """ADR-0111 п. 3 (ревью Codex, круг 29): «Остановить» во время инструмента с неизвестным исходом – строка «результат
    неизвестен», не очередь; «Продолжить» её не отправляет, остальные строки идут."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        runner = runner_for(web)

        def stop_then_504(_body):
            with runner._lock:
                runner._stops.add(int(run["id"]))
            return ("http", 504, {"error": {"message": "gateway timeout"}})
        fake.search_answers += [stop_then_504]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls")]
        runner.run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "unknown" and "мог быть принят и оплачен" in first["reason"] and "в очередь не возвращается" in first["reason"]
        assert states[rows[1]["input_ref"]]["state"] == "queued" and db.research_run(run["id"])["state"] == "stopped"
        sent = len(fake.chats())
        db.resume_research_run(run["id"])
        fake.answers += [_answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "unknown" and states[rows[1]["input_ref"]]["state"] == "saved"
        assert len(fake.chats()) == sent + 1, "первая строка после «Продолжить» не отправлена"


def test_402_from_a_tool_stops_the_run(web):  # noqa: F811
    """К7: 402 внутри инструмента – получение остановлено, следующие строки не отправляются."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 402, {"error": {"message": "insufficient balance"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls")]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "402" in done["reason"]
        assert states[rows[0]["input_ref"]] == "failed" and states[rows[1]["input_ref"]] == "queued"
        assert len(fake.chats()) == 1


def test_failed_row_after_tool_unknown_outcome_keeps_the_note(web):  # noqa: F811
    """ADR-0111 п. 3: после сбоя инструмента модель так и не дала годной строки – «не получена» с пометкой, что запрос
    инструмента мог быть оплачен."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 502, {"error": {"message": "bad gateway"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls")]
        fake.answers += [("message", {"role": "assistant", "content": "не знаю"}, "stop")] * 4
        fake.answers += [_answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "failed" and "мог быть принят и оплачен" in first["reason"]
        assert db.research_run(run["id"])["rows_saved"] == 1


def test_equivalent_fetch_url_is_not_resent_after_unknown_outcome(web):  # noqa: F811
    """Ревью Codex, круги 30–31: адрес страницы приводится к каноническому виду – `https://EXAMPLE.org/` после
    неизвестного исхода `https://example.org` не отправляется, другой путь того же узла отправляется; IPv6 в полной и
    сжатой записи – один адрес."""
    from app.llm_chat import check_fetch_url
    assert check_fetch_url("HTTPS://Example.org") == "https://example.org/"
    assert check_fetch_url("https://example.org:443/a?b=1#c") == "https://example.org/a?b=1#c"
    assert check_fetch_url("http://example.org:8080/A/") == "http://example.org:8080/A/"
    assert check_fetch_url("https://[2606:4700:4700:0:0:0:0:1111]:443/x") == "https://[2606:4700:4700::1111]/x"
    mapped = check_fetch_url("https://[::ffff:8.8.8.8]/x")
    assert mapped == check_fetch_url("https://[0:0:0:0:0:ffff:808:808]:443/x") and mapped.startswith("https://[::ffff:")
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.fetch_answers += [("http", 504, {"error": {"message": "gateway timeout"}})]
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "fetch", url="https://example.org")]}, "tool_calls"),
            ("message", {"role": "assistant", "content": "", "tool_calls": [
                _tool_call("c2", "fetch", url="https://EXAMPLE.org/"), _tool_call("c3", "fetch", url="https://example.org/other")]}, "tool_calls"),
            _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        fetches = [r for r in fake.requests if r["path"] == "/v1/tools/fetch"]
        assert [f["body"]["url"] for f in fetches] == ["https://example.org/", "https://example.org/other"], "канонический адрес; другой путь отправлен"
        assert [t["status"] for t in first["tools"]] == ["unknown", "error", "error"] and first["state"] == "saved"
        assert first["tools"][1]["error"] == "повтор запроса с неизвестным исходом не отправлен"
        assert "no content" in first["tools"][2]["error"], "другой путь ушёл провайдеру (404 фальшивого API)"


@pytest.mark.parametrize("first_url, second_url, canonical", [
    ("https://[2606:4700:4700::1111]/x", "https://[2606:4700:4700:0:0:0:0:1111]:443/x", "https://[2606:4700:4700::1111]/x"),
    ("https://[::ffff:8.8.8.8]/x", "https://[0:0:0:0:0:ffff:808:808]:443/x", None),
])
def test_equivalent_ipv6_fetch_url_is_not_resent_after_unknown_outcome(web, first_url, second_url, canonical):  # noqa: F811
    """Ревью Codex, круги 31–32: полная и сжатая записи одного IPv6 (в том числе IPv4-mapped) – один отпечаток, второй
    запрос не отправляется."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.fetch_answers += [("http", 504, {"error": {"message": "gateway timeout"}})]
        fake.answers += [
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "fetch", url=first_url)]}, "tool_calls"),
            ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c2", "fetch", url=second_url)]}, "tool_calls"),
            _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        fetches = [r for r in fake.requests if r["path"] == "/v1/tools/fetch"]
        assert len(fetches) == 1 and fetches[0]["body"]["url"] == (canonical or first["tools"][0]["url"])
        assert [t["status"] for t in first["tools"]] == ["unknown", "error"] and first["state"] == "saved"


def test_overflow_after_tool_unknown_outcome_fails_with_the_note(web, monkeypatch):  # noqa: F811
    """Ревью Codex, круги 30–31: переполнение контекста после сбоя инструмента – строка «не получена» с пометкой о
    запросе инструмента, который мог быть оплачен; получение идёт дальше, следующая строка сохранена."""
    from app.llm import PromptOverflowError
    from app.llm_chat import ChatCompletionsClient
    db = web.app.state.db
    original = ChatCompletionsClient.chat_turn
    calls = {"n": 0}

    def chat_turn(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise PromptOverflowError("Промпт не помещается в окно контекста модели.")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(ChatCompletionsClient, "chat_turn", chat_turn)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 502, {"error": {"message": "bad gateway"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls"),
                         _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "failed" and "не помещается" in first["reason"] and "мог быть принят и оплачен" in first["reason"]
        assert states[rows[1]["input_ref"]]["state"] == "saved" and db.research_run(run["id"])["state"] == "done"


def test_tool_drop_without_http_answer_continues_the_row(web):  # noqa: F811
    """П. 26: обрыв соединения у инструмента без HTTP-ответа (не 502/504) – тоже неизвестный исход: шаг «unknown»,
    строка продолжается и сохраняется, запрос инструмента не повторяется."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("drop",)]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls"),
                         _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0]["status"] == "unknown" and first["usage"]["search_calls"] == 1
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 1


def test_tool_unknown_outcome_on_the_last_allowed_step(web):  # noqa: F811
    """П. 26: неизвестный исход на последнем допустимом шаге (предел 3): следующий вызов получает «предел шагов
    исчерпан» без сети, годный ответ принимается."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [None, None, ("http", 504, {"error": {"message": "gateway timeout"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call(f"c{i}", "search", query=f"q{i}")]}, "tool_calls")
                         for i in (1, 2, 3, 4)] + [_answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert [t["status"] for t in first["tools"]] == ["ok", "ok", "unknown"] and first["state"] == "saved"
        assert len([r for r in fake.requests if r["path"] == "/v1/tools/search"]) == 3
        chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == rows[0]["input_ref"]]
        tool_msgs = [m["content"] for m in chats[-1]["messages"] if m.get("role") == "tool"]
        assert "предел шагов исчерпан" in tool_msgs[-1]


def test_later_saved_boundaries_lower_run_and_other_task(web):  # noqa: F811
    """П. 26: «исследована позже» ставится только по получению с большим номером и того же задания: успех раннего
    получения и успех получения другого задания строку из доисследования не убирают."""
    import re
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run_a = start_run(web, fake)
        rows = manifest_rows(web, task)
        x = rows[0]["input_ref"]
        fake.answers += [_answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run_a["id"])
        assert db.research_run(run_a["id"])["rows_saved"] == 2
        _, _, _, run_b = start_run(web, fake, rows=[x], project=(pid, task))
        fake.answers += [("drop",)]
        runner_for(web).run(run_b["id"])
        assert {r["input_ref"]: r["state"] for r in db.research_run_rows(run_b["id"])} == {x: "unknown"}

        def page_b() -> tuple[int, bool]:
            page = web.client.get(f"/projects/{pid}/components/research/{run_b['id']}").text
            return int(re.search(r'data-count="leftover">(\d+)<', page).group(1)), "исследована позже" in page
        # ранний успех (run_a < run_b) – не «позже»
        assert page_b() == (1, False)
        assert db.followup_research_consent(run_b["id"], include_unknown=True)["rows"] == [x]
        # поздний успех по той же строке, но в другом задании (другой проект с той же выгрузкой) – не «позже»
        pid2 = project_with_sca(web)
        build_task(web, pid2)
        task2 = db.current_task(pid2)
        assert x in [r["input_ref"] for r in manifest_rows(web, task2)]
        _, _, _, run_d = start_run(web, fake, rows=[x], project=(pid2, task2))
        fake.answers += [_answer(good_row(rows[0], task2))]
        runner_for(web).run(run_d["id"])
        assert db.research_run(run_d["id"])["rows_saved"] == 1 and run_d["id"] > run_b["id"]
        assert page_b() == (1, False)
        assert db.followup_research_consent(run_b["id"], include_unknown=True)["rows"] == [x]
        # поздний успех того же задания – «позже»
        _, _, _, run_c = start_run(web, fake, rows=[x], project=(pid, task))
        fake.answers += [_answer(good_row(rows[0], task))]
        runner_for(web).run(run_c["id"])
        assert page_b() == (0, True)
        assert db.followup_research_consent(run_b["id"], include_unknown=True) is None


def test_overflow_row_resets_the_drop_streak(web, monkeypatch):  # noqa: F811
    """П. 26 (ADR-0111 п. 5): строка, где обрывался только инструмент, а ход модели упёрся в переполнение контекста,
    серию обрывов сбрасывает – при пороге 2 два обрыва модели по краям такой строки получение не останавливают."""
    from hub_fixtures import SCA_BASE, SCA_ROWS, make_hub_xlsx
    from test_web import create_project, upload
    from app.llm import PromptOverflowError
    from app.llm_chat import ChatCompletionsClient
    db = web.app.state.db
    monkeypatch.setattr(net, "DROP_STREAK_PAUSE", 2)
    third = dict(SCA_BASE, **{"Issue id": "73009", "CVSS score": "7.5", "Component name": "demo-third",
                              "Component version": "2.0.0", "CVE id": "CVE-2099-10009", "Non-vulnerable versions": "2.0.1",
                              "CWE ID": "79", "CWE link": "https://cwe.mitre.org/data/definitions/79.html"})
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub3.xlsx", sast=(), sca=SCA_ROWS + [third])).status_code == 303
    build_task(web, pid)
    task = db.current_task(pid)
    original = ChatCompletionsClient.chat_turn
    calls = {"n": 0}

    def chat_turn(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:  # 1 – обрыв первой строки, 2 – вызов инструмента второй строки, 3 – её следующий ход
            raise PromptOverflowError("Промпт не помещается в окно контекста модели.")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(ChatCompletionsClient, "chat_turn", chat_turn)
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task))
        rows = manifest_rows(web, task)
        assert len(rows) == 3
        fake.search_answers += [("http", 502, {"error": {"message": "bad gateway"}})]
        fake.answers += [("drop",),
                         ("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls"),
                         ("drop",)]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]]["state"] == "unknown"
        second = states[rows[1]["input_ref"]]
        assert second["state"] == "failed" and "мог быть принят и оплачен" in second["reason"]
        assert states[rows[2]["input_ref"]]["state"] == "unknown"
        done = db.research_run(run["id"])
        assert done["state"] == "done", done["reason"]  # серия сброшена второй строкой: 1, 0, 1 – паузы нет


def test_overflow_with_pending_unknown_keeps_the_row_unknown(web, monkeypatch):  # noqa: F811
    """П. 26: после обрыва хода модели повтор (отметка профиля) упёрся в переполнение контекста – строка «результат
    неизвестен» с пометкой, а не «не получена»: исход оборванного запроса открыт."""
    from app.llm import PromptOverflowError
    from app.llm_chat import ChatCompletionsClient
    db = web.app.state.db
    monkeypatch.setattr(net, "drop_retry_allowed", lambda execution: True)
    original = ChatCompletionsClient.chat_turn
    calls = {"n": 0}

    def chat_turn(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:  # повтор после обрыва
            raise PromptOverflowError("Промпт не помещается в окно контекста модели.")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(ChatCompletionsClient, "chat_turn", chat_turn)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [("drop",), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "unknown" and "не помещается" in first["reason"] and "мог быть принят и оплачен" in first["reason"]
        assert states[rows[1]["input_ref"]]["state"] == "saved"


def test_save_refusal_after_tool_unknown_outcome_keeps_the_note(web, monkeypatch):  # noqa: F811
    """П. 26 (ADR-0111 п. 3): отказ сохранения годного ответа (задание устарело) после сбоя инструмента – строка
    «не получена» с пометкой о запросе инструмента, который мог быть оплачен; получение остановлено."""
    from app.db import TaskSuperseded
    db = web.app.state.db
    original = db.finish_research_row

    def finish(run_id, input_ref, state, *args, **kwargs):
        if state == "saved":
            raise TaskSuperseded(0, "состав изменился")
        return original(run_id, input_ref, state, *args, **kwargs)
    monkeypatch.setattr(db, "finish_research_row", finish)
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.search_answers += [("http", 502, {"error": {"message": "bad gateway"}})]
        fake.answers += [("message", {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "search", query="q")]}, "tool_calls"),
                         _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "failed" and first["reason"].startswith("не сохранено:") and "мог быть принят и оплачен" in first["reason"]
        assert db.research_run(run["id"])["state"] == "stopped"


def npm_project(web, names: tuple[str, ...] = ("zod", "lodash")) -> tuple[int, dict]:
    """Проект с выгрузкой SCA по npm (имя реестра – координаты разрешены): для запросов OSV; у maven-заготовки
    имена короткие (short_name), и OSV по ним не запрашивается (ADR-0112)."""
    from hub_fixtures import SCA_BASE, make_hub_xlsx
    from test_web import create_project, upload
    db = web.app.state.db
    rows = [dict(SCA_BASE, **{"Type": "npm", "Issue id": f"7400{i}", "CVSS score": "7.5", "Component name": name,
                              "Component version": "1.0.0", "CVE id": f"CVE-2099-3000{i}", "Non-vulnerable versions": "1.0.1",
                              "CWE ID": "79", "CWE link": "https://cwe.mitre.org/data/definitions/79.html"})
            for i, name in enumerate(names)]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / f"hub-npm-{pid}.xlsx", sast=(), sca=rows)).status_code == 303
    build_task(web, pid)
    return pid, db.current_task(pid)


def _first_user_message(fake: FakeChatApi, input_ref: str) -> dict:
    chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == input_ref]
    return json.loads(chats[0]["messages"][1]["content"])


def test_osv_answer_goes_into_the_first_message(web):  # noqa: F811
    """ADR-0112: до обращения к модели приложение само запрашивает OSV по паре координаты/версия (ровно экосистема,
    имя, версия) и кладёт урезанный ответ в поле osv первого сообщения; шаг 0 «osv» в ходе строки, расход osv_calls."""
    from app import osv
    db = web.app.state.db
    pid, task = npm_project(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        eco, name, version = osv.osv_ecosystem(rows[0]["ecosystem"]), rows[0]["component"], rows[0]["version"]
        assert eco, rows[0]
        fake.osv_answers += [{"vulns": [{"id": "GHSA-osv1", "aliases": ["CVE-2099-10001"], "summary": "Обход проверки",
                                         "published": "2026-01-01T00:00:00Z", "modified": "2026-02-01T00:00:00Z",
                                         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                                         "affected": [{"package": {"ecosystem": eco, "name": name},
                                                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.4.9"}]}],
                                                       "versions": ["1.0.0", version]},
                                                      {"package": {"ecosystem": eco, "name": "other:pkg"},
                                                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
                                         "references": [{"type": "ADVISORY", "url": "https://advisories.example.invalid/osv1"}]}]}]
        fake.answers += [_answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        queries = [r for r in fake.requests if r["path"] == "/v1/query"]
        assert len(queries) == 2, "по одному запросу OSV на строку"
        assert queries[0]["body"] == {"package": {"ecosystem": eco, "name": name}, "version": version}
        assert "Authorization" not in queries[0]["headers"] and "authorization" not in {k.lower() for k in queries[0]["headers"]}
        message = _first_user_message(fake, rows[0]["input_ref"])
        assert message["osv"]["status"] == "ok" and message["osv"]["query"] == queries[0]["body"]
        vuln = message["osv"]["vulns"][0]
        assert vuln["id"] == "GHSA-osv1" and vuln["aliases"] == ["CVE-2099-10001"] and "versions" not in json.dumps(vuln)
        assert len(vuln["affected"]) == 1 and vuln["affected"][0]["ranges"][0]["events"][1] == {"fixed": "1.4.9"}
        assert vuln["references"] == ["https://advisories.example.invalid/osv1"]
        assert "seconds" not in message["osv"] and "sent" not in message["osv"]
        assert set(message) == {"cutoff_date", "row", "osv"}, "ничего сверх строки, даты среза и ответа OSV"
        assert f"адрес запроса OSV: {osv_base(fake)})" in _consent["instructions"], "адрес OSV – в тексте согласия"
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        first = states[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["tools"][0] == {**first["tools"][0], "step": 0, "tool": "osv", "status": "ok", "results": 1}
        assert first["usage"]["osv_calls"] == 1
        second = _first_user_message(fake, rows[1]["input_ref"])
        assert second["osv"]["status"] == "empty" and second["osv"]["vulns"] == [] and "не знает" in second["osv"]["note"]


def test_osv_error_and_empty_do_not_stop_the_row(web):  # noqa: F811
    """ADR-0112 п. 5: сбой запроса OSV (500, обрыв) – status error с причиной, повтора нет, строка исследуется дальше."""
    db = web.app.state.db
    pid, task = npm_project(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        fake.osv_answers += [("http", 500, {"error": "boom"}), ("drop",)]
        fake.answers += [_answer(osv_failed_row(rows[0], task)), _answer(osv_failed_row(rows[1], task))]
        runner_for(web).run(run["id"])
        assert len([r for r in fake.requests if r["path"] == "/v1/query"]) == 2, "по одному запросу, без повтора"
        for ref in (rows[0]["input_ref"], rows[1]["input_ref"]):
            message = _first_user_message(fake, ref)
            assert message["osv"]["status"] == "error" and "не удался" in message["osv"]["note"]
        states = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}
        assert all(states[r["input_ref"]]["state"] == "saved" for r in rows)
        assert states[rows[0]["input_ref"]]["tools"][0]["status"] == "error"
        assert db.research_run(run["id"])["state"] == "done"


def test_osv_off_keeps_the_message_without_the_field(web):  # noqa: F811
    """Согласие без адреса OSV (OSV_URL=off или согласие до 0.9.18): запроса нет, поля osv в первом сообщении нет,
    шага «osv» в ходе строки нет – даже если запрос OSV в приложении включён."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake)
        rows = manifest_rows(web, task)
        fake.answers += [_answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        assert not [r for r in fake.requests if r["path"] == "/v1/query"]
        message = _first_user_message(fake, rows[0]["input_ref"])
        assert "osv" not in message and set(message) == {"cutoff_date", "row"}
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert not [t for t in first["tools"] if t.get("tool") == "osv"] and first["usage"].get("osv_calls", 0) == 0


def test_osv_response_shapes(web):  # noqa: F811
    """Б3/В1 круга 34: {} и null – empty; vulns не список и не объект – error; запись с неверной структурой
    пропускается с примечанием, остальные идут; next_page_token – partial; строка исследуется дальше всегда."""
    db = web.app.state.db
    pid, task = npm_project(web, tuple(f"demo-shape-{i}" for i in range(8)))
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        assert len(rows) == 8
        fake.osv_answers += [{}, {"vulns": None}, {"vulns": "x"}, {"error": "boom"},
                             {"vulns": [{"id": "X", "affected": 1}, {"id": "Y", "aliases": ["CVE-2099-20003"]}]},
                             {"vulns": [{"id": "Z"}], "next_page_token": "abc"},
                             ("http", 200, ""), ("http", 200, " \n ")]
        expected = ["empty", "empty", "error", "error", "partial", "partial", "error", "error"]
        fake.answers += [_answer(good_row(r, task) if st == "empty" else osv_failed_row(r, task, st)) for r, st in zip(rows, expected, strict=True)]
        runner_for(web).run(run["id"])
        statuses = [_first_user_message(fake, r["input_ref"])["osv"] for r in rows]
        # Б1 круга 35: empty – только чистый пустой ответ; любая потеря (пропущенная запись, продолжение) – partial;
        # Б1 круга 36: пустое тело HTTP 200 – error, не «OSV уязвимостей не знает»
        assert [s["status"] for s in statuses] == ["empty", "empty", "error", "error", "partial", "partial", "error", "error"]
        assert "не по формату" in statuses[2]["note"] and "нет поля vulns" in statuses[3]["note"]
        assert [v["id"] for v in statuses[4]["vulns"]] == ["Y"] and "пропущено: 1" in statuses[4]["note"]
        assert statuses[5]["vulns"][0]["id"] == "Z" and "продолжение" in statuses[5]["note"]
        assert "пустым телом" in statuses[6]["note"] and "пустым телом" in statuses[7]["note"]
        done = db.research_run(run["id"])
        assert done["state"] == "done" and done["rows_saved"] == 8


def test_osv_request_obeys_the_admission_check(web):  # noqa: F811
    """Б2 круга 34: запрос OSV идёт под тем же допуском, что и обращение к модели – выключенный профиль останавливает
    получение до отправки в OSV (запроса нет), строка остаётся в очереди."""
    db = web.app.state.db
    pid, task = npm_project(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        profile = next(p for p in db.list_providers() if p["name"] == "Исследователь")
        with db._tx() as c:
            c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (profile["id"],))
        runner_for(web).run(run["id"])
        assert not [r for r in fake.requests if r["path"] == "/v1/query"] and not fake.chats()
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states[rows[0]["input_ref"]] == "queued"
        done = db.research_run(run["id"])
        assert done["state"] == "stopped" and "выключен" in done["reason"]


def test_osv_short_maven_name_is_unsupported_without_request(web):  # noqa: F811
    """В2 круга 34: короткое имя Maven (identity_kind short_name) – запроса в OSV нет, в первом сообщении
    status unsupported с причиной, шага «osv» в ходе строки нет, строка исследуется дальше."""
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run = start_run(web, fake, osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        assert rows[0]["identity_kind"] == "short_name"
        fake.answers += [_answer(osv_failed_row(rows[0], task)), _answer(osv_failed_row(rows[1], task))]
        runner_for(web).run(run["id"])
        assert not [r for r in fake.requests if r["path"] == "/v1/query"]
        message = _first_user_message(fake, rows[0]["input_ref"])
        assert message["osv"]["status"] == "unsupported" and "короткое имя" in message["osv"]["note"]
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and not [t for t in first["tools"] if t.get("tool") == "osv"]
        assert first["usage"].get("osv_calls", 0) == 0


def test_osv_request_alone_does_not_mark_the_row_unknown(web):  # noqa: F811
    """В1 круга 35: запрос OSV бесплатен и не считается отправкой провайдеру – если после успешного ответа OSV допуск
    к модели отклонён (профиль выключен), строка остаётся в очереди, а не «результат неизвестен»; получение
    останавливается, обращения к модели нет."""
    db = web.app.state.db
    pid, task = npm_project(web)
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        profile = next(p for p in db.list_providers() if p["name"] == "Исследователь")

        def osv_then_disable(_body):
            with db._tx() as c:
                c.execute("UPDATE llm_providers SET enabled = 0 WHERE id = ?", (profile["id"],))
            return {}
        fake.osv_answers += [osv_then_disable]
        runner_for(web).run(run["id"])
        assert len([r for r in fake.requests if r["path"] == "/v1/query"]) == 1 and not fake.chats()
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "queued" and "оплачен" not in (first["reason"] or "")
        assert first["usage"]["osv_calls"] == 1 and [t["tool"] for t in first["tools"]] == ["osv"]
        assert db.research_run(run["id"])["state"] == "stopped"
        # «Продолжить» с включённым профилем: второй запрос OSV и ход модели дописываются к прежней попытке, а не
        # заменяют её (В3 круга 36)
        with db._tx() as c:
            c.execute("UPDATE llm_providers SET enabled = 1 WHERE id = ?", (profile["id"],))
        db.resume_research_run(run["id"])
        fake.answers += [_answer(good_row(rows[0], task)), _answer(good_row(rows[1], task))]
        runner_for(web).run(run["id"])
        first = {r["input_ref"]: r for r in db.research_run_rows(run["id"])}[rows[0]["input_ref"]]
        assert first["state"] == "saved" and first["usage"]["osv_calls"] == 2 and first["usage"]["sends"] == 1
        assert [t["tool"] for t in first["tools"]] == ["osv", "osv"]
        done = db.research_run(run["id"])
        assert done["state"] == "done" and json.loads(done["usage_json"])["osv_calls"] == 3


def test_osv_address_round_trips_through_the_instructions(web):  # noqa: F811
    """М1 круга 35: адрес OSV, записанный в текст инструкций, читается обратно без искажений; без адреса – пусто."""
    for url in ("https://api.osv.dev", "http://127.0.0.1:8080", "https://osv.example.invalid:8443"):
        assert net.osv_url_from(net.instructions(True, url)) == url
        assert net.osv_url_from(net.instructions(False, url)) == url
    assert net.osv_url_from(net.instructions(True)) == "" and net.osv_url_from("") == ""
    assert "адрес запроса OSV" not in net.instructions(False) and "приложение его не делает" in net.instructions(False)
    assert "кроме OSV" not in net.instructions(False) and "кроме OSV" in net.instructions(False, "https://api.osv.dev")


def test_osv_outcome_overrides_the_coverage_claim(web):  # noqa: F811
    """Б1 кругов 38–39 (ADR-0112): после ошибки OSV модель назвала покрытие «ok, complete» (и под другим написанием
    источника) – приложение приводит запись к исходу запроса; без записи или при нестрогой форме названия (круг 49:
    «[OSV](https://osv.dev)» не переписывается) – добавляет свою; строка с применимой находкой сохраняется с первого
    ответа. Четыре получения по одной строке – четыре варианта ответа."""
    db = web.app.state.db
    pid, task = npm_project(web, ("zod",))
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        rows = manifest_rows(web, task)
        x = rows[0]["input_ref"]
        renamed = good_row(rows[0], task)
        renamed["research_coverage"][0]["source"] = "OSV.dev"
        without = good_row(rows[0], task)
        without["research_coverage"] = [c for c in without["research_coverage"] if c["source"] != "OSV"]
        expected_sources = []
        wrapped = good_row(rows[0], task)
        wrapped["research_coverage"][0]["source"] = "[OSV](https://osv.dev)"
        wrapped["research_coverage"].append({**good_row(rows[0], task)["research_coverage"][0], "source": "ProsVuln"})
        for answer, source in ((good_row(rows[0], task), "OSV"), (renamed, "OSV.dev"), (without, "OSV"),
                               (wrapped, "OSV")):  # круг 49: нестрогая форма не переписывается, запись OSV добавляется
            pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake), rows=[x])
            fake.osv_answers += [("http", 500, {"error": "boom"})]
            before = len(fake.chats())
            fake.answers += [_answer(answer)]
            runner_for(web).run(run["id"])
            assert len(fake.chats()) == before + 1, "строка принята с первого ответа: запись OSV приведена приложением"
            assert db.research_run(run["id"])["rows_saved"] == 1
            payload = db.research(pid)[x]["payload"]
            from app.sca_research_net import _osv_source
            recs = [c for c in payload["research_coverage"] if _osv_source(c["source"])]  # «ProsVuln» – не OSV
            assert len(recs) == 1 and recs[0]["status"] == "error" and recs[0]["complete"] is False
            assert "по данным приложения" in recs[0]["note"] and recs[0]["source"] == source
            if answer is wrapped:  # круг 49: обе чужие записи целы, своя запись OSV добавлена рядом
                kept = {c["source"]: c for c in payload["research_coverage"]}
                assert kept["[OSV](https://osv.dev)"]["status"] == "ok" and kept["[OSV](https://osv.dev)"]["complete"] is True
                assert kept["ProsVuln"]["status"] == "ok" and kept["ProsVuln"]["complete"] is True
            if answer is without:  # запись добавлена приложением – с координатами строки задания
                assert recs[0]["query"] == {"ecosystem": rows[0]["ecosystem"], "coordinates": rows[0]["component"], "version": rows[0]["version"]}
            expected_sources.append(recs[0]["source"])
        assert expected_sources == ["OSV", "OSV.dev", "OSV", "OSV"]
        foreign = [c for c in db.research(pid)[x]["payload"]["research_coverage"] if c["source"] == "ProsVuln"]
        assert foreign and foreign[0]["status"] == "ok" and foreign[0]["complete"] is True, "чужое покрытие не переписано"


def test_false_negative_after_osv_error_goes_to_the_correction_loop(web):  # noqa: F811
    """Б1: OSV не ответил, а модель заявила «уязвимостей нет» с полным покрытием OSV – после приведения покрытия
    валидатор пересчитывает статус строки (incomplete), ответ отвергается и исправляется; честный второй ответ
    сохраняется."""
    db = web.app.state.db
    pid, task = npm_project(web, ("zod", "lodash"))
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        fake.osv_answers += [{}, ("http", 500, {"error": "boom"})]
        claim = clean_row(rows[1], task, rows[0])
        assert claim["package_status"] == "no_known_vulnerabilities"
        honest = clean_row(rows[1], task, rows[0])
        for item in honest["research_coverage"]:
            if item["source"] == "OSV":
                item["status"], item["complete"], item["note"] = "error", False, "OSV: запрос не удался"
        honest["package_status"] = "incomplete"
        honest["gaps"] = [{"code": "COVERAGE_INCOMPLETE", "text": "OSV не ответил: точный запрос не выполнен"}]
        fake.answers += [_answer(good_row(rows[0], task)), _answer(claim), _answer(honest)]
        runner_for(web).run(run["id"])
        chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == rows[1]["input_ref"]]
        assert len(chats) == 2, (len(chats), [c["messages"][-1]["content"][:600] for c in chats[1:]])  # заявка отвергнута
        correction = chats[1]["messages"][-1]
        assert correction["role"] == "user" and "package_status" in correction["content"] and "incomplete" in correction["content"]
        states = {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}
        assert states == {rows[0]["input_ref"]: "saved", rows[1]["input_ref"]: "saved"}
        payload = db.research(pid)[rows[1]["input_ref"]]["payload"]
        assert payload["package_status"] == "incomplete"
        assert [c["status"] for c in payload["research_coverage"] if c["source"] == "OSV"] == ["error"]


def test_apply_osv_outcome_is_pure():
    """Приведение покрытия OSV: без ответа OSV и при ok/empty – без изменений; error/unsupported/partial – записи OSV
    (строго распознанное написание, круг 49) получают статус и complete false, без записи – запись добавляется; остальные записи не трогаются."""
    from app.sca_research_net import apply_osv_outcome
    row = {"ecosystem": "npm", "component": "zod", "version": "1.0.0"}
    answer = {"package_status": "no_known_vulnerabilities",
              "research_coverage": [{"source": "api.osv.dev", "status": "ok", "complete": True, "note": "ok"},
                                    {"source": "GitHub Advisory", "status": "ok", "complete": True}]}
    assert apply_osv_outcome(answer, row, None, "2026-10-26") == answer
    assert apply_osv_outcome(answer, row, {"status": "ok"}, "2026-10-26") == answer
    assert apply_osv_outcome(answer, row, {"status": "empty"}, "2026-10-26") == answer
    fixed = apply_osv_outcome(answer, row, {"status": "partial", "note": "показаны 40 из 60"}, "2026-10-26")
    assert fixed["research_coverage"][0] == {"source": "api.osv.dev", "status": "partial", "complete": False,
                                             "note": "ok; по данным приложения: ответ OSV – partial (показаны 40 из 60)"}
    assert fixed["research_coverage"][1] == answer["research_coverage"][1] and answer["research_coverage"][0]["status"] == "ok"
    added = apply_osv_outcome({"research_coverage": [{"source": "NVD", "status": "ok", "complete": True}]}, row,
                              {"status": "unsupported", "note": "короткое имя"}, "2026-10-26")
    assert added["research_coverage"][1] == {"source": "OSV", "purpose": "vulnerabilities",
                                             "query": {"ecosystem": "npm", "coordinates": "zod", "version": "1.0.0"},
                                             "source_refs": [], "checked_at": "2026-10-26", "status": "error", "complete": False,
                                             "note": "по данным приложения: ответ OSV – unsupported (короткое имя)"}
    # круг 40: запись OSV другого назначения не отменяет добавление записи «уязвимости»
    releases = {"research_coverage": [{"source": "OSV", "purpose": "releases", "status": "ok", "complete": True, "note": ""}]}
    both = apply_osv_outcome(releases, row, {"status": "error"}, "2026-10-26")["research_coverage"]
    assert [(c["purpose"], c["status"], c["complete"]) for c in both] == [("releases", "error", False), ("vulnerabilities", "error", False)]
    # посторонний источник с подстрокой «osv» не трогается; формы имени OSV распознаются
    foreign = {"research_coverage": [{"source": "ProsVuln", "purpose": "vulnerabilities", "status": "ok", "complete": True}]}
    out = apply_osv_outcome(foreign, row, {"status": "error"}, "2026-10-26")["research_coverage"]
    assert out[0] == foreign["research_coverage"][0] and out[1]["source"] == "OSV"
    from app.sca_research_net import _osv_source
    # круг 49: распознавание строгое – каждое слово либо слово названия OSV, либо адрес узла OSV, хотя бы одно – само OSV
    assert all(_osv_source(n) for n in ("OSV", "osv", "osv.dev", "api.osv.dev", "https://api.osv.dev/v1/query", "OSV (Google)", " OSV ",
                                        "Google OSV", "OSV.dev API", "osv.dev/vulnerability/GHSA-1", "https://api.osv.dev:443/v1/query",
                                        "https://osv.dev", "OSV database", "OSV (https://osv.dev)", "api.osv.dev API",
                                        "OSV, https://api.osv.dev/v1/query", "<https://osv.dev>", "OSV.dev,", "api.osv.dev?x=1", "osv.dev.",
                                        "https://osv.dev,", "https://api.osv.dev;", "`https://osv.dev`", "**OSV**", "//api.osv.dev/v1/query",
                                        "`OSV`", "OSV.", "https://osv.dev./", "https://osv.dev/?sources=nvd,osv", "_https://osv.dev_",
                                        "__https://osv.dev__", "~~https://osv.dev~~", "OSV:", "(https://api.osv.dev/v1/query)",
                                        "osv.dev/vulnerability/GHSA-1?x=1#top", "osv.dev/?u=https://example.invalid",
                                        "https://api.osv.dev/v1/query?u=//example.invalid", "example.invalid:443@osv.dev/",
                                        "https://user:pass@osv.dev:443/", "osv.dev:443/path", "HTTPS://API.OSV.DEV/v1/query", "OSV DB"))
    # чужие названия и адреса – никогда (узел только из authority; «osv» в пути, параметрах, userinfo и ссылках не считается)
    foreign_forms = ("ProsVuln", "NVD", "GitHub Advisory", "cosv", "osvx", "", "https://osv/v1/query", "https://api.osv/v1/query",
                     "https://osv.dev.example.invalid/", "Prosv Vuln", "osvdev", "osv.dev.example.invalid", "osv.dev.example.invalid/path",
                     "https://evil.invalid/osv.dev", "NVD (https://nvd.nist.gov)", "osv.dev.example.invalid?x=1",
                     "osv.dev.example.invalid#about", "osv.dev.example.invalid.", "[NVD](https://nvd.nist.gov/osv.dev)",
                     "//nvd.nist.gov/osv.dev", "https://example.invalid/?q=osv", "https://example.invalid/?q=*osv",
                     "(see https://example.invalid/osv)", "nvd.nist.gov/?u=https://osv.dev", "nvd.nist.gov/?u=//api.osv.dev/v1/query",
                     "[NVD](nvd.nist.gov/?q=osv)", "[NVD](https://nvd.nist.gov/?q=osv.dev)", "https://example.invalid/?q=https://osv.dev",
                     "[NVD database](https://nvd.nist.gov/?q=osv)", "[NVD](https://nvd.nist.gov/a(b)/osv)",
                     "_[NVD](https://nvd.nist.gov/?q=osv)_", "[NVD](https://nvd.nist.gov/?q= osv)", "[NVD](https://nvd.nist.gov/a(b)/osv",
                     "osv.dev:443@example.invalid/", "https://osv.dev@example.invalid/", "https://osv.dev@[::1]:443/", "[NVD](osv)",
                     "[NVD](http:osv.dev)", "[NVD]()", "[NVD [database]](https://nvd.nist.gov/?q=osv)", "[[NVD]](https://nvd.nist.gov/?q=osv)",
                     "[NVD](https://nvd.nist.gov/?q=\\)osv)", "https://nvd.nist.gov/?q=[OSV](x)", "NVD](https://nvd.nist.gov/?q=osv)",
                     "OSV[x](y)", "Google", "API database", "osv.dev,nvd.nist.gov", "http:osv.dev", "https://[::1]/osv")
    assert not any(_osv_source(n) for n in foreign_forms)
    # формы с OSV внутри, которые строгое распознавание не берёт: не переписываются, запись OSV добавляется рядом – безвредно
    loose_forms = ("[OSV](https://osv.dev)", "OSV(https://osv.dev)", "OSV/NVD", "OSV_DB", "osv-vulnerability-db", "см. OSV",
                   "[NVD](https://osv.dev)", "см. [OSV](https://osv.dev) и NVD")
    assert not any(_osv_source(n) for n in loose_forms)

    # круги 48–49: чужая или нестрогая запись с любой из этих форм сохраняется целиком, запись OSV добавляется рядом
    for source in foreign_forms + loose_forms:
        other = {"source": source, "purpose": "vulnerabilities", "status": "ok", "complete": True, "note": "чужая"}
        for outcome, forced in (("error", "error"), ("unsupported", "error"), ("partial", "partial")):  # круг 50: все исходы
            kept = apply_osv_outcome({"research_coverage": [other]}, row, {"status": outcome}, "2026-10-26")["research_coverage"]
            assert kept[0] == other and len(kept) == 2, (source, outcome)
            assert (kept[1]["source"], kept[1]["purpose"], kept[1]["status"], kept[1]["complete"]) == ("OSV", "vulnerabilities", forced, False)
    # координаты добавленной записи – как разрешила модель; research_coverage не список – не трогается
    resolved = apply_osv_outcome({"identity_resolution": {"coordinates": "org.example:demo-lib"}, "research_coverage": []},
                                 {"ecosystem": "maven", "component": "demo-lib", "version": "1.0"}, {"status": "unsupported"}, "2026-10-26")
    assert resolved["research_coverage"][0]["query"] == {"ecosystem": "maven", "coordinates": "org.example:demo-lib", "version": "1.0"}
    assert apply_osv_outcome({"research_coverage": 17}, row, {"status": "error"}, "2026-10-26")["research_coverage"] == 17
    # причина приложения не теряется при длинном note модели
    long_note = apply_osv_outcome({"research_coverage": [{"source": "OSV", "purpose": "vulnerabilities", "status": "ok", "complete": True,
                                                          "note": "x" * 1900}]}, row, {"status": "error"}, "2026-10-26")
    assert long_note["research_coverage"][0]["note"].endswith("по данным приложения: ответ OSV – error")


def test_later_saved_ignores_another_task_of_the_same_project(web):  # noqa: F811
    """В2 круга 38: успех по той же строке в другом задании того же проекта (состав перестроен) не делает строку
    прежнего получения «исследованной позже» – граница по task_id, не только по проекту."""
    from hub_fixtures import SCA_BASE, SCA_ROWS, make_hub_xlsx
    from test_web import upload
    import re
    db = web.app.state.db
    with FakeChatApi(models=["flash-model"]) as fake:
        pid, task, _consent, run_a = start_run(web, fake)
        rows = manifest_rows(web, task)
        x = rows[0]["input_ref"]
        fake.answers += [("drop",), _answer(good_row(rows[1], task))]
        runner_for(web).run(run_a["id"])
        assert {r["input_ref"]: r["state"] for r in db.research_run_rows(run_a["id"])}[x] == "unknown"
        page = web.client.get(f"/projects/{pid}/components/research/{run_a['id']}").text
        assert int(re.search(r'data-count="leftover">(\d+)<', page).group(1)) == 1 and "исследована позже" not in page
        # состав перестроен: новая выгрузка с третьим компонентом → новое задание того же проекта
        third = dict(SCA_BASE, **{"Issue id": "73019", "CVSS score": "7.5", "Component name": "demo-third",
                                  "Component version": "2.0.0", "CVE id": "CVE-2099-10019", "Non-vulnerable versions": "2.0.1",
                                  "CWE ID": "79", "CWE link": "https://cwe.mitre.org/data/definitions/79.html"})
        assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub-task2.xlsx", sast=(), sca=SCA_ROWS + [third])).status_code == 303
        build_task(web, pid)
        task2 = db.current_task(pid)
        assert task2["id"] != task["id"] and x in [r["input_ref"] for r in manifest_rows(web, task2)]
        _, _, _, run_e = start_run(web, fake, rows=[x], project=(pid, task2))
        fake.answers += [_answer(good_row(rows[0], task2))]
        runner_for(web).run(run_e["id"])
        assert db.research_run(run_e["id"])["rows_saved"] == 1 and run_e["id"] > run_a["id"]
        page = web.client.get(f"/projects/{pid}/components/research/{run_a['id']}").text
        assert int(re.search(r'data-count="leftover">(\d+)<', page).group(1)) == 1 and "исследована позже" not in page


def test_coverage_of_wrong_type_goes_to_the_validator_not_to_a_crash(web):  # noqa: F811
    """В1 круга 40: research_coverage не список при неудавшемся OSV – приведение не падает, валидатор отвергает ответ
    и цикл исправления продолжается; получение не прерывается."""
    db = web.app.state.db
    pid, task = npm_project(web, ("zod",))
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        fake.osv_answers += [("http", 500, {"error": "boom"})]
        broken = good_row(rows[0], task)
        broken["research_coverage"] = 17
        fake.answers += [_answer(broken), _answer(good_row(rows[0], task))]
        runner_for(web).run(run["id"])
        assert len(fake.chats()) == 2
        assert "research_coverage" in fake.chats()[1]["messages"][-1]["content"]
        assert db.research_run(run["id"])["state"] == "done" and db.research_run(run["id"])["rows_saved"] == 1


def test_osv_release_record_does_not_hide_the_vulnerabilities_gap(web):  # noqa: F811
    """Б1 круга 40: у модели запись OSV с назначением releases и чужая запись vulnerabilities «ok, complete», OSV не
    ответил, заявлено «уязвимостей нет» – приложение добавляет запись OSV/vulnerabilities, валидатор пересчитывает
    статус в incomplete, заявка отвергается."""
    db = web.app.state.db
    pid, task = npm_project(web, ("zod", "lodash"))
    with FakeChatApi(models=["flash-model"]) as fake:
        make_profile(web, fake)
        pid, task, _consent, run = start_run(web, fake, project=(pid, task), osv_url=osv_base(fake))
        rows = manifest_rows(web, task)
        fake.osv_answers += [{}, ("http", 500, {"error": "boom"})]
        claim = clean_row(rows[1], task, rows[0])
        for item in claim["research_coverage"]:
            if item["source"] == "OSV":
                item["purpose"] = "releases"
        claim["research_coverage"].append({**[c for c in claim["research_coverage"] if c["purpose"] == "releases"][0],
                                           "source": "GitHub Advisory", "purpose": "vulnerabilities"})
        fake.answers += [_answer(good_row(rows[0], task)), _answer(claim)]
        runner_for(web).run(run["id"])
        chats = [c for c in fake.chats() if json.loads(c["messages"][1]["content"])["row"]["input_ref"] == rows[1]["input_ref"]]
        assert len(chats) >= 2 and "package_status" in chats[1]["messages"][-1]["content"]
        assert {r["input_ref"]: r["state"] for r in db.research_run_rows(run["id"])}[rows[1]["input_ref"]] == "failed"
