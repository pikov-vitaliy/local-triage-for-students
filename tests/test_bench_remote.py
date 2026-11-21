"""Стенд замера на внешнем провайдере (scripts/bench/run_bench_remote.py, В7): настоящий ChatCompletionsClient
приложения по https к поддельному серверу (tests/fake_chat_api.py), класс external с подменой правила адресов, как в
tests/test_llm_chat.py. Набор – демо-находки (build_cases.py --demo-only). Всё пишется во временную папку."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import socket
import ssl
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from app import llm_net
from fake_chat_api import CERTS, FakeChatApi

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "scripts" / "bench"
KEY = "sk-test-0123456789abcdef"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bc = _load("bench_build_cases_remote", BENCH / "build_cases.py")
rr = _load("bench_run_bench_remote", BENCH / "run_bench_remote.py")


@pytest.fixture(scope="module")
def cases_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bench-remote-cases")
    with redirect_stdout(io.StringIO()):
        assert bc.main(["--demo-only", "--out-dir", str(out)]) == 0
    return out / "cases.json"


@pytest.fixture
def external(monkeypatch):
    """Класс external на loopback: https, имя → 127.0.0.1, сертификат тестового центра, LLM_EXTERNAL=1, ключ в
    переменной окружения."""
    monkeypatch.setenv("LLM_EXTERNAL", "1")
    monkeypatch.setenv("BENCH_TEST_KEY", KEY)
    monkeypatch.setattr(llm_net, "in_container", lambda: False)
    monkeypatch.setattr(llm_net, "external_address_ok", lambda ip, hosts=None: str(ip) == "127.0.0.1")
    monkeypatch.setattr(llm_net, "_tls_context", lambda: ssl.create_default_context(cafile=str(CERTS / "ca.pem")))
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host == "external-test.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)
    monkeypatch.setattr(llm_net.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(rr.rb, "MASK_KEY_PATH", Path(monkeypatch_tmp(monkeypatch)) / "mask.key")


def monkeypatch_tmp(monkeypatch) -> str:
    import tempfile
    path = tempfile.mkdtemp(prefix="bench-remote-")
    return path


def answer_for(body: dict) -> dict:
    """Ответ модели sast-v7: цитата – строка срабатывания из запроса (как её видела модель)."""
    user = next(m["content"] for m in body["messages"] if m["role"] == "user")
    target = re.search(r"^>>\s*(\d+)\| (.*)$", user, re.M)
    quotes = [{"line": int(target.group(1)), "code": target.group(2).strip()}] if target else []
    return {"what_code_does": "Берёт параметр и передаёт дальше.", "data_flow": ["строка 1: значение"],
            "why": ["строка 1: значение приходит от пользователя"], "evidence_quotes": quotes,
            "missing_context": "Где вызывается метод.", "verdict": "true_positive", "confidence": 80,
            "summary": "Есть уязвимость.", "evidence_lines": [], "check_by_eye": ["строка 1: откуда значение"],
            "terms": [], "fix": "Проверять значение.", "hub_comment": "Подтверждено: значение без проверки.",
            "cwe_fit": "да"}


def run(cases_file: Path, server: FakeChatApi, out: Path, *extra: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = rr.main(["--cases", str(cases_file), "--url", server.url, "--key-env", "BENCH_TEST_KEY",
                        "--model", "test-model", "--thinking", "enabled", "--effort", "high", "--max-output", "4096",
                        "--context-window", "200000", "--out", str(out), *extra])
    return code, buf.getvalue()


def test_v7_run_sends_the_key_from_env_and_measures_quotes(cases_file, external, tmp_path):
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        code, text = run(cases_file, server, tmp_path / "v7.json", "--prompt-version", "sast-v7", "--limit", "3")
        assert code == 0, text
        bodies = server.chats()
        assert len(bodies) == 3 and all(h.get("Authorization") == f"Bearer {KEY}" for h in server.headers)
        assert bodies[0]["max_tokens"] == 4096 and bodies[0]["thinking"] == {"type": "enabled"}
        assert bodies[0]["reasoning_effort"] == "high"
        assert "evidence_quotes" in bodies[0]["messages"][0]["content"]
    result = json.loads((tmp_path / "v7.json").read_text(encoding="utf-8"))
    assert result["prompt_version"] == "sast-v7" and result["done"] == 3
    assert result["quotes"]["applicable"] and result["quotes"]["found_rate"] == 1.0
    assert result["quotes"]["missing_context_rate"] == 1.0
    journal = (tmp_path / "v7.jsonl").read_text(encoding="utf-8")
    attempts = [json.loads(x) for x in journal.splitlines() if '"type": "attempt"' in x]
    assert [a["event"] for a in attempts] == ["start", "done"] * 3
    assert KEY not in journal and KEY not in text
    assert result["attempts"]["answered"] == 3 and result["attempts"]["prompt_tokens"] == 3 * 120
    assert len(result["cases"]) == 3 and result["cases"][0]["code"]["sha"] and result["client_fingerprint"]


def test_refuses_without_llm_external_or_key(cases_file, external, tmp_path, monkeypatch):
    with FakeChatApi(tls=True) as server:
        monkeypatch.delenv("LLM_EXTERNAL")
        code, text = run(cases_file, server, tmp_path / "x.json", "--limit", "1")
        assert code == 1 and "LLM_EXTERNAL=1" in text
        monkeypatch.setenv("LLM_EXTERNAL", "1")
        monkeypatch.setenv("BENCH_TEST_KEY", "")
        code, text = run(cases_file, server, tmp_path / "x.json", "--limit", "1")
        assert code == 1 and "BENCH_TEST_KEY" in text
        assert server.chats() == []


def test_unknown_outcome_is_not_resent_without_the_flag(cases_file, external, tmp_path):
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        server.answers.append(("drop",))  # первый случай: соединение закрыто без ответа – исход неизвестен
        out = tmp_path / "u.json"
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2")
        assert code == 0, text
        assert len(server.chats()) == 2
        first = json.loads(out.read_text(encoding="utf-8"))["unknown_outcome"]
        assert len(first) == 1
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2")
        assert code == 0 and len(server.chats()) == 2, "неизвестный исход не отправляется заново сам"
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2", "--resend-unknown")
        assert code == 0 and len(server.chats()) == 3
        assert json.loads(out.read_text(encoding="utf-8"))["unknown_outcome"] == []


def test_sent_without_a_record_counts_as_unknown(cases_file, external, tmp_path):
    """Прерывание между отправкой и записью: «отправка начата» без записи случая – при продолжении не отправляется."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "s.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
        journal = out.with_suffix(".jsonl")
        lines = [json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines() if x.strip()]
        kept = [x for x in lines if x.get("type") != "case"]  # как если бы процесс оборвался до записи случая
        journal.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in kept), encoding="utf-8")
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")
        assert code == 0 and len(server.chats()) == 1
        assert len(json.loads(out.read_text(encoding="utf-8"))["unknown_outcome"]) == 1


def test_other_prompt_version_on_the_same_journal_stops_before_sending(cases_file, external, tmp_path):
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "c.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v6", "--limit", "1")
        assert code == 2 and "другими параметрами" in text and len(server.chats()) == 1


def test_v6_run_has_no_quote_metrics(cases_file, external, tmp_path):
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: {k: v for k, v in answer_for(body).items()
                                              if k not in ("evidence_quotes", "missing_context")}
        out = tmp_path / "v6.json"
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v6", "--limit", "2")
        assert code == 0, text
        assert "evidence_quotes" not in server.chats()[0]["messages"][0]["content"]
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["quotes"] == {"applicable": False} and result["metrics"]["correct"] >= 0


@pytest.mark.parametrize("status,code", [(401, 6), (403, 6), (402, 7)])
def test_key_and_payment_errors_stop_the_run(cases_file, external, tmp_path, status, code):
    """401 и 403 – ключ, 402 – баланс: запуск останавливается на первом таком ответе, а не превращает весь набор в
    серию одинаковых отказов."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = ("http", status, {"error": {"message": "no"}})
        got, text = run(cases_file, server, tmp_path / f"{status}.json", "--prompt-version", "sast-v7", "--limit", "3")
        assert got == code and len(server.chats()) == 1, text


def test_accepted_answer_cut_by_the_limit_is_counted(cases_file, external, tmp_path):
    """Целый JSON при finish_reason=length клиент принимает – попытка всё равно отмечена как оборванная по пределу."""
    from fake_chat_api import chat_reply
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: ("message", {"role": "assistant",
                                                          "content": json.dumps(answer_for(body), ensure_ascii=False)},
                                              "length")
        out = tmp_path / "len.json"
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")
        assert code == 0, text
        assert chat_reply  # формат ответа поддельного сервера – общий
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["attempts"]["finish_length"] >= 1


def test_compare_runs_reports_transitions_and_comparability(cases_file, external, tmp_path):
    cr = _load("bench_compare_runs", BENCH / "compare_runs.py")
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: {k: v for k, v in answer_for(body).items()
                                              if k not in ("evidence_quotes", "missing_context")}
        assert run(cases_file, server, tmp_path / "v6.json", "--prompt-version", "sast-v6", "--limit", "3")[0] == 0
        server.default_answer = lambda body: {**answer_for(body), "verdict": "false_positive"}
        assert run(cases_file, server, tmp_path / "v7.json", "--prompt-version", "sast-v7", "--limit", "3")[0] == 0
    a = json.loads((tmp_path / "v6.json").read_text(encoding="utf-8"))
    b = json.loads((tmp_path / "v7.json").read_text(encoding="utf-8"))
    result = cr.compare(a, b)
    assert result["differs"] == [], "различается только версия промпта"
    assert sum(result["transitions"].values()) == 3 and result["changed"], result
    assert set(result["codes"]) <= {"тот же", "срез меньше", "код другой"}
    text = cr.markdown(a, b, result)
    assert "| Точность |" in text and "sast-v6" in text and "sast-v7" in text and "Цитаты найдены в коде" in text
    other = {**b, "model": "другая"}
    assert "модель" in cr.compare(a, other)["differs"]


# ============================================================================ ревью Codex, круг 22

def test_new_attempt_after_an_old_record_is_unknown(cases_file, external, tmp_path):
    """Находка 1: случай записан (R1), затем начата новая отправка и оборвалась до записи – при продолжении это
    неизвестный исход, а не повод отправить ещё раз."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "r.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
        journal = out.with_suffix(".jsonl")
        lines = [json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines() if x.strip()]
        case = next(x for x in lines if x.get("type") == "case")
        extra = {"type": "attempt", "event": "start", "config_key": case["config_key"], "id": case["id"],
                 "request_key": "другой-запрос", "n": 1}
        with journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(extra, ensure_ascii=False) + "\n")
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1", "--retry-errors")
        assert code == 0 and len(server.chats()) == 1, text
        assert json.loads(out.read_text(encoding="utf-8"))["unknown_outcome"] == [case["id"]]


def test_stopped_case_is_sent_again_after_the_key_is_fixed(cases_file, external, tmp_path):
    """Находка 4: после 401 случай записан как «остановлен», и продолжение той же командой отправляет его снова."""
    with FakeChatApi(tls=True) as server:
        server.answers.append(("http", 401, {"error": {"message": "bad key"}}))
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "k.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2")[0] == 6
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2")
        assert code == 0 and len(server.chats()) == 3, text
        result = json.loads(out.read_text(encoding="utf-8"))
        assert result["unknown_outcome"] == [] and {c["status"] for c in result["cases"]} == {"ok"}


def test_attempt_log_survives_a_malformed_answer(tmp_path):
    """Находка 5: ответ с неверной структурой записывается как есть, счётчики не числом – «неизвестно», не падение."""
    class Client:
        def _request(self, path, payload=None, *a, **kw):
            return {"choices": [1], "usage": {"prompt_tokens": "unknown", "completion_tokens": 7}}
    journal = rr.rb.Journal(tmp_path / "j.jsonl")
    client = Client()
    log = rr.AttemptLog(client, journal, "cfg")
    log.case = {"id": "1", "request_key": "k", "attempts": 0, "sent": 0, "finishes": []}
    client._request("/chat/completions", {"x": 1})
    journal.close()
    records = [json.loads(x) for x in (tmp_path / "j.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["event"] for r in records] == ["start", "done"] and records[1]["finish_reason"] is None
    summary = rr.attempts_summary(records)
    assert summary["completion_tokens"] == 7 and summary["usage_invalid"] == 1 and "prompt_tokens" not in summary


def test_unknown_outcome_stays_in_the_case_table(cases_file, external, tmp_path):
    """Находка 7: неизвестный исход – строка таблицы и «нет ответа» в метриках цитат, а не пропажа."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        server.answers.append(("drop",))
        out = tmp_path / "t.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "2")[0] == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(c["status"] for c in result["cases"]) == ["ok", "unknown"]
    assert result["quotes"]["applicable"] and result["quotes"]["no_answer"] == 1


def test_dry_run_writes_nothing(cases_file, external, tmp_path, monkeypatch):
    """Находка 8: --dry-run без ключа стенда его не создаёт."""
    key = tmp_path / "fresh" / "mask.key"
    monkeypatch.setattr(rr.rb, "MASK_KEY_PATH", key)
    with FakeChatApi(tls=True) as server:
        code, text = run(cases_file, server, tmp_path / "d.json", "--prompt-version", "sast-v7", "--limit", "2",
                         "--dry-run")
        assert code == 0 and server.chats() == [], text
    assert not key.exists() and not (tmp_path / "d.jsonl").exists()


def test_compare_flags_an_implementation_change_inside_a_run():
    cr = _load("bench_compare_runs_22", BENCH / "compare_runs.py")
    base = {"cases": [], "metrics": {}, "app_fingerprints_used": ["a"], "complete": True, "last_stop": "done"}
    assert cr.compare(base, {**base, "app_fingerprints_used": ["a", "b"]})["differs"] == [
        "реализация менялась внутри второго прогона"]


# ============================================================================ ревью Codex, круг 23

def test_pending_attempt_replaces_the_old_answer_in_the_result(cases_file, external, tmp_path):
    """Находка 1: после новой незавершённой попытки в итоге – «неизвестен», а не прежний верный ответ."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "p.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
        journal = out.with_suffix(".jsonl")
        case = next(json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines() if '"type": "case"' in x)
        with journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "attempt", "event": "start", "config_key": case["config_key"],
                                 "id": case["id"], "request_key": "новый", "n": 1}, ensure_ascii=False) + "\n")
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert [c["status"] for c in result["cases"]] == ["unknown"] and result["metrics"]["correct"] == 0


def test_stopped_case_is_not_a_result_and_the_pair_is_incomplete(cases_file, external, tmp_path):
    """Находка 2: остановка на 401 – не «неверный ответ»: случай ждёт продолжения, прогон неполный, сравнение
    это говорит."""
    cr = _load("bench_compare_runs_23", BENCH / "compare_runs.py")
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        assert run(cases_file, server, tmp_path / "a.json", "--prompt-version", "sast-v7", "--limit", "2")[0] == 0
        server.answers += [answer_for, ("http", 401, {"error": {"message": "bad key"}})]
        assert run(cases_file, server, tmp_path / "b.json", "--prompt-version", "sast-v7", "--limit", "2")[0] == 6
    b = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert b["done"] == 1 and not b["complete"] and len(b["waiting"]) == 1
    assert b["metrics"]["known"] == 1, "остановленный случай в знаменатель точности не входит"
    a = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))
    assert any("неполный" in d for d in cr.compare(a, b)["differs"])


def test_partial_usage_is_marked_incomplete():
    """Находка 4: у ответа нет поля prompt_tokens – расход помечен неполным, а не молча меньше."""
    records = [{"type": "attempt", "event": "done", "usage": {"prompt_tokens": 100, "completion_tokens": 5}},
               {"type": "attempt", "event": "done", "usage": {"completion_tokens": 7}}]
    summary = rr.attempts_summary(records)
    assert summary["prompt_tokens"] == 100 and summary["usage_missing"] == 1 and not summary["usage_complete"]
    cr = _load("bench_compare_runs_23b", BENCH / "compare_runs.py")
    assert cr.tokens({"attempts": summary}, "prompt_tokens") == "100 (неполно)"
    full = rr.attempts_summary(records[:1])
    assert full["usage_complete"] and cr.tokens({"attempts": full}, "prompt_tokens") == "100"


def test_retries_and_length_feed_the_common_metrics(cases_file, external, tmp_path):
    """Находка 5: повтор после 429 и принятый ответ, оборванный по пределу, – в общих метриках стенда."""
    with FakeChatApi(tls=True) as server:
        server.answers += [("http", 429, {"error": {"message": "slow down"}}, {"Retry-After": "0"}),
                           lambda body: ("message", {"role": "assistant",
                                                     "content": json.dumps(answer_for(body), ensure_ascii=False)},
                                         "length")]
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "m.json"
        code, text = run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")
        assert code == 0, text
    m = json.loads(out.read_text(encoding="utf-8"))["metrics"]
    assert m["retried"] == 1 and m["hit_length"] == 1


def test_bad_arguments_exit_with_code_one(cases_file, tmp_path):
    """Находка 7: ошибка аргументов – код 1; код 2 – только журнал с другими параметрами."""
    with redirect_stdout(io.StringIO()):
        assert rr.main(["--cases", str(cases_file), "--url", "https://x.example", "--key-env", "K", "--model", "m",
                        "--max-output", "0"]) == 1
        assert rr.main(["--model", "m"]) == 1


# ============================================================================ ревью Codex, круг 24

def test_unpriced_attempt_makes_spend_incomplete():
    """Обрыв после отправки (расход неизвестен), потом повтор с полным usage – общий расход всё равно неполон;
    незакрытая попытка – тоже."""
    after_drop = [{"event": "start", "id": "1", "n": 1}, {"event": "error", "id": "1", "n": 1, "sent": True},
                  {"event": "start", "id": "1", "n": 1, "request_key": "k2"},
                  {"event": "done", "id": "1", "n": 1, "request_key": "k2",
                   "usage": {"prompt_tokens": 10, "completion_tokens": 2}}]
    summary = rr.attempts_summary(after_drop)
    assert summary["unpriced_attempts"] == 1 and not summary["usage_complete"]
    hanging = rr.attempts_summary([{"event": "start", "id": "2", "n": 1}])
    assert hanging["unpriced_attempts"] == 1 and not hanging["usage_complete"]
    clean = rr.attempts_summary(after_drop[2:])
    assert clean["unpriced_attempts"] == 0 and clean["usage_complete"]


def test_restored_unknown_keeps_a_known_cut_by_the_limit(cases_file, external, tmp_path):
    """Ответ с finish_reason=length записан, затем прерывание до записи случая: в итоге случай «неизвестен», но
    обрыв по пределу в общих метриках виден."""
    with FakeChatApi(tls=True) as server:
        server.default_answer = lambda body: answer_for(body)
        out = tmp_path / "h.json"
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
        journal = out.with_suffix(".jsonl")
        case = next(json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines() if '"type": "case"' in x)
        base = {"type": "attempt", "config_key": case["config_key"], "id": case["id"], "request_key": "новый", "n": 1}
        with journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({**base, "event": "start"}, ensure_ascii=False) + "\n")
            fh.write(json.dumps({**base, "event": "done", "finish_reason": "length",
                                 "usage": {"prompt_tokens": 1, "completion_tokens": 1}}, ensure_ascii=False) + "\n")
        assert run(cases_file, server, out, "--prompt-version", "sast-v7", "--limit", "1")[0] == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["cases"][0]["status"] == "unknown" and result["metrics"]["hit_length"] == 1
