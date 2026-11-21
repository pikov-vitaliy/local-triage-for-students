"""Стенд замера моделей (scripts/bench) без видеокарты и без OWASP Benchmark.

Набор собирается из демо-находок (build_cases.py --demo-only). У клиента Ollama подменён только HTTP-слой
(_request), поэтому chat_json (повтор, проверка формата) и разбор вердикта работают настоящие. Сводка проверяется
и на итогах прогона, и на маленьком выдуманном итоге. Всё пишется во временную папку.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from app import context, llm

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "scripts" / "bench"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bc = _load("bench_build_cases", BENCH / "build_cases.py")
rb = _load("bench_run_bench", BENCH / "run_bench.py")
sm = _load("bench_summary", BENCH / "summary.py")
mm = _load("bench_make_modelfile", BENCH / "make_modelfile.py")

GOOD = {
    "what_code_does": "Берёт параметр запроса и передаёт дальше.",
    "data_flow": ["строка 1: значение из запроса"],
    "why": ["строка 1: значение приходит от пользователя без проверки"],
    "verdict": "true_positive", "confidence": 80, "summary": "Есть уязвимость.",
    "evidence_lines": [1], "check_by_eye": ["строка 1: откуда значение"], "terms": [],
    "fix": "Проверять значение перед использованием.", "hub_comment": "Подтверждено: значение без проверки.",
    "cwe_fit": "да",
}
# ответ поддельной модели по номеру демо-находки: вердикт и уверенность или особый сценарий
PLAN = {
    "100101": ("true_positive", 90),     # задумано TP – верно
    "100102": ("uncertain", 40),         # задумано FP, допустимо «неясно» (also_ok) – верно
    "100103": "bad_once",                # не по формату, повтор – TP, верно
    "100104": "truncated",               # оборван по num_predict – не разобран
    "100105": "bad_twice",               # дважды не по формату – не разобран
    "100106": ("false_positive", 95),    # задумано TP – пропуск уязвимости, уверенно
    "100107": ("false_positive", 70),    # задумано FP – верно
    "100115": ("uncertain", 30),         # задумано «неясно» – верно
}


@pytest.fixture(scope="module")
def cases_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bench-cases")
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = bc.main(["--demo-only", "--out-dir", str(out)])
    assert code == 0, buf.getvalue()
    return out / "cases.json"


class FakeClient(llm.OllamaClient):
    def __init__(self, url, timeout=900, scenario=None, by_place=None):
        super().__init__(url, timeout)
        self.s = scenario if scenario is not None else {}
        self.s.setdefault("chat_calls", 0)
        self.s.setdefault("seen", {})
        self.by_place = by_place or {}

    def _request(self, path, payload=None, timeout=10.0):
        model = self.s["model"]
        if path == "/api/version":
            return {"version": "0.0-test"}
        if path == "/api/tags":
            return {"models": [{"name": model, "model": model, "size": 13 * 1024 ** 3, "digest": "0123456789abcdef",
                                "details": {"family": self.s.get("family", "gptoss"), "parameter_size": "20.9B",
                                            "quantization_level": "MXFP4"}}]}
        if path == "/api/show":
            return {"details": {"family": self.s.get("family", "gptoss")}, "digest": "0123456789abcdef"}
        if path == "/api/ps":
            if self.s["chat_calls"] == 0:
                return {"models": []}
            return {"models": [{"name": model, "size": 14 * 1024 ** 3, "size_vram": 14 * 1024 ** 3,
                                "context_length": 16384}]}
        if path == "/api/chat":
            self.s["chat_calls"] += 1
            self.s["think"] = payload.get("think", "(нет)")
            user = payload["messages"][1]["content"]
            file = re.search(r"^Файл: (.+)$", user, re.M)
            line = re.search(r"^Строка срабатывания: (\d+)$", user, re.M)
            cid = self.by_place.get((file.group(1) if file else "", line.group(1) if line else ""))
            plan = PLAN.get(cid, ("true_positive", 60))
            attempt = self.s["seen"].get(cid, 0) + 1
            self.s["seen"][cid] = attempt
            stats = {"eval_count": 400, "eval_duration": int(2.5e9), "prompt_eval_count": 3000,
                     "prompt_eval_duration": int(0.5e9), "load_duration": int(1e8), "done_reason": "stop"}
            if plan == "bad_twice" or (plan == "bad_once" and attempt % 2 == 1):
                return {"message": {"content": "Думаю, это уязвимость."}, **stats}
            if plan == "truncated":
                return {"message": {"content": '{"what_code_does": "Берёт'}, **{**stats, "done_reason": "length"}}
            verdict, confidence = plan if isinstance(plan, tuple) else ("true_positive", 60)
            answer = dict(GOOD, verdict=verdict, confidence=confidence)
            if verdict == "false_positive":
                answer["fix"] = ""
                answer["hub_comment"] = "Ложное срабатывание: значение постоянное."
            return {"message": {"content": json.dumps(answer, ensure_ascii=False)}, **stats}
        raise AssertionError(path)


@pytest.fixture
def bench_run(cases_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Запуск run_bench.main с поддельной Ollama: ключ маскирования и итоги – во временной папке."""
    monkeypatch.setattr(rb, "MASK_KEY_PATH", tmp_path / "mask.key")
    monkeypatch.setattr(rb, "RESULTS_DIR", tmp_path / "runs")
    monkeypatch.setattr(rb, "WAIT_POLL_S", 0.05)
    cases = json.loads(cases_file.read_text(encoding="utf-8"))
    by_place = {(c.get("hub_file") or c["file"], str(c["line"])): str(c["id"]) for c in cases}

    def run(args: list[str], scenario: dict) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rb.main(["--cases", str(cases_file), "--url", "http://127.0.0.1:9", *args],
                           client_factory=lambda url, timeout=900: FakeClient(url, timeout, scenario, by_place))
        return code, buf.getvalue()

    return run


# ============================================================================ сборщик набора

def test_demo_only_set(cases_file: Path) -> None:
    cases = json.loads(cases_file.read_text(encoding="utf-8"))
    meta = json.loads((cases_file.parent / "cases_meta.json").read_text(encoding="utf-8"))
    assert len(cases) == 15 and {c["source"] for c in cases} == {"demo"}
    assert sum(c["language"] == "Python" for c in cases) == 5
    assert [c["expected"] for c in cases].count("uncertain") == 1
    assert meta["owasp"] is None and meta["problems"] == []


def test_selection_file_has_no_answers() -> None:
    data = json.loads((BENCH / "owasp-selection.json").read_text(encoding="utf-8"))
    tests = data["tests"]
    assert len(tests) == len(data["categories"]) * data["per_group"] * 2
    assert all(set(t) == {"id", "category"} for t in tests)
    assert [t["id"] for t in tests] == sorted(t["id"] for t in tests)
    assert re.fullmatch(r"[0-9a-f]{40}", data["commit"])


def _invented_rows() -> list[dict]:
    rows, n = [], 0
    for category in bc.CATEGORIES:
        for real in (True, False, True, False, True, False, True, False, True, False, True, False):
            n += 1
            rows.append({"name": f"BenchmarkTest{n:05d}", "category": category, "real": real, "cwe": 89})
    return rows


def test_selection_rule_and_check(tmp_path: Path) -> None:
    csv_text = "# test name, category, real vulnerability, cwe\n" + "".join(
        f"{r['name']},{r['category']},{'true' if r['real'] else 'false'},{r['cwe']}\n" for r in _invented_rows())
    (tmp_path / "expected.csv").write_text(csv_text, encoding="utf-8")
    rows = bc.read_expected(tmp_path, "expected.csv")
    picked = bc.select(rows)
    assert len(picked) == len(bc.CATEGORIES) * bc.PER_GROUP * 2
    first = [r for r in picked if r["category"] == bc.CATEGORIES[0]]
    assert [r["real"] for r in first] == [True] * bc.PER_GROUP + [False] * bc.PER_GROUP
    tests = [{"id": r["name"], "category": r["category"]} for r in picked]
    assert bc.check_selection(picked, tests) == []
    tests[0] = {"id": "BenchmarkTest99999", "category": tests[0]["category"]}
    problems = bc.check_selection(picked, tests)
    assert len(problems) == 2 and any("BenchmarkTest99999" in p for p in problems)


def test_find_sink_skips_comments() -> None:
    java = ("package org.example;\n"
            "public class T {\n"
            "    public void doPost(Object request) {\n"
            "        String q = \"SELECT 1\";\n"
            "        // st.executeQuery(bad);\n"
            "        java.sql.Statement st = conn.createStatement();\n"
            "        st.executeQuery(q);\n"
            "    }\n"
            "}\n")
    assert bc.find_sink(context, java, "sqli")[:2] == (7, "pattern")
    assert bc.find_sink(context, java, "weakrand")[:2] == (3, "fallback")


def test_builder_writes_only_to_results() -> None:
    with pytest.raises(bc.BuildError):
        bc.check_out_dir(ROOT / "docs", ROOT)
    bc.check_out_dir(ROOT / "results" / "bench", ROOT)
    assert rb.forbidden(ROOT / "app" / "x.json", ROOT)
    assert not rb.forbidden(ROOT / "results" / "bench" / "x.json", ROOT)


def test_builder_needs_source() -> None:
    with pytest.raises(SystemExit):
        bc.parse_args([])


# ============================================================================ прогон

def test_run_metrics_and_resume(bench_run, tmp_path: Path) -> None:
    out = tmp_path / "runs" / "fake.json"
    base = ["--model", "gpt-oss:fake", "--ids", ",".join(PLAN), "--out", str(out)]
    scenario = {"model": "gpt-oss:fake"}
    code, text = bench_run(base, scenario)
    assert code == 0, text
    res = json.loads(out.read_text(encoding="utf-8"))
    m = res["metrics"]
    assert res["done"] == 8 and res["complete"] and not res["full_set"]
    assert res["think"] == "low" and scenario["think"] == "low"
    assert res["app_version"] and res["prompt_version"]
    assert (m["correct"], m["known"]) == (5, 8)
    assert m["tp_as_fp"] == 1 and m["confidence_flip_mean"] == 95
    assert m["parse_errors"] == 2 and m["truncated"] == 1 and m["retried"] == 1
    assert abs(m["tps"] - 160.0) < 0.01
    journal = [json.loads(x) for x in out.with_suffix(".jsonl").read_text(encoding="utf-8").splitlines() if x]
    assert sum(1 for x in journal if x["type"] == "case") == 8

    # повторный запуск той же командой – всё из журнала, модель не вызывается
    again = {"model": "gpt-oss:fake"}
    code, _ = bench_run(base, again)
    assert code == 0 and again["chat_calls"] == 0

    # другой режим рассуждений в тот же журнал – отказ (код 2)
    code, _ = bench_run(base + ["--think", "medium"], {"model": "gpt-oss:fake"})
    assert code == 2


def test_think_override_for_any_model(bench_run, tmp_path: Path) -> None:
    scenario = {"model": "qwen-fake:14b", "family": "qwen2"}
    code, _ = bench_run(["--model", "qwen-fake:14b", "--think", "false", "--ids", "100101"], scenario)
    assert code == 0 and scenario["think"] is False
    assert (tmp_path / "runs" / "qwen-fake_14b__think-false__np3072.json").is_file()


def test_dry_run_calls_no_model(bench_run, tmp_path: Path) -> None:
    scenario = {"model": "gpt-oss:fake"}
    code, text = bench_run(["--model", "gpt-oss:fake", "--dry-run", "--show", "100109"], scenario)
    assert code == 0, text
    assert scenario["chat_calls"] == 0
    assert "Замечаний нет." in text and "секрет скрыт" in text
    assert not (tmp_path / "runs").exists()


def test_out_inside_app_refused(bench_run) -> None:
    code, _ = bench_run(["--model", "gpt-oss:fake", "--ids", "100101", "--out", str(ROOT / "docs" / "x.json")],
                        {"model": "gpt-oss:fake"})
    assert code == 1


# ============================================================================ сводка

def _result(model: str, correct: int, known: int, full: bool, median: float, version: str) -> dict:
    return {
        "model": model, "think": "low", "num_predict": 3072, "done": known, "selected": known, "complete": True,
        "full_set": full, "cases_total": 10, "prompt_version": "sast-v3", "app_version": version,
        "app_fingerprint": "f1", "cases_sha256": "c" * 64, "options": {"num_ctx": 16384},
        "correct_rule": "Верный ответ – вердикт совпал с ожидаемым или входит в also_ok.",
        "metrics": {"correct": correct, "known": known, "accuracy": correct / known, "tp": 5, "tp_correct": 4,
                    "fp": 5, "fp_correct": correct - 4, "answered": known, "uncertain_answers": 0, "tp_as_fp": 1,
                    "fp_as_tp": 1, "confidence_wrong_mean": 90, "time_median_s": median, "time_mean_s": median,
                    "tps": 100, "parse_errors": 0, "model_calls": known, "truncated": 0},
        "by_source": {}, "by_hint": {}, "by_category": {"sqli": {"correct": correct, "known": known}},
        "gpu": {},
    }


def test_summary_on_invented_results(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "a.json").write_text(json.dumps(_result("model-a", 6, 10, True, 3.0, "0.3.5")), encoding="utf-8")
    (runs / "b.json").write_text(json.dumps(_result("model-b", 9, 10, True, 5.0, "0.3.5")), encoding="utf-8")
    (runs / "c.json").write_text(json.dumps(_result("model-c", 4, 4, False, 1.0, "0.3.4")), encoding="utf-8")
    (runs / "broken.json").write_text("{", encoding="utf-8")
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert sm.main(["--results", str(runs), "--out", str(tmp_path / "summary.md")]) == 0
    table = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert table.index("| 1 | model-b |") < table.index("| 2 | model-a |") < table.index("| 3 | model-c * |")
    assert "90,0 % (9/10)" in table
    assert "broken.json: не прочитан" in table
    assert "разными версиями приложения" in table


# ============================================================================ Modelfile

def test_modelfile_transform() -> None:
    source = ("# Modelfile generated by ollama show\n"
              "FROM /blobs/sha256-weights\n"
              "FROM /blobs/sha256-projector\n"
              'TEMPLATE """{{ .Prompt }}\n'
              '{{ .Response }}"""\n'
              "PARAMETER stop <|im_end|>\n"
              "PARAMETER temperature 1\n"
              "PARAMETER repeat_last_n 64\n")
    spec = {"keep_projector": False, "renderer": "qwen3.5", "parser": "qwen3.5",
            "parameters": {"num_ctx": 16384, "temperature": 0.7}}
    text, dropped = mm.transform(source, spec)
    assert text.splitlines() == ["FROM /blobs/sha256-weights", "PARAMETER repeat_last_n 64", "RENDERER qwen3.5",
                                 "PARSER qwen3.5", "PARAMETER num_ctx 16384", "PARAMETER temperature 0.7"]
    assert dropped == ["FROM /blobs/sha256-projector"]
    kept, dropped = mm.transform(source, {**spec, "keep_projector": True})
    assert "FROM /blobs/sha256-projector" in kept and dropped == []


def test_models_json_is_complete() -> None:
    models = json.loads((BENCH / "modelfiles" / "models.json").read_text(encoding="utf-8"))["models"]
    assert {"qwen36-a3b-iq3", "qwen38-27b-iq3"} <= set(models)
    for spec in models.values():
        assert spec["source"] and spec["renderer"] and spec["parser"]
