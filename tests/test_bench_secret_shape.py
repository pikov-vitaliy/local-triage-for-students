"""Стенд меток маскирования (бэклог 101, план dev18): --prompt-version, --mask-shape, --secret-note и выдуманные случаи
CWE-259/CWE-798. Без флагов стенд даёт прежние сообщения и ключи; промпт и маскирование приложения не меняются."""

from __future__ import annotations

import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "scripts" / "bench"
KEY = b"bench-secret-shape-key-0123456789"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bc = _load("bench_build_cases_s", BENCH / "build_cases.py")
rb = _load("bench_run_bench_s", BENCH / "run_bench.py")


@pytest.fixture(scope="module")
def secret_cases(tmp_path_factory: pytest.TempPathFactory) -> list[dict]:
    out = tmp_path_factory.mktemp("bench-secrets")
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = bc.main(["--demo-only", "--secrets", "--out-dir", str(out)])
    assert code == 0, buf.getvalue()
    cases = json.loads((out / "cases.json").read_text(encoding="utf-8"))
    return [c for c in cases if c["source"] == "secrets"]


@pytest.fixture(scope="module")
def ns():
    return rb.load_app(ROOT)


def _prep(ns, case, **kw):
    settings = ns.config.Settings()
    runner = ns.triage.TriageRunner(None, settings, mask_key=KEY)
    options = ns.triage.model_options(settings.num_ctx)
    return rb.prepare(ns, runner, case, KEY, options, **kw), options


def test_secret_cases_build_and_both_answers(secret_cases):
    assert len(secret_cases) == 12
    answers = {c["expected"] for c in secret_cases}
    assert {"true_positive", "false_positive"} <= answers
    assert {c["cwe"] for c in secret_cases} == {"CWE-259", "CWE-798"}
    for c in secret_cases:
        text = (Path(c["repo_root"]) / c["file"]).read_text(encoding="utf-8")
        assert ">>>" not in text and text.split("\n")[c["line"] - 1].strip() == c["snippet"]


def _app_messages(ns, case):
    """Сообщения прямо конвейером приложения, без кода стенда: срез, промпт текущей версии, последнее маскирование."""
    settings = ns.config.Settings()
    runner = ns.triage.TriageRunner(None, settings, mask_key=KEY)
    f = ns.models.Finding(hub_id=str(case["id"]), kind="SAST", rule=case["rule"], cwe=[case["cwe"]],
                          codebase=case["codebase"], file=case["file"], line=case["line"], snippet=case["snippet"],
                          language=case["language"])
    ctx = ns.context.build_context(Path(case["repo_root"]), f, max_chars=ns.triage.CONTEXT_CHARS, mask_key=KEY)
    return runner._masked(ns.prompts.build_sast_messages(f, ctx, mask_key=KEY))


def test_without_flags_messages_and_keys_unchanged(ns, secret_cases):
    """Без флагов – сообщения как у приложения и прежние ключи журнала: сравнение с независимым построением, а не с
    кодом стенда (ревью Codex, 101, круг 1)."""
    import hashlib
    case = secret_cases[1]
    spec = ns.prompts.spec_for(None)
    new, options = _prep(ns, case, spec=spec, variant={"mask_shape": False, "secret_note": False})
    app_messages = _app_messages(ns, case)
    assert new.messages == app_messages
    assert rb.request_key(ns, "gpt-oss:20b", new, options, "low", spec.version) == \
        ns.prompts.request_key("gpt-oss:20b", app_messages, options, "low")
    # прежняя формула ключа параметров (до бэклога 101)
    old_payload = {"model": ns.llm.norm_model_name("gpt-oss:20b"), "think": "low",
                   "prompt_version": ns.prompts.PROMPT_VERSION,
                   "system_prompt": hashlib.sha256(ns.prompts.spec_for(None).system.encode("utf-8")).hexdigest(),
                   "options": {str(k): v for k, v in {**ns.llm.DEFAULT_OPTIONS, **options}.items()}}
    old_key = hashlib.sha256(json.dumps(old_payload, sort_keys=True, ensure_ascii=False, default=str)
                             .encode("utf-8")).hexdigest()[:16]
    assert rb.config_key(ns, "gpt-oss:20b", "low", options, spec, {"mask_shape": False, "secret_note": False}) == old_key
    assert rb.config_key(ns, "gpt-oss:20b", "low", options) == old_key
    assert rb.config_key(ns, "gpt-oss:20b", "low", options, spec, {"mask_shape": True, "secret_note": False}) != old_key


def test_mask_shape_uses_app_boundaries(ns, tmp_path):
    """Экранированная кавычка и многострочная строка: форма – по значению, которое замаскировало приложение (ревью
    Codex, 101, круг 1); после стенда маскирование приложения прежнее."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    source = ('import db\n\npassword = "abc\\"def12"\n'
              'PRIVATE = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MbmYQ8NW\n'
              '-----END RSA PRIVATE KEY-----"""\n\ndb.connect(password)\n')
    (repo / "app" / "conf.py").write_text(source, encoding="utf-8")
    case = {"id": "t-1", "rule": "Использование жестко закодированного пароля", "cwe": "CWE-259", "codebase": "x",
            "file": "app/conf.py", "line": 3, "snippet": 'password = "abc\\"def12"', "language": "Python",
            "repo_root": repo.as_posix()}
    shaped, _ = _prep(ns, case, spec=ns.prompts.spec_for(None), variant={"mask_shape": True})
    user = shaped.messages[1]["content"]
    import re as _re
    tags = _re.findall(r"<SECRET_[0-9a-f]{6}[^>]*>", user)
    assert len(tags) >= 2, user
    bare = [t for t in tags if "len=" not in t]
    assert not bare, f"метки без формы: {bare}"
    assert "len=10 chars=mixed>" in user, "экранированная кавычка – значение целиком, как у приложения"
    assert 'abc\\"def12' not in user and "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn" not in user
    assert ns.masking._Masker.placeholder.__name__ == "placeholder", "обёртка стенда снята"


def test_mask_shape_adds_form_not_value(ns, secret_cases):
    case = next(c for c in secret_cases if c["id"] == "sec-02")
    plain, _ = _prep(ns, case)
    shaped, _ = _prep(ns, case, spec=ns.prompts.spec_for(None), variant={"mask_shape": True})
    user = shaped.messages[1]["content"]
    assert "Wint3r-Is-C0ming!" not in user and "Wint3r-Is-C0ming!" not in plain.messages[1]["content"]
    assert "len=17 chars=mixed>" in user
    assert shaped.messages[0] == plain.messages[0], "системное сообщение – как у версии промпта"
    assert rb.value_shape("") == "len=0 chars=mixed" and rb.value_shape("a1Bz") == "len=4 chars=alnum"
    assert rb.value_shape("dead01") == "len=6 chars=hex"


def test_secret_note_only_in_system(ns, secret_cases):
    case = secret_cases[0]
    plain, _ = _prep(ns, case, spec=ns.prompts.spec_for("sast-v7"))
    noted, _ = _prep(ns, case, spec=ns.prompts.spec_for("sast-v7"), variant={"secret_note": True})
    assert plain.messages[0]["content"] == ns.prompts.spec_for("sast-v7").system
    assert noted.messages[0]["content"].endswith(rb.SECRET_NOTE)
    assert rb.SECRET_NOTE not in ns.prompts.SYSTEM_PROMPT_V7 and rb.SECRET_NOTE not in ns.prompts.SYSTEM_PROMPT
    assert noted.messages[1]["content"] == plain.messages[1]["content"]


def test_out_name_has_variant():
    args = rb.parse_args(["--model", "gpt-oss:20b", "--prompt-version", "sast-v7", "--secret-note"])
    assert rb.resolve_out(args, "gpt-oss:20b", "low", 4096).name.endswith("__sast-v7__secret-note.json")
    plain = rb.parse_args(["--model", "gpt-oss:20b"])
    assert rb.resolve_out(plain, "gpt-oss:20b", "low", 4096).name.endswith("__think-low__np4096.json")
