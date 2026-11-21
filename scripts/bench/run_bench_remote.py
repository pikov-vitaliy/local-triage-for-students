"""Стенд замера на внешнем провайдере по API чат-завершений (В7, 0.9.15): тот же эталонный набор, что у run_bench.py,
вызов – клиентом приложения ChatCompletionsClient (класс доверия external), версия промпта задаётся явно
(--prompt-version sast-v6 | sast-v7). Описание, метрики и ограничения – docs/model-benchmark.md, раздел «Внешний
провайдер»; сравнение двух итогов (v6 и v7) – compare_runs.py.

Запускает владелец: это платные запросы с его ключом. Ключ – только из переменной окружения (--key-env ИМЯ), из папки
данных приложения стенд ключ не читает и никуда не пишет; LLM_EXTERNAL=1 – как у приложения: без неё внешний запрос
не уходит. Вне контейнера действуют все проверки адреса приложения (только https, только публичный адрес).

Подготовка случая – app.context.build_context с ключом маскирования стенда, prompts.build_sast_messages выбранной
версии, второй проход маскирования TriageRunner._masked; подгонка среза под окно – как в прогоне с удалённым
исполнителем (executors.fit_options за вычетом схемы ответа, json_overhead; длина – по JSON сообщений, prompt_size;
наименьший срез MIN_CONTEXT_CHARS тоже пробуется). Цитаты sast-v7 сверяются с кодом окончательного запроса
(prompts.shown_code по тому же срезу).

Журнал <out>.jsonl – каждая HTTP-отправка отдельно (обёртка над client._request: повтор после 429 и исправление
формата – отдельные отправки): до отправки – «попытка начата» (fsync; не записалась – отправка не начинается, запуск
останавливается), после – «ответ получен» (finish_reason и usage как в ответе; нет usage – null) или «ошибка»
(ушли ли байты, статус). Расход – сумма «ответ получен». Затем – запись случая. Продолжение той же командой: случай
с записью не отправляется; случай, у которого попытка начата, а записи нет или исход «неизвестен» (обрыв после
отправки, 502, 504), не отправляется (запрос мог быть принят и оплачен) – по номеру случая, даже если изменился
запрос; повтор – только с --resend-unknown. Журнал с другими параметрами – код 2 до отправки.

Остановка запуска: отказ допуска (SendNotAllowed) – код 1; 401 и 403 – код 6 (ключ); 402 – код 7 (баланс). Ошибка
случая (запуск идёт дальше): промпт не помещается до отправки, известный исход ответа (LlmError.reason), 429 и 5xx
после повторов клиента; неизвестный исход – случай «неизвестен».

Запуск из корня репозитория (ключи -I и -B обязательны), PowerShell – полные команды четырёх прогонов и двух
сравнений – в docs/model-benchmark.md, раздел «Внешний провайдер и sast-v7». Коротко:
    $env:LLM_EXTERNAL = '1'; $env:DEEPSEEK_API_KEY = '<ключ>'
    .venv\\Scripts\\python -I -B scripts/bench/run_bench_remote.py --url https://api.deepseek.com --key-env DEEPSEEK_API_KEY --model deepseek-v4-pro --prompt-version sast-v7 --out <папка>\\v7-95.json
    ... --dry-run (срезы и промпты без отправки)

Коды выхода: 0 – готово; 1 – неверный запуск (в том числе ошибка аргументов) или отказ допуска; 2 – только
журнал с другими параметрами; 6 – ключ не принят (401, 403); 7 – нужна оплата (402); 130 – прервано (Ctrl+C).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # модули приложения – только на чтение

import argparse  # noqa: E402
import datetime as dt  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import time  # noqa: E402
from collections import Counter  # noqa: E402
from pathlib import Path  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from typing import Any  # noqa: E402

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import run_bench as rb  # noqa: E402

RESULT_FORMAT = "remote-1"
REMOTE_DIR = rb.BENCH_DIR / "runs-remote"
QUOTE_FOUND = ("exact", "normalized")
CLIENT_MODULES = ("llm_chat.py", "llm_http.py", "llm_net.py", "executors.py", "provider_keys.py")
STOP_STATUSES = {401: (6, "ключ API не принят"), 403: (6, "ключ API не принят"), 402: (7, "нужна оплата")}


def load_remote(app_dir: Path) -> SimpleNamespace:
    ns = rb.load_app(app_dir)
    from app import executors, llm_chat, llm_net, provider_keys  # noqa: PLC0415
    ns.executors, ns.llm_chat, ns.llm_net, ns.provider_keys = executors, llm_chat, llm_net, provider_keys
    client_files = {name: rb.sha256_hex((app_dir / "app" / name).read_bytes())[:12] for name in CLIENT_MODULES}
    ns.client_files = client_files
    ns.client_fingerprint = rb.sha256_hex(json.dumps(client_files, sort_keys=True))[:16]
    return ns


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Замер на внешнем провайдере (API чат-завершений) через конвейер "
                                            "«Локального триажа».")
    p.add_argument("--model", required=True, help="точное имя модели у провайдера, например deepseek-v4-pro")
    p.add_argument("--url", required=True, help="база API провайдера, только https, например https://api.deepseek.com")
    p.add_argument("--key-env", required=True, help="имя переменной окружения с ключом API (сам ключ в команду не "
                                                    "пишется)")
    p.add_argument("--prompt-version", default="", help="версия промпта: sast-v6 или sast-v7 (по умолчанию – версия "
                                                        "приложения)")
    p.add_argument("--response-mode", default="json_object", choices=("json_object", "json_schema", "none"))
    p.add_argument("--thinking", default="", help="поле thinking запроса (enabled, disabled; пусто – не передавать)")
    p.add_argument("--effort", default="", help="поле reasoning_effort (low, medium, high; пусто – не передавать)")
    p.add_argument("--max-output", type=int, default=65536, help="предел ответа, токенов (max_tokens)")
    p.add_argument("--context-window", type=int, default=0, help="окно модели, токенов: промпт и ответ (0 – не "
                                                                 "проверять)")
    p.add_argument("--timeout", type=float, default=600.0, help="срок одного обращения, секунд (как в профиле: 600)")
    p.add_argument("--limit", type=int, default=0, help="только первые N отобранных случаев")
    p.add_argument("--ids", help="только эти случаи, через запятую")
    p.add_argument("--source", help="только случаи этого источника (owasp, demo, juice-shop-markers, …)")
    p.add_argument("--category", help="только эти категории, через запятую")
    p.add_argument("--cases", default=str(rb.DEFAULT_CASES), help="эталонный набор (по умолчанию results/bench/"
                                                                  "cases.json; тестовые проекты – cases-projects.json)")
    p.add_argument("--app", default=str(rb.DEFAULT_APP), help="папка приложения (по умолчанию – этот репозиторий)")
    p.add_argument("--out", help="итоговый JSON; журнал – рядом, .jsonl; по умолчанию results/bench/runs-remote/…")
    p.add_argument("--resend-unknown", action="store_true",
                   help="отправить заново случаи с неизвестным исходом (запрос мог быть принят и оплачен)")
    p.add_argument("--retry-errors", action="store_true", help="отправить заново случаи с известной ошибкой")
    p.add_argument("--restart", action="store_true", help="журнал с другими параметрами переименовать и начать заново")
    p.add_argument("--dry-run", action="store_true", help="только срезы и промпты: ничего не отправляется и не пишется")
    args = p.parse_args(argv)
    if args.limit < 0 or args.max_output < 1 or args.context_window < 0 or args.timeout <= 0:
        p.error("--limit, --context-window – неотрицательные, --max-output – не меньше 1, --timeout – больше 0")
    return args


def settings_of(args: argparse.Namespace) -> dict[str, Any]:
    """Параметры клиента – как поля профиля провайдера (executors.apply_chat)."""
    return {"response_mode": args.response_mode, "thinking": args.thinking.strip(), "effort": args.effort.strip(),
            "max_output": int(args.max_output), "context_window": int(args.context_window) or None}


def execution_of(settings: dict[str, Any]) -> dict[str, Any]:
    """Снимок исполнителя для подгонки среза (executors.fit_options, prompt_size) – как у прогона с профилем."""
    return {"kind": "chat_completions", "options_json": json.dumps({"chat": settings})}


def config_key(model: str, url: str, spec: Any, settings: dict[str, Any], timeout: float,
               implementation: str = "") -> str:
    """Что должно совпадать у всех записей одного журнала: протокол, адрес, точное имя модели, версия и текст
    системного промпта, ключи ответа, параметры клиента, срок обращения и реализация (отпечатки конвейера и клиента:
    иначе продолжение смешало бы ответы разных реализаций)."""
    payload = {"kind": "chat_completions", "url": url.rstrip("/"), "model": model, "prompt_version": spec.version,
               "system_prompt": rb.sha256_hex(spec.system), "fields": list(spec.fields), "settings": settings,
               "timeout": float(timeout), "implementation": implementation}
    return rb.sha256_hex(json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str))[:16]


def prepare(ns: SimpleNamespace, runner: Any, case: dict, key: bytes, spec: Any, options: dict, size: Any,
            model: str) -> SimpleNamespace:
    """Срез кода, промпт выбранной версии и подгонка под окно удалённого исполнителя – как в прогоне
    (TriageRunner._process_item): сокращение на нужную долю с запасом, наименьший срез тоже пробуется."""
    triage, llm, prompts = ns.triage, ns.llm, ns.prompts
    f = ns.models.Finding(hub_id=str(case["id"]), kind="SAST", rule=case["rule"], cwe=[case["cwe"]],
                          codebase=case["codebase"], file=case.get("hub_file") or case["file"], line=case["line"],
                          snippet=case["snippet"], language=case["language"])
    repo_dir = Path(case["repo_root"]) if case.get("repo_root") else None
    max_chars = triage.CONTEXT_CHARS
    ctx = ns.context.build_context(repo_dir, f, max_chars=max_chars, mask_key=key)
    messages: list[dict] | None = None
    shrinks = 0
    for attempt in range(triage.FIT_ATTEMPTS + 1):
        if not ctx.lines:
            messages = None
            break
        messages = runner._masked(prompts.build_sast_messages(f, ctx, mask_key=key, prompt_version=spec.version))
        if attempt == triage.FIT_ATTEMPTS or llm.prompt_fits(messages, options, size):
            break
        excess = (size or llm.prompt_tokens)(messages) - (llm.prompt_budget(options) or 0)
        code = "\n".join(ctx.lines)
        keep = max(0.0, 1.0 - excess / max(1, llm.estimate_tokens(code))) * 0.9
        smaller = int((len(code) + 10 * len(ctx.lines)) * keep)
        if smaller < triage.MIN_CONTEXT_CHARS:
            if max_chars <= triage.MIN_CONTEXT_CHARS:
                break
            smaller = triage.MIN_CONTEXT_CHARS
        max_chars = smaller
        ctx = ns.context.build_context(repo_dir, f, max_chars=max_chars, mask_key=key)
        shrinks += 1
    shown = prompts.shown_code(messages, ctx) if messages else []
    code_text = "\n".join(text for _, text in shown) if shown else ""
    tokens = (size or llm.prompt_tokens)(messages) if messages else 0
    request_key = (prompts.request_key(model, messages, options, None, spec.version)
                   if messages else rb.sha256_hex(f"no_code:{triage.case_hash(f, ctx)}:{spec.version}"))
    return SimpleNamespace(case=case, finding=f, ctx=ctx, messages=messages, max_chars=max_chars, shrinks=shrinks,
                           case_hash=triage.case_hash(f, ctx), tokens_est=tokens, request_key=request_key,
                           shown=shown, steering=prompts.steering_lines(ctx),
                           code={"lines": len(shown) if shown else 0, "chars": len(code_text),
                                 "sha": rb.sha256_hex(code_text)[:16] if shown else None,
                                 "first": shown[0][0] if shown else None, "last": shown[-1][0] if shown else None,
                                 "checked": shown is not None})


class AttemptLog:
    """Обёртка над client._request: по записи журнала на каждую HTTP-отправку (до и после)."""

    def __init__(self, client: Any, journal: Any, config: str) -> None:
        self.journal, self.config, self.case = journal, config, None
        self.original = client._request
        client._request = self.request

    def request(self, path: str, payload: Any = None, *args: Any, **kwargs: Any) -> Any:
        if payload is None or self.case is None:  # GET (список моделей) и вне случая – без записи
            return self.original(path, payload, *args, **kwargs)
        n = self.case["attempts"] = self.case["attempts"] + 1  # попытка начата (байты могли и не уйти)
        base = {"type": "attempt", "config_key": self.config, "id": self.case["id"],
                "request_key": self.case["request_key"], "n": n}
        self.journal.write({**base, "event": "start", "ts": rb.now_iso()})  # не записалось – отправки нет
        try:
            data = self.original(path, payload, *args, **kwargs)
        except Exception as e:
            sent = bool(getattr(e, "sent", False)) or getattr(e, "status", None) is not None
            self.case["sent"] += int(sent)
            self.journal.write({**base, "event": "error", "ts": rb.now_iso(), "sent": sent,
                                "status": getattr(e, "status", None), "reason": getattr(e, "reason", None),
                                "error": str(e)[:300]})
            raise
        # ответ сохраняется как есть и при неверной структуре: проверку формата делает клиент после записи
        choices = data.get("choices") if isinstance(data, dict) else None
        choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
        usage = data.get("usage") if isinstance(data, dict) and isinstance(data.get("usage"), dict) else None
        finish = str(choice.get("finish_reason") or "") or None
        self.case["sent"] += 1
        self.case["finishes"].append(finish)
        self.journal.write({**base, "event": "done", "ts": rb.now_iso(), "finish_reason": finish, "usage": usage})
        return data


def run_case(ns: SimpleNamespace, client: Any, prep: SimpleNamespace, cfg: SimpleNamespace,
             log: AttemptLog | None) -> dict:
    llm, prompts, triage = ns.llm, ns.prompts, ns.triage
    rec = rb.base_record(prep, cfg, {})
    rec.update(kind="chat_completions", code=dict(prep.code), quotes=None, quotes_received=None,
               missing_context=None, attempts_log=0, client_fingerprint=cfg.client_fingerprint)
    if not prep.messages:
        rec.update(status="skipped", error_kind="no_code", model_call=False,
                   error=f"Нет кода для разбора: {prep.ctx.note or prep.ctx.status}.")
        return rec
    spec = cfg.spec
    state = {"id": str(prep.case["id"]), "request_key": prep.request_key, "attempts": 0, "sent": 0, "finishes": []}
    if log is not None:
        log.case = state
    started = time.monotonic()
    try:
        obj, stats = client.chat_json(cfg.model, prep.messages, spec.fields, spec.required, spec.enums,
                                      options=cfg.options, types=spec.types, validate=prompts.check_verdict_answer)
    except llm.LlmError as e:
        seconds = time.monotonic() - started
        status = getattr(e, "status", None)
        stop = None
        if isinstance(e, llm.SendNotAllowed):
            stop = (1, "not_sent", f"Отправка не допущена: {e}")
        elif status in STOP_STATUSES:
            code, why = STOP_STATUSES[status]
            stop = (code, "stopped", f"Провайдер ответил HTTP {status}: {why}. Запуск остановлен на случае "
                                     f"{state['id']}; продолжить можно той же командой.")
        if stop is not None:
            # исход известен (запрос не принят): запись случая есть, продолжение отправит его заново
            rec.update(status=stop[1], error_kind="stop", error=str(e), seconds=round(seconds, 3),
                       model_call=bool(state["sent"]), attempts_log=state["attempts"], attempts=state["attempts"])
            rec["stop"] = {"code": stop[0], "message": stop[2]}
            return rec
        unknown = llm.outcome_unknown(e)
        reason = str(getattr(e, "reason", "") or "")
        # причины – словами общей сводки стенда (run_bench.bucket): оборван по пределу – truncated, не по формату –
        # format; прочие известные причины – как у клиента
        kind = ("unknown" if unknown else "prompt" if isinstance(e, llm.PromptOverflowError) or not state["sent"]
                else {"length": "truncated", "bad_format": "format"}.get(reason, reason)
                or ("http" if status else rb.error_kind(e)))
        rec.update(status="unknown" if unknown else ("parse_error" if reason in ("bad_format", "length") else "error"),
                   error_kind=kind, error=str(e), raw_head=(getattr(e, "raw", "") or "")[:rb.RAW_HEAD] or None,
                   stats_partial=bool(triage._stats_partial(e)), seconds=round(seconds, 3),
                   model_call=bool(state["sent"]), attempts_log=state["attempts"], attempts=state["attempts"],
                   hit_length="length" in state["finishes"])
        stats = getattr(e, "stats", None)
        if stats is not None:  # расход полученного ответа известной ошибки (оборван по пределу, не по формату)
            rec.update(prompt_tokens=stats.prompt_tokens, output_tokens=stats.output_tokens,
                       reasoning_tokens=stats.reasoning_tokens, cache_hit_tokens=stats.cache_hit_tokens)
        return rec
    finally:
        if log is not None:
            log.case = None
    rec.update(seconds=round(time.monotonic() - started, 3), model_call=True, attempts_log=state["attempts"],
               attempts=state["attempts"], hit_length="length" in state["finishes"],
               prompt_tokens=stats.prompt_tokens, output_tokens=stats.output_tokens,
               reasoning_tokens=stats.reasoning_tokens, cache_hit_tokens=stats.cache_hit_tokens,
               timing=stats.timing or "app")
    view = ns.context.export_fragment_view(prep.finding, prep.ctx)
    try:
        v = prompts.parse_verdict(obj, view, prompt_version=spec.version, shown=prep.shown)
    except Exception as e:  # noqa: BLE001 – сбой разбора ответа – ошибка этого случая, прогон идёт дальше
        rec.update(status="parse_error", error_kind="parse_verdict", error=f"{type(e).__name__}: {e}",
                   raw_head=json.dumps(obj, ensure_ascii=False, default=str)[:rb.RAW_HEAD])
        return rec
    v7 = spec.version != "sast-v6"
    received = obj.get("evidence_quotes") if isinstance(obj, dict) else None
    rec.update(status="ok", verdict=v.verdict, confidence=v.confidence, summary=v.summary, why=list(v.why),
               evidence_lines=list(v.evidence_lines), cwe_fit=v.cwe_fit, hub_comment=v.hub_comment,
               quotes=list(v.evidence_quotes) if v7 else None,
               quotes_received=(len(received) if isinstance(received, list) else 0) if v7 else None,
               missing_context=v.missing_context if v7 else None)
    return rec


def _count(value: Any) -> int | None:
    """Счётчик usage: целое не меньше нуля; иначе None (не ноль: «неизвестно»)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def attempts_summary(records: list[dict]) -> dict[str, Any]:
    """По записям попыток журнала: отправки, ответы, ошибки, оборванные по пределу, расход по usage ответов (без
    usage – отдельно, а не нулём)."""
    done = [r for r in records if r.get("event") == "done"]
    total: Counter = Counter()
    for r in done:
        usage = r.get("usage") if isinstance(r.get("usage"), dict) else {}
        details = usage.get("completion_tokens_details") if isinstance(usage.get("completion_tokens_details"),
                                                                       dict) else {}
        for name, value in (("prompt_tokens", usage.get("prompt_tokens")),
                            ("completion_tokens", usage.get("completion_tokens")),
                            ("reasoning_tokens", details.get("reasoning_tokens")),
                            ("cache_hit_tokens", usage.get("prompt_cache_hit_tokens"))):
            count = _count(value)
            if count is not None:
                total[name] += count
            elif value is not None:
                total["usage_invalid"] += 1
            elif name in ("prompt_tokens", "completion_tokens") and usage:
                total["usage_missing"] += 1  # поле не прислано: расход по нему неизвестен
    # попытки, расход которых неизвестен, хотя запрос мог быть оплачен: байты ушли, ответа нет (ошибка с sent) или
    # попытка начата и не закрыта (прерывание); у них нет usage – общий расход неполон
    opened: dict[tuple[Any, Any], bool] = {}
    for r in records:
        key = (r.get("id"), r.get("n"), r.get("request_key"))
        if r.get("event") == "start":
            opened[key] = True
        elif r.get("event") in ("done", "error"):
            opened.pop(key, None)
    unpriced = len(opened) + sum(1 for r in records if r.get("event") == "error" and r.get("sent"))
    return {"started": sum(1 for r in records if r.get("event") == "start"), "answered": len(done),
            "errors": sum(1 for r in records if r.get("event") == "error"),
            "errors_sent": sum(1 for r in records if r.get("event") == "error" and r.get("sent")),
            "finish_length": sum(1 for r in done if r.get("finish_reason") == "length"),
            "without_usage": sum(1 for r in done if not r.get("usage")), "unpriced_attempts": unpriced,
            "usage_complete": not any(r.get("event") == "done" and not r.get("usage") for r in records)
            and not total.get("usage_invalid") and not total.get("usage_missing") and not unpriced, **dict(total)}


def quote_metrics(records: list[dict], applicable: bool) -> dict[str, Any]:
    """Цитаты sast-v7 по принятым ответам: знаменатели – цитаты после свёртки повторов и отсечения лишних (принятые);
    отброшенные (повторы и сверх QUOTES_MAX) – отдельно; «принятый ответ без цитат» и «нет принятого ответа»
    (ошибка, неизвестный исход) различаются; у sast-v6 – не применимо."""
    if not applicable:
        return {"applicable": False}
    ok = [r for r in records if r.get("status") == "ok"]
    quotes = [q for r in ok for q in (r.get("quotes") or [])]
    statuses = Counter(str(q.get("status")) for q in quotes)
    found = sum(statuses[s] for s in QUOTE_FOUND)
    with_found = sum(1 for r in ok if any(q.get("status") in QUOTE_FOUND for q in r.get("quotes") or []))
    return {"applicable": True, "answers": len(ok), "no_answer": sum(1 for r in records if r.get("status") != "ok"),
            "quotes": len(quotes), "dropped": sum(max(0, int(r.get("quotes_received") or 0)
                                                      - len(r.get("quotes") or [])) for r in ok),
            "statuses": dict(statuses), "found_rate": round(found / len(quotes), 4) if quotes else None,
            "answers_with_found_rate": round(with_found / len(ok), 4) if ok else None,
            "answers_without_quotes": sum(1 for r in ok if not r.get("quotes")),
            "missing_context_rate": round(sum(1 for r in ok if str(r.get("missing_context") or "").strip())
                                          / len(ok), 4) if ok else None}


def case_table(pairs: list[tuple[dict, dict]]) -> list[dict]:
    """Строка на случай – для сравнения двух итогов (compare_runs.py)."""
    rows = []
    for c, r in pairs:
        quotes = r.get("quotes")
        rows.append({"id": str(c["id"]), "source": c.get("source"), "category": c.get("category"),
                     "expected": c.get("expected"), "also_ok": list(c.get("also_ok") or []),
                     "hint_comment": bool(c.get("hint_comment")), "status": r.get("status"),
                     "error_kind": r.get("error_kind"), "verdict": r.get("verdict"), "confidence": r.get("confidence"),
                     "correct": rb.is_correct(c, r), "code": r.get("code"),
                     "shrinks": (r.get("context") or {}).get("shrinks"),
                     "quotes": None if quotes is None else {
                         "accepted": len(quotes), "dropped": max(0, int(r.get("quotes_received") or 0) - len(quotes)),
                         "statuses": dict(Counter(q.get("status") for q in quotes))},
                     "missing_context": r.get("missing_context"),
                     "tokens": {k: r.get(k) for k in ("prompt_tokens", "output_tokens", "reasoning_tokens")}})
    return rows


def resolve_out(args: argparse.Namespace, spec_version: str) -> Path:
    if args.out:
        out = Path(args.out).resolve()
    else:
        out = REMOTE_DIR / f"{rb.safe_name(args.model)}__{spec_version}__mo{int(args.max_output)}.json"
    return out if out.suffix.lower() == ".json" else out.with_name(out.name + ".json")


def run(args: argparse.Namespace, client_factory: Any = None) -> int:
    app_dir = Path(args.app)
    ns = load_remote(app_dir)
    try:
        spec = ns.prompts.spec_for(args.prompt_version or None)
    except KeyError:
        raise rb.Stop(1, f"Версия промпта «{args.prompt_version}» неизвестна: {', '.join(ns.prompts.SPECS)}.") from None
    cases_path = Path(args.cases)
    cases, cases_sha = rb.load_cases(cases_path)
    selected = rb.select_cases(cases, args)
    for path in (rb.MASK_KEY_PATH, cases_path):
        if rb.forbidden(path, app_dir):
            raise rb.Stop(1, f"{path} – внутри папки приложения, но не в results/: стенд там своих файлов не держит.")
    if not args.dry_run:
        if not ns.llm_net.external_enabled():
            raise rb.Stop(1, "Внешние запросы выключены: задайте переменную окружения LLM_EXTERNAL=1 в этой команде.")
        if not str(os.environ.get(args.key_env) or "").strip():
            raise rb.Stop(1, f"Переменная окружения {args.key_env} с ключом API не задана или пуста.")
    model = args.model.strip()
    settings = settings_of(args)
    client = (client_factory or ns.llm_chat.ChatCompletionsClient)(args.url, timeout=args.timeout)
    ns.executors.apply_chat(client, settings, model)
    key_env = args.key_env
    client.auth = lambda: ns.provider_keys.key_headers("chat_completions", str(os.environ.get(key_env) or "").strip())
    try:
        client.check_url()
    except ns.llm.LlmError as e:
        raise rb.Stop(1, str(e)) from None
    execution = execution_of(settings)
    overhead = ns.executors.json_overhead(client, spec.fields, spec.required, spec.enums, spec.types)
    options = ns.executors.fit_options(execution, {}, overhead)
    size = ns.executors.prompt_size(execution)
    if args.dry_run and not rb.MASK_KEY_PATH.is_file():
        key = os.urandom(32)  # без отправки ключ стенда не создаётся: метки скрытых значений в просмотре – временные
        rb.say("Ключа маскирования стенда ещё нет: для просмотра – временный ключ (файл не создаётся).")
    else:
        key = ns.masking.load_or_create_key(rb.MASK_KEY_PATH)
    runner = ns.triage.TriageRunner(None, ns.config.Settings(), mask_key=key)  # нужен только _masked
    out = resolve_out(args, spec.version)
    if rb.forbidden(out, app_dir):
        raise rb.Stop(1, f"{out} – внутри папки приложения, но не в results/: укажите --out в results/ или вне "
                         "приложения.")
    journal_path = out.with_suffix(".jsonl")
    cfg = SimpleNamespace(model=model, think=settings["thinking"] or None, spec=spec, options=options,
                          prompt_version=spec.version, fingerprint=ns.fingerprint,
                          client_fingerprint=ns.client_fingerprint,
                          config_key=config_key(model, args.url, spec, settings, args.timeout,
                                                f"{ns.fingerprint}:{ns.client_fingerprint}"))
    preps = [prepare(ns, runner, case, key, spec, options, size, model) for case in selected]

    records, broken = rb.read_journal(journal_path)
    alien = [r for r in records if r.get("config_key") and r.get("config_key") != cfg.config_key]
    if alien and not args.dry_run:
        if not args.restart:
            raise rb.Stop(2, f"Журнал {journal_path} собран с другими параметрами (ключ {alien[0].get('config_key')}), "
                             f"а сейчас – модель {model}, промпт {spec.version}, ключ параметров {cfg.config_key}. "
                             "Смешивать нельзя: укажите другой --out или добавьте --restart (прежний журнал будет "
                             "переименован).")
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        old = journal_path.with_name(f"{journal_path.stem}.{stamp}.old.jsonl")
        os.replace(journal_path, old)
        rb.say(f"Прежний журнал переименован: {old}")
        records, broken = [], 0
    own = [r for r in records if r.get("config_key") == cfg.config_key]
    index: dict[str, dict] = {}  # последняя запись случая по номеру случая
    pending: set[str] = set()  # попытка начата после последней записи случая – исход неизвестен
    for r in own:  # по порядку журнала
        if r.get("type") == "case":
            index[str(r.get("id"))] = r
            pending.discard(str(r.get("id")))
        elif r.get("type") == "attempt" and r.get("event") == "start":
            pending.add(str(r.get("id")))

    def unknown(case_id: str) -> bool:
        done = index.get(case_id)
        return case_id in pending or (done is not None and done.get("status") == "unknown")

    mask_sha = rb.sha256_hex(rb.MASK_KEY_PATH.read_bytes())[:16] if rb.MASK_KEY_PATH.is_file() else None
    meta = {
        "result_format": RESULT_FORMAT, "kind": "chat_completions", "url": args.url.rstrip("/"), "model": model,
        "prompt_version": spec.version, "system_prompt_sha": rb.sha256_hex(spec.system)[:16],
        "settings": settings, "options": options, "overhead_tokens": overhead, "timeout_s": args.timeout,
        "think": cfg.think, "config_key": cfg.config_key, "app_dir": str(app_dir), "app_version": ns.version,
        "app_fingerprint": ns.fingerprint, "app_files": ns.files, "client_fingerprint": ns.client_fingerprint,
        "client_files": ns.client_files, "mask_key_sha": mask_sha,
        "cases_file": str(cases_path), "cases_sha256": cases_sha, "cases_total": len(cases),
        "selection": {"ids": rb.split_list(args.ids) or None, "source": args.source,
                      "category": rb.split_list(args.category) or None, "limit": args.limit or None},
        "selected": len(preps), "selected_ids": [str(p.case["id"]) for p in preps], "full_set": len(preps) == len(cases),
        "journal": str(journal_path), "broken_lines": broken,
    }
    if args.dry_run:
        sizes = [p.tokens_est for p in preps if p.messages]
        window = settings["context_window"] or "не проверяется"
        rb.say(f"Проверка без отправки: {model}, промпт {spec.version}, окно {window}, предел ответа "
               f"{settings['max_output']}, добавка схемы {overhead} токенов.")
        for p in preps:
            c = p.case
            rb.say(f"{c['id']:<19} {str(c.get('source')):<20} строк кода {p.code['lines']}, ~{p.tokens_est} ток."
                   + (f", срез сокращён {p.shrinks} раз" if p.shrinks else "") + ("" if p.messages else ", кода нет")
                   + ("" if p.code["checked"] else ", раздел кода не сошёлся со срезом"))
        rb.say(f"Промпт: от {min(sizes) if sizes else 0} до {max(sizes) if sizes else 0} токенов. Уже в журнале: "
               f"{sum(1 for p in preps if str(p.case['id']) in index)} из {len(preps)}; ключ параметров "
               f"{cfg.config_key}.")
        return 0

    rb.say(f"Модель {model} ({args.url}), промпт {spec.version}, thinking {settings['thinking'] or '–'}, effort "
           f"{settings['effort'] or '–'}, предел ответа {settings['max_output']}, окно "
           f"{settings['context_window'] or 'не проверяется'}. Случаев: {len(preps)}; уже в журнале: "
           f"{sum(1 for p in preps if str(p.case['id']) in index)}; исход неизвестен: "
           f"{sum(1 for p in preps if unknown(str(p.case['id'])))}. Журнал: {journal_path}")
    journal = rb.Journal(journal_path)
    log = AttemptLog(client, journal, cfg.config_key)
    session_started = time.monotonic()
    journal.write({"type": "session", "event": "start", "ts": rb.now_iso(), "config_key": cfg.config_key,
                   "model": model, "prompt_version": spec.version, "app_fingerprint": ns.fingerprint,
                   "selected": len(preps), "argv": list(sys.argv[1:])})
    ran, skipped_unknown, reason, code = 0, 0, "done", 0
    try:
        total = len(preps)
        for n, prep in enumerate(preps, 1):
            case_id = str(prep.case["id"])
            done = index.get(case_id)
            if unknown(case_id):
                if not args.resend_unknown:
                    skipped_unknown += 1
                    continue
            elif done is not None and done.get("request_key") == prep.request_key and done.get("status") not in (
                    "stopped", "not_sent") and not (args.retry_errors and done.get("status") in ("error",
                                                                                                "parse_error")):
                continue
            rec = run_case(ns, client, prep, cfg, log)
            journal.write(rec)
            index[case_id] = rec
            pending.discard(case_id)
            ran += 1
            rb.say(rb.progress_line(n, total, prep.case, rec))
            if rec.get("stop"):
                raise rb.Stop(rec["stop"]["code"], rec["stop"]["message"])
    except rb.Stop as e:
        reason, code = "stopped", e.code
        rb.say(str(e))
    except KeyboardInterrupt:
        reason, code = "interrupted", 130
        rb.say("Прервано (Ctrl+C): сделанное сохранено в журнале; случай, отправка которого началась, при "
               "продолжении считается «исход неизвестен».")
    finally:
        journal.write({"type": "session", "event": "end", "ts": rb.now_iso(), "config_key": cfg.config_key,
                       "reason": reason, "ran": ran, "seconds": round(time.monotonic() - session_started, 1)})
        journal.close()

    final = [r for r in rb.read_journal(journal_path)[0] if r.get("config_key") == cfg.config_key]
    # состояние – заново из журнала (как при продолжении): прерывание Ctrl+C между отправкой и записью тоже видно
    index, pending = {}, set()
    since: dict[str, dict[str, Any]] = {}  # попытки после последней записи случая: число и обрывы по пределу
    for r in final:
        rid = str(r.get("id"))
        if r.get("type") == "case":
            index[rid] = r
            pending.discard(rid)
            since.pop(rid, None)
        elif r.get("type") == "attempt":
            mark = since.setdefault(rid, {"attempts": 0, "length": False})
            if r.get("event") == "start":
                pending.add(rid)
                mark["attempts"] += 1
            elif r.get("event") == "done" and r.get("finish_reason") == "length":
                mark["length"] = True
    pairs = []
    for p in preps:
        case_id = str(p.case["id"])
        if case_id in pending:  # попытка начата после последней записи: прежний ответ не действует
            gap = rb.base_record(p, cfg, {})
            mark = since.get(case_id) or {}
            gap.update(status="unknown", error_kind="unknown", model_call=True, code=dict(p.code),
                       attempts=mark.get("attempts", 0), hit_length=bool(mark.get("length")),
                       error="Попытка начата, записи случая нет: исход неизвестен.")
            pairs.append((p.case, gap))
        elif case_id in index and index[case_id].get("status") not in ("stopped", "not_sent"):
            pairs.append((p.case, index[case_id]))  # остановка – не результат: случай ждёт продолжения
    result = rb.build_result(pairs, {**meta, "last_stop": reason})
    result["quotes"] = quote_metrics([r for _, r in pairs], spec.version != "sast-v6")
    result["attempts"] = attempts_summary([r for r in final if r.get("type") == "attempt"])
    result["unknown_outcome"] = sorted(str(p.case["id"]) for p in preps if unknown(str(p.case["id"])))
    result["waiting"] = sorted(str(p.case["id"]) for p in preps if str(p.case["id"]) not in pending
                               and (index.get(str(p.case["id"])) or {}).get("status") in ("stopped", "not_sent"))
    result["unknown_skipped_this_run"] = skipped_unknown
    result["cases"] = case_table(pairs)
    rb.write_json(out, result)
    m = result["metrics"]
    rb.say(f"\nИтог: {model}, промпт {spec.version}; случаев {result['done']} из {result['selected']}; точность "
           f"{rb.pct(m['accuracy'])} ({m['correct']}/{m['known']}); «неясно» {rb.pct(m['uncertain_rate'])}; "
           f"исход неизвестен: {len(result['unknown_outcome'])}; итог: {out}")
    return code


def main(argv: list[str] | None = None, client_factory: Any = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        args = parse_args(argv)
    except SystemExit as e:  # argparse: неверный запуск – код 1 (код 2 – только журнал с другими параметрами)
        return 1 if e.code == 2 else int(e.code or 0)
    try:
        return run(args, client_factory)
    except rb.Stop as e:
        rb.say(str(e))
        return e.code


if __name__ == "__main__":
    sys.exit(main())
