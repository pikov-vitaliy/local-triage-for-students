"""Сравнение двух итогов внешнего стенда (run_bench_remote.py) – обычно sast-v6 и sast-v7 на одном наборе (В7):
сопоставимы ли прогоны, попарные переходы по случаям и метрики рядом. Таблица Markdown – в консоль или в файл.

Сопоставимость: одинаковые набор (cases_sha256) и отобранные случаи, ключ маскирования стенда, реализация конвейера
и клиента, модель, адрес, параметры клиента и срок обращения; различаться может только версия промпта. Что не
совпало – перечисляется в начале: выводы по такой паре – с оговоркой.

По случаям: «было верно – стало неверно» и наоборот; ошибки и неизвестные исходы каждой стороны; показанный код –
«тот же» (хеш совпал), «срез меньше» (у второго прогона меньше строк или знаков), «код другой», «сравнить нельзя».

Запуск из корня репозитория:
    .venv\\Scripts\\python -I -B scripts/bench/compare_runs.py ИТОГ_V6.json ИТОГ_V7.json [--out ФАЙЛ.md]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
from collections import Counter  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

SAME = ("cases_sha256", "selected_ids", "mask_key_sha", "client_fingerprint", "app_fingerprint", "model", "url",
        "settings", "timeout_s", "kind")
LABELS = {"cases_sha256": "набор", "selected_ids": "отобранные случаи", "mask_key_sha": "ключ маскирования стенда",
          "client_fingerprint": "реализация клиента", "app_fingerprint": "реализация конвейера", "model": "модель",
          "url": "адрес", "settings": "параметры клиента", "timeout_s": "срок обращения", "kind": "протокол"}


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "cases" not in data:
        raise SystemExit(f"{path}: это не итог run_bench_remote.py (нет таблицы случаев).")
    return data


def code_relation(a: dict | None, b: dict | None) -> str:
    if not a or not b or not a.get("sha") or not b.get("sha"):
        return "сравнить нельзя"
    if a["sha"] == b["sha"]:
        return "тот же"
    if (b.get("lines") or 0) < (a.get("lines") or 0) or (b.get("chars") or 0) < (a.get("chars") or 0):
        return "срез меньше по размеру"  # по числу строк или знаков; что это часть прежнего кода, не доказано
    return "код другой"


def compare(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    differs = [LABELS[k] for k in SAME if a.get(k) != b.get(k)]
    for name, run in (("первого", a), ("второго", b)):  # продолжение журнала новой реализацией – тоже не сопоставимо
        if len(run.get("app_fingerprints_used") or []) > 1:
            differs.append(f"реализация менялась внутри {name} прогона")
        if not run.get("complete") or run.get("last_stop") not in (None, "done") or run.get("waiting"):
            differs.append(f"{name} прогон неполный (остановлен или есть случаи без ответа)")
    rows_a = {r["id"]: r for r in a["cases"]}
    rows_b = {r["id"]: r for r in b["cases"]}
    ids = sorted(set(a.get("selected_ids") or rows_a) | set(b.get("selected_ids") or rows_b))
    transitions: Counter = Counter()
    codes: Counter = Counter()
    changed: list[dict[str, Any]] = []
    for case_id in ids:
        ra, rb_ = rows_a.get(case_id), rows_b.get(case_id)
        codes[code_relation((ra or {}).get("code"), (rb_ or {}).get("code"))] += 1
        if ra is None or rb_ is None or ra.get("status") != "ok" or rb_.get("status") != "ok":
            side = ("нет ответа в первом" if ra is None or ra.get("status") != "ok" else "") or ""
            side += ("; " if side else "") + ("нет ответа во втором" if rb_ is None or rb_.get("status") != "ok" else "")
            transitions["без пары (" + (side or "?") + ")"] += 1
            continue
        key = ("верно" if ra["correct"] else "неверно") + " → " + ("верно" if rb_["correct"] else "неверно")
        transitions[key] += 1
        if ra["correct"] != rb_["correct"] or ra.get("verdict") != rb_.get("verdict"):
            changed.append({"id": case_id, "source": ra.get("source"), "expected": ra.get("expected"),
                            "a": f"{ra.get('verdict')} {ra.get('confidence')}", "b": f"{rb_.get('verdict')} "
                            f"{rb_.get('confidence')}", "code": code_relation(ra.get("code"), rb_.get("code"))})
    return {"differs": differs, "transitions": dict(transitions), "codes": dict(codes), "changed": changed,
            "unknown": {"a": a.get("unknown_outcome") or [], "b": b.get("unknown_outcome") or []}}


def tokens(run: dict[str, Any], name: str) -> str:
    """Расход по журналу попыток; неполный (нет usage, поле не прислано или не числом) – с пометкой."""
    att = run.get("attempts") or {}
    return f"{att.get(name)}" + ("" if att.get("usage_complete", True) else " (неполно)")


def pct(value: Any) -> str:
    return "–" if value is None else f"{value * 100:.1f}".replace(".", ",") + " %"


def markdown(a: dict[str, Any], b: dict[str, Any], result: dict[str, Any]) -> str:
    va, vb = a.get("prompt_version"), b.get("prompt_version")
    lines = [f"# Сравнение: {va} и {vb} – {a.get('model')}", ""]
    if result["differs"]:
        lines += ["**Прогоны сопоставимы не полностью** – различаются: " + ", ".join(result["differs"])
                  + ". Выводы по паре – с оговоркой.", ""]
    else:
        lines += ["Прогоны сопоставимы: различается только версия промпта.", ""]
    ma, mb = a["metrics"], b["metrics"]
    rows = [("Точность", pct(ma.get("accuracy")), pct(mb.get("accuracy"))),
            ("Верно / известно", f"{ma.get('correct')}/{ma.get('known')}", f"{mb.get('correct')}/{mb.get('known')}"),
            ("«Неясно»", pct(ma.get("uncertain_rate")), pct(mb.get("uncertain_rate"))),
            ("Настоящая названа ложной", str(ma.get("tp_as_fp")), str(mb.get("tp_as_fp"))),
            ("Ложная названа настоящей", str(ma.get("fp_as_tp")), str(mb.get("fp_as_tp"))),
            ("Не разобрано / сбоев", f"{ma.get('parse_errors')} / {ma.get('errors')}",
             f"{mb.get('parse_errors')} / {mb.get('errors')}"),
            ("Исход неизвестен", str(len(result["unknown"]["a"])), str(len(result["unknown"]["b"]))),
            ("Токены входа (все попытки)", tokens(a, "prompt_tokens"), tokens(b, "prompt_tokens")),
            ("Токены ответа (все попытки)", tokens(a, "completion_tokens"), tokens(b, "completion_tokens")),
            ("Оборвано по пределу ответа", str((a.get("attempts") or {}).get("finish_length")),
             str((b.get("attempts") or {}).get("finish_length")))]
    qa, qb = a.get("quotes") or {}, b.get("quotes") or {}
    if qa.get("applicable") or qb.get("applicable"):
        rows += [("Цитаты найдены в коде", pct(qa.get("found_rate")), pct(qb.get("found_rate"))),
                 ("Ответы хотя бы с одной найденной цитатой", pct(qa.get("answers_with_found_rate")),
                  pct(qb.get("answers_with_found_rate"))),
                 ("Ответы с «не хватило кода»", pct(qa.get("missing_context_rate")),
                  pct(qb.get("missing_context_rate")))]
    lines += [f"| Показатель | {va} | {vb} |", "|---|---|---|"] + [f"| {n} | {x} | {y} |" for n, x, y in rows]
    lines += ["", "## Переходы по случаям", "", "| Переход | Случаев |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(result["transitions"].items())]
    lines += ["", "## Показанный код", "", "| Отношение | Случаев |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(result["codes"].items())]
    if result["changed"]:
        lines += ["", "## Случаи, где ответ изменился", "", f"| Случай | Источник | Эталон | {va} | {vb} | Код |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {c['id']} | {c['source']} | {c['expected']} | {c['a']} | {c['b']} | {c['code']} |"
                  for c in result["changed"]]
    lines += ["", "Один замер: разница в несколько случаев не доказывает превосходство версии."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(description="Сравнение двух итогов run_bench_remote.py.")
    p.add_argument("first")
    p.add_argument("second")
    p.add_argument("--out", help="файл Markdown (по умолчанию – в консоль)")
    args = p.parse_args(argv)
    a, b = load(Path(args.first)), load(Path(args.second))
    text = markdown(a, b, compare(a, b))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Сравнение: {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
