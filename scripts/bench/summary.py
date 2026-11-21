"""Сводная таблица замеров «Локального триажа»: все итоги run_bench.py (results/bench/runs/*.json) -> одна таблица
Markdown. Метрики и правило верного ответа – docs/model-benchmark.md.

Порядок строк: сначала полные прогоны (все случаи набора), по точности; при равной точности – меньше пропусков
уязвимостей (настоящая находка названа ложной), затем быстрее (медиана времени на находку). Неполные прогоны
(--limit, --ids, остановленные) – в конце, со звёздочкой: их точность посчитана на части набора.

Вложенные папки (results/bench/runs/probe/ и т. п.) не читаются.

Запуск из корня репозитория:
    .venv\\Scripts\\python -I -B scripts/bench/summary.py [--results ПАПКА] [--out ФАЙЛ.md]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent.parent / "results" / "bench" / "runs"
OWASP_ORDER = ("sqli", "cmdi", "pathtraver", "xss", "ldapi", "xpathi", "trustbound", "weakrand")


def num(value: float | None, digits: int = 1) -> str:
    return "–" if value is None else f"{value:.{digits}f}".replace(".", ",")


def pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.1f}".replace(".", ",") + " %"


def pf(part: int | None, whole: int | None) -> str:
    """Процент из целых числителя и знаменателя (без двойного округления долей из итогов)."""
    if not whole or part is None:
        return "–"
    from decimal import Decimal, ROUND_HALF_UP
    v = (Decimal(part) * 100 / Decimal(whole)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    return f"{v}".replace(".", ",") + " %"


def frac(part: int | None, whole: int | None) -> str:
    return "–" if not whole else f"{part}/{whole}"


def gb(size: int | None) -> str:
    return "?" if not size else num(size / 1024 ** 3) + " ГиБ"


def minutes(seconds: float | None) -> str:
    if not seconds:
        return "0"
    return f"{num(seconds / 60)} мин" if seconds >= 60 else f"{int(round(seconds))} с"


def load(results: Path) -> tuple[list[dict], list[str]]:
    rows, problems = [], []
    for path in sorted(results.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            problems.append(f"{path.name}: не прочитан ({e})")
            continue
        if not isinstance(data, dict) or not isinstance(data.get("metrics"), dict) or not data.get("model"):
            problems.append(f"{path.name}: не итог run_bench.py – пропущен")
            continue
        if not data.get("done"):
            problems.append(f"{path.name}: ни одного разобранного случая ({data.get('model')}, остановка: "
                            f"{data.get('last_stop')}) – пропущен")
            continue
        data["_file"] = path.name
        rows.append(data)
    return rows, problems


def full(r: dict) -> bool:
    """Полный прогон: отобран весь набор и все случаи разобраны."""
    return bool(r.get("full_set")) and bool(r.get("complete"))


def sort_key(r: dict) -> tuple:
    m = r["metrics"]
    return (0 if full(r) else 1, -(m.get("accuracy") or 0.0), m.get("tp_as_fp") or 0,
            m.get("time_median_s") if m.get("time_median_s") is not None else float("inf"))


def label(r: dict) -> str:
    return f"{r['model']}{'' if full(r) else ' *'}"


def think(r: dict) -> str:
    """Режим рассуждений и предел ответа: «false, np 3072»; у итогов до result_format 2 – только режим."""
    mode = r.get("think") or "none"
    return f"{mode}, np {r['num_predict']}" if r.get("num_predict") else mode


def vram_cell(r: dict) -> str:
    g = r.get("gpu") or {}
    first = g.get("vram_after_load") or {}
    if not first:
        return "–"
    ratio = g.get("vram_ratio_min") if g.get("vram_ratio_min") is not None else first.get("ratio")
    text = f"{gb(first.get('size_vram'))} из {gb(first.get('size'))} ({pct(ratio)})"
    return text + (", часть на процессоре" if g.get("partial_offload") else "")


def trunc_cell(m: dict) -> str:
    if m.get("truncated") is None:
        return "–"  # итог до result_format 2
    return f"{m['truncated']} ({pf(m['truncated'], m.get('model_calls'))})"


def wait_cell(r: dict) -> str:
    g = r.get("gpu") or {}
    parts = []
    if g.get("waited_cases"):
        parts.append(f"ждали {g['waited_cases']} раз, {minutes(g.get('waited_s'))}")
    if g.get("contended_cases"):
        parts.append(f"{g['contended_cases']} ответов рядом с чужой моделью")
    return "; ".join(parts) or "нет"


def main_table(rows: list[dict]) -> list[str]:
    out = [
        "| Место | Модель | think | Случаев | Точность | Настоящие найдены | Ложные распознаны | «Неясно» | "
        "Настоящая названа ложной | Ложная названа настоящей | Уверенность на ошибках | Время на находку, с "
        "(медиана / среднее) | ток/с | Не разобрано | Оборвано по num_predict | Видеопамять | Ожидание |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for place, r in enumerate(rows, 1):
        m = r["metrics"]
        out.append(
            f"| {place} | {label(r)} | {think(r)} | {r.get('done')} из {r.get('cases_total')} | "
            f"{pf(m.get('correct'), m.get('known'))} ({frac(m.get('correct'), m.get('known'))}) | "
            f"{pf(m.get('tp_correct'), m.get('tp'))} ({frac(m.get('tp_correct'), m.get('tp'))}) | "
            f"{pf(m.get('fp_correct'), m.get('fp'))} ({frac(m.get('fp_correct'), m.get('fp'))}) | "
            f"{pf(m.get('uncertain_answers'), m.get('answered'))} | {m.get('tp_as_fp')} ({pf(m.get('tp_as_fp'), m.get('tp'))}) | "
            f"{m.get('fp_as_tp')} ({pf(m.get('fp_as_tp'), m.get('fp'))}) | {num(m.get('confidence_wrong_mean'), 0)} | "
            f"{num(m.get('time_median_s'))} / {num(m.get('time_mean_s'))} | {num(m.get('tps'), 0)} | "
            f"{m.get('parse_errors')} ({pf(m.get('parse_errors'), m.get('model_calls'))}) | {trunc_cell(m)} | {vram_cell(r)} | {wait_cell(r)} |")
    return out


def source_table(rows: list[dict]) -> list[str]:
    out = ["| Модель | think | OWASP | OWASP: в коде нет подсказок генератора | OWASP: подсказки есть | Демо |",
           "|---|---|---:|---:|---:|---:|"]
    for r in rows:
        src, hint = r.get("by_source") or {}, r.get("by_hint") or {}

        def cell(b: dict | None) -> str:
            return "–" if not b else f"{pf(b.get('correct'), b.get('known'))} ({frac(b.get('correct'), b.get('known'))})"

        out.append(f"| {label(r)} | {think(r)} | {cell(src.get('owasp'))} | {cell(hint.get('owasp_no_hint'))} | "
                   f"{cell(hint.get('owasp_hint'))} | {cell(src.get('demo'))} |")
    return out


def category_table(rows: list[dict]) -> list[str]:
    seen: list[str] = []
    for r in rows:
        for k in (r.get("by_category") or {}):
            if k not in seen:
                seen.append(k)
    order = [k for k in OWASP_ORDER if k in seen] + sorted(k for k in seen if k not in OWASP_ORDER)
    out = ["| Модель | think | " + " | ".join(order) + " |", "|---|---|" + "---:|" * len(order)]
    for r in rows:
        cats = r.get("by_category") or {}
        cells = [frac(cats[k].get("correct"), cats[k].get("known")) if k in cats else "–" for k in order]
        out.append(f"| {label(r)} | {think(r)} | " + " | ".join(cells) + " |")
    return out


def notes(rows: list[dict], problems: list[str]) -> list[str]:
    out = []
    if rows:
        out.append(f"- {rows[0].get('correct_rule', '')}")
    out.append("- Точность – доля верных ответов среди всех случаев с известным ответом; «настоящие найдены» – "
               "чувствительность, «ложные распознаны» – специфичность. «Настоящая названа ложной» – самая "
               "опасная ошибка: пропуск уязвимости. Уверенность на ошибках – средняя уверенность модели в разобранных "
               "неверных ответах (высокая – модель ошибается уверенно).")
    out.append("- Время на находку – без загрузки модели в память; ток/с – все токены ответа, делённые на всё время "
               "генерации (как средняя скорость прогона в приложении).")
    partial = [r for r in rows if not full(r)]
    if partial:
        out.append("- * – неполный прогон: " + "; ".join(
            f"{r['model']} ({think(r)}, {r['_file']}) – {r.get('done')} из {r.get('selected')} отобранных, в наборе "
            f"{r.get('cases_total')}" for r in partial) + ". Сравнивать с полными нельзя.")
    versions = sorted({str(r.get("prompt_version")) for r in rows})
    if len(versions) > 1:
        out.append(f"- Внимание: итоги собраны с разными версиями промпта ({', '.join(versions)}) – сравнение "
                   "неравноценное.")
    prints = sorted({fp for r in rows for fp in (r.get("app_fingerprints_used") or [r.get("app_fingerprint")]) if fp})
    if len(prints) > 1:
        out.append(f"- Внимание: код конвейера приложения менялся между прогонами (отпечатки {', '.join(prints)}): "
                   "проверьте, не изменились ли промпт и разбор ответа.")
    app_versions = sorted({str(r.get("app_version") or "?") for r in rows})
    if len(app_versions) > 1:
        out.append(f"- Внимание: итоги собраны разными версиями приложения ({', '.join(app_versions)}; «?» – итог "
                   "без версии).")
    cases = sorted({str(r.get("cases_sha256"))[:12] for r in rows})
    if len(cases) > 1:
        out.append(f"- Внимание: итоги собраны на разных версиях набора cases.json ({', '.join(cases)}).")
    offload = [r for r in rows if (r.get("gpu") or {}).get("partial_offload")]
    if offload:
        out.append("- Часть модели в памяти процессора (не поместилась в видеопамять вместе с окном контекста): "
                   + ", ".join(f"{r['model']} ({think(r)})" for r in offload) + " – отсюда низкая скорость.")
    contended = [r for r in rows if (r.get("gpu") or {}).get("contended_cases")]
    if contended:
        out.append("- Во время части ответов рядом была загружена чужая модель – время этих ответов ненадёжно: "
                   + ", ".join(f"{r['model']} ({(r.get('gpu') or {}).get('contended_cases')})" for r in contended)
                   + ".")
    for p in problems:
        out.append(f"- Файл {p}")
    return out


def render(rows: list[dict], problems: list[str], results: Path) -> str:
    if not rows:
        return f"В {results} нет итогов run_bench.py." + ("\n" + "\n".join(problems) if problems else "")
    lines = ["# Замер моделей «Локального триажа»", "",
             f"Итогов: {len(rows)}; набор – {rows[0].get('cases_total')} случаев; промпт "
             f"{', '.join(sorted({str(r.get('prompt_version')) for r in rows}))}; окно контекста "
             f"{', '.join(sorted({str((r.get('options') or {}).get('num_ctx')) for r in rows}))}.", "",
             "## Сводка", "", *main_table(rows), "",
             "## По источнику", "", *source_table(rows), "",
             "## По категориям (верно / всего)", "", *category_table(rows), "",
             "## Примечания", "", *notes(rows, problems), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(description="Сводная таблица итогов run_bench.py (Markdown).")
    p.add_argument("--results", default=str(RESULTS_DIR), help="папка с итогами (по умолчанию results/bench/runs)")
    p.add_argument("--out", help="сохранить таблицу в файл .md (иначе – только вывод на экран)")
    args = p.parse_args(argv)
    results = Path(args.results)
    rows, problems = load(results)
    rows.sort(key=sort_key)
    text = render(rows, problems, results)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8", errors="replace")
    return 0


if __name__ == "__main__":
    sys.exit(main())
