"""Показ кода, строки выгрузки и полей по выбору оператора (0.10.0.dev14, ADR-0141).

Маски мешают проверить находки о жёстко заданных учётных данных, а за маскированием отвечает оператор: решать
за человека приложение не должно. Выбран вариант «только показ»: флажок проекта `mask_secrets`
управляет тем, что видит человек в приложении. Модели код уходит с масками всегда (ADR-0003), сохранённые срезы,
отпечатки и решения от флажка не зависят – переключение в любой момент ничего не пересчитывает.

Здесь только функции показа; промпт, вопрос модели и предпросмотр внешней отправки их не используют.
"""

from __future__ import annotations

import html
from collections.abc import Callable, Iterable
from typing import Any

from app import i18n, masking
from app.context import build_context
from app.models import CodeContext, Finding


def masked(project: dict | None) -> bool:
    """Показывать с масками: флажок проекта; нет проекта или поля (база до схемы 35) – как раньше, с масками."""
    if not project:
        return True
    return bool(project.get("mask_secrets", 1))


def export_line(f: Finding, mask_key: bytes | None, project: dict | None) -> str:
    """Строка срабатывания из выгрузки для карточки: с маской – как в промпте; без маски – исходная, свёрнутая в строку
    с тем же ограничением длины."""
    from app.prompts import _one_line, masked_export_line
    if masked(project):
        return masked_export_line(f, mask_key)
    raw = str(f.snippet or "").strip("\n")
    return _one_line(html.unescape(raw)) if raw.strip() else ""


def plain_context(project: dict | None, repo_dir, f: Finding, why: str) -> CodeContext | None:
    """«Текущий файл в клоне, без масок» – только при снятом флажке и только SAST: строки вокруг строки находки из
    текущего файла клона, без маски. Это не срез разбора и ничего о нём не утверждает. Флажок включён или не SAST –
    None; иначе срез как есть: при status != 'ok' карточка показывает его причину (note), а не строки (ревью dev14)."""
    if masked(project) or f.kind != "SAST":
        return None
    if repo_dir is None:
        return CodeContext(status="no_repo", file=f.file, language=f.language or "", start_line=0, end_line=0,
                           target_line=None, lines=[], note=why or i18n._("клона нет"))
    from app.triage import CONTEXT_CHARS
    return build_context(repo_dir, f, max_chars=CONTEXT_CHARS, mask_key=None, no_repo_note=why)


# поля вердикта модели, которые карточка показывает человеку в «Подробностях разбора»: у вердикта с разбором по
# шагам – одни, у прежнего формата – другие (тот же признак, что is_v3 в карточке)
MODEL_TEXT_FIELDS = {True: ("what_code_does", "why", "data_flow"), False: ("explanation", "data_flow")}


def label_values(project: dict | None, repo_dir, f: Finding, mask_key: bytes | None, why: str = "",
                 also: Iterable[Callable[[], Any]] = ()) -> dict[str, str]:
    """Значения меток маскирования для показа текстов модели без масок (бэклог 111) – только при снятом флажке и
    только SAST. Модель видела код с метками (ADR-0003), её ответ хранится с метками. Значение восстанавливается, когда
    его даёт то же маскирование тем же ключом: строка выгрузки, прочие колонки выгрузки (also – функции, которые их
    маскируют) и текущий файл клона. Метка, которой там нет (код изменился, клон отвязан), остаётся меткой. Словарь
    живёт в ответе на запрос карточки и никуда не сохраняется."""
    if masked(project) or f.kind != "SAST" or not mask_key:
        return {}
    from app.prompts import masked_export_line
    from app.triage import CONTEXT_CHARS
    with masking.recording() as book:
        masked_export_line(f, mask_key)
        for extra in also:
            extra()
        if repo_dir is not None:
            build_context(repo_dir, f, max_chars=CONTEXT_CHARS, mask_key=mask_key, no_repo_note=why)
    return {label: value for label, value in book.items() if value is not None}


def reveal(text: Any, values: dict[str, str] | None) -> str:
    """Текст модели для показа: метки, значение которых известно, заменены значением; остальные остаются метками."""
    text = str(text or "")
    if not values:
        return text
    return masking.PLACEHOLDER_RE.sub(lambda m: values.get(m.group(0), m.group(0)), text)


def labels_note(project: dict | None, verdict: Any, values: dict[str, str]) -> dict | None:
    """Что сказать под текстами модели при снятом флажке: сколько разных меток заменено значением (revealed) и какие
    остались метками (left) – по тем полям, которые карточка показывает. Флажок включён, вердикта нет или меток в
    показанных текстах нет – None."""
    if masked(project) or verdict is None:
        return None
    stepwise = any(getattr(verdict, name, None) for name in ("why", "what_code_does", "check_by_eye", "terms"))
    found: set[str] = set()
    for name in MODEL_TEXT_FIELDS[bool(stepwise)]:
        value = getattr(verdict, name, None)
        for part in (value if isinstance(value, (list, tuple)) else [value]):
            found.update(m.group(0) for m in masking.PLACEHOLDER_RE.finditer(str(part or "")))
    if not found:
        return None
    return {"revealed": len(found & set(values)), "left": sorted(found - set(values))}


def _ranges(numbers: list[int]) -> str:
    """Номера строк подряд – диапазонами: [3, 4, 5, 9] -> «3–5, 9»."""
    out: list[str] = []
    for n in numbers:
        if out and isinstance(out[-1], list) and out[-1][1] == n - 1:
            out[-1][1] = n
        else:
            out.append([n, n])  # type: ignore[arg-type]
    return ", ".join(str(a) if a == b else f"{a}–{b}" for a, b in out)  # type: ignore[misc]


def current_slice(model_ctx: CodeContext | None, current: CodeContext | None) -> dict | None:
    """Текущий срез клона рядом со срезом модели (бэклог 112): когда разбор устарел, оператор видит и код, который
    сейчас в клоне, – с теми же масками, что и срез модели. rows – строки текущего среза с пометкой changed (строки нет
    в срезе модели или она другая; сопоставление – по содержимому, сдвиг номеров отличием не считается), changed –
    их номера диапазонами, removed – сколько строк среза модели в текущем срезе нет. Текущего кода нет – None."""
    if model_ctx is None or current is None or current.status != "ok" or not current.lines:
        return None
    import difflib
    old, new = list(model_ctx.lines or []), list(current.lines)
    same_new: set[int] = set()
    kept_old = 0
    for block in difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_matching_blocks():
        same_new.update(range(block.b, block.b + block.size))
        kept_old += block.size
    start = int(current.start_line or 1)
    rows = [{"n": start + i, "text": line, "changed": i not in same_new, "target": start + i == current.target_line}
            for i, line in enumerate(new)]
    return {"rows": rows, "start": start, "end": start + len(new) - 1,
            "changed": _ranges([r["n"] for r in rows if r["changed"]]), "removed": len(old) - kept_old,
            "masked": bool(getattr(current, "masked", None))}
