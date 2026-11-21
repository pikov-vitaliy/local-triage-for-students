"""Замечания к оформлению «Объяснения» дефекта SCA – предупреждения, а не запрет выдачи (ADR-0152: оператор
вправе создать дефект своим решением): нет отдельной строки для уязвимости, текст не на русском.
Пустое «Объяснение» остаётся запретом. Пакеты, версии и идентификаторы выдуманы."""

from __future__ import annotations

from test_sca_no_fix_mode import GHSA, MEASURES, RECORD, defect, env  # noqa: F401
from test_web import web  # noqa: F401

FREE = ("Разбор файла сертификата без ограничения размера ведёт к отказу в обслуживании. Уязвимость описана в "
        f"бюллетене {GHSA}, исправления для используемой версии нет.")


def ready_with(db, store, pid, record: dict) -> dict:
    """Текст набора с отметкой остаточного риска: в режиме заготовки её требует сама уязвимость без исправления."""
    first = defect(db, store, pid, record)
    return defect(db, store, pid, {**record, "residual_checked_sig": first["residual_confirm_sig"]})


def test_explanation_in_own_words_is_approved_with_a_warning(env):  # noqa: F811
    db, store, pid, _ = env
    done = ready_with(db, store, pid, {**RECORD, "explanation": FREE})
    assert done["ready"], done["problems"]
    assert not any("Объяснени" in p for p in done["problems"]), done["problems"]
    warn = [c for c in done["cautions"] if "нет отдельной строки или она слишком короткая" in c]
    assert len(warn) == 1 and GHSA in warn[0] and "Дефект можно утвердить и так" in warn[0]
    assert f"«{GHSA}: что это и при каких условиях срабатывает»" in warn[0], "пример строки назван"
    assert FREE in done["body"] and MEASURES in done["body"], "в тело уходит текст оператора как написан"


def test_line_per_vulnerability_gives_no_warning(env):  # noqa: F811
    db, store, pid, _ = env
    done = ready_with(db, store, pid, RECORD)
    assert done["ready"] and not any("нет отдельной строки" in c for c in done["cautions"]), done["cautions"]


def test_not_russian_explanation_warns_and_the_mark_removes_the_warning(env):  # noqa: F811
    db, store, pid, _ = env
    english = f"{GHSA}: Parsing a certificate file without a size limit leads to denial of service."
    done = ready_with(db, store, pid, {**RECORD, "explanation": english})
    assert done["ready"], done["problems"]
    assert any("не на русском" in c and "Дефект можно утвердить и так" in c for c in done["cautions"]), done["cautions"]
    marked = ready_with(db, store, pid, {**RECORD, "explanation": english, "text_checked_sig": done["text_confirm_sig"]})
    assert marked["ready"] and not any("не на русском" in c for c in marked["cautions"]), marked["cautions"]


def test_empty_explanation_still_blocks(env):  # noqa: F811
    db, store, pid, _ = env
    first = ready_with(db, store, pid, {**RECORD, "explanation": ""})
    assert not first["ready"] and any("Объяснение" in p for p in first["problems"]), first["problems"]
    assert not any("нет отдельной строки" in c for c in first["cautions"]), "о строках пустого текста не предупреждаем"


def test_explanation_of_internal_ids_only_is_empty_and_blocks(env):  # noqa: F811
    """Ревью 0.10.0.dev26: в поле только внутренний номер AST – в Hub он не уходит, объяснения не остаётся: запрет,
    как у пустого поля."""
    db, store, pid, _ = env
    first = ready_with(db, store, pid, {**RECORD, "explanation": "AST-2099-000001"})
    assert not first["ready"] and any("Объяснение пустое" in p for p in first["problems"]), first["problems"]
    assert not any("нет отдельной строки" in c for c in first["cautions"]), first["cautions"]


def test_short_line_is_named_as_short(env):  # noqa: F811
    """Ревью 0.10.0.dev26, круг 2: строка с идентификатором есть, но в ней меньше двадцати букв – предупреждение говорит
    и о короткой строке, а не только об отсутствующей."""
    db, store, pid, _ = env
    done = ready_with(db, store, pid, {**RECORD, "explanation": f"{GHSA}: Ошибка чтения."})
    assert done["ready"], done["problems"]
    assert any("слишком короткая" in c and "хотя бы одной фразой" in c for c in done["cautions"]), done["cautions"]
