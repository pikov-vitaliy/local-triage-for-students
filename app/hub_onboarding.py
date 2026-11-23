"""Шаг «Состояние Hub» в начале проекта (0.10.0.dev13).

После заведения проекта (название, режим модели, исходники, выгрузка) оператор одной кнопкой подтягивает
текущее состояние приложения в Hub – дефекты, их состав, статусы находок – и только потом работает; ввод номеров дефектов
через запятую – тупиковый вариант. Кнопка – полная синхронизация ADR-0127 («Синхронизировать», затем «Принять
состояние Hub»). Здесь только чтение базы: какое состояние у текущего назначения проекта (адрес Hub и номер
приложения), чтобы показать шаг и напоминание. Запросов к Hub нет, запретов нет: решает оператор.

Состояния (ревью плана dev13, круги 1–2): нет назначения; не читали; чтение идёт; номер не совпал с выгрузкой;
остановлено; прочитано – ждёт принятия; прочитано – пригодных объектов нет; принято частично; принято полностью;
совпадает с Hub. «Совпадает» – по matches_snapshot при актуальном локальном сравнении, а не по нулю объектов.
"""

from datetime import UTC, datetime, timedelta

from app import i18n
from app.db import loads
from app.hub_ops import hub_base

STALE_READ = timedelta(days=3)  # чтение Hub старше трёх суток – подсказка «Синхронизировать»


def read_is_stale(read_at: str | None, now: datetime | None = None) -> bool:
    """Последнее чтение Hub было больше трёх суток назад: состояние Hub могло измениться. Время не разобрать – нет."""
    try:
        moment = datetime.fromisoformat(str(read_at or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (now or datetime.now(UTC)) - moment > STALE_READ

DONE = ("accepted", "matches")  # шаг выполнен: напоминание не показывается

LABELS = i18n.Labels({
    "no_target": "Приложение в Hub не указано",
    "not_read": "Состояние Hub ещё не принималось",
    "reading": "Чтение Hub идёт",
    "app_mismatch": "Номер приложения не совпал с выгрузкой",
    "stopped": "Чтение Hub остановлено",
    "ready": "Прочитано – ждёт принятия",
    "nothing": "Прочитано – принять нечего",
    "partial": "Принято частично",
    "accepted": "Состояние Hub принято",
    "matches": "Совпадает с Hub",
    "unapplied": "Прочитано – не принято",
    # после принятия у принятого объекта осталось отличие – ошибка приложения, объекты названы (dev15, план п. 1.5)
    "accepted_error": "Принято с ошибкой: после принятия остались отличия",
})


def state(db, project: dict, hub_url: str, *, light: bool = False) -> dict:
    """Состояние шага для текущего назначения проекта; прежние номера приложения – история (последний прогон).
    light – для напоминания на вкладках (ревью dev13): без перебора объектов прогона для принятия; совпадение с Hub
    проверяется на актуальность так же, как на обзоре; прочитанный, но не принятый прогон – «прочитано – не принято»."""
    from app import hub_pull, hub_sync, hub_sync_compare
    base, app_id = hub_base(hub_url or ""), project.get("hub_app_id")
    out = {"state": "no_target", "run": None, "data": {}, "pull": {}, "history": None, "app_id": app_id, "done": False}
    if base and app_id:
        out["history"] = db._one("SELECT id,app_id,state,applied_at,created_at FROM hub_defect_sync_runs WHERE project_id=?"
                                 " AND hub_url=? AND app_id<>? ORDER BY id DESC LIMIT 1", (project["id"], base, app_id))
    if not base or not app_id:
        return {**out, "label": LABELS["no_target"]}
    row = db._one("SELECT * FROM hub_defect_sync_runs WHERE project_id=? AND hub_url=? AND app_id=? ORDER BY id DESC LIMIT 1",
                  (project["id"], base, app_id))
    if row is None:
        return {**out, "state": "not_read", "label": LABELS["not_read"]}
    data = hub_sync.passport(row)
    out.update(run=row, data=data)
    if row["state"] in (*hub_sync.ACTIVE, "comparing"):
        name = "reading"
    elif data.get("app_check", {}).get("stop"):
        name = "app_mismatch"
    elif row["state"] == "closed" and not row["applied_at"]:
        # закрытый запуск: завершённое актуальное совпадение остаётся совпадением, иначе принятия не было (ревью dev13, круг 4)
        # то же для полного чтения, где принять нечего и все пропуски – противоречия Hub (ревью Codex dev14, круг 4)
        current = data.get("comparison_complete") and hub_sync_compare.snapshot_current(db, row)
        name = "matches" if current and data.get("matches_snapshot") else "stopped"
    elif row["state"] != "ready" and not row["applied_at"]:
        name = "stopped"
    elif row["applied_at"]:
        result = loads(row["result_json"], {})
        out["pull"] = result
        # dev15 (план п. 1.2): противоречия Hub – пометки, находка принимается; пропуск – только незавершённое чтение
        name = "partial" if _count(result.get("skipped")) else "accepted"
        out["saved"] = int(result.get("saved") or 0)  # решения, заменённые состоянием Hub (история, план п. 1.4)
        residue = result.get("residue") or []
        if residue:  # после принятия остались отличия – ошибка приложения (план п. 1.5)
            name = "accepted_error"
            out["residue"] = residue
    elif data.get("matches_snapshot") and hub_sync_compare.snapshot_current(db, row):
        name = "matches"  # и в облегчённом режиме: совпадение не превращается в «не принято» (ревью dev13, круг 2)
    elif light:
        name = "unapplied"
    else:
        pull = hub_pull.preview(db, row)
        out["pull"] = pull
        if pull.get("count"):
            name = "ready"
        else:
            name = "nothing"
    # done – единый признак завершённого шага для шаблонов (обзор и напоминание на вкладках, ревью Codex dev14, круг 4);
    # stale – последнее чтение старше трёх суток, пока новое не идёт: подсказка «Синхронизировать»
    return {**out, "state": name, "label": LABELS[name], "done": name in DONE,
            "skipped": _count(out["pull"].get("skipped")),
            "stale": name != "reading" and read_is_stale(row["created_at"])}


def _count(value) -> int:
    """Пропуски: у применённого прогона – список причин, у предпросмотра – число."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    return len(value) if isinstance(value, (list, tuple, dict)) else 0
