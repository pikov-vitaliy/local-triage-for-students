"""Отбор «К разбору» на странице SCA: версии компонента, у которых
есть находки не внесённые в Hub и не отложенные оператором, и которые не входят в дефект приложения. Отложенные
(«Отложить» – решение `later`) ждут сборки dev17 и в отбор не попадают; «Не внесены в Hub» их по-прежнему показывает.
Счётчик `todo` считается по каждой находке отдельно: одна находка может быть и отложенной, и внесённой в Hub
(`mark_entered` решение не проверяет), и разность сумм `entered + later` такую версию скрыла бы (ревью Codex 08.11)."""
from app import sca
from app.db import Database


def _view(name, findings, entered=0, todo=None, in_defect=False):
    view = {"component": name, "version": "1.0", "findings": findings, "entered": entered, "in_defect": in_defect,
            "urgent": False, "answer": None, "conclusion": "", "reviewed": 0}
    if todo is not None:
        view["todo"] = todo
    return view


def test_todo_excludes_deferred_entered_and_in_defect():
    views = [
        _view("fresh", 2, todo=2),                          # ничего не решено – к разбору
        _view("deferred", 1, todo=0),                       # отложена целиком – не к разбору
        _view("mixed", 3, todo=2),                          # одна отложена, две нет – к разбору
        _view("entered", 2, entered=2, todo=0),             # внесены – не к разбору
        _view("partly", 2, entered=1, todo=0),              # внесена и отложена – ничего не осталось
        _view("in_defect", 2, todo=2, in_defect=True),      # в дефекте приложения – не к разбору
    ]
    assert [v["component"] for v in sca.filter_views(views, "todo")] == ["fresh", "mixed"]
    # прежние отборы не меняются: «Не внесены в Hub» показывает и отложенные
    assert [v["component"] for v in sca.filter_views(views, "not_entered")] == ["fresh", "deferred", "mixed", "partly", "in_defect"]
    assert ("todo", "К разбору") in sca.FILTERS and "todo" in sca.FILTER_KEYS


def test_todo_without_counter_falls_back_to_not_entered():
    """Представление без счётчика `todo` (прежние данные): отложенные неизвестны, действует правило «не внесены»."""
    assert sca.todo_count(_view("old", 3, entered=1)) == 2
    assert sca.filter_views([_view("old", 3, entered=1)], "todo") == [_view("old", 3, entered=1)]
    assert sca.filter_views([_view("done", 2, entered=2)], "todo") == []


def _row(fid, entered_hub, decision):
    return {"id": fid, "hub_id": str(fid), "cvss": 7.5, "urgent": 0, "codebase": "a", "reviewed": 1,
            "entered_hub": entered_hub, "decision": decision,
            "data_json": '{"component": "lib", "version": "1.0", "build_type": "npm"}'}


def test_component_groups_count_todo_per_finding():
    """Контрпример ревью Codex 08.11: одинаковые суммы `entered` и отложенных, разные ответы на «к разбору»."""
    # первая находка одновременно отложена и внесена, вторая без решения и не внесена – версия к разбору
    (overlap,) = Database._sca_component_groups([_row(1, 1, "later"), _row(2, 0, "")])
    assert (overlap["findings"], overlap["entered"], overlap["todo"]) == (2, 1, 1)
    assert sca.filter_views([{**overlap, "answer": None, "conclusion": ""}], "todo")
    # одна внесена, другая отложена – разбирать нечего
    (split,) = Database._sca_component_groups([_row(1, 1, "agree"), _row(2, 0, "later")])
    assert (split["findings"], split["entered"], split["todo"]) == (2, 1, 0)
    assert sca.filter_views([{**split, "answer": None, "conclusion": ""}], "todo") == []
    # без решений и отметок все находки к разбору
    (fresh,) = Database._sca_component_groups([_row(1, 0, ""), _row(2, 0, None)])
    assert fresh["todo"] == 2
