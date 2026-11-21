"""Контракт dev1b: типы на обеих сторонах, явная правка и слияние трёх версий."""

import copy
from pathlib import Path

import pytest

from app import defect_fields as fields
from app.defect_dto import DEFECT_CONTRACT, validate_defect
from test_hub_worker import hw


def dto(**changes):
    return {"id": 777, "appId": 7, "summary": "ID5 - Тест (SAST)", "priority": {"name": "High"},
            "severity": {}, "linkedIssues": [], **changes}


def both(body, valid=True):
    for validate in (validate_defect, hw.validate_defect):
        if valid:
            validate(body, 777, 7)
        else:
            with pytest.raises(ValueError):
                validate(body, 777, 7)


def test_worker_embeds_the_same_standalone_contract():
    root = Path(__file__).resolve().parents[1]
    blocks = [p.read_text(encoding="utf-8").split("# BEGIN DEFECT DTO")[1].split("# END DEFECT DTO")[0]
              for p in (root / "app/defect_dto.py", root / "deploy/hub-worker/hub_worker.py")]
    assert blocks[0] == blocks[1]


@pytest.mark.parametrize("key,value", [
    ("priority", {}), ("priority", {"name": "", "rank": 2}), ("priorityId", 0), ("severity", {"rank": -1}),
    ("severityId", 3), ("source", ""), ("tool", "custom"), ("stage", "TEST"), ("type", "new type"),
    ("structureUnitId", 11), ("appStructureUnit", {"id": "11", "name": ""}), ("releaseObject", {}),
    ("externalBugs", [{}, {"product": "arbitrary", "link": "not a URI", "displayName": ""}]),
    ("isActive", False), ("settings", {}), ("settings", {"isInheritedARStatusFromDefect": False}),
    ("dueDate", "2026-11-10T18:00:00+01:00"), ("createTs", "2026-10-27T00:00:00Z"),
    ("extension", {"unknown": None}), ("linkedIssues", [{"cwes": [{}], "application": {}, "aiProviderStatus": "0"}]),
])
def test_declared_types_without_invented_nested_requirements(key, value):
    both(dto(**{key: value}))


@pytest.mark.parametrize("key,value", [
    ("isActive", "false"), ("isActive", 0), ("priorityId", "2"), ("priorityId", True),
    ("priority", {"rank": True}), ("priority", {"name": None}), ("severity", None),
    ("appStructureUnit", {"id": 11}), ("releaseObject", {"name": False}),
    ("externalBugs", {"link": "x"}), ("externalBugs", [None]), ("externalBugs", [{"product": 5}]),
    ("settings", {"isInheritedFPStatusFromDefect": "false"}), ("settings", None),
    ("dueDate", 1761600000000), ("dueDate", None), ("dueDate", "2026-11-10T18:00:00"),
    ("dueDate", "2026-02-30T18:00:00Z"), ("dueDate", "2026-11-10T18:00:00+25:00"),
    ("createTs", True), ("author", {"id": True}), ("linkedIssues", [{"id": "1"}]),
    ("linkedIssues", [{"cvss": True}]), ("linkedIssues", [{"aiProviderStatus": "2"}]),
    ("linkedIssues", [{"cwes": [{"id": 5}]}]), ("linkedIssues", [{"scanObject": {"id": None}}]),
    ("id", 778), ("appId", 8), ("priorityId", 2 ** 63),
])
def test_invalid_full_dto_is_rejected_by_app_and_worker(key, value):
    both(dto(**{key: value}), False)


@pytest.mark.parametrize("key", ["id", "appId", "priority", "severity", "summary"])
def test_required_properties(key):
    body = dto()
    del body[key]
    both(body, False)


@pytest.mark.parametrize("a,b", [(True, 1), (1, "1"), ({}, {"x": None}), ({"x": ""}, {"x": None}),
                                 ([], {}), ([1, 2], [2, 1]), (0, False)])
def test_presence_types_and_array_order_are_distinct(a, b):
    assert not fields.equal(a, b)
    assert fields.diff(a, b)


def test_key_order_is_irrelevant_and_diff_preserves_presence():
    assert fields.equal({"a": 1, "b": 2}, {"b": 2, "a": 1})
    assert fields.diff({}, {"x": False}) == [{"path": "/x", "before_present": False, "after_present": True, "after": False}]
    assert fields.apply_changes({"x": False}, fields.diff({"x": False}, {})) == {}


@pytest.mark.parametrize("base,local,remote,expected", [
    ({"stage": "DEV"}, {"stage": "DEV"}, {"stage": "TEST"}, {"stage": "TEST"}),
    ({"stage": "DEV"}, {"stage": "LOCAL"}, {"stage": "DEV"}, {"stage": "LOCAL"}),
    ({"stage": "DEV"}, {"stage": "TEST"}, {"stage": "TEST"}, {"stage": "TEST"}),
    ({}, {}, {"isActive": False}, {"isActive": False}),
    ({"stage": "DEV"}, {}, {"stage": "DEV"}, {}),
    ({"settings": {"a": 1, "b": 2}}, {"settings": {"a": 3, "b": 2}},
     {"settings": {"a": 1, "b": 4}}, {"settings": {"a": 3, "b": 4}}),
])
def test_three_way_merge(base, local, remote, expected):
    original = copy.deepcopy((base, local, remote))
    assert fields.merge(base, local, remote) == expected
    assert (base, local, remote) == original


@pytest.mark.parametrize("base,local,remote", [
    ({"stage": "DEV"}, {"stage": "LOCAL"}, {"stage": "TEST"}),
    ({"isActive": False}, {}, {"isActive": True}),
    ({"priority": {"name": "Low"}, "priorityId": 1}, {"priority": {"name": "High"}, "priorityId": 1},
     {"priority": {"name": "Low"}, "priorityId": 2}),
    ({"externalBugs": [{"link": "a"}]}, {"externalBugs": [{"link": "b"}]}, {"externalBugs": [{"link": "c"}]}),
])
def test_conflicting_groups_and_arrays_are_not_partially_merged(base, local, remote):
    with pytest.raises(ValueError, match="Конфликт"):
        fields.merge(base, local, remote)


def test_choices_never_invent_ids_or_ranks():
    change = [{"path": "/priority/name", "op": "set", "value": "High"}]
    assert fields.edit({"priority": {"name": "Low"}}, change, {"priorities": ["High"]}) == {"priority": {"name": "High"}}
    for current in ({"priority": {"name": "Low", "rank": 1}}, {"priority": {"name": "Low"}, "priorityId": 1}):
        with pytest.raises(fields.FieldError, match="соответствия"):
            fields.edit(current, change, {"priorities": ["High"]})
    with pytest.raises(fields.FieldError):
        fields.edit({"severity": {}}, [{"path": "/severity/name", "op": "set", "value": "High"}], {})


@pytest.mark.parametrize("path", ["/status", "/id", "/linkedIssues", "/settings/extension", "/priority/extension"])
def test_form_cannot_edit_system_or_unknown_properties(path):
    with pytest.raises(fields.FieldError):
        fields.edit({}, [{"path": path, "op": "set", "value": "x"}], {})


def test_candidate_applies_delta_to_fresh_dto_preserving_unedited_fields():
    base = dto(stage="DEV", tool="old", settings={"isInheritedFPStatusFromDefect": False, "extension": 8})
    draft = fields.fields_of(base)
    draft["stage"] = "LOCAL"
    import json
    row = {"hub_defect_id": "777", "app_id": 7, "draft_fields_json": json.dumps(draft),
           "draft_fields_basis_json": json.dumps(fields.new_basis(base, "test"))}
    fresh = {**base, "tool": "fresh", "systemExtension": [1]}
    result, changes, _ = fields.candidate(fresh, row, base["summary"], "text")
    assert result["stage"] == "LOCAL" and result["tool"] == "fresh"
    assert result["settings"]["extension"] == 8 and result["systemExtension"] == [1]
    assert fields.changed_roots(changes) == ["description", "stage"]
    assert DEFECT_CONTRACT == hw.DEFECT_CONTRACT
