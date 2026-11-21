"""Ревью кода 0.10.0.dev15, круг 4 (Codex xhigh 0/1/0): подсказка после «Push в Hub» называет только действия, которые
карточка дефекта в этой фазе действительно даёт (та же функция доступности кнопок, что у карточки)."""
import pytest

from app import hub_sync_compare as compare
from app.db import dumps
from app.routes.hub_defect_routes import update_context
from test_web import web  # noqa: F401


@pytest.mark.parametrize("phase", ["unknown", "confirming", "unconfirmed", "observed_old", "unclear", "failed",
                                   "putting", "refused", "read_failed"])
def test_suggested_push_action_is_available_on_the_card(phase):
    row = {"id": 1, "state": "done", "draft_owner_id": 1, "update_json": dumps({"phase": phase, "note": "заметка"}),
           "update_op_id": None, "sync_op_id": None, "hub_defect_id": "77", "conflicts_json": "[]"}
    card = update_context(None, row, True, False)
    pull = not card["busy"] and phase != "unconfirmed"  # «Pull из Hub» закрыт при Push в работе и при unconfirmed
    diff = {"groups": ["pending"], "current_pending": True}
    found = compare.delivery_of("defect", "77", {"owner": row}, diff, None)
    available = {"verify": card["can_verify"], "reread": card["can_reread"], "push": card["can_prepare"], "pull": pull}
    if found.get("action"):
        assert available[found["action"]], (phase, found)
    cause = compare.causes("defect", "77", {}, {**diff, "delivery": found}, None)[0]
    for button, ok in (("«Сверить»", card["can_verify"]), ("«Повторить чтение»", card["can_reread"]),
                       ("«Pull из Hub»", pull)):
        if button in cause:
            assert ok, (phase, button, cause)
    if "отправьте её снова («Push в Hub»" in cause:
        assert card["can_prepare"], (phase, cause)


def test_comparison_saved_by_the_previous_calculation_is_recomputed(web):
    """Kimi круг 4: сравнение, сохранённое прежним расчётом (до правок отправки), не берётся как текущее – ни страницей,
    ни snapshot_current."""
    from app import hub_state
    from test_dev15_review_r1 import tamper
    from test_hub_status_routes import HUB, project, sast
    from test_sync_golden_path import LiveHub, synchronize
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    forged = {"groups": ["pending"], "fields": [], "causes": [], "current_pending": True,
              "delivery": {"state": "queued", "stored": 0, "date": "", "error": "", "op_id": None}}
    tamper(db, row["id"], "SAST:1", forged, version=15)  # так сохранял расчёт до круга 3
    st = hub_state.project_states(db, db.get_project(pid), HUB)["by_hub_id"]["1"]
    assert st["group"] == "matched" and not st["delivery"]["state"], st
    run = db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (row["id"],))
    assert not compare.snapshot_current(db, run)
    assert compare.COMPARE_VERSION > 15


def test_check_result_is_named_not_waiting_for_reread():
    for phase, words in (("observed_old", "отправьте её снова"), ("unclear", "Посмотрите версию Hub")):
        row = {"update_json": dumps({"phase": phase, "note": "в Hub прежний текст"})}
        found = compare.delivery_of("defect", "77", {"owner": row}, {"groups": ["pending"], "current_pending": True}, None)
        cause = compare.causes("defect", "77", {}, {"groups": ["pending"], "current_pending": True, "delivery": found},
                               None)[0]
        assert found["state"] == "unsent" and words in cause and "не завершилось" not in cause, (phase, cause)
