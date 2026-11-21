"""Ревью кода 0.10.0.dev15, круг 2 (Codex xhigh 0/6/1, Kimi high 0/4/0): регрессии на каждую подтверждённую находку.
Данные выдуманные: поддельный Hub."""
import time

import pytest

from app import hub_pull as pull, hub_state, hub_sync_compare as compare
from app.db import dumps, loads
from test_dev15_review_r1 import discard, fid, replaced_by_hub, saved_id, tamper
from test_hub_status_routes import decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, synchronize
from test_sync_saved_edits import restore_saved
from test_web import web  # noqa: F401


def run_row(db, rid):
    return db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (rid,))


def test_discard_after_restored_decision_was_sent_keeps_it(web):
    """Codex 1: восстановить A, отправить A, отбросить запись истории – редактор не откатывается к старому Hub."""
    db, pid, hub = replaced_by_hub(web)
    ident = saved_id(db, pid)
    restore_saved(web, pid, ident)
    # в Hub уже «Ложное срабатывание» с другим основанием – отправка заменяет комментарий, как в карточке
    answer = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert answer.status_code == 200
    drain(db, hub)  # первый шаг выполнен, последствия ответа ещё не доставлены – второй шаг не поставлен
    # отправка не завершена (ревью кода dev15, круг 10: первый шаг – отправка конечного решения): правку не отбросить
    assert discard(web, pid, ident).status_code == 409
    from app import hub_effects
    first = db.hub_op(answer.json()["op_id"])
    hub_effects.after_result(db, first)  # последствия первого шага: поставлен второй – решение с основанием A
    second = db.hub_last_op(pid, "1", "status")
    assert second["id"] != first["id"] and second["state"] == "queued", dict(second)
    drain(db, hub)
    hub_effects.after_result(db, db.hub_op(second["id"]))
    response = discard(web, pid, ident)
    assert response.status_code in (302, 303) and "pending_kept" in response.headers["location"]
    review = db.get_review(pid, "1")
    assert review["final_comment"] == "Основание оператора" and review["decision_origin"] == "operator", dict(review)


def test_restored_edit_without_expiry_is_not_closed_without_sending(web):
    """Codex 2: восстановленная правка без срока при сроке в Hub не закрывается как доставленная без отправки."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    synchronize(db, pid, hub)
    decide(web, pid, "1", comment="Одно основание")
    hub.decision(1, status="False Positive", reason="Одно основание")  # то же основание, в Hub – со сроком
    synchronize(db, pid, hub)
    ident = saved_id(db, pid)
    restore_saved(web, pid, ident)
    web.client.get(f"/projects/{pid}/hub-pending/{ident}")  # страница сверяет ожидания
    assert db._one("SELECT state FROM hub_sync_pending WHERE id=?", (ident,))["state"] == "restored"


def test_history_matches_rule():
    accepted = {"status": "False Positive", "reason": "R", "expiredAt": "2030-01-01"}
    mine = {"status": "False Positive", "reason": "R"}
    assert not pull.history_matches("saved", mine, accepted, {})
    assert not pull.history_matches("restored", mine, accepted, {})
    assert pull.history_matches("pending", mine, accepted, {})  # прежнее ожидание (ADR-0142 п. 5)
    sent = {"status_intent": {"state": "done", "body": {**mine, "expiredAt": "2030-01-01"}}}
    assert pull.history_matches("restored", mine, accepted, sent)  # доставлено операцией этой редакции
    assert pull.history_matches("saved", accepted, accepted, {})


def test_snapshot_current_requires_the_same_version_and_unexpired_evidence(web):
    """Kimi 1: шаг «Состояние Hub» и страница чтения не объявляют совпадение по сравнению другой версии или после
    срока записи Hub."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    row = synchronize(db, pid, hub)
    assert compare.snapshot_current(db, run_row(db, row["id"]))
    tamper(db, row["id"], "SAST:1", version=compare.COMPARE_VERSION - 1)
    assert not compare.snapshot_current(db, run_row(db, row["id"]))
    tamper(db, row["id"], "SAST:1", version=compare.COMPARE_VERSION)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    tamper(db, row["id"], "SAST:1", {**diff, "valid_until": int(time.time() * 1000) - 1000})
    assert not compare.snapshot_current(db, run_row(db, row["id"]))


def test_stale_comparison_keeps_the_expiry(web):
    """Kimi 2, Codex 3: устаревшее наблюдение сохраняет срок записи Hub."""
    db = web.app.state.db
    hub = LiveHub(1)
    pid = project(web, [sast("1")])
    hub.decision(1, status="False Positive", reason="Основание Hub")  # ручная запись со сроком
    row = synchronize(db, pid, hub)
    with db._tx() as c:
        c.execute("UPDATE hub_sync_items SET stale_reason='Наблюдение устарело для проверки.' WHERE run_id=?"
                  " AND entity_key='SAST:1'", (row["id"],))
    compare.recompare(db, row["id"])
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    assert diff["groups"] == ["stale"] and diff.get("valid_until"), diff


@pytest.mark.parametrize("state, text", [("unknown", "Исход отправки неизвестен"), ("queued", "ждёт исполнителя"),
                                         ("failed", "Hub не принял отправку")])
def test_never_read_card_text_follows_delivery(web, state, text):
    """Kimi 3, Codex 4: до первого чтения пояснение карточки – по состоянию отправки, а не всегда «не отправлялось»."""
    db = web.app.state.db
    pid = project(web, [sast("1")])
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET state=? WHERE project_id=? AND purpose='status'", (state, pid))
    card = web.client.get(f"/projects/{pid}/findings/{fid(db, pid, '1')}").text
    assert text in card and "в Hub не отправлялось" not in card, (state, text)


@pytest.mark.parametrize("phase, note, expected", [
    ("failed", "Hub не принял: отказ", "refused"),
    ("failed", "запрос в Hub не отправлен", "unsent"),
    ("read_failed", "чтение не прошло", "unsent"),
    ("refused", "кандидат не прошёл проверку", "unsent"),
])
def test_push_preparation_errors_are_not_hub_refusals(phase, note, expected):
    """Codex 6: «Hub не принял» – только отказ на отправленный PUT; ошибка подготовки – «не отправлено»."""
    local = {"owner": {"update_json": dumps({"phase": phase, "note": note})}}
    found = compare.delivery_of("defect", "77", local, {"groups": ["pending"], "current_pending": True}, None)
    assert found["state"] == expected and found["error"] == note, found


def test_defect_cause_follows_push_outcome():
    """Codex 5: причина у дефекта – по тому же состоянию отправки, что и метка."""
    def cause(state, error="", action=""):
        diff = {"groups": ["pending"], "current_pending": True,
                "delivery": {"state": state, "error": error, "action": action}}
        return compare.causes("defect", "77", {}, diff, None)
    # круг 4: действие при неизвестном исходе – из фазы Push («Сверить»)
    assert cause("unconfirmed", action="verify")[0].startswith("Исход «Push в Hub» неизвестен")
    assert cause("refused", "Hub не принял: Bad Request")[0] == "Hub не принял правку дефекта: Bad Request."
    assert cause("unsent")[0].startswith("Правка дефекта в приложении в Hub не отправлена")


def test_badge_link_opens_the_group_of_the_sync_page():
    """Codex 7 (круг 2) и 5 (круг 3): ссылка значка – по ключу; группу, где объект стоит в сохранённом сравнении,
    открывает сама страница синхронизации."""
    st = hub_state._state(1, 5, "issue", "SAST:1", {"groups": ["coincident", "observed"]}, {})
    assert st["link"].endswith("?q=SAST%3A1") and st["badges"][0]["text"] == compare.LABELS["observed"]
