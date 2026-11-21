"""История текста решения SAST (О5): прежняя редакция комментария и рекомендации сохраняется при смене текста или
исхода, повторное сохранение того же текста историю не множит, решения SCA её не пишут; карточка показывает
«Прежние редакции текста» с экранированием; шаг 20 создаёт таблицу на базе схемы 19. Данные выдуманы."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db import Database
from app.models import Finding
from app.triage import order_findings
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_web import create_project, upload, web  # noqa: F401


def sast(hub_id: str) -> Finding:
    return Finding(hub_id=hub_id, kind="SAST", rule="Внедрение SQL-кода", file="src/A.java", line=10, cwe=["CWE-89"])


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "t.db")
    yield database
    database.close()


def save(db: Database, pid: int, comment: str, verdict: str = "false_positive", fix: str = "", **kw):
    return db.save_review(pid, "1", decision="disagree", final_verdict=verdict, final_comment=comment,
                          reviewed=True, final_fix=fix, **kw)


def project(db: Database) -> int:
    pid = db.create_project("p")
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings([sast("1")]))
    return pid


def test_changed_text_keeps_the_previous_edition(db):
    pid = project(db)
    save(db, pid, "Первый текст.")
    assert db.review_text_history(pid, "1")[0] == [], "первое решение – истории ещё нет"
    save(db, pid, "Второй текст.")
    save(db, pid, "Третий текст.", verdict="true_positive", fix="Параметризовать запрос.")
    history = db.review_text_history(pid, "1")[0]
    assert [h["final_comment"] for h in history] == ["Второй текст.", "Первый текст."], "новые первыми"
    assert history[0]["final_verdict"] == "false_positive" and history[0]["replaced_at"]
    assert history[0]["decided_at"], "когда прежний текст был принят"


def test_same_text_or_marks_only_do_not_grow_history(db):
    pid = project(db)
    save(db, pid, "Текст.")
    save(db, pid, "Текст.")
    db.save_review(pid, "1", decision="disagree", final_verdict="false_positive", final_comment="Текст.",
                   reviewed=False)
    assert db.review_text_history(pid, "1")[0] == []


def test_outcome_change_with_the_same_comment_is_recorded(db):
    pid = project(db)
    save(db, pid, "Текст.")
    save(db, pid, "Текст.", verdict="true_positive")
    assert [h["final_verdict"] for h in db.review_text_history(pid, "1")[0]] == ["false_positive"]


def test_empty_previous_text_is_not_history(db):
    pid = project(db)
    db.save_review(pid, "1", decision="later", final_verdict="", final_comment="", reviewed=False)
    save(db, pid, "Текст.")
    assert db.review_text_history(pid, "1")[0] == []


def test_sca_reviews_do_not_write_sast_history(db):
    pid = db.create_project("p")
    sca = Finding(hub_id="s", kind="SCA", component="example-parser", version="1.4.2")
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings([sca]))
    db.save_review(pid, "s", decision="", final_verdict="false_positive", final_comment="А.", reviewed=True)
    db.save_review(pid, "s", decision="", final_verdict="false_positive", final_comment="Б.", reviewed=True)
    assert db.review_text_history(pid, "s")[0] == []


def test_card_shows_previous_editions_escaped(web):  # noqa: F811
    rows = [dict(SAST_ROWS[0], **{"Issue id": "540001"})]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "h.xlsx", sast=rows)).status_code == 303
    db = web.app.state.db
    for text in ("Прежний <b>текст</b>.", "Новый текст."):
        db.save_review(pid, "540001", decision="disagree", final_verdict="false_positive", final_comment=text,
                       reviewed=True)
    fid = db.get_finding_by_hub_id(pid, "540001")["id"]
    page = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="review-history"' in page and "Прежние редакции текста: 1" in page
    assert "Прежний &lt;b&gt;текст&lt;/b&gt;." in page and "<b>текст</b>" not in page


def test_card_without_history_has_no_block(web):  # noqa: F811
    rows = [dict(SAST_ROWS[0], **{"Issue id": "540002"})]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "h.xlsx", sast=rows)).status_code == 303
    fid = web.app.state.db.get_finding_by_hub_id(pid, "540002")["id"]
    assert 'id="review-history"' not in web.client.get(f"/projects/{pid}/findings/{fid}").text


def test_card_shows_the_last_ten_and_the_total(web):  # noqa: F811
    rows = [dict(SAST_ROWS[0], **{"Issue id": "540003"})]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "h.xlsx", sast=rows)).status_code == 303
    db = web.app.state.db
    for n in range(13):
        db.save_review(pid, "540003", decision="disagree", final_verdict="false_positive",
                       final_comment=f"Редакция {n}.", reviewed=True)
    shown, total = db.review_text_history(pid, "540003")
    assert total == 12 and len(shown) == 10 and shown[0]["final_comment"] == "Редакция 11."
    page = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '540003')['id']}").text
    assert "Прежние редакции текста: 12" in page and "Показаны последние 10" in page
    assert "Редакция 1." not in page and "Редакция 11." in page
