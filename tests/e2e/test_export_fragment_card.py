"""Карточки старых срезов: фрагмент рядом и фрагмент не найден, без клона и без настоящей модели."""

import pytest
from playwright.sync_api import expect

from app.db import Database
from e2e_support import make_fake_ollama, open_page, start_app, stop_app
from test_export_fragment import seed_legacy
from test_export_shift import seed_shifted

pytestmark = pytest.mark.e2e


def test_saved_fragment_near_and_differs(browser, tmp_path):
    db = Database(tmp_path / "data" / "triage.db")
    try:
        near_pid, near_fid, _ = seed_legacy(db, [11])
        diff_pid, diff_fid, _ = seed_legacy(db)
        shift_pid, shift_fid, _ = seed_shifted(db)
    finally:
        db.close()
    repos = tmp_path / "repos"
    repos.mkdir()
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f"/projects/{near_pid}/findings/{near_fid}")
            expect(page.locator("#export-fragment-near")).to_contain_text("Фрагмент из выгрузки – на строке 11")
            expect(page.locator("#export-fragment-differs, #code-changed")).to_have_count(0)
            expect(page.locator("#L11")).to_have_class("is-export")
            expect(page.locator("#L10")).to_have_class("is-target")
            page.goto(f"/projects/{diff_pid}/findings/{diff_fid}")
            expect(page.locator("#export-fragment-near, #code-changed")).to_have_count(0)
            expect(page.locator("#export-fragment-differs")).to_be_visible()
            expect(page.locator("#trace-export-line")).to_contain_text("log.info(value)")
            expect(page.locator("#export-fragment-differs")).not_to_contain_text("коммите")
            page.goto(f"/projects/{shift_pid}/findings/{shift_fid}")
            expect(page.locator("#export-fragment-shifted")).to_contain_text("сдвинут на 24 строки")
            expect(page.locator("#export-fragment-differs")).to_have_count(0)
            expect(page.locator("#L34")).to_have_class("is-export")
            assert not watch.problems(), watch.problems()
            assert fake.chats() == []
        finally:
            context.close()
            stop_app(server.process)


def test_legacy_entered_note_hides_after_changed_copy(browser, tmp_path):
    """Отметка «Внесено в Hub» по тексту прежнего формата: после правки решения и копирования пометка «решение
    прежнее» исчезает без перезагрузки – сервер снял отметку."""
    from app.config import DEFAULT_STATUS_MAP
    from app.db import text_hash
    from app.routes.findings import saved_hub_text_v1
    db = Database(tmp_path / "data" / "triage.db")
    try:
        pid, fid, f = seed_shifted(db)
        # ложное срабатывание: в Hub уходит комментарий оператора, его и копирует кнопка (ADR-0089)
        review = db.save_review(pid, f.hub_id, decision="disagree", final_verdict="false_positive",
                                final_comment="Проверено по сохранённому коду: значение ограничено.", reviewed=True)
        db.mark_entered(pid, f.hub_id, True, review["revision"],
                        text_hash(saved_hub_text_v1(f, review, dict(DEFAULT_STATUS_MAP))))
    finally:
        db.close()
    repos = tmp_path / "repos"
    repos.mkdir()
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f"/projects/{pid}/findings/{fid}")
            expect(page.locator("#entered-format-updated")).to_be_visible()
            expect(page.locator("#entered-badge")).to_be_visible()
            page.fill("#comment", "Проверено заново: другой текст обоснования.")
            page.click("#copy-hub")
            expect(page.locator("#entered-format-updated")).to_be_hidden()
            expect(page.locator("#entered-at")).to_have_text("")
            expect(page.locator("#entered-badge")).to_be_hidden()
            expect(page.locator("#entered-note")).to_be_hidden()
            # кнопка снова приглашает поставить отметку (надпись ей возвращает скрипт)
            expect(page.locator("#mark-entered")).to_be_visible()
            expect(page.locator("#mark-entered")).to_contain_text("Отметить: статус и комментарий внесены в Hub")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
