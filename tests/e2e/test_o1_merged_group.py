"""О1 (ADR-0095 п. 4) в браузере: группа, слившаяся при обновлении схемы, – уведомление в карточке, номера не
сводятся: каждая находка выдаёт дефект со своим номером, номер вне исторических – отказ. Данные выдуманы."""

from __future__ import annotations


import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from app import defect  # noqa: E402
from app.db import Database  # noqa: E402
from e2e_support import open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_operator_sast_route import card_urls, save_tp, seeded, wait_clipboard_contains  # noqa: E402

pytestmark = pytest.mark.e2e

REASON = "Значение приходит из запроса пользователя и без проверки попадает в SQL."
FIX = "Передавать значение параметром подготовленного запроса."


def mark_merged(tmp_path, pid: int) -> None:
    """Как после шага 20: у двух находок группы разные номера, группа записана слившейся."""
    db = Database(tmp_path / "data" / "triage.db")
    try:
        db.set_defect_number(pid, defect.defect_key_sast("993000"), 10)
        db.set_defect_number(pid, defect.defect_key_sast("993001"), 20)
        key = db._one("SELECT group_key2 FROM findings WHERE project_id = ? AND hub_id = '993000'", (pid,))["group_key2"]
        with db._tx() as c:
            c.execute("INSERT INTO sast_group_merges(project_id, group_key2, old_keys_json, numbers_json, merged_at)"
                      " VALUES (?, ?, '[\"a\",\"b\"]', '[10,20]', '2026-10-23T14:00:00+00:00')", (pid, key))
    finally:
        db.close()


def test_merged_group_keeps_each_number_and_refuses_a_new_one(browser, tmp_path):
    pid, repos = seeded(tmp_path, 2)
    mark_merged(tmp_path, pid)
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        watch.allowed_errors.append("status of 400")  # отказ по номеру – 400, так и задумано
        try:
            run_triage(page, pid)
            first, second = card_urls(page, pid)
            for url in (first, second):
                page.goto(url)
                save_tp(page, REASON, FIX)
            for url in (first, second):
                page.goto(url)
                expect(page.locator("#group-merge-notice")).to_contain_text("Группа объединена при обновлении")
                own = page.locator("#defect-number").input_value()
                assert own in ("10", "20"), own
                page.click("#copy-defect-body")
                expect(page.locator("#defect-status")).to_contain_text("Полный текст дефекта скопирован")
                expect(page.locator("#defect-status")).to_contain_text("В Hub могли быть два дефекта")
                assert REASON in wait_clipboard_contains(page, REASON)
                assert page.locator("#defect-number").input_value() == own, "номер находки не подменён"
            page.goto(second)
            page.fill("#defect-number", "30")
            page.click("#copy-defect-body")
            expect(page.locator("#defect-status")).to_contain_text("выберите один из них")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
