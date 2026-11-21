"""Бэклог 104 в Chrome: форма запуска триажа без переключения охвата берёт «Живые в Hub» – находки Fixed и False Positive
в прогон не попадают, страница прогона называет, сколько их не разбиралось. Выдуманный проект, поддельная модель."""
from __future__ import annotations

import pytest
from playwright.sync_api import expect

from app import hub_ops
from app.db import Database, dumps
from e2e_support import open_page, start_app, stop_app, wait_run_done
from fake_ollama import FakeOllama, verdict_answer
from test_operator_readiness import seeded_app

pytestmark = pytest.mark.e2e
HUB = "https://hub.example.org"


def test_default_scope_skips_fixed_and_closed(browser, tmp_path):
    pid, repos, _ = seeded_app(tmp_path, count=3)
    db = Database(tmp_path / "data" / "triage.db")
    try:
        db.update_project(pid, hub_app_id=7)
        db.set_settings({"hub_url": HUB})
        with db._tx() as c:
            for hub_id, status in (("990000", "Fixed"), ("990001", "False Positive")):
                c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json,"
                          " confirmed_presence) VALUES (?, ?, 7, 'SAST', ?, ?, 'present')",
                          (pid, hub_ops.hub_base(HUB), hub_id, dumps({"detail": {"status": status}})))
    finally:
        db.close()
    with FakeOllama(default_answer=verdict_answer()) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(f"/projects/{pid}#step3")
            expect(page.locator('input[name="scope"][value="live"]')).to_be_checked()
            expect(page.locator("#step3")).to_contain_text("Живые в Hub (1)")
            page.get_by_role("button", name="Запустить триаж", exact=True).click()
            page.wait_for_url("**/runs/*")
            wait_run_done(page)
            expect(page.locator("#run-excluded")).to_contain_text("Исправлено в Hub – 1, закрыто решением – 1")
            expect(page.locator(".page-head")).to_contain_text("охват: живые в Hub")
            assert len(fake.chats()) == 1, "модели ушла только живая находка"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
