"""Два экземпляра тестового приложения одновременно получают разные порты ОС."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from playwright.sync_api import expect

from app.db import Database
from e2e_support import make_fake_ollama, start_app, stop_app

pytestmark = pytest.mark.e2e


def test_two_app_servers_keep_their_own_data(browser, tmp_path):
    folders = [tmp_path / "first", tmp_path / "second"]
    names = ["Первый тестовый проект", "Второй тестовый проект"]
    for folder, name in zip(folders, names):
        folder.mkdir()
        db = Database(folder / "data" / "triage.db")
        try:
            db.create_project(name)
        finally:
            db.close()
    with make_fake_ollama() as fake, ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(start_app, folder, fake.url, team_name="") for folder in folders]
        try:
            servers = [job.result() for job in jobs]
            assert servers[0].url != servers[1].url
            assert all(server.process.poll() is None for server in servers)
            for n, server in enumerate(servers):
                context = browser.new_context()
                try:
                    page = context.new_page()
                    page.goto(server.url)
                    expect(page.get_by_role("link", name=names[n], exact=True)).to_be_visible()
                    expect(page.get_by_role("link", name=names[1 - n], exact=True)).to_have_count(0)
                finally:
                    context.close()
        finally:
            for job in jobs:
                try:
                    server = job.result()
                except Exception:
                    continue
                stop_app(server.process)
