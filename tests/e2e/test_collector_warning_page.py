"""Страница прогона: предупреждение «сборщик метрик компьютера не работает» с командой запуска появляется, когда
снимки сборщика устарели, и уходит само, когда он снова пишет снимки, – без перезагрузки страницы (HOSTCOL-01).
Отдельное приложение с временной папкой данных: снимки сборщика других проверок не задевают."""

from __future__ import annotations

import json
import time

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, make_fake_ollama, open_page, run_triage, start_app, stop_app

pytestmark = pytest.mark.e2e


def snapshot(data_dir, age: float) -> None:
    path = data_dir / "telemetry" / "host.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": 1, "collector_id": "e2e", "sequence": 1, "sampled_at": time.time() - age,
                                "host_scope": "ollama_host", "cpu_pct": 5.0, "addresses": ["192.0.2.10"],
                                "memory": {"total_bytes": 64 << 30, "available_bytes": 40 << 30}}), encoding="utf-8")


def test_run_page_shows_and_clears_the_collector_warning(browser, tmp_path):
    fake = make_fake_ollama()
    server = start_app(tmp_path, fake.url)
    context, page, watch = open_page(browser, server.url)
    try:
        pid = create_demo(page)
        run_triage(page, pid)
        warning = page.locator("#collector-warning")
        expect(warning).to_be_hidden()  # вне контейнера и без следов сборщика – ни слова
        snapshot(server.data_dir, 0)
        page.reload()
        expect(warning).to_be_hidden()
        # сборщик остановился, пока страница открыта: предупреждение появляется без перезагрузки – с давностью снимка
        snapshot(server.data_dir, 30 * 60)
        expect(warning).to_be_visible(timeout=20000)
        expect(warning).to_contain_text("последний снимок 30 мин назад")
        expect(warning).to_contain_text(r".\scripts\host-metrics.ps1 -Action Start")
        snapshot(server.data_dir, 0)
        expect(warning).to_be_hidden(timeout=20000)  # статус прогона опрашивается раз в несколько секунд
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
        stop_app(server.process)
        fake.close()
