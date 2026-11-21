"""Срочный долг 10.11 (план 09.11, этап 3): предварительная версия исправления из Hub помечена, старое чтение Hub
подсказывает «Синхронизировать с Hub», текст настроек о Hub без отвергнутого правила. Данные выдуманы."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app import hub_onboarding, sca
from test_web import web  # noqa: F401


@pytest.mark.parametrize("version, pre", [
    ("20.0.0-rc.0", True), ("3.0.0-M1", True), ("1.0.0-beta.2", True), ("2.1-SNAPSHOT", True), ("1.0a1", True),
    ("0.9.dev3", True), ("5.0.0-alpha", True), ("1.2.3.RC1", True), ("6.0.0-preview.7", True),
    ("2.3.9", False), ("1.2.3.Final", False), ("4.0.0.RELEASE", False), ("2.0-GA", False), ("1.0-src", False),
    ("3.1.2-sp1", False), ("", False),
    # метаданные сборки после «+» на признак не влияют (ревью Codex)
    ("1.2.3+dev.7", False), ("1.2.3+rc", False), ("1.2.3-rc.1+build.7", True),
])
def test_prerelease_versions(version, pre):
    assert sca.prerelease(version) is pre


def test_prerelease_versions_from_text_or_list():
    assert sca.prerelease_versions("2.3.9, 3.0.0-M1; 20.0.0-rc.0") == ["3.0.0-M1", "20.0.0-rc.0"]
    assert sca.prerelease_versions(["1.0", "1.1-beta"]) == ["1.1-beta"]
    assert sca.prerelease_versions(["2.3.9, 3.0.0-M1"]) == ["3.0.0-M1"], "элемент списка – сам перечень"
    assert sca.prerelease_versions(None) == []


def test_stale_hub_read_after_three_days():
    now = datetime(2026, 11, 10, 7, 0, tzinfo=UTC)
    assert hub_onboarding.read_is_stale((now - timedelta(days=3, minutes=1)).isoformat(), now)
    assert not hub_onboarding.read_is_stale((now - timedelta(days=2, hours=23)).isoformat(), now)
    assert not hub_onboarding.read_is_stale("", now) and not hub_onboarding.read_is_stale("вчера", now)
    assert hub_onboarding.read_is_stale("2026-11-01T10:00:00Z", now)
    assert not hub_onboarding.read_is_stale((now - timedelta(days=3)).isoformat(), now), "ровно трое суток – ещё нет"
    assert hub_onboarding.read_is_stale("2026-11-07T09:59:00+03:00", now), "смещение пояса учитывается"
    assert not hub_onboarding.read_is_stale("2026-11-07T07:01:00", now), "время без пояса – UTC"


def test_stale_hint_on_the_project_page_and_not_while_reading(web, monkeypatch):  # noqa: F811
    from test_hub_status_routes import project, sast
    pid = project(web, [sast("101")])
    db = web.app.state.db
    with db._tx() as c:  # прочитано давно и закрыто (stopped): шаг показывает прежнее чтение
        c.execute("INSERT INTO hub_defect_sync_runs(project_id,hub_url,app_id,state,run_json,result_json,created_at,"
                  "closed_at) VALUES (?,?,?,?,?,?,?,?)",
                  (pid, "https://hub.example.org", 7, "stopped", "{}", "{}", "2026-10-01T10:00:00+00:00",
                   "2026-10-01T10:00:01+00:00"))
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="step-hub-stale"' in page
    monkeypatch.setattr(hub_onboarding, "read_is_stale", lambda *a, **k: False)
    assert 'id="step-hub-stale"' not in web.client.get(f"/projects/{pid}").text


def test_settings_page_has_no_rejected_rule(web):  # noqa: F811
    page = web.client.get("/settings").text
    assert "само в Hub не ходит" not in page
    assert "Прямой режим, в котором приложение обращается к Hub само, ещё не сделан" in page
