"""Полоса шагов карточки SAST: номер находки рядом с проектом – кнопка копирования (бэклог 31); подсказка «Решение
подставлено – сохраните» в нижней панели (бэклог 32). Данные выдуманы."""

from __future__ import annotations

import re

from test_hub_status_routes import fid, project, sast
from test_web import web  # noqa: F401


def test_route_bar_carries_the_finding_number_as_a_copy_button(web):
    pid = project(web, [sast("4242")])
    html = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '4242')}").text
    nav = re.search(r'<nav class="route"[^>]*>(.*?)</nav>', html, re.S).group(1)
    button = re.search(r'<button[^>]*id="route-id"[^>]*>4242</button>', nav)
    assert button, nav[:600]
    assert 'data-copy-text="4242"' in button.group(0) and 'class="route-id mono"' in button.group(0)
    assert nav.index('class="route-project"') < nav.index('id="route-id"') < nav.index('class="route-list"')
    note = re.search(r'<span[^>]*id="take-note"[^>]*>', html).group(0)
    assert 'role="status"' in note and 'data-text="Решение подставлено – сохраните"' in note and " hidden" in note
