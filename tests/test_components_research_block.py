"""Бэклог 96: на странице «Компоненты» блок «Исследование провайдером» виден всегда – без задания в нём подсказка «сначала
соберите задание» и кнопка сборки; заголовок первого блока – «Задание исследования». Три состояния: без задания, задание без
подходящего профиля, задание с профилем. Данные выдуманы, поддельный сервер на этом компьютере."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fake_chat_api import FakeChatApi  # noqa: E402
from test_sca_research_net import make_profile  # noqa: E402
from test_sca_research_routes import build_task, project_with_sca  # noqa: E402
from test_web import ORIGIN, web  # noqa: E402, F401


def test_research_block_in_three_states(web):  # noqa: F811
    pid = project_with_sca(web)
    page = web.client.get(f"/projects/{pid}/components").text
    assert 'id="component-research"' in page and 'id="research-no-task"' in page and 'id="build-task-research"' in page
    assert "Задание исследования" in page and "Задание внешнему агенту" not in page
    assert 'id="research-preview"' not in page and 'id="research-no-profile"' not in page
    build_task(web, pid)
    page = web.client.get(f"/projects/{pid}/components").text
    assert 'id="research-no-task"' not in page and 'id="research-no-profile"' in page and 'id="research-preview"' not in page
    with FakeChatApi(models=["flash-model"]) as fake:
        profile = make_profile(web, fake)
        r = web.client.post(f"/projects/{pid}/components/research-provider", headers=ORIGIN, follow_redirects=False,
                            data={"research_provider_id": str(profile["id"])})
        assert r.status_code == 303
        page = web.client.get(f"/projects/{pid}/components").text
        assert 'id="research-preview"' in page and 'id="research-no-task"' not in page
        assert "или исследование провайдером" in page
