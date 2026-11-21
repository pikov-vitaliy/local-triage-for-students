"""Перенос текста соседней находки: только действующее решение, без записи и номера."""
import re

import pytest

from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_sast_two_outcomes import card_url, review
from test_web import create_project, upload, web  # noqa: F401


@pytest.mark.parametrize("outcome", ["false_positive", "true_positive"])
def test_near_take_only_current_operator_text(web, outcome):  # noqa: F811
    rows = [dict(SAST_ROWS[0], **{"Issue id": "530001"}),
            dict(SAST_ROWS[0], **{"Issue id": "530002", "Line number": "60"})]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "near.xlsx", sast=rows)).status_code == 303
    first, second = [card_url(web, pid, hid) for hid in ("530001", "530002")]
    def near():
        return re.search(r'<details[^>]+id="near-category"[\s\S]*?</details>',
                         web.client.get(first).text).group(0)
    assert "data-take-outcome" not in near()
    reason, fix = 'Проверено <значение> и "путь".', "Проверять значение."
    assert review(web, second, outcome, reason, fix if outcome == "true_positive" else "").status_code == 200
    db = web.app.state.db
    before = db.get_review(pid, "530001")
    source_before = db.get_review(pid, "530002")
    snippet = near()
    assert f'data-take-outcome="{outcome}"' in snippet and "Взять текст" in snippet
    assert "&lt;значение&gt;" in snippet and "&#34;путь&#34;" in snippet
    assert db.get_review(pid, "530001") == before
    assert db.get_review(pid, "530002") == source_before
    # Изменённая выгрузка делает решение соседа устаревшим.
    rows[1]["Source code"] = "changed(value) : 60"
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "changed.xlsx", sast=rows)).status_code == 303
    assert "data-take-outcome" not in near()
    assert "устарело – сверьте" in near()
