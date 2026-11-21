"""Бэклог 103: причина отсутствия кода – по `reason` среза, «внутри архива» и «строки выгрузки нет» рядом с причиной, только
в представлении (модели уходят прежние тексты). Бэклог 102/103: итог прогона по вердиктам этого прогона – «неясно, из них без
кода в клоне» и «Hub и модель разошлись» по текущим данным. Данные выдуманы."""

from __future__ import annotations

import pytest

from app.view import code_reason
from test_db import verdict
from test_finding_status_now import accept_state
from test_hub_status_routes import project, sast
from test_web import web  # noqa: F401


@pytest.mark.parametrize("status, reason, file, lines, label", [
    ("ok", "", "a.py", 3, ""),
    (None, None, None, None, ""),
    ("export_line_only", "no_repo", "lib/x.jar!/A.class", 1, "клон не подключён"),
    ("no_repo", "no_repo", "lib/x.jar/A.class", 0, "клон не подключён, строки выгрузки нет"),
    ("export_line_only", "missing", "", 1, "в находке не указан файл"),
    ("export_line_only", "missing", "src/A.java", 1, "файла нет в клоне"),
    ("file_missing", "missing", "lib/app.war/WEB-INF/A.java", 0, "файла нет в клоне, внутри архива, строки выгрузки нет"),
    ("export_line_only", "ambiguous", "a.py", 2, "файл найден неоднозначно или обход клона не завершён"),
    ("export_line_only", "unreadable", "a.py", 2, "файл не прочитан"),
    ("export_line_only", "empty", "a.py", 2, "файл пуст"),
    ("export_line_only", "line_out_of_range", "a.py", 2, "строка за пределами файла"),
    ("binary", "binary", "a.bin", 0, "двоичный файл, строки выгрузки нет"),
    ("too_large", "too_large", "big.js", 2, "файл слишком большой"),
    ("export_line_only", "", "a.py", 2, "причина не записана"),
])
def test_code_reason_by_reason_not_status(status, reason, file, lines, label):
    assert code_reason(status, reason, file, lines) == label


def test_run_summary_counts_this_run_and_current_state(web):  # noqa: F811
    pid = project(web, [sast(h, line=n + 2) for n, h in enumerate(("201", "202", "203", "204"))])
    db = web.app.state.db
    plan = (("201", "uncertain", "export_line_only", "missing"), ("202", "uncertain", "ok", ""),
            ("203", "true_positive", "ok", ""), ("204", "false_positive", "ok", ""))
    run_id = db.create_run(pid, "demo", "selected", "sast-v6", [h for h, *_ in plan])
    for hub_id, value, status, reason in plan:
        vid = db.save_verdict(f"code-{hub_id}", "demo", "sast-v6", verdict(value), {})
        db.save_case(pid, hub_id, f"code-{hub_id}", {"status": status, "reason": reason, "lines": []}, vid)
        with db._tx() as c:  # 204 – готовый ответ из кэша, остальные – новые
            c.execute("UPDATE run_items SET state = ?, verdict_id = ? WHERE run_id = ? AND hub_id = ?",
                      ("cached" if hub_id == "204" else "done", vid, run_id, hub_id))
    accept_state(web, pid, "203", "False Positive")  # Hub: ложное, модель: истинная – расхождение
    accept_state(web, pid, "204", "Accepted risk")  # Accepted risk – не расхождение
    summary = db.run_summary(run_id)
    assert summary["verdicts"] == {"uncertain": 2, "true_positive": 1, "false_positive": 1} and summary["total"] == 4
    assert summary["uncertain_no_code"] == 1 and summary["hub_model_diff"] == 1
    assert (summary["new"], summary["cached"]) == (3, 1)
    page = web.client.get(f"/runs/{run_id}").text
    assert "неясно – 2, из них без кода в клоне – 1 (по текущим срезам)" in page
    assert "3 новых ответов модели, 1 готовых" in page
    assert "Hub и модель разошлись – 1 (по текущему состоянию Hub)" in page
    with db._tx() as c:  # позднее чтение Hub: Confirmed и «ложная» – расхождение, подпись объясняет
        c.execute("UPDATE hub_issue_states SET confirmed_json = ? WHERE project_id = ? AND issue_id = '204'",
                  ('{"detail": {"status": "Confirmed"}}', pid))
    assert db.run_summary(run_id)["hub_model_diff"] == 2


def test_list_badge_names_the_reason(web):  # noqa: F811
    pid = project(web, [sast("301")])
    db = web.app.state.db
    vid = db.save_verdict("code-301", "demo", "sast-v6", verdict("uncertain"), {})
    db.save_case(pid, "301", "code-301", {"status": "export_line_only", "reason": "missing", "file": "lib/a.jar/B.java",
                                          "lines": ["x"]}, vid)
    page = web.client.get(f"/projects/{pid}/findings?kind=SAST").text
    assert "Модель видела только строку из выгрузки: файла нет в клоне, внутри архива" in page


SNAPSHOTS = (  # (статус, причина, файл, строки) – каждая причина, со строкой выгрузки и без, архив поверх причины
    ("export_line_only", "missing", "src/A.java", ["x"]), ("file_missing", "missing", "src/B.java", []),
    ("export_line_only", "missing", "", ["x"]), ("export_line_only", "no_repo", "lib/a.jar/C.java", ["x"]),
    ("no_repo", "no_repo", "lib/a.jar!/D.class", []), ("export_line_only", "ambiguous", "lib/b.war/E.java", ["x"]),
    ("export_line_only", "unreadable", "f.py", ["x"]), ("export_line_only", "empty", "g.py", ["x"]),
    ("export_line_only", "line_out_of_range", "h.py", ["x"]), ("binary", "binary", "i.bin", []),
    ("file_missing", "ambiguous", "m.py", []), ("file_missing", "unreadable", "n.py", []),
    ("file_missing", "empty", "o.py", []), ("file_missing", "line_out_of_range", "p.py", []),
    ("export_line_only", "binary", "q.bin", ["x"]), ("export_line_only", "too_large", "r.js", ["x"]),
    ("too_large", "too_large", "j.js", []), ("export_line_only", "", "k.py", ["x"]), ("ok", "", "l.py", ["x"]),
)


def test_python_and_sql_classify_the_same(web):  # noqa: F811
    from app.view import code_reason_key, in_archive
    hub_ids = [str(400 + n) for n in range(len(SNAPSHOTS))]
    pid = project(web, [sast(h, line=n + 2) for n, h in enumerate(hub_ids)])
    db = web.app.state.db
    for hub_id, (status, reason, file, lines) in zip(hub_ids, SNAPSHOTS):
        db.save_case(pid, hub_id, f"code-{hub_id}", {"status": status, "reason": reason, "file": file, "lines": lines}, None)
    expected: dict = {"reasons": {}, "archive": 0, "no_line": 0, "total": 0}
    for status, reason, file, lines in SNAPSHOTS:
        key = code_reason_key(status, reason, file)
        if not key:
            continue
        expected["reasons"][key] = expected["reasons"].get(key, 0) + 1
        expected["archive"] += in_archive(reason, file)
        expected["no_line"] += not lines
        expected["total"] += 1
    got = db.snapshot_reasons(pid)
    assert got == expected and got["archive"] == 1 and got["total"] == 18
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="snapshot-reasons"' in page and "Без кода в клоне – 18" in page and "внутри архива – 1" in page
