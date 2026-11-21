"""Вкладка «Дефекты»: сортировка по ID и по виду, адреса сохраняют порядок, «Занести из Hub» внизу."""

import re

import pytest

from test_web import web  # noqa: F401


def project(web) -> int:
    return web.app.state.db.create_project("p")


def add(db, pid: int, rows) -> None:
    with db._tx() as c:
        for kind, number, summary in rows:
            c.execute("INSERT INTO hub_defects(project_id, kind, number, summary, state, origin, created_at, updated_at)"
                      " VALUES (?, ?, ?, ?, 'draft', 'app', '2026-10-30T00:00:00', '2026-10-30T00:00:00')",
                      (pid, kind, number, summary))


def order(html: str) -> list[str]:
    return re.findall(r'<td data-label="ID" class="col-id mono">(?:<a href="[^"]*">)?(ID\d+|–)', html)


def test_sort_by_number_and_kind_with_rows_without_number_last(web):
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 7, "ID7 - b"), ("SCA", 2, "ID2 - a"), ("SAST", None, "без номера"), ("SCA", 9, "ID9 - c")])
    base = f"/projects/{pid}/defects"
    assert order(web.client.get(base).text) == ["ID9", "–", "ID2", "ID7"], "по умолчанию – от новых к старым"
    assert order(web.client.get(base + "?sort=number_asc").text) == ["ID2", "ID7", "ID9", "–"]
    assert order(web.client.get(base + "?sort=number_desc").text) == ["ID9", "ID7", "ID2", "–"]
    assert order(web.client.get(base + "?sort=kind_asc").text) == ["ID7", "–", "ID2", "ID9"]
    assert order(web.client.get(base + "?sort=kind_desc").text) == ["ID2", "ID9", "ID7", "–"]
    assert order(web.client.get(base + "?sort=id;DROP").text) == ["ID9", "–", "ID2", "ID7"], "чужой порядок не берётся"


def test_sort_links_keep_query_and_card_links_keep_sort(web):
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 3, "ID3 - поиск")])
    html = web.client.get(f"/projects/{pid}/defects?sort=number_asc&q=поиск").text
    assert 'aria-sort="ascending"' in html
    link = re.search(r'<a class="table-sort" href="([^"]+)">ID', html).group(1)
    assert "sort=number_desc" in link and "q=" in link
    card = re.search(r'<a href="(/projects/\d+/defects/\d+[^"]*)">ID3</a>', html).group(1)
    assert "sort=number_asc" in card.replace("&amp;", "&")
    assert '<input type="hidden" name="sort" value="number_asc">' in html
    row_id = db._scalar("SELECT id FROM hub_defects WHERE project_id = ?", (pid,))
    back = web.client.get(f"/projects/{pid}/defects/{row_id}?sort=number_asc&page=1").text
    assert re.search(r'href="/projects/\d+/defects\?[^"]*sort=number_asc', back), "карточка возвращает в каталог с порядком"


@pytest.mark.parametrize("count", [499, 500, 501])
def test_catalog_has_all_rows_across_500_boundary(web, count):
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", n, f"ID{n} - тестовый дефект") for n in range(1, count + 1)])
    base = f"/projects/{pid}/defects"
    found = []
    for page in (1, 2, 3):
        response = web.client.get(base, params={"page": page, "page_size": 200, "sort": "number_asc"})
        assert response.status_code == 200
        html = response.text
        assert f"Всего: {count}. Страница {page} из 3." in html
        found.extend(order(html))
    assert found == [f"ID{n}" for n in range(1, count + 1)]
    card = re.search(r'<a href="(/projects/\d+/defects/\d+[^\"]*)">ID401</a>', html).group(1).replace("&amp;", "&")
    assert "page=3" in card and "sort=number_asc" in card
    back = web.client.get(card).text
    back_url = re.search(r'href="(/projects/\d+/defects\?[^\"]*page=3[^\"]*)"', back).group(1).replace("&amp;", "&")
    returned = web.client.get(back_url).text
    assert '<option value="200" selected>' in returned
    assert order(returned) == [f"ID{n}" for n in range(401, count + 1)]


def test_no_numbers_form_existing_hub_defects_come_from_sync(web):
    """Формы ввода номеров дефектов через запятую нет; дефекты Hub заносит синхронизация."""
    db = web.app.state.db
    pid = project(web)
    empty = web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-import"' not in empty and 'id="hub-import-numbers"' not in empty
    assert 'id="hub-sync-start"' in empty and "«Принять состояние Hub»" in empty
    add(db, pid, [("SAST", 1, "ID1 - x")])
    html = web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-import"' not in html and 'id="hub-sync-start"' in html


def test_filters_by_kind_state_origin_with_counts_and_page_size(web):
    """«Все фильтры» над таблицей дефектов, как у находок; по умолчанию 200 строк на странице."""
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 1, "ID1 - a"), ("SCA", 2, "ID2 - b"), ("SCA", 3, "ID3 - c")])
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET origin='import', state='done' WHERE project_id=? AND number=3", (pid,))
    base = f"/projects/{pid}/defects"
    html = web.client.get(base).text
    assert 'id="defects-filters"' in html and "Все фильтры" in html
    assert re.search(r'href="[^"]*kind=SCA[^"]*">SCA <span class="chip-count">2</span>', html)
    assert order(web.client.get(base + "?kind=SAST").text) == ["ID1"]
    assert order(web.client.get(base + "?kind=SCA&sort=number_asc").text) == ["ID2", "ID3"]
    assert order(web.client.get(base + "?origin=import").text) == ["ID3"]
    assert order(web.client.get(base + "?state=done").text) == ["ID3"]
    assert order(web.client.get(base + "?kind=SAST&origin=import").text) == []
    assert order(web.client.get(base + "?kind=DROP").text) == ["ID3", "ID2", "ID1"], "неизвестный вид – без отбора"
    picked = web.client.get(base + "?kind=SCA").text
    assert "выбрано 1" in picked and "Сбросить фильтры" in picked
    assert '<option value="200" selected>' in html
    add(db, pid, [("SAST", n, f"ID{n} - x") for n in range(10, 40)])
    small = web.client.get(base + "?page_size=25&sort=number_asc").text
    assert len(order(small)) == 25 and "Страница 1 из 2" in small
    nxt = re.search(r'<a href="([^"]+)">Следующая страница', small).group(1).replace("&amp;", "&")
    assert "page_size=25" in nxt and "sort=number_asc" in nxt


def test_chip_counts_follow_other_filters_and_empty_filter_is_honest(web):
    """При виде SCA фишка «не принят» не показывает 1 (неудачная попытка SAST), когда список пуст с текстом
    «дефектов из приложения ещё нет». Числа фишек – с учётом остальных отборов; пустой отбор – «ничего не попало»."""
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 1, "ID1 - a"), ("SCA", 2, "ID2 - b")])
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state='failed' WHERE project_id=? AND number=1", (pid,))
    base = f"/projects/{pid}/defects"
    html = web.client.get(base + "?kind=SCA").text
    assert re.search(r'не принят <span class="chip-count">0</span>', html)
    assert re.search(r'SAST <span class="chip-count">1</span>', html), "число вида – по текущему состоянию (все)"
    empty = web.client.get(base + "?kind=SCA&state=failed").text
    assert "Под этот отбор ничего не попало" in empty and "Дефектов из приложения ещё нет" not in empty
    reset = re.search(r'href="([^"]*)">Сбросить фильтры и поиск</a>', empty).group(1).replace("&amp;", "&")
    assert reset.startswith(base) and "q=" not in reset and "state=" not in reset
    assert order(web.client.get(reset).text) == ["ID2", "ID1"]
    nothing = web.client.get(base + "?q=нет-такого").text  # поиск тоже снимается кнопкой
    reset = re.search(r'href="([^"]*)">Сбросить фильтры и поиск</a>', nothing).group(1).replace("&amp;", "&")
    assert "q=" not in reset and "дефекты проекта есть" not in nothing
    empty_project = project(web)
    assert "Дефектов из приложения ещё нет" in web.client.get(f"/projects/{empty_project}/defects").text
    searched = web.client.get(f"/projects/{empty_project}/defects?q=x").text
    assert "Под этот отбор ничего не попало" in searched and "дефекты проекта есть" not in searched


def test_reset_keeps_sort_and_size_and_empty_kind_has_no_chip(web):
    """Ревью 31.10: «Сбросить фильтры» сбрасывает только отборы; незавершённое занесение (вид пуст) не даёт чипа."""
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 1, "ID1 - a"), ("", None, "занесение идёт")])
    html = web.client.get(f"/projects/{pid}/defects?kind=SAST&sort=number_asc&page_size=25").text
    reset = re.search(r'<a class="btn btn-small btn-ghost" href="([^"]+)">Сбросить фильтры', html).group(1)
    reset = reset.replace("&amp;", "&")
    assert "sort=number_asc" in reset and "page_size=25" in reset and "kind=" not in reset
    kinds = re.search(r'aria-labelledby="defects-filter-kind">(.*?)</nav>', html, re.S).group(1)
    assert re.findall(r'<a class="chip[^"]*" href="[^"]*"[^>]*>([^<]*)', kinds) == ["все", "SAST "]  # «SAST » – перед числом


def test_tab_syncs_only_rows_with_pending_operations(web):
    """Ревью 31.10: показ вкладки доводит только строки с незакрытыми операциями или последствиями, не весь проект."""
    from app import hub_defects
    db = web.app.state.db
    pid = project(web)
    add(db, pid, [("SAST", 1, "ID1 - settled"), ("SAST", 2, "ID2 - update"), ("SCA", 3, "ID3 - effects"),
                  ("SCA", 4, "ID4 - creating")])
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET state='done', effects_done=1 WHERE project_id=? AND number IN (1, 2, 3)", (pid,))
        c.execute("UPDATE hub_defects SET update_op_id=99 WHERE project_id=? AND number=2", (pid,))
        c.execute("UPDATE hub_defects SET effects_done=0 WHERE project_id=? AND number=3", (pid,))
        c.execute("UPDATE hub_defects SET state='creating' WHERE project_id=? AND number=4", (pid,))
    picked = sorted(r["number"] for r in db.hub_defects_to_sync(pid, hub_defects.OPEN_STATES))
    assert picked == [2, 3, 4]
