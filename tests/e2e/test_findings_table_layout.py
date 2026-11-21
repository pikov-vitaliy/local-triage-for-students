"""Таблица находок не «едет» (проект после повторного разбора): у находки с двумя плашками
модели («истинная · 100 %» и «разборов: 2») и отметками решения («проверено», «в Hub») колонка «Место» не сжимается
до двух букв – имя файла читается в одну-две строки, без горизонтальной прокрутки страницы. На телефоне строка
таблицы – карточка: место на всю ширину, отметки решения не выходят за край."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from e2e_support import create_demo, no_horizontal_scroll, open_page, run_triage, wait_run_done

pytestmark = pytest.mark.e2e

CELLS = """() => [...document.querySelectorAll('tbody tr')].map(tr => {
  const place = tr.querySelector('td.col-place'); const file = place && place.querySelector('.place-file');
  if (!place || !file) return null;
  const line = parseFloat(getComputedStyle(file).lineHeight) || 20;
  const marks = tr.querySelector('td.col-decision .marks');
  return {width: place.getBoundingClientRect().width, lines: Math.round(file.getBoundingClientRect().height / line),
          marks: marks ? marks.getBoundingClientRect().right : null};
}).filter(Boolean)"""


def decide_first_sast(page, pid: int) -> None:
    """Решение по одной находке SAST: ложное срабатывание (n), комментарий, копирование (c), «Внесено в Hub» (h)."""
    page.goto(f"/projects/{pid}/findings")
    page.locator("tbody tr").filter(has=page.locator("td.col-kind", has_text="SAST")).first.locator("td.col-id a").click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+"))
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("n")
    expect(page.locator("#reviewed-box")).to_be_checked()
    page.fill("#comment", "Значение берётся из заранее заданной строки.")
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.keyboard.press("c")
    expect(page.locator("#mark-entered")).to_be_visible()
    page.keyboard.press("h")
    expect(page.locator("#entered-badge")).to_be_visible()


@pytest.mark.parametrize("size", [(960, 800), (1024, 768), (1280, 800), (1440, 900), (1920, 1080), (390, 844)])
def test_place_column_stays_readable_with_several_badges(browser, app_server, size):
    width, height = size
    context, page, watch = open_page(browser, app_server.url, width=width, height=height)
    try:
        pid = create_demo(page)
        run_triage(page, pid)
        # повторный разбор всех находок: у каждой – два ответа модели, в колонке «Модель» – плашка «разборов: 2»
        page.goto(f"/projects/{pid}#step3")
        page.check('input[name="fresh"]')
        page.get_by_role("button", name="Запустить триаж", exact=True).click()
        page.wait_for_url(re.compile(r"/runs/\d+$"))
        wait_run_done(page)
        decide_first_sast(page, pid)
        page.goto(f"/projects/{pid}/findings")  # режим «Все»: и находки SCA с длинными координатами компонентов
        assert page.locator(".col-model .badge-muted, .col-model .badge-warn").count() > 0, "плашки разборов есть"
        cells = page.evaluate(CELLS)
        assert cells, "в таблице есть строки с местом"
        decided = [c for c in cells if c["marks"] is not None]
        assert decided, "у решённой находки в колонке «Моё решение» – отметки"
        floor = 250 if width < 761 else 140  # на телефоне место – на всю ширину карточки
        assert all(c["width"] >= floor for c in cells), cells
        # 960–1024 px: таблица со всеми плашками шире контейнера и прокручивается вбок внутри себя (заголовки тогда не
        # закрепляются – test_headers_stick_only_when_table_fits); «Место» держит свой минимум, имя файла – до трёх
        # строк. На рабочих экранах (от 1280) и на телефоне – до двух строк, отметки решения в пределах окна.
        narrow = 761 <= width < 1280
        assert all(c["lines"] <= (3 if narrow else 2) for c in cells), cells
        if not narrow:
            assert all(c["marks"] <= width for c in decided), decided
        assert no_horizontal_scroll(page)
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
