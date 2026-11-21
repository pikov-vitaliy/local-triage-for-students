"""Сведение разделов этапа 2: вкладки проекта на всех его страницах, фильтры списка находок чипами, отметка
«Внесено в Hub» с редакцией решения, которую видела карточка."""

from __future__ import annotations

import html
import re

from test_web import create_project, prepared, web  # noqa: F401


def tabs_of(page: str) -> dict[str, str]:
    """Вкладки проекта: {подпись: число}, и какая из них текущая (ключ "current")."""
    nav = re.search(r'<nav class="tabs" aria-label="Разделы проекта">(.*?)</nav>', page, re.S)
    assert nav, "нет вкладок проекта"
    tabs = {}
    for attrs, label, count in re.findall(r'<a class="tab"([^>]*)>([^<]+?)(?: <span class="tab-count">(\d+)</span>)?'
                                          r'</a>', nav.group(1)):
        tabs[label.strip()] = count
        if 'aria-current="page"' in attrs:
            tabs["current"] = label.strip()
    return tabs


def test_project_tabs_on_every_project_page(web):
    pid = prepared(web)
    db = web.app.state.db
    total = db.count_findings(pid)["total"]
    sca_total = db.review_stats(pid)["sca"]
    sast = db.get_finding_by_hub_id(pid, "510001")["id"]
    sca = db.get_finding_by_hub_id(pid, "73001")["id"]
    pages = {f"/projects/{pid}": "Обзор", f"/projects/{pid}/findings": "Находки",
             f"/projects/{pid}/findings/{sast}": "Находки", f"/projects/{pid}/sca": "SCA",
             f"/projects/{pid}/sca/findings/{sca}": "SCA"}
    for url, current in pages.items():
        tabs = tabs_of(web.client.get(url).text)
        assert tabs["current"] == current, url
        assert tabs["Находки"] == str(total) and tabs["SCA"] == str(sca_total), url


def test_entered_marks_send_the_revision_the_card_showed(web):
    """«Внесено в Hub» и снятие отметки отправляют редакцию решения из формы карточки: отметка из устаревшей
    вкладки не ставится (409), а ответ редакцию не возвращает – форма устаревшей вкладки так и остаётся устаревшей."""
    pid = prepared(web)
    db = web.app.state.db
    for url in (f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}",
                f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"):
        card = web.client.get(url).text
        for form_id in ("entered-form", "unenter-form"):
            tag = re.search(rf'<form [^>]*id="{form_id}"[^>]*>', card).group(0)
            assert 'data-include="review-revision"' in tag and "data-ajax" in tag, (url, form_id)
        assert 'id="review-revision"' in card


def test_findings_filters_are_chip_links(web):
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}/findings?kind=SAST&reviewed=no").text
    assert 'class="filters filter-panel"' in page and "<select name=\"kind\"" not in page
    links = {html.unescape(label).strip(): (html.unescape(href), bool(current)) for href, current, label in re.findall(
        r'<a class="chip(?: is-active)?" href="([^"]+)"( aria-current="true")?>([^<]+)</a>', page)}
    base = f"/projects/{pid}/findings"
    # выбранные значения отмечены, «все» снимает только свой фильтр, другой чип группы заменяет значение
    assert links["SAST"] == (f"{base}?kind=SAST&reviewed=no", True)
    assert links["SCA"] == (f"{base}?kind=SCA&reviewed=no", False)
    assert links["любой"][0] == f"{base}?kind=SAST&reviewed=no" and links["любой"][1]
    # «да» в группах «Проверено» и «Внесено в Hub» меняют каждый свой параметр
    assert f'href="{base}?kind=SAST&amp;reviewed=yes">да</a>' in page
    assert f'href="{base}?kind=SAST&amp;reviewed=no&amp;entered=yes">да</a>' in page
    # флажок включается и выключается той же ссылкой
    flag = "проверены, но не скопированы в Hub"
    assert links[flag] == (f"{base}?kind=SAST&reviewed=no&copied=no", False)
    page = web.client.get(f"{base}?copied=no").text
    assert re.search(rf'href="{base}" aria-current="true">{flag}</a>', page)
    # подробные фильтры свёрнуты, пока ничего не выбрано; «Все» отмечено
    plain = web.client.get(base).text
    assert '<details class="filters-more" id="findings-filters">' in plain and 'aria-current="true" class="is-active">Все</a>' in plain
    assert '<details class="filters-more" id="findings-filters" open>' in page and "выбрано 1" in page
    # срочные и указания для модели – только среди готовых отборов, без дублей в фильтрах
    assert "только срочные" not in plain and "с указаниями для модели" not in plain
    # кодовая база – список с отправкой при выборе; прочие фильтры уходят скрытыми полями
    page = web.client.get(f"{base}?kind=SAST&reviewed=no").text
    form = re.search(r'<form method="get" class="filter-group" data-autosubmit>(.*?)</form>', page, re.S).group(1)
    assert '<input type="hidden" name="kind" value="SAST">' in form
    assert '<input type="hidden" name="reviewed" value="no">' in form and 'name="cb"' in form
    # по строкам таблицы ходят клавиши j и k
    assert re.search(r'<table class="table table-findings table-sticky-head" data-rows>', page)


def test_findings_list_marks_use_the_shared_badges(web):
    pid = prepared(web)
    db = web.app.state.db
    db.save_review(pid, "510001", decision="agree", final_verdict="false_positive", final_comment="", reviewed=True)
    db.mark_entered(pid, "510001", True)
    db.save_review(pid, "510004", decision="disagree", final_verdict="true_positive", final_comment="x",
                   reviewed=True)
    page = web.client.get(f"/projects/{pid}/findings?kind=SAST").text
    row = re.search(r'<tr[^>]*class="is-reviewed"[^>]*>(?:(?!</tr>).)*?510001(?:(?!</tr>).)*</tr>', page, re.S).group(0)
    assert '<span class="marks">' in row and "проверено</span>" in row and "в Hub</span>" in row
    assert "не в Hub" not in row
    row = re.search(r'<tr[^>]*class="is-reviewed"[^>]*>(?:(?!</tr>).)*?510004(?:(?!</tr>).)*</tr>', page, re.S).group(0)
    assert "проверено</span>" in row and "не в Hub</span>" in row
