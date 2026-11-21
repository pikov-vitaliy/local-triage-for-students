"""Регрессии ежедневной работы: возврат, порядок очереди и сроки решений."""
from datetime import date, timedelta
from html import unescape
import re
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import pytest

from app import sca_research as research
from app.models import Finding
from test_db import load, sast
from test_feeds import load_cwe
from test_web import create_project, prepared, web  # noqa: F401 – фикстуры


def hrefs(text):
    return [unescape(x) for x in re.findall(r'href="([^"]+)"', text)]


def identified_link(text, ident):
    found = re.search(r'<a[^>]*id="' + ident + r'"[^>]*href="([^"]+)"', text)
    assert found is not None, f'Нет ссылки {ident}'
    return unescape(found.group(1))


@pytest.mark.parametrize('offset,expected', [(-1, True), (0, True), (1, False)])
def test_review_date_enters_queue_independently_of_unchanged_facts(offset, expected):
    due = (date.today() + timedelta(days=offset)).isoformat()
    row = research.row_view({'name': 'demo', 'ecosystem': 'maven', 'version': '1.0'},
                            {'payload': {}, 'answer_sig': 'same'},
                            {'research_sig': 'same', 'action': 'accept_risk', 'review_at': due}, 'current')
    assert row['decision_stale'] is expected
    assert bool(research.filter_rows([row], {'stale': '1'})) is expected
    if expected:
        assert 'review_date' in row['decision_reasons']


def test_review_date_still_applies_without_research():
    row = research.row_view({'name': 'demo'}, None,
                            {'action': 'investigate', 'review_at': '2000-01-01'}, 'current')
    assert row['decision_stale']
    assert row['decision_reasons'] == ['review_date']


@pytest.mark.parametrize('sort,direction', [('severity_asc', 'next'), ('severity_desc', 'prev')])
def test_card_walk_uses_the_table_order(web, sort, direction):
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sast('DEMO-H', severity='high'), sast('DEMO-L', severity='low'),
                                sast('DEMO-M', severity='medium')])
    rows, _ = web.app.state.db.list_findings(pid)
    by_name = {r['hub_id']: r['id'] for r in rows}
    back = f'/projects/{pid}/findings?kind=SAST&sort={sort}&page_size=25'
    params = urlencode({'kind': 'SAST', 'sort': sort, 'back': back})
    page = web.client.get(f'/projects/{pid}/findings/{by_name["DEMO-L"]}?{params}').text
    target = identified_link(page, 'nav-' + direction)
    assert urlsplit(target).path.endswith('/' + str(by_name['DEMO-M']))
    assert parse_qs(urlsplit(target).query)['back'] == [back]


def test_cwe_keeps_source_card_and_filtered_queue(web, tmp_path):
    pid = create_project(web.client)
    item = sast('DEMO-42')
    item.cwe = ['CWE-2099']
    load(web.app.state.db, pid, [item])
    load_cwe(web, tmp_path)
    rows, _ = web.app.state.db.list_findings(pid, kind='SAST')
    fid = rows[0]['id']
    queue = f'/projects/{pid}/findings?kind=SAST&sort=severity_asc&page=3&page_size=25'
    card = f'/projects/{pid}/findings/{fid}?' + urlencode({'kind': 'SAST', 'sort': 'severity_asc', 'back': queue})
    page = web.client.get(card).text
    cwe = next(h for h in hrefs(page) if urlsplit(h).path == '/cwe/CWE-2099')
    assert parse_qs(urlsplit(cwe).query).get('origin') == [card]
    article = web.client.get(cwe).text
    assert 'id="task-context"' in article
    assert unquote(identified_link(article, 'task-origin')) == unquote(card)
    assert identified_link(article, 'task-queue') == queue
    for h in hrefs(article):
        if urlsplit(h).path.startswith(('/cwe/', '/capec/')):
            assert parse_qs(urlsplit(h).query).get('origin') == [card]
    assert 'id="task-context"' not in web.client.get('/cwe/CWE-2099').text


def test_component_entry_from_menu_keeps_version_and_queue(web):
    from app.routes.components import views
    pid = create_project(web.client)
    load(web.app.state.db, pid, [Finding(hub_id='DEMO-SCA', kind='SCA', component='org.demo:parser',
                                        version='1.2.0', build_type='maven')])
    row = views(web.app.state.db, pid)[0][0]
    queue = f'/projects/{pid}/components?sort=name_desc&group_by=family&page_size=25'
    card = f'/projects/{pid}/components/{quote(row["input_ref"])}?' + urlencode({'back': queue})
    page = web.client.get(card).text
    catalog = next(h for h in hrefs(page) if urlsplit(h).path == '/cwe')
    article = web.client.get(catalog).text
    assert unquote(identified_link(article, 'task-origin')) == unquote(card)
    assert identified_link(article, 'task-queue') == queue
    assert 'org.demo:parser@1.2.0' in article


def test_component_card_can_reach_decision_from_first_screen(web):
    from test_operator_tables import versions_project
    pid, rows = versions_project(web)
    page = web.client.get(f'/projects/{pid}/components/{rows[0]["input_ref"]}').text
    assert 'href="#operator-decision"' in page
    assert 'id="component-draft-status"' in page
    assert 'id="save-component-next"' in page


def test_component_save_next_keeps_queue_and_individual_decisions(web):
    from test_operator_tables import versions_project
    from test_web import ORIGIN
    pid, rows = versions_project(web)
    back = f'/projects/{pid}/components?decision=unset&sort=name_asc&page_size=25'
    path = f'/projects/{pid}/components/{rows[0]["input_ref"]}'
    page = web.client.get(path + '?' + urlencode({'back': back})).text
    values = {k: unescape(v) for k, v in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', page)}
    values.update(action='keep', rationale='Проверено только для этой версии.', after='next')
    result = web.client.post(path + '/decision?' + urlencode({'back': back}), data=values,
                             headers=ORIGIN, follow_redirects=False)
    assert result.status_code == 303
    assert rows[1]['input_ref'] in unquote(result.headers['location'])
    assert parse_qs(urlsplit(result.headers['location']).query)['back'] == [back]
    assert len(web.app.state.db.decisions(pid)) == 1


def test_reference_chain_preserves_origin_without_nested_return_urls(web, tmp_path):
    from feed_fixtures import CWE_FULL_XML
    from test_capec_routes import loaded
    pid = create_project(web.client)
    item = sast('DEMO-42'); item.cwe = ['CWE-2099']
    load(web.app.state.db, pid, [item])
    load_cwe(web, tmp_path, CWE_FULL_XML.replace('CAPEC_ID="209"', 'CAPEC_ID="2099"'))
    loaded(web)
    fid = web.app.state.db.list_findings(pid)[0][0]['id']
    origin = f'/projects/{pid}/findings/{fid}?kind=SAST'
    target = '/cwe/CWE-2099?' + urlencode({'origin': origin})
    for _ in range(8):
        cwe = web.client.get(target).text
        capec = next(h for h in hrefs(cwe) if urlsplit(h).path == '/capec/CAPEC-2099')
        detail = web.client.get(capec).text
        assert identified_link(detail, 'task-origin') == origin
        target = next(h for h in hrefs(detail) if urlsplit(h).path == '/cwe/CWE-2099')
        assert len(target) < 600
    via = parse_qs(urlsplit(target).query)['via'][0]
    assert 'origin=' not in via and 'via=' not in via


def test_journal_return_keeps_filters(web):
    db = web.app.state.db
    pid = db.create_project('Статистика')
    rid = db.create_run(pid, 'demo-model', 'all', 'p1', [])
    listing = web.client.get('/journal?model=demo-model&sort=oldest').text
    detail_url = next(h for h in hrefs(listing) if urlsplit(h).path == f'/journal/{rid}')
    detail = web.client.get(detail_url).text
    back = next(h for h in hrefs(detail) if urlsplit(h).path == '/journal' and 'model=' in h)
    assert parse_qs(urlsplit(back).query)['model'] == ['demo-model']


def test_continue_uses_same_sorted_queue_as_table(web):
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sast('DEMO-H', severity='high'), sast('DEMO-L', severity='low')])
    page = web.client.get(f'/projects/{pid}/findings?kind=SAST&sort=severity_asc').text
    head = page.split('<table')[0]
    target = next(h for h in hrefs(head) if re.fullmatch(fr'/projects/{pid}/findings/[0-9]+', urlsplit(h).path))
    assert parse_qs(urlsplit(target).query)['sort'] == ['severity_asc']
    assert 'back' in parse_qs(urlsplit(target).query)


def test_legacy_sca_save_preserves_return_to_filtered_list(web):
    from test_db import sca
    from test_web import ORIGIN
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sca('DEMO-SCA')])
    fid = web.app.state.db.list_findings(pid)[0][0]['id']
    back = f'/projects/{pid}/sca?cvss_min=7&sort=cvss_desc&page_size=25'
    path = f'/projects/{pid}/sca/findings/{fid}'
    page = web.client.get(path + '?' + urlencode({'back': back})).text
    values = {k: unescape(v) for k, v in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', page)}
    values.update(decision='disagree', final_verdict='uncertain', comment='Нужно уточнить применение.', action='save')
    target = unescape(re.search(r'<form[^>]*action="([^"]+)"[^>]*id="review-form"', page).group(1))
    assert parse_qs(urlsplit(target).query).get('back') == [back]
    result = web.client.post(target, data=values, headers=ORIGIN, follow_redirects=False)
    assert result.status_code == 303, result.text
    assert parse_qs(urlsplit(result.headers['location']).query).get('back') == [back]
