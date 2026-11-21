"""Рабочие сценарии каталога CAPEC без внешних запросов."""
import pytest
from html import unescape
import re
from urllib.parse import parse_qs, urlencode, urlsplit
from test_web import web, ORIGIN, create_project, upload  # noqa: F401
from capec_fixtures import capec_zip


def loaded(web):
    p=web.tmp/'capec.zip';p.write_bytes(capec_zip())
    web.app.state.feeds.load('capec',p,p.name)


@pytest.mark.parametrize('with_origin', [False, True])
def test_project_count_link_selects_findings_and_keeps_filters(web, with_origin):
    from test_db import load, sast
    from capec_fixtures import CAPEC_XML
    p = web.tmp/'capec.zip'
    p.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"', 'CWE_ID="89"')))
    web.app.state.feeds.load('capec', p, p.name)
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sast('demo-1'), sast('demo-2'), sast('demo-low', severity='low')])
    query = {'finding_severity': 'high', 'sort': 'name_desc', 'page_size': '25'}
    if with_origin:
        query['origin'] = f'/projects/{pid}/findings?kind=SAST'
    response = web.client.get(f'/projects/{pid}/capec?' + urlencode(query))
    link = unescape(re.search(r'<td[^>]*><a[^>]*href="([^"]+)"[^>]*>2</a></td>', response.text).group(1))
    params = parse_qs(urlsplit(link).query)
    assert params.get('scenario') == ['CAPEC-2099']
    assert params['finding_severity'] == ['high']
    assert params['sort'] == ['name_desc']
    assert params['page_size'] == ['25']
    assert urlsplit(link).fragment == 'source-findings'
    response = web.client.get(link)
    assert response.status_code == 200
    assert 'Исходные находки · CAPEC-2099 · 2' in response.text
    assert 'demo-1' in response.text and 'demo-2' in response.text and 'demo-low' not in response.text
    clear = unescape(re.search(r'<a[^>]*id="clear-scenario"[^>]*href="([^"]+)"', response.text).group(1))
    assert 'scenario' not in parse_qs(urlsplit(clear).query)
    assert parse_qs(urlsplit(clear).query)['finding_severity'] == ['high']


def test_selected_scenario_with_no_matches_explains_empty_list(web):
    loaded(web)
    pid = create_project(web.client)
    response = web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099')
    assert 'Исходные находки · CAPEC-2099 · 0' in response.text
    assert 'Для этого сценария в текущей выборке находок нет.' in response.text
    response = web.client.get(f'/projects/{pid}/capec')
    assert 'id="source-findings"' not in response.text


def test_view_members_link_passes_query_parameters_once(web):
    loaded(web)
    response = web.client.get('/capec/1000')
    link = unescape(re.search(r'href="([^"]+)">Открыть состав представления', response.text).group(1))
    params = parse_qs(urlsplit(link).query)
    assert params.get('view') == ['CAPEC-1000']
    assert params.get('include_retired') == ['1']
    response = web.client.get(link)
    assert 'Demo Injection' in response.text and 'Demo Parent' in response.text
    assert 'Retired Demo' not in response.text


def test_empty_catalog_and_missing_detail(web):
    r=web.client.get('/capec')
    assert r.status_code==200 and 'capec_latest.zip' in r.text
    assert web.client.get('/capec/66').status_code==404


def test_summary_numbers_are_filters_with_the_same_count(web):
    """Число сводки – ссылка, таблица показывает ровно столько записей."""
    loaded(web)
    page = web.client.get('/capec').text
    seen = 0
    for label in ('Attack Patterns', 'Categories', 'Views'):
        link = re.search(r'<a class="stat stat-filter[^"]*" href="([^"]+)"[^>]*><span class="stat-label">' + label + r'</span><span class="stat-value">(\d+)</span>', page)
        assert link, label
        target = web.client.get(unescape(link.group(1)).split('#')[0]).text
        assert f'из {link.group(2)}</strong>' in target, (label, link.group(2))
        assert 'is-active' in target.split(f'<span class="stat-label">{label}<')[0].rsplit('<a class="stat', 1)[1]
        seen += 1
    assert seen == 3


def test_project_summary_counts_its_own_scenarios_and_filters_its_table(web):
    """Ревью dev8: на странице проекта число считается по сценариям его находок и отбирает его же таблицу."""
    from test_db import load, sast
    from capec_fixtures import CAPEC_XML
    p = web.tmp/'capec.zip'
    p.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"', 'CWE_ID="89"')))
    web.app.state.feeds.load('capec', p, p.name)
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sast('demo-1'), sast('demo-low', severity='low')])
    page = web.client.get(f'/projects/{pid}/capec?finding_severity=high').text
    link = re.search(r'<a class="stat stat-filter[^"]*" href="([^"]+)"[^>]*><span class="stat-label">Attack Patterns</span><span class="stat-value">(\d+)</span>', page)
    assert link and int(link.group(2)) > 0
    url = unescape(link.group(1))
    assert url.startswith(f'/projects/{pid}/capec?') and 'finding_severity=high' in url and url.endswith('#capec-results')
    target = web.client.get(url.split('#')[0]).text
    assert f'из {link.group(2)}</strong>' in target
    assert '<span class="stat-label">Categories<' not in page, 'вид без сценариев проекта не показывается'
    assert 'id="capec-whole-catalog"' in page
    narrowed = web.client.get(url.split('#')[0] + '&has_flow=yes').text
    assert 'aria-current="true"' not in narrowed.split('class="stats"')[1].split('</section>')[0], 'другой отбор – число не активно'


def test_cvss_bounds_narrow_the_findings_of_the_project(web):
    """Ревью dev8: границы CVSS в отборе находок проекта не применялись, выборка оставалась прежней."""
    from test_db import load, sca
    from capec_fixtures import CAPEC_XML
    p = web.tmp/'capec.zip'
    p.write_bytes(capec_zip(CAPEC_XML))
    web.app.state.feeds.load('capec', p, p.name)
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sca('low', 4.0), sca('high', 9.0)])

    def total(query):
        page = web.client.get(f'/projects/{pid}/capec{query}')
        assert page.status_code == 200
        return int(re.search(r'Находок в выборке</span><span class="stat-value">(\d+)<', page.text).group(1))
    assert total('') == 2
    assert total('?cvss_min=8') == 1
    assert total('?cvss_max=5') == 1
    assert total('?cvss_min=9.5') == 0


def test_catalog_search_filters_and_full_card(web):
    loaded(web)
    r=web.client.get('/capec')
    assert r.status_code==200
    assert 'Demo Injection' in r.text and 'Retired Demo' not in r.text
    assert r.text.count('aria-label="Страницы таблицы:')==2
    # число каталога и число строк расходятся из-за скрытых устаревших: подпись это называет и ведёт к ним
    note=r.text.split('id="capec-hidden-note">',1)[1].split('</span>',1)[0]
    assert 'скрыто: 1' in note and 'include_retired=1' in note
    shown=web.client.get('/capec?include_retired=1').text
    assert 'Retired Demo' in shown and 'id="capec-show-retired"' not in shown
    r=web.client.get('/capec?status=Deprecated')
    assert 'Retired Demo' in r.text and 'Demo Injection' not in r.text
    r=web.client.get('/capec?q=CWE-2099')
    assert 'Demo Injection' in r.text and 'Demo Parent' not in r.text
    r=web.client.get('/capec/capec-02099?back=%2Fcapec%3Fq%3Ddemo')
    assert r.status_code==200
    assert 'Execution Flow' in r.text and 'Observe a test.' in r.text
    assert 'Future Field' in r.text and 'Must remain readable.' in r.text
    assert '&lt;script&gt;demo&lt;/script&gt;' in r.text
    assert 'href="/capec?q=demo"' in r.text
    assert 'Demo source' in r.text
    assert web.client.get('/capec/2099?back=https://example.org/').status_code==200
    assert web.client.get('/capec/2101').status_code==200
    r=web.client.get('/capec?taxonomy=__empty__')
    assert 'Demo Parent' in r.text and 'Demo Injection' not in r.text


def test_graph_and_implicit_views(web):
    loaded(web)
    r=web.client.get('/capec?view=1000')
    assert r.status_code==200 and 'Demo Injection' in r.text and 'Demo Parent' in r.text
    r=web.client.get('/capec?view=658')
    assert 'Demo Injection' in r.text and 'Demo Parent' not in r.text
    assert web.client.get('/capec?severity=UnknownValue').status_code==400
    assert '<a class="rule-link" href="/capec/CAPEC-1000?' in web.client.get('/capec?q=CAPEC-1000').text


def test_feed_card_names_correct_archive(web):
    r=web.client.get('/feeds')
    assert 'feed-capec-file' in r.text and 'capec_latest.zip' in r.text
    assert '/capec' in r.text


def test_project_context_preserves_each_finding(web):
    from hub_fixtures import make_hub_xlsx
    loaded(web)
    pid=create_project(web.client)
    upload(web.client,pid,make_hub_xlsx(web.tmp/'hub.xlsx'))
    # Два различных исходных ID с общей CWE; двойной путь одной находки не удваивает её счёт.
    db=web.app.state.db
    for row in db.list_findings(pid,limit=100)[0]:
        raw=dict(row['data']);raw['cwe']=['CWE-2099','CWE-2100']
        import json
        with db._tx() as conn:conn.execute('UPDATE findings SET data_json=? WHERE id=?',(json.dumps(raw),row['id']))
    r=web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099')
    assert r.status_code==200 and 'Исходные находки' in r.text
    assert '510001' in r.text and '510004' in r.text
    first=db.list_findings(pid,limit=1)[0][0]
    r=web.client.get(f'/projects/{pid}/findings/{first["id"]}')
    assert 'Связанные сценарии атак' in r.text and 'CAPEC-2099' in r.text
    response=web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099&finding_kind=SAST&finding_severity=high')
    assert response.status_code==200 and '510001' in response.text and '510004' not in response.text
    assert 'finding_kind=SAST' in response.text
    assert web.client.get(f'/projects/{pid}/capec?cvss_min=8&cvss_max=2').status_code==400


def test_source_findings_follow_table_page_size(web):
    from test_db import load, sast
    from capec_fixtures import CAPEC_XML
    p = web.tmp/'capec.zip'
    p.write_bytes(capec_zip(CAPEC_XML.replace('CWE_ID="2099"', 'CWE_ID="89"')))
    web.app.state.feeds.load('capec', p, p.name)
    pid = create_project(web.client)
    load(web.app.state.db, pid, [sast(f'demo-{n:02d}') for n in range(30)])
    whole = web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099').text
    assert 'Страница 1 из 1' in whole and whole.count('· SAST ·') == 30, 'по умолчанию 200'
    first = web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099&page_size=25').text
    assert 'Страница 1 из 2' in first and first.count('· SAST ·') == 25
    second = web.client.get(f'/projects/{pid}/capec?scenario=CAPEC-2099&page_size=25&finding_page=2').text
    assert 'Страница 2 из 2' in second and second.count('· SAST ·') == 5
