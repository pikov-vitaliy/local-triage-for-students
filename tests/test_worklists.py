"""Списки оператора: сортировка всей выборки, группы без потери идентичности, навигация."""
from app import worklists as w


def test_family_separates_ecosystems_and_keeps_versions():
    rows = [dict(ecosystem=e, component='lib', version=v, id=i) for i,(e,v) in
            enumerate([('maven','1'),('maven','2'),('npm','1')])]
    view = w.table(rows, {'group_by':'family'}, path='/x', kind='sca')
    assert [g['count'] for g in view['groups']] == [2,1]
    group = view['groups'][0]
    child = w.table(rows, {'family':group['token']}, path='/x', kind='sca')
    assert [r['id'] for r in child['rows']] == [0,1]
    assert rows[0]['version'] == '1'


def test_pagination_after_grouping_and_preserves_filters():
    rows = [dict(ecosystem='npm', name=f'lib{i//2}', version=str(i), id=i) for i in range(120)]
    view = w.table(rows, {'group_by':'family','page_size':'25','page':'2','q':'имя & версия'}, path='/x', kind='components')
    assert (view['page'],view['pages'],view['total'],view['all_total']) == (2,3,60,120)
    assert len(view['groups']) == 25
    assert 'group_by=family' in view['next'] and 'page=3' in view['next']
    assert '%26' in view['next']
    assert w.table([], {}, path='/x')['start'] == 0
    fallback = w.table(rows, {'page':'999999999999999999999','page_size':'-1'}, path='/x')
    assert (fallback['size'], fallback['page']) == (200, 1)
    assert w.table(rows, {'page':'999999999999999999999','page_size':'-1'}, path='/x', default_size=50)['page'] == 3


def test_severity_unknown_last_both_directions_and_numeric():
    rows = [dict(id=i,kind='SCA',cvss=v) for i,v in enumerate([None,2.0,10.0,7.1,7.9])]
    assert [r['id'] for r in w.sort_findings(rows,'severity_desc')] == [2,4,3,1,0]
    assert [r['id'] for r in w.sort_findings(rows,'severity_asc')] == [1,3,4,2,0]


def test_rules_with_no_name_are_not_combined():
    rows=[dict(id=i,kind='SAST',data={'rule':'','tool':'x'}) for i in (1,2)]
    assert w.family(rows[0],'findings')[0] != w.family(rows[1],'findings')[0]
    rows[0]['data']['rule'] = rows[1]['data']['rule'] = 'same'
    assert w.family(rows[0],'findings')[0] == w.family(rows[1],'findings')[0]
    rows[1]['data']['tool'] = 'other'
    assert w.family(rows[0],'findings')[0] != w.family(rows[1],'findings')[0]


def test_cvss_two_does_not_invent_critical_level():
    assert w.severity_key({'kind':'SCA','cvss':10,'data':{'extra':{'CVSS version':'2.0'}}})[0] == 3
    assert w.severity_key({'kind':'SCA','cvss':10,'data':{'extra':{'CVSS version':'3.1'}}})[0] == 4


def test_return_url_ignores_malformed_external_address():
    from types import SimpleNamespace
    assert w.return_url(SimpleNamespace(query_params={'back':'http://['}),'/projects/1/components') == '/projects/1/components'


def test_default_page_size_is_200():
    rows = [dict(id=i) for i in range(205)]
    view = w.table(rows, {}, path='/x')
    assert (view['size'], len(view['rows']), view['pages']) == (200, 200, 2)
    assert 'page_size=200' in view['next']
