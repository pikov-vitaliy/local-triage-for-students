"""Поведение рабочих таблиц через настоящие маршруты приложения."""
import re
from urllib.parse import parse_qs, urlsplit
from html import unescape
import pytest
from test_web import prepared, web  # noqa: F401 – фикстуры
from test_feeds import load_cwe


@pytest.mark.parametrize('route', ['findings','sca','components'])
def test_project_tables_have_top_and_bottom_navigation(web, route):
    pid=prepared(web)
    page=web.client.get(f'/projects/{pid}/{route}').text
    assert page.count('class="worklist-pager"') == 2
    assert 'Номер страницы' in page and 'На странице' in page
    assert page.index('class="worklist-pager"') < page.index('<table', page.index('class="worklist-pager"'))


def test_cwe_combined_filters_and_sort_controls(web, tmp_path):
    load_cwe(web,tmp_path)
    page=web.client.get('/cwe?kind=weakness&abstraction=Base&status=Stable&sort=id_desc').text
    assert page.count('class="worklist-pager"') == 2
    assert 'name="abstraction"' in page and 'name="status"' in page
    assert 'aria-sort="descending"' in page
    form=re.search(r'<form[^>]*id="cwe-filters".*?</form>',page,re.S).group()
    assert 'name="kind"' in form and 'value="weakness" selected' in form


def test_group_navigation_preserves_selection_and_separate_ids(web):
    pid=prepared(web)
    path=f'/projects/{pid}/findings'
    page=web.client.get(path+'?group_by=family&kind=SCA&sort=severity_desc').text
    assert 'worklist-groups' in page
    url=unescape(re.search(r'href="([^"]*family=[^\"]+)"',page).group(1))
    query=parse_qs(urlsplit(url).query)
    assert query['kind'] == ['SCA'] and query['sort'] == ['severity_desc']
    child=web.client.get(url).text
    assert 'К группам' in child and 'table-findings' in child


def test_components_service_sections_are_disclosures(web):
    pid=prepared(web)
    from test_sca_research_routes import build_task, kit_answer
    from test_web import ORIGIN
    manifest=build_task(web,pid)
    response=web.client.post(f'/projects/{pid}/components/answers',headers=ORIGIN,
                             data={'text':kit_answer(manifest)})
    assert response.status_code == 200
    page=response.text
    assert re.search(r'<details[^>]*id="component-task"',page)
    assert re.search(r'<details[^>]*id="component-answers"',page)
    assert not re.search(r'<details[^>]*id="component-answers"[^>]*\bopen\b',page)


def versions_project(web):
    from test_web import create_project
    from test_db import load
    from app.models import Finding
    from app.routes.components import views
    pid=create_project(web.client)
    load(web.app.state.db,pid,[Finding(hub_id=str(800+i),kind='SCA',component='org.demo:lib',
          version=str(i),build_type='maven',cvss=8.1) for i in (1,2)])
    return pid, views(web.app.state.db,pid)[0]


def snapshots(rows):
    return [dict(input_ref=r['input_ref'], expected_input_sig=r['input_sig'],
                 expected_research_sig=r['answer_sig'],expected_research_revision=r['revision'],
                 revision=r['decision']['revision'] if r['decision'] else 0) for r in rows]


def test_batch_decisions_are_atomic_and_keep_per_version_history(web):
    from app.db import DecisionStale
    pid,rows=versions_project(web)
    db=web.app.state.db
    assert callable(getattr(db,'save_decisions',None)), 'Нужен атомарный метод пакетных решений'
    entries=snapshots(rows)
    values=dict(action='keep',rationale='Проверено для обеих версий',target_version='',replacement_name='',replacement_version='',review_at='')
    bad=[dict(e) for e in entries];bad[-1]['revision']=99
    with pytest.raises(DecisionStale): db.save_decisions(pid,bad,values)
    assert db.decisions(pid) == {}
    db.save_decisions(pid,entries,values)
    assert len(db.decisions(pid)) == 2
    assert all(len(db.decision_history(pid,r['input_ref'])) == 1 for r in rows)
    with pytest.raises(DecisionStale): db.save_decisions(pid,entries,values)
    assert all(len(db.decision_history(pid,r['input_ref'])) == 1 for r in rows)


def test_batch_preview_and_apply_require_explicit_selection(web):
    import json
    from test_web import ORIGIN
    pid,rows=versions_project(web)
    path=f'/projects/{pid}/components/decisions'
    empty=web.client.post(path+'/preview',headers=ORIGIN,data={})
    assert empty.status_code == 422
    preview=web.client.post(path+'/preview',headers=ORIGIN,data={'input_ref':[r['input_ref'] for r in rows]})
    assert preview.status_code == 200
    assert all(r['version'] in preview.text for r in rows)
    payload=unescape(re.search(r'name="snapshots" value="([^"]+)"',preview.text).group(1))
    assert len(json.loads(payload)) == 2
    values={'snapshots':payload,'action':'keep','rationale':'Явное решение по выбранным версиям'}
    assert web.client.post(path+'/apply',headers=ORIGIN,data=values).status_code == 422
    response=web.client.post(path+'/apply',headers=ORIGIN,data={**values,'confirm':'1'},follow_redirects=False)
    assert response.status_code == 303
    assert len(web.app.state.db.decisions(pid)) == 2
