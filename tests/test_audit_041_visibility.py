"""Подтверждения и история компонентов не зависят от размера страницы."""
from app import sca, sca_research as research
from app.routes import components
from test_web import web, ORIGIN, create_project  # noqa: F401
from test_sca_research_routes import project_with_sca, build_task, kit_answer, upload_answer, decide

def test_doubt_key_distinguishes_ecosystems():
    assert sca.doubt_key('folder/lib','1.0','npm') != sca.doubt_key('folder/lib','1.0','maven')

def test_confirmation_preserves_components_beyond_visible_200(web,monkeypatch):
    pid=create_project(web.client);db=web.app.state.db
    rows=[{'component':f'folder/lib{i:03}','version':'1.0','ecosystem':'npm'} for i in range(201)]
    monkeypatch.setattr(db,'sca_components',lambda _pid:rows)
    _,excluded=sca.package_report(rows)
    keys=[x['key'] for x in excluded if x.get('doubtful')]
    assert len(keys)==201
    db.set_sca_confirmed(pid,keys)
    response=web.client.post(f'/projects/{pid}/sca/package/confirm',headers=ORIGIN,data={'item':keys[:199]},follow_redirects=False)
    assert response.status_code==303
    assert keys[200] in db.sca_confirmed(pid)
    assert keys[199] not in db.sca_confirmed(pid)

def test_historical_decision_visible_outside_recent_task_list(web,monkeypatch):
    pid=project_with_sca(web);manifest=build_task(web,pid);ref=manifest['rows'][0]['input_ref']
    assert upload_answer(web,pid,kit_answer(manifest)).status_code==303
    assert decide(web,pid,ref).status_code==303
    db=web.app.state.db
    monkeypatch.setattr(components,'_live_rows',lambda *a:[])
    monkeypatch.setattr(db,'tasks',lambda *a,**k:[])
    views,_=components.views(db,pid)
    view=next((r for r in views if r['input_ref']==ref),None)
    assert view and view['decision'] and view['export_missing']

def test_unsafe_saved_evidence_is_not_rendered_as_a_link():
    assert research._evidence_view({'url':'http://127.0.0.1/x'})['url']==''

def test_unknown_version_order_exposed_to_operator():
    source={'ecosystem':'custom','version':'vendor1'}
    view=research.row_view(source,{'payload':{'latest_stable_release':{'version':'vendor2'},'update_status':'update_available'}},None,'current')
    assert view['version_order_unchecked']

def test_legacy_confirmation_does_not_cross_ecosystems():
    item={'component':'folder/lib','version':'1.0','ecosystem':'npm'}
    old={'folder/lib@1.0'}
    assert sca.doubt_key('folder/lib','1.0','npm') in sca.confirmed_keys([item],old)
    assert sca.doubt_key('folder/lib','1.0','npm') not in sca.confirmed_keys([item,{**item,'ecosystem':'pypi'}],old)
