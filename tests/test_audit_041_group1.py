"""Приёмка первой группы: полный комплект, устойчивый состав и безопасный отказ."""
import copy
import json

import pytest

from app import sca_contract as sc, sca_research as research
from test_sca_research_contract import answer, check, row
from test_sca_research_routes import build_task, kit_answer, project_with_sca, upload_answer
from test_sca_research_transactions import loaded, save_task  # noqa: F401 – loaded: фикстура
from test_sca_research import answer_for, hub_export, load_export
from test_sca_research_transactions import HUB_ROWS
from test_web import web  # noqa: F401


def test_one_source_can_cover_different_purposes():
    rows=[row(),row(1)]
    for item in rows:
        item['research_coverage'][-1]['source']=item['research_coverage'][0]['source']
    report=check(answer(*rows))
    assert report.ok,report.errors


def test_completed_template_accepts_one_registry_for_identity_and_releases():
    items=[]
    for index in range(2):
        filled=row(index)
        source={'input_ref':filled['input_ref'],'ecosystem':filled['ecosystem'],
                'component':filled['component'],'version':filled['current_version']}
        item=sc.empty_row(source)
        item.update(filled)
        identity=copy.deepcopy(item['research_coverage'][-1])
        identity['purpose']='releases'
        item['research_coverage'].append(identity)
        items.append(item)
    report=check(answer(*items))
    assert report.ok,report.errors


@pytest.mark.parametrize('field',['id','evidence_ref'])
@pytest.mark.parametrize('bad',[[],{}])
def test_structured_identifier_is_a_contract_error(field,bad):
    item=row()
    target=item['public_findings'][0] if field=='id' else item['evidence'][0]
    target[field]=bad
    report=check(answer(item,row(1)))
    assert not report.ok
    assert any(e['path'].endswith(field) for e in report.errors)


def test_composition_is_independent_of_order():
    rows,_=research.task_rows([
        {'ecosystem':'npm','component':'alpha','version':'1.0.0','findings':1},
        {'ecosystem':'npm','component':'beta','version':'1.0.0','findings':1}])
    assert research.composition(rows)==research.composition(list(reversed(rows)))


def test_saved_manifest_digest_is_not_rewritten_by_new_ordering():
    rows,_=research.task_rows([{'ecosystem':'npm','component':'alpha','version':'1.0.0','findings':1}])
    task={'task_id':'t-legacy','manifest_sha256':'a'*64}
    assert research.manifest(task,rows)['manifest_sha256']==task['manifest_sha256']


def test_legacy_manifest_still_accepts_its_answer_after_cvss_reordering(web):
    pid=project_with_sca(web);manifest=build_task(web,pid);db=web.app.state.db
    task=db.current_task(pid);rows=db.task_rows(task['id'])
    old_digest=research.sha256(sc.canonical([research.row_text(item) for item in reversed(rows)]))
    with db._tx() as c:c.execute('UPDATE sca2_tasks SET manifest_sha256=? WHERE id=?',(old_digest,task['id']))
    assert build_task(web,pid)['manifest_sha256']==old_digest
    current=web.client.get(f'/projects/{pid}/components/task.json').json()
    assert current['task_id']==manifest['task_id']
    body=json.loads(kit_answer(current));body['validator_version']='sca-contract/2.0.1'
    assert upload_answer(web,pid,json.dumps(body)).status_code==303


def test_cvss_only_reimport_keeps_existing_task_and_accepts_its_answer(loaded):
    db,pid,tmp=loaded
    task,rows=save_task(db,pid)
    changed=[dict(r,**{'CVSS score':str(1+index*4)}) for index,r in enumerate(HUB_ROWS)]
    load_export(db,pid,hub_export(tmp/'scores.xlsx',changed))
    same,_=save_task(db,pid)
    assert same['id']==task['id']
    result=db.save_research(pid,task['id'],research.research_results(answer_for(rows),rows))
    assert result['saved']==len(rows)


def test_support_observation_date_is_not_a_material_change():
    first=row();second=copy.deepcopy(first)
    second['support_status']['as_of']='2026-10-17'
    assert research.content_sig(first)==research.content_sig(second)


def test_refreshed_dates_do_not_create_another_revision(loaded):
    db,pid,_=loaded
    task,rows=save_task(db,pid)
    original=answer_for(rows)
    db.save_research(pid,task['id'],research.research_results(original,rows))
    changed=copy.deepcopy(original)
    for item in changed['rows']:
        item['support_status']['as_of']='2026-10-17'
        for ev in item['evidence']:ev['checked_at']='2026-10-17'
        for cov in item['research_coverage']:cov['checked_at']='2026-10-17'
    result=db.save_research(pid,task['id'],research.research_results(changed,rows))
    assert result['saved']==0 and result['unchanged']==len(rows)
    assert {x['revision'] for x in db.research(pid).values()}=={1}


def test_error_page_names_the_validator_and_returns_422(web):
    pid=project_with_sca(web);manifest=build_task(web,pid)
    response=upload_answer(web,pid,kit_answer(manifest,tamper='ast'))
    assert response.status_code==422
    assert sc.VALIDATOR_VERSION in response.text


def test_structured_identifier_route_returns_422_without_writing(web):
    pid=project_with_sca(web);manifest=build_task(web,pid)
    body=json.loads(kit_answer(manifest));body['rows'][0]['evidence'][0]['evidence_ref']=[]
    response=upload_answer(web,pid,json.dumps(body))
    assert response.status_code==422
    assert not web.app.state.db.research(pid)
