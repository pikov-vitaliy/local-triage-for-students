"""Регрессии проверки применимости, источников и пределов ответа."""
import copy
import json
import pytest
from app import sca_contract as sc
from test_sca_research_contract import TASK, TODAY, answer, row

def check(item, **kwargs):
    task=copy.deepcopy(TASK);task['rows']=task['rows'][:1];task['row_count']=1
    return sc.validate_answer(json.dumps(answer(item)),task,today=TODAY,**kwargs)

@pytest.mark.parametrize('current,applies,introduced,fixed,last',[
    ('9.0.83','no','9.0.0.M1','9.0.99',None),
    ('9.0.83','yes','9.0.0.M1','9.0.83',None),
    ('9.0.83','no','9.0.0.M1',None,'9.0.83'),
])
def test_range_contradiction(current,applies,introduced,fixed,last):
    item=row();f=item['public_findings'][0];f['applies']=applies
    f['ranges']=[dict(introduced=introduced,fixed=fixed,**({'last_affected':last} if last else {}))]
    item['package_status']=sc.row_status(item)
    report=check(item)
    assert any(e['code']=='SCA-A001' and 'ranges' in e['path'] for e in report.errors),report.text()

def test_unknown_range_requires_unknown_and_gap():
    item=row();item['public_findings'][0]['ranges'][0]['introduced']='vendor-unknown'
    assert 'SCA-A001' in check(item).codes()
    item['public_findings'][0]['applies']='unknown';item['package_status']='incomplete'
    item['gaps'].append({'code':'APPLICABILITY_UNCLEAR','text':'Порядок версии поставщика неизвестен'})
    assert check(item).ok,check(item).text()

def test_up_to_date_without_release_evidence_rejected():
    item=row();item['latest_stable_release'].update(version=None,source_refs=[]);item['update_status']='up_to_date'
    assert any('latest_stable_release.source_refs' in e['path'] for e in check(item).errors)

def test_empty_ecosystem_cannot_be_invented():
    task=copy.deepcopy(TASK);task['rows']=task['rows'][:1];task['rows'][0]['ecosystem']='';task['row_count']=1
    report=sc.validate_answer(json.dumps(answer(row())),task,today=TODAY)
    assert 'SCA-C002' in report.codes()

@pytest.mark.parametrize('url',['http://127.0.0.1/x','https://10.0.0.1/x','https://good.example@evil.example/x','http://127.0.0x0.1/x','https://%65xample.com/x'])
def test_evidence_requires_public_unambiguous_url(url):
    item=row();item['evidence'][0]['url']=url
    assert any('.url' in e['path'] for e in check(item).errors)

def test_same_url_under_new_evidence_ref_rejected():
    item=row();extra=dict(item['evidence'][0],evidence_ref='another');item['evidence'].append(extra)
    assert 'SCA-E001' in check(item).codes()

def test_row_count_must_be_integer_not_float():
    payload=answer(row(),row(1));payload['row_count']=2.0
    assert not sc.validate_answer(json.dumps(payload),TASK,today=TODAY).ok

def test_declared_depth_limit_is_enforced():
    payload=answer(row(),row(1));nested='leaf'
    for _ in range(sc.LIMITS['depth']+1):nested=[nested]
    payload['extra']=nested
    assert 'SCA-M006' in sc.validate_answer(json.dumps(payload),TASK,today=TODAY).codes()

@pytest.mark.parametrize('eco,older,newer',[
    ('pypi','1.0.dev1','1.0a1'),('pypi','1.0rc1','1.0'),('pypi','1.0','1.0.post1'),
    ('pypi','1!1.0','2!0.1'),('nuget','1.0.0-beta.2','1.0.0-beta.11'),
    ('cargo','1.0.0-rc.1','1.0.0'),('composer','v1.2.0','v1.3.0'),('gem','1.0.pre','1.0'),
])
def test_additional_ecosystem_order(eco,older,newer):
    assert sc.compare_versions(eco,older,newer)==-1
    assert sc.compare_versions(eco,newer,older)==1

def test_unsupported_comparator_does_not_hide_update_advice():
    item=row();item['ecosystem']='custom';item['research_coverage']=[dict(e,query={**e['query'],'ecosystem':'custom'}) for e in item['research_coverage']]
    task=copy.deepcopy(TASK);task['rows']=task['rows'][:1];task['rows'][0]['ecosystem']='custom';task['row_count']=1
    item['public_findings'][0]['applies']='unknown';item['package_status']='incomplete'
    item['gaps'].append({'code':'APPLICABILITY_UNCLEAR','text':'Порядок не проверен'})
    report=sc.validate_answer(json.dumps(answer(item)),task,today=TODAY)
    assert report.ok,report.text()

@pytest.mark.parametrize('eco,raw,coordinates',[('maven','parser','org.example:parser'),('npm','parser','@example/parser')])
def test_short_coordinates_with_identity_evidence_are_accepted(eco,raw,coordinates):
    item=row();item.update(ecosystem=eco,component=raw)
    item['identity_resolution'].update(coordinates=coordinates,basis='Реестр подтверждает namespace и текущую версию')
    for entry in item['research_coverage']:entry['query'].update(ecosystem=eco,coordinates=coordinates)
    item['public_findings'][0]['ranges']=[{'introduced':'0','fixed':'9.0.99'}]
    task=copy.deepcopy(TASK);task['rows']=task['rows'][:1];task['rows'][0].update(ecosystem=eco,component=raw);task['row_count']=1
    report=sc.validate_answer(json.dumps(answer(item)),task,today=TODAY)
    assert report.ok,report.text()

def test_empty_ecosystem_honestly_unresolved_is_accepted():
    task=copy.deepcopy(TASK);task['rows']=task['rows'][:1];task['rows'][0]['ecosystem']='';task['row_count']=1
    item=sc.empty_row(task['rows'][0]);item['identity_resolution']['state']='unresolved'
    item['research_coverage'][0].update(source='Реестр',note='Экосистема не определена')
    item['research_coverage']=item['research_coverage'][:1]
    item['gaps']=[{'code':'IDENTITY_UNRESOLVED','text':'В исходной выгрузке нет экосистемы'}]
    item['package_status']='identity_unresolved'
    report=sc.validate_answer(json.dumps(answer(item)),task,today=TODAY)
    assert report.ok,report.text()

def test_pep440_matches_reference_order():
    from packaging.version import Version
    versions=['v1.0','1.0.0','1.0.dev1','1.0a1','1.0-alpha2','1.0b0','1.0rc1','1.0rc1.post1',
              '1.0.post1.dev2','1.0.post1','1.0+abc.1','1.0+abc.2','1.0+2','1!0.1','2.0']
    for left in versions:
        for right in versions:
            a,b=Version(left),Version(right)
            assert sc.compare_versions('pypi',left,right)==(a>b)-(a<b),(left,right)

def test_gem_normalizes_trailing_zero_before_prerelease():
    assert sc.compare_versions('gem','1.0.0.pre','1.pre')==0

def test_late_digest_error_is_included_in_error_limit_count():
    payload=answer(row(),row(1));payload['rows'][0]['public_findings'][0]['cvss']['score']=1.25
    raw=json.dumps(payload).replace('1.25','1e999')
    full=sc.validate_answer(raw,TASK,today=TODAY)
    limited=sc.validate_answer(raw,TASK,today=TODAY,limits={**sc.LIMITS,'reported_errors':1})
    assert len(limited.errors)==2 and limited.errors[-1]['code']=='SCA-M007'
    assert f'из {len(full.errors)}:' in limited.errors[-1]['message']

def test_unknown_order_does_not_prove_two_distinct_versions_equal():
    item=row();item['latest_stable_release']['version']='vendor-unknown';item['update_status']='up_to_date'
    assert 'SCA-L001' in check(item).codes()

def test_reversed_range_is_not_evidence_of_no_vulnerabilities():
    item=row();item['public_findings'][0].update(applies='no',ranges=[{'introduced':'9.0.99','fixed':'9.0.0'}])
    item['package_status']=sc.row_status(item)
    assert 'SCA-A001' in check(item).codes()
