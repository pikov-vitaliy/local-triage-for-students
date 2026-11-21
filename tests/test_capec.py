"""Полный каталог, происхождение связей и атомарное обновление CAPEC."""
import pytest
from app.feeds import FeedStore, FeedError
from capec_fixtures import CAPEC_XML, capec_zip
from feed_fixtures import CWE_FULL_XML, cwe_zip


@pytest.fixture
def store(tmp_path):
    with_store = FeedStore(tmp_path / "feeds.db")
    yield with_store
    with_store.close()


def load(store, tmp_path, data=None):
    path=tmp_path / "capec.zip"
    path.write_bytes(capec_zip() if data is None else data)
    return store.load("capec", path, path.name)


def test_shared_snapshot_is_reused_until_atomic_catalog_replacement(store,tmp_path):
    load(store,tmp_path)
    first=store.capec_data(shared=True)
    assert store.capec_data(shared=True) is first
    editable=store.capec_data()
    editable['records']['CAPEC-2099']['name']='Changed by caller'
    assert store.capec_data(shared=True)['records']['CAPEC-2099']['name']=='Demo Injection'
    with pytest.raises(FeedError):load(store,tmp_path,capec_zip(CAPEC_XML.replace('ID="2100"','ID="2099"')))
    assert store.capec_data(shared=True) is first
    load(store,tmp_path,capec_zip(CAPEC_XML.replace('Demo Injection','Updated Demo')))
    fresh=store.capec_data(shared=True)
    assert fresh is not first
    assert fresh['records']['CAPEC-2099']['name']=='Updated Demo'
    assert first['records']['CAPEC-2099']['name']=='Demo Injection'


def test_full_catalog_and_original_sections(store, tmp_path):
    meta=load(store,tmp_path)
    data=store.capec_data()
    assert meta['records']==6 and meta['ref_records']==1
    assert data['meta']['version']=='9.99'
    assert data['profile']['counts']=={'pattern':3,'category':1,'view':2}
    assert data['profile']['cwe_pairs']==2
    row=data['records']['CAPEC-2099']
    assert row['cwes']==['CWE-2099','CWE-2100']
    assert [x['tag'] for x in row['sections']][:3]==['Description','Likelihood_Of_Attack','Typical_Severity']
    assert row['sections'][-1]['text']=='Must remain readable.'
    assert 'Future_Field' in row['unknown_fields']
    assert data['refs']['REF-1']['title']=='Demo source'
    assert len(data['profile']['sha256'])==64


@pytest.mark.parametrize('xml',[
    CAPEC_XML.replace('Name="CAPEC"','Name="Demo subset"',1),
    CAPEC_XML.replace('capec-3','cwe-7'),
    CAPEC_XML.replace('ap_schema_v3.5.xsd','ap_schema_v9.9.xsd'),
    CAPEC_XML.replace('ID="2100" Name="Demo Parent"','ID="2099" Name="Demo Parent"'),
    CAPEC_XML.replace('<View ID="1000"','<View ID="2099"'),
], ids=['subset','namespace','schema','duplicate-pattern','duplicate-view'])
def test_wrong_feed_and_duplicate_ids_preserve_catalog(store,tmp_path,xml):
    load(store,tmp_path)
    before=store.capec_data()
    with pytest.raises(FeedError):
        load(store,tmp_path,capec_zip(xml))
    assert store.capec_data()==before
    assert store.staging_rows() == 0


def test_cwe_links_have_separate_provenance(store,tmp_path):
    load(store,tmp_path)
    path=cwe_zip(tmp_path/'cwe.zip',CWE_FULL_XML)
    store.load('cwe',path,path.name)
    assert store.capec_for_cwes(['CWE-2099'])['CAPEC-2099']['sources']==['CAPEC']
    assert store.capec_for_cwes(['CWE-2099'])['CAPEC-209']['sources']==['CWE']
    load(store,tmp_path)
    assert 'CAPEC-209' in store.capec_for_cwes(['CWE-2099'])


def test_view_exclusions_cycles_and_unknown_filter(store,tmp_path):
    from app import capec
    load(store,tmp_path)
    records=store.capec_data()['records']
    ids,note=capec.view_members(records,'CAPEC-1000')
    assert {'CAPEC-2099','CAPEC-2100'} <= ids
    records['CAPEC-2099']['exclude']=['CAPEC-2200']
    ids,note=capec.view_members(records,'CAPEC-1000')
    assert 'CAPEC-2099' not in ids
    records['CAPEC-2100']['links'].append({'rel':'HasMember','id':'CAPEC-2200'})
    assert capec.view_members(records,'CAPEC-1000')[1]
    records['CAPEC-658']['filter']='unrecognized()'
    assert capec.view_members(records,'CAPEC-658')==(set(),'Условие представления пока не поддерживается.')


def test_implicit_taxonomy_preserves_spaces(store,tmp_path):
    from app import capec
    load(store,tmp_path)
    records=store.capec_data()['records']
    records['CAPEC-2099']['taxonomies']=['OWASP Attacks']
    records['CAPEC-658']['filter']="/Attack_Pattern_Catalog/*/*[Taxonomy_Mappings/Taxonomy_Mapping[@Taxonomy_Name='OWASP Attacks']]"
    assert capec.view_members(records,'CAPEC-658')[0]=={'CAPEC-2099'}
