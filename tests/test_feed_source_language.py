"""Содержание и терминология справочников сохраняются на языке источника."""
from test_web import web  # noqa: F401
from feed_fixtures import CWE_FULL_XML,cwe_zip


def test_cwe_source_fields_values_and_classifications_are_not_translated(web):
    path=cwe_zip(web.tmp/'cwe-original.zip',CWE_FULL_XML)
    web.app.state.feeds.load('cwe',path,path.name)
    text=web.client.get('/cwe/CWE-2099').text
    for field in ('Abstraction','Structure','Status','Language','Technology','Operating System','Architecture',
                  'Scope','Impact','Likelihood','Note','Effectiveness','Taxonomy Name','Entry ID','Entry Name',
                  'Mapping Fit','Usage','Rationale','Comments','Reasons'):
        assert field in text,field
    assert 'Bad · Python' in text and 'Good · Python' in text
    assert '>Языки<' not in text and '>Область воздействия<' not in text
    assert 'Confidentiality' in text and 'Read Application Data' in text
    catalog=web.client.get('/cwe').text
    assert '>Weakness<' in catalog and '>Abstraction<' in catalog


def test_embedded_cwe_keeps_mitre_name_and_labels_bdu_as_separate_source(web):
    from feed_fixtures import CWE_XML
    from test_web import create_project,upload
    from hub_fixtures import make_hub_xlsx
    store=web.app.state.feeds
    path=cwe_zip(web.tmp/'cwe-original.zip',CWE_XML);store.load('cwe',path,path.name)
    for ident in ('CWE-89','CWE-1333'):
        store._conn.execute('INSERT INTO feeds.cwe_ru VALUES (?,?)',(ident,'Оригинальное название БДУ'))
    pid=create_project(web.client);upload(web.client,pid,make_hub_xlsx(web.tmp/'source.xlsx'))
    rows=web.app.state.db.list_findings(pid,limit=100)[0]
    for kind,prefix in [('SAST','findings'),('SCA','sca/findings')]:
        row=next(r for r in rows if r['kind']==kind)
        text=web.client.get(f'/projects/{pid}/{prefix}/{row["id"]}').text
        assert 'БДУ ФСТЭК России: Оригинальное название БДУ' in text
        assert 'Improper Neutralization' in text if kind=='SAST' else 'Inefficient Regular Expression' in text
