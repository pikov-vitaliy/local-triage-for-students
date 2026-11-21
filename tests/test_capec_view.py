import xml.etree.ElementTree as ET
from app.capec import _node, parse_reference
from app.capec_view import rich


def test_feed_field_names_and_values_keep_original_language():
    tree=_node(ET.fromstring('<Execution_Flow><Attack_Step><Step>1</Step><Phase>Explore</Phase>'
        '<Description>Original description.</Description><Technique>Original technique.</Technique>'
        '</Attack_Step></Execution_Flow>'))
    rendered=str(rich(tree))
    for label in ('Execution Flow','Attack Step','Step','Phase','Description','Technique'):
        assert '<strong>'+label+'</strong>' in rendered
    for translated in ('Шаг атаки','Номер','Этап','Описание','Техника'):
        assert translated not in rendered
    assert 'Explore' in rendered and 'Original description.' in rendered


def test_rich_preserves_lists_tables_code_and_text_order():
    tree = _node(ET.fromstring('<Description>До <b>выделено</b> после<ul><li>Один</li></ul>'
                              '<table><tr><td colspan="2">Ячейка</td></tr></table><pre>&lt;x&gt;</pre>'
                              '<script>alert(1)</script></Description>'))
    text = str(rich(tree))
    assert 'До <b>выделено</b> после<ul>' in text
    assert '<li>Один</li>' in text and '<td colspan="2">Ячейка</td>' in text
    assert '<pre>&lt;x&gt;</pre>' in text and '<script>' not in text


def test_reference_keeps_long_title_authors_and_unknown_fields():
    title = 'Слово ' * 3000
    elem = ET.fromstring('<External_Reference Reference_ID="REF-1"><Title>' + title + '</Title>'
                        + '<Author>Автор</Author>' * 30 + '<Future>Сохранить</Future></External_Reference>')
    ref = parse_reference(elem)
    assert ref['title'] == title.strip()
    assert len(ref['authors']) == 30
    assert ref['tree']['children'][-1]['text'] == 'Сохранить'


def test_future_root_attributes_and_namespaces_are_preserved():
    from app.capec import parse_record, NS
    elem=ET.fromstring(f'<Attack_Pattern xmlns="{NS}" xmlns:x="urn:extension" ID="99" Name="Demo" x:future="keep"><x:Future>Value</x:Future></Attack_Pattern>')
    row=parse_record(elem)
    assert row['attributes']['{urn:extension}future']=='keep'
    assert row['sections'][0]['namespace']=='urn:extension'
