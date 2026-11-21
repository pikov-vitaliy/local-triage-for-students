"""Разбор XML и маскирование резервного контекста."""
import zipfile
import pytest
from app import hub_import as hi
from app.context import build_context
from app.models import Finding
from app.prompts import masked_export_line
from hub_fixtures import make_hub_xlsx

@pytest.mark.parametrize('part',['xl/sharedStrings.xml','xl/styles.xml','docProps/core.xml','xl/worksheets/sheet1.xml'])
@pytest.mark.parametrize('encoding',['utf-8','utf-16'])
def test_dtd_rejected_before_openpyxl(tmp_path,part,encoding):
    original=make_hub_xlsx(tmp_path/'original.xlsx');bad=tmp_path/'bad.xlsx'
    xml=f'<?xml version="1.0" encoding="{encoding}"?><!DOCTYPE root [<!ENTITY demo "expanded">]><root>&demo;</root>'.encode(encoding)
    with zipfile.ZipFile(original) as src,zipfile.ZipFile(bad,'w',zipfile.ZIP_DEFLATED) as dst:
        for entry in src.infolist():
            if entry.filename!=part:dst.writestr(entry,src.read(entry))
        dst.writestr(part,xml)
    with pytest.raises(hi.ImportFailure,match='DTD|сущност'):
        hi._check_archive(bad)

@pytest.mark.parametrize('file,snippet',[
    ('demo.cpp','const char *password = "first-half" "demo-raw-secret";'),
    ('demo.rs','let password = r###"demo-raw-secret"###;'),
])
def test_export_fallback_and_prompt_mask_complete_literals(file,snippet):
    finding=Finding(hub_id='demo',kind='SAST',file=file,line=1,cwe=['CWE-89'],snippet=snippet)
    context=build_context(None,finding,mask_key=b'a'*32)
    assert 'demo-raw-secret' not in '\n'.join(context.lines)
    assert 'demo-raw-secret' not in masked_export_line(finding,b'a'*32)
