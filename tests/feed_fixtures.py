"""Маленькие выдуманные справочники того же формата, что настоящие: выгрузка БДУ ФСТЭК России (vulxml.xml в архиве)
и каталог CWE MITRE. Идентификаторы – выдуманные (BDU:2099-…, CVE-2099-…); в репозиторий настоящие файлы не входят."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

BDU_XML = """<?xml version="1.0" encoding="utf-8"?>
<vulnerabilities><vul><identifier>BDU:2099-00001</identifier><name>Уязвимость библиотеки разбора example-parser, позволяющая нарушителю вызвать отказ в обслуживании</name><description>Уязвимость функции разбора выражений библиотеки example-parser связана с неэффективной сложностью регулярного выражения. Эксплуатация уязвимости может позволить нарушителю вызвать отказ в обслуживании</description><vulnerable_software><soft><name>example-parser</name><vendor>Example</vendor><version>от 1.0.0 до 1.4.8 включительно</version></soft></vulnerable_software><cwes><cwe><identifier>CWE-1333</identifier><name>Неэффективная сложность регулярного выражения</name></cwe></cwes><identify_date>01.02.2099</identify_date><publication_date>03.02.2099</publication_date><last_upd_date>05.02.2099</last_upd_date><cvss><vector score="7,8">AV:N/AC:L/Au:N/C:N/I:N/A:C</vector></cvss><cvss3><vector score="7,5">AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</vector></cvss3><severity>Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,5)</severity><solution>Обновление программного обеспечения до версии 1.4.9 или более поздней</solution><vul_status>Подтверждена производителем</vul_status><exploit_status>Данные уточняются</exploit_status><fix_status>Уязвимость устранена</fix_status><sources>https://example.org/advisories/parser-1
https://osv.dev/vulnerability/CVE-2099-10002</sources><identifiers><identifier type="CVE" link="https://nvd.nist.gov/vuln/detail/CVE-2099-10002">CVE-2099-10002</identifier></identifiers><other></other><vul_incident>Данные уточняются</vul_incident><vul_class>Уязвимость кода</vul_class><vul_state>Опубликована</vul_state><vul_elimination>Данные уточняются</vul_elimination></vul><vul><identifier>BDU:2099-00002</identifier><name>Уязвимость библиотеки example-parser, связанная с обработкой внешних сущностей XML</name><description>Уязвимость библиотеки example-parser связана с обработкой внешних сущностей XML</description><cwes><cwe><identifier>CWE-611</identifier><name>Неправильное ограничение ссылок на внешние сущности XML</name></cwe></cwes><publication_date>10.03.2099</publication_date><last_upd_date>11.03.2099</last_upd_date><severity>Средний уровень опасности</severity><solution>Обновление программного обеспечения до версии 1.4.9</solution><sources>javascript:alert(1) https://127.0.0.1/x</sources><identifiers><identifier type="CVE">CVE-2099-10001</identifier><identifier type="Other">VENDOR-1</identifier></identifiers></vul><vul><identifier>не BDU</identifier><name>Пропускается</name></vul></vulnerabilities>
"""

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?><Weakness_Catalog Name="CWE" Version="9.99" Date="2099-04-30" xmlns="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml">
<Weaknesses>
<Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')" Abstraction="Base" Status="Stable"><Description>The product constructs all or part of an SQL command using externally-influenced input.</Description><Extended_Description><xhtml:p>Extended text.</xhtml:p></Extended_Description><Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="943"/></Related_Weaknesses></Weakness>
<Weakness ID="1333" Name="Inefficient Regular Expression Complexity" Status="Draft"><Description>The product uses a regular expression with an inefficient worst-case complexity.</Description></Weakness>
</Weaknesses>
<Categories><Category ID="9999" Name="Demo Category" Status="Draft"><Summary>Demo summary.</Summary></Category></Categories>
<External_References><External_Reference Reference_ID="REF-1"><Title>Demo</Title></External_Reference></External_References>
</Weakness_Catalog>
"""

# Каталог со всеми разделами слабости и справочником ссылок: по нему проверяется разбор полной записи.
# Номера классов и CVE выдуманы, разметка – как в настоящем каталоге (xhtml:p, xhtml:div, xhtml:br).
CWE_FULL_XML = """<?xml version="1.0" encoding="UTF-8"?><Weakness_Catalog Name="CWE" Version="9.99" Date="2099-04-30" xmlns="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml">
<Weaknesses>
<Weakness ID="2099" Name="Improper Neutralization of Demo Input" Abstraction="Base" Structure="Simple" Status="Stable">
<Description>The demo product builds a demo command from input &lt;script&gt;alert(1)&lt;/script&gt; without checking it.</Description>
<Extended_Description><xhtml:p>Extended first paragraph.</xhtml:p><xhtml:p>Extended second paragraph.</xhtml:p></Extended_Description>
<Alternate_Terms><Alternate_Term><Term>Demo injection</Term><Description>Другое название класса из каталога.</Description></Alternate_Term></Alternate_Terms>
<Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="2098" View_ID="1000" Ordinal="Primary"/><Related_Weakness Nature="ParentOf" CWE_ID="2100"/><Related_Weakness Nature="CanPrecede" CWE_ID="2101"/><Related_Weakness Nature="PeerOf" CWE_ID="2102"/></Related_Weaknesses>
<Weakness_Ordinalities><Weakness_Ordinality><Ordinality>Primary</Ordinality></Weakness_Ordinality></Weakness_Ordinalities>
<Applicable_Platforms><Language Class="Not Language-Specific" Prevalence="Undetermined"/><Technology Class="Web Based" Prevalence="Often"/><Operating_System Name="Demo OS" Prevalence="Undetermined"/><Architecture Name="X86" Prevalence="Undetermined"/></Applicable_Platforms>
<Background_Details><Background_Detail>Background detail of the demo class.</Background_Detail></Background_Details>
<Modes_Of_Introduction><Introduction><Phase>Implementation</Phase><Note>Phase note.</Note></Introduction><Introduction><Phase>Architecture</Phase></Introduction></Modes_Of_Introduction>
<Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
<Common_Consequences><Consequence><Scope>Confidentiality</Scope><Scope>Integrity</Scope><Impact>Read Application Data</Impact><Impact>Modify Application Data</Impact><Likelihood>High</Likelihood><Note>Consequence note.</Note></Consequence></Common_Consequences>
<Detection_Methods><Detection_Method Detection_Method_ID="DM-14"><Method>Automated Static Analysis</Method><Description><xhtml:p>Detection text.</xhtml:p></Description><Effectiveness>High</Effectiveness><Effectiveness_Notes>Detection notes.</Effectiveness_Notes></Detection_Method></Detection_Methods>
<Potential_Mitigations><Mitigation><Phase>Implementation</Phase><Phase>Architecture</Phase><Strategy>Reduce</Strategy><Description><xhtml:p>Mitigation text.</xhtml:p></Description><Effectiveness>High</Effectiveness><Effectiveness_Notes>Mitigation notes.</Effectiveness_Notes></Mitigation></Potential_Mitigations>
<Demonstrative_Examples>
<Demonstrative_Example><Intro_Text><xhtml:p>Example intro.</xhtml:p></Intro_Text><Body_Text>Intro to bad code.</Body_Text><Example_Code Nature="Bad" Language="Python"><xhtml:div>value = demo_input()<xhtml:br/>run(value)</xhtml:div></Example_Code><Body_Text>Intro to good code.</Body_Text><Example_Code Nature="Good" Language="Python"><xhtml:div>value = checked(demo_input())<xhtml:br/>run(value)</xhtml:div></Example_Code><References><Reference External_Reference_ID="REF-2" Section="Page 5"/></References></Demonstrative_Example>
<Demonstrative_Example><Intro_Text>Second example intro.</Intro_Text><Example_Code Nature="Attack" Language="C"><xhtml:div style="margin-left:1em;">int main(void) {<xhtml:br/>    return demo();<xhtml:br/>}</xhtml:div></Example_Code></Demonstrative_Example>
</Demonstrative_Examples>
<Observed_Examples><Observed_Example><Reference>CVE-2099-10001</Reference><Description>Observed in the demo product.</Description><Link>https://example.org/cve-2099-10001</Link></Observed_Example><Observed_Example><Reference>CVE-2099-10099</Reference><Description>Not in the BDU sample.</Description></Observed_Example></Observed_Examples>
<Functional_Areas><Functional_Area>Demo area</Functional_Area></Functional_Areas>
<Affected_Resources><Affected_Resource>Demo resource</Affected_Resource></Affected_Resources>
<Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="Demo taxonomy"><Entry_ID>T-1</Entry_ID><Entry_Name>Demo entry</Entry_Name><Mapping_Fit>Exact</Mapping_Fit></Taxonomy_Mapping></Taxonomy_Mappings>
<Related_Attack_Patterns><Related_Attack_Pattern CAPEC_ID="209"/><Related_Attack_Pattern CAPEC_ID="не CAPEC"/></Related_Attack_Patterns>
<References><Reference External_Reference_ID="REF-1" Section="Chapter 1"/></References>
<Mapping_Notes><Usage>Allowed</Usage><Rationale>Rationale text.</Rationale><Comments>Comments text.</Comments><Reasons><Reason Type="Demo"/></Reasons></Mapping_Notes>
<Notes><Note Type="Other">Note text.</Note></Notes>
</Weakness>
<Weakness ID="2098" Name="Demo Parent Class" Abstraction="Class" Status="Draft"><Description>Parent description.</Description></Weakness>
<Weakness ID="2100" Name="Demo Child Class" Abstraction="Class" Status="Draft"><Description>Child description.</Description></Weakness>
<Weakness ID="2101" Name="Demo Following Class" Abstraction="Class" Status="Draft"><Description>Following description.</Description><Related_Weaknesses><Related_Weakness Nature="CanPrecede" CWE_ID="2099"/></Related_Weaknesses></Weakness>
<Weakness ID="2102" Name="Demo Peer Class" Abstraction="Class" Status="Draft"><Description>Peer description.</Description></Weakness>
</Weaknesses>
<Categories><Category ID="3000" Name="Demo Category" Status="Draft"><Summary>Demo summary.</Summary><Relationships><Has_Member CWE_ID="2099"/></Relationships><References><Reference External_Reference_ID="REF-3" Section="Section"/></References><Mapping_Notes><Usage>Prohibited</Usage><Rationale>Demo rationale.</Rationale></Mapping_Notes><Notes><Note Type="Other">Category note.</Note></Notes></Category></Categories>
<External_References>
<External_Reference Reference_ID="REF-1"><Author>Demo Author</Author><Title>Demo title</Title><Edition>1</Edition><Publication>Demo publication</Publication><Publisher>Demo publisher</Publisher><Publication_Year>2098</Publication_Year><Publication_Month>-12</Publication_Month><Publication_Day>-05</Publication_Day><URL>https://example.org/ref1</URL></External_Reference>
<External_Reference Reference_ID="REF-2"><Author>Demo Author 2</Author><Title>Demo title 2</Title><Publication_Year>2099</Publication_Year><URL>javascript:alert(1)</URL></External_Reference>
<External_Reference Reference_ID="REF-3"><Title>Demo title 3</Title></External_Reference>
</External_References>
</Weakness_Catalog>
"""


def zip_bytes(name: str, text: str | bytes, extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, text if isinstance(text, bytes) else text.encode("utf-8"))
        for other, data in (extra or {}).items():
            archive.writestr(other, data)
    return buf.getvalue()


def bdu_zip(path: Path, text: str = BDU_XML) -> Path:
    path.write_bytes(zip_bytes("export/vulxml.xml", text))
    return path


def cwe_zip(path: Path, text: str = CWE_XML) -> Path:
    path.write_bytes(zip_bytes("cwec_v9.99.xml", text))
    return path
