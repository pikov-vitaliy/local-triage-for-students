"""Выдуманный каталог формата CAPEC; не содержит выгрузок проектов."""
import io
import zipfile

CAPEC_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 Name="CAPEC" Version="9.99" Date="2099-01-24" xsi:schemaLocation="http://capec.mitre.org/capec-3 ap_schema_v3.5.xsd">
<Attack_Patterns>
<Attack_Pattern ID="2099" Name="Demo Injection" Abstraction="Standard" Status="Draft">
<Description>Input &lt;script&gt;demo&lt;/script&gt; reaches a demo command.</Description>
<Likelihood_Of_Attack>High</Likelihood_Of_Attack><Typical_Severity>High</Typical_Severity>
<Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="2100"/></Related_Attack_Patterns>
<Execution_Flow><Attack_Step><Step>1</Step><Phase>Explore</Phase><Description>Inspect demo input.</Description><Techniques><Technique>Observe a test.</Technique></Techniques></Attack_Step><Attack_Step><Step>2</Step><Phase>Experiment</Phase><Description>Check a demo condition.</Description></Attack_Step></Execution_Flow>
<Prerequisites><Prerequisite>Untrusted demo input reaches an interpreter.</Prerequisite></Prerequisites>
<Mitigations><Mitigation>Use a parameterized demo API.</Mitigation></Mitigations>
<Related_Weaknesses><Related_Weakness CWE_ID="2099"/><Related_Weakness CWE_ID="2099"/><Related_Weakness CWE_ID="2100"/></Related_Weaknesses>
<References><Reference External_Reference_ID="REF-1" Section="Demo section"/></References>
<Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>9999</Entry_ID><Entry_Name>Demo mapping</Entry_Name></Taxonomy_Mapping></Taxonomy_Mappings>
<Future_Field>Must remain readable.</Future_Field>
</Attack_Pattern>
<Attack_Pattern ID="2100" Name="Demo Parent" Abstraction="Meta" Status="Stable"><Description>Demo parent.</Description></Attack_Pattern>
<Attack_Pattern ID="2101" Name="Retired Demo" Abstraction="Detailed" Status="Deprecated"><Description>Retired.</Description></Attack_Pattern>
</Attack_Patterns>
<Categories><Category ID="2200" Name="Demo Category" Status="Stable"><Summary>Demo family.</Summary><Relationships><Has_Member CAPEC_ID="2100"/></Relationships></Category></Categories>
<Views><View ID="1000" Name="Demo Graph" Type="Graph" Status="Stable"><Objective>Demo graph view.</Objective><Members><Has_Member CAPEC_ID="2200"/></Members></View><View ID="658" Name="Demo Implicit" Type="Implicit" Status="Draft"><Objective>Demo selection.</Objective><Filter>/Attack_Pattern_Catalog/*/*[Taxonomy_Mappings/Taxonomy_Mapping[@Taxonomy_Name='ATTACK']]</Filter></View></Views>
<External_References><External_Reference Reference_ID="REF-1"><Title>Demo source</Title><URL>https://example.org/demo</URL></External_Reference></External_References>
</Attack_Pattern_Catalog>'''


def capec_zip(xml=CAPEC_XML):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('capec_demo.xml',xml)
        z.writestr('ap_schema_demo.xsd','demo')
    return out.getvalue()
