"""Каталог CAPEC: структура источника и прямые справочные связи, без вывода о применимости."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

NS = "http://capec.mitre.org/capec-3"
TABLES = ("capec", "capec_index", "capec_refs", "capec_links", "capec_cwe", "capec_meta")  # таблицы – миграция 0002, ADR-0133
KNOWN = set("Description Extended_Description Likelihood_Of_Attack Typical_Severity Related_Attack_Patterns Execution_Flow Prerequisites Skills_Required Resources_Required Consequences Mitigations Example_Instances Related_Weaknesses Taxonomy_Mappings Content_History Indicators References Notes Alternate_Terms Summary Relationships Objective Members Filter Audience".split())
KINDS = {"Attack_Pattern": "pattern", "Category": "category", "View": "view"}
MAX_JSON = 1024 * 1024


def identifier(value, prefix="CAPEC"):
    match = re.fullmatch(r"\s*(?:" + prefix + r"\s*-?\s*)?0*(\d{1,7})\s*", str(value or ""), re.I)
    return f"{prefix}-{int(match[1])}" if match and int(match[1]) else ""


def _tag(elem):
    return elem.tag.rsplit("}", 1)[-1]


def _node(elem):
    # Полное дерево записи: текст, атрибуты, хвосты и порядок не теряются при появлении нового поля.
    return {"tag": _tag(elem), "namespace": elem.tag.rsplit('}',1)[0].lstrip('{') if '}' in elem.tag else '',
            "attrs": _attributes(elem), "text": elem.text or "",
            "tail": elem.tail or "", "children": [_node(x) for x in elem]}


def _attributes(elem):
    return {('{' + key if '}' in key and not key.startswith('{') else key):value for key,value in elem.attrib.items()}


def parse_record(elem):
    from .feeds import FeedError
    for part in elem.iter():
        if '}' in part.tag and not part.tag.startswith('{'):
            part.tag = '{' + part.tag
    ident = identifier(elem.get("ID"))
    if not ident or not elem.get("Name") or not elem.tag.startswith("{" + NS + "}"):
        raise FeedError("Некорректная запись CAPEC: нужны ID, Name и пространство имён CAPEC.")
    def elements(path): return elem.findall(path, {"c": NS})
    def text(name): return elem.findtext("c:" + name, default="", namespaces={"c": NS}).strip()
    links = [{"rel": x.get("Nature", ""), "id": identifier(x.get("CAPEC_ID"))}
             for x in elements("c:Related_Attack_Patterns/c:Related_Attack_Pattern")]
    links += [{"rel": "HasMember", "id": identifier(x.get("CAPEC_ID"))}
              for path in ("c:Relationships/c:Has_Member", "c:Members/c:Has_Member") for x in elements(path)]
    row = {"id": ident, "kind": KINDS[_tag(elem)], "name": elem.get("Name"), "attributes": _attributes(elem), "text":elem.text or '',
           "abstraction": elem.get("Abstraction", ""), "status": elem.get("Status", ""),
           "view_type": elem.get("Type", ""), "filter": text("Filter"),
           "severity": text("Typical_Severity"), "likelihood": text("Likelihood_Of_Attack"),
           "description": text("Description") or text("Summary") or text("Objective"),
           "has_flow": bool(elements("c:Execution_Flow")),
           "cwes": sorted({identifier(x.get("CWE_ID"), "CWE") for x in elements("c:Related_Weaknesses/c:Related_Weakness")} - {""}),
           "links": [x for x in links if x["id"]],
           "exclude": [identifier(x.get("Exclude_ID")) for x in elements(".//c:Exclude_Related")],
           "taxonomies": [x.get("Taxonomy_Name", "") for x in elements("c:Taxonomy_Mappings/c:Taxonomy_Mapping")],
           "sections": [_node(x) for x in elem],
           "unknown_fields": [_tag(x) for x in elem if _tag(x) not in KNOWN]}
    row["search_text"] = " ".join(elem.itertext()).casefold() + " " + row["name"].casefold()
    if len(json.dumps(row, ensure_ascii=False).encode()) > MAX_JSON:
        raise FeedError("Запись CAPEC слишком велика: полный текст не был сохранён, каталог не заменён.")
    return row


def parse_reference(elem):
    """Источник целиком, без сокращения полей и количества авторов."""
    from .feeds import FeedError
    def text(name):
        return ' '.join(''.join(x.itertext()).strip() for x in elem if _tag(x) == name)
    ident = elem.get('Reference_ID', '')
    if not ident:
        raise FeedError('В источнике CAPEC нет Reference_ID.')
    row = {'id': ident, 'title': text('Title'), 'url': text('URL'),
           'authors': [''.join(x.itertext()) for x in elem if _tag(x) == 'Author'], 'tree': _node(elem)}
    if len(json.dumps(row, ensure_ascii=False).encode()) > MAX_JSON:
        raise FeedError('Источник CAPEC слишком велик: каталог не заменён.')
    return row


def fill(store, archive, info, check):
    """Потоковый импорт в подготовленный imp; подмена остаётся общей операцией FeedStore."""
    from .feeds import FeedError, guarded_chunks, iter_records, MAX_RECORDS
    root_attrs, seen, counts, statuses = {}, set(), Counter(), Counter()
    refs = pairs = 0
    xml_hash = hashlib.sha256()
    def root(elem):
        root_attrs.update(elem.attrib)
        if elem.tag.lstrip('{') != NS + "}Attack_Pattern_Catalog" or elem.get("Name") != "CAPEC":
            raise FeedError("Нужен полный архив capec_latest.zip с каталогом CAPEC, не отдельное представление.")
        schema = next((v for k,v in elem.attrib.items() if k.lstrip('{') == 'http://www.w3.org/2001/XMLSchema-instance}schemaLocation'), '')
        if not re.search(r"ap_schema_v3\.5\.xsd(?:\s|$)", schema):
            raise FeedError("Версия XML-схемы CAPEC не поддерживается: ожидается 3.5.")
    def chunks(stream):
        for piece in guarded_chunks(stream, compressed=info.compress_size):
            xml_hash.update(piece)
            yield piece
    with archive.open(info) as stream:
        for elem in iter_records(chunks(stream), set(KINDS) | {"External_Reference"}, on_root=root, check=check):
            check()
            is_ref = _tag(elem) == "External_Reference"
            row = parse_reference(elem) if is_ref else parse_record(elem)
            if row is None: raise FeedError("Некорректный источник CAPEC.")
            key = ("ref" if is_ref else "record", row["id"])
            if key in seen: raise FeedError(f"Повтор ID {row['id']} в каталоге CAPEC.")
            seen.add(key)
            if len(seen) > MAX_RECORDS["capec"]: raise FeedError("Слишком много записей CAPEC.")
            encoded = json.dumps(row, ensure_ascii=False)
            store._check_space(len(encoded.encode()) * 4 + 65536)
            with store._tx() as conn:
                if is_ref:
                    refs += 1
                    conn.execute("INSERT INTO feeds_imp.capec_refs VALUES (?,?)", (row["id"], encoded))
                else:
                    counts[row["kind"]] += 1
                    statuses[row["status"]] += 1
                    conn.execute("INSERT INTO feeds_imp.capec VALUES (?,?)", (row["id"], encoded))
                    conn.execute("INSERT INTO feeds_imp.capec_index VALUES (?,?,?,?)", (row["id"], row["kind"], row["name"], row["search_text"]))
                    conn.executemany("INSERT INTO feeds_imp.capec_links VALUES (?,?,?) ON CONFLICT DO NOTHING", [(row['id'],x['rel'],x['id']) for x in row['links']])
                    conn.executemany("INSERT INTO feeds_imp.capec_cwe VALUES (?,?) ON CONFLICT DO NOTHING", [(row['id'],x) for x in row['cwes']])
                    pairs += len(row['cwes'])
    if not all(counts[x] for x in ('pattern','category','view')) or not refs:
        raise FeedError("В архиве нет полного состава CAPEC: нужны шаблоны, категории, представления и источники.")
    profile = {"counts": dict(counts), "statuses": dict(statuses), "cwe_pairs": pairs,
               "sha256": xml_hash.hexdigest(), "schema": "3.5", "namespace": NS, "storage_version": 1}
    with store._tx() as conn:
        conn.execute("INSERT INTO feeds_imp.capec_meta VALUES ('catalog',?)", (json.dumps(profile),))
    return {"records": sum(counts.values()), "ref_records": refs,
            "version": root_attrs.get("Version", ""), "source_date": root_attrs.get("Date", "")}


def view_members(records, ident):
    """Состав представления; исключения относятся к пути, а не к записи целиком."""
    view=records.get(ident,{})
    if view.get('kind')!='view': return set(),'Представление не найдено.'
    if view['view_type']=='Implicit':
        expr=re.sub(r"\s+(?=(?:[^']*'[^']*')*[^']*$)",'',view['filter'])
        if expr=='/Attack_Pattern_Catalog/*[not(self::External_References)]/*': return set(records),''
        m=re.fullmatch(r"/Attack_Pattern_Catalog/Attack_Patterns/Attack_Pattern\[@Abstraction='(Meta|Standard|Detailed)'\]",expr)
        if m:return {k for k,v in records.items() if v['kind']=='pattern' and v['abstraction']==m[1]},''
        m=re.fullmatch(r"/Attack_Pattern_Catalog/\*/\*\[@Status='([^']+)'\]",expr)
        if m:return {k for k,v in records.items() if v['status']==m[1]},''
        m=re.fullmatch(r"/Attack_Pattern_Catalog/\*/\*\[Taxonomy_Mappings/Taxonomy_Mapping\[@Taxonomy_Name='([^']+)'\]\]",expr)
        if m:return {k for k,v in records.items() if m[1] in v['taxonomies']},''
        m=re.fullmatch(r'/Attack_Pattern_Catalog/\*/\*\[@ID=\(([\d,]+)\)\]',expr)
        if m:return {identifier(x) for x in m[1].split(',')} & records.keys(),''
        return set(),'Условие представления пока не поддерживается.'
    roots=[x['id'] for x in view['links'] if x['rel']=='HasMember']
    if view['view_type']=='Explicit':return set(roots),''
    children={}
    for k,v in records.items():
        for e in v['links']:
            if e['rel']=='ChildOf':children.setdefault(e['id'],set()).add(k)
            if e['rel']=='HasMember':children.setdefault(k,set()).add(e['id'])
    result,note,stack,steps=set(),'',[(x,(ident,)) for x in roots],0
    while stack:
        key,path=stack.pop();steps+=1
        if steps>20000:return result,'Обход ограничен: слишком много путей в представлении.'
        if key in path:
            note='В связях обнаружен цикл; повторный путь пропущен.'
            continue
        row=records.get(key)
        if not row or set(row['exclude']) & set(path):continue
        result.add(key)
        stack.extend((child,path+(key,)) for child in children.get(key,()))
    return result,note
