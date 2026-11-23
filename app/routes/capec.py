"""Локальные сценарии CAPEC: только справочный контекст для решения оператора."""
from __future__ import annotations
import re
from urllib.parse import urlencode, urlsplit
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from app import capec, i18n, worklists
from app.routes.common import render
from app.routes.references import missing_reference

PROJECT_FILTERS = ('finding_kind','codebase','finding_severity','reviewed','cvss_min','cvss_max','cvss_version')

router=APIRouter()
LABELS=i18n.Labels({'pattern':'Attack Pattern','category':'Category','view':'View','all':'Все записи'})
SCORES={'Very Low':1,'Low':2,'Medium':3,'High':4,'Very High':5}
SORTS={f'{k}_{d}' for k in ('id','name','abstraction','severity','likelihood') for d in ('asc','desc')}


def back_url(request, fallback='/capec'):
    value=request.query_params.get('back','')[:2000]
    try:p=urlsplit(value)
    except ValueError:return fallback
    return value if not p.netloc and not p.scheme and (p.path=='/capec' or re.fullmatch(r'/cwe/(?:CWE-)?\d+',p.path) or re.fullmatch(r'/projects/\d+/(?:capec|findings(?:/\d+)?|sca(?:/[^/]+)?|components(?:/[^/]+)?)',p.path)) else fallback


STAT_LABELS={'pattern':'Attack Patterns','category':'Categories','view':'Views'}


def catalog_context(request, *, project=None, allowed=None, matches=None):
    store=request.app.state.feeds
    with store.snapshot():
        data=store.capec_data(shared=True)
        rows=list(data['records'].values())
        f={k:request.query_params.get(k,'')[:200] for k in ('q','kind','abstraction','status','include_retired','view','severity','likelihood','has_flow','taxonomy','cwe_mode')}
        f.update(worklists.options(request.query_params,SORTS))
        if project:
            f.update({k:request.query_params.get(k,'')[:200] for k in PROJECT_FILTERS})
        f['kind']=f['kind'] or ('all' if capec.identifier(f['q']) else 'pattern')
        if f['kind'] not in LABELS:raise HTTPException(400,i18n._('Неизвестный вид записи CAPEC.'))
        choices={key:sorted({r.get(key,'') for r in rows if r.get(key)}) for key in ('abstraction','status','severity','likelihood')}
        choices['taxonomy']=sorted({t for r in rows for t in r['taxonomies']})
        for key in choices:
            if f[key] and f[key]!='__empty__' and f[key] not in choices[key]:raise HTTPException(400,i18n._('Неизвестное значение фильтра: {key}.',key=key))
        f['cwe']=','.join(request.query_params.getlist('cwe'))[:1000]
        keys={capec.identifier(x,'CWE') for x in re.split(r'[,;\s]+',f['cwe']) if x}
        if '' in keys:raise HTTPException(400,i18n._('Введите номера CWE через запятую.'))
        q=f['q'].strip()
        if q.upper().startswith('CWE-') and capec.identifier(q,'CWE'):keys.add(capec.identifier(q,'CWE'));q=''
        links=store.capec_for_cwes(keys)
    # страница проекта: всё считается по сценариям его находок, иначе числа расходятся с таблицей
    if allowed is not None:rows=[r for r in rows if r['id'] in allowed]
    # число сводки – весь вид записи с устаревшими и без прочих отборов: таблица по его ссылке показывает ровно столько строк
    by_kind={k:sum(r['kind']==k for r in rows) for k in STAT_LABELS}
    subject=any(f.get(k) for k in ('q','abstraction','status','view','severity','likelihood','has_flow','taxonomy','cwe')) or f.get('cwe_mode')=='all'
    total_kind=sum(f['kind']=='all' or r['kind']==f['kind'] for r in rows)
    if f['kind']!='all':rows=[r for r in rows if r['kind']==f['kind']]
    hidden=0
    if not f['status'] and not f['include_retired'] and not f['q']:
        hidden=sum(r['status'] in ('Deprecated','Obsolete') for r in rows)
        rows=[r for r in rows if r['status'] not in ('Deprecated','Obsolete')]
    for key in choices:
        if f[key]:rows=[r for r in rows if (not (r['taxonomies'] if key=='taxonomy' else r.get(key)) if f[key]=='__empty__' else f[key] in r['taxonomies'] if key=='taxonomy' else r.get(key)==f[key])]
    if keys:rows=[r for r in rows if r['id'] in links and (f['cwe_mode']!='all' or keys<=set(links[r['id']]['cwes']))]
    if f['has_flow'] in ('yes','no'):rows=[r for r in rows if r['has_flow']==(f['has_flow']=='yes')]
    notice=''
    if f['view']:
        members,notice=capec.view_members(data['records'],capec.identifier(f['view']))
        rows=[r for r in rows if r['id'] in members]
    if q:
        ident=capec.identifier(q)
        rows=[r for r in rows if r['id']==ident] if ident else [r for r in rows if all(t in r['search_text'] for t in q.casefold().split())]
    f['sort']=f['sort'] or 'id_asc'
    key,direction=f['sort'].rsplit('_',1)
    rows.sort(key=lambda r:int(r['id'].split('-')[1]))
    def value(r):return int(r['id'].split('-')[1]) if key=='id' else SCORES.get(r[key],0) if key in ('severity','likelihood') else r[key].casefold()
    rows=sorted([r for r in rows if key=='id' or r.get(key)],key=value,reverse=direction=='desc')+[r for r in rows if key!='id' and not r.get(key)]
    path=f"/projects/{project['id']}/capec" if project else '/capec'
    w=worklists.table(rows,f,path=path)
    source={k:f[k] for k in PROJECT_FILTERS if project and f.get(k)}
    kind_stats=[{'kind':k,'label':label,'count':by_kind[k],'active':not subject and f['kind']==k and bool(f['include_retired']),
                 'url':path+'?'+urlencode({**source,'kind':k,'include_retired':'1','page_size':w['size']})+'#capec-results'}
                for k,label in STAT_LABELS.items()]
    return {**data,'rows':w['rows'],'worklist':w,'filters':f,'choices':choices,'kind_labels':LABELS,
            'views':[r for r in data['records'].values() if r['kind']=='view'],'catalog_size':total_kind,
            'hidden_count':hidden,'kind_stats':kind_stats,'notice':notice,'project':project,'matches':matches or {},'path':path,
            'scenario_query':urlencode({k:v for k,v in f.items() if v and k!='scenario'}),
            'current_url':request.url.path+('?' + request.url.query if request.url.query else '')}


@router.get('/capec',response_class=HTMLResponse)
def catalog(request:Request):
    return render(request,'capec/index.html',catalog_context(request))


@router.get('/capec/{number}',response_class=HTMLResponse)
def detail(request:Request,number:str):
    from app.capec_view import plain, rich
    data=request.app.state.feeds.capec_data(shared=True)
    record=data['records'].get(capec.identifier(number))
    if not record:
        message = (i18n._('Каталог CAPEC не загружен: загрузите capec_latest.zip на странице «Справочники».')
                   if not data['meta'] else i18n._('Записи с таким номером в каталоге CAPEC нет.'))
        return missing_reference(request, 'capec', number, capec.identifier(number), message, data['meta'])
    links=[{**e,'name':data['records'].get(e['id'],{}).get('name',i18n._('Запись отсутствует в каталоге'))} for e in record['links']]
    for other in data['records'].values():
        for e in other['links']:
            if e['id']==record['id'] and e['rel'] in ('ChildOf','HasMember'):links.append({'rel':'ParentOf' if e['rel']=='ChildOf' else 'MemberOf','id':other['id'],'name':other['name']})
    prerequisites=' '.join(' '.join(plain(x).split()) for x in record['sections'] if x['tag']=='Prerequisites')
    note='\n'.join([i18n._('Справочный сценарий: {id}, {name}; CAPEC {version} от {date}.',id=record['id'],name=record['name'],
                           version=data['meta'].get('version'),date=data['meta'].get('source_date')),
        i18n._('Предпосылки из CAPEC: {text}',text=prerequisites or i18n._('Не указаны в источнике.')),
        i18n._('Подсказка приложения: проверить входные данные, достижимость операции и действующие ограничения.'),
        i18n._('Наблюдаемые факты и ссылки на код/тест: [заполняет оператор].'),
        i18n._('Вывод о применимости и основание: [заполняет оператор].')])
    return render(request,'capec/detail.html',{**data,'record':record,'links':links,'back_url':back_url(request),'check_note':note,'rich':rich})


def cwe_values(value):
    return sorted(set(x.upper() for x in re.findall(r'CWE-\d+',str(value),re.I)))


def related_context(request, values, project_id):
    store=request.app.state.feeds
    with store.snapshot():
        data=store.capec_data(shared=True)
        found=store.capec_for_cwes(values)
        items=[{'id':k,'name':data['records'].get(k,{}).get('name',i18n._('Запись CAPEC пока не загружена')),**v} for k,v in found.items()]
        status=store.status()
    items.sort(key=lambda r:({'Standard':0,'Detailed':1,'Meta':2}.get(data['records'].get(r['id'],{}).get('abstraction'),3),int(r['id'].split('-')[1])))
    url=getattr(request,'url',None)
    return {'candidates':items[:5],'total':len(items),'values':values,'meta':data['meta'],
            'source_labels':{key.upper():key.upper()+' '+str(value.get('version','')) for key,value in status.items()},
            'url':f'/projects/{project_id}/capec?'+urlencode({'cwe':','.join(values)}),
            'back':url.path+('?' +url.query if url.query else '') if url else f'/projects/{project_id}/components'}


def project_matches(request, project_id):
    from app.routes.common import db_of
    rows=db_of(request).finding_descriptors(project_id,{})
    rows=[r for r in rows if not r['missing']]
    params=request.query_params
    for key,field in [('finding_kind','kind'),('codebase','codebase'),('finding_severity','severity')]:
        if params.get(key):rows=[r for r in rows if r.get(field)==params[key]]
    if params.get('reviewed') in ('yes','no'):rows=[r for r in rows if bool(r['reviewed'])==(params['reviewed']=='yes')]
    from app import cvss
    selection=cvss.parse({k:params.get(k,'') for k in ('cvss_min','cvss_max','cvss_version')})
    if selection['errors']:raise HTTPException(400,' '.join(selection['errors']))
    if selection['active']:
        rows=[{**r,'cvss_versions':{cvss.version_of(r['data']):r['cvss']}} for r in rows]
        rows=cvss.select(rows,selection['version'],cvss.bounds_item(selection['min'],selection['max']) or selection['item'])
    values={r['id']:cwe_values(r['data'].get('cwe',[])) for r in rows}
    links=request.app.state.feeds.capec_for_cwes({v for group in values.values() for v in group})
    matches={k:[r for r in rows if set(values[r['id']]) & set(v['cwes'])] for k,v in links.items()}
    return rows,values,matches


def component_context(request, project_id, row):
    from app.routes.common import db_of
    from app import package_identity
    found=db_of(request).finding_descriptors(project_id,{})
    vals=set()
    for item in found:
        d=item['data']
        # эффективная тройка (план dev17, п. 4.3)
        if not item['missing'] and item['kind'] in ('SCA','SCA-license') and package_identity.of(d)==(row['ecosystem'],row['name'],row['version']):
            vals.update(cwe_values(d.get('cwe',[])))
    return related_context(request,sorted(vals),project_id)


@router.get('/projects/{project_id}/capec',response_class=HTMLResponse)
def project_catalog(request:Request,project_id:int):
    from app.routes.common import project_or_404
    project=project_or_404(request,project_id)
    rows,values,matches=project_matches(request,project_id)
    scenario=capec.identifier(request.query_params.get('scenario',''))
    chosen=matches.get(scenario,[]) if scenario else []
    ctx=catalog_context(request,project=project,allowed=set(matches),matches=matches)
    size=ctx['worklist']['size']
    page=max(1,min(worklists.integer(request.query_params.get('finding_page')),max(1,(len(chosen)+size-1)//size)))
    params={k:v for k,v in request.query_params.items() if k!='finding_page'}
    def href(number):return request.url.path+'?'+urlencode({**params,'finding_page':number})+'#source-findings'
    db=request.app.state.db
    ctx.update(counts=db.count_findings(project_id),review_stats=db.review_stats(project_id))
    ctx.update(scenario=scenario,scenario_reset=ctx['path']+'?'+ctx['scenario_query']+'#capec-results',
               project_findings=chosen[(page-1)*size:page*size],finding_count=len(chosen),finding_page=page,
               finding_pages=max(1,(len(chosen)+size-1)//size),finding_prev=href(page-1) if page>1 else '',
               finding_next=href(page+1) if page*size<len(chosen) else '',
               project_codebases=sorted({r['codebase'] for r in request.app.state.db.finding_descriptors(project_id,{})}),
               coverage={'total':len(rows),'cwe':sum(bool(v) for v in values.values()),'linked':len({r['id'] for group in matches.values() for r in group})})
    return render(request,'capec/index.html',ctx)
