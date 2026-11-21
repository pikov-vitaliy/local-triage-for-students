"""Журнал пакетного триажа локальной моделью."""
import csv
import io
from collections import defaultdict
from datetime import date

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from app import journal, worklists
from app.db import RUN_STATES
from app.executors import executor_label
from app.routes.common import db_of, render

router = APIRouter()
SORTS = {'newest', 'oldest', 'duration_desc', 'speed_desc', 'answers_desc'}


def selection(request):
    filters = {k: request.query_params.get(k, '')[:200] for k in ('model', 'project', 'state', 'language', 'from', 'to', 'sort')}
    for key in ('from', 'to'):
        if filters[key]:
            try:
                date.fromisoformat(filters[key])
            except ValueError:
                raise HTTPException(400, 'Дата должна быть в формате ГГГГ-ММ-ДД.') from None
    if filters['from'] and filters['to'] and filters['from'] > filters['to']:
        raise HTTPException(400, 'Начало периода позже конца.')
    if filters['state'] and filters['state'] not in RUN_STATES:
        raise HTTPException(400, 'Неизвестное состояние прогона.')
    if filters['project'] and not (filters['project'].isascii() and filters['project'].isdigit()
                                   and len(filters['project']) <= 18):
        raise HTTPException(400, 'Неизвестный проект.')
    if filters['sort'] and filters['sort'] not in SORTS:
        raise HTTPException(400, 'Неизвестная сортировка.')
    rows = journal.collect(db_of(request), filters)
    sort = filters['sort']
    if sort == 'oldest':
        rows.reverse()
    elif sort in ('duration_desc', 'speed_desc', 'answers_desc'):
        key = {'duration_desc': 'active_seconds', 'speed_desc': 'tokens_per_second', 'answers_desc': 'new_answers'}[sort]
        rows.sort(key=lambda r: (r[key] is not None, r[key] or 0), reverse=True)
    return filters, rows


@router.get('/journal')
def index(request: Request):
    db = db_of(request)
    filters, rows = selection(request)
    assessments = journal.review_counts(db,[x['run']['id'] for x in rows])
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['run']['model']].append(row)
    models = []
    for name, group in sorted(grouped.items()):
        tokens = sum(x['run']['output_tokens'] for x in group)
        duration = sum(x['run']['eval_seconds'] for x in group)
        agree=sum(assessments.get(x['run']['id'],{}).get('agree',0) for x in group)
        disagree=sum(assessments.get(x['run']['id'],{}).get('disagree',0) for x in group)
        models.append({'name': name, 'runs': len(group), 'new': sum(x['new_answers'] for x in group),
                       'errors': sum(x['run']['failed'] for x in group), 'tps': tokens / duration if duration else None,
                       'assessed':agree+disagree,'agreement':100*agree/(agree+disagree) if agree+disagree else None,
                       'partial':sum(x['run']['partial_stats'] for x in group)})
    params = dict(filters)
    params.update({k: request.query_params.get(k, '') for k in ('page', 'page_size')})
    table = worklists.table(rows, params, path='/journal')
    executions = db.get_executions(row['run'].get('execution_id') for row in table['rows'])
    providers = {int(p['id']): p for p in db.list_providers()}
    for row in table['rows']:  # чей ответ (ADR-0102): профиль снимка исполнителя – только у строк этой страницы
        row['executor'] = executor_label(db, executions.get(row['run'].get('execution_id')), providers)
    return render(request, 'journal/index.html', {
        'filters': filters, 'table': table, 'models': models,
        'model_choices': db._all('SELECT DISTINCT model FROM runs ORDER BY model'),
        'language_choices': db._all("SELECT DISTINCT x.key AS language FROM run_journal j,json_object_keys(j.payload_json::json -> 'queue' -> 'languages') AS x(key) ORDER BY x.key"),
        'project_choices': db._all('SELECT id,name FROM projects ORDER BY name'), 'states': RUN_STATES,
        'total_runs': len(rows), 'new_answers': sum(x['new_answers'] for x in rows),
        'errors': sum(x['run']['failed'] for x in rows), 'export_query': str(request.query_params)})


@router.get('/journal/export.json')
def export_json(request: Request):
    from app import __version__
    from app.db import now_iso
    filters, rows = selection(request)
    db = db_of(request)
    data = [detail for r in rows if (detail := journal.detail(db, r['run']['id'])) is not None]
    # /2 (ADR-0102): поля /1 с теми же именами и смыслом плюс provider у каждого прогона
    return JSONResponse({'contract': 'local-triage/run-journal/2', 'application_version': __version__,
                         'exported_at': now_iso(), 'installation_id': db._scalar("SELECT value FROM meta WHERE key='journal_installation'"),
                         'filters': filters, 'runs': data},
                        headers={'Content-Disposition': 'attachment; filename="run-journal.json"'})


@router.get('/journal/export.csv')
def export_csv(request: Request):
    _, rows = selection(request)
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter=';')
    writer.writerow(['Установка', 'Прогон', 'Создан', 'Проект', 'Модель', 'Состояние', 'В очереди', 'Новые ответы',
                     'Кэш', 'Ошибки', 'Пропуски', 'Активно секунд', 'Токенов в секунду', 'Промпт', 'Вход SHA256',
                     'GPU', 'VRAM МиБ', 'RAM байт', 'Окружений', 'Модель digest', 'Квантизация', 'Окно контекста',
                     'Контекст SHA256', 'TP', 'FP', 'Неясно', 'Согласие %', 'Проверенных оценок',
                     'Провайдер', 'Где модель'])
    installation = db_of(request)._scalar("SELECT value FROM meta WHERE key='journal_installation'")
    for row in rows:
        detail = journal.detail(db_of(request), row['run']['id'])
        if detail is None:continue
        row = detail
        r = row['run']
        environments=detail['snapshot'].get('environments',[])
        passport=environments[-1]['data'] if environments else {}
        gpu=passport.get('gpu') or {}
        model=passport.get('model') or {}
        values = [installation, r['id'], r['created_at'], r['project_name'], r['model'], r['state'], r['total'],
                  row['new_answers'], r['cached'], r['failed'], r['skipped'], row['active_seconds'],
                  row['tokens_per_second'], r['prompt_version'], row['snapshot'].get('workload_sha256', ''),
                  gpu.get('name'),gpu.get('memory_total_mb'),passport.get('host_memory_total'),len(environments),
                  model.get('digest'),model.get('quant'),(passport.get('options') or {}).get('num_ctx'),
                  detail['context_sha256'],detail['verdicts'].get('true_positive',0),detail['verdicts'].get('false_positive',0),
                  detail['verdicts'].get('uncertain',0),detail['agreement_pct'],detail['review_denominator'],
                  detail['provider']['name'],detail['provider']['where']]
        writer.writerow(["'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else v for v in values])
    return Response('\ufeff' + stream.getvalue(), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="run-journal.csv"'})


@router.get('/journal/{run_id}')
def show(request: Request, run_id: int):
    data = journal.detail(db_of(request), run_id)
    if data is None:
        raise HTTPException(404, 'Прогон не найден.')
    return render(request, 'journal/detail.html', {'item': data,
                  'back_url': worklists.return_url(request, '/journal')})
