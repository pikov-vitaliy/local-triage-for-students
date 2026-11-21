"""Паспорта прогонов и статистика, независимая от открытого браузера."""
from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import Counter
from datetime import datetime
from time import monotonic

def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(encode(value).encode('utf-8')).hexdigest()


def seconds(start, end):
    if not start or not end:
        return None
    try:
        return max(0., (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except (ValueError, TypeError):
        return None


def composition(rows):
    return {'total': len(rows), **{key: dict(Counter(str(r.get(key) or 'не указано') for r in rows))
                                for key in ('kinds', 'languages', 'severities', 'rules')}}


def capture(c, run_id, project_id, hub_ids, excluded=None):
    rows = [dict(r) for r in c.execute('SELECT hub_id,kind,severity,data_json FROM findings '
                                      'WHERE project_id=? AND missing=0 ORDER BY hub_id', (project_id,))]
    selected = set(hub_ids)
    def describe(row):
        data = json.loads(row['data_json'])
        return {'kinds': row['kind'], 'languages': data.get('language'),
                'severities': row['severity'], 'rules': data.get('rule') or data.get('component')}
    queued = [r for r in rows if r['hub_id'] in selected]
    payload = {'input': composition([describe(r) for r in rows]),
               'queue': composition([describe(r) for r in queued]),
               'workload_sha256': digest([json.loads(r['data_json']) for r in queued]),
               'environments': []}
    if excluded is not None:  # исключённые охватом «живые в Hub» – тем же чтением, что очередь (бэклог 104);
        # {} – охват без отбора по статусу Hub; ключа нет – прогон до 0.10.0.dev18 или продолжение: сведений нет
        payload['excluded'] = ({'fixed': int(excluded.get('fixed', 0)), 'closed': int(excluded.get('closed', 0))}
                               if excluded else {})
    c.execute('INSERT INTO run_journal(run_id,payload_json) VALUES (?,?)', (run_id, encode(payload)))


def transition(c, run_id, state, at, *, interrupted=False, clocks=None):
    row = c.execute('SELECT active_since FROM run_journal WHERE run_id=?', (run_id,)).fetchone()
    if not row:
        return
    tick = clocks.get(run_id) if clocks is not None else None
    elapsed = (max(0,monotonic()-tick[0]) if tick and tick[1]==row['active_since'] and not interrupted
               else seconds(row['active_since'], at) or 0.)
    c.execute('UPDATE run_journal SET active_seconds=active_seconds+?,active_since=?, '
              'incomplete=GREATEST(incomplete,?) WHERE run_id=?',
              (elapsed, at if state == 'running' else None, int(interrupted), run_id))
    if clocks is not None:
        if state == 'running':clocks[run_id]=(monotonic(),at)
        else:clocks.pop(run_id,None)


def review_event(c, project_id=None, hub_id=None):
    """История оценки ответа; автоматический сброс текущей проверки её не переписывает."""
    where = ' AND project_id=? AND hub_id=?' if project_id is not None else ''
    c.execute('INSERT INTO run_review_events(project_id,hub_id,verdict_id,revision,decision,final_verdict,reviewed,observed_at) '
              'SELECT project_id,hub_id,verdict_id,revision,decision,final_verdict,reviewed,updated_at FROM reviews '
              'WHERE verdict_id IS NOT NULL' + where + ' ON CONFLICT(project_id,hub_id,revision) DO NOTHING',
              (project_id, hub_id) if where else ())


def environment(db, run_id, value):
    """Снимок каждого отличающегося окружения; продолжение не затирает прежний паспорт."""
    from app.db import now_iso
    with db._tx() as c:
        row = c.execute('SELECT payload_json FROM run_journal WHERE run_id=?', (run_id,)).fetchone()
        if not row:
            return
        payload = json.loads(row['payload_json'])
        environments = payload.setdefault('environments', [])
        fingerprint = digest(value)
        if not environments or environments[-1]['sha256'] != fingerprint:
            environments.append({'at': now_iso(), 'sha256': fingerprint, 'data': value})
        c.execute('UPDATE run_journal SET payload_json=? WHERE run_id=?', (encode(payload), run_id))


def resources(db, data, host, run_ids=None):
    """Средние и пики ресурсов хоста во время прогона; это не расход одной модели. run_ids – только эти идущие
    прогоны (метрики их сервера модели, ADR-0102); None – все идущие."""
    gpu = data.get('gpu') or {}
    memory = host.get('memory') if host.get('status') == 'fresh' else None
    values = {'gpu_pct': gpu.get('util_pct'), 'vram_mb': data.get('vram_used_mb'),
              'ram_gib': memory['used_bytes'] / 1024**3 if memory else None,
              'cpu_pct': host.get('cpu_pct') if host.get('status') == 'fresh' else None}
    with db._tx() as c:
        rows = c.execute("SELECT j.run_id,j.payload_json FROM run_journal j JOIN runs r ON r.id=j.run_id WHERE r.state='running'").fetchall()
        if run_ids is not None:
            wanted = {int(x) for x in run_ids}
            rows = [row for row in rows if int(row['run_id']) in wanted]
        for row in rows:
            payload = json.loads(row['payload_json'])
            aggregate = payload.setdefault('resources', {'samples': 0})
            aggregate['samples'] += 1
            for key, value in values.items():
                if type(value) in (int, float) and math.isfinite(value):
                    stat = aggregate.setdefault(key, {'count': 0, 'sum': 0, 'max': value})
                    stat['count'] += 1; stat['sum'] += value; stat['max'] = max(stat['max'], value)
            c.execute('UPDATE run_journal SET payload_json=? WHERE run_id=?', (encode(payload), row['run_id']))


def call_sample(c, run_id, duration):
    if duration is None or duration <= 0:
        return
    row = c.execute('SELECT payload_json FROM run_journal WHERE run_id=?', (run_id,)).fetchone()
    if row:
        payload = json.loads(row['payload_json'])
        payload['model_durations'] = (payload.get('model_durations', []) + [duration])[-20:]
        c.execute('UPDATE run_journal SET payload_json=? WHERE run_id=?', (encode(payload), run_id))


def eta_median(db, run_id):
    """Медиана времени ответа модели без загрузки (не среднее): отдельный очень долгий ответ не сдвигает оценку.
    Меньше трёх замеров – оценки нет. Медленные ответы и первый ответ после загрузки модели в выборку не попадают
    (app/triage.py передаёт это через Database.finish_item)."""
    row = db._one('SELECT payload_json FROM run_journal WHERE run_id=?', (run_id,))
    samples = json.loads(row['payload_json']).get('model_durations', []) if row else []
    return statistics.median(samples) if len(samples) >= 3 else None


# Историческое имя: на него ссылаются прежние вызовы и проверки. Считается медиана, а не среднее.
eta_average = eta_median


SLOW_MODEL_KEY = 'slow_model'  # раздел payload_json журнала прогона: медленный режим и перезагрузки


def slow_model_state(db, run_id):
    """Что записано в журнал прогона о медленном режиме модели: reloads, text, warning, events (может быть пусто)."""
    row = db._one('SELECT payload_json FROM run_journal WHERE run_id=?', (run_id,))
    value = json.loads(row['payload_json']).get(SLOW_MODEL_KEY) if row else None
    return value if isinstance(value, dict) else {}


def slow_model_event(db, run_id, *, action, tps, baseline, text, reloads):
    """Событие медленного режима в журнал прогона (страница «Журнал»): перезагрузка или предупреждение.
    Схема базы не меняется: запись живёт в payload_json журнала прогона."""
    from app.db import now_iso
    with db._tx() as c:
        row = c.execute('SELECT payload_json FROM run_journal WHERE run_id=?', (run_id,)).fetchone()
        if not row:
            return
        payload = json.loads(row['payload_json'])
        data = payload.setdefault(SLOW_MODEL_KEY, {})
        data['reloads'] = int(reloads)
        data['text'] = str(text)
        data['warning'] = action == 'warning'
        data['tps'] = round(float(tps), 1)
        data['baseline'] = round(float(baseline), 1)
        events = data.get('events') if isinstance(data.get('events'), list) else []
        events = events[-19:] + [{'at': now_iso(), 'action': action, 'tps': round(float(tps), 1),
                                  'baseline': round(float(baseline), 1), 'reloads': int(reloads)}]
        data['events'] = events
        c.execute('UPDATE run_journal SET payload_json=? WHERE run_id=?', (encode(payload), run_id))


def summary(row, now, clocks=None):
    row = dict(row)
    payload = json.loads(row.pop('payload_json', None) or '{}')
    active = row.pop('active_seconds', None)
    since = row.pop('active_since', None)
    incomplete = bool(row.pop('incomplete', 0))
    tick = clocks.get(row['id']) if clocks is not None else None
    extra = max(0,monotonic()-tick[0]) if tick and tick[1]==since else seconds(since, now) or 0
    active = active + extra if active is not None else None
    end = row.get('finished_at') or now
    done = max(0, row['done'] - row['failed'] - row['cached'] - row['skipped'])
    return {'run': row, 'snapshot': payload, 'new_answers': done,
            'pending': max(0, row['total'] - row['done']), 'active_seconds': active,
            'elapsed_seconds': seconds(row['started_at'], end), 'time_incomplete': incomplete,
            'tokens_per_second': row['output_tokens'] / row['eval_seconds'] if row['eval_seconds'] > 0 else None,
            'answers_per_hour': done * 3600 / active if active and done else None}


SELECT = ('SELECT r.*,p.name AS project_name,j.payload_json,j.active_seconds,j.active_since,j.incomplete '
          'FROM runs r JOIN projects p ON p.id=r.project_id LEFT JOIN run_journal j ON j.run_id=r.id ')


def collect(db, filters):
    from app.db import now_iso
    clauses, args = [], []
    for key, column in [('model', 'r.model'), ('project', 'r.project_id'), ('state', 'r.state')]:
        if filters.get(key):
            clauses.append(column + '=?'); args.append(filters[key])
    if filters.get('language'):
        clauses.append("EXISTS(SELECT 1 FROM json_object_keys(j.payload_json::json -> 'queue' -> 'languages') AS x(key) WHERE key=?)")
        args.append(filters['language'])
    for key, sign, suffix in [('from', '>=', 'T00:00:00'), ('to', '<=', 'T23:59:59.999999')]:
        if filters.get(key):
            clauses.append('r.created_at' + sign + '?'); args.append(filters[key] + suffix)
    light = SELECT.replace('j.payload_json', "json_build_object('workload_sha256',j.payload_json::json -> 'workload_sha256',"
                           "'hardware',j.payload_json::json -> 'environments' -> -1 -> 'data' -> 'gpu' -> 'name') AS payload_json")
    with db._run_clocks_lock, db._lock:
        rows = db._all(light + ('WHERE ' + ' AND '.join(clauses) if clauses else '') + ' ORDER BY r.id DESC', args)
        now = now_iso()
        return [summary(r, now, db._run_clocks) for r in rows]


def review_counts(db, run_ids):
    result = {}
    for offset in range(0,len(run_ids),500):
        ids=run_ids[offset:offset+500]
        marks=','.join('?' for _ in ids)
        rows=db._all('SELECT i.run_id,re.decision,COUNT(*) AS n FROM run_items i JOIN runs r ON r.id=i.run_id '
                     'JOIN run_review_events re ON re.project_id=r.project_id AND re.hub_id=i.hub_id AND re.verdict_id=i.verdict_id '
                     f"WHERE i.run_id IN ({marks}) AND i.state='done' AND re.reviewed=1 "
                     'AND re.id=(SELECT MAX(ev.id) FROM run_review_events ev WHERE ev.project_id=re.project_id '
                     'AND ev.hub_id=re.hub_id AND ev.verdict_id=re.verdict_id) GROUP BY i.run_id,re.decision',ids)
        for row in rows:result.setdefault(row['run_id'],{})[row['decision']]=row['n']
    return result


def detail(db, run_id):
    from app.db import now_iso
    with db._run_clocks_lock, db._lock:
        row = db._one(SELECT + 'WHERE r.id=?', (run_id,))
        if row is None:
            return None
        result = summary(row, now_iso(), db._run_clocks)
        contexts = db._all('SELECT seq,case_hash FROM run_items WHERE run_id=? ORDER BY seq', (run_id,))
        result['context_sha256'] = (digest([[r['seq'], r['case_hash']] for r in contexts])
                                    if contexts and all(r['case_hash'] for r in contexts) and row['done'] == row['total'] else None)
        for field, state in [('verdicts','done'),('cached_verdicts','cached')]:
            result[field] = {r['verdict']: r['n'] for r in db._all(
                'SELECT v.verdict,COUNT(*) AS n FROM run_items i JOIN verdicts v ON v.id=i.verdict_id '
                'WHERE i.run_id=? AND i.state=? GROUP BY v.verdict', (run_id,state))}
        result['reviews'] = review_counts(db,[run_id]).get(run_id,{})
        reviews = result['reviews']
        denominator = reviews.get('agree', 0) + reviews.get('disagree', 0)
        result['agreement_pct'] = reviews.get('agree', 0) * 100 / denominator if denominator else None
        result['review_denominator'] = denominator
        # профиль исполнителя (run-journal/2, ADR-0102): имя, версия и класс доверия, без адреса сервера
        from app.executors import executor_info
        result['provider'] = executor_info(db, db.get_execution(row.get('execution_id')))
        return result
