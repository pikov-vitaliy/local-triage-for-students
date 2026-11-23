"""Один наблюдатель ресурсов: неблокирующие снимки и ограниченная история, отдельно от триажа."""
from __future__ import annotations
import copy
import json
import math
import sqlite3
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from app import i18n


def host_snapshot(path, now=None):
    now=time.time() if now is None else now
    missing={'status':'unavailable','memory':None,'cpu_pct':None,'scope':'ollama_host','sampled_at':None}
    try:
        path=Path(path)
        if path.stat().st_size>16384:return missing
        data=json.loads(path.read_text(encoding='utf-8-sig'))
        stamp=float(data['sampled_at'])
        memory=data['memory']
        total,available=memory['total_bytes'],memory['available_bytes']
        if data['schema']!=1 or data['host_scope']!='ollama_host' or not all(type(x) in (int,float) and math.isfinite(x) for x in (stamp,total,available)) or not 0<=available<=total or total<=0:return missing
        cpu=data.get('cpu_pct')
        if type(cpu) not in (int,float) or not math.isfinite(cpu) or not 0<=cpu<=100:cpu=None
        raw=data.get('addresses')
        addresses=[str(a)[:64] for a in raw[:64] if isinstance(a,str)] if isinstance(raw,list) else None
        return {'status':'fresh' if -5<=now-stamp<=30 else 'stale','sampled_at':stamp,
                'scope':'ollama_host','collector_id':str(data.get('collector_id',''))[:100],
                'memory':{'total_bytes':total,'available_bytes':available,'used_bytes':total-available},'cpu_pct':cpu,
                'addresses':addresses}
    except (OSError,ValueError,KeyError,TypeError):return missing


HOST_ADDRESSES_FRESH_S = 300  # адреса хоста от сборщика свежи 5 минут (внешний профиль, llm_net.HOST_SOURCE)


def host_addresses_from(path, now=None):
    """Адреса компьютера-хоста от сборщика метрик, если снимок свежий (не старше HOST_ADDRESSES_FRESH_S) и адреса в нём
    есть; иначе None."""
    now=time.time() if now is None else now
    return _fresh_addresses(host_snapshot(path,now),now)


def _fresh_addresses(snapshot, now):
    stamp=snapshot.get('sampled_at')
    if stamp is None or not -5<=now-stamp<=HOST_ADDRESSES_FRESH_S or not snapshot.get('addresses'):return None
    return list(snapshot['addresses'])


COLLECTOR_DOWN_S = 60  # сборщик пишет снимок раз в 5 с: минута без снимка – он не работает


def collector_state(path, expected, now=None):
    """Работает ли сборщик метрик компьютера (scripts/host-metrics.ps1) – для предупреждения на страницах
    (HOSTCOL-01: после перезагрузки компьютера контейнер поднимается сам, а сборщик – нет).
    expected – приложение в контейнере: там его вместе со сборщиком запускает start.ps1; вне контейнера
    предупреждение – только если сборщик здесь уже работал (host.json есть). state: ok, stale (снимок старше минуты),
    missing (снимка нет или он не читается), not_used (сборщик здесь не используется). addresses – есть ли свежие
    адреса компьютера для внешних провайдеров (host_addresses_from); detail – что видно, словами."""
    now=time.time() if now is None else now
    path=Path(path)
    snapshot=host_snapshot(path,now)  # одно чтение файла: и состояние, и адреса
    stamp=snapshot.get('sampled_at')
    addresses=_fresh_addresses(snapshot,now) is not None
    if stamp is not None and -5<=now-stamp<=COLLECTOR_DOWN_S:
        state='ok'
    elif not expected and not path.exists():
        state='not_used'
    else:
        state='stale' if stamp is not None else 'missing'
    age=None if stamp is None else abs(now-stamp)
    if state=='stale':
        minutes=int(age//60)
        detail=(i18n._('последний снимок {minutes} мин назад',minutes=minutes) if minutes<120
                else i18n._('последний снимок {hours} ч назад',hours=minutes//60))
    elif state=='missing':
        detail=i18n._('снимков от него нет')
    elif state=='ok' and not addresses:
        detail=i18n._('сборщик работает, но адреса компьютера не прочитались')
    else:
        detail=''
    return {'state':state,'expected':bool(expected),'addresses':addresses,'sampled_at':stamp,
            'age_s':None if age is None else round(age),'detail':detail}


class Telemetry:
    def __init__(self, folder, compute, interval=5):
        self.folder=Path(folder)
        self.folder.mkdir(parents=True,exist_ok=True)
        self.compute=compute
        self.interval=interval
        self._lock=threading.RLock()
        self._stop=threading.Event()
        self._ready=threading.Event()
        self._thread=None
        self._data={}
        self._series={}  # краткая история по рядам сервера модели (server_tag): у каждого – свои 180 точек
        self._last_at=None
        self._sequence=0
        self.epoch=uuid.uuid4().hex
        self._servers={}  # снимки серверов идущих прогонов (remember)
        self._wanted={}  # серверы, метрики которых попросили страницы (want)
        self._history_error=''
        self._conn=None
        try:
            self._conn=sqlite3.connect(str(self.folder/'telemetry.db'),check_same_thread=False)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute('PRAGMA journal_size_limit=1048576')
            self._conn.execute('PRAGMA wal_autocheckpoint=128')
            page_size=self._conn.execute('PRAGMA page_size').fetchone()[0]
            self._conn.execute('PRAGMA max_page_count='+str(48*1024**2//page_size))
            self._conn.execute('CREATE TABLE IF NOT EXISTS telemetry_meta(schema_version INTEGER)')
            if not self._conn.execute('SELECT 1 FROM telemetry_meta').fetchone():self._conn.execute('INSERT INTO telemetry_meta VALUES (1)')
            self._conn.execute('CREATE TABLE IF NOT EXISTS resource_samples(minute INTEGER,epoch TEXT,data_json TEXT,PRIMARY KEY(minute,epoch))')
            self._conn.commit()
        except sqlite3.Error:self._history_error=i18n.N_('История ресурсов недоступна.')

    def start(self):
        if self._thread is not None:return
        self._thread=threading.Thread(target=self._run,name='resource-observer',daemon=True)
        self._thread.start()
        self._ready.wait(.2)

    def _run(self):
        while not self._stop.is_set():
            try:
                directory=self.folder/'telemetry';directory.mkdir(exist_ok=True)
                (directory/'lease').write_text(str(time.time()),encoding='ascii')
            except OSError:pass
            try:
                data=self.compute()
                self.record(data if isinstance(data,dict) else {})
            except Exception:
                self.record({'gpu':None,'models':[],'error':i18n._('Измерения ресурсов временно недоступны.')})
            self._ready.set()
            self._stop.wait(self.interval)

    @staticmethod
    def server_tag(server):
        """Метка ряда истории: сервер модели ('local|адрес' или 'remote|адрес'); '' – снимок без метки (до 0.9.12)."""
        if isinstance(server,dict):
            if not server.get('base_url'):return ''
            return ('local|' if server.get('local') else 'remote|')+str(server['base_url'])
        return ('local|' if server[1] else 'remote|')+str(server[0])

    def local_host(self,now=None):
        """Память и процессор этого компьютера из сборщика хоста – независимо от того, чей снимок сейчас у наблюдения."""
        return host_snapshot(self.folder/'telemetry'/'host.json',time.time() if now is None else now)

    def want(self,server,now=None):
        """Страница просит метрики сервера, которого наблюдение сейчас не измеряет: оно измерит его в ближайший цикл
        (wanted) – страница сама сервер не опрашивает."""
        with self._lock:  # сервер целиком (класс доверия, адреса, ключ) – фоновый опрос идёт по его правилам
            self._wanted[server]=time.time() if now is None else now
            while len(self._wanted)>8:self._wanted.pop(next(iter(self._wanted)))

    def wanted(self,max_age=60,now=None):
        now=time.time() if now is None else now
        with self._lock:
            return [k for k,at in self._wanted.items() if now-at<=max_age]

    def pending(self,server,empty):
        """Ответ «ещё не измерено» для сервера, которого нет в наблюдении: без сетевых обращений."""
        data=copy.deepcopy(empty)
        data.update(server={'base_url':str(server[0]),'local':bool(server[1])},observed_at=None,
                    resource_status='unavailable',pending=True,history_error=i18n._(self._history_error),
                    host=self.local_host() if server[1] else self._remote_host())
        return data

    @staticmethod
    def _remote_host():
        return {'status':'remote','memory':None,'cpu_pct':None,'scope':'remote','sampled_at':None}

    def _view(self,data,now):
        """Снимок для страницы: свежесть данных хоста и ресурсов по одному правилу для всех серверов."""
        data.setdefault('gpu',None);data.setdefault('models',[])
        stamp=data.get('observed_at')
        host=data.get('host') or {}
        if host.get('sampled_at') and now-host['sampled_at']>30:
            host['status']='stale'
        data['resource_status']='unavailable' if stamp is None or not data.get('gpu') and not data.get('models') and host.get('status')!='fresh' else 'stale' if now-stamp>30 else 'fresh'
        data['history_error']=i18n._(self._history_error)
        return data

    def _point(self,data,host,now):
        """Точка истории и её ряд (source_epoch): эпоха наблюдения, сборщик, видеокарта и сервер модели – ряды разных
        серверов не сливаются ни на графике, ни в поминутных средних."""
        gpu=data.get('gpu') or {}
        memory=host['memory'] if host.get('status')=='fresh' else None
        tag=self.server_tag(data.get('server') or {})
        source=self.epoch+':'+host.get('collector_id','')+':'+str(gpu.get('name',''))+('|'+tag if tag else '')
        return {'at':now,'source_epoch':source,'server':tag,'gpu':gpu.get('util_pct'),'vram':data.get('vram_used_mb'),
                'ram':(memory['used_bytes']/1024**3) if memory else None,'cpu':host['cpu_pct'] if host.get('status')=='fresh' else None}

    def _host(self,data,now):
        """Память и процессор этого компьютера – только если снимок сервера модели на нём (server.local, ADR-0102
        п. 9); сервер в сети – {'status':'remote'}. Снимок без метки сервера – как раньше, этот компьютер."""
        if (data.get('server') or {}).get('local') is False:
            return {'status':'remote','memory':None,'cpu_pct':None,'scope':'remote','sampled_at':None}
        return host_snapshot(self.folder/'telemetry'/'host.json',now)

    def remember(self,server,data,now=None,point=True):
        """Снимок метрик сервера идущего прогона или запрошенного страницей (не профиля приложения): страницы берут его
        (server_snapshot), а не опрашивают сервер сами; точка – в историю этого сервера."""
        now=time.time() if now is None else now
        item=copy.deepcopy(data if isinstance(data,dict) else {})
        item.setdefault('server',{'base_url':str(server[0]),'local':bool(server[1])})
        item.update(observed_at=now,host=self._host(item,now))
        mark=self._point(item,item['host'],now)
        with self._lock:
            self._servers[tuple(server)]=item
            while len(self._servers)>8:self._servers.pop(next(iter(self._servers)))
            series=self._series.get(mark['server'])
            # point=False – ряд этого сервера пишет record (тот же сервер, что у профиля приложения); два профиля
            # одного сервера в одном цикле – одна точка
            if not point or series and now-series[-1]['at']<self.interval/2:return
            self._append(mark)
            self._store(mark,now)

    def server_snapshot(self,server,now=None,max_age=30):
        """Запомненный снимок сервера (remember) не старше max_age секунд или None; свежесть – как у snapshot()."""
        now=time.time() if now is None else now
        with self._lock:
            item=copy.deepcopy(self._servers.get(tuple(server)))
        if not item or now-item.get('observed_at',0)>max_age:return None
        return self._view(item,now)

    def record(self,data,now=None):
        now=time.time() if now is None else now
        host=self._host(data,now)
        with self._lock:
            self._sequence+=1
            self._data=copy.deepcopy(data)
            self._data.update(observed_at=now,sequence=self._sequence,sampler_epoch=self.epoch,host=host)
            self._last_at=now
            point=self._point(data,host,now)
            self._append(point)
            self._store(point,now)

    def _append(self,point):
        """Точка – в краткую историю своего ряда; рядов не больше 9 (сервер приложения и до 8 запомненных)."""
        series=self._series.setdefault(point.get('server',''),deque(maxlen=180))
        series.append(point)
        while len(self._series)>9:self._series.pop(next(iter(self._series)))

    def _store(self,point,now):
        """Поминутные средние и пики точки – в базу истории (под замком наблюдения)."""
        source=point['source_epoch']
        if self._conn:
            try:
                minute=int(now//60)
                epoch=source
                old=self._conn.execute('SELECT data_json FROM resource_samples WHERE minute=? AND epoch=?',(minute,epoch)).fetchone()
                stats=json.loads(old[0]) if old else {}
                for key in ('gpu','vram','ram','cpu'):
                    v=point[key]
                    if type(v) in (float,int) and math.isfinite(v):
                        item=stats.setdefault(key,{'sum':0,'max':v,'count':0})
                        item['sum']+=v;item['max']=max(item['max'],v);item['count']+=1
                self._conn.execute('INSERT OR REPLACE INTO resource_samples VALUES (?,?,?)',(minute,epoch,json.dumps(stats)))
                self._conn.execute('DELETE FROM resource_samples WHERE minute<?',(minute-7*1440,))
                if minute%10==0:self._conn.execute('DELETE FROM resource_samples WHERE rowid NOT IN (SELECT rowid FROM resource_samples ORDER BY minute DESC LIMIT 12000)')
                self._conn.commit()
                if self._sequence%12==0:
                    self._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    if sum(p.stat().st_size for p in self.folder.glob('telemetry.db*'))>50*1024**2:
                        self._conn.close();self._conn=None
                        self._history_error=i18n.N_('История ресурсов остановлена: достигнут предел 50 МиБ.')
            except (sqlite3.Error,OSError):self._history_error=i18n.N_('История ресурсов временно не сохраняется.')

    def snapshot(self,now=None):
        now=time.time() if now is None else now
        with self._lock:
            data=copy.deepcopy(self._data)
        return self._view(data,now)

    def history(self,window='15m',server=None):
        """Точки истории за 15 минут или средние по минутам за 24 часа; server – метка ряда (server_tag): только точки
        этого сервера модели (страница прогона – сервер его исполнителя); '' – ряд без метки сервера (история до
        0.9.12, страницы прежних прогонов). None – все ряды. Окно и предел числа точек – у каждого ряда свои."""
        with self._lock:
            if window=='15m':
                rows=[p for tag,series in self._series.items() if server is None or tag==server for p in series]
                start=max(time.time(),self._last_at or 0)-900  # последние 15 минут – от текущего времени
                return copy.deepcopy(sorted((p for p in rows if p['at']>=start),key=lambda p:p['at']))
            if not self._conn:return []
            try:
                end=int((self._last_at or time.time())//60)
                if server is None:
                    where,args='',()
                elif server:  # ряд сервера: метка в конце идентификатора ряда – фильтр до предела строк
                    where,args=' AND substr(epoch,-length(?))=?',('|'+server,'|'+server)
                else:
                    where,args=" AND instr(epoch,'|')=0",()
                rows=self._conn.execute('SELECT minute,epoch,data_json FROM resource_samples WHERE minute>=?'+where+' ORDER BY minute DESC LIMIT 1440',(end-1440,*args)).fetchall()
                return [{'at':m*60,'source_epoch':epoch,**{k:(round(s[k]['sum']/s[k]['count'],2) if k in s else None) for k in ('gpu','vram','ram','cpu')}} for m,epoch,raw in reversed(rows) for s in [json.loads(raw)]]
            except sqlite3.Error:return []

    def close(self):
        self._stop.set()
        if self._thread:self._thread.join(5)
        with self._lock:
            if self._conn:
                try:self._conn.commit()
                except sqlite3.Error:pass
                finally:self._conn.close();self._conn=None
