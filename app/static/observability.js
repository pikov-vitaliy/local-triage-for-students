(function () {
  'use strict';
  var runNode = document.getElementById('run');
  var runId = runNode ? runNode.dataset.events.split('/')[2] : null;
  var current = null, arrived = null, lastRun = null, dismissed = null, activeBusy = false, historyBusy = false;
  var bar = document.getElementById('active-run-bar');
  function set(id, value) { var e=document.getElementById(id); if(e) e.textContent=value; }
  function age(stamp) { if(!stamp) return null; var t=typeof stamp==='number'?stamp*1000:Date.parse(stamp); return Number.isFinite(t)?Math.max(0,Math.floor((Date.now()-t)/1000)):null; }
  function ago(stamp) { var s=age(stamp); return s===null?ltT('ещё не было'):s<60?ltT('{n} с назад',{n:s}):ltT('{n} мин назад',{n:Math.floor(s/60)}); }
  function number(n) { return typeof n==='number'&&Number.isFinite(n)?n.toLocaleString(ltLocale(),{maximumFractionDigits:1}):'–'; }
  function finalState(s) { return ['done','stopped','error'].indexOf(s)>=0; }
  function get(url) { var c=new AbortController(), t=setTimeout(function(){c.abort();},5000); return fetch(url,{signal:c.signal,cache:'no-store'}).then(function(r){if(!r.ok) throw new Error('HTTP'); return r.json();}).finally(function(){clearTimeout(t);}); }
  function status(s) {
    if(!s || !s.run) return;
    current=s;arrived=performance.now();lastRun=s.run.id;
    if(bar && dismissed!==s.run.id) {
      bar.hidden=false;
      var link=document.getElementById('active-run-link');link.href='/runs/'+s.run.id;
      link.textContent=(s.project_name?s.project_name+' · ':'')+(s.run.state==='done'?(s.run.failed?ltT('Завершён с ошибками'):ltT('Разбор завершён')):(s.run.state_label||s.run.state))+' · '+s.run.done+' / '+s.run.total+' · '+ltT('открыть ход разбора')+(s.slow_model&&s.slow_model.text?' · '+s.slow_model.text:'');
    }
    if(runNode) {
      var m=s.metrics||{}, host=m.host||{}, mem=host.memory;
      set('obs-ram',mem?number(mem.used_bytes/1073741824)+' / '+number(mem.total_bytes/1073741824)+' GiB':ltT('Недоступно'));
      set('obs-ram-source',host.status==='fresh'?'Windows · '+ago(host.sampled_at):host.status==='stale'?ltT('Данные хоста устарели')+' · '+ago(host.sampled_at):host.status==='remote'?ltT('Модель на сервере в сети: память и процессор этого компьютера не показываются'):ltT('Сборщик хоста не передал измерение'));
      set('obs-cpu',host.cpu_pct!==null&&host.cpu_pct!==undefined?number(host.cpu_pct)+'%':ltT('Недоступно'));
      // сборщик метрик компьютера не работает (HOSTCOL-01): предупреждение появляется и уходит вместе с ним
      // у прогона внешним провайдером – своё предупреждение: без сборщика не уходят внешние запросы (ревью круг 18)
      var cwx=document.getElementById('collector-warning-external');
      if(cwx){var cx=s.collector||{};cwx.hidden=!(cx.state==='stale'||cx.state==='missing');}
      var cw=document.getElementById('collector-warning'), c=s.collector||{};
      if(cw) {
        cw.hidden=!((c.state==='stale'||c.state==='missing')&&host.status!=='remote');
        var cd=cw.querySelector('[data-collector-detail]'), cdw=cw.querySelector('[data-collector-detail-wrap]');
        if(cd)cd.textContent=c.detail||'';if(cdw)cdw.hidden=!c.detail;
        // внешние запросы встают только в контейнере без свежих адресов компьютера (те же условия, что у отказа)
        var ce=cw.querySelector('[data-collector-external]');
        if(ce)ce.hidden=!(cw.getAttribute('data-external-on')==='1'&&c.expected&&!c.addresses);
      }
      var devices=((m.gpu||{}).gpus||[]), details=document.getElementById('obs-gpus'), list=document.getElementById('obs-gpu-list');
      if(details && list) {
        details.hidden=devices.length<2;
        while(list.children.length>devices.length) list.lastChild.remove();
        devices.forEach(function(g,i){
          var row=list.children[i];if(!row){row=document.createElement('li');list.appendChild(row);}
          row.textContent=(g.name||ltT('Неизвестная видеокарта'))+' · '+number(g.utilization_pct)+(g.utilization_pct==null?'':'%')+' · '+number(g.memory_used_mb)+' / '+number(g.memory_total_mb)+' MiB · '+number(g.temperature_c)+' °C · '+ltT('{n} Вт',{n:number(g.power_w)});
        });
      }
      var tiles=document.querySelector('section.tiles');if(tiles) tiles.classList.toggle('measurements-stale',m.resource_status!=='fresh');
      set('obs-resource-time',ltT('Ресурсы: {state}',{state:m.pending?ltT('измерение ещё не готово'):m.resource_status==='fresh'?ltT('измерение {ago}',{ago:ago(m.observed_at)}):m.resource_status==='stale'?ltT('снимок устарел'):ltT('недоступны')})+(m.error?' · Ollama: '+m.error:'')+(m.history_error?' · '+m.history_error:''));
      health();
    }
  }
  var MODEL_SILENCE_S=180;  // тот же порог «модель молчит», что и в подсказке ниже
  function health() {
    if(!current||!runNode) return;
    var r=current.run,c=current.current||{};
    var stale=arrived===null||performance.now()-arrived>15000;
    var signal=c.last_model_event_at||c.request_started_at;
    var silent=!stale && r.state==='running' && !!signal && age(signal)>MODEL_SILENCE_S;
    var message=stale?ltT('Нет свежих данных страницы. Переподключение…'):r.state==='done'?(r.failed?ltT('Разбор завершён с ошибками: {n}',{n:r.failed}):ltT('Разбор завершён')):finalState(r.state)?(r.state_label||r.state):r.state==='paused'?ltT('Разбор на паузе'):c.last_model_event_at?ltT('Последние данные модели: {ago}',{ago:ago(c.last_model_event_at)}):ltT('Ожидаем данные модели. Это может включать загрузку модели и обработку входа.');
    if(silent) message=ltT('Долго нет новых данных модели: {ago}. Проверьте состояние запроса.',{ago:ago(signal)});
    set('obs-health',message);
    var el=document.getElementById('obs-health');if(el)el.classList.toggle('text-warn',stale||silent);
    set('obs-result-time',ltT('Последний сохранённый результат: {ago}',{ago:ago(current.last_result_at)})+' · '+(stale?ltT('связь со страницей устарела'):ltT('связь со страницей {n} с назад',{n:Math.floor((performance.now()-arrived)/1000)})));
  }
  function poll() {
    if(activeBusy||document.hidden) return;
    activeBusy=true;
    get(runId?'/runs/'+runId+'/status':'/api/runs/active').then(function(s){if(s.run)status(s);else if(lastRun&&!finalState((current||{}).run.state))return get('/runs/'+lastRun+'/status').then(status);}).catch(function(){}).finally(function(){activeBusy=false;});
  }
  function graph(id,points,key) {
    var svg=document.getElementById(id);if(!svg)return;
    while(svg.firstChild)svg.removeChild(svg.firstChild);
    var values=points.map(function(p){return p[key];}).filter(function(v){return typeof v==='number'&&Number.isFinite(v);});
    if(!values.length){var t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x','8');t.setAttribute('y','45');t.textContent=ltT('Нет измерений');svg.appendChild(t);return;}
    var max=key==='gpu'?100:Math.max.apply(null,values)*1.1||1;
    var d='',previous=null,begin=points[0].at,end=points[points.length-1].at;
    points.forEach(function(p){var v=p[key];if(typeof v!=='number'||!Number.isFinite(v)){previous=null;return;}var x=8+(p.at-begin)*304/Math.max(1,end-begin), y=77-v/max*52;var join=previous&&p.source_epoch===previous.source_epoch&&p.at-previous.at<130;d+=(join?' L':' M')+x.toFixed(1)+','+y.toFixed(1);previous=p;});
    var label=document.createElementNS('http://www.w3.org/2000/svg','text');label.setAttribute('x','8');label.setAttribute('y','15');label.textContent=ltT('Последний замер {last} · пик {peak}',{last:number(values[values.length-1]),peak:number(Math.max.apply(null,values))});svg.appendChild(label);
    var path=document.createElementNS('http://www.w3.org/2000/svg','path');path.setAttribute('d',d);path.setAttribute('fill','none');path.setAttribute('stroke','currentColor');path.setAttribute('stroke-width','2');svg.appendChild(path);
  }
  function history() {
    var choice=document.getElementById('obs-window');
    if(!runNode||!choice||historyBusy||document.hidden)return;  // у удалённого исполнителя истории ресурсов нет
    historyBusy=true;
    get('/api/metrics/history?window='+choice.value+(runId?'&run='+runId:'')).then(function(s){graph('obs-gpu-chart',s.points,'gpu');graph('obs-vram-chart',s.points,'vram');graph('obs-ram-chart',s.points,'ram');}).catch(function(){}).finally(function(){historyBusy=false;});
  }
  // Полоса «идёт получение» исследования компонентов – на любой странице, как «ход разбора» у прогона (страницу
  // хода получения долго искать). Получение закончилось – полоса говорит итог, пока её не
  // скроют; «Скрыть» – до следующего получения.
  var researchBar=document.getElementById('active-research-bar'), researchLast=null, researchDismissed=null, researchBusy=false;
  function researchText(s) {
    var r=s.run, parts=[(s.project_name?s.project_name+' · ':'')+ltT('Исследование компонентов №{id}: {state}',{id:r.id,state:r.state_label||r.state})];
    parts.push(ltT('сохранено {saved} из {total}',{saved:r.rows_saved||0,total:r.rows_total||0}));
    if(r.rows_unchanged) parts.push(ltT('без изменений {n}',{n:r.rows_unchanged}));
    if(r.rows_failed) parts.push(ltT('не получено {n}',{n:r.rows_failed}));
    if(r.rows_unknown) parts.push(ltT('результат неизвестен {n}',{n:r.rows_unknown}));
    return parts.join(' · ')+' · '+ltT('открыть ход получения');
  }
  function researchPoll() {
    if(!researchBar||researchBusy||document.hidden) return;
    researchBusy=true;
    get('/api/research/active'+(researchLast?'?last='+researchLast:'')).then(function(s){
      if(!s.run){researchBar.hidden=true;return;}
      researchLast=s.run.id;
      if(researchDismissed===s.run.id) return;
      var link=document.getElementById('active-research-link');
      link.href=s.url; link.textContent=researchText(s);
      researchBar.hidden=false;
      researchBar.classList.toggle('is-done',s.run.state!=='running');
    }).catch(function(){}).finally(function(){researchBusy=false;});
  }
  var researchClose=document.getElementById('active-research-dismiss');
  if(researchClose)researchClose.onclick=function(){researchDismissed=researchLast;researchBar.hidden=true;};
  document.addEventListener('triage:status',function(e){status(e.detail);});
  document.addEventListener('visibilitychange',function(){if(!document.hidden){poll();history();researchPoll();}});
  var close=document.getElementById('active-run-dismiss');if(close)close.onclick=function(){dismissed=lastRun;bar.hidden=true;};
  var choice=document.getElementById('obs-window');if(choice)choice.onchange=history;
  poll();history();researchPoll();setInterval(health,1000);setInterval(poll,5000);setInterval(researchPoll,5000);
  if(runNode)setInterval(history,10000);
})();
