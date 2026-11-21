'use strict';
// Кластер учебного стенда (раздел 3.4 плана): разбор состояния при каждом запуске и обновление схемы на отдельном
// экземпляре кластера – оригинал не меняется, переключение по метке pg/switch.json.
//
// Разбор идёт по тому, какие папки и метки на месте, а не по тому, на каком шаге оборвался прошлый запуск. Остановка
// процесса на любом шаге оставляет одно из состояний таблицы decide(), и из каждого запуск доводит дело без потери
// оригинала. На Windows Node не умеет fsync папок, поэтому при потере питания гарантия слабее: при неясном
// состоянии стенд не продолжает сам, а сообщает, где лежат оригинал и копия.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fsx = require('./fsx');

const { StandError } = require('./paths');
const { readJson, writeJsonAtomic } = require('./stand');
const { npmVersionOf } = require('./version');

const BOOKKEEPING = new Set(['meta', 'schema_version', 'storage_migrations']); // меняются самой миграцией

function fsyncFile(file) {
  const fd = fs.openSync(file, 'r+');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function fsyncDir(dir) {
  if (process.platform === 'win32') return; // Node на Windows папки не синхронизирует (гарантия слабее, см. выше)
  const fd = fs.openSync(dir, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function observe(pgDir) {
  const at = (name) => fs.existsSync(path.join(pgDir, name));
  const mark = readJson(path.join(pgDir, 'switch.json'));
  const nextInfo = readJson(path.join(pgDir, 'next.json'));
  return {
    data: at('data'), next: at('next'), nextTmp: at('next.tmp'), mark, nextInfo,
    markBackup: Boolean(mark && mark.backup && at(path.join('backups', mark.backup))),
    nextBackup: Boolean(nextInfo && nextInfo.backup && at(path.join('backups', nextInfo.backup))),
  };
}

/**
 * Шаги по состоянию – таблица раздела 3.4. Чистая функция:
 *   pg/next.tmp                                      → remove-next-tmp (сервер на копии не запускался)
 *   метка, pg/data и pg/next на месте                 → switch (переключение не началось)
 *   метка, pg/data нет, оригинал в backups, pg/next   → second-rename (первое переименование сделано)
 *   метка, pg/data на месте, pg/next нет              → drop-mark (переключение сделано)
 *   pg/next без метки, pg/data на месте               → remove-next (недоделанная подготовка)
 *   pg/next без метки, pg/data нет, фаза «готов»       → second-rename-unmarked (метка не дожила до носителя)
 *   pg/next без метки, pg/data нет, фаза не «готов»    → restore-original (вернуть оригинал, удалить pg/next)
 *   pg/next.json без pg/next и без метки              → drop-next-json
 *   иное с меткой или pg/next                         → unclear (стенд не продолжает сам)
 */
function decide(s) {
  const steps = s.nextTmp ? ['remove-next-tmp'] : [];
  if (s.mark) {
    if (s.data && s.next) steps.push('switch');
    else if (!s.data && s.markBackup && s.next) steps.push('second-rename');
    else if (s.data && !s.next) steps.push('drop-mark');
    else steps.push('unclear');
  } else if (s.next) {
    if (s.data) steps.push('remove-next');
    else if (s.nextInfo && s.nextInfo.phase === 'ready' && s.nextBackup) steps.push('second-rename-unmarked');
    else if (s.nextBackup) steps.push('restore-original');
    else steps.push('unclear');
  } else if (s.nextInfo) {
    steps.push('drop-next-json');
  }
  return steps;
}

function unclear(pgDir, s) {
  const where = [];
  if (s.data) where.push(`рабочий каталог: ${path.join(pgDir, 'data')}`);
  if (s.next) where.push(`копия после обновления: ${path.join(pgDir, 'next')}`);
  const name = (s.mark && s.mark.backup) || (s.nextInfo && s.nextInfo.backup);
  if (name) where.push(`оригинал до обновления: ${path.join(pgDir, 'backups', name)}`);
  return new StandError('Обновление схемы базы прервано в состоянии, из которого стенд не продолжает сам. Ничего не удалено. ' +
    `${where.join('; ')}. Порядок возврата базы до обновления – в README пакета, раздел «Вернуть базу до обновления».`);
}

/**
 * Доводит прерванное обновление. ops.ensureStopped(dir, port) – сервер на каталоге точно не работает (остановлен с
 * подтверждением каталога или не запущен); false – не установить, каталог не трогается.
 */
async function recover(pgDir, ops, say = () => {}) {
  const s = observe(pgDir);
  const p = (name) => path.join(pgDir, name);
  const steps = decide(s);
  // мажорная версия каждого каталога, который шаги тронут, – до первого переноса или удаления (ревью круга 5)
  if (ops.verify) {
    const named = (s.mark && s.mark.backup) || (s.nextInfo && s.nextInfo.backup);
    const original = named ? p(path.join('backups', String(named))) : '';
    const becomesData = new Set(); // каталог, который шаги поставят на место pg/data: целый кластер своей версии
    for (const step of steps) {
      if (step === 'switch' || step === 'second-rename' || step === 'second-rename-unmarked') becomesData.add(p('next'));
      if (step === 'restore-original' && original) becomesData.add(original);
      if (step === 'drop-mark') becomesData.add(p('data')); // метка снимается только над пригодным рабочим каталогом
    }
    if (steps.some((step) => step !== 'drop-next-json')) {
      for (const dir of [p('data'), p('next'), p('next.tmp'), original]) {
        if (dir && fs.existsSync(dir)) ops.verify(dir, becomesData.has(dir));
      }
    }
  }
  for (const step of steps) {
    if (step === 'remove-next-tmp') {
      fsx.rmSync(p('next.tmp'), { recursive: true, force: true });
    } else if (step === 'switch') {
      say('Довожу переключение базы после обновления схемы…');
      switchOver(pgDir, s.mark.backup);
    } else if (step === 'second-rename' || step === 'second-rename-unmarked') {
      say('Довожу второй шаг переключения базы…');
      fsx.renameSync(p('next'), p('data'));
      fsyncDir(pgDir);
      if (fs.existsSync(p('backups'))) fsyncDir(p('backups'));
      finishSwitch(pgDir);
    } else if (step === 'drop-mark') {
      finishSwitch(pgDir);
    } else if (step === 'remove-next' || step === 'restore-original') {
      const port = s.nextInfo && s.nextInfo.port;
      if (!(await ops.ensureStopped(p('next'), port))) {
        throw new StandError(`Не удалось установить, остановлен ли сервер на ${p('next')}: каталог не тронут. Закройте ` +
          'процессы postgres этого стенда и запустите стенд снова.');
      }
      if (step === 'restore-original') {
        say('Обновление схемы не завершилось: возвращаю прежнюю базу на место…');
        fsx.renameSync(p(path.join('backups', s.nextInfo.backup)), p('data'));
        fsyncDir(pgDir);
        fsyncDir(p('backups'));
      }
      fsx.rmSync(p('next'), { recursive: true, force: true });
      fsx.rmSync(p('next.json'), { force: true });
    } else if (step === 'drop-next-json') {
      fsx.rmSync(p('next.json'), { force: true });
    } else {
      throw unclear(pgDir, s);
    }
  }
}

function switchOver(pgDir, backup) {
  const backups = path.join(pgDir, 'backups');
  fs.mkdirSync(backups, { recursive: true });
  fsx.renameSync(path.join(pgDir, 'data'), path.join(backups, backup));
  fsyncDir(pgDir);
  fsyncDir(backups);
  fsx.renameSync(path.join(pgDir, 'next'), path.join(pgDir, 'data'));
  fsyncDir(pgDir);
  finishSwitch(pgDir);
}

function finishSwitch(pgDir) {
  // перенос в backups – на диске до снятия меток в любой ветке завершения (ревью круга 4, Д2)
  if (fs.existsSync(path.join(pgDir, 'backups'))) fsyncDir(path.join(pgDir, 'backups'));
  fsx.rmSync(path.join(pgDir, 'switch.json'), { force: true });
  fsx.rmSync(path.join(pgDir, 'next.json'), { force: true });
  fsyncDir(pgDir);
}

// ---------------------------------------------------------------- копия кластера

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

/** Копия остановленного кластера с проверкой SHA-256 каждого файла; ответ – перечень {путь: sha256 оригинала}. */
function copyVerified(source, target) {
  if (fs.existsSync(path.join(source, 'postmaster.pid'))) {
    throw new StandError(`Сервер на ${source} не остановлен (есть postmaster.pid): копия не снимается.`);
  }
  const files = {};
  const walk = (rel) => {
    const from = path.join(source, rel);
    const to = path.join(target, rel);
    fs.mkdirSync(to, { recursive: true });
    // права папки – как у оригинала: PostgreSQL на Linux и macOS принимает каталог данных только 0700 или 0750
    if (process.platform !== 'win32') fs.chmodSync(to, fs.statSync(from).mode & 0o777);
    for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
      const name = path.join(rel, entry.name);
      if (entry.isDirectory()) walk(name);
      else if (entry.isFile()) {
        fs.copyFileSync(path.join(source, name), path.join(target, name));
        const original = sha256(path.join(source, name));
        if (sha256(path.join(target, name)) !== original) throw new StandError(`Копия файла базы ${name} не совпала с оригиналом.`);
        files[name.split(path.sep).join('/')] = original;
      } else {
        throw new StandError(`В каталоге базы есть ссылка или особый файл ${name}: копия не снимается.`);
      }
    }
  };
  walk('');
  return files;
}

function writeExclusive(file, text) {
  const fd = fs.openSync(file, 'wx');
  try {
    fsx.writeAll(fd, text);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Метаданные копии рядом с ней: <имя>.json – вид, версия приложения и пакета npm (для npx local-triage@<версия>),
 * схема; <имя>.pg.pw – копия пароля кластера на момент копии, только для пользователя. Возврат по README берёт версию и
 * пароль отсюда, а не из имени (ревью сборки А, круг 3).
 */
function writeBackupMeta(pgDir, backup, meta, passwordFile, restrict = () => {}) {
  const dir = path.join(pgDir, 'backups');
  let password = '';
  if (passwordFile && fs.existsSync(passwordFile)) {
    // права – до записи пароля, копия появляется под своим именем только целой (ревью круга 5)
    fsx.writeSecret(path.join(dir, `${backup}.pg.pw`), fs.readFileSync(passwordFile), restrict, { exclusive: true });
    password = `${backup}.pg.pw`;
  }
  writeExclusive(path.join(dir, `${backup}.json`), `${JSON.stringify({ ...meta, password_file: password,
    created: new Date().toISOString() }, null, 1)}\n`);
}

/**
 * Свободное имя копии в pg/backups: ни папки, ни перечня с таким именем нет (ревью сборки А, круг 2) – совпадение до
 * минуты не перезаписывает прежнюю копию и не застревает на переключении.
 */
function uniqueBackupName(pgDir, base) {
  const taken = (name) => ['', '.files.json', '.json', '.pg.pw'].some((ext) => fs.existsSync(path.join(pgDir, 'backups', `${name}${ext}`)));
  if (!taken(base)) return base;
  for (let n = 2; n < 1000; n += 1) if (!taken(`${base}-${n}`)) return `${base}-${n}`;
  throw new StandError(`В ${path.join(pgDir, 'backups')} нет свободного имени для копии ${base}.`);
}

function comparable(summary) {
  const out = {};
  for (const [table, count] of Object.entries((summary && summary.tables) || {})) {
    if (!BOOKKEEPING.has(table)) out[table] = count;
  }
  return out;
}

function flat(summary) {
  const out = comparable(summary);
  for (const [state, count] of Object.entries((summary && summary.hub_ops) || {})) out[`hub_ops:${state}`] = count;
  for (const [group, values] of Object.entries((summary && summary.groups) || {})) {
    for (const [value, count] of Object.entries(values || {})) out[`${group}:${value}`] = count;
  }
  return out;
}

/** Копия совпала с оригиналом: строки таблиц (кроме служебных миграции), операции Hub по состояниям, группировки. */
function sameCounts(before, after) {
  const a = flat(before);
  const b = flat(after);
  const differ = Object.keys(a).filter((key) => key in b && a[key] !== b[key]);
  const lost = Object.keys(a).filter((key) => !(key in b) && a[key] !== 0);
  const extra = Object.keys(b).filter((key) => !(key in a) && key.includes(':') && b[key] !== 0);
  return { ok: !differ.length && !lost.length && !extra.length, differ: differ.concat(extra), lost };
}

/**
 * Обновление схемы (раздел 3.4, шаги 1–7). ops: summary(port), stop(dir, port) – остановка с подтверждением
 * каталога, start(dir, port), status(port) – ответ tools status, migrate(port), syncOnly(dir), freePort().
 * Рабочий сервер к началу запущен на ctx.port; к концу – запущен на новом pg/data.
 */
async function updateSchema(pgDir, ctx, ops, say = () => {}) {
  const p = (name) => path.join(pgDir, name);
  const before = await ops.summary(ctx.port);
  if ((before.hub_ops || {}).taken) {
    throw new StandError(`Обновление схемы отложено: операций Hub в состоянии «выдана» – ${before.hub_ops.taken}. В стенде ` +
      'Hub выключен, выдавать их некому; обратитесь к преподавателю.');
  }
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 13);
  // в имени – версия пакета npm: её подставляют в npx local-triage@<версия> при ручном возврате (README пакета)
  let shown = ctx.fromVersion;
  try { shown = npmVersionOf(ctx.fromVersion); } catch { /* версия неизвестна – как есть */ }
  const backup = uniqueBackupName(pgDir, `${stamp}-schema${ctx.schema}-v${shown}`);
  say(`Обновляю схему базы ${ctx.schema} → ${ctx.expected}: сначала копия, оригинал не меняется…`);
  await ops.stop(p('data'), ctx.port);
  fsx.rmSync(p('next.tmp'), { recursive: true, force: true });
  const files = copyVerified(p('data'), p('next.tmp'));
  fsx.renameSync(p('next.tmp'), p('next'));
  fsyncDir(pgDir);
  await ops.syncOnly(p('next'));
  const port = await ops.freePort();
  writeJsonAtomic(p('next.json'), { port, phase: 'preparing', backup, from_version: ctx.fromVersion, to_version: ctx.toVersion });
  fsyncDir(pgDir);
  await ops.start(p('next'), port);
  try {
    await migrateCopy(ops, port, before);
  } catch (error) {
    // временный сервер не переживает отказ: остановка с подтверждением каталога, копия остаётся для разбора при
    // следующем запуске (строка «pg/next без метки, pg/data на месте» – удаление)
    try { await ops.stop(p('next'), port); } catch { /* разберёт следующий запуск */ }
    throw error;
  }
  await ops.stop(p('next'), port);
  fs.writeFileSync(path.join(p('next'), 'local-triage.version'), `${ctx.toVersion}\n`); // схема уже новая (ревью круга 6)
  await ops.syncOnly(p('next'));
  writeJsonAtomic(p('next.json'), { port, phase: 'ready', backup, from_version: ctx.fromVersion, to_version: ctx.toVersion });
  fsyncDir(pgDir);
  fs.mkdirSync(path.join(pgDir, 'backups'), { recursive: true });
  // перечень, метаданные и пароль копии – на месте до переключения, без замены чужого (имя выбрано свободным)
  writeExclusive(path.join(pgDir, 'backups', `${backup}.files.json`), `${JSON.stringify(files, null, 1)}\n`);
  writeBackupMeta(pgDir, backup, { kind: 'schema-update', app_version: ctx.fromVersion, npm_version: shown, schema: ctx.schema },
    ctx.passwordFile, ops.restrict);
  fsyncDir(path.join(pgDir, 'backups'));
  writeJsonAtomic(p('switch.json'), { kind: 'schema-update', backup, from_version: ctx.fromVersion, to_version: ctx.toVersion,
    schema_from: ctx.schema, schema_to: ctx.expected });
  fsyncDir(pgDir);
  switchOver(pgDir, backup);
  await ops.start(p('data'), ctx.port);
  return backup;
}

async function migrateCopy(ops, port, before) {
  const copied = await ops.summary(port);
  const same = sameCounts(before, copied);
  if (!same.ok) throw new StandError(`Копия базы не совпала с оригиналом по числу строк (${same.differ.concat(same.lost).join(', ')}).`);
  await ops.migrate(port);
  const status = await ops.status(port);
  if (status.state !== 'ok') throw new StandError(`После обновления схемы база в состоянии «${status.state}».`);
  const after = await ops.summary(port);
  const kept = sameCounts(before, after);
  if (!kept.ok) throw new StandError(`После обновления схемы изменилось число строк (${kept.differ.concat(kept.lost).join(', ')}).`);
}

module.exports = { fsyncFile, fsyncDir, observe, decide, recover, updateSchema, copyVerified, sameCounts, switchOver, uniqueBackupName, writeBackupMeta,
  BOOKKEEPING };
