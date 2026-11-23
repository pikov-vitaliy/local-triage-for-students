'use strict';
// Держатель учебного стенда (ADR-0155). Окно npx (npm/cli.js) – только интерфейс:
// оно запускает этот процесс без консоли и печатает его ход. Держатель занимает служебный порт (замок стенда держит
// ОС), ставит Python, ведёт PostgreSQL, запускает приложение, пишет сведения о компьютере и останавливает всё сам,
// когда закрывается его stdin: Ctrl+C, закрытие окна или гибель окна.
//
// Строки для окна: обычный текст – печатается как есть; «@@ready <адрес>» – стенд готов, «@@phase <фаза>» – смена фазы.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const binding = require('./binding');
const cluster = require('./cluster');
const fsx = require('./fsx');
const { getJson } = require('./http');
const envs = require('./env');
const metrics = require('./metrics');
const pg = require('./pg');
const python = require('./python');
const stand = require('./stand');
const { StandError, canonical, pathMargin } = require('./paths');
const { npmVersionOf } = require('./version');
const { run, tail, settle } = require('./proc');
const { t, setLang } = require('./lang');

const APP_STOP_MS = 25000; // сколько ждать штатной остановки приложения после закрытия его stdin
const READY_MS = 60000; // ожидание готовности /healthz
const LOCK_STALE_MS = 20000; // STALE_S замка папки данных (app/lockfile.py)
const RESTARTS = 3; // перезапусков приложения после готовности за RESTART_WINDOW_MS (Д15)
const RESTART_WINDOW_MS = 600000;
const APP_PORT_FIRST = 8765;
const APP_PORT_TRIES = 30;

const opts = JSON.parse(process.argv[2] || '{}');
setLang(opts.lang); // язык окна стенда (--lang или TRIAGE_LANG), ADR-0158
const home = opts.home;
const codeDir = opts.codeDir;
const packageDir = opts.packageDir;
const version = opts.appVersion;
const dirs = {
  base: path.join(home, version), logs: path.join(home, 'logs'), tmp: path.join(home, 'tmp'), data: path.join(home, 'data'),
  secrets: path.join(home, 'secrets'), pg: path.join(home, 'pg'),
};
const dataDir = path.join(dirs.pg, 'data');
const binDir = path.join(dirs.pg, `bin-${pg.PG_RELEASE}`);

let phase = 'installing';
let message = '';
let appPort = 0;
let appUrl = '';
let pgPort = 0;
let password = '';
let py = '';
let appRoot = '';
let child = null;
let stopping = false;
let stopCollector = () => {};
let lockServer = null;
let state = null;
let logFile = null;
const apps = new Set(); // запущенные процессы приложения, пока не завершились
let tempServer = null; // временный сервер на pg/next во время обновления схемы
let pgStarted = false; // рабочий PostgreSQL запущен или найден этим держателем

class Cancelled extends Error {}

/** Остановка началась: дальнейшие шаги запуска не выполняются. */
function checkStop() {
  if (stopping) throw new Cancelled('остановка');
}
const token = crypto.randomBytes(16).toString('hex');
const restarts = [];

process.stdout.on('error', () => {});
process.stderr.on('error', () => {});

function stamp() {
  return new Date().toISOString();
}

function log(line) {
  if (!logFile) return;
  try { fs.appendFileSync(logFile, `${stamp()} ${line}\n`); } catch { /* журнал недоступен – ход всё равно виден в окне */ }
}

function say(text) {
  for (const line of String(text).split(/\r?\n/)) {
    try { process.stdout.write(`${line}\n`); } catch { /* окно закрыто */ }
    log(line);
  }
}

function setPhase(next, text = '') {
  phase = next;
  message = text;
  try { process.stdout.write(`@@phase ${next}\n`); } catch { /* окно закрыто */ }
  log(`фаза: ${next}${text ? ` – ${text}` : ''}`);
}

// ---------------------------------------------------------------- замок стенда: служебный порт

function status() {
  return { stand: 'local-triage', id: state ? state.data.id : '', version, mode: opts.local ? 'local-only' : 'external',
    code_dir: codeDir, code_dir_real: codeReal ? canonical(codeReal) : '', home, phase, message, stopping, app_port: appPort,
    url: appUrl, app_token: token, pid: process.pid };
}

function holdLock(port) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.headers.host !== `127.0.0.1:${port}` || req.url !== '/status' || req.method !== 'GET') {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(status()));
    });
    server.once('error', reject);
    server.listen({ port, host: '127.0.0.1', exclusive: true }, () => resolve(server));
  });
}

// ---------------------------------------------------------------- служебные команды приложения

function toolEnv(port) {
  return envs.appEnv({ dataDir: dirs.data, tmpDir: dirs.tmp, codeDir, codeReal, libpq: envs.libpqEnv(port, password), external: false,
    build: opts.build || {}, token });
}

async function tools(args, port, timeoutMs = 300000) {
  const result = await run(py, ['-E', '-s', '-X', 'utf8', '-m', 'app.storage.tools', ...args],
    { cwd: appRoot, env: toolEnv(port), timeoutMs });
  let answer = null;
  try { answer = JSON.parse(result.stdout); } catch { answer = null; }
  return { code: result.code, answer, result };
}

async function toolOk(args, port, what) {
  const { code, answer, result } = await tools(args, port);
  if (code !== 0 || !answer) {
    throw new StandError(`${what}: ${answer && answer.error ? answer.error : tail(result.stderr || result.stdout, 10)}`);
  }
  return answer;
}

// ---------------------------------------------------------------- PostgreSQL

function pgEnv() {
  return envs.pgToolEnv(dirs.tmp);
}

/** Порт можно занять: пробная привязка (порт мог зарезервировать Windows, отвечать при этом некому). */
function canBind(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.listen({ port, host, exclusive: true }, () => server.close(() => resolve(true)));
  });
}

function freePort(host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen({ port: 0, host, exclusive: true }, () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function portAnswers(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1' });
    const done = (value) => { socket.destroy(); resolve(value); };
    socket.setTimeout(800, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

function pgStatus(dir) {
  return run(pg.exe(binDir, 'pg_ctl'), pg.statusArgs(dir), { env: pgEnv(), cwd: home, timeoutMs: 60000 });
}

/** postmaster.pid каталога: первая строка – номер процесса, четвёртая – порт. Нет файла – null. */
function pidFile(dir) {
  try {
    const lines = fs.readFileSync(path.join(dir, 'postmaster.pid'), 'utf8').split(/\r?\n/);
    return { pid: Number(lines[0]) || 0, port: Number(lines[3]) || 0 };
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    return { pid: 0, port: 0, unreadable: true }; // файл есть, но не прочитан: остановку он не доказывает
  }
}

const STARTING = /starting up|not yet accepting connections|in recovery mode/i;
let whoamiError = '';

/**
 * Сервер на каталоге (ревью сборки А, круг 3 и проверка агентами):
 * running – отвечает, и это он; foreign – на порту другой каталог; starting – процесс жив и ещё восстанавливается;
 * unconfirmed – отвечает, но каталог не подтвердить (чаще всего не подходит пароль); elsewhere – сохранённый порт молчит,
 * а сервер отвечает на порту из postmaster.pid; stale – pg_ctl status видит живой процесс из postmaster.pid, но
 * PostgreSQL нигде не отвечает (номер процесса после сбоя достался другой программе); down – не работает.
 * Порт неизвестен (stand.json утрачен) – всё равно pg_ctl status: работающий сервер не принимается за остановленный.
 */
let codeReal = ''; // физический путь папки кода, проверенный при запуске (Д10)
let dataState = ''; // последний результат serverOn для pg/data: итог остановки берётся отсюда, а не из голого pg_ctl status

async function serverOn(dir, port) {
  try {
    const who = await classify(dir, port);
    if (dir === dataDir) dataState = who;
    return who;
  } catch (error) {
    if (dir === dataDir) dataState = 'error';
    throw error;
  }
}

async function classify(dir, port) {
  whoamiError = '';
  if (port) {
    const { code, answer } = await tools(['whoami', '--expect-data-dir', dir], port, 60000);
    if (code === 0) return 'running';
    if (code === 1) return 'foreign';
    whoamiError = answer && answer.error ? String(answer.error) : '';
  }
  const st = await pgStatus(dir);
  if (st.code === 3) return 'down';
  // 4 – каталог не признан кластером: pg_ctl ничего не проверял; ни «остановлен», ни «работает» (ревью круга 6)
  if (st.code === 4) return 'notcluster';
  if (st.code !== 0) {
    throw new StandError(t(`pg_ctl status для ${dir} не ответил штатно (код ${st.code}): состояние сервера неизвестно, ничего ` +
      'не изменено. Запустите стенд снова; если повторится – переустановите: npx local-triage --reinstall.', `pg_ctl status for ${dir} did not answer normally (code ${st.code}): the server state is unknown, nothing ` +
      'was changed. Start the stand again; if it happens again, reinstall: npx local-triage --reinstall.'));
  }
  if (STARTING.test(whoamiError)) return 'starting';
  const pf = pidFile(dir);
  if (port && (await portAnswers(port))) {
    if (pf && pf.port && pf.port !== port) {
      const there = await tools(['whoami', '--expect-data-dir', dir], pf.port, 60000);
      if (there.code === 0) return 'elsewhere';
    }
    return 'unconfirmed';
  }
  if (pf && pf.port && pf.port !== port && (await portAnswers(pf.port))) return 'elsewhere';
  return 'stale';
}

/** Ожидание конца восстановления после сбоя: pg_ctl start -w мог выйти по сроку, а сервер ещё поднимается. */
async function awaitStartup(dir, port, ms = 300000) {
  const deadline = Date.now() + ms;
  let who = 'starting';
  let told = false;
  while (who === 'starting' && Date.now() < deadline && !stopping) {
    if (!told) {
      say(t('PostgreSQL восстанавливается после прерванной работы – жду…', 'PostgreSQL is recovering after an interrupted session – waiting…'));
      told = true;
    }
    await new Promise((r) => setTimeout(r, 2000));
    who = await serverOn(dir, port);
  }
  return who;
}

function unconfirmedError(dir, port) {
  const auth = /password authentication failed/i.test(whoamiError);
  return new StandError(t(`На порту ${port} отвечает PostgreSQL, но подтвердить, что это сервер стенда с каталогом ${dir}, не удалось – ` +
    `${auth ? 'не подходит пароль в secrets/pg.pw' : `ответ: ${whoamiError || 'нет ответа'}`}. Ничего не изменено: порт, ` +
    `журнал и сервер оставлены как были. ${auth ? 'Верните прежний файл пароля или остановите' : 'Остановите'} сервер ` +
    `вручную: "${pg.exe(binDir, 'pg_ctl')}" stop -D "${dir}" -m fast`, `PostgreSQL answers on port ${port}, but it could not be confirmed as the stand server with directory ${dir} – ` +
    `${auth ? 'the password in secrets/pg.pw does not match' : `answer: ${whoamiError || 'no answer'}`}. Nothing was changed: the port, ` +
    `log and server are left as they were. ${auth ? 'Restore the previous password file or stop' : 'Stop'} the server ` +
    `manually: "${pg.exe(binDir, 'pg_ctl')}" stop -D "${dir}" -m fast`));
}

function staleError(dir) {
  const pf = pidFile(dir) || { pid: 0 };
  return new StandError(t(`В ${dir} лежит postmaster.pid процесса ${pf.pid}: процесс работает, но PostgreSQL ни на каком ` +
    'порту не отвечает. Вероятно, файл остался после сбоя, а номер процесса достался другой программе. Проверьте, что ' +
    `процесс ${pf.pid} – не postgres (Диспетчер задач или ps), удалите файл postmaster.pid и запустите стенд снова.`, `${dir} contains postmaster.pid of process ${pf.pid}: the process is running, but PostgreSQL does not answer on any ` +
    'port. The file probably remained after a crash and the process number went to another program. Check that ' +
    `process ${pf.pid} is not postgres (Task Manager or ps), delete postmaster.pid and start the stand again.`));
}

function stateError(who, dir, port) {
  if (who === 'unconfirmed') return unconfirmedError(dir, port);
  if (who === 'starting') {
    return new StandError(t(`PostgreSQL на ${dir} восстанавливается дольше 5 минут. Подождите и запустите стенд снова; журнал – ` +
      `${path.join(dirs.logs, 'postgres.log')}.`, `PostgreSQL on ${dir} has been recovering for more than 5 minutes. Wait and start the stand again; log: ` +
      `${path.join(dirs.logs, 'postgres.log')}.`));
  }
  return staleError(dir);
}

/**
 * Точно ли сервер на каталоге не работает (раздел 3.4): pg_ctl status «не запущен» и postmaster.pid нет – или он остался
 * после сбоя: процесса из него нет (pg_ctl status проверяет это сам) и на его порту никто не отвечает. Сам файл обёртка
 * не трогает: устаревший снимает PostgreSQL при запуске, а копия pg/next удаляется целиком.
 */
async function surelyDown(dir) {
  const st = await pgStatus(dir);
  // только штатное «не запущен» (3); код 4 – каталог не признан кластером, pg_ctl ничего не проверял: неопределённо,
  // каталог не удаляется и не переносится (Д3, ревью кругов 4–5)
  if (st.code !== 3) return false;
  const pf = pidFile(dir);
  if (!pf) return true;
  if (pf.unreadable) return false;
  return !(pf.port && (await portAnswers(pf.port)));
}

/** «Точно остановлен» с записью итога для основного каталога: shutdown не скажет «оставлен работать» про остановленный. */
async function confirmDown(dir) {
  const down = await surelyDown(dir);
  if (down && dir === dataDir) dataState = 'down';
  return down;
}

/** Остановка только подтверждённого сервера: каталог сверяется по порту до сигнала. */
async function stopServer(dir, port) {
  let who = await serverOn(dir, port);
  if (who === 'starting') who = await awaitStartup(dir, port, 120000);
  if (who === 'notcluster') return confirmDown(dir); // только «точно остановлен», иначе каталог не трогается
  if (who === 'elsewhere') return stopServer(dir, pidFile(dir).port);
  if (who === 'stale' || who === 'starting') {
    say(stateError(who, dir, port).message);
    return false;
  }
  if (who === 'foreign') {
    say(t(`На порту ${port} отвечает сервер с другим каталогом данных: сигнал остановки не посылается.`, `A server with a different data directory answers on port ${port}: no stop signal is sent.`));
    return false;
  }
  if (who === 'unconfirmed') {
    say(t(`Сервер на ${dir} работает, но его каталог не подтверждён: сигнал остановки не посылается.`, `The server on ${dir} is running, but its directory is not confirmed: no stop signal is sent.`));
    return false;
  }
  if (who === 'down') return confirmDown(dir);
  const binary = pg.exe(binDir, 'pg_ctl');
  const fast = await run(binary, pg.stopArgs(dir, 'fast'), { env: pgEnv(), cwd: home, timeoutMs: 60000 });
  if (fast.code !== 0) {
    // за 30 с сервер на каталоге мог смениться: сигнал – только снова подтверждённому
    const again = await serverOn(dir, port);
    if (again === 'running') {
      say(t('PostgreSQL не остановился штатно за 30 с – останавливаю немедленно.', 'PostgreSQL did not stop normally within 30 s – stopping it immediately.'));
      await run(binary, pg.stopArgs(dir, 'immediate'), { env: pgEnv(), cwd: home, timeoutMs: 60000 });
    } else if (again !== 'down') {
      say(t(`Сервер на ${dir} после штатной остановки не подтверждён: немедленная остановка не посылается.`, `The server on ${dir} is not confirmed after the normal stop: no immediate stop is sent.`));
      return false;
    }
  }
  return confirmDown(dir);
}

async function ensureStopped(dir, port) {
  const known = port || (pidFile(dir) || {}).port || 0; // порт утрачен вместе со stand.json – он есть в postmaster.pid
  if (known) return stopServer(dir, known);
  return surelyDown(dir);
}

async function startServer(dir, port, logName = 'postgres.log') {
  // до записи журнала и настроек – только штатное «не запущен» (3): работающий сервер или каталог, который pg_ctl не
  // признаёт кластером (4), не трогаются (ревью круга 7)
  const pre = await pgStatus(dir);
  if (pre.code === 4) {
    throw new StandError(t(`pg_ctl не признаёт каталог ${dir} кластером: запуск остановлен, журнал и настройки не тронуты.`, `pg_ctl does not recognise directory ${dir} as a cluster: start aborted, the log and settings were not touched.`));
  }
  if (pre.code !== 3) {
    throw new StandError(t(`PostgreSQL на ${dir} уже работает, хотя по порту ${port} его не видно: журнал и настройки сервера ` +
      'не тронуты. Закройте прежние процессы postgres этого стенда или перезагрузите компьютер и запустите стенд снова.', `PostgreSQL on ${dir} is already running, although it is not visible on port ${port}: the server log and settings ` +
      'were not touched. Close the previous postgres processes of this stand or restart the computer and start the stand again.'));
  }
  const logPath = logName === 'postgres.log' ? pg.rotateLog(dirs.logs) : path.join(dirs.logs, logName);
  pg.writeConf(dir, port);
  const result = await run(pg.exe(binDir, 'pg_ctl'), pg.startArgs(dir, logPath),
    { env: pgEnv(), cwd: home, stdio: 'ignore', timeoutMs: 120000 });
  let who = await serverOn(dir, port);
  if (who === 'starting') who = await awaitStartup(dir, port);
  if (who === 'running') {
    if (result.code !== 0) {
      const late = await pgStatus(dir);
      log(`pg_ctl start вышел с кодом ${result.code}, сервер подтверждён по порту, pg_ctl status – ${late.code}`);
    }
    return;
  }
  if (who === 'notcluster') {
    throw new StandError(t(`pg_ctl не признаёт каталог ${dir} кластером: запуск остановлен, каталог не изменён.`, `pg_ctl does not recognise directory ${dir} as a cluster: start aborted, the directory was not changed.`));
  }
  if (who === 'unconfirmed' || who === 'starting' || who === 'stale' || who === 'elsewhere') {
    // процесс работает, а каталог не подтверждён: сигнал остановки ему не посылается, и об этом сказано прямо
    if (dir === dataDir) pgStarted = false;
    throw stateError(who, dir, port);
  }
  const st = await pgStatus(dir);
  let journal = '';
  try { journal = tail(fs.readFileSync(logPath, 'utf8'), 15); } catch { journal = ''; }
  const hint = /lock file .* already exists|shared memory block .* still in use/i.test(journal)
    ? t('\nПрежний процесс postgres этого стенда ещё работает: закройте его или перезагрузите компьютер.', '\nA previous postgres process of this stand is still running: close it or restart the computer.') : '';
  throw new StandError(t(`PostgreSQL не запустился (pg_ctl start – код ${result.code}, pg_ctl status – ${st.code}).\n${journal}${hint}`, `PostgreSQL did not start (pg_ctl start – code ${result.code}, pg_ctl status – ${st.code}).\n${journal}${hint}`));
}

async function initCluster() {
  for (const name of fs.readdirSync(dirs.pg)) {
    // дерево initdb на Windows живёт дольше родителя: удаление с повтором до 30 с
    if (name.startsWith('data.init-')) fsx.rmSync(path.join(dirs.pg, name), { recursive: true, force: true });
  }
  const target = path.join(dirs.pg, `data.init-${process.pid}`);
  const pw = pg.ensurePassword(dirs.secrets, false);
  password = pw.password;
  const logPath = path.join(dirs.logs, `initdb-${stamp().replace(/[:.]/g, '-')}.log`);
  const fd = fs.openSync(logPath, 'w');
  say(t('Создаю базу PostgreSQL…', 'Creating the PostgreSQL database…'));
  let result;
  try {
    result = await run(pg.exe(binDir, 'initdb'), pg.initdbArgs(target, pw.file), { env: pgEnv(), cwd: home, fd, timeoutMs: 300000 });
  } finally {
    fs.closeSync(fd);
  }
  if (result.code !== 0) {
    let journal = '';
    try { journal = tail(fs.readFileSync(logPath, 'utf8'), 15); } catch { journal = ''; }
    throw new StandError(t(`initdb не создал кластер (код ${result.code}).\n${journal}`, `initdb did not create the cluster (code ${result.code}).\n${journal}`));
  }
  fsx.renameSync(target, dataDir);
}

/** --new-database: прежний кластер и его пароль уходят в pg/backups, дальше – как первая установка. */
async function setAsideCluster() {
  if (fs.existsSync(dataDir)) {
    // прежний сервер мог пережить держатель: переносится только кластер, который точно не работает
    if (pg.passwordReadable(dirs.secrets)) password = pg.ensurePassword(dirs.secrets, true).password;
    if (!(await ensureStopped(dataDir, state.data.pg_port || 0))) {
      throw new StandError(t(`Не удалось установить, что сервер на ${dataDir} остановлен: прежняя база не тронута. Закройте ` +
        'процессы postgres этого стенда и запустите стенд с --new-database снова.', `Could not confirm that the server on ${dataDir} is stopped: the previous database was not touched. Close ` +
        'the postgres processes of this stand and start the stand with --new-database again.'));
    }
  }
  const pw = path.join(dirs.secrets, 'pg.pw');
  const backups = path.join(dirs.pg, 'backups');
  // прошлый перенос прерван: остаток (база или пароль) доносится в ту же копию, новое имя не заводится
  let name = unfinishedReplaced(backups);
  if (!name && !fs.existsSync(dataDir) && !fs.existsSync(pw)) {
    // переносить нечего: первая установка – и выбранная папка кода действует уже сейчас (ревью круга 6)
    stand.save(state, { phase: 'none', pg_port: 0, code_dir: codeDir, code_dir_real: canonical(codeDir) });
    return;
  }
  let shown = clusterVersion();
  try { shown = npmVersionOf(shown); } catch { /* версия неизвестна – как есть */ }
  const meta = (extra) => ({ kind: 'replaced', app_version: clusterVersion(), npm_version: shown, ...extra });
  if (!name) {
    fs.mkdirSync(backups, { recursive: true });
    name = cluster.uniqueBackupName(dirs.pg, `${stamp().replace(/[-:]/g, '').replace('T', '-').slice(0, 13)}-replaced-v${shown}`);
    fs.mkdirSync(path.join(backups, name)); // эксклюзивно: прежняя копия с тем же именем не открывается заново
    // метаданные – до переносов: прерванный перенос находится по ним и доводится в эту же копию
    fs.writeFileSync(path.join(backups, `${name}.json`), `${JSON.stringify(meta({ state: 'moving', password_file: '',
      created: new Date().toISOString() }), null, 1)}\n`, { flag: 'wx' });
  }
  const target = path.join(backups, name);
  if (fs.existsSync(dataDir)) fsx.renameSync(dataDir, path.join(target, 'data'));
  const copy = path.join(target, 'pg.pw');
  if (fs.existsSync(pw)) {
    // пароль – копией: права до записи, на место – целым; действующий пароль кластера – этот, а несовпадающая копия
    // (след сбоя прежней версии) отодвигается, но не удаляется
    if (fs.existsSync(copy) && !fs.readFileSync(copy).equals(fs.readFileSync(pw))) {
      fsx.renameSync(copy, path.join(target, `pg.pw.prev-${stamp().replace(/[:.]/g, '-')}`));
    }
    if (!fs.existsSync(copy)) fsx.writeSecret(copy, fs.readFileSync(pw), (file) => pg.restrictToUser(file));
    cluster.fsyncDir(target);
    if (!fs.readFileSync(copy).equals(fs.readFileSync(pw))) { // единственный действующий пароль – только после сверки копии
      throw new StandError(t(`Копия пароля ${copy} не совпала с ${pw}: исходный файл оставлен. Запустите стенд с --new-database снова.`, `The password copy ${copy} does not match ${pw}: the original file was kept. Start the stand with --new-database again.`));
    }
    fsx.rmSync(pw, { force: true });
  }
  // новая привязка – до отметки «done»: прерванный после неё запуск уже не ищет незавершённый перенос (ревью круга 6)
  stand.save(state, { code_dir: codeDir, code_dir_real: canonical(codeDir) });
  const before = stand.readJson(path.join(backups, `${name}.json`)) || {};
  stand.writeJsonAtomic(path.join(backups, `${name}.json`), {
    ...meta({}), app_version: before.app_version || clusterVersion(), npm_version: before.npm_version || shown,
    state: 'done', password_file: fs.existsSync(copy) ? `${name}/pg.pw` : '', created: before.created || new Date().toISOString(),
  });
  // прежняя база ушла в копию: с этого момента действует папка кода нового запуска (ревью круга 5)
  stand.save(state, { phase: 'none', pg_port: 0, code_dir: codeDir, code_dir_real: canonical(codeDir) });
  password = '';
  say(t(`Прежняя база перенесена в ${target}; создаю новую.`, `The previous database was moved to ${target}; creating a new one.`));
}

/** Копия --new-database, перенос в которую прервался: метаданные с state «moving» и папка на месте. */
function unfinishedReplaced(backups) {
  let names = [];
  try { names = fs.readdirSync(backups); } catch { return ''; }
  for (const file of names.filter((n) => n.endsWith('.json') && !n.endsWith('.files.json')).sort()) {
    const name = file.slice(0, -'.json'.length);
    const meta = stand.readJson(path.join(backups, file)) || {};
    const dir = path.join(backups, name);
    if (meta.kind !== 'replaced' || meta.state !== 'moving' || !fs.existsSync(dir)) continue;
    // продолжать – только если перенос начался: в копии уже есть база или пароль, либо pg/data уже нет; пустая копия
    // (прервано сразу после создания) убирается, новая получит своё время и версию (проверка агентами, круг 7)
    if (fs.existsSync(path.join(dir, 'data')) || fs.existsSync(path.join(dir, 'pg.pw')) || !fs.existsSync(dataDir)) return name;
    try {
      fs.rmdirSync(dir);
      fs.rmSync(path.join(backups, file), { force: true });
    } catch { /* не пуста – оставить как есть */ }
  }
  return '';
}

/** Версия стенда, работавшего с этой базой: метка самого кластера главнее stand.json – после ручного возврата копии
 * рядом может лежать stand.json другой версии (ревью круга 5). */
function clusterVersion() {
  try {
    const own = fs.readFileSync(path.join(dataDir, 'local-triage.version'), 'utf8').trim();
    if (own) return own;
  } catch { /* метки нет */ }
  return state.data.last_good_version || 'unknown';
}

function lost(why) {
  return new StandError(t(`${why} Это прежняя установка стенда, и пустую базу вместо неё стенд сам не создаёт. Прежние базы – в ` +
    `${path.join(dirs.pg, 'backups')}. Начать с новой базы: запустите стенд с ключом --new-database.`, `${why} This is an existing stand installation, and the stand does not replace it with an empty database by itself. Previous databases are in ` +
    `${path.join(dirs.pg, 'backups')}. To start with a new database, run the stand with --new-database.`));
}

/** Прежние копии есть. Нет папки – нет копий; не прочиталась – отказ: иначе прежняя установка стала бы первой. */
function backupsPresent() {
  try {
    return fs.readdirSync(path.join(dirs.pg, 'backups')).length > 0;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw new StandError(t(`Папка прежних копий ${path.join(dirs.pg, 'backups')} не читается (${error.code}): стенд не решает, ` +
      'первая это установка или прежняя. Проверьте права на папку и запустите стенд снова.', `The previous copies folder ${path.join(dirs.pg, 'backups')} cannot be read (${error.code}): the stand cannot tell ` +
      'whether this is a first or an existing installation. Check the folder permissions and start the stand again.'));
  }
}

async function preparePostgres() {
  pg.installBinaries(pg.nativeDir(packageDir), binDir, process.platform, { force: Boolean(opts.reinstall) });
  fs.mkdirSync(dirs.pg, { recursive: true });
  // пароль прежнего кластера – до разбора состояния: подтвердить каталог временного сервера без него нельзя
  const pwFile = path.join(dirs.secrets, 'pg.pw');
  if (fs.existsSync(pwFile)) {
    if (pg.passwordReadable(dirs.secrets)) password = pg.ensurePassword(dirs.secrets, true).password;
    else if (fs.existsSync(dataDir) && !opts.newDatabase) {
      throw new StandError(t(`Файл пароля базы ${pwFile} повреждён, а кластер на месте: к базе не подключиться. Начать с новой ` +
        'базы: запустите стенд с ключом --new-database (прежняя база останется в pg/backups).', `The database password file ${pwFile} is damaged, but the cluster is in place: cannot connect to the database. To start with a new ` +
        'database, run the stand with --new-database (the previous database stays in pg/backups).'));
    }
  }
  await cluster.recover(dirs.pg, { ensureStopped, verify: (dir, required) => pg.checkMajor(dir, required) }, say);
  checkStop();
  if (opts.newDatabase) {
    if (fs.existsSync(dataDir)) pg.checkCluster(dataDir); // чужая мажорная версия – отказ до изменения папки (§3.4)
    await setAsideCluster();
  }
  if (!fs.existsSync(dataDir)) {
    // база уже создавалась (db-created) или работала (ready): пропавший каталог – утрата, а не первая установка
    if (state.data.phase === 'ready' || state.data.phase === 'db-created') throw lost(t(`Каталога базы ${dataDir} нет.`, `Database directory ${dataDir} is missing.`));
    stand.save(state, { phase: 'none' });
    await initCluster();
  }
  pg.checkCluster(dataDir);
  password = pg.ensurePassword(dirs.secrets, true).password;
  pgPort = state.data.pg_port || 0;
  let who = await serverOn(dataDir, pgPort);
  if (who === 'elsewhere') { // сохранённый порт устарел (stand.json утрачен или старый): сервер – на порту из postmaster.pid
    pgPort = pidFile(dataDir).port;
    who = await serverOn(dataDir, pgPort);
  }
  if (who === 'starting') who = await awaitStartup(dataDir, pgPort);
  if (who === 'notcluster') {
    throw new StandError(t(`pg_ctl не признаёт каталог ${dataDir} кластером: стенд его не меняет. Пришлите журнал преподавателю.`, `pg_ctl does not recognise directory ${dataDir} as a cluster: the stand does not change it. Send the log to your teacher.`));
  }
  if (who === 'starting' || who === 'stale' || who === 'elsewhere' || who === 'unconfirmed') {
    throw stateError(who, dataDir, pgPort);
  }
  if (who === 'foreign') {
    throw new StandError(t(`На порту базы ${pgPort} отвечает другой сервер PostgreSQL. Закройте его или запустите стенд с другой ` +
      'служебной папкой (--home).', `Another PostgreSQL server answers on the database port ${pgPort}. Close it or start the stand with a different ` +
      'home folder (--home).'));
  }
  if (who === 'running') {
    pgStarted = true;
    if (pgPort !== state.data.pg_port) stand.save(state, { pg_port: pgPort }); // порт из postmaster.pid – запомнить
    say(t('PostgreSQL этого стенда уже работает – подключаюсь к нему.', 'PostgreSQL of this stand is already running – connecting to it.'));
  } else {
    if (!pgPort || !(await canBind(pgPort))) pgPort = await freePort(); // занят или зарезервирован – новый (круг 7)
    stand.save(state, { pg_port: pgPort });
    checkStop();
    say(t('Запускаю PostgreSQL…', 'Starting PostgreSQL…'));
    pgStarted = true; // остановка с этого момента проверит сервер (с подтверждением каталога), даже если запуск не дошёл
    await startServer(dataDir, pgPort);
  }
  pgStarted = true;
  checkStop();
  const create = state.data.phase === 'none' || state.data.phase === 'db-creating';
  if (state.data.phase === 'none') stand.save(state, { phase: 'db-creating' });
  const { code, answer, result } = await tools(['ensure-database', '--expect-data-dir', dataDir, ...(create ? ['--create'] : [])], pgPort);
  if (code === 1 && answer && answer.match === false) {
    throw new StandError(t(`Сервер на порту ${pgPort} – не кластер этого стенда (${answer.data_directory}): записи не было.`, `The server on port ${pgPort} is not this stand's cluster (${answer.data_directory}): nothing was written.`));
  }
  if (code === 1 && answer && !answer.exists) throw lost(t('Базы triage в кластере нет.', 'The cluster has no triage database.'));
  if (code !== 0 || !answer) throw new StandError(t(`База не подготовлена: ${answer && answer.error ? answer.error : tail(result.stderr, 8)}`, `The database is not prepared: ${answer && answer.error ? answer.error : tail(result.stderr, 8)}`));
  if (create) stand.save(state, { phase: 'db-created' });
  // один ответ: 0 – готова или пуста, 1 – migrate, newer, foreign; ошибка команды – отказ сразу (§3.4, ревью круга 6)
  const first = await tools(['status'], pgPort);
  if (!first.answer || first.answer.error || (first.code !== 0 && first.code !== 1)) {
    throw new StandError(t(`Состояние схемы базы не прочитано: ${first.answer && first.answer.error ? first.answer.error
      : tail(first.result.stderr || first.result.stdout, 8)}`, `Could not read the database schema state: ${first.answer && first.answer.error ? first.answer.error
      : tail(first.result.stderr || first.result.stdout, 8)}`));
  }
  const st = first.answer;
  if (st.state === 'empty' && state.data.phase === 'ready') throw lost(t('База пуста.', 'The database is empty.'));
  if (st.state === 'newer') {
    throw new StandError(t(`Схема базы (${st.schema}) новее этой версии стенда (${st.expected}). Запустите новую версию: npx local-triage@latest.`, `The database schema (${st.schema}) is newer than this stand version (${st.expected}). Run the new version: npx local-triage@latest.`));
  }
  if (st.state === 'foreign') throw new StandError(t('В базе triage нет схемы приложения: это чужая база.', 'The triage database has no app schema: it is a foreign database.'));
  if (st.state === 'migrate') {
    const backup = await cluster.updateSchema(dirs.pg, {
      port: pgPort, schema: st.schema, expected: st.expected, fromVersion: clusterVersion(), toVersion: version,
      passwordFile: path.join(dirs.secrets, 'pg.pw'),
    }, {
      summary: (port) => toolOk(['summary'], port, t('Сводка базы не снята', 'Database summary not taken')),
      stop: async (dir, port) => {
        if (!(await stopServer(dir, port))) throw new StandError(t(`Сервер на ${dir} не остановлен.`, `The server on ${dir} is not stopped.`));
        if (tempServer && tempServer.dir === dir) tempServer = null;
      },
      start: async (dir, port) => {
        if (dir !== dataDir) tempServer = { dir, port };
        await startServer(dir, port, dir === dataDir ? 'postgres.log' : 'postgres-next.log');
      },
      status: (port) => tools(['status'], port).then((r) => r.answer || {}),
      migrate: (port) => toolOk(['migrate'], port, t('Миграция схемы не выполнена', 'Schema migration not performed')),
      syncOnly: async (dir) => {
        const r = await run(pg.exe(binDir, 'initdb'), pg.syncOnlyArgs(dir), { env: pgEnv(), cwd: home, timeoutMs: 600000 });
        if (r.code !== 0) throw new StandError(t(`initdb --sync-only: код ${r.code}`, `initdb --sync-only: code ${r.code}`));
      },
      freePort: () => freePort(),
      restrict: (file) => pg.restrictToUser(file),
    }, say);
    say(t(`Схема обновлена; база до обновления – ${path.join(dirs.pg, 'backups', backup)}.`, `Schema updated; the database from before the update is in ${path.join(dirs.pg, 'backups', backup)}.`));
    // шаг 7: рабочий сервер на новом каталоге – база на месте и схема этой сборки, только потом приложение
    const again = await tools(['ensure-database', '--expect-data-dir', dataDir], pgPort);
    if (again.code !== 0) throw new StandError(t('После обновления схемы база triage не найдена на рабочем сервере.', 'After the schema update the triage database was not found on the working server.'));
    const now = await tools(['status'], pgPort);
    if (!now.answer || now.answer.state !== 'ok') {
      throw new StandError(t(`После обновления схемы база в состоянии «${now.answer ? now.answer.state : 'неизвестно'}».`, `After the schema update the database is in the "${now.answer ? now.answer.state : 'unknown'}" state.`));
    }
  }
}

// ---------------------------------------------------------------- файлы приложения

function manifestFiles() {
  const file = path.join(packageDir, 'npm', 'files.manifest');
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  return lines.filter((l) => l.startsWith('app/') || l.startsWith('examples/'));
}

/** <версия>/app-root – копия app/ и examples/ из пакета; build.json – рядом с app/ (app/build_info.py). */
function syncAppRoot() {
  const target = path.join(dirs.base, 'app-root');
  const files = manifestFiles();
  const digest = crypto.createHash('sha256');
  const build = path.join(packageDir, 'npm', 'build.json');
  for (const name of files.concat(fs.existsSync(build) ? ['npm/build.json'] : [])) {
    digest.update(name).update('\0').update(fs.readFileSync(path.join(packageDir, name))).update('\0');
  }
  const fingerprint = digest.digest('hex');
  const marker = path.join(dirs.base, 'app-root.json');
  const intact = () => files.every((name) => {
    try { return fs.readFileSync(path.join(target, name)).equals(fs.readFileSync(path.join(packageDir, name))); } catch { return false; }
  }) && (!fs.existsSync(build) || (() => {
    try { return fs.readFileSync(path.join(target, 'build.json')).equals(fs.readFileSync(build)); } catch { return false; }
  })());
  // отпечаток – по источнику, поэтому и сама копия сверяется: пропавший или усечённый файл – пересборка (ревью круга 6)
  if (!opts.reinstall && fs.existsSync(target) && (stand.readJson(marker) || {}).sha256 === fingerprint && intact()) return target;
  fsx.removeLeftovers(path.dirname(target), path.basename(target));
  const tmp = `${target}.tmp-${process.pid}`;
  for (const name of files) {
    fs.mkdirSync(path.dirname(path.join(tmp, name)), { recursive: true });
    fs.copyFileSync(path.join(packageDir, name), path.join(tmp, name));
  }
  if (fs.existsSync(build)) fs.copyFileSync(build, path.join(tmp, 'build.json'));
  const old = `${target}.old-${process.pid}`;
  if (fs.existsSync(target)) fsx.renameSync(target, old);
  try {
    fsx.renameSync(tmp, target);
  } catch (error) {
    if (fs.existsSync(old) && !fs.existsSync(target)) fsx.renameSync(old, target); // прежняя копия – на место
    throw error;
  }
  try { fsx.rmSync(old, { recursive: true, force: true }, 5000); } catch { /* удалится при следующем запуске */ }
  stand.writeJsonAtomic(marker, { sha256: fingerprint, files: files.length });
  return target;
}

function clusterMarked() {
  return [dataDir, path.join(dirs.pg, 'next')].some((dir) => fs.existsSync(path.join(dir, 'local-triage.version')) ||
    fs.existsSync(path.join(dir, binding.FILE)));
}

function bindingError(bound) {
  const moved = canonical(bound.path) === canonical(codeDir) && bound.real && bound.real !== canonical(codeDir);
  if (moved) {
    return new StandError(t(`Папка кода ${codeDir} теперь указывает на ${canonical(codeDir)}, а база привязана к ${bound.real}. ` +
      'Верните ссылку на прежнюю папку или запустите стенд с --code-dir прежней папки.', `The code folder ${codeDir} now points to ${canonical(codeDir)}, but the database is bound to ${bound.real}. ` +
      'Point the link back to the previous folder or start the stand with --code-dir set to the previous folder.'));
  }
  return new StandError(t(`Папка кода этой базы – ${bound.path}. Сменить её нельзя: проекты стенда ссылаются на неё. Запустите ` +
    `стенд с этой папкой (npx local-triage --code-dir "${bound.path}"); другая папка кода – это другой стенд (ключ --home).`, `The code folder of this database is ${bound.path}. It cannot be changed: the stand projects refer to it. Start ` +
    `the stand with this folder (npx local-triage --code-dir "${bound.path}"); another code folder means another stand (--home).`));
}

/** Запись о начатой публикации демо – в служебной папке: только по ней стенд узнаёт свой временный каталог и свою метку. */
function demoRecordFile() {
  return path.join(home, 'demo-publish.json');
}

/**
 * Остаток прерванной публикации демо (ревью кругов 3–7): удаляется только каталог из записи этой служебной папки, если в
 * его метке тот же токен, а процесс-владелец не живёт. Чужие каталоги и файлы по имени не опознаются и не трогаются.
 */
function demoLeftovers() {
  const record = stand.readJson(demoRecordFile());
  if (!record || !record.dir || !record.token) return;
  let mark = '';
  try { mark = fs.readFileSync(path.join(String(record.dir), fsx.MARK), 'utf8').trim(); } catch { mark = ''; }
  let alive = false;
  try { process.kill(Number(record.pid), 0); alive = true; } catch (error) { alive = error.code === 'EPERM'; }
  if (alive && Number(record.pid) !== process.pid) return; // другой держатель ещё публикует
  if (mark === record.token) {
    try { fsx.rmSync(String(record.dir), { recursive: true, force: true }, 5000); } catch { return; }
  }
  const published = path.join(codeDir, 'local-triage-demo', fsx.MARK);
  try { if (fs.readFileSync(published, 'utf8').trim() === record.token) fs.rmSync(published); } catch { /* метки нет */ }
  try { fs.rmSync(demoRecordFile(), { force: true }); } catch { /* в следующий раз */ }
}

/**
 * Демо-проект – в папку кода целиком: уникальный временный каталог (mkdtemp), запись о публикации в служебной папке и
 * метка с токеном – до копирования, публикация переименованием, метка и запись снимаются после.
 */
function publishDemo(demo, target) {
  const tmp = fs.mkdtempSync(path.join(codeDir, DEMO_TMP));
  const token = `local-triage ${process.pid} ${crypto.randomBytes(8).toString('hex')}`;
  stand.writeJsonAtomic(demoRecordFile(), { dir: tmp, token, pid: process.pid });
  fs.writeFileSync(path.join(tmp, fsx.MARK), `${token}\n`);
  try {
    fs.cpSync(demo, tmp, { recursive: true });
    fsx.renameSync(tmp, target);
  } catch (error) {
    try { fsx.rmSync(tmp, { recursive: true, force: true }, 5000); } catch { /* разберёт demoLeftovers */ }
    if (!fs.existsSync(target)) throw error; // демо опубликовал другой стенд с той же папкой кода – своя копия не нужна
    try { fs.rmSync(demoRecordFile(), { force: true }); } catch { /* разберёт demoLeftovers */ }
    return;
  }
  try { fs.rmSync(path.join(target, fsx.MARK), { force: true }); } catch { /* снимется при следующем запуске */ }
  try { fs.rmSync(demoRecordFile(), { force: true }); } catch { /* разберёт demoLeftovers */ }
}

const DEMO_TMP = '.local-triage-demo-';

/** Папка кода и служебная не вложены одна в другую (физические пути): служебные каталоги стенд чистит и заменяет. */
function checkFoldersApart() {
  const inside = (a, b) => a === b || a.startsWith(b.endsWith(path.sep) ? b : b + path.sep);
  const [c, h] = [canonical(codeDir), canonical(home)];
  if (inside(c, h) || inside(h, c)) {
    throw new StandError(t(`Папка кода ${codeDir} и служебная папка ${home} вложены друг в друга: служебные каталоги стенд ` +
      'чистит и заменяет, а приложение видит всё внутри папки кода. Выберите папки, не вложенные одна в другую.', `The code folder ${codeDir} and the home folder ${home} are nested in each other: the stand cleans and replaces its ` +
      'service directories, and the app sees everything inside the code folder. Choose folders that are not nested.'));
  }
}

function prepareCodeDir() {
  // привязку папки кода знает кластер (pg/data, pg/next или копия, названная меткой переключения) – она главнее
  // stand.json: тот мог быть утрачен или записан запуском, который потом отказал (Д10, ревью круга 4). Новая привязка
  // пишется в stand.json только когда стенд дошёл до готовности
  const bound = binding.current(home);
  if (bound && !opts.newDatabase && !binding.matches(bound, codeDir)) throw bindingError(bound);
  checkFoldersApart();
  fs.mkdirSync(codeDir, { recursive: true });
  codeReal = fs.realpathSync.native(codeDir); // физический путь – на всё время работы держателя
  const demo = path.join(appRoot, 'examples', 'demo', 'repos');
  const target = path.join(codeDir, 'local-triage-demo');
  demoLeftovers(); // своя метка в опубликованном демо и свой временный каталог – по записи публикации
  if (fs.existsSync(demo) && !fs.existsSync(target)) publishDemo(demo, target);
  const margin = pathMargin(codeDir);
  if (process.platform === 'win32') {
    say(t(`Папка кода: ${margin.path} (запас длины пути для самого длинного файла примеров – ${margin.margin} знаков).`, `Code folder: ${margin.path} (path length margin for the longest example file – ${margin.margin} characters).`));
    if (margin.margin < 0) say(t('Путь длинный: часть файлов примеров не откроется без политики LongPathsEnabled; лучше короткая папка кода (--code-dir).', 'The path is long: some example files will not open without the LongPathsEnabled policy; a short code folder (--code-dir) is better.'));
  } else {
    say(t(`Папка кода: ${margin.path}`, `Code folder: ${margin.path}`));
  }
}

// ---------------------------------------------------------------- приложение

function appLogStream() {
  const day = stamp().slice(0, 10);
  const stream = fs.createWriteStream(path.join(dirs.logs, `app-${day}.log`), { flags: 'a' });
  // журнал недоступен: приложение работает дальше, держатель не падает в обход остановки базы (ревью круга 5)
  stream.on('error', (error) => log(`журнал приложения не пишется: ${error.message}`));
  return stream;
}

function lockBeat() {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(dirs.data, 'telemetry', 'instance.lock'), 'utf8'));
    return String(data.beat || '');
  } catch {
    return '';
  }
}

/** Прежний процесс приложения убит, а отметка его замка ещё свежая: ждать, пока она перестанет меняться (код 75). */
async function waitLockStale() {
  say(t('Прежний процесс приложения ещё держит папку данных – жду, пока его отметка устареет…', 'A previous app process still holds the data folder – waiting for its lock mark to expire…'));
  let last = lockBeat();
  let quietSince = Date.now();
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2000));
    const beat = lockBeat();
    if (beat !== last) {
      last = beat;
      quietSince = Date.now();
    } else if (Date.now() - quietSince > LOCK_STALE_MS + 2000) {
      return;
    }
  }
  throw new StandError(t('Папку данных держит другой работающий экземпляр приложения: его отметка продолжает обновляться. ' +
    'Закройте его и запустите стенд снова.', 'Another running app instance holds the data folder: its lock mark keeps updating. ' +
    'Close it and start the stand again.'));
}

function spawnApp(port) {
  // язык – только заданный явно (--lang или TRIAGE_LANG): иначе приложение берёт сохранённую настройку или английский
  const env = envs.appEnv({ dataDir: dirs.data, tmpDir: dirs.tmp, codeDir, codeReal, libpq: envs.libpqEnv(pgPort, password),
    external: !opts.local, build: opts.build || {}, token, lang: opts.appLang || '' });
  const proc = spawn(py, ['-E', '-s', '-X', 'utf8', '-m', 'app.serve', '--host', '127.0.0.1', '--port', String(port)],
    { cwd: appRoot, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const out = appLogStream();
  proc.bound = false;
  const watch = (chunk) => {
    out.write(chunk);
    if (!proc.bound && /Uvicorn running on http:\/\/127\.0\.0\.1:\d+/.test(String(chunk))) proc.bound = true;
  };
  proc.stdout.on('data', watch);
  proc.stderr.on('data', watch);
  proc.stdin.on('error', () => {});
  proc.exited = new Promise((resolve) => {
    let done = false;
    const finish = (code) => {
      if (done) return;
      done = true;
      out.end();
      resolve(code);
    };
    proc.on('exit', (code) => finish(code));
    // процесс не создан (нет интерпретатора): попытка завершена, держатель не падает в обход остановки базы
    proc.on('error', (error) => {
      proc.failed = true;
      log(`приложение не запустилось: ${error.message}`);
      finish(-1);
    });
  });
  apps.add(proc);
  proc.exited.then(() => apps.delete(proc));
  return proc;
}

function healthz(port, ms = 3000) {
  return getJson(port, '/healthz', Math.max(200, ms)).then((r) => (r.state === 'ok' ? r.data : null));
}

async function waitReady(proc, port) {
  const deadline = Date.now() + READY_MS;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null || proc.failed) return false;
    const answer = await healthz(port, Math.min(3000, deadline - Date.now()));
    if (proc.bound && answer && answer.stand && answer.stand.token === token && ['ok', 'hub_write_paused'].includes(answer.status)) {
      if (answer.status === 'hub_write_paused') {
        say(t('В базе отмечена пауза записи в Hub; в стенде Hub выключен, на работу с находками это не влияет.', 'The database has Hub writes paused; Hub is disabled on the stand, so this does not affect work with findings.'));
      }
      return true;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

function appLogTail() {
  try { return tail(fs.readFileSync(path.join(dirs.logs, `app-${stamp().slice(0, 10)}.log`), 'utf8'), 15); } catch { return ''; }
}

/** Запуск приложения: свободный порт с 8765 (порт, где отвечает чужой процесс, пропускается), коды 75 и 76. */
async function startApp() {
  let port = opts.port || appPort || APP_PORT_FIRST;
  const firstPort = port;
  for (let attempt = 0; attempt < APP_PORT_TRIES && port <= 65535; attempt += 1) {
    checkStop();
    if (await portAnswers(port)) {
      if (opts.port && port === opts.port) { // и при перезапуске: явный порт не меняется (ревью круга 9)
        throw new StandError(t(`Порт ${port}, заданный ключом --port, занят другой программой. Освободите его или выберите другой.`, `Port ${port} set with --port is used by another program. Free it or choose another one.`));
      }
      port += 1;
      continue;
    }
    checkStop();
    const proc = spawnApp(port);
    const ready = await Promise.race([waitReady(proc, port), proc.exited.then(() => false)]);
    if (ready) return { proc, port };
    if (proc.exitCode === null) {
      await killTree(proc);
      throw new StandError(t(`Приложение не ответило за ${READY_MS / 1000} с.\n${appLogTail()}`, `The app did not respond within ${READY_MS / 1000} s.\n${appLogTail()}`));
    }
    if (proc.exitCode === 75) {
      await waitLockStale();
      continue;
    }
    if (proc.exitCode === 76) {
      if (opts.port && port === opts.port) {
        throw new StandError(t(`Порт ${port}, заданный ключом --port, занять нельзя (зарезервирован системой или занят). ` +
          'Выберите другой порт.', `Port ${port} set with --port cannot be used (reserved by the system or in use). ` +
          'Choose another port.'));
      }
      port += 1;
      continue;
    }
    throw new StandError(t(`Приложение не запустилось (код ${proc.exitCode}).\n${appLogTail()}`, `The app did not start (code ${proc.exitCode}).\n${appLogTail()}`));
  }
  throw new StandError(t(`Свободного порта для приложения не нашлось (${firstPort}–${Math.min(65535, port - 1)}).`, `No free port was found for the app (${firstPort}–${Math.min(65535, port - 1)}).`));
}

/**
 * Принудительная остановка приложения вместе с дочерними процессами: python.exe окружения uv на Windows – перенаправитель,
 * а сервер работает в его дочернем процессе базового интерпретатора.
 */
async function killTree(proc) {
  if (proc.exitCode !== null) return;
  if (process.platform === 'win32') {
    await run('taskkill.exe', ['/pid', String(proc.pid), '/t', '/f'], { timeoutMs: 30000 });
  } else {
    proc.kill('SIGKILL');
  }
  await Promise.race([proc.exited, new Promise((r) => setTimeout(r, 10000))]);
}

function exitText(code) {
  return code === null || code < 0 || code > 255 ? t('процесс завершён извне', 'process terminated externally') : t(`код ${code}`, `code ${code}`);
}

async function waitPortFree(port, ms = 15000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline && (await portAnswers(port))) await new Promise((r) => setTimeout(r, 500));
}

function watchApp(proc) {
  proc.exited.then(async (raw) => {
    if (stopping || proc !== child) return;
    const code = exitText(raw);
    setPhase('restarting', t(`приложение остановилось (${code})`, `the app stopped (${code})`)); // прежний адрес больше не выдаётся как готовый
    appUrl = '';
    await waitPortFree(appPort); // прежний процесс ещё может держать порт: перезапуск – на том же адресе
    if (stopping) return;
    const now = Date.now();
    while (restarts.length && now - restarts[0] > RESTART_WINDOW_MS) restarts.shift();
    if (restarts.length >= RESTARTS) {
      setPhase('failed', t(`приложение остановилось (${code}) и перезапуски не помогли`, `the app stopped (${code}) and restarts did not help`));
      say(t(`Приложение остановилось (${code}), перезапуски не помогли. Журнал: ${dirs.logs}\n${appLogTail()}`, `The app stopped (${code}), restarts did not help. Logs: ${dirs.logs}\n${appLogTail()}`));
      return;
    }
    restarts.push(now);
    say(t(`Приложение остановилось (${code}) – перезапускаю…`, `The app stopped (${code}) – restarting…`));
    try {
      const started = await startApp();
      child = started.proc;
      appPort = started.port;
      appUrl = `http://127.0.0.1:${appPort}/`;
      watchApp(child);
      setPhase('ready');
      say(t(`Стенд снова работает: ${appUrl}`, `The stand is running again: ${appUrl}`));
      watchExamples(); // перезапущенное приложение снова скачивает недостающие примеры
    } catch (error) {
      if (stopping || error instanceof Cancelled) return; // остановку доводит shutdown
      setPhase('failed', error.message);
      say(error.message);
    }
  });
}

// ---------------------------------------------------------------- остановка

let stopIssues = 0; // что остановить не удалось: последнее сообщение и код выхода говорят об этом


async function stopApps() {
  for (const proc of [...apps]) { // в том числе запущенное, но ещё не готовое приложение
    if (proc.exitCode !== null || proc.failed) continue;
    try { proc.stdin.end(); } catch { /* канал уже закрыт */ }
    const done = await Promise.race([proc.exited.then(() => true), new Promise((r) => setTimeout(() => r(false), APP_STOP_MS))]);
    if (!done) {
      say(t('Приложение не остановилось за 25 с – останавливаю принудительно.', 'The app did not stop within 25 s – forcing it to stop.'));
      await killTree(proc);
    }
    if (proc.exitCode === null) stopIssues += 1;
  }
}

async function shutdown(code = 0, fromMain = false) {
  if (stopping) return;
  stopping = true;
  if (phase !== 'failed') setPhase('stopping'); // причина отказа остаётся видна ждущему окну
  say(t('Останавливаю стенд…', 'Stopping the stand…'));
  stopCollector();
  await stopApps();
  await settle(60000); // установщик, initdb, pg_ctl, начатые до остановки
  // цепочка запуска могла быть между шагами (выбор порта, запуск сервера): дождаться её отмены до проверки серверов
  if (!fromMain) await Promise.race([mainRun, new Promise((r) => setTimeout(r, 120000))]);
  await settle(30000);
  await stopApps(); // приложение могло стартовать, пока цепочка запуска доходила до проверки остановки
  const tryStop = async (dir, port) => {
    try {
      return await stopServer(dir, port);
    } catch (error) {
      say(t(`Сервер на ${dir}: ${error.message}`, `Server on ${dir}: ${error.message}`));
      return false;
    }
  };
  if (tempServer && py) {
    const stopped = await tryStop(tempServer.dir, tempServer.port);
    say(stopped ? t('Временный сервер обновления схемы остановлен.', 'The temporary schema update server was stopped.') : t('Временный сервер обновления схемы остановить не удалось.', 'Could not stop the temporary schema update server.'));
    if (!stopped) stopIssues += 1;
  }
  if (pgStarted && pgPort && fs.existsSync(dataDir) && py) {
    const stopped = await tryStop(dataDir, pgPort);
    say(stopped ? t('PostgreSQL остановлен.', 'PostgreSQL stopped.') : t('PostgreSQL остановить не удалось: подробности выше.', 'Could not stop PostgreSQL: see the details above.'));
    if (!stopped) stopIssues += 1;
  }
  if (!(pgStarted && pgPort) && fs.existsSync(dataDir) && !fs.existsSync(pg.exe(binDir, 'pg_ctl')) && !dataState) {
    dataState = 'error'; // проверить состояние нечем: честное «не установлено», сигнала нет (ревью круга 8)
  }
  const nextDir = path.join(dirs.pg, 'next');
  if (!tempServer && fs.existsSync(nextDir) && fs.existsSync(pg.exe(binDir, 'pg_ctl'))) {
    let code = -1;
    try { code = (await pgStatus(nextDir)).code; } catch { code = -1; }
    if (code === 0) {
      say(t(`На ${nextDir} (прерванное обновление схемы) работает процесс PostgreSQL: сигнал остановки не посылался.`, `A PostgreSQL process is running on ${nextDir} (interrupted schema update): no stop signal was sent.`));
      stopIssues += 1;
    } else if (code !== 3) {
      say(t(`Работает ли PostgreSQL на ${nextDir} (прерванное обновление схемы), не установлено: сигнал не посылался.`, `Whether PostgreSQL is running on ${nextDir} (interrupted schema update) could not be determined: no signal was sent.`));
      stopIssues += 1;
    }
  }
  if (!(pgStarted && pgPort) && !py && fs.existsSync(dataDir) && fs.existsSync(pg.exe(binDir, 'pg_ctl'))) {
    // отказ до подготовки Python: подтвердить каталог по SQL нечем
    try {
      const st = await pgStatus(dataDir);
      if (st.code === 0) dataState = 'process';
      else if (st.code === 4) dataState = 'notcluster';
      else if (st.code !== 3) dataState = 'error';
    } catch { dataState = 'error'; }
  }
  if (!(pgStarted && pgPort) && dataState === 'starting' && py) {
    // остановка пришла, пока PostgreSQL восстанавливался: ограниченное ожидание конца восстановления, затем штатная
    // остановка подтверждённого сервера (ревью круга 10)
    const deadline = Date.now() + 120000;
    let who = 'starting';
    while (who === 'starting' && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000));
      try { who = await serverOn(dataDir, pgPort || state.data.pg_port || 0); } catch { who = 'error'; }
    }
    if (who === 'running') {
      const stopped = await tryStop(dataDir, pgPort || state.data.pg_port);
      say(stopped ? t('PostgreSQL остановлен после восстановления.', 'PostgreSQL stopped after recovery.') : t('PostgreSQL остановить не удалось: подробности выше.', 'Could not stop PostgreSQL: see the details above.'));
      if (!stopped) stopIssues += 1;
      else dataState = 'down';
    }
  }
  if (!(pgStarted && pgPort) && fs.existsSync(dataDir)) {
    // сервер не запускался этим держателем: что с ним, говорит последняя проверка каталога; её не было (отказ раньше,
    // например без файла пароля) – одна проверка сейчас, сигнал не посылается
    if (!dataState && py) {
      try { await serverOn(dataDir, state.data.pg_port || (pidFile(dataDir) || {}).port || 0); } catch { dataState = 'error'; }
    }
    if (dataState === 'running') {
      say(t('PostgreSQL стенда оставлен работать: сигнал остановки ему не посылался.', 'The stand PostgreSQL was left running: no stop signal was sent to it.'));
      stopIssues += 1;
    } else if (['unconfirmed', 'starting', 'elsewhere', 'process'].includes(dataState)) {
      say(t('На каталоге базы работает процесс PostgreSQL, но по SQL он не подтверждён: сигнал остановки не посылался.', 'A PostgreSQL process is running on the database directory, but it is not confirmed via SQL: no stop signal was sent.'));
      stopIssues += 1;
    } else if (['stale', 'foreign', 'error', 'notcluster'].includes(dataState)) {
      say(t('Работает ли PostgreSQL стенда, не установлено: сигнал остановки не посылался.', 'Whether the stand PostgreSQL is running could not be determined: no stop signal was sent.'));
      stopIssues += 1;
    }
  }
  if (stopIssues) {
    say(t('Стенд остановлен не полностью: часть процессов оставлена работать, подробности выше.', 'The stand did not stop completely: some processes were left running, see the details above.'));
    if (code === 0) code = 1;
  } else {
    say(t('Стенд остановлен.', 'The stand has stopped.'));
  }
  if (lockServer) lockServer.close();
  setTimeout(() => process.exit(code), 200);
}

// ---------------------------------------------------------------- ход запуска

async function main() {
  try {
    lockServer = await holdLock(opts.lockPort);
  } catch (error) {
    if (error && error.code === 'EADDRINUSE') process.exit(3); // другое окно успело первым: CLI подключится к нему
    say(t(`Служебный порт стенда ${opts.lockPort} недоступен (${error && error.code ? error.code : error}): вероятно, Windows ` +
      'зарезервировала его для Hyper-V, WSL или Docker. Запустите стенд с другой служебной папкой: npx local-triage --home <папка>.', `The stand service port ${opts.lockPort} is unavailable (${error && error.code ? error.code : error}): Windows has probably ` +
      'reserved it for Hyper-V, WSL or Docker. Start the stand with a different home folder: npx local-triage --home <folder>.'));
    process.exit(4);
  }
  checkFoldersApart(); // до любых записей и чисток: ни один файл в папке кода ещё не тронут (ревью кругов 7–8)
  for (const dir of Object.values(dirs)) fs.mkdirSync(dir, { recursive: true });
  logFile = path.join(dirs.logs, `supervisor-${stamp().slice(0, 10)}.log`);
  pg.pruneLogs(dirs.logs);
  process.stdin.on('end', () => shutdown(0));
  process.stdin.on('close', () => shutdown(0));
  process.stdin.on('error', () => shutdown(0));
  process.stdin.resume();
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK']) {
    try { process.on(sig, () => shutdown(0)); } catch { /* сигнала нет на платформе */ }
  }
  state = stand.load(home);
  // stand.json утрачен, а прежние базы есть – это прежняя установка (раздел 3.2): отмечается до первой записи файла,
  // чтобы прерванный запуск не превратил её в первую; явный --new-database – выбор оператора
  if (!state.existed && (backupsPresent() || clusterMarked()) && !opts.newDatabase) stand.save(state, { phase: 'ready' });
  let npmShown = version;
  try { npmShown = npmVersionOf(version); } catch { /* как есть */ }
  say(t(`Учебный стенд «Локальный триаж» ${version} (пакет npm ${npmShown}). Служебная папка: ${home}`, `Local Triage training stand ${version} (npm package ${npmShown}). Home folder: ${home}`));
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    throw new StandError(t('Стенд не запускается от root: PostgreSQL от root не работает. Запустите от обычного пользователя.', 'The stand does not run as root: PostgreSQL does not work as root. Run it as a regular user.'));
  }
  pg.platformPackage();
  py = await python.ensurePython({ home, version, requirements: path.join(packageDir, 'npm', 'requirements.txt'),
    env: envs.pythonInstallEnv(dirs.tmp), say, reinstall: Boolean(opts.reinstall) });
  checkStop();
  appRoot = syncAppRoot();
  prepareCodeDir();
  setPhase('starting');
  await preparePostgres();
  const after = binding.fromCluster(home);
  if (after && !opts.newDatabase && !binding.matches(after, codeDir)) throw bindingError(after);
  checkStop();
  stopCollector = metrics.startCollector(dirs.data, (error) => log(`сведения о компьютере не записаны: ${error.message}`));
  say(t('Запускаю приложение…', 'Starting the app…'));
  const started = await startApp();
  child = started.proc;
  appPort = started.port;
  appUrl = `http://127.0.0.1:${appPort}/`;
  watchApp(child);
  // Д10: привязка – тот физический путь, с которым работает Python; ссылку перенацелили во время запуска – отказ
  if (canonical(codeDir) !== canonical(codeReal)) {
    throw new StandError(t(`Папка кода ${codeDir} во время запуска стала указывать на ${canonical(codeDir)}, а приложение ` +
      `работает с ${canonical(codeReal)}. Верните ссылку и запустите стенд снова.`, `During startup the code folder ${codeDir} started pointing to ${canonical(codeDir)}, but the app ` +
      `works with ${canonical(codeReal)}. Restore the link and start the stand again.`));
  }
  stand.save(state, { phase: 'ready', app_port: appPort, last_good_version: version, code_dir: codeDir,
    code_dir_real: canonical(codeReal) });
  // версия рядом с самим кластером: имя копии обновления знает её и при утраченном stand.json
  try { fs.writeFileSync(path.join(dataDir, 'local-triage.version'), `${version}\n`); } catch { /* не критично */ }
  try { fs.writeFileSync(path.join(dataDir, binding.FILE), binding.fileText(codeDir, codeReal)); } catch { /* не критично */ }
  setPhase('ready');
  say(t(`Стенд работает: ${appUrl}`, `The stand is running: ${appUrl}`));
  try { process.stdout.write(`@@ready ${appUrl}\n`); } catch { /* окно закрыто */ }
  watchExamples();
}

/** Ход фонового скачивания учебных примеров – в окне запуска (ADR-0156): по строке на смену состояния примера,
 *  пока не останется скачиваемых или в очереди; не дольше 30 минут. Сбой опроса окно не трогает. */
let examplesTimer = null;
let examplesGeneration = 0;

function watchExamples() {
  if (examplesTimer) clearTimeout(examplesTimer); // один опрос на стенд: прежний (до перезапуска приложения) отменяется
  const generation = ++examplesGeneration; // опрос, дождавшийся ответа после перезапуска, дальше не планируется
  const seen = {};
  const until = Date.now() + 30 * 60 * 1000;
  const words = { downloaded: t('скачан', 'downloaded'), failed: t('не скачан', 'not downloaded'), fetching: t('скачивается', 'downloading'), queued: t('в очереди', 'queued') };
  const tick = async () => {
    if (stopping || Date.now() > until || !appPort) return;
    let busy = true;
    try {
      const r = await getJson(appPort, '/examples/status', 3000);
      if (r.state === 'ok' && r.data && typeof r.data === 'object') {
        busy = false;
        for (const [id, item] of Object.entries(r.data)) {
          const phase = item && item.phase;
          if (phase === 'fetching' || phase === 'queued') busy = true;
          if (!words[phase] || seen[id] === phase) continue;
          if (phase === 'queued') { seen[id] = phase; continue; } // очередь запоминается, строка не нужна
          if (seen[id] === undefined && phase === 'downloaded' && !item.fresh) { seen[id] = phase; continue; } // был до запуска
          seen[id] = phase;
          say(t(`Пример ${id}: ${words[phase]}${phase === 'failed' && item.message ? ` – ${item.message}` : ''}`, `Example ${id}: ${words[phase]}${phase === 'failed' && item.message ? ` – ${item.message}` : ''}`));
        }
      }
    } catch { /* приложение ещё не ответило – следующий опрос */ }
    if (generation !== examplesGeneration) return;
    if (busy) { examplesTimer = setTimeout(tick, 5000); examplesTimer.unref(); } else examplesTimer = null;
  };
  examplesTimer = setTimeout(tick, 3000);
  examplesTimer.unref();
}

const mainRun = main().then(() => null, (error) => error);
mainRun.then(async (error) => {
  if (!error || error instanceof Cancelled || stopping) return; // остановку доводит shutdown
  const text = error instanceof StandError ? error.message : t(`Сбой стенда: ${error && error.stack ? error.stack : error}`, `Stand failure: ${error && error.stack ? error.stack : error}`);
  setPhase('failed', text.split('\n')[0]);
  say(text);
  say(t(`Журналы: ${dirs.logs}`, `Logs: ${dirs.logs}`));
  await shutdown(1, true);
});
