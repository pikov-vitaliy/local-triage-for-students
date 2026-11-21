'use strict';
// Тесты чистых функций обёртки учебного стенда (ADR-0155): node --test tests/npm.
// Запускаются и из pytest (tests/test_npm_launcher.py).

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const lib = (name) => require(path.join(__dirname, '..', '..', 'npm', 'lib', name));
const version = lib('version');
const paths = lib('paths');
const envs = lib('env');
const pg = lib('pg');
const stand = lib('stand');
const cluster = lib('cluster');

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lt-npm-test-'));
}

// ---------------------------------------------------------------- версия

test('версия пакета и приложения переводятся друг в друга', () => {
  assert.equal(version.npmVersionOf('0.10.0.dev32'), '0.10.0-dev.32');
  assert.equal(version.npmVersionOf('0.10.0'), '0.10.0');
  assert.equal(version.appVersionOf('0.10.0-dev.32'), '0.10.0.dev32');
  assert.throws(() => version.npmVersionOf('0.10.0-dev32'));
  assert.throws(() => version.appVersionOf('0.10.0.dev32'));
});

// ---------------------------------------------------------------- папки

test('служебная папка: ASCII – как есть, кириллица – короткое имя 8.3', () => {
  const base = tmp();
  const ascii = paths.resolveHome({ override: path.join(base, 'home'), platform: 'win32', env: {}, short: () => '' });
  assert.equal(ascii.how, 'as-is');
  const cyr = path.join(base, 'Папка');
  const alias = path.join(base, 'PAPKA~1');
  const short = paths.resolveHome({ override: cyr, platform: 'win32', env: {}, short: () => alias });
  assert.deepEqual([short.how, short.home], ['short', alias]);
});

test('без короткого имени – запасной корень с хешем пути: у разных папок разные корни (Д20)', () => {
  const drive = tmp();
  const env = { SystemDrive: drive };
  const one = paths.resolveHome({ override: path.join(drive, 'Первая'), platform: 'win32', env, short: () => '' });
  const two = paths.resolveHome({ override: path.join(drive, 'Вторая'), platform: 'win32', env, short: () => '' });
  assert.equal(one.how, 'fallback');
  assert.ok(one.home.startsWith(`${drive}\\local-triage-`));
  assert.notEqual(one.home, two.home);
  assert.ok(paths.isAscii(path.basename(one.home)));
  assert.ok(!fs.existsSync(path.join(drive, 'Первая')), 'созданная для 8.3 пустая папка убрана');
});

test('на Linux и macOS путь не меняется, по умолчанию – XDG_DATA_HOME или ~/.local/share', () => {
  assert.equal(paths.defaultHome({ XDG_DATA_HOME: '/data/x' }, 'linux', '/home/u'), '/data/x/local-triage');
  assert.equal(paths.defaultHome({ XDG_DATA_HOME: 'relative' }, 'linux', '/home/u'), '/home/u/.local/share/local-triage');
  assert.equal(paths.defaultHome({ LOCALAPPDATA: 'C:\\Profiles\\u\\AppData\\Local' }, 'win32', 'C:\\Profiles\\u'),
    'C:\\Profiles\\u\\AppData\\Local\\local-triage');
  assert.equal(paths.defaultCodeDir({ USERPROFILE: 'C:\\Profiles\\u' }, 'win32', 'C:\\Profiles\\u'), 'C:\\Profiles\\u\\local-triage');
});

test('порт замка: из диапазона 49152–65535, одинаков для одного пути, на Windows без учёта регистра', () => {
  const dir = tmp();
  const port = paths.lockPortOf(dir);
  assert.ok(port >= paths.LOCK_PORT_MIN && port <= paths.LOCK_PORT_MAX);
  assert.equal(paths.lockPortOf(dir), port);
  if (process.platform === 'win32') assert.equal(paths.lockPortOf(dir.toUpperCase()), port);
  assert.notEqual(paths.lockPortOf(path.join(dir, 'other')), port);
});

test('запас длины пути считается по раскрытому пути и пределу 259', () => {
  const dir = tmp();
  const m = paths.pathMargin(dir);
  assert.equal(m.limit, 259);
  assert.equal(m.margin, 259 - m.used);
  assert.ok(m.used > m.path.length + paths.LONGEST_EXAMPLE_PATH);
});

// ---------------------------------------------------------------- окружение

const PARENT = {
  Path: 'C:\\Windows', SystemRoot: 'C:\\Windows', USERPROFILE: 'C:\\Profiles\\u', PGHOSTADDR: '10.9.9.9', PGSERVICE: 'x',
  pgpassword: 'p', VIRTUAL_ENV: 'C:\\venv', CONDA_PREFIX: 'C:\\c', PYTHONPATH: 'C:\\p', PIP_TARGET: 'C:\\t',
  PIP_INDEX_URL: 'https://mirror.example/simple', UV_INDEX_URL: 'https://mirror.example/uv', UV_PYTHON: '3.9',
  TRIAGE_MAINTENANCE: '1', TRUSTED_HOSTS: 'evil.example', LLM_EXTERNAL: '1', OLLAMA_URL: 'http://10.9.9.9:1',
  HTTPS_PROXY: 'http://proxy.example:3128', SSL_CERT_FILE: 'C:\\ca.pem',
};

test('окружение приложения – перечень и явные значения стенда, унаследованное не проходит', () => {
  const env = envs.appEnv({ dataDir: 'D', tmpDir: 'T', codeDir: 'C', libpq: envs.libpqEnv(5555, 'pw'), external: false,
    build: { commit: 'abc1234', dirty: false, time: '20.11.2026 21:00' }, token: 'f'.repeat(32), env: PARENT, platform: 'win32' });
  for (const name of ['PGHOSTADDR', 'PGSERVICE', 'pgpassword', 'VIRTUAL_ENV', 'TRUSTED_HOSTS', 'CONDA_PREFIX', 'HTTPS_PROXY']) {
    assert.ok(!(name in env), name);
  }
  assert.equal(env.PATH, 'C:\\Windows');
  assert.equal(env.TRIAGE_MAINTENANCE, '0');
  assert.equal(env.LLM_EXTERNAL, '0');
  assert.equal(env.OLLAMA_URL, 'http://127.0.0.1:11434');
  assert.equal(env.TRIAGE_STAND, 'npm');
  assert.deepEqual([env.PGHOST, env.PGPORT, env.PGUSER, env.PGDATABASE, env.PGPASSWORD, env.PGCONNECT_TIMEOUT],
    ['127.0.0.1', '5555', 'triage', 'triage', 'pw', '10']);
  assert.deepEqual([env.LT_BUILD_COMMIT, env.LT_BUILD_DIRTY], ['abc1234', '0']);
  assert.equal(envs.appEnv({ dataDir: 'D', tmpDir: 'T', codeDir: 'C', libpq: {}, external: true, token: 't', env: PARENT,
    platform: 'win32' }).LLM_EXTERNAL, '1');
});

test('initdb и pg_ctl не получают ни одной переменной PG*', () => {
  const env = envs.pgToolEnv('T', PARENT, 'win32');
  assert.ok(Object.keys(env).every((k) => !k.toUpperCase().startsWith('PG')));
  assert.equal(env.TEMP, 'T');
});

test('установка Python: без выбора интерпретатора и пакетов, адрес индекса и прокси проходят (Д16)', () => {
  const env = envs.pythonInstallEnv('T', PARENT);
  for (const name of ['VIRTUAL_ENV', 'CONDA_PREFIX', 'PYTHONPATH', 'PIP_TARGET', 'UV_PYTHON', 'PGHOSTADDR']) assert.ok(!(name in env), name);
  assert.equal(env.PIP_INDEX_URL, PARENT.PIP_INDEX_URL);
  assert.equal(env.UV_INDEX_URL, PARENT.UV_INDEX_URL);
  assert.equal(env.HTTPS_PROXY, PARENT.HTTPS_PROXY);
  assert.equal(env.UV_NATIVE_TLS, '1');
});

// ---------------------------------------------------------------- PostgreSQL

test('аргументы initdb и pg_ctl – по таблице раздела 3.4', () => {
  assert.deepEqual(pg.initdbArgs('D', 'P'), ['-D', 'D', '-U', 'triage', '--pwfile=P', '--auth=scram-sha-256', '-E', 'UTF8',
    '--locale=C', '--locale-provider=builtin', '--builtin-locale=C.UTF-8']);
  assert.ok(!pg.initdbArgs('D', 'P').includes('-l'));
  assert.deepEqual(pg.syncOnlyArgs('D'), ['--sync-only', '-D', 'D']);
  assert.deepEqual(pg.startArgs('D', 'L'), ['start', '-D', 'D', '-l', 'L', '-w', '-t', '60']);
  assert.deepEqual(pg.statusArgs('D'), ['status', '-D', 'D']);
  assert.deepEqual(pg.stopArgs('D'), ['stop', '-D', 'D', '-m', 'fast', '-w', '-t', '30']);
  assert.deepEqual(pg.stopArgs('D', 'immediate'), ['stop', '-D', 'D', '-m', 'immediate', '-w', '-t', '30']);
});

test('журнал сервера без данных: настройки local-triage.conf', () => {
  const text = pg.confText(5432);
  for (const line of ["listen_addresses = '127.0.0.1'", 'port = 5432', 'log_min_messages = log', 'log_min_error_statement = panic',
    'log_error_verbosity = terse', 'log_statement = none', 'log_min_duration_statement = -1']) assert.ok(text.includes(line), line);
});

test('строка include в postgresql.conf – одна, local-triage.conf переписывается', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'postgresql.conf'), '#x\n');
  pg.writeConf(dir, 1);
  pg.writeConf(dir, 2);
  const conf = fs.readFileSync(path.join(dir, 'postgresql.conf'), 'utf8');
  assert.equal(conf.split(pg.INCLUDE_LINE).length - 1, 1);
  assert.ok(fs.readFileSync(path.join(dir, pg.CONF_NAME), 'utf8').includes('port = 2'));
});

test('пароль: base64url одной строкой, прежний не меняется, кластер без файла – ошибка (Д17)', () => {
  const dir = tmp();
  const made = pg.ensurePassword(dir, false);
  assert.match(made.password, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(fs.readFileSync(made.file, 'utf8'), `${made.password}\n`);
  assert.equal(pg.ensurePassword(dir, true).password, made.password);
  assert.throws(() => pg.ensurePassword(tmp(), true), /файла пароля/);
});

test('каталог кластера: неполный и чужой мажорной версии – отказ', () => {
  const dir = tmp();
  assert.throws(() => pg.checkCluster(dir), /неполный/);
  fs.mkdirSync(path.join(dir, 'global'));
  fs.writeFileSync(path.join(dir, 'global', 'pg_control'), Buffer.alloc(8192));
  fs.writeFileSync(path.join(dir, 'postgresql.conf'), '');
  fs.writeFileSync(path.join(dir, 'PG_VERSION'), '18\n');
  assert.throws(() => pg.checkCluster(dir), /PostgreSQL 18/);
  fs.writeFileSync(path.join(dir, 'PG_VERSION'), '17\n');
  pg.checkCluster(dir);
});

test('Windows на ARM64 – отказ до установки', () => {
  assert.throws(() => pg.platformPackage('win32', 'arm64'), /ARM64/);
  assert.equal(pg.platformPackage('linux', 'arm64'), '@embedded-postgres/linux-arm64');
});

// ---------------------------------------------------------------- фазы установки

test('stand.json: новая установка – фаза none, запись атомарная, пароля в файле нет', () => {
  const home = tmp();
  const state = stand.load(home);
  assert.deepEqual([state.existed, state.data.phase], [false, 'none']);
  stand.save(state, { phase: 'db-creating', pg_port: 5 });
  const again = stand.load(home);
  assert.deepEqual([again.existed, again.data.phase, again.data.pg_port], [true, 'db-creating', 5]);
  assert.ok(!/password|pw/i.test(fs.readFileSync(path.join(home, 'stand.json'), 'utf8')));
  assert.deepEqual(stand.PHASES, ['none', 'db-creating', 'db-created', 'ready']);
});

// ---------------------------------------------------------------- разбор состояния кластера

const ROWS = [
  ['pg/next.tmp', { nextTmp: true, data: true }, ['remove-next-tmp']],
  ['метка, pg/data и pg/next', { mark: { backup: 'b' }, data: true, next: true }, ['switch']],
  ['метка, pg/data нет, оригинал и pg/next', { mark: { backup: 'b' }, markBackup: true, next: true }, ['second-rename']],
  ['метка, pg/data, pg/next нет', { mark: { backup: 'b' }, data: true }, ['drop-mark']],
  ['метка, нет ни pg/data, ни оригинала', { mark: { backup: 'b' }, next: true }, ['unclear']],
  ['pg/next без метки, pg/data на месте', { next: true, data: true }, ['remove-next']],
  ['pg/next без метки, фаза «готов»', { next: true, nextInfo: { phase: 'ready', backup: 'b' }, nextBackup: true }, ['second-rename-unmarked']],
  ['pg/next без метки, фаза не «готов»', { next: true, nextInfo: { phase: 'preparing', backup: 'b' }, nextBackup: true }, ['restore-original']],
  ['pg/next без метки и без оригинала', { next: true }, ['unclear']],
  ['только pg/next.json', { data: true, nextInfo: { phase: 'preparing' } }, ['drop-next-json']],
  ['обычный запуск', { data: true }, []],
];
for (const [row, state, steps] of ROWS) {
  test(`разбор состояния: ${row}`, () => {
    assert.deepEqual(cluster.decide({ data: false, next: false, nextTmp: false, mark: null, nextInfo: null, markBackup: false,
      nextBackup: false, ...state }), steps);
  });
}

function layout(dir, spec) {
  for (const [name, content] of Object.entries(spec)) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
  }
}

test('восстановление: метка и обе папки – переключение, оригинал уходит в backups', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': 'old', 'next/PG_VERSION': 'new', 'switch.json': { backup: 'b1' }, 'next.json': { phase: 'ready' } });
  await cluster.recover(pgDir, { ensureStopped: async () => true });
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'PG_VERSION'), 'utf8'), 'new');
  assert.equal(fs.readFileSync(path.join(pgDir, 'backups', 'b1', 'PG_VERSION'), 'utf8'), 'old');
  assert.ok(!fs.existsSync(path.join(pgDir, 'switch.json')) && !fs.existsSync(path.join(pgDir, 'next.json')));
});

test('восстановление: первое переименование сделано – второе и снятие метки', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'backups/b1/PG_VERSION': 'old', 'next/PG_VERSION': 'new', 'switch.json': { backup: 'b1' } });
  await cluster.recover(pgDir, { ensureStopped: async () => true });
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'PG_VERSION'), 'utf8'), 'new');
  assert.ok(!fs.existsSync(path.join(pgDir, 'switch.json')));
});

test('восстановление: недоделанная подготовка – pg/next удаляется только при точно остановленном сервере', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': 'old', 'next/PG_VERSION': 'copy', 'next.json': { port: 5, phase: 'preparing', backup: 'b' } });
  const seen = [];
  await assert.rejects(cluster.recover(pgDir, { ensureStopped: async (dir, port) => { seen.push([dir, port]); return false; } }),
    /не тронут/);
  assert.ok(fs.existsSync(path.join(pgDir, 'next', 'PG_VERSION')), 'неопределённость – каталог не трогается');
  assert.deepEqual(seen, [[path.join(pgDir, 'next'), 5]]);
  await cluster.recover(pgDir, { ensureStopped: async () => true });
  assert.ok(!fs.existsSync(path.join(pgDir, 'next')) && fs.existsSync(path.join(pgDir, 'data', 'PG_VERSION')));
});

test('восстановление: метка потеряна, pg/next не готов – оригинал возвращается на место', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'backups/b/PG_VERSION': 'old', 'next/PG_VERSION': 'half', 'next.json': { phase: 'preparing', backup: 'b' } });
  await cluster.recover(pgDir, { ensureStopped: async () => true });
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'PG_VERSION'), 'utf8'), 'old');
  assert.ok(!fs.existsSync(path.join(pgDir, 'next')));
});

test('восстановление: неясное состояние – отказ с местами оригинала и копии, ничего не удалено', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'next/PG_VERSION': 'x', 'switch.json': { backup: 'b' } });
  await assert.rejects(cluster.recover(pgDir, { ensureStopped: async () => true }), /не продолжает сам/);
  assert.ok(fs.existsSync(path.join(pgDir, 'next', 'PG_VERSION')));
});

// ---------------------------------------------------------------- обновление схемы на копии

function fakeOps(pgDir, { taken = 0, copiedTables = null } = {}) {
  const calls = [];
  const summary = { tables: { projects: 2, findings: 7, meta: 1 }, hub_ops: taken ? { taken } : {} };
  return {
    calls,
    summary: async (port) => { calls.push(['summary', port]); return port === 1 || !copiedTables ? summary : { tables: copiedTables }; },
    stop: async (dir, port) => { calls.push(['stop', path.basename(dir), port]); },
    start: async (dir, port) => { calls.push(['start', path.basename(dir), port]); },
    status: async () => ({ state: 'ok' }),
    migrate: async (port) => { calls.push(['migrate', port]); },
    syncOnly: async (dir) => { calls.push(['sync', path.basename(dir)]); },
    freePort: async () => 2,
  };
}

test('обновление схемы: копия, миграция на ней, переключение; оригинал – в backups с перечнем файлов', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': '17', 'data/base/1/a': 'rows' });
  const ops = fakeOps(pgDir);
  const backup = await cluster.updateSchema(pgDir, { port: 1, schema: 35, expected: 36, fromVersion: 'v1', toVersion: 'v2' }, ops);
  assert.match(backup, /-schema35-vv1$/);
  assert.equal(fs.readFileSync(path.join(pgDir, 'backups', backup, 'base', '1', 'a'), 'utf8'), 'rows');
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'base', '1', 'a'), 'utf8'), 'rows');
  const files = JSON.parse(fs.readFileSync(path.join(pgDir, 'backups', `${backup}.files.json`), 'utf8'));
  assert.ok('base/1/a' in files && 'PG_VERSION' in files);
  assert.deepEqual(ops.calls.filter((c) => c[0] === 'migrate'), [['migrate', 2]], 'миграция – только на копии');
  for (const name of ['next', 'next.tmp', 'next.json', 'switch.json']) assert.ok(!fs.existsSync(path.join(pgDir, name)), name);
});

test('обновление схемы: выданные операции Hub – отказ без изменений', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': '17' });
  await assert.rejects(cluster.updateSchema(pgDir, { port: 1, schema: 35, expected: 36, fromVersion: 'a', toVersion: 'b' },
    fakeOps(pgDir, { taken: 1 })), /выдана/);
  assert.deepEqual(fs.readdirSync(pgDir), ['data']);
});

test('обновление схемы: копия не совпала с оригиналом по строкам – отказ, рабочий каталог цел', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': '17' });
  await assert.rejects(cluster.updateSchema(pgDir, { port: 1, schema: 35, expected: 36, fromVersion: 'a', toVersion: 'b' },
    fakeOps(pgDir, { copiedTables: { projects: 1, findings: 7 } })), /не совпала/);
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'PG_VERSION'), 'utf8'), '17');
  assert.ok(!fs.existsSync(path.join(pgDir, 'switch.json')));
});

test('сверка строк не учитывает служебные таблицы миграций', () => {
  assert.ok(cluster.sameCounts({ tables: { a: 1, meta: 1 } }, { tables: { a: 1, meta: 2, storage_migrations: 9 } }).ok);
  assert.deepEqual(cluster.sameCounts({ tables: { a: 1, b: 2 } }, { tables: { a: 2 } }), { ok: false, differ: ['a'], lost: ['b'] });
});

test('сверка копии видит смену состояний и группировок при прежнем числе строк (ревью, В7)', () => {
  const before = { tables: { hub_ops: 1 }, hub_ops: { queued: 1 }, groups: { reviews_decision: { fp: 2 } } };
  assert.equal(cluster.sameCounts(before, { tables: { hub_ops: 1 }, hub_ops: { done: 1 }, groups: { reviews_decision: { fp: 2 } } }).ok, false);
  assert.equal(cluster.sameCounts(before, { tables: { hub_ops: 1 }, hub_ops: { queued: 1 }, groups: { reviews_decision: { tp: 2 } } }).ok, false);
  assert.equal(cluster.sameCounts(before, before).ok, true);
});

test('обновление схемы: имя копии – с версией пакета npm, перечень файлов в backups до переключения', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': '17' });
  const ops = fakeOps(pgDir);
  const seen = [];
  const origStart = ops.start;
  ops.start = async (dir, port) => {
    if (path.basename(dir) === 'data') seen.push(fs.readdirSync(path.join(pgDir, 'backups')).sort());
    return origStart(dir, port);
  };
  const backup = await cluster.updateSchema(pgDir, { port: 1, schema: 35, expected: 36, fromVersion: '0.10.0.dev20', toVersion: '0.10.0.dev32' }, ops);
  assert.match(backup, /-schema35-v0\.10\.0-dev\.20$/);
  assert.deepEqual(seen[0], [backup, `${backup}.files.json`, `${backup}.json`].sort());
  const meta = JSON.parse(fs.readFileSync(path.join(pgDir, 'backups', `${backup}.json`), 'utf8'));
  assert.equal(meta.npm_version, '0.10.0-dev.20');
});

test('обновление схемы: сбой миграции – временный сервер останавливается, рабочий каталог цел', async () => {
  const pgDir = tmp();
  layout(pgDir, { 'data/PG_VERSION': '17' });
  const ops = fakeOps(pgDir);
  ops.migrate = async () => { throw new Error('миграция упала'); };
  await assert.rejects(cluster.updateSchema(pgDir, { port: 1, schema: 35, expected: 36, fromVersion: 'a', toVersion: 'b' }, ops), /упала/);
  assert.deepEqual(ops.calls.filter((c) => c[0] === 'stop').map((c) => c[1]), ['data', 'next']);
  assert.equal(fs.readFileSync(path.join(pgDir, 'data', 'PG_VERSION'), 'utf8'), '17');
  assert.ok(!fs.existsSync(path.join(pgDir, 'switch.json')));
});

test('имя копии свободно: совпадение до минуты не перезаписывает прежнюю копию и её перечень (ревью, круг 2)', () => {
  const pgDir = tmp();
  layout(pgDir, { 'backups/n1/PG_VERSION': '17', 'backups/n1-2.files.json': '{}' });
  assert.equal(cluster.uniqueBackupName(pgDir, 'n0'), 'n0');
  assert.equal(cluster.uniqueBackupName(pgDir, 'n1'), 'n1-3');
});

test('пароль: файл повреждён при отсутствующем кластере – создаётся заново, при кластере – ошибка', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'pg.pw'), '');
  assert.equal(pg.passwordReadable(dir), false);
  assert.throws(() => pg.ensurePassword(dir, true), /повреждён/);
  const made = pg.ensurePassword(dir, false);
  assert.ok(made.created && pg.passwordReadable(dir));
  assert.deepEqual(fs.readdirSync(dir), ['pg.pw'], 'временного файла не осталось');
});

test('fsx: повтор только на «занято», на исчерпании – понятное сообщение, прочие ошибки сразу', () => {
  const fsx = lib('fsx');
  let calls = 0;
  const busy = () => { calls += 1; if (calls < 3) { const e = new Error('busy'); e.code = 'EPERM'; throw e; } return 'ok'; };
  assert.equal(fsx.retrying('проба', busy, 5000), 'ok');
  assert.equal(calls, 3);
  const missing = () => { const e = new Error('нет'); e.code = 'ENOENT'; throw e; };
  assert.throws(() => fsx.retrying('проба', missing, 5000), (e) => e.code === 'ENOENT');
  const always = () => { const e = new Error('busy'); e.code = 'EBUSY'; throw e; };
  assert.throws(() => fsx.retrying('Не удалось переименовать a в b', always, 300),
    (e) => e instanceof paths.StandError && /занят другой программой \(EBUSY\)/.test(e.message));
});

test('fsx: остатки прерванных запусков удаляются с любым номером процесса, чужие имена не трогаются', () => {
  const fsx = lib('fsx');
  const dir = tmp();
  for (const name of ['app-root', 'app-root.tmp-111', 'app-root.old-222', 'app-root.tmp-333', 'app-rootx.tmp-1']) {
    fs.mkdirSync(path.join(dir, name));
  }
  fsx.removeLeftovers(dir, 'app-root');
  assert.deepEqual(fs.readdirSync(dir).sort(), ['app-root', 'app-rootx.tmp-1']);
});

test('pg: занятый postgres.log не роняет запуск – сервер пишет в новый файл', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'postgres.log'), 'старый');
  const real = fs.renameSync;
  fs.renameSync = () => { const e = new Error('busy'); e.code = 'EBUSY'; throw e; };
  let file;
  try {
    file = pg.rotateLog(dir, new Date('2026-11-21T01:02:03Z'));
  } finally {
    fs.renameSync = real;
  }
  assert.match(path.basename(file), /^postgres-2026-11-21-01-02-03-run\.log$/);
  assert.equal(fs.readFileSync(path.join(dir, 'postgres.log'), 'utf8'), 'старый');
});

test('pg: копия бинарников без одного файла пакета (pg_ctl) пересобирается из пакета', () => {
  const dir = tmp();
  const source = path.join(dir, 'native');
  for (const name of ['postgres.exe', 'initdb.exe', 'pg_ctl.exe']) {
    fs.mkdirSync(path.join(source, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(source, 'bin', name), name);
  }
  const binDir = path.join(dir, 'bin-17');
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  assert.equal(pg.installBinaries(source, binDir, 'win32'), false, 'полная копия не трогается');
  fs.rmSync(path.join(binDir, 'bin', 'pg_ctl.exe'));
  assert.equal(pg.binariesComplete(source, binDir), false);
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  assert.ok(fs.existsSync(path.join(binDir, 'bin', 'pg_ctl.exe')));
  assert.deepEqual(fs.readdirSync(dir).sort(), ['bin-17', 'native'], 'временных и прежних копий не осталось');
});

test('fsx: в папке кода удаляются только свои временные каталоги – с меткой стенда и номером процесса', () => {
  const fsx = lib('fsx');
  const dir = tmp();
  for (const name of ['local-triage-demo.tmp-notes', 'local-triage-demo.tmp-123', 'local-triage-demo.tmp-456']) {
    fs.mkdirSync(path.join(dir, name));
    fs.writeFileSync(path.join(dir, name, 'work.txt'), 'файл студента');
  }
  fs.writeFileSync(path.join(dir, 'local-triage-demo.tmp-456', fsx.MARK), '');
  fsx.removeLeftovers(dir, 'local-triage-demo', ['tmp'], { marked: true });
  assert.deepEqual(fs.readdirSync(dir).sort(), ['local-triage-demo.tmp-123', 'local-triage-demo.tmp-notes']);
});

test('pg: потеря файла из любой вложенной папки пакета (share/postgres.bki) – копия пересобирается', () => {
  const dir = tmp();
  const source = path.join(dir, 'native');
  for (const rel of ['bin/postgres.exe', 'bin/initdb.exe', 'bin/pg_ctl.exe', 'share/postgres.bki', 'share/timezone/UTC']) {
    fs.mkdirSync(path.dirname(path.join(source, rel)), { recursive: true });
    fs.writeFileSync(path.join(source, rel), rel);
  }
  const binDir = path.join(dir, 'bin-17');
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  for (const rel of ['share/postgres.bki', 'share/timezone/UTC']) {
    fs.rmSync(path.join(binDir, rel));
    assert.equal(pg.binariesComplete(source, binDir), false, rel);
    assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
    assert.ok(fs.existsSync(path.join(binDir, rel)));
  }
});

test('cluster: каталог другой мажорной версии – отказ до первого переноса, все каталоги на месте', async () => {
  const dir = tmp();
  for (const name of ['data', 'next', 'backups']) fs.mkdirSync(path.join(dir, name));
  fs.writeFileSync(path.join(dir, 'data', 'PG_VERSION'), '18\n');
  fs.writeFileSync(path.join(dir, 'next', 'PG_VERSION'), '17\n');
  fs.writeFileSync(path.join(dir, 'switch.json'), JSON.stringify({ backup: 'b1' }));
  fs.writeFileSync(path.join(dir, 'next.json'), JSON.stringify({ phase: 'ready', backup: 'b1' }));
  await assert.rejects(cluster.recover(dir, { ensureStopped: async () => true, verify: (d) => pg.checkMajor(d) }),
    /PostgreSQL 18/);
  assert.deepEqual(fs.readdirSync(dir).sort(), ['backups', 'data', 'next', 'next.json', 'switch.json']);
  assert.deepEqual(fs.readdirSync(path.join(dir, 'backups')), []);
});

test('binding: привязка из pg/next и копии переключения, раскрытый путь – отдельно', () => {
  const binding = lib('binding');
  const home = tmp();
  const codeA = path.join(home, 'codeA');
  fs.mkdirSync(codeA);
  fs.mkdirSync(path.join(home, 'pg', 'backups', 'b1'), { recursive: true });
  fs.writeFileSync(path.join(home, 'pg', 'switch.json'), JSON.stringify({ backup: 'b1' }));
  fs.writeFileSync(path.join(home, 'pg', 'backups', 'b1', binding.FILE), binding.fileText(codeA));
  const found = binding.current(home);
  assert.equal(found.path, codeA);
  assert.ok(binding.matches(found, codeA));
  assert.equal(binding.matches({ path: codeA, real: paths.canonical(path.join(home, 'other')) }, codeA), false,
    'раскрытый путь привязки другой – это другая папка, даже при том же написании');
  fs.writeFileSync(path.join(home, 'stand.json'), JSON.stringify({ code_dir: path.join(home, 'codeB') }));
  assert.equal(binding.current(home).path, codeA, 'кластер главнее stand.json');
});

test('http: обрыв тела и молчание после соединения – «занято», отказ соединения – «свободно»', async () => {
  const http = require('node:http');
  const { getJson } = lib('http');
  const server = http.createServer((req, res) => {
    if (req.url === '/cut') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '100' });
      res.write('{"stand": "loc');
      setTimeout(() => res.destroy(), 50);
    } // /mute – ответа нет
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    assert.equal((await getJson(port, '/cut', 2000)).state, 'busy');
    const started = Date.now();
    assert.equal((await getJson(port, '/mute', 300)).state, 'busy');
    assert.ok(Date.now() - started < 2000, 'срок ограничивает и текущий запрос');
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
  assert.equal((await getJson(port, '/status', 1000)).state, 'free');
});

test('fsx: секрет – права до записи; отказ прав не оставляет ни копии, ни цели', () => {
  const fsx = lib('fsx');
  const dir = tmp();
  const file = path.join(dir, 'pg.pw');
  const seen = [];
  fsx.writeSecret(file, 'секрет\n', (f) => seen.push(fs.readFileSync(f, 'utf8')));
  assert.deepEqual(seen, [''], 'restrict видит пустой файл');
  assert.equal(fs.readFileSync(file, 'utf8'), 'секрет\n');
  const other = path.join(dir, 'copy.pw');
  assert.throws(() => fsx.writeSecret(other, 'секрет\n', () => { throw new Error('acl'); }), /acl/);
  assert.deepEqual(fs.readdirSync(dir).sort(), ['pg.pw']);
  assert.throws(() => fsx.writeSecret(file, 'другой\n', () => {}, { exclusive: true }), (e) => e.code === 'EEXIST');
});

test('pg: усечённый файл копии – не копия; --reinstall пересобирает и целую', () => {
  const dir = tmp();
  const source = path.join(dir, 'native');
  fs.mkdirSync(path.join(source, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(source, 'share'), { recursive: true });
  fs.writeFileSync(path.join(source, 'bin', 'initdb.exe'), 'initdb');
  fs.writeFileSync(path.join(source, 'share', 'postgres.bki'), 'x'.repeat(1000));
  const binDir = path.join(dir, 'bin-17');
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  fs.writeFileSync(path.join(binDir, 'share', 'postgres.bki'), '');
  assert.equal(pg.binariesComplete(source, binDir), false);
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  assert.equal(fs.statSync(path.join(binDir, 'share', 'postgres.bki')).size, 1000);
  assert.equal(pg.installBinaries(source, binDir, 'win32', { force: true }), true);
});

test('cluster: будущий рабочий каталог без PG_VERSION – отказ до переключения, оба дерева и метки на месте', async () => {
  const dir = tmp();
  for (const name of ['data', 'next', 'backups']) fs.mkdirSync(path.join(dir, name));
  fs.writeFileSync(path.join(dir, 'data', 'PG_VERSION'), '17\n');
  fs.writeFileSync(path.join(dir, 'switch.json'), JSON.stringify({ backup: 'b1' }));
  fs.writeFileSync(path.join(dir, 'next.json'), JSON.stringify({ phase: 'ready', backup: 'b1' }));
  await assert.rejects(cluster.recover(dir, { ensureStopped: async () => true,
    verify: (d, required) => pg.checkMajor(d, required) }), /прочитать не удалось/);
  assert.deepEqual(fs.readdirSync(dir).sort(), ['backups', 'data', 'next', 'next.json', 'switch.json']);
});

test('fsx: короткая запись дописывается до конца', () => {
  const fsx = lib('fsx');
  const dir = tmp();
  const file = path.join(dir, 'pg.pw');
  const real = fs.writeSync;
  fs.writeSync = (fd, buf, offset = 0, length = buf.length - offset) => real(fd, buf, offset, Math.min(length, 5));
  try {
    fsx.writeSecret(file, 'длинный-пароль-33-байта-примерно\n');
  } finally {
    fs.writeSync = real;
  }
  assert.equal(fs.readFileSync(file, 'utf8'), 'длинный-пароль-33-байта-примерно\n');
});

test('pg: чистка журналов – только свои по имени, чужие *.log в папке logs не трогаются', () => {
  const dir = tmp();
  const old = new Date('2026-01-01T00:00:00Z');
  for (const name of ['supervisor-2025-12-01.log', 'app-2025-12-01.log', 'build.log', 'postgres.log']) {
    fs.writeFileSync(path.join(dir, name), 'x');
    fs.utimesSync(path.join(dir, name), old, old);
  }
  pg.pruneLogs(dir, new Date('2026-11-21T00:00:00Z'));
  assert.deepEqual(fs.readdirSync(dir).sort(), ['build.log', 'postgres.log']);
});

function fakeCluster(dir, controlBytes = 8192) {
  fs.mkdirSync(path.join(dir, 'global'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'PG_VERSION'), '17\n');
  fs.writeFileSync(path.join(dir, 'postgresql.conf'), '');
  fs.writeFileSync(path.join(dir, 'global', 'pg_control'), Buffer.alloc(controlBytes));
}

test('cluster: копия с обнулённым pg_control не встаёт на место рабочей базы, метки и каталоги на месте', async () => {
  const dir = tmp();
  fakeCluster(path.join(dir, 'data'));
  fakeCluster(path.join(dir, 'next'), 0);
  fs.mkdirSync(path.join(dir, 'backups'));
  fs.writeFileSync(path.join(dir, 'switch.json'), JSON.stringify({ backup: 'b1' }));
  fs.writeFileSync(path.join(dir, 'next.json'), JSON.stringify({ phase: 'ready', backup: 'b1' }));
  await assert.rejects(cluster.recover(dir, { ensureStopped: async () => true,
    verify: (d, required) => pg.checkMajor(d, required) }), /повреждён/);
  assert.deepEqual(fs.readdirSync(dir).sort(), ['backups', 'data', 'next', 'next.json', 'switch.json']);
  assert.equal(fs.statSync(path.join(dir, 'data', 'global', 'pg_control')).size, 8192);
});

test('pg: изменённый файл копии того же размера – не копия (время изменения сверяется)', () => {
  const dir = tmp();
  const source = path.join(dir, 'native');
  fs.mkdirSync(path.join(source, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(source, 'bin', 'pg_ctl.exe'), 'abcdef');
  const binDir = path.join(dir, 'bin-17');
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  assert.equal(pg.binariesComplete(source, binDir), true);
  fs.writeFileSync(path.join(binDir, 'bin', 'pg_ctl.exe'), 'zzzzzz');
  fs.utimesSync(path.join(binDir, 'bin', 'pg_ctl.exe'), new Date('2020-01-01'), new Date('2020-01-01'));
  assert.equal(pg.binariesComplete(source, binDir), false);
});

test('paths: физический путь ещё не созданной папки раскрывает существующего предка', () => {
  const dir = tmp();
  const real = paths.canonical(dir);
  const fresh = paths.canonical(path.join(dir, 'нет', 'ещё'));
  assert.ok(fresh.startsWith(real), `${fresh} начинается с ${real}`);
  assert.ok(fresh.endsWith(path.join('нет', 'ещё').toLowerCase()) || fresh.endsWith(path.join('нет', 'ещё')));
});

test('pg: время копии в пределах округления файловой системы – копия целая, повторная установка ничего не меняет', () => {
  const dir = tmp();
  const source = path.join(dir, 'native');
  fs.mkdirSync(path.join(source, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(source, 'bin', 'initdb.exe'), 'initdb');
  const binDir = path.join(dir, 'bin-17');
  assert.equal(pg.installBinaries(source, binDir, 'win32'), true);
  const t = fs.statSync(path.join(source, 'bin', 'initdb.exe')).mtimeMs;
  fs.utimesSync(path.join(binDir, 'bin', 'initdb.exe'), new Date(t + 1), new Date(t + 1));
  assert.equal(pg.installBinaries(source, binDir, 'win32'), false);
  fs.utimesSync(path.join(binDir, 'bin', 'initdb.exe'), new Date(t + 60000), new Date(t + 60000)); // время ушло, байты те же
  assert.equal(pg.installBinaries(source, binDir, 'win32'), false);
});
