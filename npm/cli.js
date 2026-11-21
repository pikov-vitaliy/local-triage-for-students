#!/usr/bin/env node
'use strict';
// Учебный стенд «Локальный триаж»: npx local-triage (ADR-0155).
//
// Это окно – только интерфейс (раздел 3.5 плана): запускает держатель npm/lib/supervisor.js без консоли, печатает его
// ход, открывает браузер и ждёт Ctrl+C. Ctrl+C, закрытие окна или его гибель закрывают stdin держателя, и он сам
// останавливает приложение и PostgreSQL. Второй запуск находит работающий стенд по служебному порту.

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');

const binding = require('./lib/binding');
const { getJson } = require('./lib/http');
const paths = require('./lib/paths');
const pg = require('./lib/pg');
const { appVersionOf } = require('./lib/version');

const PACKAGE_DIR = path.resolve(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, 'package.json'), 'utf8'));
const WAIT_INSTALL_MS = 15 * 60000;
const WAIT_START_MS = 2 * 60000;

const HELP = `Учебный стенд «Локальный триаж» ${PKG.version}

  npx local-triage [ключи]

Ключи:
  --port N          порт приложения (по умолчанию первый свободный с 8765)
  --no-open         не открывать браузер
  --home ПАПКА      служебная папка стенда (база, Python, журналы) – отдельная новая папка; другая папка – другой стенд
  --code-dir ПАПКА  папка кода с примерами для IDE (задаётся при первом запуске, потом не меняется)
  --local-only      внешние провайдеры моделей выключены; Ollama и подтверждённые серверы локальной сети остаются
  --new-database    начать с новой базы (прежняя остаётся в pg/backups служебной папки)
  --reinstall       заново поставить окружение Python этой версии
  --where           показать папки стенда и выйти
  --doctor          проверить окружение и выйти
  --version         версия стенда
  --help            эта справка`;

function parseArgs(argv) {
  const opts = { port: 0, portGiven: false, open: true, home: '', codeDir: '', local: false, newDatabase: false, reinstall: false,
    where: false, doctor: false, version: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];
    let inline = null;
    if (arg.startsWith('--') && arg.includes('=')) [arg, inline] = [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)];
    const value = () => {
      if (inline !== null) return inline;
      i += 1;
      if (i >= argv.length) throw new paths.StandError(`Ключу ${arg} нужно значение.`);
      return argv[i];
    };
    const flag = () => {
      if (inline !== null) throw new paths.StandError(`Ключ ${arg} пишется без значения (без «=${inline}»).`);
      return true;
    };
    const path_ = () => {
      const v = String(value()).trim();
      if (!v) throw new paths.StandError(`Ключу ${arg} нужна папка – пустое значение не принимается.`);
      return v;
    };
    if (arg === '--port') {
      const raw = String(value()).trim();
      opts.portGiven = true;
      opts.port = /^\d+$/.test(raw) ? Number(raw) : NaN;
    }
    else if (arg === '--home') opts.home = path_();
    else if (arg === '--code-dir') opts.codeDir = path_();
    else if (arg === '--no-open') opts.open = !flag();
    else if (arg === '--local-only') opts.local = flag();
    else if (arg === '--new-database') opts.newDatabase = flag();
    else if (arg === '--reinstall') opts.reinstall = flag();
    else if (arg === '--where') opts.where = flag();
    else if (arg === '--doctor') opts.doctor = flag();
    else if (arg === '--version' || arg === '-v') opts.version = flag();
    else if (arg === '--help' || arg === '-h') opts.help = flag();
    else throw new paths.StandError(`Неизвестный ключ ${argv[i]}. Список ключей: npx local-triage --help`);
  }
  if (opts.portGiven && (!Number.isInteger(opts.port) || opts.port < 1024 || opts.port > 65535)) {
    throw new paths.StandError('--port: нужен номер порта от 1024 до 65535.');
  }
  return opts;
}

async function getStatus(port) {
  const r = await getJson(port, '/status', 2000);
  if (r.state === 'ok') {
    return r.data && r.data.stand === 'local-triage' ? { state: 'ours', status: r.data } : { state: 'foreign' };
  }
  if (r.state === 'bad') return { state: 'foreign' };
  if (r.state === 'free' || r.state === 'busy') return { state: r.state };
  return new Promise((resolve) => { // прочие ошибки соединения: слушает ли кто-то порт вообще
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.setTimeout(1000, () => { socket.destroy(); resolve({ state: 'free' }); });
    socket.once('connect', () => { socket.destroy(); resolve({ state: 'foreign' }); });
    socket.once('error', () => resolve({ state: 'free' }));
  });
}

/** Опрос служебного порта с ожиданием, пока держатель занят (до 30 с): «занят» не принимается за чужую программу. */
async function settledStatus(port, ms = 30000) {
  const deadline = Date.now() + ms;
  let now = await getStatus(port);
  while (now.state === 'busy' && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    now = await getStatus(port);
  }
  return now;
}

const AGAIN = Symbol('again'); // стенд в другом окне закрылся – запуск начинается заново

function openBrowser(url) {
  const [cmd, args] = process.platform === 'win32' ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
    : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => {});
    child.unref();
  } catch { /* браузер не открылся – адрес напечатан */ }
}

function shouldOpen(opts) {
  return opts.open && !process.env.CI;
}

/** Стенд уже запущен в другом окне: ждать готовности – установку до 15 минут, запуск до 2 минут. Каждый ответ
 * сверяется с тем стендом, которого ждём (служебная папка и идентификатор): владелец порта мог смениться. */
async function waitOther(port, expect) {
  let deadline = Date.now() + WAIT_INSTALL_MS;
  let last = '';
  let closing = Boolean(expect.stopping); // первый ответ уже был «останавливается»
  while (Date.now() < deadline) {
    const now = await settledStatus(port);
    if (now.state === 'busy') continue;
    if (closing && now.state === 'free') return AGAIN; // дождались закрытия – запускаемся сами
    if (now.state !== 'ours' || !sameStand(now.status, expect)) {
      throw new paths.StandError('Стенд в другом окне остановился или сменился. Запустите стенд снова.');
    }
    const { phase, url, message } = now.status;
    if (phase === 'failed') throw new paths.StandError(`Стенд в другом окне не запустился: ${message || 'подробности – в том окне'}.`);
    // готовность держателя – и ответ самого приложения: база могла пропасть после первой готовности (ревью круга 6)
    const appOk = phase === 'ready' && url && !now.status.stopping &&
      (await getJson(now.status.app_port, '/healthz', 3000).then((r) => r.state === 'ok' && r.data &&
        ['ok', 'hub_write_paused'].includes(r.data.status) &&
        // на порту – приложение именно этого стенда: токен запуска совпадает (ревью круга 10)
        Boolean(now.status.app_token) && r.data.stand && r.data.stand.token === now.status.app_token));
    if (appOk) {
      if (expect.port && now.status.app_port !== expect.port) {
        throw new paths.StandError(`Стенд в другом окне работает на порту ${now.status.app_port}, а --port ${expect.port} ` +
          'действует только при новом запуске. Закройте окно стенда и запустите команду снова.');
      }
      return url;
    }
    const shown = now.status.stopping || phase === 'stopping' ? 'stopping' : phase;
    if (shown !== last) {
      const text = { installing: 'Стенд в другом окне ещё устанавливается – жду…',
        stopping: 'Стенд в другом окне останавливается – жду, пока он закроется, и запущу его снова…',
        restarting: 'Стенд в другом окне перезапускает приложение – жду…' }[shown] || 'Стенд в другом окне запускается – жду…';
      console.log(text);
      if (shown !== 'installing') deadline = Math.min(deadline, Date.now() + WAIT_START_MS);
      closing = shown === 'stopping';
      last = shown;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new paths.StandError('Стенд в другом окне не стал готов вовремя: посмотрите сообщения в том окне.');
}

function portBusy(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.setTimeout(800, () => { socket.destroy(); resolve(false); });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
}

async function doctor(home, codeDir, lockPort, local = false) {
  const margin = paths.pathMargin(codeDir);
  console.log(`Стенд ${PKG.version}, Node ${process.version}, ${process.platform}-${process.arch}`);
  try { console.log(`PostgreSQL: пакет ${pg.platformPackage()} ${pg.PACKAGE_VERSION}`); } catch (e) { console.log(e.message); }
  console.log(`Служебная папка: ${home}\nПапка кода: ${margin.path} (запас длины пути – ${margin.margin} знаков)`);
  console.log(`Служебный порт стенда: ${lockPort}`);
  let saved = {};
  try { saved = JSON.parse(fs.readFileSync(path.join(home, 'stand.json'), 'utf8')); } catch { saved = {}; }
  for (const [what, port] of [['базы', saved.pg_port], ['приложения', saved.app_port]]) {
    if (port) console.log(`Порт ${what} из прошлого запуска: ${port} (${(await portBusy(port)) ? 'сейчас занят' : 'сейчас свободен'})`);
  }
  try {
    const stat = fs.statfsSync(home);
    console.log(`Свободно на диске служебной папки: ${Math.round((stat.bavail * stat.bsize) / 2 ** 30)} ГБ (нужно около 2 ГБ)`);
  } catch { /* statfs нет – пропускаем */ }
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: 11434, path: '/api/version', timeout: 2000 }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        let version = '';
        try { version = res.statusCode === 200 ? String(JSON.parse(body).version || '') : ''; } catch { version = ''; }
        // ответ любого HTTP-сервиса – не Ollama: нужен успешный /api/version с версией (ревью круга 7)
        console.log(version ? `Ollama на этом компьютере отвечает (версия ${version}).${local ? ' Внешние провайдеры выключены (--local-only).' : ''}`
          : `На порту 11434 отвечает не Ollama (HTTP ${res.statusCode}).`);
        resolve();
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', () => {
      console.log('Ollama на этом компьютере (127.0.0.1:11434) не отвечает. ' + (local
        ? 'Внешние провайдеры выключены (--local-only); остаются серверы моделей в локальной сети с подтверждённым адресом.'
        : 'Серверы моделей в локальной сети и внешние провайдеры – по настройкам профиля.'));
      resolve();
    });
  });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { console.log(HELP); return 0; }
  if (opts.version) { console.log(PKG.version); return 0; }
  pg.platformPackage(); // Windows на ARM64 и прочие платформы – отказ до установки
  const resolved = paths.resolveHome({ override: opts.home });
  const home = resolved.home;
  // без --code-dir – папка, записанная стендом при первом запуске (раздел 3.2: потом она не меняется)
  // привязку знает кластер, где бы он ни был (pg/data, pg/next, копия переключения), затем stand.json – как у держателя
  const bound = binding.current(home);
  const saved = bound ? bound.path : '';
  const codeDir = paths.resolveCodeDir({ override: opts.codeDir || saved });
  const lockPort = paths.lockPortOf(home);
  if (resolved.how !== 'as-is') {
    console.log(`Путь ${resolved.requested} содержит буквы не из латиницы: служебная папка стенда – ${home}.`);
  }
  if (opts.where) {
    console.log(`Служебная папка: ${home}\nПапка кода: ${codeDir}\nЖурналы: ${path.join(home, 'logs')}`);
    return 0;
  }
  if (opts.doctor) { await doctor(home, codeDir, lockPort, Boolean(opts.local)); return 0; }
  const appVersion = appVersionOf(PKG.version);
  // явной считается только папка из ключа: без него окно присоединяется к папке работающего стенда (круг 7)
  const ctx = { lockPort, home, codeDir, appVersion, opts, explicitCodeDir: Boolean(opts.codeDir) };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const other = await settledStatus(lockPort);
    const code = other.state === 'free' ? await runHolder(ctx) : await joinOther(other, ctx);
    if (code !== AGAIN) return code;
  }
  console.log('Стенд в другом окне несколько раз закрывался и открывался заново. Запустите стенд ещё раз.');
  return 1;
}

const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK'];

async function runHolder(ctx) {
  const { lockPort, home, codeDir, appVersion, opts } = ctx;
  let build = {};
  try { build = JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, 'npm', 'build.json'), 'utf8')); } catch { build = {}; }
  const supervisorOpts = { home, codeDir, packageDir: PACKAGE_DIR, appVersion, lockPort, port: opts.port, local: opts.local,
    newDatabase: opts.newDatabase, reinstall: opts.reinstall, build };
  const child = spawn(process.execPath, [path.join(__dirname, 'lib', 'supervisor.js'), JSON.stringify(supervisorOpts)],
    { cwd: home, detached: true, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.on('error', () => {});
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    console.log('\nОстанавливаю стенд…');
    try { child.stdin.end(); } catch { /* держатель уже вышел */ }
  };
  for (const sig of SIGNALS) {
    try { process.on(sig, stop); } catch { /* сигнала нет на платформе */ }
  }
  readline.createInterface({ input: child.stdout }).on('line', (line) => {
    if (line.startsWith('@@ready ')) {
      const url = line.slice(8).trim();
      if (shouldOpen(opts)) openBrowser(url);
      console.log(`\nСтенд открыт: ${url}\nОстановить – Ctrl+C в этом окне или закрыть окно.${os.EOL}`);
    } else if (!line.startsWith('@@')) {
      console.log(line);
    }
  });
  readline.createInterface({ input: child.stderr }).on('line', (line) => console.error(line));
  const code = await new Promise((resolve) => child.on('exit', (exit) => resolve(exit === null ? 1 : exit)));
  if (code === 3 && !stopping) {
    // два запуска одновременно: служебный порт успел занять другой держатель – ждать его, как при втором запуске;
    // Ctrl+C теперь обычный выход окна: своего стенда здесь нет
    for (const sig of SIGNALS) process.removeListener(sig, stop);
    return joinOther(await settledStatus(lockPort), ctx);
  }
  return code;
}

/** Ответ служебного порта – тот же стенд: папки, версия, режим и идентификатор (на каждом опросе, ревью круга 3). */
function sameCodeDir(s, codeDir) {
  // работающий держатель сообщает физический путь, проверенный при его запуске: перенацеленная ссылка – другая папка
  return s.code_dir_real ? s.code_dir_real === paths.canonical(codeDir) : paths.canonical(s.code_dir || '') === paths.canonical(codeDir);
}

function sameStand(s, expect) {
  return paths.canonical(s.home || '') === paths.canonical(expect.home) && (!expect.id || s.id === expect.id) &&
    s.version === expect.version && s.mode === expect.mode && sameCodeDir(s, expect.codeDir);
}

/** Порт замка уже занят: тот же стенд – дождаться и открыть браузер; другой стенд или программа – сообщение. */
async function joinOther(other, { lockPort, home, codeDir, appVersion, opts, explicitCodeDir }) {
  if (other.state === 'free') return AGAIN; // держатель другого окна только что вышел
  if (other.state === 'busy') {
    console.log(`Служебный порт стенда ${lockPort} не отвечает: стенд в другом окне занят долгой операцией. Подождите и ` +
      'запустите стенд снова.');
    return 1;
  }
  if (other.state === 'ours') {
    const s = other.status;
    const mode = opts.local ? 'local-only' : 'external';
    if (paths.canonical(s.home || '') !== paths.canonical(home)) {
      console.log(`Служебный порт ${lockPort} занят стендом с другой служебной папкой (${s.home}). Запустите этот стенд с ` +
        'другой служебной папкой (--home) или закройте окно того стенда.');
      return 1;
    }
    if (s.version !== appVersion || s.mode !== mode) {
      console.log(`Работает версия ${s.version} в режиме ${s.mode}. Закройте её окно и запустите снова.`);
      return 1;
    }
    // папку кода выбирает первый запуск: без --code-dir окно присоединяется к той, что у работающего стенда
    const wanted = explicitCodeDir ? codeDir : s.code_dir || codeDir;
    if (!sameCodeDir(s, wanted)) {
      console.log(`Папка кода этого стенда – ${s.code_dir}, сменить её нельзя. Запустите стенд без --code-dir; другая папка ` +
        'кода – это другой стенд (ключ --home).');
      return 1;
    }
    // --port: пока приложение не поднято (app_port 0), порт сверяется в готовности
    // --port сверяется только в готовности (waitOther): при запуске и перезапуске порт приложения ещё не окончателен
    const unused = [opts.newDatabase && '--new-database', opts.reinstall && '--reinstall'].filter(Boolean);
    if (unused.length) {
      console.log(`Стенд уже работает в другом окне, а ${unused.join(', ')} ${unused.length === 1 ? 'действует' : 'действуют'} только при новом запуске. Закройте окно ` +
        'стенда и запустите команду снова.');
      return 1;
    }
    const url = await waitOther(lockPort, { home, id: s.id, version: appVersion, mode, codeDir: wanted,
      stopping: Boolean(s.stopping || s.phase === 'stopping'), port: opts.portGiven ? opts.port : 0 });
    if (url === AGAIN) return AGAIN;
    console.log(`Стенд уже работает в другом окне: ${url}`);
    if (shouldOpen(opts)) openBrowser(url);
    return 0;
  }
  console.log(`Служебный порт стенда ${lockPort} занят другой программой. Запустите стенд с другой служебной папкой: ` +
    'npx local-triage --home <папка>.');
  return 1;
}

main().then((code) => process.exit(code), (error) => {
  console.error(error instanceof paths.StandError ? error.message : `Сбой стенда: ${error && error.stack ? error.stack : error}`);
  process.exit(1);
});
