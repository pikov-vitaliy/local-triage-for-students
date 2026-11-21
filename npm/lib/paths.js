'use strict';
// Папки учебного стенда (раздел 3.2 плана): служебная папка с базой, Python и журналами и видимая папка кода.
//
// На Windows путь служебной папки – только ASCII: кириллица в пути ломает initdb при кодовой странице 1252 (проба
// 20.11). Не ASCII – короткое имя 8.3; если и оно не ASCII – запасной корень %SystemDrive%\local-triage-<хеш пути>
// (Д20: у двух разных папок – разные корни); не вышло – отказ с подсказкой --home. Папка кода может быть с
// кириллицей: её читает Python, PostgreSQL к ней не обращается.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ASCII = /^[\x20-\x7e]*$/;
const LOCK_PORT_MIN = 49152;
const LOCK_PORT_MAX = 65535;
const MAX_PATH = 259; // без LongPathsEnabled Python на Windows не открывает файл с путём длиннее
const LONGEST_EXAMPLE_PATH = 162; // самый длинный относительный путь среди файлов примеров каталога (Juice Shop)
const EXAMPLE_DIR = 'examples\\juice-shop-0000000\\'; // вид папки примера в папке кода: <id>-<commit7>

class StandError extends Error {}

function isAscii(text) {
  return ASCII.test(text);
}

function defaultHome(env, platform, homedir) {
  if (platform === 'win32') {
    return path.win32.join(env.LOCALAPPDATA || path.win32.join(homedir, 'AppData', 'Local'), 'local-triage');
  }
  const xdg = env.XDG_DATA_HOME;
  return path.posix.join(xdg && path.posix.isAbsolute(xdg) ? xdg : path.posix.join(homedir, '.local', 'share'),
    'local-triage');
}

function defaultCodeDir(env, platform, homedir) {
  return platform === 'win32' ? path.win32.join(env.USERPROFILE || homedir, 'local-triage')
    : path.posix.join(homedir, 'local-triage');
}

function hash8(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 8);
}

function fallbackRoot(env, requested) {
  const drive = String(env.SystemDrive || env.SYSTEMDRIVE || 'C:').replace(/[\\/]+$/, '');
  return `${drive}\\local-triage-${hash8(requested.toLowerCase())}`;
}

function shortName(dir) {
  // короткое имя 8.3 существующей папки: cmd раскрывает %~sI; при выключенных 8.3 вернётся длинное имя
  const run = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/c', `for %I in ("${dir}") do @echo %~sI`],
    { windowsVerbatimArguments: true, windowsHide: true, encoding: 'latin1', timeout: 15000 });
  const out = String(run.stdout || '').trim().split(/\r?\n/).pop() || '';
  return run.status === 0 && out ? out : '';
}

function writable(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const probe = path.join(dir, `.probe-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
    fs.writeFileSync(probe, 'ok', { flag: 'wx' }); // чужой файл с тем же именем не заменяется
    fs.unlinkSync(probe);
    return true;
  } catch {
    return false;
  }
}

/**
 * Служебная папка: --home, LOCAL_TRIAGE_HOME или место по умолчанию. Возвращает {requested, home, how}: how – as-is,
 * short (короткое имя 8.3) или fallback (запасной корень). Папка создаётся.
 */
function resolveHome({ override = '', env = process.env, platform = process.platform, homedir = os.homedir(),
  short = shortName } = {}) {
  const join = platform === 'win32' ? path.win32 : path.posix;
  const requested = join.resolve(override || env.LOCAL_TRIAGE_HOME || defaultHome(env, platform, homedir));
  if (platform !== 'win32' || isAscii(requested)) {
    if (!writable(requested)) throw new StandError(`Служебную папку ${requested} не создать: нет доступа. Укажите другую ключом --home.`);
    return { requested, home: requested, how: 'as-is' };
  }
  const existed = fs.existsSync(requested);
  if (writable(requested)) {
    const alias = short(requested);
    if (alias && isAscii(alias) && alias.toLowerCase() !== requested.toLowerCase()) {
      return { requested, home: alias, how: 'short' };
    }
    if (!existed) {
      try { fs.rmdirSync(requested); } catch { /* не пустая или занята – остаётся */ }
    }
  }
  const root = fallbackRoot(env, requested);
  if (writable(root)) return { requested, home: root, how: 'fallback' };
  throw new StandError(`В пути служебной папки ${requested} есть буквы не из латиницы, короткого имени нет, а запасную ` +
    `папку ${root} создать не удалось. Укажите папку из латинских букв ключом --home, например --home C:\\local-triage.`);
}

function resolveCodeDir({ override = '', env = process.env, platform = process.platform, homedir = os.homedir() } = {}) {
  const join = platform === 'win32' ? path.win32 : path.posix;
  return join.resolve(override || defaultCodeDir(env, platform, homedir));
}

/** Канонический путь: ссылки и короткие имена раскрыты, на Windows без учёта регистра и вида разделителей. */
function canonical(p, platform = process.platform) {
  const lib = platform === 'win32' ? path.win32 : path.posix;
  let real;
  try {
    real = fs.realpathSync.native(p);
  } catch {
    // папки ещё нет: раскрывается ближайший существующий предок (ссылка выше по пути учитывается, ревью круга 7)
    let head = lib.resolve(p);
    const tail = [];
    for (;;) {
      try {
        real = lib.join(fs.realpathSync.native(head), ...tail);
        break;
      } catch {
        const up = lib.dirname(head);
        if (up === head) { real = lib.resolve(p); break; }
        tail.unshift(lib.basename(head));
        head = up;
      }
    }
  }
  return platform === 'win32' ? real.replace(/\//g, '\\').toLowerCase() : real;
}

/** Служебный порт держателя стенда – замок, который держит ОС (раздел 3.5): хеш канонического пути служебной папки. */
function lockPortOf(home, platform = process.platform) {
  const digest = crypto.createHash('sha256').update(canonical(home, platform), 'utf8').digest();
  return LOCK_PORT_MIN + (digest.readUInt32BE(0) % (LOCK_PORT_MAX - LOCK_PORT_MIN + 1));
}

/** Запас длины пути до предела Windows для самого длинного файла примеров в папке кода (по каноническому пути). */
function pathMargin(codeDir, platform = process.platform) {
  let full;
  try {
    full = fs.realpathSync.native(codeDir);
  } catch {
    full = (platform === 'win32' ? path.win32 : path.posix).resolve(codeDir);
  }
  const used = full.length + 1 + EXAMPLE_DIR.length + LONGEST_EXAMPLE_PATH;
  return { path: full, used, limit: MAX_PATH, margin: MAX_PATH - used };
}

module.exports = {
  StandError, isAscii, defaultHome, defaultCodeDir, fallbackRoot, resolveHome, resolveCodeDir, canonical, lockPortOf,
  pathMargin, hash8, LOCK_PORT_MIN, LOCK_PORT_MAX, MAX_PATH, LONGEST_EXAMPLE_PATH,
};
