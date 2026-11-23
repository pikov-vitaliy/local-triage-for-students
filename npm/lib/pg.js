'use strict';
// PostgreSQL учебного стенда (раздел 3.4 плана): свой цикл жизни сервера на бинарниках пакета @embedded-postgres.
// Сам пакет embedded-postgres не используется: его остановка на Windows – taskkill /f /t, пароль кладётся в TEMP,
// сервер запускается напрямую, а не через pg_ctl. Аргументы вызовов – по таблице плана; тесты проверяют массивы.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fsx = require('./fsx');
const { spawnSync } = require('node:child_process');

const { StandError } = require('./paths');
const { t } = require('./lang');

const PG_MAJOR = '17';
const PG_RELEASE = '17.12';
const PACKAGE_VERSION = '17.12.0-beta.19';
const PLATFORM_PACKAGES = {
  'win32-x64': '@embedded-postgres/windows-x64',
  'linux-x64': '@embedded-postgres/linux-x64',
  'linux-arm64': '@embedded-postgres/linux-arm64',
  'darwin-arm64': '@embedded-postgres/darwin-arm64',
  'darwin-x64': '@embedded-postgres/darwin-x64',
};
const CLUSTER_FILES = ['PG_VERSION', path.join('global', 'pg_control'), 'postgresql.conf'];
const CONF_NAME = 'local-triage.conf';
const INCLUDE_LINE = `include_if_exists = '${CONF_NAME}'`;
const LOG_KEEP_DAYS = 14;

function platformPackage(platform = process.platform, arch = process.arch) {
  if (platform === 'win32' && arch === 'arm64') {
    throw new StandError(t('Windows на ARM64 стенд не поддерживает: для неё нет ни сборки PostgreSQL, ни колеса psycopg-binary.', 'The stand does not support Windows on ARM64: there is neither a PostgreSQL build nor a psycopg-binary wheel for it.'));
  }
  const name = PLATFORM_PACKAGES[`${platform}-${arch}`];
  if (!name) throw new StandError(t(`Платформа ${platform}-${arch} не поддерживается: есть сборки для Windows x64, Linux x64 и arm64, macOS.`, `Platform ${platform}-${arch} is not supported: builds exist for Windows x64, Linux x64 and arm64, macOS.`));
  return name;
}

/** Папка native платформенного пакета – ищется от папки пакета стенда (в кэше npx – рядом с ним). */
function nativeDir(packageDir, platform = process.platform, arch = process.arch) {
  const name = platformPackage(platform, arch);
  // package.json пакета закрыт полем exports, поэтому не require.resolve, а обход node_modules вверх от папки пакета:
  // в кэше npx платформенный пакет лежит рядом с самим стендом
  for (let dir = path.resolve(packageDir); ; dir = path.dirname(dir)) {
    const pkgDir = path.join(dir, 'node_modules', ...name.split('/'));
    const native = path.join(pkgDir, 'native');
    let found = '';
    try { found = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version || ''; } catch { found = ''; }
    // только закреплённая версия: пакет другой версии выше по дереву не подменяет PostgreSQL стенда (ревью круга 9)
    if (found === PACKAGE_VERSION && fs.existsSync(path.join(native, 'bin'))) return native;
    if (path.dirname(dir) === dir) break;
  }
  // npm cache clean дерево npx не трогает; удалить можно только дерево npx, а не проект пользователя (ревью круга 8)
  // путь для удаления не подсказывается: вычисленная папка может оказаться проектом студента (ревью кругов 8–10)
  throw new StandError(t(`Не найден пакет ${name}: установка npm неполная (платформенный пакет не скачался). Запуск через ` +
    'npx: очистите кэш npx командой npm cache npx rm --force (npm 11) и запустите стенд снова. Из клона или проекта: ' +
    'npm install без --omit=optional.', `Package ${name} not found: the npm installation is incomplete (the platform package was not downloaded). When running via ` +
    'npx: clear the npx cache with npm cache npx rm --force (npm 11) and start the stand again. From a clone or project: ' +
    'npm install without --omit=optional.'));
}

function exe(binDir, name, platform = process.platform) {
  return path.join(binDir, 'bin', platform === 'win32' ? `${name}.exe` : name);
}

// ---------------------------------------------------------------- аргументы вызовов (таблица раздела 3.4)

function initdbArgs(dataDir, pwfile) {
  return ['-D', dataDir, '-U', 'triage', `--pwfile=${pwfile}`, '--auth=scram-sha-256', '-E', 'UTF8', '--locale=C',
    '--locale-provider=builtin', '--builtin-locale=C.UTF-8'];
}

function syncOnlyArgs(dataDir) {
  return ['--sync-only', '-D', dataDir];
}

function startArgs(dataDir, logFile) {
  return ['start', '-D', dataDir, '-l', logFile, '-w', '-t', '60'];
}

function statusArgs(dataDir) {
  return ['status', '-D', dataDir];
}

function stopArgs(dataDir, mode = 'fast') {
  return ['stop', '-D', dataDir, '-m', mode, '-w', '-t', '30'];
}

// ---------------------------------------------------------------- бинарники

/**
 * Копия бинарников из платформенного пакета в pg/bin-17.12: во временную папку без разыменования ссылок, затем каждая
 * цель из pg-symlinks.json (Linux) пересоздаётся относительной ссылкой, затем атомарное переименование. Повторный
 * запуск поверх готовой папки ничего не меняет. Ответ – true, если папка создана этим вызовом.
 */
/** Копия бинарников полная: каждый файл платформенного пакета (все вложенные папки: bin, lib, share…) есть в копии
 * (ревью кругов 4–5: без pg_ctl или share/postgres.bki стенд не поднимался, хотя пакет был цел). */
function binariesComplete(source, binDir) {
  const walk = (rel) => {
    let entries;
    try { entries = fs.readdirSync(path.join(source, rel), { withFileTypes: true }); } catch { return false; }
    for (const entry of entries) {
      const child = rel ? path.join(rel, entry.name) : entry.name;
      if (entry.isDirectory()) {
        if (!walk(child)) return false;
      } else {
        // файл на месте и того же размера (усечённый файл – не копия); ссылка – раскрывается
        let src;
        let dst;
        try { src = fs.statSync(path.join(source, child)); dst = fs.statSync(path.join(binDir, child)); } catch { return false; }
        // размер и время изменения (копия сохраняет время источника, допуск 2 мс на округление файловой системы);
        // время разошлось – решает содержимое (ревью кругов 7–8)
        if (!dst.isFile() || dst.size !== src.size) return false;
        if (Math.abs(dst.mtimeMs - src.mtimeMs) > 2) {
          try {
            if (!fs.readFileSync(path.join(binDir, child)).equals(fs.readFileSync(path.join(source, child)))) return false;
          } catch { return false; }
        }
      }
    }
    return true;
  };
  if (!fs.existsSync(path.join(source, 'bin')) || !walk('')) return false;
  // ссылки из pg-symlinks.json (Linux) создаются при копировании: каждая должна раскрываться в файл
  let links = [];
  try { links = JSON.parse(fs.readFileSync(path.join(source, 'pg-symlinks.json'), 'utf8')); } catch { links = []; }
  for (const link of Array.isArray(links) ? links : []) {
    const strip = (p) => String(p).replace(/^native[\\/]/, '');
    const target = path.join(binDir, strip(link.target));
    const expected = path.relative(path.dirname(target), path.join(binDir, strip(link.source)));
    try {
      if (fs.readlinkSync(target) !== expected || !fs.statSync(target).isFile()) return false; // цель ссылки – та самая
    } catch { return false; }
  }
  return true;
}

/** Мажорная версия каталога – до любого переноса или удаления (§3.4): чужая версия – отказ, каталог не тронут. */
function checkMajor(dir, required = false) {
  let major;
  try {
    major = fs.readFileSync(path.join(dir, 'PG_VERSION'), 'utf8').trim();
  } catch (error) {
    // версии нет у незаконченной копии – её можно убрать; каталог, который станет рабочим, обязан быть целым
    if (error.code === 'ENOENT' && !required) return;
    throw new StandError(t(`Версию PostgreSQL каталога ${dir} прочитать не удалось (${error.code}): стенд его не меняет, ` +
      'оба каталога и метки оставлены как были. Пришлите журнал преподавателю.', `Could not read the PostgreSQL version of directory ${dir} (${error.code}): the stand does not change it, ` +
      'both directories and the markers are left as they were. Send the log to your teacher.'));
  }
  if (required) checkCluster(dir);
  if (major !== PG_MAJOR) {
    throw new StandError(t(`Каталог ${dir} создан PostgreSQL ${major}, а в стенде – ${PG_RELEASE}: стенд его не меняет. ` +
      'Запустите версию стенда, которая создала эту базу.', `Directory ${dir} was created by PostgreSQL ${major}, but the stand has ${PG_RELEASE}: the stand does not change it. ` +
      'Run the stand version that created this database.'));
  }
}

function installBinaries(source, binDir, platform = process.platform, { force = false } = {}) {
  if (!force && binariesComplete(source, binDir)) return false; // --reinstall – пересборка копии в любом случае
  fs.mkdirSync(path.dirname(binDir), { recursive: true });
  fsx.removeLeftovers(path.dirname(binDir), path.basename(binDir)); // остатки прерванных копий с любым номером процесса
  const tmp = `${binDir}.tmp-${process.pid}`;
  fs.cpSync(source, tmp, { recursive: true, dereference: false, verbatimSymlinks: true, errorOnExist: false, preserveTimestamps: true });
  let links = [];
  try {
    links = JSON.parse(fs.readFileSync(path.join(source, 'pg-symlinks.json'), 'utf8'));
  } catch {
    links = [];
  }
  for (const link of Array.isArray(links) ? links : []) {
    // пути в pg-symlinks.json – от корня пакета: native/lib/… – их часть после native/ ложится в копию
    const strip = (p) => String(p).replace(/^native[\\/]/, '');
    const target = path.join(tmp, strip(link.target));
    const sourcePath = path.join(tmp, strip(link.source));
    fs.rmSync(target, { force: true });
    fs.symlinkSync(path.relative(path.dirname(target), sourcePath), target);
  }
  if (platform !== 'win32') {
    for (const name of fs.readdirSync(path.join(tmp, 'bin'))) fs.chmodSync(path.join(tmp, 'bin', name), 0o755);
  }
  // неполная прежняя папка – в сторону, новая – на место, прежняя удаляется последней
  const old = `${binDir}.old-${process.pid}`;
  if (fs.existsSync(binDir)) fsx.renameSync(binDir, old);
  try {
    fsx.renameSync(tmp, binDir);
  } catch (error) {
    if (fs.existsSync(old) && !fs.existsSync(binDir)) fs.renameSync(old, binDir);
    throw error;
  }
  try { fsx.rmSync(old, { recursive: true, force: true }, 5000); } catch { /* удалится при следующей установке */ }
  return true;
}

// ---------------------------------------------------------------- пароль и кластер

/**
 * Пароль базы: до первого initdb – 24 случайных байта в base64url одной строкой (так его читает --pwfile – первая
 * строка файла, Д17), только для пользователя. Файл появляется сразу целым: временный файл и переименование. При
 * существующем кластере – прежний; кластер есть, а файла нет или он повреждён – отдельная ошибка. Кластера нет, а
 * файл повреждён (обрыв первой установки) – пароль создаётся заново.
 */
function ensurePassword(secretsDir, clusterExists) {
  const file = path.join(secretsDir, 'pg.pw');
  if (fs.existsSync(file)) {
    const value = fs.readFileSync(file, 'utf8').split(/\r?\n/)[0].trim();
    if (/^[A-Za-z0-9_-]{16,}$/.test(value)) {
      restrictToUser(file);
      return { file, password: value, created: false };
    }
    if (clusterExists) throw new StandError(t(`Файл пароля базы ${file} повреждён, а кластер на месте: к базе не подключиться.`, `The database password file ${file} is damaged, but the cluster is in place: cannot connect to the database.`));
    fs.rmSync(file, { force: true });
  } else if (clusterExists) {
    throw new StandError(t(`Кластер базы на месте, а файла пароля ${file} нет: без него к базе не подключиться. Верните файл ` +
      'из копии служебной папки или начните с новой базы ключом --new-database (прежняя база останется в pg/backups).', `The database cluster is in place, but the password file ${file} is missing: without it the database cannot be reached. ` +
      'Restore the file from a copy of the stand home folder or start with a new database using --new-database (the previous database stays in pg/backups).'));
  }
  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  restrictToUser(secretsDir);
  const password = crypto.randomBytes(24).toString('base64url');
  fsx.writeSecret(file, `${password}\n`, restrictToUser);
  return { file, password, created: true };
}

/** Файл пароля читается: формат верен. Не бросает – для решения, можно ли начать заново. */
function passwordReadable(secretsDir) {
  try {
    return /^[A-Za-z0-9_-]{16,}$/.test(fs.readFileSync(path.join(secretsDir, 'pg.pw'), 'utf8').split(/\r?\n/)[0].trim());
  } catch {
    return false;
  }
}

/**
 * На Windows mode 0600 не действует, а папка может наследовать чтение для группы Users (ревью сборки А, В11): у папки
 * секретов наследование снимается, полный доступ – только текущему пользователю. Не вышло – отказ до записи пароля.
 */
function restrictToUser(target, platform = process.platform) {
  if (platform !== 'win32') {
    try { fs.chmodSync(target, fs.statSync(target).isDirectory() ? 0o700 : 0o600); } catch { /* проверка ниже */ }
    const mode = fs.statSync(target).mode;
    if (mode & 0o077) {
      throw new StandError(t(`Права ${target} не ограничить владельцем (сейчас ${(mode & 0o777).toString(8)}): файл принадлежит ` +
        'другому пользователю? Исправьте владельца или права и запустите стенд снова.', `Cannot restrict ${target} to its owner (currently ${(mode & 0o777).toString(8)}): does the file belong to ` +
        'another user? Fix the owner or permissions and start the stand again.'));
    }
    return;
  }
  // точный список доступа: защищён от наследования и содержит только текущего пользователя (ревью, круг 2)
  const script = [
    '$ErrorActionPreference = "Stop"',
    '$item = Get-Item -LiteralPath $env:LT_TARGET -Force',
    '$acl = $item.GetAccessControl()',
    '$acl.SetAccessRuleProtection($true, $false)',
    'foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }',
    '$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$flags = if ($item.PSIsContainer) { "ContainerInherit, ObjectInherit" } else { "None" }',
    '$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, "FullControl", $flags, "None", "Allow")))',
    '$item.SetAccessControl($acl)',
    '$left = @((Get-Item -LiteralPath $env:LT_TARGET -Force).GetAccessControl().Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -ne $me })',
    'if ($left.Count) { exit 3 }',
  ].join('; ');
  const run = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { windowsHide: true, encoding: 'latin1', timeout: 60000, env: { ...process.env, LT_TARGET: target } });
  if (run.status !== 0) {
    throw new StandError(t(`Не удалось закрыть ${target} от других пользователей (код ${run.status}). Укажите служебную папку в ` +
      'своём профиле ключом --home.', `Could not restrict ${target} from other users (code ${run.status}). Choose a stand home folder in ` +
      'your own profile using --home.'));
  }
}

/** Каталог кластера пригоден: все обязательные файлы есть, мажорная версия совпадает с бинарниками. */
function checkCluster(dataDir) {
  // обязательные файлы – обычные файлы, читаются; pg_control – не короче своей структуры (296 байт): обнулённая или
  // усечённая копия не ставится на место рабочей базы (ревью круга 7)
  const bad = CLUSTER_FILES.filter((name) => {
    try {
      const st = fs.statSync(path.join(dataDir, name));
      if (!st.isFile()) return true;
      fs.closeSync(fs.openSync(path.join(dataDir, name), 'r'));
      return name === path.join('global', 'pg_control') && st.size < 296;
    } catch {
      return true;
    }
  });
  if (bad.length) {
    throw new StandError(t(`Каталог базы ${dataDir} неполный или повреждён (${bad.join(', ')}). Он не удаляется автоматически; ` +
      'перенесите его в сторону и запустите стенд с ключом --new-database.', `Database directory ${dataDir} is incomplete or damaged (${bad.join(', ')}). It is not deleted automatically; ` +
      'move it aside and start the stand with --new-database.'));
  }
  const major = fs.readFileSync(path.join(dataDir, 'PG_VERSION'), 'utf8').trim();
  if (major !== PG_MAJOR) {
    throw new StandError(t(`Каталог базы ${dataDir} создан PostgreSQL ${major}, а в стенде – ${PG_RELEASE}. Обновления ` +
      'мажорной версии в стенде нет: запустите версию стенда, которая создала базу.', `Database directory ${dataDir} was created by PostgreSQL ${major}, but the stand has ${PG_RELEASE}. The stand ` +
      'has no major version upgrade: run the stand version that created the database.'));
  }
}

function confText(port) {
  return ['# Файл пишет учебный стенд перед каждым запуском сервера: правки вручную пропадут.',
    "listen_addresses = '127.0.0.1'",
    `port = ${Number(port)}`,
    '# журнал без данных: ни текста ошибочных запросов, ни DETAIL и CONTEXT (раздел 3.4 плана стенда)',
    'log_min_messages = log',
    'log_min_error_statement = panic',
    'log_error_verbosity = terse',
    'log_statement = none',
    'log_min_duration_statement = -1',
    ''].join('\n');
}

/** Перед каждым запуском: local-triage.conf переписывается, строка include в postgresql.conf – одна. */
function writeConf(dataDir, port) {
  const conf = path.join(dataDir, 'postgresql.conf');
  const text = fs.readFileSync(conf, 'utf8');
  if (!text.split(/\r?\n/).some((line) => line.trim() === INCLUDE_LINE)) {
    fs.appendFileSync(conf, `${text.endsWith('\n') ? '' : '\n'}${INCLUDE_LINE}\n`);
  }
  const tmp = path.join(dataDir, `${CONF_NAME}.tmp`);
  fs.writeFileSync(tmp, confText(port));
  fsx.renameSync(tmp, path.join(dataDir, CONF_NAME));
}

/** Пока сервер остановлен: postgres.log – в файл с датой, файлы старше 14 дней удаляются. */
function rotateLog(logsDir, now = new Date()) {
  fs.mkdirSync(logsDir, { recursive: true });
  const current = path.join(logsDir, 'postgres.log');
  if (fs.existsSync(current)) {
    const stamp = now.toISOString().replace(/[:T]/g, '-').slice(0, 19);
    try {
      fs.renameSync(current, path.join(logsDir, `postgres-${stamp}.log`));
    } catch (error) {
      // журнал держит другая программа: сервер пишет в новый файл, прежний не трогается
      if (!fsx.BUSY.has(error.code)) throw error;
      return path.join(logsDir, `postgres-${stamp}-run.log`);
    }
  }
  pruneLogs(logsDir, now);
  return current;
}

function pruneLogs(logsDir, now = new Date()) {
  const edge = now.getTime() - LOG_KEEP_DAYS * 86400000;
  for (const name of fs.readdirSync(logsDir)) {
    // только свои журналы по имени: чужие *.log в папке logs не трогаются (проверка агентами, круг 7)
    if (!/^(?:supervisor|app|initdb|postgres)-[\w.-]+\.log$/.test(name)) continue;
    const file = path.join(logsDir, name);
    try {
      if (fs.statSync(file).mtimeMs < edge) fs.unlinkSync(file);
    } catch { /* файл занят – удалится в следующий раз */ }
  }
}

module.exports = {
  PG_MAJOR, PG_RELEASE, PACKAGE_VERSION, PLATFORM_PACKAGES, CONF_NAME, INCLUDE_LINE, platformPackage, nativeDir, exe,
  initdbArgs, syncOnlyArgs, startArgs, statusArgs, stopArgs, installBinaries, ensurePassword, passwordReadable, restrictToUser,
  checkCluster, checkMajor, confText, binariesComplete,
  writeConf, rotateLog, pruneLogs,
};
