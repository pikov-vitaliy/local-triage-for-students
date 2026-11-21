'use strict';
// Окружение дочерних процессов стенда (разделы 3.3–3.5 плана).
//
// Приложению передаётся не копия окружения оболочки, а перечень: системные переменные, без которых не работают Python
// и сеть, плюс явные значения стенда. Унаследованные PGHOSTADDR, PGSERVICE, VIRTUAL_ENV, TRIAGE_MAINTENANCE,
// TRUSTED_HOSTS, LLM_EXTERNAL, OLLAMA_URL до приложения не доходят. initdb и pg_ctl получают тот же перечень без
// единой переменной PG*. Установка Python – окружение оболочки без переменных, которые меняют выбор интерпретатора
// и пакетов (VIRTUAL_ENV, CONDA_*, PYTHON*, PIP_* и UV_* кроме адреса индекса): прокси для скачивания проходят.

const WINDOWS_KEEP = ['SystemRoot', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'LOCALAPPDATA', 'APPDATA', 'COMPUTERNAME', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE'];
const POSIX_KEEP = ['PATH', 'HOME', 'USER', 'LANG', 'TZ'];
const BOTH_KEEP = ['SSL_CERT_FILE', 'SSL_CERT_DIR'];
const INDEX_VARS = ['UV_INDEX_URL', 'PIP_INDEX_URL'];

function lookup(env, name, platform) {
  if (platform !== 'win32') return Object.prototype.hasOwnProperty.call(env, name) ? name : undefined;
  return Object.keys(env).find((key) => key.toUpperCase() === name.toUpperCase());
}

/** Системные переменные из перечня – основа окружения приложения, initdb и pg_ctl. */
function systemEnv(env = process.env, platform = process.platform) {
  const out = {};
  for (const name of (platform === 'win32' ? WINDOWS_KEEP : POSIX_KEEP).concat(BOTH_KEEP)) {
    const key = lookup(env, name, platform);
    if (key !== undefined && env[key] !== undefined) out[name] = env[key];
  }
  if (platform !== 'win32') {
    for (const key of Object.keys(env)) if (key.startsWith('LC_')) out[key] = env[key];
  }
  return out;
}

function withoutPg(env) {
  const out = {};
  for (const [key, value] of Object.entries(env)) if (!key.toUpperCase().startsWith('PG')) out[key] = value;
  return out;
}

/** initdb и pg_ctl: перечень без PG*, временные файлы – в служебной папке. */
function pgToolEnv(tmpDir, env = process.env, platform = process.platform) {
  return { ...withoutPg(systemEnv(env, platform)), TEMP: tmpDir, TMP: tmpDir, TMPDIR: tmpDir };
}

/** Один явный набор libpq для служебных команд и приложения (раздел 3.4). */
function libpqEnv(port, password, database = 'triage') {
  return { PGHOST: '127.0.0.1', PGPORT: String(port), PGDATABASE: database, PGUSER: 'triage', PGPASSWORD: password,
    PGCONNECT_TIMEOUT: '10' };
}

/** Установка Python и зависимостей: окружение оболочки без переменных выбора интерпретатора и пакетов (Д16). */
function pythonInstallEnv(tmpDir, env = process.env) {
  const out = {};
  for (const [key, value] of Object.entries(env)) {
    const upper = key.toUpperCase();
    if (INDEX_VARS.includes(upper)) {
      out[upper] = value;
      continue;
    }
    if (upper === 'VIRTUAL_ENV' || upper.startsWith('CONDA') || upper.startsWith('PYTHON') || upper.startsWith('PIP_') ||
      upper.startsWith('UV_') || upper.startsWith('PG') || upper === '__PYVENV_LAUNCHER__') continue;
    out[key] = value;
  }
  return { ...out, UV_NATIVE_TLS: '1', TEMP: tmpDir, TMP: tmpDir, TMPDIR: tmpDir };
}

/** Окружение приложения: перечень и явные значения стенда (раздел 3.5). */
function appEnv({ dataDir, tmpDir, codeDir, codeReal = '', libpq, external, build = {}, token, env = process.env,
  platform = process.platform }) {
  return {
    ...withoutPg(systemEnv(env, platform)),
    DATA_DIR: dataDir, TMP_DIR: tmpDir, TEMP: tmpDir, TMP: tmpDir, TMPDIR: tmpDir,
    // приложению – проверенный физический путь: перенацеленная ссылка не подменяет код открытого проекта (ревью круга 6)
    REPOS_ROOT: codeReal || codeDir, REPOS_ROOT_HOST: codeDir, REPOS_ROOT_IS_DEMO: '0',
    ...libpq,
    TRIAGE_MAINTENANCE: '0',
    OLLAMA_URL: 'http://127.0.0.1:11434',
    DEFAULT_MODEL: 'gpt-oss:20b',
    LLM_EXTERNAL: external ? '1' : '0',
    LT_BUILD_COMMIT: String(build.commit || ''),
    LT_BUILD_DIRTY: build.dirty === true ? '1' : build.dirty === false ? '0' : '',
    LT_BUILD_TIME: String(build.time || ''),
    TRIAGE_STAND: 'npm',
    TRIAGE_STAND_TOKEN: token,
  };
}

module.exports = { systemEnv, withoutPg, pgToolEnv, libpqEnv, pythonInstallEnv, appEnv, WINDOWS_KEEP, POSIX_KEEP };
