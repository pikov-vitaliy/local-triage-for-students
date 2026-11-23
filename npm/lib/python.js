'use strict';
// Python стенда (раздел 3.3 плана): свой uv или uv в PATH; иначе системный Python 3.12 (venv и
// pip); иначе официальный установщик uv закреплённой версии в служебную папку, без правки PATH. Пути – абсолютные,
// зависимости – по хешам (npm/requirements.txt). Отметка installed.json – только после проверки импорта.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fsx = require('./fsx');

const { StandError } = require('./paths');
const { t } = require('./lang');
const { run, tail } = require('./proc');
const { writeJsonAtomic, readJson } = require('./stand');

const UV_VERSION = '0.11.19';
const PYTHON = '3.12';
const IMPORT_CHECK = 'import fastapi, uvicorn, psycopg, psycopg_pool, openpyxl, jinja2, multipart, pydantic';

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function venvPython(venv, platform = process.platform) {
  return platform === 'win32' ? path.join(venv, 'Scripts', 'python.exe') : path.join(venv, 'bin', 'python');
}

async function findUv(home, env) {
  const own = path.join(home, 'uv', process.platform === 'win32' ? 'uv.exe' : 'uv');
  for (const candidate of [own, 'uv']) {
    const probe = await run(candidate, ['--version'], { env, timeoutMs: 30000 });
    if (probe.code === 0) return candidate;
  }
  return '';
}

async function findSystemPython(env) {
  const tries = process.platform === 'win32' ? [['py', ['-3.12']], ['python3.12', []], ['python', []]]
    : [['python3.12', []], ['python3', []]];
  for (const [file, pre] of tries) {
    // путь – JSON с экранированием не-ASCII (кодовая страница консоли его не искажает); ensurepip – venv с pip создастся
    const probe = await run(file, [...pre, '-E', '-s', '-X', 'utf8', '-c',
      'import sys,json,venv,ensurepip;assert sys.version_info[:2]==(3,12);print(json.dumps(sys.executable))'],
      { env, timeoutMs: 30000 });
    if (probe.code === 0 && probe.stdout.trim()) {
      try { return JSON.parse(probe.stdout.trim().split(/\r?\n/).pop()); } catch { /* следующий вариант */ }
    }
  }
  return '';
}

async function installUv(home, env, say) {
  const dir = path.join(home, 'uv');
  fs.mkdirSync(dir, { recursive: true });
  const installEnv = { ...env, UV_INSTALL_DIR: dir, UV_UNMANAGED_INSTALL: dir, UV_NO_MODIFY_PATH: '1' };
  say(t(`Ставлю uv ${UV_VERSION} официальным установщиком в ${dir}…`, `Installing uv ${UV_VERSION} with the official installer into ${dir}…`));
  const result = process.platform === 'win32'
    ? await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      `irm https://astral.sh/uv/${UV_VERSION}/install.ps1 | iex`], { env: installEnv, timeoutMs: 600000 })
    : await run('sh', ['-c', `curl -LsSf https://astral.sh/uv/${UV_VERSION}/install.sh | sh`],
      { env: installEnv, timeoutMs: 600000, group: true });
  const own = path.join(dir, process.platform === 'win32' ? 'uv.exe' : 'uv');
  if (result.code !== 0 || !fs.existsSync(own)) {
    throw new StandError(t(`uv не установился (код ${result.code}). ${tail(result.stderr || result.stdout, 8)}\nПоставьте Python ` +
      '3.12 с python.org или uv вручную и запустите стенд снова.', `uv was not installed (code ${result.code}). ${tail(result.stderr || result.stdout, 8)}\nInstall Python ` +
      '3.12 from python.org or uv manually and start the stand again.'));
  }
  return own;
}

function failed(step, result) {
  return new StandError(t(`${step}: код ${result.code}.\n${tail(result.stderr || result.stdout, 15)}`, `${step}: code ${result.code}.\n${tail(result.stderr || result.stdout, 15)}`));
}

/**
 * Окружение Python для версии стенда: <служебная>/<версия>/venv. Готовое (отметка совпадает с перечнем зависимостей
 * и интерпретатор отвечает) не трогается. Ответ – путь к python.exe окружения.
 */
async function ensurePython({ home, version, requirements, env, say, reinstall = false }) {
  const base = path.join(home, version);
  const venv = path.join(base, 'venv');
  const python = venvPython(venv);
  const marker = path.join(base, 'installed.json');
  const wanted = sha256File(requirements);
  const done = readJson(marker);
  if (!reinstall && done && done.requirements_sha256 === wanted && fs.existsSync(python)) {
    const ok = await run(python, ['-E', '-s', '-c', IMPORT_CHECK], { env, timeoutMs: 120000 });
    if (ok.code === 0) return python;
  }
  fsx.rmSync(marker, { force: true });
  fsx.rmSync(venv, { recursive: true, force: true });
  fs.mkdirSync(base, { recursive: true });
  let uv = await findUv(home, env);
  let system = '';
  if (!uv) system = await findSystemPython(env);
  if (!uv && system) {
    const viaSystem = await systemVenv(system, venv, python, requirements, env, say);
    if (viaSystem.ok) return finish();
    say(t(`${viaSystem.why} Перехожу к установке Python через uv…`, `${viaSystem.why} Switching to installing Python with uv…`));
    fsx.rmSync(venv, { recursive: true, force: true });
    system = '';
  }
  if (!uv) uv = await installUv(home, env, say);
  {
    say(t(`Готовлю Python ${PYTHON} (uv)…`, `Preparing Python ${PYTHON} (uv)…`));
    const made = await run(uv, ['venv', venv, '--python', PYTHON, '--no-config'], { env, timeoutMs: 900000 });
    if (made.code !== 0) throw failed(t('uv venv не создал окружение Python', 'uv venv did not create the Python environment'), made);
    say(t('Ставлю зависимости приложения по хешам…', 'Installing the app dependencies by hash…'));
    const installed = await run(uv, ['pip', 'install', '--python', python, '--require-hashes', '--no-config', '-r', requirements],
      { env, timeoutMs: 1800000 });
    if (installed.code !== 0) throw failed(t('Зависимости не установились', 'The dependencies were not installed'), installed);
  }
  return finish();

  async function finish() {
    const check = await run(python, ['-E', '-s', '-c', IMPORT_CHECK], { env, timeoutMs: 120000 });
    if (check.code !== 0) throw failed(t('Окружение Python собрано, но модули не импортируются', 'The Python environment is built, but the modules do not import'), check);
    writeJsonAtomic(marker, { requirements_sha256: wanted, python: PYTHON, via: uv ? 'uv' : 'pip', at: new Date().toISOString() });
    return python;
  }
}

/** Окружение из системного Python 3.12: venv и pip по хешам. Отказ – {ok: false, why}, чтобы перейти к uv. */
async function systemVenv(system, venv, python, requirements, env, say) {
  say(t(`Готовлю Python ${PYTHON} (системный, venv и pip)…`, `Preparing Python ${PYTHON} (system, venv and pip)…`));
  const made = await run(system, ['-E', '-s', '-m', 'venv', venv], { env, timeoutMs: 600000 });
  if (made.code !== 0) return { ok: false, why: t(`Системный Python не создал окружение (код ${made.code}).`, `The system Python did not create the environment (code ${made.code}).`) };
  const index = env.PIP_INDEX_URL ? ['--index-url', env.PIP_INDEX_URL] : [];
  const installed = await run(python, ['-E', '-s', '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check',
    '--no-input', ...index, '--require-hashes', '-r', requirements], { env, timeoutMs: 1800000 });
  if (installed.code !== 0) throw failed(t('Зависимости не установились', 'The dependencies were not installed'), installed); // сеть или хеши – uv тут не поможет
  return { ok: true };
}

module.exports = { ensurePython, venvPython, UV_VERSION, PYTHON, IMPORT_CHECK };
