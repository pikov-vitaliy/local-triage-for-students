'use strict';
// Запуск дочерних процессов стенда: всегда без окна консоли (windowsHide), с пределом времени.

const { spawn } = require('node:child_process');

const KEEP = 200000; // сколько знаков вывода хранить: хвост для сообщений об ошибке
// Запущенные и ещё не завершённые процессы: при остановке держатель дожидается их или снимает (ревью сборки А, В4)
const ACTIVE = new Set();

/** Дождаться завершения запущенных процессов (ms), затем снять оставшиеся вместе с дочерними. */
async function settle(ms = 60000) {
  const deadline = Date.now() + ms;
  while (ACTIVE.size && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  for (const child of ACTIVE) {
    if (process.platform === 'win32') spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
    else stop(child, 'SIGKILL');
  }
  const after = Date.now() + 10000;
  while (ACTIVE.size && Date.now() < after) await new Promise((r) => setTimeout(r, 200));
}

/** Сигнал процессу, а запущенному группой (POSIX) – всей группе: конвейер curl | sh не переживает отмену. */
function stop(child, signal = 'SIGTERM') {
  try {
    if (child.group) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch { /* уже вышел */ }
}

function groupAlive(child) {
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Запускает процесс и ждёт его завершения. stdio: pipe – вывод возвращается; ignore – никаких унаследованных
 * дескрипторов (pg_ctl start: его postgres живёт дольше pg_ctl и держал бы канал открытым); fd – вывод в открытый файл.
 * Ответ: {code, signal, stdout, stderr, timedOut, error}; code -1 – процесс не запустился.
 */
function run(file, args, { env, cwd, timeoutMs = 0, input = null, stdio = 'pipe', fd = null, group = false } = {}) {
  return new Promise((resolve) => {
    let mode;
    if (stdio === 'ignore') mode = 'ignore';
    else if (fd !== null) mode = ['ignore', fd, fd];
    else mode = ['pipe', 'pipe', 'pipe'];
    let child;
    try {
      const own = group && process.platform !== 'win32';
      child = spawn(file, args, { env, cwd, windowsHide: true, stdio: mode, detached: own });
      child.group = own;
    } catch (error) {
      resolve({ code: -1, signal: null, stdout: '', stderr: '', timedOut: false, error });
      return;
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let done = false;
    ACTIVE.add(child);
    child.once('exit', () => {
      if (!child.group) { ACTIVE.delete(child); return; }
      // группа: держатель ждёт, пока выйдут и потомки (settle видит её до конца)
      const poll = setInterval(() => {
        if (!groupAlive(child)) { clearInterval(poll); ACTIVE.delete(child); }
      }, 200);
    });
    child.once('error', () => ACTIVE.delete(child));
    const finish = (code, signal, error = null) => {
      if (done) return;
      done = true;
      if (!child.group) ACTIVE.delete(child);
      if (timer) clearTimeout(timer);
      resolve({ code: code === null ? -1 : code, signal, stdout, stderr, timedOut, error });
    };
    const timer = timeoutMs ? setTimeout(() => {
      timedOut = true;
      // на Windows – всё дерево служебной команды, пока жив её корень (ревью круга 6)
      if (process.platform === 'win32') spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
      else stop(child);
    }, timeoutMs) : null;
    if (child.stdout) child.stdout.on('data', (d) => { stdout = (stdout + d).slice(-KEEP); });
    if (child.stderr) child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-KEEP); });
    child.on('error', (error) => finish(-1, null, error));
    // с каналами – по закрытию каналов (весь вывод прочитан), без них – по завершению процесса
    child.on(Array.isArray(mode) && mode[1] === 'pipe' ? 'close' : 'exit', (code, signal) => finish(code, signal));
    if (child.stdin) {
      child.stdin.on('error', () => {});
      child.stdin.end(input === null ? undefined : input);
    }
  });
}

function tail(text, lines = 20) {
  return String(text || '').trimEnd().split(/\r?\n/).slice(-lines).join('\n');
}

module.exports = { run, tail, settle, ACTIVE };
