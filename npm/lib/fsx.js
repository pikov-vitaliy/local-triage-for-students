'use strict';

/**
 * Переименование и удаление с повтором. На Windows антивирус и индексатор открывают только что записанные файлы, и
 * rename или rm каталога на несколько секунд даёт EPERM, EACCES или EBUSY. Повтор – только на «занято», с нарастающей
 * паузой до 30 с; прочие ошибки – сразу. На исчерпании – понятное сообщение вместо стека (проверка агентами перед
 * кругом 4 ревью сборки А).
 */

const fs = require('node:fs');
const path = require('node:path');
const { StandError } = require('./paths');

const BUSY = new Set(['EPERM', 'EACCES', 'EBUSY']);
const RETRY_MS = 30000;

function pause(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function retrying(what, fn, ms = RETRY_MS) {
  const deadline = Date.now() + ms;
  let wait = 100;
  for (;;) {
    try {
      return fn();
    } catch (error) {
      if (!error || !BUSY.has(error.code)) throw error;
      if (Date.now() >= deadline) {
        throw new StandError(`${what}: файл занят другой программой (${error.code}), чаще всего антивирусом или ` +
          'индексатором. Ничего не потеряно: подождите минуту и запустите стенд снова. Помогает исключить служебную ' +
          'папку стенда из проверки антивируса.');
      }
      pause(wait);
      wait = Math.min(wait * 2, 2000);
    }
  }
}

function renameSync(from, to, ms) {
  return retrying(`Не удалось переименовать ${from} в ${to}`, () => fs.renameSync(from, to), ms);
}

function rmSync(target, options, ms) {
  return retrying(`Не удалось удалить ${target}`, () => fs.rmSync(target, options), ms);
}

const MARK = '.local-triage-tmp';

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

/**
 * Удаление остатков прерванных запусков с любым номером процесса: ровно <имя>.tmp-<число>, <имя>.old-<число>. В папке,
 * где лежат и файлы пользователя (папка кода), – только каталоги с меткой стенда MARK внутри (ревью круга 4).
 * Ошибки не роняют запуск.
 */
function removeLeftovers(dir, base, kinds = ['tmp', 'old'], { marked = false } = {}) {
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return; }
  const escaped = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const own = new RegExp(`^${escaped}\\.(?:${kinds.join('|')})-\\d+$`);
  for (const name of names) {
    if (!own.test(name)) continue;
    if (marked) {
      let owner = NaN;
      try { owner = Number(fs.readFileSync(path.join(dir, name, MARK), 'utf8').trim()); } catch { continue; } // не наш
      if (owner && owner !== process.pid && alive(owner)) continue; // другой стенд ещё копирует
    }
    try { rmSync(path.join(dir, name), { recursive: true, force: true }, 5000); } catch { /* в следующий раз */ }
  }
}

/** Запись всех байтов: fs.writeSync может записать меньше, короткая запись не выдаётся за полную (ревью круга 6). */
function writeAll(fd, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  let offset = 0;
  while (offset < buf.length) {
    const n = fs.writeSync(fd, buf, offset, buf.length - offset);
    if (!(n > 0)) throw new Error('запись на диск не продвигается');
    offset += n;
  }
}

/**
 * Файл с секретом (пароль): пустой временный файл 0600, права (restrict) – до записи содержимого, затем запись, fsync и
 * переименование на место. Сбой на любом шаге не оставляет копии секрета с наследованными правами (ревью круга 5).
 * exclusive – цель не заменяется. Остатки <файл>.tmp-<число> прежних попыток удаляются.
 */
function writeSecret(file, data, restrict = () => {}, { exclusive = false } = {}) {
  removeLeftovers(path.dirname(file), path.basename(file), ['tmp']);
  if (exclusive && fs.existsSync(file)) {
    const error = new Error(`${file} уже есть`);
    error.code = 'EEXIST';
    throw error;
  }
  const tmp = `${file}.tmp-${process.pid}`;
  fs.rmSync(tmp, { force: true });
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.closeSync(fs.openSync(tmp, 'r')); // файл создан пустым
    restrict(tmp);
    writeAll(fd, data);
    fs.fsyncSync(fd);
  } catch (error) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw error;
  }
  fs.closeSync(fd);
  const want = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  if (!fs.readFileSync(tmp).equals(want)) { // сверка до публикации: на место – только целый секрет
    fs.rmSync(tmp, { force: true });
    throw new Error(`${file}: записанный файл не совпал с исходным`);
  }
  renameSync(tmp, file);
}

module.exports = { BUSY, MARK, retrying, renameSync, rmSync, removeLeftovers, writeSecret, writeAll };
