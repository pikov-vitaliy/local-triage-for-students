'use strict';
// stand.json – состояние стенда в служебной папке (раздел 3.2 плана): идентификатор, фаза установки базы, порты,
// папка кода, последняя успешная версия. Пароля и строк подключения в нём нет. Запись – временный файл, fsync,
// переименование.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fsx = require('./fsx');

const PHASES = ['none', 'db-creating', 'db-created', 'ready'];

function writeJsonAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  const fd = fs.openSync(tmp, 'w');
  try {
    fsx.writeAll(fd, `${JSON.stringify(data, null, 1)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fsx.renameSync(tmp, file);
}

function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function load(home) {
  const file = path.join(home, 'stand.json');
  const data = readJson(file);
  if (data && typeof data === 'object' && PHASES.includes(data.phase)) return { file, data, existed: true };
  return { file, data: { schema: 1, id: crypto.randomBytes(8).toString('hex'), phase: 'none' }, existed: false };
}

function save(state, changes = {}) {
  Object.assign(state.data, changes, { updated_at: new Date().toISOString() });
  writeJsonAtomic(state.file, state.data);
}

module.exports = { PHASES, load, save, readJson, writeJsonAtomic };
