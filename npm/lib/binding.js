'use strict';

/**
 * Привязка папки кода к базе (Д10): одна процедура для CLI и держателя (ревью круга 5). Кластер главнее stand.json: его
 * привязка лежит в local-triage.code-dir рядом с ним – в pg/data, в pg/next или в копии из pg/backups, названной меткой
 * переключения (кластер мог быть между двумя переименованиями). Файл – две строки: путь, как его задал оператор, и
 * раскрытый путь на момент привязки: перенацеленная ссылка (junction, symlink) не выдаёт чужую папку за прежнюю.
 */

const fs = require('node:fs');
const path = require('node:path');
const { canonical } = require('./paths');
const { readJson } = require('./stand');

const FILE = 'local-triage.code-dir';

function readBinding(dir) {
  try {
    const [given, real] = fs.readFileSync(path.join(dir, FILE), 'utf8').split(/\r?\n/).map((line) => line.trim());
    return given ? { path: given, real: real || '' } : null;
  } catch {
    return null;
  }
}

/** Где может лежать кластер этой служебной папки, по порядку таблицы раздела 3.4. */
function clusterPlaces(home) {
  const pgDir = path.join(home, 'pg');
  const places = [path.join(pgDir, 'data'), path.join(pgDir, 'next')];
  for (const mark of ['switch.json', 'next.json']) {
    const info = readJson(path.join(pgDir, mark));
    if (info && info.backup) places.push(path.join(pgDir, 'backups', String(info.backup)));
  }
  return places;
}

function fromCluster(home) {
  for (const dir of clusterPlaces(home)) {
    const found = readBinding(dir);
    if (found) return found;
  }
  return null;
}

function fromStand(home) {
  const s = readJson(path.join(home, 'stand.json'));
  return s && s.code_dir ? { path: String(s.code_dir), real: String(s.code_dir_real || '') } : null;
}

function current(home) {
  return fromCluster(home) || fromStand(home);
}

/** Та же папка: по раскрытому пути привязки, если он записан, иначе по раскрытию записанного пути сейчас. */
function matches(binding, codeDir) {
  const now = canonical(codeDir);
  return binding.real ? binding.real === now : canonical(binding.path) === now;
}

function fileText(codeDir) {
  return `${codeDir}\n${canonical(codeDir)}\n`;
}

module.exports = { FILE, readBinding, clusterPlaces, fromCluster, fromStand, current, matches, fileText };
