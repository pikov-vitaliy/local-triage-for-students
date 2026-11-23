'use strict';
const { t } = require('./lang');
// Версия пакета npm и версия приложения (ADR-0155): запись 0.10.0.devNN в
// app/__init__.py – 0.10.0-dev.NN в package.json. npm не принимает 0.10.0.devNN, а предрелиз semver сравнивается по
// числу: 0.10.0-dev.9 < 0.10.0-dev.10.

const APP = /^(\d+)\.(\d+)\.(\d+)(?:\.dev(\d+))?$/;
const NPM = /^(\d+)\.(\d+)\.(\d+)(?:-dev\.(\d+))?$/;

function npmVersionOf(app) {
  const m = APP.exec(String(app).trim());
  if (!m) throw new Error(t(`Версия приложения не вида X.Y.Z или X.Y.Z.devN: ${app}`, `App version is not of the form X.Y.Z or X.Y.Z.devN: ${app}`));
  return `${m[1]}.${m[2]}.${m[3]}${m[4] === undefined ? '' : `-dev.${m[4]}`}`;
}

function appVersionOf(npm) {
  const m = NPM.exec(String(npm).trim());
  if (!m) throw new Error(t(`Версия пакета не вида X.Y.Z или X.Y.Z-dev.N: ${npm}`, `Package version is not of the form X.Y.Z or X.Y.Z-dev.N: ${npm}`));
  return `${m[1]}.${m[2]}.${m[3]}${m[4] === undefined ? '' : `.dev${m[4]}`}`;
}

module.exports = { npmVersionOf, appVersionOf };
