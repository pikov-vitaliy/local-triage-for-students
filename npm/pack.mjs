// Сборка пакета npm учебного стенда (ADR-0155).
//
//   node npm/pack.mjs manifest              – записать npm/files.manifest по правилам состава
//   node npm/pack.mjs check                 – перечень совпадает с правилами (код 1 – нет)
//   node npm/pack.mjs pack [--commit REV] [--out ПАПКА]
//
// Состав пакета – только перечень npm/files.manifest: посторонний файл попадает в пакет лишь явной строкой, которую
// видит ревью. Сборка выгружает дерево git во временную папку командой git archive: до коммита – дерево
// подготовленного индекса (git write-tree), после – сам коммит. Сведения о сборке пишутся в npm/build.json (в выгрузке
// нет .git), README пакета – из npm/README.md. Затем npm pack и страж по распакованному .tgz
// (scripts/npm_package_guard.py). Выдаётся именно проверенный .tgz.

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = path.join(ROOT, 'npm', 'files.manifest');
const FIXED = new Set(['package.json', 'npm-shrinkwrap.json', 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'npm/cli.js', 'npm/requirements.txt',
  'npm/files.manifest', 'examples/demo/demo-hub-report.xlsx', 'examples/demo/demo-hub-report-v2.xlsx']);
// пути пакета, которых нет в дереве git как есть: README – из npm/README.md, сведения о сборке – пишутся при сборке
const GENERATED = { 'README.md': 'npm/README.md', 'npm/build.json': null };
const RULES = [
  /^npm\/lib\/[^/]+\.js$/,
  /^app\/(?:[^/]+\/)*[^/]+\.py$/,
  /^app\/templates\/(?:[^/]+\/)*[^/]+\.html$/,
  /^app\/static\/(?:[^/]+\/)*[^/]+\.(?:css|js|svg)$/,
  /^app\/static\/fonts\/[^/]+\.woff2$/,
  /^app\/storage\/migrations\/postgresql\/[^/]+\.sql$/,
  /^app\/static\/fonts\/OFL\.txt$/,
  /^app\/static\/capec-license\.txt$/,
  /^examples\/demo\/repos\/(?:billing-core|catalog-api)\//,
  // каталог учебных примеров (ADR-0156): описание, источники и выгрузки без кода; входы сборки каталога – только в git
  /^examples\/catalog\/(?:catalog\.json|NOTICE\.md)$/,
  /^examples\/catalog\/[a-z0-9-]+\/export\.xlsx$/,
];

function git(...args) {
  return execFileSync('git', ['-C', ROOT, '-c', 'core.quotepath=false', ...args], { encoding: 'utf8', maxBuffer: 1 << 28 });
}

export function packaged(file) {
  return FIXED.has(file) || RULES.some((rule) => rule.test(file));
}

/** Файлы репозитория: отслеживаемые и новые, кроме игнорируемых (как repo_files() в тестах гигиены). */
function repoFiles() {
  return git('ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0').filter(Boolean)
    .filter((name) => fs.existsSync(path.join(ROOT, name)));
}

export function computeManifest(files = repoFiles()) {
  const problems = [];
  for (const file of files) {
    if (file.startsWith('app/') && !packaged(file) && !/(^|\/)__pycache__\//.test(file)) {
      problems.push(`${file}: файл приложения не попадает в пакет – добавьте правило в npm/pack.mjs или уберите файл`);
    }
  }
  const present = new Set(files);
  for (const name of [...FIXED, ...Object.values(GENERATED).filter(Boolean)]) {
    if (!present.has(name) && name !== 'npm/files.manifest') problems.push(`${name}: обязательного файла пакета нет`);
  }
  const list = files.filter(packaged).concat([...FIXED], Object.keys(GENERATED));
  return { list: [...new Set(list)].sort(), problems };
}

function readManifest() {
  return fs.readFileSync(MANIFEST, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

function writeManifest() {
  const { list, problems } = computeManifest();
  if (problems.length) throw new Error(problems.join('\n'));
  fs.writeFileSync(MANIFEST, `# Состав пакета npm учебного стенда: сценарий npm/pack.mjs manifest, проверка – npm/pack.mjs check.\n${list.join('\n')}\n`);
  console.log(`npm/files.manifest: ${list.length} путей`);
}

function check() {
  const { list, problems } = computeManifest();
  const current = readManifest();
  const extra = current.filter((name) => !list.includes(name));
  const missing = list.filter((name) => !current.includes(name));
  const out = [...problems, ...extra.map((n) => `${n}: в перечне, но не по правилам или нет файла`),
    ...missing.map((n) => `${n}: по правилам входит, но в перечне нет – node npm/pack.mjs manifest`)];
  if (out.length) {
    console.error(out.join('\n'));
    return 1;
  }
  console.log(`npm/files.manifest совпадает с правилами: ${current.length} путей`);
  return 0;
}

function buildTime() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function pack(argv) {
  const at = (flag) => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : ''; };
  const commit = at('--commit');
  const out = path.resolve(at('--out') || path.join(ROOT, 'npm-build'));
  const tree = commit ? git('rev-parse', `${commit}^{tree}`).trim() : git('write-tree').trim();
  const head = (commit ? git('rev-parse', '--short=12', commit) : git('rev-parse', '--short=12', 'HEAD')).trim();
  const dirty = !commit && tree !== git('rev-parse', 'HEAD^{tree}').trim();
  const manifestInTree = git('show', `${tree}:npm/files.manifest`).split(/\r?\n/).map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  // перечень выбранного дерева сверяется с правилами по файлам этого же дерева: не пропустить модуль приложения
  const treeFiles = git('ls-tree', '-r', '--name-only', '-z', tree).split('\0').filter(Boolean);
  const wanted = computeManifest(treeFiles);
  const differ = wanted.list.filter((n) => !manifestInTree.includes(n)).concat(manifestInTree.filter((n) => !wanted.list.includes(n)));
  if (wanted.problems.length || differ.length) {
    throw new Error(`Перечень npm/files.manifest в дереве ${tree.slice(0, 12)} не совпадает с правилами: ` +
      `${wanted.problems.concat(differ).join('; ')}`);
  }
  const sources = manifestInTree.filter((name) => !(name in GENERATED)).concat(Object.values(GENERATED).filter(Boolean));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'local-triage-pack-'));
  const pkgDir = path.join(work, 'package');
  fs.mkdirSync(pkgDir);
  const tar = path.join(work, 'tree.tar');
  // дерево выгружается целиком, затем остаётся ровно перечень: путей слишком много для командной строки Windows
  execFileSync('git', ['-C', ROOT, 'archive', '--format=tar', '-o', tar, tree]);
  // на Windows – системный tar: GNU tar из Git Bash принимает «C:» за адрес удалённого узла
  const tarExe = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  execFileSync(tarExe, ['-xf', tar, '-C', pkgDir]);
  // страж и правила – из того же дерева, что и пакет
  const guardDir = path.join(work, 'guard');
  fs.mkdirSync(guardDir);
  for (const name of ['npm_package_guard.py', 'hygiene_rules.py']) {
    fs.copyFileSync(path.join(pkgDir, 'scripts', name), path.join(guardDir, name));
  }
  const treeManifest = path.join(guardDir, 'files.manifest');
  fs.writeFileSync(treeManifest, `${manifestInTree.join('\n')}\n`);
  const keep = new Set(sources);
  const missing = sources.filter((name) => !fs.existsSync(path.join(pkgDir, name)));
  if (missing.length) throw new Error(`В дереве ${tree.slice(0, 12)} нет файлов перечня: ${missing.join(', ')}`);
  const prune = (rel) => {
    for (const entry of fs.readdirSync(path.join(pkgDir, rel), { withFileTypes: true })) {
      const name = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        prune(name);
        if (!fs.readdirSync(path.join(pkgDir, name)).length) fs.rmdirSync(path.join(pkgDir, name));
      } else if (!keep.has(name)) {
        fs.rmSync(path.join(pkgDir, name), { force: true });
      }
    }
  };
  prune('');
  fs.renameSync(path.join(pkgDir, 'npm', 'README.md'), path.join(pkgDir, 'README.md'));
  fs.writeFileSync(path.join(pkgDir, 'npm', 'build.json'), `${JSON.stringify({ commit: head, dirty, time: buildTime() }, null, 1)}\n`);
  const staging = path.join(work, 'out');
  fs.mkdirSync(staging);
  // npm на Windows – сценарий npm.cmd, его запускает только оболочка: одна строка с путём в кавычках
  const packed = process.platform === 'win32'
    ? spawnSync(`npm pack --json --pack-destination "${staging}"`, { cwd: pkgDir, encoding: 'utf8', shell: true })
    : spawnSync('npm', ['pack', '--json', '--pack-destination', staging], { cwd: pkgDir, encoding: 'utf8' });
  if (packed.status !== 0) throw new Error(`npm pack: ${packed.stderr}`);
  const name = JSON.parse(packed.stdout)[0].filename;
  const built = path.join(staging, name);
  // окружение разработки репозитория, а в чистом клоне без него – Python из PATH (страж – только стандартная библиотека)
  const venvPython = process.platform === 'win32' ? path.join(ROOT, '.venv', 'Scripts', 'python.exe') : path.join(ROOT, '.venv', 'bin', 'python');
  const python = fs.existsSync(venvPython) ? venvPython : process.env.LT_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
  const guard = spawnSync(python, ['-X', 'utf8', path.join(guardDir, 'npm_package_guard.py'), built, '--manifest', treeManifest],
    { encoding: 'utf8' });
  process.stdout.write(guard.stdout || '');
  process.stderr.write(guard.stderr || '');
  if (guard.status !== 0) {
    fs.rmSync(work, { recursive: true, force: true });
    throw new Error(`Страж пакета не пропустил .tgz (код ${guard.status}${guard.error ? `, ${guard.error.message}` : ''}): пакет не выдан.`);
  }
  // в выходную папку – только проверенный пакет
  fs.mkdirSync(out, { recursive: true });
  const tgz = path.join(out, name);
  fs.copyFileSync(built, tgz);
  fs.rmSync(work, { recursive: true, force: true });
  console.log(`Пакет: ${tgz} (коммит ${head}${dirty ? ', дерево индекса с правками' : ''})`);
}

const [command, ...rest] = process.argv.slice(2);
try {
  if (command === 'manifest') writeManifest();
  else if (command === 'check') process.exitCode = check();
  else if (command === 'pack') pack(rest);
  else {
    console.error('node npm/pack.mjs manifest | check | pack [--commit REV] [--out ПАПКА]');
    process.exitCode = 2;
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
