'use strict';
// Сведения о компьютере для приложения (раздел 3.5 плана): в Docker-установке их пишет scripts/host-metrics.ps1,
// в стенде – держатель, раз в 5 с, по тому же контракту, что читает app/telemetry.py (host_snapshot): schema 1,
// host_scope ollama_host, sampled_at, memory.total_bytes и available_bytes, cpu_pct 0–100, addresses, collector_id.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PERIOD_MS = 5000;

function cpuTimes() {
  let idle = 0;
  let total = 0;
  for (const cpu of os.cpus()) {
    for (const value of Object.values(cpu.times)) total += value;
    idle += cpu.times.idle;
  }
  return { idle, total };
}

function addresses() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list || []) {
      if (!item.internal && item.address) out.push(String(item.address).split('%')[0]);
    }
  }
  return [...new Set(out)].slice(0, 64);
}

function snapshot(previous, now = Date.now()) {
  const times = cpuTimes();
  let cpu = null;
  if (previous) {
    const total = times.total - previous.total;
    const idle = times.idle - previous.idle;
    if (total > 0) cpu = Math.min(100, Math.max(0, Math.round(1000 * (1 - idle / total)) / 10));
  }
  return {
    times,
    data: {
      schema: 1, host_scope: 'ollama_host', sampled_at: now / 1000,
      memory: { total_bytes: os.totalmem(), available_bytes: Math.min(os.freemem(), os.totalmem()) },
      cpu_pct: cpu, addresses: addresses(), collector_id: 'local-triage-stand',
    },
  };
}

/** Пишет telemetry/host.json атомарно каждые 5 с; возвращает функцию остановки. */
function startCollector(dataDir, onError = () => {}) {
  const dir = path.join(dataDir, 'telemetry');
  const file = path.join(dir, 'host.json');
  let previous = null;
  const write = () => {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const next = snapshot(previous);
      previous = next.times;
      const tmp = `${file}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify(next.data));
      fs.renameSync(tmp, file);
    } catch (error) {
      onError(error);
    }
  };
  write();
  const timer = setInterval(write, PERIOD_MS);
  timer.unref();
  return () => clearInterval(timer);
}

module.exports = { startCollector, snapshot, addresses, PERIOD_MS };
