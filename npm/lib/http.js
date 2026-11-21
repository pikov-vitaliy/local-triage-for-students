'use strict';

/**
 * Опрос служебных HTTP-адресов (/status держателя, /healthz приложения) одной процедурой (ревью круга 5): общий срок
 * ограничивает и текущий запрос; обрыв ответа посреди тела, тайм-аут после соединения и ошибка ответа – «занято».
 * Ответ: {state: 'ok', data} – полный JSON; 'bad' – полный ответ, но не JSON; 'free' – соединение отклонено;
 * 'busy' – соединение было, ответа целиком нет; 'error' – прочие ошибки соединения (code).
 */

const http = require('node:http');

function getJson(port, pathName, timeoutMs = 2000) {
  return new Promise((resolve) => {
    let settled = false;
    let connected = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const req = http.get({ host: '127.0.0.1', port, path: pathName, headers: { Host: `127.0.0.1:${port}` } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('aborted', () => done({ state: 'busy' }));
      res.on('error', () => done({ state: 'busy' }));
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (!res.complete) { done({ state: 'busy' }); return; }
        try {
          done({ state: 'ok', data: JSON.parse(body) });
        } catch {
          done({ state: 'bad' });
        }
      });
    });
    req.on('socket', (socket) => {
      // сокет из пула keep-alive приходит уже соединённым: событие connect не наступит (проверка агентами, круг 7)
      if (!socket.connecting) connected = true;
      else socket.once('connect', () => { connected = true; }); // у сокета из пула обработчики не копятся
    });
    const timer = setTimeout(() => {
      done({ state: connected ? 'busy' : 'error', code: 'ETIMEDOUT' });
      req.destroy();
    }, timeoutMs);
    req.on('error', (error) => {
      if (error.code === 'ECONNREFUSED') done({ state: 'free' });
      else done({ state: connected ? 'busy' : 'error', code: error.code });
    });
  });
}

module.exports = { getJson };
