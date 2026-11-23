'use strict';
// Язык сообщений стенда в терминале (ADR-0158): английский по умолчанию, русский – при TRIAGE_LANG=ru или ключе
// --lang ru. Таблица переводов – сами пары t(русский, английский) у каждого сообщения: каталог приложения
// (app/locales) окну стенда не нужен. Служебные строки протокола держателя (@@phase, @@ready) не переводятся.

const LANGS = ['en', 'ru'];
const DEFAULT = 'en';

function normalize(value) {
  const text = String(value || '').trim().toLowerCase();
  return LANGS.includes(text) ? text : '';
}

let current = normalize(process.env.TRIAGE_LANG) || DEFAULT;

/** Сменить язык (ключ --lang, язык из окна стенда у держателя); неизвестное значение не меняет язык. */
function setLang(value) {
  const lang = normalize(value);
  if (lang) current = lang;
  return current;
}

function lang() {
  return current;
}

/** Сообщение на действующем языке: { ru, en } – одна пара на фразу. */
function t(ru, en) {
  return current === 'ru' ? ru : en;
}

module.exports = { LANGS, DEFAULT, normalize, setLang, lang, t };
