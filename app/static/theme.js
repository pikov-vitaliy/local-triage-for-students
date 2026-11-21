/* Тема оформления: по умолчанию – по времени суток на часах компьютера (с 20:00 до 07:00 тёмная, днём светлая).
   Ручной выбор кнопкой ☾/☀ хранится в localStorage вместе со сроком – до ближайшей смены дня и ночи (07:00 или
   20:00), потом снова действует время суток. Файл подключается в <head> без defer, чтобы тема применилась до
   отрисовки страницы. Здесь же у <html> появляется класс js: без скрипта видны элементы .no-js-only, со скриптом –
   .js-only. */
(function () {
  "use strict";
  var KEY = "local-triage-theme";
  var NIGHT_FROM = 20, DAY_FROM = 7;
  var root = document.documentElement;
  root.classList.add("js");

  function byClock(now) {
    var h = now.getHours();
    return (h >= NIGHT_FROM || h < DAY_FROM) ? "dark" : "light";
  }
  // ближайшая смена дня и ночи после now (миллисекунды)
  function nextSwitch(now) {
    var next = new Date(now.getTime());
    var h = now.getHours();
    next.setMinutes(0, 0, 0);
    if (h < DAY_FROM) next.setHours(DAY_FROM);
    else if (h < NIGHT_FROM) next.setHours(NIGHT_FROM);
    else { next.setDate(next.getDate() + 1); next.setHours(DAY_FROM); }
    return next.getTime();
  }
  function load() {
    try {
      var raw = window.localStorage.getItem(KEY);
      if (!raw) return null;
      var data = JSON.parse(raw);
      if (data && (data.theme === "light" || data.theme === "dark") && typeof data.until === "number" &&
          Date.now() < data.until) return data.theme;
      return null; // прежний формат без срока или срок истёк – снова время суток
    } catch (e) { return null; }
  }
  function save(value) {
    try {
      window.localStorage.setItem(KEY, JSON.stringify({ theme: value, until: nextSwitch(new Date()) }));
    } catch (e) { /* хранилище недоступно – выбор не запоминается */ }
  }
  function current() {
    var chosen = root.getAttribute("data-theme");
    return chosen === "light" || chosen === "dark" ? chosen : byClock(new Date());
  }
  // Значок кнопки – по атрибуту data-mode (луна в светлой теме, солнце в тёмной); кнопка без значков – знаком
  function paint(button) {
    var dark = current() === "dark";
    button.setAttribute("data-mode", dark ? "dark" : "light");
    if (!button.querySelector("svg")) button.textContent = dark ? "☀" : "☾";
    button.setAttribute("aria-label", dark ? "Включить светлую тему" : "Включить тёмную тему");
    button.setAttribute("title", dark ? "Светлая тема" : "Тёмная тема");
  }

  root.setAttribute("data-theme", load() || byClock(new Date()));

  // открытая вкладка: в 07:00 и 20:00 и при возвращении к вкладке тема снова сверяется со временем суток (ручной
  // выбор действует до своей границы)
  function refresh() {
    root.setAttribute("data-theme", load() || byClock(new Date()));
    var button = document.getElementById("theme-toggle");
    if (button) paint(button);
  }
  function schedule() {
    var wait = Math.max(1000, nextSwitch(new Date()) - Date.now() + 1000);
    window.setTimeout(function () { refresh(); schedule(); }, Math.min(wait, 2147000000));
  }
  schedule();
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("theme-toggle");
    if (!button) return;
    paint(button);
    button.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      save(next);
      paint(button);
    });
  });
})();
