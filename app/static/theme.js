/* Тема оформления: выбор пользователя хранится в localStorage, по умолчанию – как в системе.
   Файл подключается в <head> без defer, чтобы тема применилась до отрисовки страницы. Здесь же у <html>
   появляется класс js: без скрипта видны элементы .no-js-only, со скриптом – .js-only. */
(function () {
  "use strict";
  var KEY = "local-triage-theme";
  var root = document.documentElement;
  root.classList.add("js");

  function load() {
    try { return window.localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function save(value) {
    try { window.localStorage.setItem(KEY, value); } catch (e) { /* хранилище недоступно – выбор не запоминается */ }
  }
  function current() {
    var chosen = root.getAttribute("data-theme");
    if (chosen === "light" || chosen === "dark") return chosen;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  // Значок кнопки – по атрибуту data-mode (луна в светлой теме, солнце в тёмной); кнопка без значков – знаком
  function paint(button) {
    var dark = current() === "dark";
    button.setAttribute("data-mode", dark ? "dark" : "light");
    if (!button.querySelector("svg")) button.textContent = dark ? "☀" : "☾";
    button.setAttribute("aria-label", dark ? "Включить светлую тему" : "Включить тёмную тему");
    button.setAttribute("title", dark ? "Светлая тема" : "Тёмная тема");
  }

  var stored = load();
  if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);

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
    if (window.matchMedia) {
      var query = window.matchMedia("(prefers-color-scheme: dark)");
      var repaint = function () { paint(button); };
      if (query.addEventListener) query.addEventListener("change", repaint);
    }
  });
})();
