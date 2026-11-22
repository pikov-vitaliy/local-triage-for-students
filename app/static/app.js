/* Локальный триаж: поведение страниц – тосты, копирование, формы без перезагрузки, опрос состояния, клавиши,
   код с подсветкой строк, карточка находки, отбор находок, живой прогон (SSE). Атрибуты data-* и договорённость
   об ответе JSON – docs/DESIGN.md.
   Данные находок и ответы модели выводятся только через textContent: код и тексты находок – недоверенные данные. */
(function () {
  "use strict";

  function $(selector, root) { return (root || document).querySelector(selector); }
  function $all(selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); }
  function byId(id) { return id ? document.getElementById(String(id)) : null; }
  function closest(el, selector) { return el && el.closest ? el.closest(selector) : null; }
  function toList(value) { return Array.isArray(value) ? value : (value === null || value === undefined ? [] : [value]); }
  function eachKey(map, fn) {
    if (!map || typeof map !== "object" || Array.isArray(map)) return;
    Object.keys(map).forEach(function (key) { fn(key, map[key]); });
  }
  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }

  // Настройки этого браузера (перенос строк кода, клавиши, чек-листы); без хранилища – значения по умолчанию
  function storageGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function storageSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) { /* хранилище недоступно – не запоминаем */ }
  }
  function storageRemove(key) {
    try { window.localStorage.removeItem(key); } catch (e) { /* хранилище недоступно */ }
  }

  // ------------------------------------------------------------------ форматирование

  function num(value, digits) {
    if (value === null || value === undefined || value === "" || isNaN(Number(value))) return "–";
    return Number(value).toFixed(digits === undefined ? 1 : digits).replace(".", ",");
  }
  function pad(n) { return n < 10 ? "0" + n : String(n); }
  function duration(value) {
    if (value === null || value === undefined || isNaN(Number(value))) return "–";
    var s = Math.max(0, Math.round(Number(value)));
    if (s < 60) return s + " с";
    var m = Math.floor(s / 60);
    s = s % 60;
    if (m < 60) return m + " мин " + pad(s) + " с";
    var h = Math.floor(m / 60);
    return h + " ч " + pad(m % 60) + " мин";
  }
  function mib(value) {
    if (value === null || value === undefined || isNaN(Number(value))) return "–";
    var v = Number(value);
    return v >= 1024 ? num(v / 1024) + " ГБ" : Math.round(v) + " МБ";
  }
  function localTime(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso || "";
    return d.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function plural(n, one, few, many) {
    var a = Math.abs(n) % 100;
    var b = a % 10;
    if (b === 1 && a !== 11) return one;
    if (b >= 2 && b <= 4 && (a < 12 || a > 14)) return few;
    return many;
  }
  // «только что», «5 минут назад», «сегодня, 12:30», «вчера, 12:30», «3 дня назад», «12 октября»
  function relativeTime(date) {
    var now = new Date();
    var seconds = (now.getTime() - date.getTime()) / 1000;
    var time = date.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
    if (seconds < 45) return "только что";
    if (seconds < 3600) {
      var minutes = Math.max(1, Math.round(seconds / 60));
      return minutes + " " + plural(minutes, "минуту", "минуты", "минут") + " назад";
    }
    if (now.toDateString() === date.toDateString()) return "сегодня, " + time;
    var yesterday = new Date(now.getTime());
    yesterday.setDate(now.getDate() - 1);
    if (yesterday.toDateString() === date.toDateString()) return "вчера, " + time;
    var days = Math.floor(seconds / 86400);
    if (days < 7) return days + " " + plural(days, "день", "дня", "дней") + " назад";
    var options = { day: "numeric", month: "long" };
    if (date.getFullYear() !== now.getFullYear()) options.year = "numeric";
    return date.toLocaleDateString("ru-RU", options);
  }

  // ------------------------------------------------------------------ время

  function localizeTimes(root) {
    $all("time[datetime]", root).forEach(function (el) {
      var iso = el.getAttribute("datetime");
      var d = new Date(iso);
      if (isNaN(d.getTime())) return;
      el.textContent = el.hasAttribute("data-relative") ? relativeTime(d) : localTime(iso);
      el.title = el.hasAttribute("data-relative") ? localTime(iso) : iso;
    });
  }

  // ------------------------------------------------------------------ значки, объявления, тосты

  var SVG_NS = "http://www.w3.org/2000/svg";
  // фигуры значков: путь SVG или окружность «c cx cy r»
  var ICONS = {
    check: ["M20 6 9 17l-5-5"],
    info: ["c 12 12 9", "M12 11v5", "M12 8h.01"],
    warning: ["c 12 12 9", "M12 7.5v5", "M12 16.5h.01"],
    x: ["M18 6 6 18", "M6 6l12 12"]
  };
  function makeIcon(name, extraClass) {
    var svg = document.createElementNS(SVG_NS, "svg");
    var attrs = { "class": "icon" + (extraClass ? " " + extraClass : ""), viewBox: "0 0 24 24", width: "16", height: "16",
      fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round",
      "aria-hidden": "true", focusable: "false" };
    Object.keys(attrs).forEach(function (key) { svg.setAttribute(key, attrs[key]); });
    (ICONS[name] || []).forEach(function (shape) {
      var el;
      if (shape.charAt(0) === "c") {
        var p = shape.split(" ");
        el = document.createElementNS(SVG_NS, "circle");
        el.setAttribute("cx", p[1]);
        el.setAttribute("cy", p[2]);
        el.setAttribute("r", p[3]);
      } else {
        el = document.createElementNS(SVG_NS, "path");
        el.setAttribute("d", shape);
      }
      svg.appendChild(el);
    });
    return svg;
  }

  // Объявление для чтения с экрана: тосты видны глазами, а озвучивает их отдельная область
  function announce(text, assertive) {
    var region = byId(assertive ? "sr-alert" : "sr-status");
    if (!region) return;
    region.textContent = "";
    window.setTimeout(function () { region.textContent = text; }, 40);
  }

  function dismissToast(item) {
    if (!item || item._gone) return;
    item._gone = true;
    window.clearTimeout(item._timer);
    item.classList.add("is-leaving");
    window.setTimeout(function () { if (item.parentNode) item.parentNode.removeChild(item); }, 200);
  }
  // Тост: tone – ok, info, warn, err; timeout – мс (0 – пока не закроют); announce: false – не озвучивать
  // (рядом уже есть своя строка состояния с aria-live)
  // Сообщения не закрывают кнопки решения (НТ11): если стопка сверху пересекает видимый [data-toast-avoid], она
  // уходит вниз – над нижней панелью карточки, если она есть
  function placeToasts(box) {
    var avoid = $all("[data-toast-avoid]").filter(function (el) { return el.getClientRects().length; });
    box.classList.remove("toasts-low", "toasts-faded");
    if (!avoid.length || !box.children.length) return;
    function covers() {
      var rect = box.getBoundingClientRect();
      return avoid.some(function (el) {
        var r = el.getBoundingClientRect();
        return r.left < rect.right && r.right > rect.left && r.top < rect.bottom && r.bottom > rect.top;
      });
    }
    if (!covers()) return;
    var bar = $(".action-bar");
    var barRect = bar && bar.getClientRects().length ? bar.getBoundingClientRect() : null;
    var offset = barRect && barRect.top < window.innerHeight ? window.innerHeight - barRect.top + 16 : 16;
    box.style.setProperty("--toast-low-offset", Math.round(offset) + "px");
    box.classList.add("toasts-low");
    // не помещается ни сверху, ни снизу: сообщения полупрозрачны и пропускают щелчки к кнопкам решения
    if (covers()) box.classList.add("toasts-faded");
  }
  // прокрутка и смена размера окна меняют, что под стопкой: расположение пересчитывается, пока сообщения видны
  var toastsFrame = 0;
  function replaceToasts() {
    var box = byId("toasts");
    if (!box || !box.children.length || toastsFrame) return;
    toastsFrame = window.requestAnimationFrame(function () {
      toastsFrame = 0;
      placeToasts(box);
    });
  }
  window.addEventListener("scroll", replaceToasts, { passive: true });
  window.addEventListener("resize", replaceToasts);
  function toast(text, options) {
    var opts = options || {};
    var tone = ["ok", "info", "warn", "err"].indexOf(opts.tone) >= 0 ? opts.tone : "ok";
    var message = String(text === null || text === undefined ? "" : text);
    if (!message) return null;
    if (opts.announce !== false) announce(message, tone === "err");
    var box = byId("toasts");
    if (!box) return null;
    var item = document.createElement("div");
    item.className = "toast toast-" + tone;
    item.setAttribute("aria-hidden", "true");
    item.appendChild(makeIcon(tone === "ok" ? "check" : (tone === "info" ? "info" : "warning"), "toast-icon"));
    var body = document.createElement("div");
    body.className = "toast-text";
    body.textContent = message;
    item.appendChild(body);
    var close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.tabIndex = -1;
    close.setAttribute("aria-label", "Закрыть");
    close.appendChild(makeIcon("x"));
    close.addEventListener("click", function () { dismissToast(item); });
    item.appendChild(close);
    box.appendChild(item);
    while (box.children.length > 4) box.removeChild(box.firstChild);
    placeToasts(box);
    var timeout = opts.timeout !== undefined ? Number(opts.timeout) : (tone === "err" ? 9000 : 4000);
    var arm = function (ms) {
      window.clearTimeout(item._timer);
      if (timeout > 0) item._timer = window.setTimeout(function () { dismissToast(item); }, ms);
    };
    arm(timeout);
    item.addEventListener("mouseenter", function () { window.clearTimeout(item._timer); });
    item.addEventListener("mouseleave", function () { arm(2000); });
    return item;
  }

  // ------------------------------------------------------------------ буфер обмена

  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "copy-buffer";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(
        function () { return true; },
        function () { return legacyCopy(text); }
      );
    }
    return Promise.resolve(legacyCopy(text));
  }
  function selectContents(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
  // Сообщение рядом с кнопкой: ошибка – своим цветом и со значком, чтобы её не приняли за успех
  function say(el, text, sticky, isError) {
    if (!el) return;
    el.textContent = text;
    el.classList.toggle("is-error", !!isError);
    window.clearTimeout(el._timer);
    if (!sticky) el._timer = window.setTimeout(function () { el.textContent = ""; el.classList.remove("is-error"); }, 6000);
  }

  // Кнопки с data-copy-text или data-copy-target; соседний .copy-status получает сообщение, как раньше
  function initCopyButtons() {
    document.addEventListener("click", function (event) {
      var button = closest(event.target, "[data-copy-text], [data-copy-target]");
      if (!button || button.disabled) return;
      var target = byId(button.getAttribute("data-copy-target"));
      var text = target ? target.textContent : button.getAttribute("data-copy-text");
      var status = button.parentNode ? $(".copy-status", button.parentNode) : null;
      copyText(text || "").then(function (ok) {
        if (ok) {
          say(status, "Скопировано");
          toast(button.getAttribute("data-copy-done") || "Скопировано", { announce: !status });
        } else {
          if (target) selectContents(target);
          say(status, "Не скопировано: выделите текст и нажмите Ctrl+C", true, true);
          toast("Не скопировано: выделите текст и нажмите Ctrl+C", { tone: "err", announce: !status });
        }
      });
    });
  }

  // ------------------------------------------------------------------ запросы и ответ JSON

  function requestError(message, status, answer) {
    var error = new Error(message);
    error.status = status;
    error.answer = answer;
    return error;
  }
  function errorText(answer, status) {
    var text = answer && (answer.detail || answer.message);
    if (typeof text === "string" && text) return text;
    if (status === 409) return "Данные изменились: обновите страницу.";
    return "Ошибка " + status + ": обновите страницу и повторите.";
  }
  // Адрес этого же приложения: «/путь», но не «//хост» и не «/\хост»
  function localUrl(value) {
    if (typeof value !== "string") return "";
    return /^\/(?![\/\\])/.test(value) && value.indexOf("\\") < 0 ? value : "";
  }

  // Запрос с ответом JSON. Ответ – страница (адрес без поддержки JSON): для формы браузер переходит на неё сам,
  // для опроса (options.follow === false) это ошибка
  function request(method, url, data, options) {
    var follow = !(options && options.follow === false);
    var verb = String(method || "GET").toUpperCase();
    var target = url;
    var init = { method: verb, headers: { "Accept": "application/json" }, credentials: "same-origin" };
    if (verb === "GET" || verb === "HEAD") {
      if (data && data.forEach) {
        var params = new URLSearchParams();
        data.forEach(function (value, key) { if (typeof value === "string") params.append(key, value); });
        var query = params.toString();
        if (query) target += (target.indexOf("?") >= 0 ? "&" : "?") + query;
      }
    } else if (data) {
      init.body = data;
    }
    return fetch(target, init).then(function (response) {
      var type = response.headers.get("content-type") || "";
      if (type.indexOf("application/json") < 0) {
        if (!response.ok) throw requestError(errorText(null, response.status), response.status, null);
        if (!follow) throw requestError("Неожиданный ответ приложения: обновите страницу.", response.status, null);
        var page = response.url || "";
        try {
          var parsed = new URL(page, window.location.href);
          if (parsed.origin === window.location.origin) window.location.assign(parsed.pathname + parsed.search + parsed.hash);
          else window.location.reload();
        } catch (e) {
          window.location.reload();
        }
        return { _navigated: true };
      }
      return response.json().catch(function () { return {}; }).then(function (answer) {
        if (!response.ok) throw requestError(errorText(answer, response.status), response.status, answer);
        return answer && typeof answer === "object" ? answer : {};
      });
    }, function () {
      throw requestError("Нет связи с приложением: проверьте, что оно запущено, и повторите.", 0, null);
    });
  }

  // Ответ JSON – по договорённости docs/DESIGN.md; всё выводится как текст
  function renderTimestamp(el, value) {
    if (!el) return;
    el.textContent = value.prefix || "";
    if (!value.datetime) return;
    var time = document.createElement("time");
    time.setAttribute("datetime", value.datetime);
    time.textContent = value.datetime;
    el.appendChild(time);
    el.appendChild(document.createTextNode(value.suffix || ""));
    localizeTimes(el);
  }
  var offerPackageReload = null;  // задаёт карточка решения: предложить обновить карточку
  // Поля пакетного решения SCA после своей записи (К6): отпечаток пакета и редакции находок – из ответа сервера
  function applyPackage(answer) {
    var box = byId("package-apply");
    if (!box || !answer) return;
    // пакет изменили другие (К6): поля формы не обновляются, карточку нужно обновить – иначе следующее сохранение
    // приняло бы чужие изменения, не показав их
    if (answer.package_stale && typeof offerPackageReload === "function") offerPackageReload(answer.notice);
    if (!answer.package) return;
    var fp = $("input[name=package_fp]", box);
    if (fp && answer.package.fp) fp.value = answer.package.fp;
    eachKey(answer.package.revisions, function (hub, value) {
      var field = $("input[name='apply_rev_" + hub + "']", box);
      if (field) field.value = String(value);
    });
    eachKey(answer.package.versions, function (hub, value) {
      var field = $("input[name='apply_ver_" + hub + "']", box);
      if (field) field.value = String(value);
    });
  }
  function applyAnswer(answer) {
    if (!answer || typeof answer !== "object" || answer._navigated) return;
    applyPackage(answer);
    if (answer.revision !== undefined && answer.revision !== null && answer.revision !== "") {
      var revision = byId("review-revision");
      if (revision) revision.value = String(answer.revision);
    }
    eachKey(answer.text, function (id, value) {
      var el = byId(id);
      if (el) el.textContent = value === null || value === undefined ? "" : String(value);
    });
    eachKey(answer.rich, function (id, value) {
      var el = byId(id);
      if (el) renderModelText(el, value);
    });
    eachKey(answer.times, function (id, value) { renderTimestamp(byId(id), value); });
    eachKey(answer.value, function (id, value) {
      var el = byId(id);
      if (el && "value" in el) el.value = value === null || value === undefined ? "" : String(value);
    });
    eachKey(answer.checked, function (id, value) {
      var el = byId(id);
      if (el && "checked" in el) el.checked = !!value;
    });
    toList(answer.show).forEach(function (id) { var el = byId(id); if (el) el.hidden = false; });
    toList(answer.hide).forEach(function (id) { var el = byId(id); if (el) el.hidden = true; });
    eachKey(answer.list, function (id, items) {
      var el = byId(id);
      if (!el) return;
      while (el.firstChild) el.removeChild(el.firstChild);
      toList(items).forEach(function (item) {
        var li = document.createElement("li");
        li.textContent = String(item);
        el.appendChild(li);
      });
    });
    if (answer.message) toast(answer.message, { tone: answer.tone || (answer.ok === false ? "err" : "ok") });
    var target = localUrl(answer.redirect);
    if (target) {
      window.location.assign(target);
      return;
    }
    if (answer.reload) window.location.reload();
  }

  // ------------------------------------------------------------------ текст модели

  // Как фильтры model_text и fix_text (app/view.py): блоки в ограде ``` – моноширинный блок, отрезки
  // в обратных кавычках – код, «строка N» – ссылка на строку, если она есть в показанном коде
  var FENCE_BLOCK = /```[\w+.-]*[ \t]*\n([\s\S]*?)(?:\n[ \t]*```|$)/g;
  var CODE_SPAN = /`([^`\n]+)`/;
  var LINE_REF = /(^|[^0-9A-Za-z_Ѐ-ӿ])(строк[аеиуой]{1,2}|line)\s+(\d{1,7})(?![0-9A-Za-z_Ѐ-ӿ])/gi;

  function appendLinked(el, text) {
    var last = 0;
    var match;
    LINE_REF.lastIndex = 0;
    while ((match = LINE_REF.exec(text)) !== null) {
      var start = match.index + match[1].length;
      var n = parseInt(match[3], 10);
      if (start > last) el.appendChild(document.createTextNode(text.slice(last, start)));
      var link;
      var row = byId("L" + n);
      // строки окна показа вне окна модели (ADR-0087) модель не видела: ссылка на них не подтверждена
      if (row && !row.classList.contains("is-outside")) {
        link = document.createElement("a");
        link.className = "line-ref";
        link.href = "#L" + n;
      } else {  // строки нет в показанном коде: довод не подтверждён – помечается, как в app/view.py
        link = document.createElement("span");
        link.className = "line-ref-missing";
        link.title = "Строки " + n + " нет в показанном коде – ссылка не подтверждена";
      }
      link.textContent = text.slice(start, match.index + match[0].length);
      el.appendChild(link);
      last = match.index + match[0].length;
    }
    if (last < text.length) el.appendChild(document.createTextNode(text.slice(last)));
  }
  function appendInline(el, text) {
    String(text).split(CODE_SPAN).forEach(function (part, k) {
      if (k % 2) {
        var code = document.createElement("code");
        code.textContent = part;
        el.appendChild(code);
      } else if (part) {
        appendLinked(el, part);
      }
    });
  }
  function renderModelText(el, text) {
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
    var source = String(text === null || text === undefined ? "" : text);
    var pos = 0;
    var match;
    FENCE_BLOCK.lastIndex = 0;
    while ((match = FENCE_BLOCK.exec(source)) !== null) {
      appendInline(el, source.slice(pos, match.index));
      var pre = document.createElement("pre");
      pre.className = "fix-code";
      var code = document.createElement("code");
      code.textContent = match[1];
      pre.appendChild(code);
      el.appendChild(pre);
      pos = match.index + match[0].length;
      if (!match[0].length) FENCE_BLOCK.lastIndex += 1;
    }
    appendInline(el, source.slice(pos));
  }

  // ------------------------------------------------------------------ формы

  // Кнопки, ссылки и формы с data-confirm переспрашивают; отказ отменяет и остальные обработчики
  function initConfirm() {
    document.addEventListener("click", function (event) {
      var el = closest(event.target, "[data-confirm]");
      if (!el || el.tagName === "FORM") return;
      if (el.form && el.form.id === "codebase-form" && el.value === "reset") return;
      if (!window.confirm(el.getAttribute("data-confirm"))) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    }, true);
    document.addEventListener("submit", function (event) {
      var form = event.target;
      if (form && form.id === "codebase-form") {
        var cases = 0, reviewed = 0;
        $all("select[data-saved-folder]", form).forEach(function (select) {
          if (select.value !== select.getAttribute("data-saved-folder")) {
            cases += Number(select.getAttribute("data-reset-cases"));
            reviewed += Number(select.getAttribute("data-reset-reviewed"));
          }
        });
        if (cases && (!event.submitter || event.submitter.value === "save")) {
          form.setAttribute("data-confirm", "Будет удалено срезов кода: " + cases
            + "; отметок «Проверено»: " + reviewed
            + ". После удаления клонов это единственная копия кода. Подтвердите удаление.");
        } else if (event.submitter && event.submitter.value === "reset") {
          form.setAttribute("data-confirm", event.submitter.getAttribute("data-confirm"));
        } else form.removeAttribute("data-confirm");
        form.elements.confirm_reset.value = "0";
      }
      if (!form || !form.hasAttribute || !form.hasAttribute("data-confirm")) return;
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
        event.stopImmediatePropagation();
      } else if (form.elements.confirm_reset) {
        form.elements.confirm_reset.value = "1";
      }
    }, true);
  }

  // data-busy: на время отправки – индикатор, текст и запрет повторного нажатия
  function busyButton(form, submitter) {
    if (submitter && submitter.hasAttribute && submitter.hasAttribute("data-busy")) return submitter;
    if (form && form.hasAttribute("data-busy")) {
      if (!submitter || submitter.classList.contains("visually-hidden")) {
        return $("button[value=save][data-busy]:not(.visually-hidden)", form)
          || $("button[data-busy]:not(.visually-hidden)", form) || submitter;
      }
      return submitter || $("button[type=submit], button:not([type]), input[type=submit]", form);
    }
    return null;
  }
  function setBusy(button, on, text) {
    if (!button) return;
    if (on) {
      if (button._busy) return;
      button._busy = Array.prototype.slice.call(button.childNodes);
      button.setAttribute("aria-busy", "true");
      if (text && button.tagName === "BUTTON") {
        while (button.firstChild) button.removeChild(button.firstChild);
        var spinner = document.createElement("span");
        spinner.className = "spinner";
        spinner.setAttribute("aria-hidden", "true");
        button.appendChild(spinner);
        button.appendChild(document.createTextNode(text));
      }
      // выключить кнопку после того, как браузер собрал данные формы: иначе её name и value не уйдут
      window.setTimeout(function () { if (button._busy) button.disabled = true; }, 0);
    } else {
      if (!button._busy) return;
      if (button.tagName === "BUTTON") {
        while (button.firstChild) button.removeChild(button.firstChild);
        button._busy.forEach(function (node) { button.appendChild(node); });
      }
      button._busy = null;
      button.removeAttribute("aria-busy");
      button.disabled = false;
    }
  }
  function busyText(form, button) {
    return (button && button.getAttribute("data-busy")) || (form && form.getAttribute("data-busy")) || "";
  }
  function initBusy() {
    document.addEventListener("submit", function (event) {
      var form = event.target;
      if (event.defaultPrevented || !form || form.hasAttribute("data-ajax")) return;
      if (form._submitting) { event.preventDefault(); return; }
      var button = busyButton(form, event.submitter || null);
      if (button) { form._submitting = true; setBusy(button, true, busyText(form, button)); }
    });
    // страница вернулась из кэша браузера (кнопка «Назад»): кнопки снова доступны
    window.addEventListener("pageshow", function (event) {
      if (!event.persisted) return;
      $all("[aria-busy=true]").forEach(function (button) { setBusy(button, false); });
      $all("form").forEach(function (form) { form._submitting = false; });
    });
  }

  // form[data-ajax]: отправка без перезагрузки, ответ – по договорённости об ответе JSON
  function formData(form, submitter) {
    var data = null;
    if (submitter) {
      try { data = new FormData(form, submitter); } catch (e) { data = null; /* старый браузер – добавим кнопку сами */ }
    }
    if (!data) {
      data = new FormData(form);
      if (submitter && submitter.name) data.append(submitter.name, submitter.value);
    }
    // data-include="id …": поля из других форм страницы (например, редакция решения #review-revision)
    (form.getAttribute("data-include") || "").split(/\s+/).forEach(function (id) {
      var field = byId(id);
      if (field && field.name && "value" in field) data.set(field.name, field.value);
    });
    return data;
  }
  function initAjaxForms() {
    document.addEventListener("submit", function (event) {
      var form = event.target;
      if (event.defaultPrevented || !form || !form.hasAttribute || !form.hasAttribute("data-ajax")) return;
      event.preventDefault();
      if (form._sending) return;
      var submitter = event.submitter || null;
      var data = formData(form, submitter);
      var method = (submitter && submitter.getAttribute("formmethod")) || form.getAttribute("method") || "post";
      var url = (submitter && submitter.getAttribute("formaction")) || form.getAttribute("action")
        || window.location.pathname + window.location.search;
      var button = busyButton(form, submitter) || submitter;
      form._sending = true;
      setBusy(button, true, busyText(form, button));
      request(method, url, data).then(function (answer) {
        if (answer._navigated) return;
        applyAnswer(answer);
        if (form.hasAttribute("data-ajax-reset")) form.reset();
        form.dispatchEvent(new CustomEvent("lt:done", { bubbles: true, detail: answer }));
      }, function (error) {
        toast(error.message, { tone: "err" });
        form.dispatchEvent(new CustomEvent("lt:error", { bubbles: true,
          detail: { message: error.message, status: error.status, answer: error.answer } }));
      }).then(function () {
        form._sending = false;
        setBusy(button, false);
      });
    });
  }

  // form[data-autosubmit]: флажки, переключатели и списки отправляют форму сразу
  function initAutosubmit() {
    document.addEventListener("change", function (event) {
      var field = event.target;
      var form = field && (field.form || closest(field, "form"));
      if (!form || !form.hasAttribute("data-autosubmit")) return;
      if (!(field.matches && field.matches("input[type=checkbox], input[type=radio], select"))) return;
      if (form.requestSubmit) form.requestSubmit();
      else form.submit();
    });
  }

  // «Параметры проекта»: смена профиля сразу показывает модели его сервера, до «Сохранить параметры».
  // Выбранная модель остаётся, если она есть в новом списке; без JS список меняется после сохранения
  function initProjectModels() {
    var provider = byId("project-provider");
    var select = byId("project-model");
    var status = byId("project-model-status");
    var url = provider ? localUrl(provider.getAttribute("data-models")) : "";
    if (!url || !select) return;
    var save = provider.form ? provider.form.querySelector("button[type=submit]") : null;
    var asked = 0;
    var shown = provider.value;  // профиль, чей список моделей сейчас в форме
    function say(text) { if (status) status.textContent = text; }
    function hold(on) { if (save) save.disabled = on; }
    provider.addEventListener("change", function () {
      var ticket = ++asked;
      var params = new URLSearchParams();
      params.append("provider_id", provider.value);
      say("Загружаю список моделей профиля…");
      hold(true);  // новый профиль со старым списком не сохраняется
      request("GET", url, params, { follow: false }).then(function (answer) {
        if (ticket !== asked) return;
        shown = provider.value;
        hold(false);
        var keep = select.value;
        var found = false;
        select.textContent = "";
        (answer.options || []).forEach(function (item) {
          var option = document.createElement("option");
          option.value = String(item.value || "");
          option.textContent = String(item.label || item.value || "");
          if (item.selected) option.selected = true;
          if (option.value === keep) found = true;
          select.appendChild(option);
        });
        if (found) select.value = keep;
        say(answer.error ? String(answer.error)
          : "Модели – с сервера профиля «" + String(answer.profile || "") + "». Профиль и модель станут профилем и " +
            "моделью проекта после «Сохранить параметры».");
      }, function (error) {
        if (ticket !== asked) return;
        provider.value = shown;  // список в форме – прежнего профиля: и профиль прежний
        hold(false);
        say(error.message + " Профиль оставлен прежним.");
      });
    });
  }

  // [data-poll="/адрес"]: опрос раз в data-poll-interval мс, пока ответ не придёт с done: true
  function initPolls() {
    $all("[data-poll]").forEach(pollElement);
  }
  // Опрос состояния для элемента с data-poll: ответ – по договорённости об ответе JSON, done – остановка
  function pollElement(el) {
    (function () {
      var url = el.getAttribute("data-poll");
      if (!localUrl(url)) return;
      var every = Math.max(1000, Number(el.getAttribute("data-poll-interval")) || 2000);
      var failures = 0;
      function schedule(ms) { window.setTimeout(tick, ms); }
      function tick() {
        if (el._stopped) return;
        if (document.hidden) { schedule(every); return; }
        request("GET", url, null, { follow: false }).then(function (answer) {
          failures = 0;
          applyAnswer(answer);
          el.dispatchEvent(new CustomEvent("lt:poll", { bubbles: true, detail: answer }));
          if (answer.done || answer._navigated) { el._stopped = true; return; }
          schedule(every);
        }, function (error) {
          failures += 1;
          if (failures === 3) toast(error.status === 0 ? error.message : "Состояние не обновляется: " + error.message, { tone: "err" });
          schedule(Math.min(every * (failures + 1), 15000));
        });
      }
      schedule(every);
    })();
  }

  // После постановки операции в Hub (ADR-0114, ADR-0115) – «Проверить связь», «Отправить в Hub», «Сверить» –
  // страница опрашивает её состояние раз в 2 с; элемент состояния заменяется, прежний опрос останавливается
  function pollAfter(formId, statusId) {
    var form = byId(formId);
    if (!form) return;
    form.addEventListener("lt:done", function (event) {
      var answer = event.detail || {};
      var status = byId(statusId);
      if (!status || !answer.status_url || answer.done) return;
      status._stopped = true;
      var fresh = status.cloneNode(true);
      status.parentNode.replaceChild(fresh, status);
      fresh.setAttribute("data-poll", answer.status_url);
      pollElement(fresh);
    });
  }
  function initHubProbe() {
    pollAfter("hub-probe-form", "hub-probe-status");
    pollAfter("hub-send-form", "hub-send-status");
    pollAfter("hub-verify-form", "hub-send-status");
    // «Создать дефект в Hub» (ADR-0120): заготовка, «Создать», «Сверить» – тот же опрос состояния
    pollAfter("hub-defect-form", "hub-defect-status");
    pollAfter("hub-defect-create-form", "hub-defect-status");
    pollAfter("hub-defect-verify-form", "hub-defect-status");
    // «Привязать к дефекту» (ADR-0121) – тот же опрос состояния; «Проверить в Hub» убрана в dev33
    pollAfter("hub-defect-link-form", "hub-defect-status");
    // находка в дефекте, созданном в Hub (ADR-0121): снятие отметки – только с подтверждением. Без скрипта флажок
    // виден сразу; со скриптом – после отказа 409 reason=defect, с текстом отказа (статус с dev32 через дефект:
    // формы отправки у такой находки нет)
    [["unenter-form", "unenter-defect-row", "unenter-defect-text"]].forEach(function (ids) {
      var boundForm = byId(ids[0]);
      var boundRow = byId(ids[1]);
      if (!boundForm || !boundRow) return;
      boundRow.hidden = true;
      var boundBox = boundRow.querySelector("input[type=checkbox]");
      if (boundBox) boundBox.checked = false;
      boundForm.addEventListener("lt:error", function (event) {
        var answer = event.detail && event.detail.answer;
        if (!answer || answer.reason !== "defect") return;
        var text = byId(ids[2]);
        if (text) text.textContent = answer.detail || event.detail.message || "";
        boundRow.hidden = false;
        if (boundBox) boundBox.focus();
      });
      boundForm.addEventListener("lt:done", function () {
        boundRow.hidden = true;
        if (boundBox) boundBox.checked = false;
      });
    });
    // быстрый срок: кнопка заполняет поле даты по data-date-for (даты посчитаны сервером)
    $all("[data-date-for]").forEach(function (button) {
      button.addEventListener("click", function () {
        var field = byId(button.getAttribute("data-date-for"));
        if (!field) return;
        field.value = button.getAttribute("data-date-value") || "";
        field.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
    // срок в Hub (ADR-0115): Hub хранит конец выбранного дня по UTC и показывает его в часовом поясе браузера –
    // подпись под полем повторяет то, что покажет Hub
    var expires = byId("hub-send-expires");
    // «как в прошлый раз»: дата последней отправки запомнена в браузере и попадает в поле только по нажатию – без
    // умолчания; вне допустимых дат кнопки нет
    var lastExpires = byId("hub-send-last");
    if (expires && lastExpires) {
      var remembered = storageGet(LAST_EXPIRES) || "";
      var fits = /^\d{4}-\d{2}-\d{2}$/.test(remembered) && (!expires.min || remembered >= expires.min)
        && (!expires.max || remembered <= expires.max);
      lastExpires.hidden = !fits;
      lastExpires.title = fits ? remembered : "";
      lastExpires.addEventListener("click", function () {
        expires.value = remembered;
        expires.dispatchEvent(new Event("change", { bubbles: true }));
      });
      // карточка отправляет запросом и сообщает итог (lt:done), общая форма списка – обычной отправкой
      var rememberExpires = function () { if (expires.value) storageSet(LAST_EXPIRES, expires.value); };
      if (expires.form) expires.form.addEventListener(expires.form.id === "hub-send-form" ? "lt:done" : "submit", rememberExpires);
    }
    var untilPreview = byId("hub-send-until-preview");
    if (expires && untilPreview) {
      var showUntil = function () {
        var day = expires.value;
        untilPreview.hidden = !/^\d{4}-\d{2}-\d{2}$/.test(day);
        untilPreview.textContent = untilPreview.hidden ? "" : "до " + localTime(day + "T23:59:59Z") + " по вашему времени";
      };
      expires.addEventListener("change", showUntil);
      expires.addEventListener("input", showUntil);
      showUntil();
    }
  }

  // .dropzone: имя выбранного файла и подсветка при перетаскивании
  function initDropzones() {
    $all(".dropzone").forEach(function (zone) {
      var input = $("input[type=file]", zone);
      var out = $(".dropzone-file", zone);
      if (!input) return;
      var show = function () {
        if (!out) return;
        var files = Array.prototype.slice.call(input.files || []);
        var names = files.map(function (file) { return file.name; }).join(", ");
        zone.classList.toggle("has-file", files.length > 0);
        if (!files.length) { out.textContent = ""; return; }
        var form = closest(zone, "form");
        var button = form && $("button[type=submit]", form);
        var bad = (input.getAttribute("accept") || "").indexOf(".zip") >= 0 && files.some(function (file) {
          return !/\.zip$/i.test(file.name);
        });
        if (bad) { out.textContent = "Выбран файл " + names + " – это не архив .zip. Выберите архив .zip."; return; }
        var mb = files.reduce(function (sum, file) { return sum + file.size; }, 0) / 1048576;
        out.textContent = "Выбран файл " + names + " (" + mb.toFixed(1).replace(".", ",") + " МБ). Теперь нажмите «"
          + (button ? button.textContent.trim() : "Загрузить") + "».";
      };
      input.addEventListener("change", show);
      ["dragenter", "dragover"].forEach(function (type) {
        zone.addEventListener(type, function () { zone.classList.add("is-over"); });
      });
      ["dragleave", "dragend", "drop"].forEach(function (type) {
        zone.addEventListener(type, function () { zone.classList.remove("is-over"); });
      });
      show();
    });
  }

  // #feed-elapsed: сколько идёт загрузка справочника – «12 с», «1 мин 05 с»; отсчёт от значения сервера
  function initElapsed() {
    var el = byId("feed-elapsed");
    if (!el) return;
    var start = Date.now() - (Number(el.getAttribute("data-elapsed")) || 0) * 1000;
    function draw() {
      var s = Math.max(0, Math.floor((Date.now() - start) / 1000));
      el.textContent = s < 60 ? s + " с" : Math.floor(s / 60) + " мин " + String(s % 60).padStart(2, "0") + " с";
    }
    draw();
    window.setInterval(draw, 1000);
  }

  // [data-fill-fields='{"имя": значение}']: подставляет значения в поля своей формы (рекомендуемые значения DeepSeek
  // в профиле провайдера); флажки – true/false; сохраняет форма, как обычно
  function initFillFields() {
    document.addEventListener("click", function (event) {
      var button = closest(event.target, "[data-fill-fields]");
      if (!button || !button.form) return;
      var values;
      try { values = JSON.parse(button.getAttribute("data-fill-fields")); } catch (e) { return; }
      var filled = 0;
      Object.keys(values).forEach(function (name) {
        var field = button.form.elements[name];
        if (!field || field.length > 1 && !field.tagName) return;
        if (field.type === "checkbox") field.checked = values[name] === true;
        else field.value = String(values[name]);
        field.dispatchEvent(new Event("change", { bubbles: true }));
        filled += 1;
      });
      var status = byId(button.getAttribute("data-fill-status") || "");
      if (status) status.textContent = "Подставлено полей: " + filled + ". Нажмите «Сохранить» внизу страницы.";
    });
  }

  // [data-dismiss] закрывает ближайшее сообщение
  function initDismiss() {
    document.addEventListener("click", function (event) {
      var button = closest(event.target, "[data-dismiss]");
      if (!button) return;
      var box = closest(button, ".callout, .flash, [data-dismissible]");
      if (box) box.hidden = true;
    });
  }

  // .checklist[data-store-key]: отметки запоминаются в браузере; [data-checklist-count] – «Отмечено 2 из 4»
  function initChecklists() {
    $all(".checklist[data-store-key]").forEach(function (list) {
      var key = "local-triage-check:" + list.getAttribute("data-store-key");
      var boxes = $all("input[type=checkbox]", list);
      var saved = [];
      try { saved = JSON.parse(storageGet(key) || "[]"); } catch (e) { saved = []; }
      if (!Array.isArray(saved)) saved = [];
      boxes.forEach(function (box, k) { if (saved.indexOf(k) >= 0) box.checked = true; });
      var counter = list.parentNode ? $("[data-checklist-count]", list.parentNode) : null;
      var update = function (store) {
        var done = [];
        boxes.forEach(function (box, k) { if (box.checked) done.push(k); });
        if (store) {
          if (done.length) storageSet(key, JSON.stringify(done));
          else storageRemove(key);
        }
        if (counter) counter.textContent = "Отмечено " + done.length + " из " + boxes.length;
      };
      boxes.forEach(function (box) { box.addEventListener("change", function () { update(true); }); });
      update(false);
    });
  }

  // details[data-remember]: раскрыт или свёрнут – запоминается
  function initRemember() {
    $all("details[data-remember]").forEach(function (details) {
      var key = "local-triage-open:" + details.getAttribute("data-remember");
      var saved = storageGet(key);
      if (details.hasAttribute("data-force-open") || location.hash === "#" + details.id) details.open = true;
      else if (saved === "1") details.open = true;
      else if (saved === "0") details.open = false;
      details.addEventListener("toggle", function () { storageSet(key, details.open ? "1" : "0"); });
    });
    function revealAnchor() {
      var id;
      try { id = decodeURIComponent(location.hash.slice(1)); } catch (e) { return; }
      var target = document.getElementById(id);
      var node = target, opened = false;
      while (node) {
        if (node.matches("details[data-remember]") && !node.open) { node.open = true; opened = true; }
        node = node.parentElement;
      }
      if (opened && target) target.scrollIntoView({ block: "start" });
    }
    window.addEventListener("hashchange", revealAnchor);
    revealAnchor();
  }

  // ------------------------------------------------------------------ окна

  function openDialog(dialog) {
    if (!dialog || dialog.open) return;
    if (dialog.id === "keys-dialog") markKeyHints(dialog);
    if (dialog.showModal) dialog.showModal();
    else dialog.setAttribute("open", "");
  }
  function closeDialog(dialog) {
    if (!dialog) return;
    if (dialog.close) dialog.close();
    else dialog.removeAttribute("open");
  }
  function initDialogs() {
    document.addEventListener("click", function (event) {
      var opener = closest(event.target, "[data-dialog-open]");
      if (opener) {
        event.preventDefault();
        openDialog(byId(opener.getAttribute("data-dialog-open")));
        return;
      }
      var closer = closest(event.target, "[data-dialog-close]");
      if (closer) {
        closeDialog(closest(closer, "dialog"));
        return;
      }
      // щелчок по затемнению вокруг окна закрывает его
      var target = event.target;
      if (target && target.tagName === "DIALOG" && target.open) {
        var rect = target.getBoundingClientRect();
        var inside = event.clientX >= rect.left && event.clientX <= rect.right
          && event.clientY >= rect.top && event.clientY <= rect.bottom;
        if (!inside) closeDialog(target);
      }
    });
  }

  // ------------------------------------------------------------------ страница проекта

  function initProject() {
    var form = $("#codebase-form");
    var save = $("#save-mapping");
    if (form && save) {
      // «Сохранить соответствие» выделяется, когда в таблице есть что сохранять
      form.addEventListener("change", function () { save.classList.add("btn-primary"); });
    }
    var models = $("#model-select");
    var info = $("#model-info");
    if (models && info) {
      var show = function () {
        var option = models.options[models.selectedIndex];
        info.textContent = option ? (option.getAttribute("data-info") || "") : "";
      };
      models.addEventListener("change", show);
      show();
    }
  }

  // ------------------------------------------------------------------ код

  function centerRow(box, row, smooth, visibleOnly) {
    var rect = box.getBoundingClientRect();
    var delta = row.getBoundingClientRect().top - rect.top;
    var height = box.clientHeight;
    if (visibleOnly) {  // страница не сдвигалась: по середине видимой части окна кода – низ может закрывать нижняя панель
      var bar = $(".action-bar");
      var limit = Math.min(window.innerHeight || document.documentElement.clientHeight,
                           bar ? bar.getBoundingClientRect().top : Infinity);
      height = Math.max(row.offsetHeight, Math.min(rect.bottom, limit) - Math.max(rect.top, 0));
    }
    var top = box.scrollTop + delta - height / 2 + row.offsetHeight / 2;
    // строка у конца среза: окну кода не хватает прокрутки – запас снизу, как у строки срабатывания
    var short = top - (box.scrollHeight - box.clientHeight);
    if (visibleOnly && short > 0) box.style.paddingBottom = Math.ceil(short) + "px";
    if (smooth && box.scrollTo) box.scrollTo({ top: top, behavior: "smooth" });
    else box.scrollTop = top;
  }
  // Строка из адреса (#L14) или строка срабатывания – в верхнюю часть окна кода (три строки выше неё видны): на первом
  // экране низ окна кода закрыт нижней панелью, а строка срабатывания должна быть видна
  function centerTargetLine() {
    var hash = /^#L(\d+)$/.exec(window.location.hash || "");
    var wanted = hash ? byId("L" + hash[1]) : null;
    $all(".code").forEach(function (box) {
      var row = wanted && box.contains(wanted) ? wanted : $("tr.is-target", box);
      if (!row) return;
      box.style.paddingBottom = "";
      var delta = row.getBoundingClientRect().top - box.getBoundingClientRect().top;
      var top = box.scrollTop + delta - Math.min(box.clientHeight / 2, 2 * row.offsetHeight);
      // строка близко к концу файла: окно кода не докрутить – пустое место после последней строки, как в редакторе,
      // иначе строка срабатывания остаётся внизу окна, под нижней панелью
      var short = top - (box.scrollHeight - box.clientHeight);
      if (short > 0) box.style.paddingBottom = Math.ceil(short) + "px";
      box.scrollTop = top;
    });
  }
  // Прокрутка к строке N кода и короткая подсветка; окно кода при необходимости – в видимую часть страницы
  function showLine(n) {
    var row = byId("L" + n);
    if (!row) { codeMissing(n); return false; }
    revealCode(row);  // переход к строке раскрывает код; сохранённое предпочтение не меняется
    var smooth = !reducedMotion();
    var box = closest(row, ".code");
    if (box) {
      var rect = box.getBoundingClientRect();
      var height = window.innerHeight || document.documentElement.clientHeight;
      // код стоит рядом с разбором и закреплён (0.9.23.dev5): страница сдвигается, только если окно кода ушло выше
      // экрана или начинается ниже его середины; иначе строка показывается прокруткой внутри окна кода
      var move = rect.top < 0 || rect.top > height * 0.6;
      if (move) {
        box.scrollIntoView({ block: rect.height > height ? "start" : "nearest", behavior: smooth ? "smooth" : "auto" });
      }
      centerRow(box, row, smooth, !move);
    } else {
      row.scrollIntoView({ block: "center", behavior: smooth ? "smooth" : "auto" });
    }
    row.classList.remove("is-flash");
    void row.offsetWidth;  // перезапуск подсветки при повторном нажатии
    row.classList.add("is-flash");
    window.clearTimeout(row._flash);
    row._flash = window.setTimeout(function () { row.classList.remove("is-flash"); }, 1900);
    return true;
  }
  function lineOf(el) {
    var n = el.getAttribute("data-line") || (el.getAttribute("href") || "").replace(/^#L/, "");
    return /^\d+$/.test(n) ? n : "";
  }
  // «строка N» в тексте модели (a.line-ref) и [data-line]: прокрутка к строке; при наведении строка в рамке
  function initLineRefs() {
    document.addEventListener("click", function (event) {
      if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey
          || event.altKey) return;
      var link = closest(event.target, "a.line-ref, [data-line]");
      var n = link ? lineOf(link) : "";
      if (n && showLine(n)) event.preventDefault();
    });
    var hover = function (on) {
      return function (event) {
        var link = closest(event.target, "a.line-ref, [data-line]");
        var n = link ? lineOf(link) : "";
        var row = n ? byId("L" + n) : null;
        if (row) row.classList.toggle("is-hover", on);
      };
    };
    document.addEventListener("mouseover", hover(true));
    document.addEventListener("mouseout", hover(false));
    document.addEventListener("focusin", hover(true));
    document.addEventListener("focusout", hover(false));
  }

  // Сворачивание кода карточки SAST (#code-toggle, #code-body). Состояние – предпочтение оператора: записывается
  // только по его нажатию и действует на следующих карточках. Переход к строке (ссылка #L<n>, «строка N»,
  // адрес с #L<n>, LocalTriage.showLine) раскрывает код до прокрутки и предпочтение не трогает. Общий механизм
  // details[data-remember] здесь не подходит: он записывает и программное раскрытие
  var CODE_FOLD_SETTING = "local-triage-code-folded";
  function codeFold() { return { panel: byId("step-3"), body: byId("code-body"), button: byId("code-toggle") }; }
  function setCodeFolded(folded) {
    var f = codeFold();
    if (!f.body || !f.button) return;
    f.body.hidden = folded;
    if (f.panel) f.panel.classList.toggle("is-collapsed", folded);
    f.button.setAttribute("aria-expanded", folded ? "false" : "true");
    f.button.textContent = f.button.getAttribute(folded ? "data-label-closed" : "data-label-open") || f.button.textContent;
    if (!folded) centerTargetLine();
  }
  function revealCode(row) {
    var f = codeFold();
    if (f.body && f.body.hidden && (!row || f.body.contains(row))) setCodeFolded(false);
  }
  function codeMissing(n) {
    var text = "Строки " + n + " нет в показанном коде: модель или ссылка указали строку вне окна кода.";
    var note = byId("code-missing");
    if (note) { note.textContent = text; note.hidden = false; }
    toast(text, { tone: "warn" });
  }
  function initCodeFold() {
    var f = codeFold();
    if (!f.body || !f.button) return;
    var hash = /^#L(\d+)$/.exec(window.location.hash || "");
    if (storageGet(CODE_FOLD_SETTING) === "1" && !hash) setCodeFolded(true);
    if (hash && !byId("L" + hash[1])) codeMissing(hash[1]);
    f.button.addEventListener("click", function () {
      var folded = !f.body.hidden;
      storageSet(CODE_FOLD_SETTING, folded ? "1" : "0");
      setCodeFolded(folded);
      f.button.focus();  // фокус остаётся на переключателе
    });
    // ссылки сверки (a[href="#L<n>"]) – до перехода браузера: свёрнутый код раскрывается, отсутствующая строка – сообщение
    document.addEventListener("click", function (event) {
      if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey) return;
      var link = closest(event.target, "a[href^='#L']");
      var m = link ? /^#L(\d+)$/.exec(link.getAttribute("href")) : null;
      if (!m) return;
      var row = byId("L" + m[1]);
      if (!row) { event.preventDefault(); codeMissing(m[1]); return; }
      revealCode(row);
      if (window.location.hash === "#L" + m[1]) { event.preventDefault(); showLine(m[1]); }
    }, true);
    window.addEventListener("hashchange", function () {
      var m = /^#L(\d+)$/.exec(window.location.hash || "");
      if (m) showLine(m[1]);
    });
  }

  // Перенос длинных строк кода: без выбора человека – на узком экране переносится, на широком – прокрутка вбок
  var WRAP_SETTING = "local-triage-wrap";
  var LAST_EXPIRES = "local-triage-hub-expires";  // срок статуса последней отправки в Hub

  function initWrap() {
    var buttons = $all("#wrap-toggle, [data-wrap-toggle]");
    var boxes = $all(".code");
    if (!boxes.length) return;
    function apply(on) {
      boxes.forEach(function (box) { box.classList.toggle("code-wrap", on); });
      buttons.forEach(function (button) { button.setAttribute("aria-pressed", on ? "true" : "false"); });
      centerTargetLine();
    }
    // Ключевые строки (срабатывание и строки из объяснения) не помещаются по ширине окна кода. Правая граница –
    // по области содержимого (clientWidth): полоса прокрутки не должна прятать хвост строки
    function keyLinesClipped() {
      return boxes.some(function (box) {
        var right = box.getBoundingClientRect().left + box.clientLeft + box.clientWidth;
        return $all("tr.is-target td.src, tr.is-evidence td.src", box).some(function (td) {
          var range = document.createRange();
          range.selectNodeContents(td);
          return range.getBoundingClientRect().right > right + 1;
        });
      });
    }
    var stored = storageGet(WRAP_SETTING);
    var narrow = !!(window.matchMedia && window.matchMedia("(max-width: 760px)").matches);
    if (stored === "on" || stored === "off") {
      apply(stored === "on");
    } else {
      // без выбора человека: перенос на узком экране и там, где ключевые строки не помещаются по ширине
      apply(false);
      if (narrow || keyLinesClipped()) apply(true);
    }
    buttons.forEach(function (button) {
      button.addEventListener("click", function () {
        var on = button.getAttribute("aria-pressed") !== "true";
        storageSet(WRAP_SETTING, on ? "on" : "off");
        apply(on);
      });
    });
  }

  // ------------------------------------------------------------------ карточка находки

  // Клавиши не перехватываются только там, где печатают; переключатели и флажки им не мешают
  // поля даты и времени – тоже ввод: цифры и буквы в них не должны менять решение (ADR-0115, срок статуса)
  var TEXT_INPUTS = ["text", "search", "email", "url", "number", "password", "tel", "date", "datetime-local", "month",
    "week", "time"];

  function isTyping(target) {
    if (!target) return false;
    var tag = target.tagName;
    if (tag === "INPUT") return TEXT_INPUTS.indexOf((target.type || "text").toLowerCase()) >= 0;
    return tag === "TEXTAREA" || tag === "SELECT" || !!target.isContentEditable;
  }

  var card = null;  // элементы карточки для клавиш

  function initReview() {
    var form = $("#review-form");
    if (!form) return;
    var modelVerdict = form.getAttribute("data-model-verdict") || "";
    var modelComment = form.getAttribute("data-model-comment") || "";
    // к какому исходу написан текст модели (сервер, model_comment_verdict): «Ложное срабатывание…» не идёт в дефект и при вердикте «истинная»
    var modelCommentFor = form.getAttribute("data-model-comment-for") || modelVerdict;
    // совет агента расходится с исследованием: вывод, текст и «Проверено» не подставляются, пока оператор не подтвердил совет
    var conflictConfirm = $("#advice-conflict-confirm input");
    function conflictOpen() { return !!conflictConfirm && !conflictConfirm.checked; }
    var select = $("#final-verdict");
    var comment = $("#comment");
    // Уточнение решения SCA по ГОСТ Р КАПО: только в карточке SCA; варианты зависят от итога решения
    var kapo = $("#kapo-state");
    var kapoField = $("#kapo-field");
    var hint = $("#comment-hint");
    var reviewedBox = $("#reviewed-box");
    var unreviewedNote = $("#unreviewed-note");
    var unreviewedWarn = $("#unreviewed-warn");  // заметное предупреждение рядом с «Сохранить»
    var riskHint = $("#risk-hint");
    var radios = $all("input[name=decision]");
    var preview = $("#hub-text");
    var previewBox = $("#hub-preview");
    var staleNote = $("#hub-stale");
    var copyButton = $("#copy-hub");
    // SAST с 0.9.6 (ADR-0089): два исхода – «Ложное срабатывание» (короткий комментарий) и «Подтверждаю дефект»
    // (обоснование и рекомендация дефекта); поле рекомендации и подписи комментария зависят от исхода
    var fixBox = $("#fix");
    var fixField = $("#fix-field");
    var commentLabel = $("#comment-label");
    var commentCount = $("#comment-count");
    var nextButton = $("#next-btn");
    var status = $("#copy-status");
    var dirtyNote = $("#dirty-note");  // надпись в нижней панели: правки формы ещё не сохранены
    // узкий экран: тост сверху лёг бы на решение, а то же сообщение уже есть в строке нижней панели
    function narrowCard() { return !!(window.matchMedia && window.matchMedia("(max-width: 760px)").matches); }
    var manualButton = $("#copied-manually");
    var copiedRevision = "";  // редакция решения, текст которой показан для копирования вручную
    // заготовка комментария – текст модели: при «Не согласен» он не подходит к другому вердикту
    var prefilled = !!modelComment && comment && comment.value === modelComment;
    var dirty = false;
    var saving = false;  // обычное «Сохранить» отправлено, ответа ещё нет
    window.addEventListener("pageshow", function (event) { if (event.persisted) saving = false; });
    var edits = 0;  // номер правки формы: ответ на прежний снимок не должен снимать отметку о более поздних правках
    // Пришёл новый ответ агента, который человек ещё не видел: токен ответа в форме остаётся прежним (сервер отклонит новое
    // сохранение), копирование отложено до обновления карточки; введённый вариант решения переживает обновление как черновик
    var answerBlocked = false;
    // HTML-ответ на отказ сохранения имеет адрес /review, но черновик остаётся общим с карточкой.
    var DRAFT_KEY = "local-triage-draft:" + window.location.pathname.replace(/\/review$/, "");
    function draftBasis() {
      var basis = {};
      ["finding_version", "verdict_id", "code_hash", "answer_id", "review_revision"].forEach(function (name) {
        basis[name] = form.elements[name] ? form.elements[name].value : "";
      });
      return basis;
    }
    // пакетное решение SCA: какие находки версии отмечены (своя – всегда, её галочка недоступна)
    function packageChoice() {
      if (!$("#package-apply")) return null;
      return $all("#package-apply input[name=apply_to]").filter(function (box) {
        return box.checked && !box.disabled;
      }).map(function (box) { return box.value; });
    }
    function draftSave(submitted) {
      try {
        window.sessionStorage.setItem(DRAFT_KEY, JSON.stringify({
          d: (radios.filter(function (r) { return r.checked; })[0] || { value: "" }).value,
          v: select ? select.value : "", c: comment ? comment.value : "", x: fixBox ? fixBox.value : "",
          r: !!(reviewedBox && reviewedBox.checked),
          k: kapo ? kapo.value : "", p: packageChoice(), basis: draftBasis(), submitted: !!submitted }));
        return true;
      } catch (e) { return false; }
    }
    function draftTake() {
      try {
        var raw = window.sessionStorage.getItem(DRAFT_KEY);
        window.sessionStorage.removeItem(DRAFT_KEY);
        var parsed = raw ? JSON.parse(raw) : null;
        if (!parsed || typeof parsed !== "object") return null;
        var currentBasis = draftBasis();
        parsed.revisionChanged = !parsed.basis || parsed.basis.review_revision !== currentBasis.review_revision;
        parsed.basisChanged = !parsed.basis || Object.keys(currentBasis).some(function (name) {
          return parsed.basis[name] !== currentBasis[name];
        });
        // Собственное успешное сохранение тоже меняет редакцию: совпавший отправленный черновик уже не нужен.
        var savedSubmission = parsed.submitted && /^(sca_)?saved$/.test(
          new URLSearchParams(window.location.search).get("ok") || "") && form.getAttribute("data-draft") !== "1";
        // После успешного сохранения форма с сервера уже содержит этот текст – старый черновик не нужен.
        if ((!parsed.basisChanged || savedSubmission)
            && parsed.d === (radios.filter(function (r) { return r.checked; })[0] || {value: ""}).value
            && parsed.v === (select ? select.value : "") && parsed.c === (comment ? comment.value : "")
            && (typeof parsed.x !== "string" || parsed.x === (fixBox ? fixBox.value : ""))
            && (typeof parsed.k !== "string" || kapoValue(parsed.k) === kapoValue(kapo ? kapo.value : ""))
            && (typeof parsed.r !== "boolean" || parsed.r === !!(reviewedBox && reviewedBox.checked))
            && (!Array.isArray(parsed.p) || parsed.p.join("\n") === (packageChoice() || []).join("\n"))) return null;
        return parsed;
      } catch (e) { return null; }
    }
    offerPackageReload = function (text) {
      offerReload(text || "Другие находки этой версии изменились: обновите карточку.");
    };
    function offerReload(text) {
      answerBlocked = true;
      if (copyButton) copyButton.disabled = true;
      say(status, text, true, true);
      var holder = status ? status.parentNode : null;
      if (holder && !$("#reload-card")) {
        var reload = document.createElement("button");
        reload.type = "button";
        reload.className = "btn btn-small";
        reload.id = "reload-card";
        reload.textContent = "Обновить карточку";
        reload.addEventListener("click", function () { draftSave(); window.location.reload(); });
        holder.appendChild(reload);
      }
      routeAccent();  // карточка SAST: главная кнопка – «Обновить карточку»
      var again = $("#reload-card");
      if (again && byId("route")) again.focus();
    }

    function decision() {
      var checked = radios.filter(function (r) { return r.checked; })[0];
      return checked ? checked.value : "";
    }
    function sastOutcome(d) { return d === "false_positive" || d === "true_positive"; }
    // SCA с 0.9.8 (ADR-0091 п. 3): короткий текст – только у «Ложное срабатывание» и «Риск принят»; у «Обновить»
    // и «Отложить» кнопки копирования короткого текста нет (карточку SCA отличает поле уточнения по ГОСТ Р КАПО)
    function scaOutcome() {
      var d = decision();
      if (d === "agree") return modelVerdict;
      if (d === "disagree") return select ? select.value : "";
      return d === "risk_accepted" ? "risk_accepted" : "";
    }
    function syncScaCopy() {
      if (!kapo || !copyButton) return;
      var o = scaOutcome();
      var shown = o === "false_positive" || o === "risk_accepted";
      if (copyButton.hidden === shown) copyButton.hidden = !shown;
      // переход к отправке – только у решения, которое уходит статусом (план dev7, раздел 4)
      var goSend = $("#go-send");
      if (goSend) {
        if (goSend.hidden === shown) goSend.hidden = !shown;
        goSend.classList.toggle("btn-primary", shown && !copyButton.classList.contains("btn-primary"));
      }
      // переход к созданию дефекта – только у вывода «обновить»
      var goCreate = $("#go-create");
      if (goCreate) {
        goCreate.hidden = o !== "true_positive";
        // другой итог идёт коротким текстом и отметкой: этап «создание» скрывал бы её (CSS панели)
        var stageBar = closest(goCreate, ".action-bar");
        if (stageBar) {
          if (o === "true_positive") stageBar.setAttribute("data-stage", "create");
          else stageBar.removeAttribute("data-stage");
        }
      }
    }
    // вывод выбран рукой, а решение ещё не отмечено: это своё решение, второй раз выбирать то же незачем. Только действие человека:
    // подставленный из совета вывод так не становится решением (план dev7, раздел 5)
    if (kapo && select) select.addEventListener("change", function () {
      if (decision() || !select.value) return;
      var chosen = select.value;
      var own = radios.filter(function (r) { return r.value === "disagree"; })[0];
      if (!own) return;
      own.checked = true;
      own.dispatchEvent(new Event("change", { bubbles: true }));
      select.value = chosen;  // обработчик «своего решения» сбрасывает вывод, совпавший с советом: здесь он выбран явно
    });
    if (kapo && copyButton) {
      radios.forEach(function (r) { r.addEventListener("change", syncScaCopy); });
      if (select) select.addEventListener("change", syncScaCopy);
      syncScaCopy();
    }
    // Подписи и поля формы SAST по исходу: у дефекта – «Обоснование» и «Рекомендация» (заготовка – рекомендация
    // модели), у ложного срабатывания – короткий комментарий и счётчик знаков; короткий текст – только у ложного
    // Рекомендация дефекта – пункты оператора (ADR-0092): поле само не заполняется; пункты модели переносит только
    // кнопка «Взять пункты из рекомендации модели»
    function syncSast(fromChoice) {
      if (!fixField && !commentLabel) return;
      var d = decision();
      var tp = d === "true_positive";
      if (fixField) fixField.hidden = !tp;
      if (commentLabel) {
        commentLabel.textContent = commentLabel.getAttribute(tp ? "data-label-tp"
          : (d === "false_positive" ? "data-label-fp" : "data-label-none")) || commentLabel.textContent;
      }
      if (comment) {
        var holder = comment.getAttribute(tp ? "data-placeholder-tp" : "data-placeholder-fp");
        if (holder) comment.placeholder = holder;
      }
      // комментарий для Hub – только у ложного срабатывания: у дефекта – полный текст, отложенная находка в Hub не идёт
      if (copyButton) copyButton.hidden = tp || d === "later";
      if (previewBox) previewBox.hidden = tp || d === "later";
      countComment();
    }
    var HUB_COMMENT_WARN = 250;  // Р8: порог предупреждения о длине комментария для Hub
  function countComment() {
      if (!commentCount || !comment) return;
      var n = comment.value.trim().length;
      var d = decision();
      var parts = [];
      if (n) parts.push(n + " " + (n % 10 === 1 && n % 100 !== 11 ? "знак"
        : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? "знака" : "знаков")));
      if (d === "false_positive") parts.push(commentCount.getAttribute("data-fp-hint") || "");
      // Р8: комментарий ложного срабатывания длиннее 250 знаков в списке Hub обрежется –
      // предупреждение, сохранение не запрещается
      var warn = d === "false_positive" && n > HUB_COMMENT_WARN;
      if (warn) parts.push("Длиннее " + HUB_COMMENT_WARN + " знаков – в списке Hub комментарий обрежется.");
      commentCount.textContent = parts.join(" · ");
      commentCount.classList.toggle("text-warn", warn);
    }
    // Варианты уточнения по итогу: «Подтверждено» – анализ не завершён или актуальна; «Риск принят» – неактуальна
    // или нейтрализована (выбор обязателен, сервер проверяет то же); у остальных итогов поле скрыто
    // «по выводу» у «Подтверждено» – то же, что «анализ не завершён»: так нормализует сервер
    var lastKapoOutcome = null;  // итог при прошлой синхронизации: подстановка по умолчанию – только при смене итога
    // выбранное уточнение по каждому итогу: переключили итог и вернулись – выбор человека возвращается, а не стирается
    // (иначе сохранённое «актуальна» терялось, и форма после перезагрузки считалась изменённой)
    var keptKapo = {};
    function kapoValue(value) {
      var d = decision();
      var outcome = d === "agree" && modelVerdict ? modelVerdict : (select ? select.value : "");
      return !value && d !== "risk_accepted" && d !== "later" && outcome === "true_positive" ? "not_finished" : value;
    }
    function kapoOutcome() {
      var d = decision();
      return d === "risk_accepted" ? "risk_accepted" : (d === "later" || !d ? ""
        : (d === "agree" && modelVerdict ? modelVerdict : (select ? select.value : "")));
    }
    function syncKapo() {
      if (!kapo || !kapoField) return;
      var d = decision();
      var outcome = kapoOutcome();
      var shown = outcome === "true_positive" || outcome === "risk_accepted";
      kapoField.hidden = !shown;
      // строка о расхождении совета агента с версией дефекта – только у вывода «обновить»
      var targetNote = $("#target-note");
      if (targetNote) targetNote.hidden = d === "risk_accepted" || d === "later"
        || (d === "agree" && modelVerdict ? modelVerdict : (select ? select.value : "")) !== "true_positive";
      Array.prototype.forEach.call(kapo.options, function (option) {
        var own = option.getAttribute("data-outcome");
        option.hidden = !!own && own !== outcome;
        option.disabled = option.hidden;
      });
      var current = kapo.options[kapo.selectedIndex];
      // пустой выбор тоже запоминается: очищенное оператором уточнение не возвращается (ревью Codex 09.11, круг 2)
      if (lastKapoOutcome && lastKapoOutcome !== outcome) keptKapo[lastKapoOutcome] = kapo.value;
      if (!shown || (current && current.disabled)) kapo.value = "";
      var kept = keptKapo[outcome];
      if (shown && !kapo.value && kept && lastKapoOutcome !== outcome) {
        var keptOption = Array.prototype.filter.call(kapo.options, function (option) { return option.value === kept; })[0];
        if (keptOption && !keptOption.disabled) kapo.value = kept;
      }
      // новое решение «обновить»: уточнение по умолчанию – «актуальна» (data-kapo-default ставит сервер только
      // у карточки без сохранённого решения); подставляется при появлении итога «Подтверждено», явный выбор не перебивается
      var preset = kapo.getAttribute("data-kapo-default");
      if (preset && shown && outcome === "true_positive" && !kapo.value && lastKapoOutcome !== "true_positive") kapo.value = preset;
      lastKapoOutcome = outcome;
      // пустой вариант называет, что за ним стоит: у «Подтверждено» – «анализ не завершён», у «Риск принят» выбор обязателен
      var empty = kapo.options[0];
      if (empty && !empty.value) {
        empty.textContent = outcome === "risk_accepted" ? "выберите состояние…" : "по выводу (сейчас: анализ не завершён)";
      }
    }
    // Решение изменено, но не сохранено: текст для Hub ещё прежний, а уход со страницы браузер переспросит.
    // Главная кнопка снова «Скопировать для Hub»: скопированный раньше текст уже не совпадает с формой
    function setDirty(value) {
      dirty = value;
      if (dirtyNote) dirtyNote.hidden = !value;
      if (value) {
        var defectConfirm = $("#defect-confirm");
        if (defectConfirm) defectConfirm.checked = false;
      }
      if (typeof syncCopyWhere === "function") syncCopyWhere(!!(defectBar && !defectBar.hidden));
      if (preview) preview.classList.toggle("is-stale", value);
      if (staleNote) staleNote.hidden = !value;
      if (!value) { try { window.sessionStorage.removeItem(DRAFT_KEY); } catch (e) { /* нет хранилища */ } return; }
      draftSave();
      accentCopy();
      // «Решение сохранено, текст скопирован» к изменённой форме уже не относится; предупреждения остаются
      if (status && status.textContent && !status.classList.contains("is-error")) status.textContent = "";
    }
    // «Отложить» – находка остаётся непроверенной; «Согласен» и «Не согласен» ставят «Проверено» сами
    function syncReviewed(auto) {
      var d = decision();
      if (!reviewedBox) return;
      if (d === "later") {
        reviewedBox.checked = false;
        reviewedBox.disabled = true;
      } else {
        reviewedBox.disabled = false;
        if (auto && !(d === "agree" && conflictOpen()) && (d === "agree" || d === "disagree" || d === "risk_accepted" || sastOutcome(d))) reviewedBox.checked = true;
      }
      if (unreviewedNote) {
        unreviewedNote.hidden = !d || reviewedBox.checked;
        unreviewedNote.textContent = d === "later" ? "Отложено: находка останется непроверенной"
          : "Находка останется непроверенной";
      }
      if (unreviewedWarn) unreviewedWarn.hidden = !d || d === "later" || reviewedBox.checked;
    }
    function syncRiskHint() {
      if (riskHint) riskHint.hidden = decision() !== "risk_accepted";
      syncVerdictUse();
    }
    // При «Риск принят» и «Отложить» статус в Hub задаёт решение, а не список вердиктов: это сказано под списком
    function syncVerdictUse() {
      var note = $("#verdict-unused");
      if (!note || !select) return;
      var d = decision();
      var text = d === "risk_accepted" ? note.getAttribute("data-risk") : (d === "later" ? note.getAttribute("data-later") : "");
      note.textContent = text || "";
      note.hidden = !text;
      select.classList.toggle("is-unused", !!text);
    }
    function checkHint() {
      if (!hint || !comment) return;
      hint.hidden = !(decision() === "disagree" && prefilled && comment.value.trim() && comment.value !== modelComment);
    }
    // Комментарий модели к другому вердикту (п. 10 проверки этапа 1): текст без правки, написанный моделью
    // к вердикту data-comment-for (или к её текущему вердикту), а в Hub уйдёт другой – поле подсвечено,
    // копирование для Hub – только после правки текста или отметки «Текст проверен» (сервер проверяет то же)
    var commentStale = $("#comment-stale");
    var confirmLabel = $("#comment-confirm-label");
    var confirmBox = $("#comment-confirm");
    var commentFor = comment ? (comment.getAttribute("data-comment-for") || "") : "";
    var initialComment = comment ? comment.value.trim() : "";
    function staleComment() {
      if (!comment) return false;
      var text = comment.value.trim();
      var origin = "";
      if (text && commentFor && text === initialComment) origin = commentFor;
      else if (text && modelComment && text === modelComment.trim()) origin = modelCommentFor;
      var d = decision();
      if (!d) return false;  // решение не выбрано – в Hub пока ничего не уходит (сервер: comment_stale = False)
      var target = sastOutcome(d) ? d : (d === "later" ? "uncertain" : (d === "risk_accepted" ? "risk_accepted"
        : (d === "agree" && modelVerdict ? modelVerdict : ((select && select.value) || "uncertain"))));
      return !!origin && origin !== target;
    }
    function checkComment() {
      if (!comment || !commentStale || !confirmLabel) return;
      var stale = staleComment();
      commentStale.hidden = !stale;
      confirmLabel.hidden = !stale;
      comment.classList.toggle("is-stale", stale);
      if (stale) comment.setAttribute("aria-invalid", "true");
      else comment.removeAttribute("aria-invalid");
      if (!stale && confirmBox) confirmBox.checked = false;
    }

    radios.forEach(function (radio) {
      radio.addEventListener("change", function () {
        if (!radio.checked) return;
        if (radio.value === "agree") {
          if (!conflictOpen()) {
            if (modelVerdict && select) select.value = modelVerdict;
            if (comment && !comment.value.trim() && modelComment) comment.value = modelComment;
          }
        } else if (radio.value === "disagree") {
          if (select && select.value === modelVerdict) select.value = "";  // свой вердикт – выбрать явно
          // текст модели написан под её вердикт: в Hub с другим статусом он не годится. Курсор остаётся на выборе:
          // стрелками можно перейти к другому решению, к незаполненному полю он перейдёт при сохранении
          if (comment && modelComment && comment.value === modelComment) comment.value = "";
        } else if (sastOutcome(radio.value)) {
          // комментарий модели написан под её вердикт: подходит, только если решение с ним совпадает
          if (comment && modelComment) {
            if (radio.value === modelCommentFor && !comment.value.trim()) comment.value = modelComment;
            else if (radio.value !== modelCommentFor && comment.value === modelComment) comment.value = "";
          }
        } else if (radio.value === "risk_accepted" && comment) {
          // «Риск принят» сохраняется только с обоснованием
          if (!comment.value.trim()) comment.placeholder = "Почему риск принимается и при каком условии решение пересматривается – без обоснования решение не сохранится";
        }
        syncReviewed(true);
        syncKapo();
        syncRiskHint();
        syncSast(true);
        checkHint();
        checkComment();
      });
    });
    // после обработчика вывода, который может переключить «Согласен» на «Не согласен»
    if (select) select.addEventListener("change", function () { window.setTimeout(syncKapo, 0); });
    // вывод «обновить»: комментарий из исследования, если поле пустое или в нём неизменённая заготовка агента; текст оператора не
    // затирается (план dev7, раздел 6). После обработчика вывода, который переключает «Согласен» на своё решение
    var updateComment = form.getAttribute("data-update-comment") || "";
    if (select && comment && updateComment) select.addEventListener("change", function () {
      window.setTimeout(function () {
        var text = comment.value.trim();
        if (select.value !== "true_positive" || (text && text !== modelComment.trim())) return;
        comment.value = updateComment;
        comment.dispatchEvent(new Event("input", { bubbles: true }));
      }, 0);
    });
    if (reviewedBox) reviewedBox.addEventListener("change", function () { syncReviewed(false); });
    if (conflictConfirm) conflictConfirm.addEventListener("change", function () {
      if (!conflictConfirm.checked || decision() !== "agree") return;
      if (modelVerdict && select) select.value = modelVerdict;
      if (comment && !comment.value.trim() && modelComment) comment.value = modelComment;
      syncReviewed(true);
      edited({ target: conflictConfirm });  // флажок вне формы: её обработчики этого изменения не слышат
    });
    if (comment) comment.addEventListener("input", checkHint);
    if (comment) comment.addEventListener("input", checkComment);
    if (comment) comment.addEventListener("input", countComment);
    // «Взять решение и текст» у находки той же строки и категории: решение, комментарий и рекомендация – как у неё.
    // Подставляется в форму, но не сохраняется (бэклог 32): «Сохранить» подсвечивается, рядом – подсказка (живая
    // область: текст ставится при показе, чтобы её озвучили). Снимается только подтверждённым сохранением: обычная
    // отправка формы перезагружает страницу, сохранение через «Скопировать» – в ветке успеха (edits === sent);
    // отменённая отправка (не заполнено поле) и отказ сервера подсказку не снимают
    var takeNote = $("#take-note");
    var saveButton = $("#save-btn");
    function showTaken(value) {
      if (takeNote) {
        takeNote.hidden = !value;
        takeNote.textContent = value ? (takeNote.getAttribute("data-text") || "") : "";
      }
      if (saveButton) saveButton.classList.toggle("is-attention", value);
    }
    $all("[data-take-outcome]").forEach(function (button) {
      button.addEventListener("click", function () {
        if (dirty && !window.confirm("Заменить несохранённое решение и текст данными соседней находки?")) return;
        showTaken(true);
        var radio = radios.filter(function (r) { return r.value === button.getAttribute("data-take-outcome"); })[0];
        if (radio && !radio.checked) {
          radio.checked = true;
          radio.dispatchEvent(new Event("change", { bubbles: true }));
        }
        if (comment) {
          comment.value = button.getAttribute("data-take-comment") || "";
          comment.dispatchEvent(new Event("input", { bubbles: true }));
        }
        if (fixBox) {
          fixBox.value = button.getAttribute("data-take-fix") || "";
          fixBox.dispatchEvent(new Event("input", { bubbles: true }));
        }
        if (comment) comment.focus();
      });
    });
    // «Взять пункты из этого разбора» в истории разборов (ADR-0097): пункты прежнего ответа модели – в поле
    // рекомендации шага 5, как кнопка у текущего разбора; рекомендация нужна только для «Подтверждаю дефект»
    $all(".take-history-fix").forEach(function (button) {
      if (!fixBox) return;
      button.hidden = false;  // без скрипта кнопка не работает – и не показывается
      button.addEventListener("click", function () {
        var points = button.getAttribute("data-points") || "";
        var current = fixBox.value.replace(/\s+$/, "");
        var joined = current ? current + "\n" + points : points;
        var limit = parseInt(fixBox.getAttribute("maxlength") || "0", 10);
        if (limit && joined.length > limit) {
          toast("Пункты не перенесены: вместе с вашим текстом рекомендация длиннее " + limit + " знаков.", { tone: "err" });
          return;
        }
        fixBox.value = joined;
        fixBox.dispatchEvent(new Event("input", { bubbles: true }));
        if (decision() === "true_positive") {
          fixBox.scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" });
          try { fixBox.focus({ preventScroll: true }); } catch (e) { fixBox.focus(); }
          toast("Пункты прежнего разбора перенесены в рекомендацию. Проверьте и поправьте их.", { tone: "ok" });
        } else {
          toast("Пункты перенесены в рекомендацию шага 5 – она уходит в Hub только при решении «Подтверждаю дефект».",
            { tone: "info" });
        }
      });
    });
    var takeModelFix = $("#take-model-fix");
    if (takeModelFix && fixBox) {
      takeModelFix.addEventListener("click", function () {
        var points = takeModelFix.getAttribute("data-points") || "";
        var current = fixBox.value.replace(/\s+$/, "");
        var joined = current ? current + "\n" + points : points;
        var limit = parseInt(fixBox.getAttribute("maxlength") || "0", 10);
        if (limit && joined.length > limit) {  // не обрезать введённое: пункты не переносятся, причина – в сообщении
          toast("Пункты модели не перенесены: вместе с вашим текстом рекомендация длиннее " + limit + " знаков.",
            { tone: "err" });
          return;
        }
        fixBox.value = joined;
        fixBox.dispatchEvent(new Event("input", { bubbles: true }));
        fixBox.focus();
        toast(takeModelFix.getAttribute("data-code-dropped")
          ? "Пункты модели перенесены, пример кода – нет. Проверьте и поправьте пункты."
          : "Пункты модели перенесены. Проверьте и поправьте их.", { tone: "ok" });
      });
    }
    syncSast(false);
    syncReviewed(false);
    syncKapo();
    syncRiskHint();
    checkComment();
    // «Текст проверен» не сохраняется в решении – это подтверждение при выдаче текста, а не правка формы
    // подтверждение «дефект в Hub останется прежним» (ADR-0121) – к одной правке: новая правка и сохранение
    // копированием его снимают, следующая смена решения снова спрашивает
    function resetBound() {
      var boundBox = $("#defect-bound-confirm");
      if (boundBox) boundBox.checked = false;
      var boundRow = $("#defect-bound-row");
      if (boundRow) boundRow.hidden = true;
    }
    function edited(event) {
      // и подтверждение «дефект в Hub останется прежним» (ADR-0121) – не правка решения
      if (event && event.target && (event.target.id === "comment-confirm"
        || event.target.id === "defect-bound-confirm")) return;
      resetBound();
      // правка решения или комментария – «Текст проверен» относился к прежнему тексту: отметить заново
      if (confirmBox) confirmBox.checked = false;
      var defectComment = $("#defect-comment-confirm");
      if (defectComment) defectComment.checked = false;
      edits += 1;
      setDirty(true);
    }
    form.addEventListener("input", edited);
    form.addEventListener("change", edited);
    // элементы панели решения стоят вне формы (атрибут form): их изменения – тоже правки формы; смена решения
    // снимает и «Текст проверен» (отметка относилась к прежнему итогу)
    radios.forEach(function (el) { el.addEventListener("change", edited); });
    if (reviewedBox) reviewedBox.addEventListener("change", function () { edits += 1; setDirty(true); });
    // Обязательное поле не заполнено: сохранение не уходит, курсор – в это поле (сервер проверяет то же).
    // Подробная причина – у самого поля (связана с ним через aria-describedby, поле – aria-invalid), в нижней
    // панели – коротко; когда условие выполнено (поле заполнено, решение сменилось), ошибка гаснет сама
    var SHORT_MISSING = {"comment": "Не сохранено: нужен комментарий – обоснование решения",
      "final-verdict": "Не сохранено: выберите итоговый вердикт", "kapo-state": "Не сохранено: уточните состояние по ГОСТ Р КАПО"};
    // Текст для Hub – решение человека: без выбранного решения ответ модели не копируется (сервер проверяет то же)
    var NO_DECISION = "Не скопировано: выберите решение – ответ модели ещё не принят";
    function stopIfNoDecision() {
      if (!radios.length || decision()) return false;
      say(status, NO_DECISION, true, true);
      var bar = closest(status, ".action-bar");
      if (bar) bar.scrollTop = 0;
      var first = radios.filter(function (r) { return !r.disabled; })[0];
      if (first) { try { first.focus({ preventScroll: true }); } catch (e) { first.focus(); } }
      // карточка SAST: варианты решения – в шаге 5; прокрутить к ним с учётом закреплённых оглавления и панели
      var choice = first && byId("route") ? closest(first, "fieldset") || first : null;
      if (choice) choice.scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" });
      return true;
    }
    var shownErrors = [];
    // Пункты рекомендации словами – правило defect.has_recommendation: строки вне ограды ``` или ~~~ и вне отступа
    // в четыре пробела или табуляцию, маркер списка снят, есть буква (У2: пустая рекомендация не уходит на сервер).
    // Слова пункта – как написал оператор: теги и прочее не вырезаются, как и на сервере.
    // clean – только для проверки, есть ли пункт: пустой тег пунктом не считается (как defect.has_recommendation)
    function recommendationPoints(text, clean) {
      var fence = "";
      var points = [];
      String(text || "").replace(/\r\n/g, "\n").split("\n").forEach(function (raw) {
        var mark = /^\s{0,3}(`{3,}|~{3,})/.exec(raw);
        if (mark) {
          if (!fence) fence = mark[1];
          else if (mark[1][0] === fence[0] && mark[1].length >= fence.length && !raw.trim().slice(mark[1].length)) fence = "";
          return;
        }
        if (fence || (/^( {4}|\t)/.test(raw) && raw.trim())) return;
        var line = raw.trim().replace(/^[ \t]*(?:[0-9]{1,2}\)[ \t]*|[0-9]{1,2}\.[ \t]+|[-*•][ \t]+)/, "").trim();
        var cleaned = line.replace(/<[^>]*>/g, "").trim();
        // пункт ли это – по прежнему критерию, как на сервере (defect.recommendation_points): пустой тег пунктом не
        // считается и рядом с другим пунктом; слова – как написаны, отступ строки в 1–3 пробела остаётся; clean – без них
        if (/[A-Za-zА-Яа-яЁё]/.test(cleaned)) points.push(clean ? cleaned : /^ */.exec(raw)[0] + line);
      });
      return points;
    }
    function hasRecommendation(text) { return recommendationPoints(text, true).length > 0; }
    // У5: под полем – какие пункты уйдут в Hub (код в Hub не идёт, ADR-0098); строки, похожие на код без ограды, –
    // предупреждение: распознавание по признакам ненадёжно, поэтому без запрета
    var fixPreview = byId("fix-preview");
    var fixCodeWarn = byId("fix-code-warn");
    function syncFixPreview() {
      if (!fixBox || !fixPreview) return;
      // пунктов по прежнему критерию нет (например, один пустой тег) – сервер рекомендацию не примет, обещать нечего
      var points = hasRecommendation(fixBox.value) ? recommendationPoints(fixBox.value) : [];
      fixPreview.hidden = !points.length;
      // по пункту в строке, пробелы видны (white-space: pre-wrap в app.css): отступ – перед номером, как в тексте
      // дефекта (defect._point)
      fixPreview.textContent = points.length ? "В Hub уйдут пункты:\n" + points.map(function (p, i) {
        var text = p.replace(/^ +/, "");
        return p.slice(0, p.length - text.length) + (i + 1) + ") " + text;
      }).join("\n") : "";
      if (fixCodeWarn) {
        var code = points.filter(function (p) {
          var bare = p.replace(/<[^>]*>/g, "").trim();  // признаки кода – по тексту без тегов (ревью круга 7)
          return /[;{}]\s*$/.test(bare) || /^(?:return|import|from|def|class|public|private|protected|static|var|let|const)\b/.test(bare);
        });
        fixCodeWarn.hidden = !code.length;
      }
    }
    if (fixBox && fixPreview) {
      fixBox.addEventListener("input", syncFixPreview);
      syncFixPreview();
    }
    function missingField() {
      var d = decision();
      if (d === "risk_accepted" && comment && !comment.value.trim()) return [comment, form.getAttribute("data-need-reason")];
      if (sastOutcome(d) && comment && !comment.value.trim()) {
        return [comment, form.getAttribute(d === "true_positive" ? "data-need-reason-tp" : "data-need-reason-fp")];
      }
      if (d === "true_positive" && fixBox && !hasRecommendation(fixBox.value)) {
        return [fixBox, form.getAttribute("data-need-fix")];
      }
      if (d === "risk_accepted" && kapo && kapoField && !kapoField.hidden && !kapo.value) {
        return [kapo, form.getAttribute("data-need-kapo")];
      }
      if (d === "disagree" && select && !select.value) return [select, form.getAttribute("data-need-verdict")];
      return null;
    }
    function fieldError(field) {
      var id = field.id + "-error";
      var box = byId(id);
      if (!box) {
        box = document.createElement("span");
        box.id = id;
        box.className = "field-error small";
        box.hidden = true;
        (closest(field, ".field") || field.parentNode).appendChild(box);
      }
      return box;
    }
    function clearFieldError(field) {
      var box = byId(field.id + "-error");
      if (!box || box.hidden) return;
      box.hidden = true;
      box.textContent = "";
      var ids = (field.getAttribute("aria-describedby") || "").split(/\s+/).filter(function (x) { return x && x !== box.id; });
      if (ids.length) field.setAttribute("aria-describedby", ids.join(" "));
      else field.removeAttribute("aria-describedby");
      field.removeAttribute("aria-invalid");
      if (field === comment) checkComment();  // у комментария aria-invalid ставит и проверка «написан под другой вывод»
      if (status && status.textContent === SHORT_MISSING[field.id]) say(status, "", true);
    }
    function refreshErrors() {
      var missing = missingField();
      shownErrors = shownErrors.filter(function (field) {
        if (missing && missing[0] === field) {
          field.setAttribute("aria-invalid", "true");  // проверка «комментарий к другому выводу» могла его снять
          return true;
        }
        clearFieldError(field);
        return false;
      });
    }
    function stopIfMissing() {
      var missing = missingField();
      if (!missing) return false;
      var field = missing[0];
      var box = fieldError(field);
      box.textContent = missing[1] || "Заполните обязательное поле";
      box.hidden = false;
      var ids = (field.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean);
      if (ids.indexOf(box.id) < 0) field.setAttribute("aria-describedby", ids.concat(box.id).join(" "));
      field.setAttribute("aria-invalid", "true");
      if (shownErrors.indexOf(field) < 0) shownErrors.push(field);
      say(status, SHORT_MISSING[field.id] || box.textContent, true, true);
      var bar = closest(status, ".action-bar");
      if (bar) bar.scrollTop = 0;  // на узком экране строка состояния – вверху панели, панель может быть прокручена
      try { field.focus({ preventScroll: true }); } catch (e) { field.focus(); }
      // поле вместе с текстом ошибки – над нижней панелью: панель только что выросла от сообщения, её высоту
      // меряем сейчас, а не ждём пересчёта переменной --bar-h
      box.scrollIntoView({ block: "nearest" });
      if (bar) {
        var barTop = bar.getBoundingClientRect().top;
        var over = box.getBoundingClientRect().bottom - barTop + 8;
        if (over > 0 && barTop < window.innerHeight) window.scrollBy(0, over);
      }
      return true;
    }
    form.addEventListener("input", refreshErrors);
    form.addEventListener("change", refreshErrors);
    radios.forEach(function (radio) { radio.addEventListener("change", refreshErrors); });
    form.addEventListener("submit", function (event) {
      if (stopIfMissing()) { event.preventDefault(); return; }
      draftSave(true);
      dirty = false;
      saving = true;  // сохранение ушло, страница перейдёт по ответу: «Отправить в Hub» до тех пор не отправляет
    });
    // решение не сохранилось (страница устарела), и в форме – введённое человеком: уход переспросит
    if (form.getAttribute("data-draft") === "1") setDirty(true);
    window.addEventListener("beforeunload", function (event) {
      if (!dirty || draftSave()) return;
      event.preventDefault();
      event.returnValue = "";
    });
    // «Согласен» – это вердикт модели: другой итоговый вердикт переключает решение на «Не согласен»
    if (select) {
      select.addEventListener("change", function () {
        var agree = radios.filter(function (r) { return r.value === "agree"; })[0];
        var disagree = radios.filter(function (r) { return r.value === "disagree"; })[0];
        if (agree && agree.checked && disagree && select.value && select.value !== modelVerdict) {
          disagree.checked = true;
          syncReviewed(true);
          checkHint();
        }
        checkComment();
        syncScaCopy();  // после возможного переключения на «Не согласен»: кнопка короткого текста – по итоговому исходу
      });
    }

    function updateProgress(progress) {
      var box = $("#nav-progress");
      if (!box || !progress) return;
      var bar = $("#progress-bar", box);
      var label = $("#progress-label", box);
      if (bar) { bar.max = Math.max(1, progress.total); bar.value = progress.reviewed; }
      if (label) {
        label.textContent = "Проверено " + progress.reviewed + " из " + progress.total + " · осталось "
          + Math.max(0, progress.total - progress.reviewed);
      }
    }
    function markCopied(copiedAt) {
      var note = $("#copied-at");
      if (note && copiedAt) renderTimestamp(note, {prefix: "Скопировано для Hub ", datetime: copiedAt, suffix: "."});
    }
    // отметка «скопировано» по ответу сервера: снятая отметка (текст изменился) убирается и со страницы
    function syncCopied(answer) {
      if (!answer || !("copied_at" in answer)) return;
      var note = $("#copied-at");
      if (answer.copied_at) markCopied(answer.copied_at);
      else if (note) note.textContent = "";
    }
    // карточка SCA без маршрута шагов: главная кнопка – прежним порядком (копирование → отметка → «Дальше»)
    function plainAccent(target) {
      [$("#go-create"), $("#go-send"), copyButton, $("#mark-entered"), nextButton].forEach(function (button) {
        if (button) button.classList.toggle("btn-primary", button === target);
      });
    }
    // главная кнопка дальше – «Дальше»: следующий шаг после вставки в Hub
    function accentNext() {
      if (byId("route")) {  // карточка SAST: главная кнопка – по этапу маршрута (routeAccent), фокус – на неё
        routeAccent();
        var primary = $(".action-bar .btn-primary");
        if (primary && !primary.hidden && !primary.disabled) { primary.focus(); return; }
      } else {
        plainAccent(nextButton);
      }
      if (nextButton) nextButton.focus();
    }
    function accentCopy() {  // без переноса фокуса: человек может печатать
      if (byId("route")) {
        routeCopied = false;  // правка после копирования: в Hub уйдёт новый текст
        routeAccent();
      } else {
        plainAccent(copyButton);
      }
    }
    // Отпечаток выданного текста для отметки «Внесено в Hub»: сервер сверит его с текущим текстом
    function setEnteredHash(answer) {
      var field = $("#entered-text-hash");
      if (field && answer && typeof answer.entered_hash === "string" && answer.entered_hash) field.value = answer.entered_hash;
      // «Отправить в Hub» (ADR-0115): отпечаток сохранённого текста – тот, что сверит сервер
      var sendField = $("#hub-send-text-hash");
      if (sendField && answer && typeof answer.hub_send_hash === "string") sendField.value = answer.hub_send_hash;
      // решение сохранено и текст выдан: пояснение «решение не сохранено» больше не верно
      var sendNote = $("#hub-send-note");
      if (sendNote && answer && answer.hub_send_hash) sendNote.hidden = true;
      syncReplace(answer);
    }
    // Режим «Обновить комментарий в Hub» (dev29): статус уже стоит в Hub, а сохранённого текста там нет – сервер
    // решает по ответу сохранения; панель переключается без перезагрузки карточки
    function syncReplace(answer) {
      var mode = answer && answer.hub_replace;
      var form = $("#hub-send-form");
      if (!form || !mode || typeof mode !== "object") return;
      var active = !!mode.active;
      var flag = $("#hub-send-replace");
      if (active && !flag) {
        flag = document.createElement("input");
        flag.type = "hidden";
        flag.name = "replace";
        flag.value = "1";
        flag.id = "hub-send-replace";
        form.appendChild(flag);
      } else if (!active && flag) {
        flag.parentNode.removeChild(flag);
      }
      var note = $("#hub-send-replace-note");
      if (note) { note.textContent = active ? String(mode.note || "") : ""; note.hidden = !active; }
      var label = $("#hub-send-replace-confirm");
      if (label) label.hidden = !active;
      var text = $("#hub-send-replace-text");
      if (text) text.textContent = active ? String(mode.check || "") : "";
      var box = $("#hub-send-replace-box");
      if (box) { box.required = active; if (!active) box.checked = false; }
      var button = $("#hub-send-button");
      if (button) button.textContent = active ? "Обновить комментарий в Hub" : "Отправить в Hub";
      // строка последней операции (отказ «already has…») – по текущему решению; операции в работе опрашиваются
      if (typeof mode.status_text === "string") {
        var line = $("#hub-send-status");
        if (line && !line.getAttribute("data-poll")) {
          line.textContent = mode.status_text;
          line.hidden = !mode.status_text;
          line.className = "small hub-send-status" + (mode.status_tone ? " text-" + mode.status_tone : "");
        }
      }
      // прежний срок статуса – в пустое поле (как при сборке карточки сервером)
      var expires = $("#hub-send-expires");
      if (active && expires && !expires.value && typeof mode.expires === "string" && mode.expires) {
        expires.value = mode.expires;
        expires.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
    // Сервер снял отметку «Внесено в Hub» (решение изменилось): пояснения о прежней отметке больше не верны
    function syncEntered(answer) {
      if (!answer || answer.entered === true) return;
      ["#entered-format-updated", "#entered-defect-format-updated", "#entered-changed", "#entered-unconfirmed",
       "#entered-bulk"].forEach(function (selector) {
        var note = $(selector);
        if (note) note.hidden = true;
      });
      ["#entered-badge", "#entered-note"].forEach(function (selector) {
        var mark = $(selector);
        if (mark) {
          mark.hidden = true;
          mark.removeAttribute("title");
        }
      });
      var at = $("#entered-at");
      if (at) at.textContent = "";
      // кнопка – снова «Отметить», а не «Подтвердить»: прежней отметки больше нет
      var button = $("#mark-entered");
      if (button && button.firstChild && button.firstChild.nodeType === 3) {
        // у SAST – что сделано в Hub при сохранённом исходе (с 0.9.2 – «точная подпись»): у дефекта
        // статус находки не меняется; у SCA – прежняя надпись
        button.firstChild.nodeValue = commentLabel && decision() === "true_positive" ? "Отметить: дефект создан в Hub "
          : "Отметить: статус и комментарий внесены в Hub ";
      }
      var badgeText = $("#entered-badge");
      if (badgeText && commentLabel) {
        badgeText.textContent = decision() === "true_positive" ? "✓ дефект создан в Hub" : "✓ статус и комментарий в Hub";
      }
    }
    // После копирования: «Отметить: внесено в Hub» показывается и получает акцент; без неё – сразу «Дальше»
    function accentEntered(answer) {
      var mark = $("#mark-entered");
      // карточка SAST: текст скопирован – этап маршрута считается и тогда, когда отметка уже стоит (прежняя отметка
      // при изменившемся тексте ждёт подтверждения)
      if (byId("route")) routeCopied = true;
      // отметка уже стоит (ответ копирования сообщает entered) или кнопка снимает её – акцент на «Дальше»
      if (!mark || mark.disabled || mark.value === "0" || (answer && answer.entered === true)) {
        if (byId("route")) {
          routeAccent();
          var bar = $(".action-bar");
          if (mark && !mark.hidden && bar && bar.getAttribute("data-stage") === "mark") {
            mark.focus();
            return true;
          }
        }
        return false;
      }
      mark.hidden = false;
      var markForm = mark.form || closest(mark, "form");
      if (markForm && markForm.hidden) markForm.hidden = false;
      if (byId("route")) {
        routeCopied = true;  // текст скопирован: этап – «Отметить: внесено в Hub»
        routeAccent();
      } else {
        plainAccent(mark);
      }
      mark.focus();
      return true;
    }
    // Отметка «Внесено в Hub» поставлена (форма кнопки #mark-entered ответила): дальше – «Дальше»
    document.addEventListener("lt:done", function (event) {
      var source = event.target;
      if (!source || !source.querySelector || !source.querySelector("#mark-entered")) return;
      if (status) status.textContent = "";  // «вставьте его в Hub» больше не к месту: отметка стоит
      // отметка подтверждена по текущему тексту: предупреждения о прежней отметке больше не верны
      routeEnteredStale = false;
      ["#entered-format-updated", "#entered-defect-format-updated", "#entered-changed", "#entered-unconfirmed",
       "#entered-bulk"].forEach(function (selector) {
        var note = $(selector);
        if (note) note.hidden = true;
      });
      if (!dirty) accentNext();
    });

    var post = function (url, body) {
      return fetch(url, {
        method: "POST",
        body: body,
        headers: { "Accept": "application/json" },
        credentials: "same-origin"
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (answer) {
          if (!response.ok) throw requestError(answer.detail || ("HTTP " + response.status), response.status, answer);
          return answer;
        });
      });
    };

    // копирование одно за раз: короткий текст и текст дефекта не перезапишут друг друга в буфере в порядке ответов
    var copyBusy = false;
    function setCopyBusy(value) {
      copyBusy = value;
      [copyButton, $("#copy-defect-bar"), $("#copy-title-bar"), $("#copy-defect-title"), $("#copy-defect-body")].forEach(function (b) {
        if (b) b.disabled = value || (b === copyButton && answerBlocked);
      });
    }
    function copyForHub() {
      if (!copyButton || copyButton.disabled || answerBlocked || copyBusy) return;
      if (fixField && decision() === "true_positive") {  // у дефекта – полный текст из раздела «Дефект для Hub»
        say(status, "Для подтверждённого дефекта сохраните решение и скопируйте текст дефекта (f)", true, true);
        return;
      }
      if (fixField && decision() === "later") {
        say(status, "Отложенная находка в Hub не переносится: выберите решение", true, true);
        return;
      }
      if (stopIfNoDecision() || stopIfMissing()) return;  // копирование сохраняет решение: те же обязательные поля
      // Комментарий модели к другому вердикту: такой текст в Hub противоречит статусу – копировать его можно после
      // правки или явной отметки «Текст проверен» (уходит вместе с формой). Отметка – флажком на странице, а не
      // окном подтверждения браузера (О7): окно перекрывало карточку и подтверждалось клавишей Enter не глядя
      checkComment();
      if (staleComment() && confirmBox && !confirmBox.checked) {
        say(status, "Комментарий написан моделью к другому вердикту, а в Hub уйдёт итоговый: поправьте текст или "
          + "отметьте «Текст проверен» и скопируйте ещё раз (c)", true, true);
        confirmBox.focus();
        return;
      }
      var data = new FormData(form);
      var sent = edits;  // снимок формы, который уходит на сервер
      data.set("action", "copy");
      setCopyBusy(true);
      if (manualButton) manualButton.hidden = true;
      post(form.getAttribute("action"), data)
        .then(function (answer) {
          // текст копируется, только если сервер подтвердил запись и разрешил копирование (находка есть в выгрузке)
          if (!answer || answer.copy_allowed !== true || typeof answer.hub_text !== "string") {
            say(status, "Текст не скопирован: сервер не подтвердил копирование. Обновите страницу.", true, true);
            return null;
          }
          if (preview) preview.textContent = answer.hub_text;
          // О9: у ложного срабатывания SAST короткий комментарий – весь текст для Hub, предпросмотр раскрыт
          var previewDetails = $("#hub-preview");
          if (previewDetails && $("#sast-form") && decision() === "false_positive") previewDetails.open = true;
          var previewNote = $("#hub-preview-note");  // текст выдан – пояснение «не показан» больше не верно
          if (previewNote) previewNote.hidden = true;
          resetBound();  // решение сохранено: подтверждение относилось к этой правке
          showDefect(answer);
          syncEntered(answer);
          setEnteredHash(answer);
          // до подтверждённого копирования этап – «скопировать»: прежняя отметка относилась к прежнему тексту
          routeCopied = false;
          syncCopied(answer);
          if (edits === sent) {  // пока ждали ответа, форму не меняли: сохранено то, что на экране
            setDirty(false);
            showTaken(false);  // подставленное решение сохранено – подсказка «сохраните» больше не нужна
            if (reviewedBox) reviewedBox.checked = !!answer.reviewed;
            syncReviewed(false);
          } else {
            setDirty(true);  // более поздние правки ещё не сохранены
          }
          var badge = $("#reviewed-badge");
          if (badge) badge.hidden = !answer.reviewed;
          // строка «итог разбора» под заголовком – по подтверждённому ответу сервера (ревью dev28)
          var summaryDecision = $("#finding-summary-decision");
          if (summaryDecision && typeof answer.summary_decision === "string") {
            summaryDecision.textContent = answer.summary_decision + (answer.reviewed ? ", проверено" : "");
            var summaryDraft = $("#finding-summary-draft");
            if (summaryDraft && edits === sent) summaryDraft.hidden = true;
          }
          updateProgress(answer.progress);
          copiedRevision = String(answer.revision || "");
          // форма дальше работает с сохранённой редакцией: иначе следующее сохранение сочтёт её устаревшей
          var revisionField = $("#review-revision");
          if (revisionField && answer.revision) revisionField.value = String(answer.revision);
          applyPackage(answer);
          // Номер ответа агента в форме не меняется, пока человек не увидел новый ответ: сервер сообщает answer_moved и
          // возвращает прежний номер. Иначе следующее «Проверено» стало бы согласием с ответом, которого он не видел
          if (answer.answer_moved) {
            offerReload(answer.notice || "Пришёл новый ответ агента: обновите карточку и сверьте решение с ним.");
          }
          return copyText(answer.hub_text).then(function (ok) {
            if (!ok) {
              if (previewBox) previewBox.open = true;
              if (preview) selectContents(preview);
              if (manualButton) manualButton.hidden = false;
              say(status, "Не скопировано в буфер: текст выделен – нажмите Ctrl+C, затем «Скопировал вручную»",
                true, true);
              return;
            }
            // пакетное решение (Б8): сохранено и для других находок версии – сведения, а не предупреждение
            var also = answer.applied && answer.applied.length
              ? " Решение сохранено и для находок: " + answer.applied.join(", ") + "." : "";
            if (answer.notice) {  // сохранено с оговоркой из ответа сервера
              say(status, answer.notice + also, true, true);
            } else if (edits === sent) {  // и пока шло копирование, форму тоже не меняли
              say(status, (decision() === "false_positive"
                ? "Решение сохранено, комментарий скопирован – вставьте его при смене статуса на «Ложное срабатывание» в Hub"
                : "Решение сохранено, короткий текст скопирован – вставьте его в комментарий к смене статуса в Hub") + also,
                true);
              if (!narrowCard()) toast("Комментарий для Hub скопирован", { announce: false });
              if (!accentEntered(answer)) accentNext();
            } else {  // в буфере – сохранённая редакция, а на экране уже другая: акцент остаётся на копировании
              say(status, "Скопирована сохранённая редакция, а форма с тех пор изменилась – скопируйте ещё раз",
                true, true);
            }
            setCopyBusy(false);  // буфер уже записан; отметка «скопировано» – отдельно, кнопки её не ждут
            confirmCopied();
          });
        })
        .catch(function (error) {
          if (preview) preview.classList.add("is-stale");
          var failure = "Не скопировано: " + (error && error.message ? error.message : "решение не сохранено – обновите страницу");
          // находка в дефекте, созданном в Hub (ADR-0121): решение меняется только с подтверждением – флажок в форме,
          // текст отказа рядом; повторное копирование уйдёт с ним
          if (error && error.answer && error.answer.reason === "defect") {
            var boundText = $("#defect-bound-text");
            if (boundText) boundText.textContent = error.answer.detail || "";
            var boundRow = $("#defect-bound-row");
            if (boundRow) boundRow.hidden = false;
            say(status, error.answer.detail || failure, true, true);
            var boundBox = $("#defect-bound-confirm");
            if (boundBox) boundBox.focus();
            return;
          }
          if (error && error.status === 409) {
            if (reviewedBox) reviewedBox.checked = false;
            syncReviewed(false);
            setDirty(true);
            offerReload(failure + " Решение, ответ модели или код изменились – проверьте решение заново. "
              + "Отметка «Проверено» снята.");
            return;
          }
          say(status, failure, true, true);
          if (error && error.answer && error.answer.reason === "answer") offerReload(failure);
        })
        .then(function () { setCopyBusy(false); });
    }
    // отметка «скопировано» – для той редакции, текст которой попал в буфер
    function confirmCopied() {
      if (!copiedRevision) return Promise.resolve(false);
      var confirmData = new FormData();
      confirmData.set("revision", copiedRevision);
      return post(form.getAttribute("data-copied-url"), confirmData)
        .then(function (mark) { markCopied(mark.copied_at); return true; })
        .catch(function () { return false; /* отметка о копировании не важна для работы */ });
    }
    if (copyButton) copyButton.addEventListener("click", copyForHub);

    // «Дефект для Hub»: заголовок и текст строит сервер по сохранённому решению; панель видна, когда дефект готов
    // (ответ сохранения сообщает defect_ready): у SAST – «Подтверждаю дефект» с обоснованием, у SCA – итог
    // «истинная» или «ложная»
    var defectPanel = $("#defect-panel");
    var defectForm = $("#defect-form");
    var defectStatus = $("#defect-status");
    var defectBar = $("#copy-defect-bar");
    var defectFromBar = false;  // копирование полного текста начато кнопкой внизу: сообщение – и рядом с ней
    var defectManual = $("#defect-copied-manually");
    var manualDefect = null;  // ответ выдачи, текст которого выделен для ручного копирования
    if (defectManual) {
      defectManual.addEventListener("click", function () {
        if (!manualDefect) return;
        var answer = manualDefect;
        copiedRevision = String(answer.revision);
        defectManual.disabled = true;
        confirmCopied().then(function (ok) {
          defectManual.disabled = false;
          if (!ok) {
            sayDefect("Отметка «скопировано» не поставлена: решение изменилось – обновите карточку и скопируйте "
              + "текст дефекта заново", true);
            return;
          }
          setEnteredHash(answer);
          if (typeof answer.entered === "boolean") syncEntered(answer);
          defectManual.hidden = true;
          sayDefect("Отмечено: текст дефекта скопирован вручную – вставьте его в Hub (описание дефекта).", false);
          if (!accentEntered(answer) && byId("route")) accentNext();  // отметка уже действует – фокус на главной
          manualDefect = null;
        });
      });
    }
    var copyWhere = $("#copy-where");
    // подсказка, куда вставлять тексты: по выбранному решению и готовности дефекта, при несохранённой правке –
    // сначала сохранить
    function syncCopyWhere(ready) {
      if (!copyWhere) return;
      var checked = $("input[name=decision]:checked");
      var choice = checked ? checked.value : "";
      var key = dirty ? "data-dirty" : (ready ? "data-ready" : "data-pending");
      if (copyWhere.hasAttribute("data-none")) {  // SAST: подсказка по выбранному решению (у SCA – прежняя)
        // ложное срабатывание сохраняется и копированием, дефект – только сохранением: их подсказка говорит, что
        // делать дальше, и при несохранённой правке; «Отложить» с правкой – общая «сохраните»
        // у статуса «Fixed» «сохраните» – только при несохранённой правке (data-fp-dirty есть только у него)
        if (choice === "false_positive") key = dirty && copyWhere.hasAttribute("data-fp-dirty") ? "data-fp-dirty" : "data-fp";
        else if (choice === "true_positive") key = ready && !dirty ? "data-ready" : "data-tp";
        else if (choice === "later") key = dirty ? "data-dirty" : "data-later";
        else key = "data-none";
      }
      copyWhere.textContent = copyWhere.getAttribute(key) || copyWhere.textContent;
    }
    $all("input[name=decision]").forEach(function (radio) {
      radio.addEventListener("change", function () { syncCopyWhere(!!(defectBar && !defectBar.hidden)); });
    });
    syncCopyWhere(!!(defectBar && !defectBar.hidden));  // черновик мог сделать форму изменённой ещё до этой строки
    function showDefect(answer) {
      if (answer && typeof answer.defect_ready === "boolean") {
        if (defectPanel) defectPanel.hidden = !answer.defect_ready;
        if (defectBar) defectBar.hidden = !answer.defect_ready;
        var titleBar = $("#copy-title-bar");
        if (titleBar) titleBar.hidden = !answer.defect_ready;
        syncCopyWhere(answer.defect_ready);
      }
      // подтверждение предупреждений относилось к прежней редакции решения
      var confirm = $("#defect-confirm");
      if (confirm) confirm.checked = false;
    }
    // «Внесено в Hub» – о сохранённом тексте: при несохранённых правках отметка не ставится
    var enteredForm = $("#entered-form");
    if (enteredForm) {
      var enteredLabel = $("#entered-confirm-label");  // без скрипта – свой флажок, со скриптом – общий «Текст проверен»
      if (enteredLabel) enteredLabel.hidden = true;
      enteredForm.addEventListener("submit", function (event) {
        // «Текст проверен» уходит и с отметкой: комментарий модели к другому вердикту сервер иначе не примет
        var flag = $("#entered-comment-confirm");
        if (flag) flag.checked = !!(confirmBox && confirmBox.checked);
        if (!dirty) return;
        event.preventDefault();
        say(status, "Решение изменено, но не сохранено: сохраните его, перенесите в Hub актуальный текст и затем "
          + "поставьте отметку «Внесено в Hub»", true, true);
      });
      // отказ из-за комментария модели к другому вердикту: показать отметку «Текст проверен», курсор – в комментарий
      enteredForm.addEventListener("lt:error", function (event) {
        var answer = event.detail && event.detail.answer;
        if (!answer || answer.reason !== "comment") return;
        if (commentStale) commentStale.hidden = false;
        if (confirmLabel) confirmLabel.hidden = false;
        say(status, answer.detail || event.detail.message, true, true);
        if (comment) comment.focus();
      });
    }
    // «Отправить в Hub» (ADR-0115) – тоже о сохранённом решении: при несохранённых правках не отправляется,
    // «Текст проверен» берётся из общего флажка карточки, отказ «комментарий к другому вердикту» показывает флажок
    var hubSendForm = $("#hub-send-form");
    if (hubSendForm) {
      var hubConfirmLabel = $("#hub-send-confirm-label");
      if (hubConfirmLabel) hubConfirmLabel.hidden = true;
      hubSendForm.addEventListener("submit", function (event) {
        var flag = $("#hub-send-comment-confirm");
        if (flag) flag.checked = !!(confirmBox && confirmBox.checked);
        // «Скопировать» тоже сохраняет решение (copyBusy) – ждём его ответа
        if (!dirty && !saving && !copyBusy) return;
        event.preventDefault();
        say(status, saving || copyBusy ?"Решение ещё сохраняется: дождитесь ответа и затем отправьте в Hub"
          : "Решение изменено, но не сохранено: сохраните его и затем отправьте в Hub", true, true);
      });
      hubSendForm.addEventListener("lt:error", function (event) {
        var answer = event.detail && event.detail.answer;
        if (!answer || answer.reason !== "comment") return;
        if (commentStale) commentStale.hidden = false;
        if (confirmLabel) confirmLabel.hidden = false;
        say(status, answer.detail || event.detail.message, true, true);
        if (comment) comment.focus();
      });
    }
    function sayDefect(text, isError) {
      say(defectStatus, text, true, isError);
      if (defectFromBar) say(status, text, true, isError);
    }
    // нижняя кнопка полного текста – кнопка отправки формы дефекта (form="defect-form"): работает и без скрипта.
    // Браузеры без event.submitter: нажатая кнопка запоминается по click (программный click фокус не переносит)
    var lastDefectButton = null;
    [defectBar, $("#copy-title-bar"), $("#copy-defect-title"), $("#copy-defect-body")].forEach(function (b) {
      if (b) b.addEventListener("click", function () { lastDefectButton = b; });
    });
    if (defectForm) {
      defectForm.addEventListener("submit", function (event) {
        var submitter = event.submitter || lastDefectButton || document.activeElement;
        lastDefectButton = null;
        var part = submitter && submitter.value === "body" ? "body" : "title";
        defectFromBar = !!(submitter && (submitter.id === "copy-defect-bar" || submitter.id === "copy-title-bar"));
        event.preventDefault();
        if (copyBusy) {
          defectFromBar = false;
          return;
        }
        if (dirty) {
          sayDefect("Сначала сохраните решение: дефект строится по сохранённому решению", true);
          defectFromBar = false;
          return;
        }
        var data = new FormData(defectForm);
        data.set("part", part);
        // «Текст проверен» относится к сохранённому решению на этой странице (правки не сохранены – выдача выше
        // отклонена): полный текст проверяет комментарий так же, как короткий. Редакция – текущая (после короткого
        // копирования она новее, чем в разметке): сервер не применит отметку к решению, изменённому в другой вкладке
        if (confirmBox && confirmBox.checked) data.set("comment_confirmed", "1");
        var revisionNow = $("#review-revision");
        if (revisionNow) data.set("review_revision", revisionNow.value);
        setCopyBusy(true);
        post(defectForm.getAttribute("action"), data)
          .then(function (answer) {
            var titleBox = $("#defect-title-text");
            var bodyBox = $("#defect-body-text");
            if (titleBox) titleBox.textContent = answer.title || "";
            if (bodyBox) bodyBox.textContent = answer.body || "";
            var hiddenNote = $("#defect-body-hidden");  // текст выдан – пояснение «не показан» больше не верно
            if (hiddenNote && answer.body) hiddenNote.hidden = true;
            var number = $("#defect-number");
            if (number && answer.number) number.value = String(answer.number);
            // номер сохранён этим ответом: следующая выдача сверяется с ним (Б9)
            var numberShown = $("#defect-number-shown");
            if (numberShown && answer.number) numberShown.value = String(answer.number);
            // SCA: отметка «Дефект создан в Hub» – о выданном тексте (номер в заголовке мог смениться)
            var defectSig = $("#entered-form input[name=defect_sig]");
            if (defectSig && answer.text_sig) defectSig.value = answer.text_sig;
            var text = part === "body" ? answer.body : answer.title;
            // отметку «Внесено в Hub» могли снять в другой вкладке: ответ выдачи сообщает её до записи в буфер (у SCA
            // этого поля нет)
            if (typeof answer.entered === "boolean") syncEntered(answer);
            if (byId("route")) {
              // любой ответ выдачи говорит, к этому ли тексту дефекта относится отметка «Внесено в Hub» (например,
              // сменилось название команды) – и при копировании заголовка
              routeEnteredStale = answer.entered === true && answer.entered_current === false;
              // скопированным считается только тело дефекта: выдача тела сбрасывает прежнее копирование, а заголовок –
              // если тело с тех пор другое
              if (part === "body" || (routeBodyHash && answer.entered_hash !== routeBodyHash)) routeCopied = false;
              if (part === "body") routeBodyHash = answer.entered_hash || "";
              // заголовок сверяется с последним подтверждённым копированием: другой (другой номер) – его копирование
              // снова этап маршрута, раньше отметки; вернулся прежний (ID1 → ID2 → ID1) – в Hub он уже есть
              if (routeTitleText && answer.title) {
                routeTitleStale = answer.title !== routeTitleText;
                routeTitleCopied = !routeTitleStale;
                if (routeTitleStale) routeTitleSkipped = false;
              }
              // текст выдан раньше заголовка – этап заголовка не навязывается (но не после изменения заголовка)
              if (part === "body" && !routeTitleStale && !routeTitleText) routeTitleSkipped = true;
              routeAccent();
            }
            var label = part === "body" ? "Полный текст дефекта" : "Заголовок дефекта";
            return copyText(text || "").then(function (ok) {
              if (!ok) {
                var box = $("#defect-preview");
                if (box) box.open = true;
                selectContents(part === "body" ? bodyBox : titleBox);
                sayDefect("Не скопировано в буфер: текст выделен – нажмите Ctrl+C" + (part === "body" && defectManual && answer.revision
                  ? ", затем «Скопировал текст дефекта вручную»" : ""), true);
                // карточка SCA: подтверждения копирования нет, идёт ручной путь – этап «создание» не скрывает отметку
                var failedBar = part === "body" && !byId("route") ? $(".action-bar") : null;
                if (failedBar) failedBar.removeAttribute("data-stage");
                // ручное копирование заголовка: Ctrl+C по выделенному заголовку подтверждает этот заголовок
                if (part === "title" && byId("route")) {
                  watchManualTitleCopy(titleBox, answer.title || "", function () {
                    sayDefect("Заголовок дефекта скопирован – вставьте его в Hub (название дефекта).", false);
                  });
                }
                // ручное копирование тела: подтверждение – той редакции и того текста, что выданы этим ответом
                if (part === "body" && defectManual && answer.revision) {
                  manualDefect = answer;
                  defectManual.hidden = false;
                }
                return;
              }
              sayDefect(label + " скопирован – вставьте его в Hub" + (part === "body" ? " (описание дефекта)."
                : " (название дефекта).") + (answer.note ? " " + answer.note : ""), !!answer.note);
              // О2: заголовок скопирован – следующий этап маршрута «Скопировать текст дефекта», фокус на нём
              if (part === "title" && byId("route")) {
                titleConfirmed(answer.title || "");
                routeFocusPrimary = true;  // фокус – после снятия блокировки копирования (кнопки ещё выключены)
              }
              if (!narrowCard()) toast(label + " скопирован", { announce: false });
              // текст дефекта в буфере: отметка «скопировано» – к выданной редакции решения, отметка «Внесено в Hub»
              // сверит отпечаток этого текста; акцент – на «Отметить: внесено в Hub»
              if (part === "body") {
                setEnteredHash(answer);
                // карточка SCA: текст скопирован – идёт ручной путь, отметка «Дефект создан в Hub» снова видна
                var plainBar = byId("route") ? null : $(".action-bar");
                if (plainBar) plainBar.removeAttribute("data-stage");
                if (answer.revision) {
                  copiedRevision = String(answer.revision);
                  confirmCopied();
                }
                // отметку «Внесено в Hub» трогать, только если ответ о ней сообщает (у SCA этого поля нет)
                // отметку «Внесено в Hub» трогать, только если ответ о ней сообщает (SAST); у SCA – как было
                if (typeof answer.entered === "boolean") {
                  syncEntered(answer);
                  // отметка уже действует – фокус на главной кнопке маршрута («Дальше»)
                  if (!accentEntered(answer) && byId("route")) accentNext();
                }
              }
            });
          })
          .catch(function (error) {
            // спорные места (ссылки на строки, которых нет в показанном коде; заголовок, похожий на путь):
            // сервер ждёт явного подтверждения – показать отметку «Предупреждения проверены»
            var confirmRow = $("#defect-confirm-row");
            if (error && error.answer && error.answer.reason === "confirm" && confirmRow) {
              confirmRow.hidden = false;
              var box = $("#defect-confirm");
              if (box) box.focus();
            }
            // решение изменили в другой вкладке: выдавать дефект по прежней редакции нельзя – обновить карточку
            if (error && error.answer && error.answer.reload === true) {
              offerReload(error.answer.detail || "Решение изменили в другой вкладке: обновите карточку.");
            }
            // комментарий модели к другому вердикту: показать отметку «Текст проверен» и перейти к комментарию
            if (error && error.answer && error.answer.reason === "comment") {
              if (commentStale) commentStale.hidden = false;
              if (confirmLabel) confirmLabel.hidden = false;
              var ownConfirm = $("#defect-comment-confirm-row");
              if (ownConfirm) ownConfirm.hidden = false;
              if (comment) comment.focus();
            }
            sayDefect("Не скопировано: " + (error && error.message ? error.message : "обновите страницу"), true);
          })
          .then(function () {
            setCopyBusy(false);
            defectFromBar = false;
            if (routeFocusPrimary) {  // О2: следующий этап маршрута – главная кнопка панели
              routeFocusPrimary = false;
              var nextPrimary = $(".action-bar .btn-primary");
              if (nextPrimary && !nextPrimary.hidden && !nextPrimary.disabled) nextPrimary.focus();
            }
          });
      });
    }
    if (manualButton) {
      manualButton.addEventListener("click", function () {
        manualButton.disabled = true;
        confirmCopied().then(function (ok) {
          manualButton.disabled = false;
          if (!ok) {
            say(status, "Отметка не поставлена: решение изменилось после копирования – скопируйте ещё раз", true, true);
            return;
          }
          manualButton.hidden = true;
          say(status, "Отмечено как скопированное – вставьте текст в Hub", true);
          if (!dirty && !accentEntered(null)) accentNext();
        });
      });
    }

    var pending = draftTake();
    if (pending) {  // карточка обновлена после нового ответа агента: вариант решения возвращён в форму, но не сохранён
      radios.forEach(function (r) { r.checked = r.value === pending.d; });
      if (select && typeof pending.v === "string") select.value = pending.v;
      if (comment && typeof pending.c === "string") comment.value = pending.c;
      if (fixBox && typeof pending.x === "string") fixBox.value = pending.x;
      if (kapo && typeof pending.k === "string") {
        kapo.value = pending.k;
        // черновик хранит выбор оператора при его итоге, пустой («по выводу») тоже: восстановительная синхронизация его не
        // перебивает умолчанием «актуальна» – итог считается уже виденным; при следующей смене итога умолчание действует
        // (ревью Codex 08.11, круги 1–2)
        lastKapoOutcome = kapoOutcome();
      }
      // выбор находок пакета – как в черновике; находки, которых в черновике не было, не отмечаются сами
      if (Array.isArray(pending.p)) {
        $all("#package-apply input[name=apply_to]").forEach(function (box) {
          if (!box.disabled) box.checked = pending.p.indexOf(box.value) >= 0;
        });
      }
      var reviewedChanged = reviewedBox && typeof pending.r === "boolean" && reviewedBox.checked !== pending.r;
      if (reviewedBox && pending.basisChanged) reviewedBox.checked = false;
      else if (reviewedBox && typeof pending.r === "boolean") reviewedBox.checked = pending.r;
      syncReviewed(false);
      syncKapo();
      syncRiskHint();
      syncSast(false);
      syncFixPreview();
      syncScaCopy();
      refreshCharCounts();
      setDirty(true);
      say(status, pending.basisChanged ? "Карточка обновлена. Черновик восстановлен. "
        + (pending.revisionChanged ? "Решение, ответ " + ($("#sast-form") ? "модели" : "агента")
          + " или код изменились после черновика"
          : "Ответ " + ($("#sast-form") ? "модели" : "агента") + " или код изменились после черновика")
        + " – проверьте решение заново"
        : reviewedChanged ? "Отметка «Проверено» не сохранена – нажмите «Сохранить»"
        : "Карточка обновлена. Черновик восстановлен: ваш вариант решения подставлен, но не сохранён. "
          + "Сверьте его с показанными "
          + "фактами и ответом " + ($("#sast-form") ? "модели" : "агента") + " и сохраните.", true, false);
    }
    card = { form: form, next: nextButton, copy: copyForHub };
  }

  // ------------------------------------------------------------------ клавиши

  // Однобуквенные клавиши можно отключить (мешают, например, голосовому вводу); выбор запоминается
  var KEYS_SETTING = "local-triage-keys";
  // Элементы этапа 1 – если на странице нет элемента с data-hotkey для этой клавиши
  var DECISION = 'input[name="decision"][value="';
  var FALLBACK_KEYS = {
    j: ["#nav-next"], k: ["#nav-prev"],
    a: [DECISION + 'agree"]'], d: [DECISION + 'disagree"]'], l: [DECISION + 'later"]'],
    n: [DECISION + 'false_positive"]'], y: [DECISION + 'true_positive"]'],
    r: [DECISION + 'risk_accepted"]'],
    "1": [DECISION + 'agree"]', DECISION + 'false_positive"]'], "2": [DECISION + 'disagree"]', DECISION + 'true_positive"]'],
    "3": [DECISION + 'later"]'],
    "4": [DECISION + 'risk_accepted"]'],
    c: ["#copy-hub"], f: ["#copy-defect-bar"], h: ["#mark-entered"], v: ["#reviewed-box"]
  };

  function keysEnabled() { return storageGet(KEYS_SETTING) !== "off"; }
  // event.code – физическая клавиша: раскладка не важна; «?» – по символу или Shift и клавише «/»
  function keyOf(event) {
    if (event.key === "?" || (event.code === "Slash" && event.shiftKey)) return "?";
    var code = event.code || "";
    if (/^Key[A-Z]$/.test(code)) return code.charAt(3).toLowerCase();
    if (/^Digit[0-9]$/.test(code)) return code.charAt(5);
    if (/^Numpad[0-9]$/.test(code)) return code.charAt(6);
    return "";
  }
  // Элемент можно нажать: не выключен, не скрыт, виден сам или его подпись
  function usable(el) {
    if (!el || el.disabled || closest(el, "[hidden]") || closest(el, "dialog:not([open])")) return false;
    if (el.getClientRects().length) return true;
    var label = closest(el, "label");
    return !!(label && label.getClientRects().length);
  }
  function hotkeyTarget(key) {
    var own = $all("[data-hotkey]").filter(function (el) {
      return (" " + el.getAttribute("data-hotkey") + " ").indexOf(" " + key + " ") >= 0 && usable(el);
    })[0];
    if (own) return own;
    return (FALLBACK_KEYS[key] || []).map(function (selector) { return $(selector); }).filter(usable)[0] || null;
  }
  function press(el) {
    el.click();
    var shown = el.tagName === "INPUT" ? (closest(el, "label") || el) : el;
    shown.classList.remove("is-hotkey");
    void shown.offsetWidth;
    shown.classList.add("is-hotkey");
    window.setTimeout(function () { shown.classList.remove("is-hotkey"); }, 600);
  }

  // Строки списка для j и k: [data-rows] или список находок; ссылка строки – [data-row-link] или первая
  function rowsContainer() { return $("[data-rows]") || $(".table-findings"); }
  function rowLink(row) { return $("[data-row-link]", row) || $("a[href]", row); }
  function moveRow(step) {
    var container = rowsContainer();
    if (!container) return false;
    var rows = (container.tagName === "TABLE" ? $all("tbody > tr", container) : Array.prototype.slice.call(container.children))
      .filter(function (row) { return rowLink(row) && row.getClientRects().length; });
    if (!rows.length) return false;
    var active = document.activeElement;
    var current = rows.indexOf($(".is-cursor", container));
    var focused = active ? rows.filter(function (row) { return row.contains(active); })[0] : null;
    if (focused) current = rows.indexOf(focused);
    var next = current < 0 ? (step > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, current + step));
    rows.forEach(function (row) { row.classList.remove("is-cursor"); });
    var row = rows[next];
    row.classList.add("is-cursor");
    var link = rowLink(row);
    try { link.focus({ preventScroll: true }); } catch (e) { link.focus(); }
    row.scrollIntoView({ block: "nearest", behavior: reducedMotion() ? "auto" : "smooth" });
    return true;
  }

  // Справка: клавиши, которых на этой странице нет, – приглушены
  function markKeyHints(dialog) {
    $all("[data-keys]", dialog).forEach(function (row) {
      var on = row.getAttribute("data-keys").split(" ").some(function (key) {
        if (key === "rows") return !!rowsContainer();
        if (key === "ctrl+enter") return !!(card && card.next);
        return !!hotkeyTarget(key);
      });
      row.classList.toggle("is-off", !on);
    });
  }

  // Длинные страницы. Кнопка «Наверх» – после полутора экранов прокрутки, над закреплённой нижней панелью.
  // В списках полоска отборов закреплена сверху, под ней – заголовки столбцов (если таблица помещается по ширине:
  // иначе остаётся горизонтальная прокрутка таблицы). Высоты панелей – в переменных CSS: отступы под панелями
  // и прокрутка к строке (j, k, якоря) не прячут содержимое под ними
  // ------------------------------------------------------------------ маршрут карточки SAST

  // Главная кнопка нижней панели – по этапу, одна на панели:
  //   ложное срабатывание: «Скопировать комментарий для Hub» → «Отметить: внесено в Hub» → «Дальше»;
  //   подтверждённый дефект: «Сохранить решение» → «Скопировать текст дефекта» → «Отметить: внесено в Hub» → «Дальше»;
  //   «Отложить» – «Дальше»; решения нет – главной кнопки нет. Этап считается по состоянию страницы: выбранное решение,
  //   несохранённые правки (#dirty-note), готовый дефект (#copy-defect-bar), копирование (#copied-at или ответ
  //   копирования), отметка «Внесено в Hub» (#entered-note)
  var routeCopied = false;
  var routeEnteredStale = false;  // выдан текст дефекта, а отметка «Внесено в Hub» – по другому тексту
  var routeBodyHash = "";  // отпечаток последнего выданного тела дефекта (копирование заголовка тело не копирует)
  // О2: заголовок дефекта скопирован на этой странице (и каким он был: другой номер – другой заголовок)
  var routeTitleCopied = false;
  var routeTitleText = "";
  var routeTitleSkipped = false;  // текст дефекта выдавался на этой странице раньше заголовка
  var routeTitleStale = false;  // скопированный заголовок устарел (другой номер) – его копирование важнее отметки
  var manualTitleCopy = null;  // ожидание Ctrl+C по выделенному заголовку после отказа буфера

  // заголовок дефекта скопирован (буфером или вручную): этап маршрута «Скопировать текст дефекта»
  function titleConfirmed(title) {
    routeTitleCopied = true;
    routeTitleStale = false;
    routeTitleText = title;
    routeAccent();
  }

  // буфер отказал, заголовок выделен: копирование выделения внутри заголовка – подтверждение именно этого заголовка
  function watchManualTitleCopy(box, title, done) {
    if (manualTitleCopy) document.removeEventListener("copy", manualTitleCopy);
    manualTitleCopy = function () {
      var selection = window.getSelection ? window.getSelection() : null;
      // засчитывается только весь заголовок: оба конца выделения – в блоке заголовка, выделено ровно оно
      if (!box || !selection || !box.contains(selection.anchorNode) || !box.contains(selection.focusNode)
          || selection.toString().trim() !== title.trim()) return;
      document.removeEventListener("copy", manualTitleCopy);
      manualTitleCopy = null;
      if (box.textContent !== title) return;  // заголовок с тех пор выдан заново – подтверждает следующая выдача
      titleConfirmed(title);
      if (done) done();
    };
    document.addEventListener("copy", manualTitleCopy);
  }
  var routeFocusPrimary = false;
  var routeWasDirty = false;
  function routeAccent() {
    var bar = $(".action-bar");
    var route = byId("route");
    if (!bar || !route) return;
    var checked = $("input[name=decision]:checked");
    var d = checked ? checked.value : "";
    var dirtyNote = byId("dirty-note");
    var dirty = !!(dirtyNote && !dirtyNote.hidden);
    var enteredNote = byId("entered-note");
    // отметка «Внесено в Hub» действует, только если карточка не просит её подтвердить заново (текст изменился,
    // формат обновился, отметка поставлена до обновления)
    var enteredStale = routeEnteredStale || ["entered-changed", "entered-format-updated", "entered-unconfirmed"].some(
      function (id) {
        var note = byId(id);
        return !!(note && !note.hidden);
      });
    var entered = !!(enteredNote && !enteredNote.hidden) && !enteredStale;
    var copiedAt = byId("copied-at");
    // «скопировано» с сервера у ложного срабатывания – копирование этого комментария; у дефекта – только копирование
    // на этой странице: отметка до 0.9.6 могла относиться к короткому тексту, а не к тексту дефекта
    var copied = routeCopied || (d === "false_positive" && !enteredStale && !!(copiedAt && copiedAt.textContent.trim()));
    var defectBar = byId("copy-defect-bar");
    var ready = !!(defectBar && !defectBar.hidden);
    var mark = byId("mark-entered");
    var save = byId("save-bar");
    var reload = byId("reload-card");
    var goSend = byId("go-send");
    if (goSend && goSend.hidden !== (d !== "false_positive")) goSend.hidden = d !== "false_positive";
    var goCreate = byId("go-create");
    // статус «Fixed» в Hub и ложное срабатывание: менять в Hub нечего – копирования нет, отметки нет, пока её не ставили;
    // прежняя отметка, которая ждёт подтверждения, остаётся с кнопкой «Подтвердить»
    var fixedMode = bar.getAttribute("data-hub-fixed") === "1" && d === "false_positive"
      ? (enteredNote && !enteredNote.hidden ? "copy" : "all") : "";
    if ((bar.getAttribute("data-fixed-fp") || "") !== fixedMode) {
      if (fixedMode) bar.setAttribute("data-fixed-fp", fixedMode);
      else bar.removeAttribute("data-fixed-fp");
    }
    var stage = "";
    if (reload) stage = "reload";  // решение изменили в другой вкладке: сначала обновить карточку
    else if (d === "later") stage = "next";
    else if (fixedMode) stage = dirty ? "save" : (entered || fixedMode === "all" ? "next" : "mark");
    // есть отправка из приложения: главная кнопка – переход к ней, копирование второстепенно (план dev7, раздел 4)
    else if (d === "false_positive" && goSend) stage = dirty ? "save" : (entered ? "next" : (copied ? "mark" : "send"));
    else if (d === "false_positive") stage = dirty ? "copy" : (entered ? "next" : (copied ? "mark" : "copy"));
    // дефект создаётся из приложения: главная кнопка – переход к блоку «Создать дефект», копирование второстепенно (план dev9, часть 2, п. 3)
    else if (d === "true_positive" && goCreate) stage = dirty || !ready ? "save" : (entered ? "next" : (copied ? "mark" : "create"));
    // дефект: сохранить → заголовок → текст → отметка; скопированный раньше заголовка текст ведёт сразу к отметке (О2)
    else if (d === "true_positive") stage = dirty || !ready ? "save" : (routeTitleStale ? "title"
      : (entered ? "next" : (copied ? "mark" : (routeTitleCopied || routeTitleSkipped ? "defect" : "title"))));
    if (stage === "mark" && (!mark || mark.disabled)) stage = "next";
    if (stage === "mark" && mark.hidden) mark.hidden = false;
    if (save) save.hidden = stage !== "save";
    if (goCreate && goCreate.hidden !== (stage !== "create")) goCreate.hidden = stage !== "create";
    // кнопка заголовка в панели – только на своём этапе: узкое окно не получает лишней кнопки, заголовок всегда
    // можно скопировать в разделе «Дефект для Hub»
    var titleBar = byId("copy-title-bar");
    if (titleBar && titleBar.hidden !== (stage !== "title")) titleBar.hidden = stage !== "title";
    var buttons = { copy: byId("copy-hub"), save: save, title: byId("copy-title-bar"), defect: defectBar, mark: mark,
      next: byId("next-btn"), reload: reload, send: goSend, create: goCreate };
    eachKey(buttons, function (key, button) {
      if (button && button.classList.contains("btn-primary") !== (key === stage)) button.classList.toggle("btn-primary", key === stage);
    });
    if (bar.getAttribute("data-stage") !== stage) bar.setAttribute("data-stage", stage);
    var value = byId("bar-decision-value");
    if (value) {
      var label = value.getAttribute({ false_positive: "data-fp", true_positive: "data-tp", later: "data-later" }[d] || "data-none");
      if (label && value.textContent !== label) value.textContent = label;
    }
    // «пройдено» – только по сохранённому: решение сохранено (правки сняты после сохранения), отметка «Внесено в Hub»
    if (routeWasDirty && !dirty && d) route.setAttribute("data-saved-outcome", d);
    routeWasDirty = dirty;
    var saved = route.getAttribute("data-saved-outcome") || "";
    var five = $(".route-step[data-step='5']", route);
    var six = $(".route-step[data-step='6']", route);
    if (five) five.classList.toggle("is-done", !!saved && !dirty && saved === d);
    if (six) {
      six.classList.toggle("is-done", entered && !dirty && !reload && d !== "later");
      six.classList.toggle("is-na", d === "later" || (!d && saved === "later"));
    }
  }
  // Первый экран карточки SAST на низком окне (ноутбук 1920 px с масштабом 125–150 %): если строка срабатывания
  // ушла под нижнюю панель, страница при открытии прокручивается ровно настолько, чтобы она была видна вместе со
  // сверкой и вердиктом. Не трогаем адрес со строкой (#L<n>), восстановленную прокрутку и свёрнутый код. Ушедшее за
  // верх сообщение «Сохранено» повторяется всплывающим
  function revealTargetOnOpen(route) {
    if (window.location.hash || window.scrollY > 0) return;
    if ($(".flash-err") || $("#review-form[data-draft]")) return;  // причина отказа и черновик – на виду
    var body = byId("code-body");
    var row = body && !body.hidden ? $("#code tr.is-target") : null;
    var bar = $(".action-bar");
    if (!row || !bar) return;
    var shift = row.getBoundingClientRect().bottom + 8 - bar.getBoundingClientRect().top;
    if (shift <= 0) return;
    window.scrollTo(0, Math.min(shift, route.getBoundingClientRect().top + window.scrollY));
    var saved = $(".saved-note");
    if (saved && saved.getBoundingClientRect().bottom < 0) toast(saved.textContent.trim(), { announce: false });
  }
  // Счётчик знаков поля с пределом (maxlength): «N из M знаков», предупреждение за 10 знаков до предела и при
  // вставке длиннее предела – браузер обрезает вставку молча (настройки: название команды)
  // пересчёт счётчиков после программной смены решения или текста (черновик восстанавливается без событий input и change)
  var charCountRefresh = [];
  function refreshCharCounts() { charCountRefresh.forEach(function (show) { show(); }); }
  function initCharCounts() {
    $all("input[data-char-count], textarea[data-char-count]").forEach(function (field) {
      var out = byId(field.getAttribute("data-char-count"));
      var max = parseInt(field.getAttribute("maxlength") || "0", 10);
      if (!out || !max) return;
      // Р8: предупреждение о длине готового текста для Hub (data-warn-at), с учётом приставки, которую добавляет
      // сервер (data-prefix-len – номер и компонент у короткого текста SCA); сохранение не запрещается
      var warnAt = parseInt(field.getAttribute("data-warn-at") || "0", 10);
      var prefix = parseInt(field.getAttribute("data-prefix-len") || "0", 10);
      // текст, начинающийся с публичного номера находки, приставку не получает (sca.hub_text) – как на сервере
      var prefixIds = (field.getAttribute("data-prefix-ids") || "").split(", ").filter(Boolean);
      function hasOwnId(value) {
        var head = value.replace(/^\s+/, "").toLowerCase();
        return prefixIds.some(function (id) {
          var low = id.toLowerCase();
          return head.indexOf(low) === 0 && !/[\w-]/.test(head.charAt(low.length));
        });
      }
      var cut = 0;
      // предел 250 – для короткого комментария к статусу находки (ложное срабатывание, риск принят). У вывода
      // «обновить» текст идёт в описание дефекта, там длина не ограничена. Кнопка короткого текста скрыта – этот случай
      function statusComment() {
        var copy = byId("copy-hub");
        return !field.hasAttribute("data-comment-for") || !copy || !copy.hidden;
      }
      function show() {
        var n = field.value.length;
        var text = n + " из " + max + " знаков";
        var short = warnAt > 0 ? statusComment() : true;
        var extra = hasOwnId(field.value) || !short ? 0 : prefix;
        if (extra && n > 0) text += " · в Hub уйдёт около " + (n + extra) + " с номером и компонентом";
        var long = warnAt > 0 && short && n > 0 && n + extra > warnAt;
        if (cut) text += ". Вставлено " + cut + " знаков – лишнее обрезано, проверьте конец названия";
        else if (n >= max) text += ". Предел: дальше текст не вводится";
        else if (n >= max - 10) text += ". Осталось " + (max - n);
        else if (long) text += ". Текст для Hub длиннее " + warnAt + " знаков" + (extra ? " (с номером и компонентом)" : "")
          + " – в списке Hub комментарий обрежется";
        out.textContent = text;
        out.classList.toggle("text-warn", !!cut || n >= max - 10 || long);
      }
      field.addEventListener("paste", function (event) {
        var data = event.clipboardData ? event.clipboardData.getData("text") : "";
        var selected = (field.selectionEnd || 0) - (field.selectionStart || 0);
        cut = field.value.length - selected + data.length > max ? data.length : 0;
        window.setTimeout(show, 0);
      });
      field.addEventListener("input", function (event) {
        if (!event || event.inputType !== "insertFromPaste") cut = 0;
        show();
      });
      // смена решения или вывода: сначала обновляется кнопка короткого текста, затем счётчик
      if (warnAt > 0) {
        $all("input[name=decision], #final-verdict").forEach(function (control) {
          control.addEventListener("change", function () { window.setTimeout(show, 0); });
        });
      }
      charCountRefresh.push(show);
      show();
    });
  }
  function initRoute() {
    var route = byId("route");
    if (!route) return;
    var root = document.documentElement;
    var links = $all(".route-link", route);
    var steps = $all("[data-route-step]");
    var queued = false;
    // текущий шаг – последний, чей верх выше нижнего края оглавления; из шагов одного ряда (1 и 2) – первый
    function current() {
      var limit = route.getBoundingClientRect().bottom + 24;
      var cur = null, curTop = -Infinity;
      steps.forEach(function (step) {
        var top = step.getBoundingClientRect().top;
        if (top <= limit && top > curTop + 4) { cur = step; curTop = top; }
      });
      var doc = document.documentElement;
      if (window.scrollY > 0 && window.innerHeight + window.scrollY >= doc.scrollHeight - 4) cur = steps[steps.length - 1];
      return cur ? cur.getAttribute("data-route-step") : (steps[0] ? steps[0].getAttribute("data-route-step") : "");
    }
    function update() {
      queued = false;
      var n = current();
      links.forEach(function (link) {
        var on = link.parentNode.getAttribute("data-step") === n;
        if (on) link.setAttribute("aria-current", "step");
        else link.removeAttribute("aria-current");
      });
      route.classList.toggle("is-stuck", window.scrollY > 0 && route.getBoundingClientRect().top <= 0.5);
    }
    function queue() {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(update);
    }
    function measure() { root.style.setProperty("--route-h", route.offsetHeight + "px"); update(); }
    window.addEventListener("scroll", queue, { passive: true });
    window.addEventListener("resize", measure);
    measure();
    // [data-press="id"]: дублирующая кнопка шага нажимает основную (копирование – одно на странице)
    document.addEventListener("click", function (event) {
      var button = closest(event.target, "[data-press]");
      if (!button) return;
      var target = byId(button.getAttribute("data-press"));
      if (target && !target.disabled && !target.hidden) target.click();
    });
    // этап пересчитывается после любых изменений, которые делает скрипт карточки
    var later = function () { window.setTimeout(routeAccent, 0); };
    document.addEventListener("change", later);
    document.addEventListener("input", later);
    if (window.MutationObserver) {
      var watch = new window.MutationObserver(later);
      ["dirty-note", "entered-note", "copied-at", "copy-defect-bar", "copy-title-bar", "mark-entered", "defect-panel"].forEach(function (id) {
        var el = byId(id);
        if (el) watch.observe(el, { attributes: true, attributeFilter: ["hidden"], childList: true, characterData: true, subtree: true });
      });
    }
    routeAccent();
    revealTargetOnOpen(route);
    revealDecisionOutcome();
  }

  // У1: после сохранения решения карточка открывается на следующем шаге (#step-6, #step-7) – сообщение над страницей
  // осталось за верхом и повторяется всплывающим; отказ сохранения (черновик в форме) – карточка на решении, причина
  // всплывающим сообщением
  function revealDecisionOutcome() {
    var form = byId("review-form");
    var err = $(".flash-err");
    if (form && form.hasAttribute("data-draft") && err && !window.location.hash) {
      var panel = byId("decision");
      if (panel) panel.scrollIntoView({ block: "start" });
      toast(err.textContent.trim(), { tone: "err", announce: false });
      return;
    }
    var ok = $(".flash-ok");
    if (ok && (window.location.hash === "#step-6" || window.location.hash === "#step-7")) {
      toast(ok.textContent.trim(), { announce: false });
    }
  }

  // карточка SCA: после сохранения страница открыта на следующем шаге – сообщение вверху за экраном, повторяется всплывающим
  function revealScaOutcome() {
    if (byId("route") || !byId("review-form") || !window.location.hash) return;
    var ok = $(".flash-ok");
    if (ok) toast(ok.textContent.trim(), { announce: false });
  }

  function initScrollAids() {
    var root = document.documentElement;
    var toTop = $("#to-top");
    var bars = $all(".action-bar, .selected-bar");
    var strips = $all("[data-sticky-strip]");
    var tables = $all(".table-sticky-head");
    var queued = false;
    function shown(el) { return !el.hidden && el.getClientRects().length > 0; }
    function tallest(list, height) {
      return list.reduce(function (h, el) { return shown(el) ? Math.max(h, height(el)) : h; }, 0);
    }
    function measure() {
      root.style.setProperty("--bar-h", tallest(bars, function (el) { return el.offsetHeight; }) + "px");
      root.style.setProperty("--strip-h", tallest(strips, function (el) { return el.offsetHeight; }) + "px");
      tables.forEach(function (table) {
        var wrap = table.parentNode;
        if (!wrap || !wrap.classList.contains("table-wrap")) return;
        // до 760 px строки таблиц – карточки, там заголовков нет
        wrap.classList.toggle("head-sticky", window.innerWidth > 760 && table.offsetWidth <= wrap.clientWidth + 1);
      });
      root.style.setProperty("--thead-h", tallest(tables, function (table) {
        var head = table.tHead;
        return head && table.parentNode.classList.contains("head-sticky") ? head.offsetHeight : 0;
      }) + "px");
      update();
    }
    function update() {
      queued = false;
      // сколько снизу закрывают закреплённые панели (панель решения, панель выбранных строк): панель учитывается, пока
      // её низ у нижнего края экрана (ближе высоты кнопки с отступом); ушедшая вверх панель кнопку за собой не тянет
      var cover = tallest(bars, function (el) {
        var rect = el.getBoundingClientRect();
        return rect.top < window.innerHeight && rect.bottom > window.innerHeight - 60 ? window.innerHeight - rect.top : 0;
      });
      cover = Math.min(Math.max(0, Math.round(cover)), Math.max(0, window.innerHeight - 60));
      root.style.setProperty("--cover-h", cover + "px");
      strips.forEach(function (strip) {
        strip.classList.toggle("is-stuck", window.scrollY > 0 && strip.getBoundingClientRect().top <= 0.5);
        $all("[data-strip-open]", strip).forEach(function (button) { button.hidden = !strip.classList.contains("is-stuck"); });
      });
      if (toTop) toTop.hidden = window.scrollY < window.innerHeight * 1.5;
    }
    function queue() {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(update);
    }
    window.addEventListener("scroll", queue, { passive: true });
    window.addEventListener("resize", measure);
    if (window.ResizeObserver) {
      var watch = new window.ResizeObserver(measure);
      bars.concat(strips, tables).forEach(function (el) { watch.observe(el); });
    }
    measure();
    function goTop() {
      window.scrollTo({ top: 0, behavior: reducedMotion() ? "auto" : "smooth" });
    }
    if (toTop) {
      toTop.addEventListener("click", function () {
        goTop();
        var main = $("#main");
        if (main) { try { main.focus({ preventScroll: true }); } catch (e) { main.focus(); } }  // кнопка сейчас скроется
      });
    }
    // «Все фильтры» в закреплённой полоске: к панели фильтров (под полоской – scroll-padding-top), панель раскрыта,
    // курсор – на её заголовке
    document.addEventListener("click", function (event) {
      var button = closest(event.target, "[data-strip-open]");
      if (!button) return;
      var details = byId(button.getAttribute("data-strip-open"));
      if (!details) return;
      details.open = true;
      details.scrollIntoView({ block: "start", behavior: reducedMotion() ? "auto" : "smooth" });
      var summary = $("summary", details);
      if (summary) { try { summary.focus({ preventScroll: true }); } catch (e) { summary.focus(); } }
    });
  }

  function initKeys() {
    var toggles = $all("#keys-toggle, #hotkeys-enabled");
    toggles.forEach(function (toggle) {
      toggle.checked = keysEnabled();
      toggle.addEventListener("change", function () {
        storageSet(KEYS_SETTING, toggle.checked ? "on" : "off");
        toggles.forEach(function (other) { other.checked = toggle.checked; });
      });
    });
    document.addEventListener("keydown", function (event) {
      if (event.defaultPrevented) return;
      var dialogOpen = !!$("dialog[open]");
      // Ctrl+Enter – сохранить и к следующей; работает и в поле комментария
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && card && card.next && !dialogOpen) {
        event.preventDefault();
        if (card.form.requestSubmit) card.form.requestSubmit(card.next);
        else card.next.click();
        return;
      }
      if (event.ctrlKey || event.metaKey || event.altKey || isTyping(event.target) || dialogOpen) return;
      var key = keyOf(event);
      if (!key) return;
      if (key === "?") {
        event.preventDefault();
        openDialog(byId("keys-dialog"));
        return;
      }
      if (!keysEnabled()) return;
      if (event.shiftKey) return;
      var target = hotkeyTarget(key);
      if (target) {
        event.preventDefault();
        press(target);
        return;
      }
      // h в карточке без сохранённого решения: подсказать, а не молчать
      var badge = $("#entered-badge");
      // статус «Fixed»: отметка здесь намеренно недоступна, решение уже сохранено – подсказка о нём была бы неверной
      var fixedBar = $(".action-bar[data-fixed-fp='all']");
      if (key === "h" && fixedBar) {
        event.preventDefault();
        toast("У находки в Hub статус «Fixed»: менять в Hub нечего, отметка не нужна", { tone: "info" });
        return;
      }
      if (key === "h" && $("#mark-entered") && badge && badge.hidden) {
        event.preventDefault();
        toast("Сначала выберите и сохраните решение – отметка «Внесено в Hub» относится к нему", { tone: "info" });
        return;
      }
      if ((key === "j" || key === "k") && moveRow(key === "j" ? 1 : -1)) event.preventDefault();
    });
  }

  // ------------------------------------------------------------------ отбор находок для прогона

  function initSelection() {
    var form = $("#selected-run");
    if (!form) return;
    var alls = $all(".check-all", form);  // в заголовке таблицы и, на узком экране, в панели запуска
    var boxes = $all(".row-check", form);
    var counter = $("#selected-count");
    var button = $("#run-selected");
    var sendButton = $("#send-selected");  // «Отправить выбранные в Hub» – доступна, пока что-то отмечено
    var defectButton = $("#defect-selected");
    var decideButton = $("#decide-selected");
    var bar = $("#selected-bar");
    var hint = $("#select-hint");
    var locked = button ? button.disabled : true;
    function update() {
      var n = boxes.filter(function (box) { return box.checked; }).length;
      if (counter) counter.textContent = String(n);
      if (button && !locked) button.disabled = n === 0;
      if (sendButton) sendButton.disabled = n === 0;
      if (defectButton) defectButton.disabled = n === 0;
      if (decideButton) decideButton.disabled = n === 0;
      // панель запуска – только когда что-то отмечено; до этого – подсказка над списком
      if (bar) bar.hidden = n === 0;
      if (hint) hint.hidden = n > 0 || boxes.length === 0;
      alls.forEach(function (all) {
        all.checked = n > 0 && n === boxes.length;
        all.indeterminate = n > 0 && n < boxes.length;
      });
    }
    alls.forEach(function (all) {
      all.disabled = boxes.length === 0;
      all.addEventListener("change", function () {
        boxes.forEach(function (box) { box.checked = all.checked; });
        update();
      });
    });
    boxes.forEach(function (box) { box.addEventListener("change", update); });
    update();
  }

  // «Дефект из выбранных»: текст модели опорной находки переносится только кнопкой (ADR-0092), к введённому – в конец;
  // после смены опорной находки кнопки прежней скрыты до «Проверить состав и текст»
  function initSelectedModelText() {
    var anchorInput = $("#selected-anchor-input");
    $all("[data-take-model]").forEach(function (btn) {
      var box = document.getElementById(btn.getAttribute("data-take-model"));
      if (!box) return;
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-text") || "";
        var current = box.value.replace(/\s+$/, "");
        box.value = current ? current + "\n" + text : text;
        box.dispatchEvent(new Event("input", { bubbles: true }));
        box.focus();
        toast(btn.getAttribute("data-code-dropped")
          ? "Пункты модели перенесены, пример кода – нет. Проверьте и поправьте текст."
          : "Текст модели перенесён. Проверьте и поправьте его.", { tone: "ok" });
      });
      if (anchorInput) {
        anchorInput.addEventListener("change", function () {
          btn.hidden = anchorInput.value !== btn.getAttribute("data-anchor");
        });
      }
    });
  }

  // ------------------------------------------------------------------ прогон

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function badge(className, text) {
    var span = document.createElement("span");
    span.className = "badge " + className;
    span.textContent = text;
    return span;
  }

  function feedRow(item) {
    var tr = document.createElement("tr");
    tr.dataset.resultId = String(item.hub_id);
    var tdId = document.createElement("td");
    tdId.setAttribute("data-label", "ID");
    var idNode = document.createElement(item.url ? "a" : "span");
    idNode.className = "mono";
    idNode.textContent = item.hub_id;
    if (item.url) idNode.setAttribute("href", item.url);
    tdId.appendChild(idNode);

    var tdResult = document.createElement("td");
    tdResult.setAttribute("data-label", "Вердикт");
    if (item.verdict) {
      var label = item.verdict_label || item.verdict;
      if (item.confidence !== null && item.confidence !== undefined) label += " · " + item.confidence + "%";
      tdResult.appendChild(badge("verdict verdict-" + item.verdict, label));
      if (item.state === "cached") {
        var cached = document.createElement("span");
        cached.className = "muted small";
        cached.textContent = " готовый";
        tdResult.appendChild(cached);
      }
    } else {
      var stateText = item.state === "error" && item.error_label
        ? item.error_label : (item.state_label || item.state);
      var stateBadge = badge("item-" + item.state, stateText);
      if (item.error) stateBadge.title = item.error;
      tdResult.appendChild(stateBadge);
      if (item.error && item.state !== "error") {
        var err = document.createElement("span");
        err.className = "muted small block";
        err.textContent = item.error;
        tdResult.appendChild(err);
      }
    }

    var tdRule = document.createElement("td");
    tdRule.setAttribute("data-label", "Правило");
    tdRule.className = "small";
    tdRule.textContent = item.rule || "";

    var tdTime = document.createElement("td");
    tdTime.setAttribute("data-label", "Время");
    tdTime.className = "num";
    tdTime.textContent = item.seconds === null || item.seconds === undefined ? "–" : duration(item.seconds);

    var tdTps = document.createElement("td");
    tdTps.setAttribute("data-label", "ток/с");
    tdTps.className = "num";
    tdTps.textContent = num(item.eval_tps);

    [tdId, tdResult, tdRule, tdTime, tdTps].forEach(function (td) { tr.appendChild(td); });
    return tr;
  }

  function errorGroupSection(group) {
    var section = document.createElement("section");
    section.className = "error-group";
    section.dataset.errorGroup = group.key;
    var title = document.createElement("h3");
    title.textContent = group.label + " ";
    var count = document.createElement("span");
    count.className = "muted";
    count.textContent = "· " + group.count;
    title.appendChild(count);
    section.appendChild(title);
    if (group.hint) {
      var hint = document.createElement("p");
      hint.className = "hint";
      hint.textContent = group.hint;
      section.appendChild(hint);
    }
    var list = document.createElement("ul");
    list.className = "error-list";
    (group.rows || []).forEach(function (item) {
      var row = document.createElement("li");
      row.className = "error-item";
      var link = document.createElement(item.url ? "a" : "span");
      link.className = "mono";
      link.textContent = item.hub_id;
      if (item.url) link.setAttribute("href", item.url);
      row.appendChild(link);
      if (item.rule) {
        var rule = document.createElement("span");
        rule.className = "muted small";
        rule.textContent = " · " + item.rule;
        row.appendChild(rule);
      }
      var reason = document.createElement("span");
      reason.className = "error-reason";
      reason.textContent = " – " + item.reason;
      row.appendChild(reason);
      var details = document.createElement("details");
      details.className = "error-detail";
      var summary = document.createElement("summary");
      summary.textContent = "Подробности";
      var text = document.createElement("p");
      text.className = "small mono";
      text.textContent = item.detail;
      details.appendChild(summary);
      details.appendChild(text);
      row.appendChild(details);
      list.appendChild(row);
    });
    section.appendChild(list);
    return section;
  }

  function renderRunErrors(errors, run) {
    var block = $("#run-errors");
    if (!block) return;
    var total = errors && errors.total ? errors.total : 0;
    var retryable = errors && errors.retryable ? errors.retryable : 0;
    var unknown = errors && errors.unknown ? errors.unknown : 0;
    block.hidden = total === 0;
    if (!total) return;
    setText("errors-total", String(total));
    var labels = [];
    ((errors && errors.groups) || []).forEach(function (group) {
      if (group.count) labels.push(group.label + ": " + group.count);
    });
    setText("errors-breakdown", labels.join(" · "));
    var groups = $("#errors-groups");
    var signature = JSON.stringify((errors && errors.groups) || []);
    if (groups && groups._signature !== signature) {
      while (groups.firstChild) groups.removeChild(groups.firstChild);
      ((errors && errors.groups) || []).forEach(function (group) {
        if (group.count) groups.appendChild(errorGroupSection(group));
      });
      groups._signature = signature;
    }
    var form = $("#retry-errors");
    if (form) {
      var canRetry = (retryable > 0 || unknown > 0) && ["done", "stopped", "error", "paused"].indexOf(run.state) >= 0;
      form.hidden = !canRetry;
      var unknownBox = $("#retry-unknown");
      if (unknownBox) { unknownBox.hidden = unknown === 0; setText("retry-unknown-count", String(unknown)); }
      var box = unknownBox ? unknownBox.querySelector("input") : null;
      form._retryState = {retryable: retryable, unknown: unknown, paused: run.state === "paused"};  // последнее состояние
      var relabel = function () {  // с отметкой – и «результат неизвестен» (новый платный запрос)
        var s = form._retryState;
        var selected = s.retryable + (box && box.checked ? s.unknown : 0);
        setText("retry-errors-button", "Повторить ошибочные (" + selected + ")");
        var message = "Запустить новый прогон по находкам с ошибкой (" + selected + ")? Прежний прогон "
          + "останется в истории";
        message += s.paused ? "; он на паузе и будет остановлен." : ".";
        form.setAttribute("data-confirm", message);
      };
      if (canRetry) relabel();
      if (box && !form._unknownBound) { form._unknownBound = true; box.addEventListener("change", relabel); }
    }
    var note = $("#retry-errors-note");
    if (note) note.textContent = (errors && errors.note) || "";  // текст – с сервера (run_errors.retry_note)
  }

  function progressText(s) {
    var run = s.run;
    var parts = ["Обработано " + run.done + " из " + run.total];
    if (s.new_verdicts) parts.push("новых вердиктов " + s.new_verdicts);
    if (run.cached) parts.push("готовых " + run.cached);
    if (run.skipped) parts.push("пропущено " + run.skipped);
    if (run.failed) parts.push("ошибок " + run.failed);
    return parts.join(" · ");
  }

  function renderRun(s) {
    document.dispatchEvent(new CustomEvent('triage:status', {detail:s}));
    var run = s.run;
    var state = $("#run-state");
    if (state) {
      state.className = "state state-" + run.state;
      state.textContent = run.state_label || run.state;
    }
    var bar = $("#run-progress");
    if (bar) {
      bar.max = Math.max(1, run.total);
      bar.value = run.done;
    }
    setText("progress-pct", Math.round(Number(s.progress) || 0) + "%");
    setText("progress-text", progressText(s));
    var finished = run.state === "done" || run.state === "stopped" || run.state === "error";
    // на паузе оценки нет – «оценка после трёх ответов» при большем числе готовых вводила в заблуждение
    setText("eta", s.eta_s !== null && s.eta_s !== undefined ? "~" + duration(s.eta_s)
      : (finished ? "–" : run.state === "paused" ? "на паузе" : "оценка после трёх ответов"));
    setText("elapsed", duration(s.elapsed_s));
    setText("avg-call", duration(s.avg_call_s));

    var current = $("#current");
    if (current) {
      if (s.current) {
        current.hidden = false;
        var link = $("#current-link");
        link.textContent = s.current.hub_id;
        link.setAttribute("href", s.current.url || "#");
        setText("current-phase", (s.current.phase_label || "") + (s.current.seconds ? ", " + duration(s.current.seconds) : ""));
      } else {
        current.hidden = true;
      }
    }
    var control = $("#control-note");
    if (control) {
      control.hidden = !s.control;
      control.textContent = s.control === "stop" ? "Остановка после текущей находки…" : "Пауза после текущей находки…";
    }
    var notice = $("#run-notice");
    if (notice) {
      notice.hidden = !run.notice;
      notice.textContent = run.notice || "";
    }
    var journalWarning = $("#journal-warning");
    if (journalWarning) {
      journalWarning.hidden = !s.journal_warning;
      journalWarning.textContent = s.journal_warning || "";
    }
    var slow = $("#slow-model");
    if (slow) {
      var slowInfo = s.slow_model || null;
      slow.hidden = !(slowInfo && slowInfo.text);
      slow.textContent = slowInfo && slowInfo.text ? slowInfo.text : "";
      slow.className = "callout " + (slowInfo && slowInfo.warning ? "callout-warn" : "callout-info");
    }
    renderRunErrors(s.errors, run);
    var actions = $("#run-actions");
    if (actions) actions.setAttribute("data-state", run.state);

    setText("m-tps", num(s.tps_last));
    setText("m-tps-avg", num(s.tps_avg));
    var partial = $("#m-tps-partial");
    if (partial) {
      partial.hidden = !run.partial_stats;
      partial.textContent = run.partial_stats ? " · замеры неполные: " + run.partial_stats : "";
    }
    var m = s.metrics || {};
    var gpu = m.gpu || null;
    setText("m-vram", mib(m.vram_used_mb));
    setText("m-vram-total", m.vram_total_mb ? "из " + mib(m.vram_total_mb)
      : (m.vram_source === "ollama" ? "по данным Ollama" : ""));
    var vramBar = $("#m-vram-bar");
    if (vramBar) {
      vramBar.hidden = !m.vram_total_mb;
      if (m.vram_total_mb) {
        vramBar.max = m.vram_total_mb;
        vramBar.value = m.vram_used_mb || 0;
      }
    }
    setText("m-util", gpu && gpu.util_pct !== null && gpu.util_pct !== undefined ? num(gpu.util_pct, 0) + "%" : "–");
    setText("m-power", gpu && gpu.power_w !== null && gpu.power_w !== undefined ? num(gpu.power_w, 0) + " Вт" : "");
    setText("m-temp", gpu && gpu.temp_c !== null && gpu.temp_c !== undefined ? num(gpu.temp_c, 0) + " °C" : "–");
    // «ещё не измерено» – наблюдение этот сервер пока не измерило; у сервера в сети видеокарты этого компьютера нет
    setText("m-gpu-name", gpu ? gpu.name : m.pending ? "измерение ещё не готово"
      : (m.server && m.server.local === false ? "видеокарта сервера в сети не показывается" : "nvidia-smi недоступна"));
    // запись /api/ps именно для модели прогона (сервер выбирает её по имени); другие загруженные – отдельно
    var loaded = s.run_model || null;
    var others = (m.models || []).filter(function (x) { return !loaded || x.name !== loaded.name; })
      .map(function (x) { return x.name; });
    setText("m-model", loaded ? loaded.name : (m.pending ? "ещё не измерено" : "не загружена"));
    setText("m-model-vram", loaded && loaded.vram_pct !== null && loaded.vram_pct !== undefined
      ? loaded.vram_pct + "% в видеопамяти" : (others.length ? "в памяти: " + others.join(", ") : ""));

    // Существующие строки сохраняют ID, узел ссылки и фокус при появлении следующего результата.
    var feed = $("#feed");
    var signature = s.feed ? JSON.stringify(s.feed) : "";
    if (feed && s.feed && feed._signature !== signature) {
      var active = document.activeElement;
      var focused = active && feed.contains(active) ? active : null;
      var existing = new Map();
      Array.from(feed.children).forEach(function(row) {
        var key = row.dataset.resultId, link = row.querySelector('td:first-child .mono');
        if (!key && link) key = link.textContent;
        if (key) existing.set(String(key), row); else row.remove();
      });
      if (!s.feed.length) {
        var empty = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 5;
        td.className = "muted";
        td.textContent = "Пока ничего не обработано.";
        empty.appendChild(td);
        feed.appendChild(empty);
      }
      var cursor = feed.firstChild;
      s.feed.forEach(function (item) {
        var key = String(item.hub_id), row = existing.get(key), itemSig = JSON.stringify(item);
        if (!row) row = feedRow(item);
        else if (row._signature !== itemSig) {
          var fresh = feedRow(item);
          // Первый столбец не меняется для того же ID. Остальные данные могли уточниться.
          while (row.children.length > 1) row.lastChild.remove();
          while (fresh.children.length > 1) row.appendChild(fresh.children[1]);
        }
        row._signature = itemSig;
        existing.delete(key);
        if (row !== cursor) feed.insertBefore(row, cursor);
        cursor = row.nextSibling;
      });
      existing.forEach(function(row){row.remove();});
      feed._signature = signature;
      if (focused && focused.isConnected && document.activeElement !== focused) focused.focus({preventScroll:true});
    }
  }

  function initRun() {
    var root = $("#run");
    if (!root || !window.EventSource) return;
    var lost = $("#conn-lost");
    var finished = false;
    var lostTimer = null;  // «Нет связи» – только если переподключение не удалось за 4 с (НТ16)
    var source = new EventSource(root.getAttribute("data-events"));
    // уход со страницы (повтор прогона, переход по ссылке) обрывает поток – это не потеря связи
    window.addEventListener("pagehide", function () {
      finished = true;
      window.clearTimeout(lostTimer);
      source.close();
    });
    // страница вернулась из кэша браузера с закрытым потоком – данные не живые: перезагрузить
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) window.location.reload();
    });
    source.addEventListener("status", function (event) {
      window.clearTimeout(lostTimer);
      lostTimer = null;
      if (lost) lost.hidden = true;
      try { renderRun(JSON.parse(event.data)); } catch (e) { /* неполное сообщение – ждём следующее */ }
    });
    source.addEventListener("end", function () {
      finished = true;
      source.close();
      // итог прогона (бэклог 102, 103) считается сервером: открытая до конца прогона страница перечитывается один раз
      var summary = $("#run-summary");
      if (summary && summary.getAttribute("data-final") === "0") window.location.reload();
    });
    // Связь потеряна (приложение перезапускается, контейнер остановлен): данные на странице больше не живые
    source.addEventListener("error", function () {
      if (finished || !lost) return;
      var closed = source.readyState === EventSource.CLOSED;
      function show() {
        if (finished) return;
        lost.textContent = source.readyState === EventSource.CLOSED
          ? "Нет связи с приложением: данные на странице могут быть устаревшими. Обновите страницу."
          : "Нет связи с приложением: данные на странице могут быть устаревшими. Переподключение…";
        lost.hidden = false;
      }
      if (closed) {
        window.clearTimeout(lostTimer);
        lostTimer = null;
        show();
        return;
      }
      // срок – от первой ошибки до восстановления: повторные попытки (каждые 3 с) его не отодвигают
      if (!lostTimer) lostTimer = window.setTimeout(show, 4000);
    });
  }

  // ------------------------------------------------------------------ запуск

  window.LocalTriage = {
    toast: toast,
    copy: copyText,
    request: request,
    apply: applyAnswer,
    showLine: showLine,
    renderModelText: renderModelText
  };

  localizeTimes(document);
  initConfirm();
  initCopyButtons();
  initBusy();
  initAjaxForms();
  initAutosubmit();
  initProjectModels();
  initDismiss();
  initDialogs();
  initDropzones();
  initElapsed();
  initFillFields();
  initChecklists();
  initRemember();
  initCodeFold();
  initCharCounts();
  initWrap();
  centerTargetLine();
  initLineRefs();
  initProject();
  initReview();
  refreshCharCounts();
  initRoute();
  revealScaOutcome();
  initScrollAids();
  initKeys();
  initSelection();
  initSelectedModelText();
  initRun();
  initPolls();
  initHubProbe();
})();

// Исследование провайдером (ADR-0105): страница хода получения опрашивает состояние раз в 5 с, пока оно идёт;
// кнопки «Остановить», «Продолжить», «Доисследовать» показываются по состоянию – без перезагрузки страницы
(function () {
  "use strict";
  var root = document.getElementById("research-run");
  if (!root || !root.dataset.status) return;
  var tone = {saved: "ok", unchanged: "muted", failed: "err", unknown: "warn", sending: "info", queued: "muted"};
  var timer = null;
  function show(name, on) {
    root.querySelectorAll('[data-when="' + name + '"]').forEach(function (el) { el.hidden = !on; });
  }
  var counts = null;
  // кнопка «Доисследовать» называет, сколько строк уйдёт: не получившиеся плюс неизвестные, если отмечены
  // (при одних неизвестных кнопка показывала «(0)» и отказывала)
  function leftover() {
    var box = document.getElementById("include-unknown");
    var button = document.getElementById("research-requeue-button");
    if (!counts || !button) return;
    var n = counts.failed + (box && box.checked ? counts.unknown : 0);
    root.querySelectorAll('[data-count="leftover"]').forEach(function (el) { el.textContent = n; });
    button.disabled = n === 0;
  }
  // до первого опроса счётчики – из серверной разметки (ревью Codex: иначе снятие отметки не обновляло кнопку)
  function fromMarkup(name) {
    var el = root.querySelector('[data-count="' + name + '"]');
    return el ? Number(el.textContent) || 0 : 0;
  }
  counts = {failed: fromMarkup("failed"), unknown: fromMarkup("unknown")};
  var box = document.getElementById("include-unknown");
  if (box) box.addEventListener("change", leftover);
  function apply(s) {
    var state = document.getElementById("run-state");
    if (state) { state.textContent = s.run.state_label; state.className = "state state-" + s.run.state; }
    ["saved", "unchanged", "failed", "unknown"].forEach(function (k) {
      var el = document.getElementById("n-" + k); if (el) el.textContent = s.run["rows_" + k];
    });
    var failed = 0, unknown = 0;
    s.rows.forEach(function (r) {
      if (r.state === "failed" && !r.later_saved) failed++;
      if (r.state === "unknown" && !r.later_saved) unknown++;
      var tr = root.querySelector('tr[data-ref="' + CSS.escape(r.input_ref) + '"]'); if (!tr) return;
      var badge = tr.querySelector("[data-state]");
      if (badge) { badge.textContent = r.state_label; badge.className = "badge badge-" + (tone[r.state] || "muted"); }
      // пометка «исследована позже» – по опросу: строку могло добрать более позднее получение (ревью Codex, круг 29)
      var later = tr.querySelector("[data-later-saved]");
      if (r.later_saved && !later && badge) {
        later = document.createElement("span");
        later.className = "badge badge-muted"; later.setAttribute("data-later-saved", "");
        later.title = "строка сохранена более поздним получением; в доисследование не идёт";
        later.textContent = "исследована позже";
        badge.insertAdjacentElement("afterend", later); badge.insertAdjacentText("afterend", " ");
      } else if (!r.later_saved && later) {
        later.remove();
      }
      tr.querySelector("[data-revision]").textContent = r.revision || "–";
      var tools = tr.querySelector("[data-tools]");
      tools.textContent = r.tools; tools.title = r.tools_text || "";
      tr.querySelector("[data-reason]").textContent = r.reason || "";
    });
    var live = document.getElementById("run-live");
    if (live) {
      live.hidden = !s.live;
      if (s.live) {
        live.querySelector("[data-live-ref]").textContent = s.live.input_ref;
        live.querySelector("[data-live-text]").textContent = s.live.text || "обращение к модели…";
      }
    }
    root.querySelectorAll('[data-count="failed"]').forEach(function (el) { el.textContent = failed; });
    root.querySelectorAll('[data-count="unknown"]').forEach(function (el) { el.textContent = unknown; });
    counts = {failed: failed, unknown: unknown};
    leftover();
    var running = s.run.state === "running";
    show("running", running);
    show("paused", s.run.state === "stopped" || s.run.state === "interrupted");
    show("leftover", !running && (failed > 0 || unknown > 0));
    show("unknown", unknown > 0);
    var reason = document.getElementById("run-reason");
    if (reason) {  // причина остановки скрывается после «Продолжить» из другой вкладки (ревью Codex, круг 32)
      reason.textContent = s.run.reason || ""; reason.hidden = !s.run.reason;
    }
    // расход по опросу (usage_json получения – строка JSON), иначе числа остаются начальными до перезагрузки
    var usage = null;
    try { usage = s.run.usage_json ? JSON.parse(s.run.usage_json) : null; } catch (e) { usage = null; }
    if (usage) {
      var box = document.getElementById("run-usage");
      root.querySelectorAll("[data-usage]").forEach(function (el) {
        var v = usage[el.getAttribute("data-usage")]; if (typeof v === "number") el.textContent = v;
      });
      if (box) box.hidden = false;
    }
    if (!running && timer) { clearInterval(timer); timer = null; }
    if (running && !timer) timer = setInterval(poll, 5000);  // «Продолжить» из другой вкладки: опрос снова идёт
    root.dataset.polling = timer ? "1" : "0";  // наблюдаемое состояние опроса (проверки в браузере)
  }
  function poll() {
    if (document.hidden) return;
    fetch(root.dataset.status, {cache: "no-store"}).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s) apply(s); }).catch(function () {});
  }
  timer = setInterval(poll, 5000);
  // завершённое получение опрашивается заново при возврате во вкладку: более позднее получение могло добрать строки
  document.addEventListener("visibilitychange", function () { if (!document.hidden && !timer) poll(); });
  poll();
})();

// Строки externalBugs: порядок и присутствие свойств задаются явно.
(() => {
  const form = document.querySelector('#defect-fields');
  if (!form) return;
  form.addEventListener('input', event => {
    const field = event.target.closest('[data-defect-field]');
    if (!field || (event.target.name.startsWith('f_') && event.target.name.endsWith('_mode'))) return;
    const mode = field.querySelector('select[id$="-mode"]');
    if (mode && [...mode.options].some(option => option.value === 'set')) mode.value = 'set';
    if (event.target.name.startsWith('bug_') && event.target.name.endsWith('_value')) {
      const presence = form.querySelector(`[name="${event.target.name.replace(/_value$/, '_mode')}"]`);
      if (presence) presence.value = 'set';
    }
  });
  form.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button) return;
    const list = document.querySelector('#external-bugs');
    const mode = document.querySelector('#f-externalBugs-mode');
    if (button.id === 'add-external-bug') {
      const indices = [...list.querySelectorAll('[name="bug_order"]')].map(x => Number(x.value));
      const index = Math.max(Number(list.dataset.nextIndex), ...indices.map(x => x + 1), 0);
      list.dataset.nextIndex = String(index + 1);
      const row = document.createElement('fieldset');
      row.className = 'external-bug';
      row.dataset.bugIndex = String(index);
      const legend = document.createElement('legend'); legend.textContent = 'Внешний дефект'; row.append(legend);
      const order = document.createElement('input'); order.type = 'hidden'; order.name = 'bug_order'; order.value = String(index); row.append(order);
      for (const prop of ['product', 'displayName', 'link']) {
        const label = document.createElement('label'); label.className = 'field'; label.append(document.createTextNode(prop));
        const input = document.createElement('input'); input.name = `bug_${index}_${prop}_value`; label.append(input); row.append(label);
        const presenceLabel = document.createElement('label'); presenceLabel.className = 'field'; presenceLabel.append(document.createTextNode(`Присутствие ${prop}`));
        const select = document.createElement('select'); select.name = `bug_${index}_${prop}_mode`;
        for (const [value, text] of [['set', 'Установить строку'], ['remove', 'Свойство отсутствует']]) {
          const option = document.createElement('option'); option.value = value; option.textContent = text; select.append(option);
        }
        presenceLabel.append(select); row.append(presenceLabel);
      }
      for (const [action, text] of [['up', 'Выше'], ['down', 'Ниже'], ['remove', 'Удалить строку']]) {
        const control = document.createElement('button'); control.type = 'button'; control.className = 'btn';
        control.dataset.bugAction = action; control.textContent = text; row.append(control);
      }
      list.append(row); mode.value = 'set'; return;
    }
    const action = button.dataset.bugAction;
    const row = button.closest('.external-bug');
    if (!action || !row) return;
    if (action === 'remove') row.remove();
    if (action === 'up' && row.previousElementSibling) list.insertBefore(row, row.previousElementSibling);
    if (action === 'down' && row.nextElementSibling) list.insertBefore(row.nextElementSibling, row);
    mode.value = 'set';
  });
})();

// Карточка дефекта: все поля и порядок строк входят в несохранённый ввод.
(() => {
  const form = document.querySelector('#defect-draft-form');
  if (!form) return;
  const note = document.querySelector('#draft-dirty-note');
  const snapshot = () => JSON.stringify([...new FormData(form).entries()]);
  const initial = snapshot();
  const rejected = form.dataset.unsaved === '1';
  let leaving = false;
  const dirty = () => rejected || snapshot() !== initial;
  const refresh = () => { if (note) note.hidden = !dirty(); };
  for (const event of ['input', 'change', 'click']) {
    form.addEventListener(event, () => queueMicrotask(refresh));
  }
  window.addEventListener('beforeunload', event => {
    if (leaving || !dirty()) return;
    event.preventDefault();
    event.returnValue = '';
  });
  document.addEventListener('submit', event => {
    if (event.target === form) {
      leaving = true;
      return;
    }
    if (!dirty()) return;
    if (!window.confirm('Есть несохранённые изменения дефекта. Действие использует сохранённый черновик. Продолжить без сохранения ввода?')) {
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }
    leaving = true;
  }, true);
  window.addEventListener('pageshow', () => { leaving = false; refresh(); });
  refresh();
})();

// Исходные данные синхронизации читаются из сохранённого прогона только при раскрытии.
for (const details of document.querySelectorAll('details[data-sync-raw]')) {
  let loading = false;
  let loaded = false;
  details.addEventListener('toggle', async () => {
    if (!details.open || loading || loaded) return;
    loading = true;
    const status = details.querySelector('[data-sync-raw-status]');
    status.textContent = 'Загрузка сохранённых данных…';
    try {
      const response = await fetch(details.dataset.syncRaw, {headers: {'Accept': 'application/json'}});
      if (!response.ok) throw new Error(String(response.status));
      const data = await response.json();
      const content = details.querySelector('[data-sync-raw-content]');
      for (const [label, value] of Object.entries(data)) {
        const heading = document.createElement('h3');
        heading.textContent = label;
        const pre = document.createElement('pre');
        pre.className = 'hub-text';
        pre.textContent = JSON.stringify(value, null, 2);
        content.append(heading, pre);
      }
      loaded = true;
      status.textContent = 'Сохранённые данные загружены.';
    } catch {
      status.textContent = 'Не удалось загрузить данные. Закройте и раскройте блок для повтора.';
    } finally {
      loading = false;
    }
  });
}

// [data-canonical-url]: страница, показанная ответом на отправку формы (отказ сборки текста, ошибка черновика),
// возвращает в адресную строку адрес карточки – обновление страницы не повторяет отправку.
const canonical = document.querySelector('[data-canonical-url]');
if (canonical && location.pathname !== canonical.dataset.canonicalUrl) {
  // page и q – возврат в каталог с фильтром и страницей (ссылка «Дефекты» строится из них)
  history.replaceState(null, '', canonical.dataset.canonicalUrl + location.search + location.hash);
}

// [data-tabs]: вкладки карточки дефекта (Описание, Связанные уязвимости). Без скрипта видна первая вкладка,
// выбор запоминается в адресе (#panel-…), стрелки ←/→ переключают вкладки.
for (const box of document.querySelectorAll('[data-tabs]')) {
  const tabs = [...box.querySelectorAll('[role="tab"]')];
  const select = (tab, focus) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = !on;
    }
    if (focus) tab.focus();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => {
      select(tab, false);
      history.replaceState(null, '', '#' + tab.getAttribute('aria-controls'));
    });
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      select(tabs[(i + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length], true);
    });
  });
  const wanted = tabs.find((t) => '#' + t.getAttribute('aria-controls') === location.hash);
  if (wanted) select(wanted, false);
}
