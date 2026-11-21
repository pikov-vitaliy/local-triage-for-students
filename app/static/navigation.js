/* Возврат к месту работы и черновик решения компонента. sessionStorage изолирует вкладки. */
(function () {
  "use strict";
  function read(key) { try { return JSON.parse(sessionStorage.getItem(key)); } catch (e) { return null; } }
  function write(key, value) {
    try { sessionStorage.setItem(key, JSON.stringify(value)); return true; } catch (e) { return false; }
  }
  function remove(key) { try { sessionStorage.removeItem(key); } catch (e) { /* недоступное хранилище */ } }
  function rememberPosition(key, value) {
    var index = read("work-position-index") || [];
    index = index.filter(function (x) { return x !== key; }); index.push(key);
    while (index.length > 160) remove(index.shift());
    write("work-position-index", index); write(key, value);
  }
  function address(value) {
    var u = new URL(value, location.href);
    var params = new URLSearchParams(u.search); params.sort();
    if (params.get("page") === "1") params.delete("page");
    return decodeURIComponent(u.pathname) + (params.toString() ? "?" + params.toString() : "");
  }
  function here() { return address(location.href); }

  // Положение хранится по полному отбору; прямой вход по закладке не прыгает к старому месту.
  var positionKey = "work-position:" + here();
  var focusedLink = "", focusedRow = "", positionAlias = "";
  document.addEventListener("click", function (event) {
    var link = event.target.closest("a[href]");
    if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || link.target === "_blank") return;
    var target = new URL(link.href, location.href);
    if (target.origin !== location.origin || address(target.href) === here()) return;
    // Отбор/сброс/пагинация сами задают новое состояние списка. Старые раскрытия при этом не восстанавливаются.
    if (target.pathname === location.pathname) { remove("work-restore"); return; }
    if (link.closest("table")) {
      focusedLink = address(target.href);
      focusedRow = (link.closest("tr") || {}).id || "";
      var back = target.searchParams.get("back");
      if (back && back.charAt(0) === "/") positionAlias = "work-position:" + address(back);
    }
    write("work-restore", address(target.href));
  });
  window.addEventListener("pagehide", function () {
    var position = {y: window.scrollY, focus: focusedLink, row: focusedRow,
      open: Array.from(document.querySelectorAll("details[id][open]")).map(function (x) { return x.id; })};
    rememberPosition(positionKey, position);
    if (positionAlias) rememberPosition(positionAlias, position);
  });
  var pending = read("work-restore");
  remove("work-restore");
  var entry = performance.getEntriesByType("navigation")[0];
  if (pending === here() || (entry && (entry.type === "back_forward" || entry.type === "reload"))) {
    var saved = read(positionKey);
    if (saved && typeof saved.y === "number") {
      (saved.open || []).forEach(function (id) { var x = document.getElementById(id); if (x && x.tagName === "DETAILS") x.open = true; });
      requestAnimationFrame(function () { requestAnimationFrame(function () {
        window.scrollTo(0, saved.y);
        if (!saved.focus) return;
        var row = saved.row ? document.getElementById(saved.row) : null;
        var link = (row ? row.querySelector("a[href]") : null) || Array.from(document.querySelectorAll("table a[href]")).find(function (a) {
          return address(a.href) === saved.focus;
        });
        if (link) {
          link.focus({preventScroll: true});
          row = link.closest("tr"); if (row) row.classList.add("is-returned");
        } else {
          var note = document.getElementById("sr-status");
          if (note) note.textContent = "Исходная строка больше не входит в текущую выборку. Показан обновлённый список.";
        }
      }); });
    }
  }

  function decisionFields(target) {
    if (!target) return function () {};
    var action = target.elements.namedItem("action");
    function sync() {
      ["target_version", "replacement_name", "replacement_version"].forEach(function (name) {
        var field = target.elements.namedItem(name);
        var active = action.value === (name === "target_version" ? "update" : "replace");
        field.closest("label").hidden = !active;
        field.disabled = !active;
        field.required = active && name !== "replacement_version";
      });
    }
    action.addEventListener("change", sync); sync(); return sync;
  }
  var batch = document.getElementById("batch-decision-form");
  var syncBatchFields = decisionFields(batch);
  if (batch) {
    // страница «Решение по выбранным версиям» – те же быстрые сроки и черновик по исследованию, что у карточки
    // компонента
    batch.querySelectorAll("[data-review-date]").forEach(function (button) {
      button.addEventListener("click", function () {
        batch.elements.namedItem("review_at").value = button.getAttribute("data-review-date");
      });
    });
    var batchFill = document.getElementById("fill-from-research");
    var batchStatus = document.getElementById("batch-draft-status");
    if (batchFill) batchFill.addEventListener("click", function () {
      var draft = {};
      try { draft = JSON.parse(batchFill.getAttribute("data-draft") || "{}") || {}; } catch (e) { draft = {}; }
      var filled = 0;
      ["action", "rationale", "target_version", "review_at", "replacement_name", "replacement_version"].forEach(function (name) {
        var field = batch.elements.namedItem(name);
        if (field && typeof draft[name] === "string" && draft[name] && !field.value) { field.value = draft[name]; filled += 1; }
      });
      syncBatchFields();
      if (batchStatus) batchStatus.textContent = filled
        ? "Пустые поля заполнены по исследованию – проверьте и поправьте их, затем примените решение."
        : "Заполнять нечего: поля уже заполнены. Очистите поле, чтобы взять значение из исследования.";
    });
  }
  var form = document.getElementById("decision-form");
  if (!form) return;
  var syncDecisionFields = decisionFields(form);
  var status = document.getElementById("component-draft-status");
  var check = document.getElementById("component-draft-check");
  var confirm = document.getElementById("component-draft-confirm");
  var discard = document.getElementById("discard-component-draft");
  var key = "component-draft:1:" + location.pathname;
  var names = ["action", "rationale", "target_version", "review_at", "replacement_name", "replacement_version"];
  var seenNames = ["revision", "expected_input_sig", "expected_research_sig", "expected_research_revision"];
  var buttons = [document.getElementById("save-component-decision"), document.getElementById("save-component-next"),
                 document.getElementById("save-component-apply")].filter(Boolean);
  var edits = 0, sending = false, dirty = false, stored = false;
  function values(fields) {
    var result = {}; fields.forEach(function (name) { result[name] = form.elements.namedItem(name).value; }); return result;
  }
  var baseline = values(names), seen = values(seenNames);
  function say(text, error) { status.textContent = text; status.classList.toggle("text-warn", !!error); }
  function updateButtons() { buttons.forEach(function (b) { b.disabled = sending || (!check.hidden && !confirm.checked); }); }
  function saveDraft() {
    stored = write(key, {v: 1, fields: values(names), seen: values(seenNames), needsCheck: !check.hidden && !confirm.checked});
    return stored;
  }
  function changed() {
    edits += 1;
    dirty = JSON.stringify(values(names)) !== JSON.stringify(baseline);
    discard.hidden = !dirty;
    if (dirty) {
      if (saveDraft()) say("Черновик сохранён в этой вкладке; решение ещё не сохранено.");
      else say("Хранилище вкладки недоступно. Не закрывайте страницу до сохранения решения.", true);
    } else { remove(key); say("Изменений нет. Показано сохранённое решение."); }
  }
  names.forEach(function (name) {
    var field = form.elements.namedItem(name); field.addEventListener("input", changed); field.addEventListener("change", changed);
  });
  confirm.addEventListener("change", function () { saveDraft(); updateButtons(); });
  // быстрый срок пересмотра (вариант А): даты посчитаны сервером от даты приложения
  form.querySelectorAll("[data-review-date]").forEach(function (button) {
    button.addEventListener("click", function () {
      var field = form.elements.namedItem("review_at");
      field.value = button.getAttribute("data-review-date");
      changed();
    });
  });
  // черновик по исследованию (вариант Б): только пустые поля, решение сохраняет человек
  var fill = document.getElementById("fill-from-research");
  if (fill) fill.addEventListener("click", function () {
    var draft = {};
    try { draft = JSON.parse(fill.getAttribute("data-draft") || "{}") || {}; } catch (e) { draft = {}; }
    var filled = 0;
    names.forEach(function (name) {
      var field = form.elements.namedItem(name);
      if (typeof draft[name] === "string" && draft[name] && !field.value) { field.value = draft[name]; filled += 1; }
    });
    syncDecisionFields();
    changed();
    say(filled ? "Пустые поля заполнены по исследованию – проверьте и поправьте их, затем сохраните решение."
               : "Заполнять нечего: поля уже заполнены. Очистите поле, чтобы взять значение из исследования.");
  });
  discard.addEventListener("click", function () {
    names.forEach(function (name) { form.elements.namedItem(name).value = baseline[name]; });
    syncDecisionFields();
    dirty = false; check.hidden = true; confirm.checked = false; discard.hidden = true;
    remove(key); updateButtons(); say("Черновик отброшен. Восстановлены значения с открытой страницы.");
  });
  var draft = read(key);
  if (draft && draft.v === 1 && draft.fields && JSON.stringify(draft.fields) !== JSON.stringify(baseline)) {
    names.forEach(function (name) { if (typeof draft.fields[name] === "string") form.elements.namedItem(name).value = draft.fields[name]; });
    syncDecisionFields();
    dirty = true; stored = true; discard.hidden = false;
    if (draft.needsCheck || JSON.stringify(draft.seen) !== JSON.stringify(seen)) check.hidden = false;
    say("Черновик восстановлен в форму, но не сохранён как решение." + (check.hidden ? "" : " Сверьте изменившиеся сведения."), !check.hidden);
    updateButtons();
  } else if (draft) { remove(key); }
  window.addEventListener("beforeunload", function (event) {
    if (!dirty || saveDraft()) return;
    event.preventDefault(); event.returnValue = "";
  });
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (sending || (!check.hidden && !confirm.checked)) return;
    var data = new FormData(form), sent = edits, fields = values(names);
    form.querySelectorAll("[aria-invalid]").forEach(function (field) { field.removeAttribute("aria-invalid"); field.removeAttribute("aria-errormessage"); });
    if (event.submitter && event.submitter.name) data.set(event.submitter.name, event.submitter.value);
    sending = true; updateButtons(); say("Сохраняется решение…");
    fetch(form.getAttribute("action"), {method: "POST", body: data, headers: {Accept: "application/json"}, credentials: "same-origin"})
      .then(function (response) { return response.json().then(function (answer) {
        if (!response.ok || !answer.ok) {
          var box = document.getElementById("decision-error");
          if (!box) { box = document.createElement("div"); box.id = "decision-error"; box.className = "callout callout-warn"; box.setAttribute("role", "alert"); form.parentNode.insertBefore(box, form); }
          box.setAttribute("tabindex", "-1");
          box.textContent = (answer.detail || "Решение не сохранено.") + " Введённый текст оставлен в форме." +
            (response.status === 409 ? " Обновите страницу и сверьте сведения перед повторным сохранением." :
             response.status === 422 ? " Исправьте указанное поле и сохраните решение снова." : " Повторите сохранение.");
          var invalid = answer.error_field && form.elements.namedItem(answer.error_field);
          if (invalid && !invalid.disabled) {
            invalid.setAttribute("aria-invalid", "true"); invalid.setAttribute("aria-errormessage", "decision-error");
            invalid.focus();
          } else { box.focus(); }
          throw new Error(answer.detail || "Решение не сохранено.");
        }
        form.elements.namedItem("revision").value = String(answer.revision);
        baseline = fields;
        if (edits === sent) {
          dirty = false; remove(key);
          // сбой записи находкам (apply_message): оба итога показываются здесь – странице карточки нужна база
          if (answer.apply_message) { say("Решение сохранено. " + answer.apply_message); }
          else { location.assign(answer.redirect); }
        } else {
          saveDraft(); check.hidden = true; confirm.checked = false;
          // «Сохранить и применить к находкам»: итог записи находкам сообщается и при оставшемся черновике
          var applyNote = answer.apply_message
            ? " " + answer.apply_message
            : (answer.apply_error
              ? " Находкам решение не записано: сохраните правки, обновите страницу и примените решение ещё раз."
              : (answer.applied ? " Находкам этой версии решение записано: " + answer.applied + "." : ""));
          say("Отправленное решение сохранено; новые правки остались черновиком и ещё не сохранены." + applyNote);
        }
      }); })
      .catch(function (error) { say(error.message + (stored ? " Черновик сохранён в этой вкладке." : " Не закрывайте страницу: решение не сохранено."), true); })
      .finally(function () { sending = false; updateButtons(); });
  });
})();
