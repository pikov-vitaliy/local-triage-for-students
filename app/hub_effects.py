"""Что делает приложение, когда исполнитель вернул ответ Hub (этап 2, ADR-0115): отметки «Внесено в Hub» по
выполненной смене статуса и сверка «результата неизвестен» чтением.

* Статус (`status`) выполнен (`done`) – каждой находке из целей ставится отметка «Внесено в Hub» с отпечатком
  текста, посчитанным при постановке, и только если редакция её решения не изменилась (mark_entered сверяет
  редакцию): решение, сохранённое заново после отправки, отметку не получает.
* Сверка идёт кругами: «Сверить» ставит одной транзакцией чтения `GET /issue/status` по всем находкам операции с
  номером круга. Итог считается только по последнему кругу и только когда закрыты все его чтения: каждое выполнено
  и совпало с отправленным (статус, комментарий, дата срока) – операция закрывается как выполненная и ставятся
  отметки; иначе она остаётся «результат неизвестен» с пояснением, решает оператор. Ответы разных кругов не
  смешиваются. Повторной отправки нет никогда.
* Последствия идемпотентны: повторная доставка того же результата (исполнитель не получил подтверждения, приложение
  упало после записи результата) доводит отметки до конца, а уже поставленная отметка с тем же текстом не
  перезаписывается.
* Замена комментария у статуса, который уже стоит в Hub (dev29, ADR-0130): первый шаг (промежуточный статус «Подтверждено») отметок не
  ставит и не ждёт; когда он выполнен, ставится второй шаг – прежний статус с новым комментарием (chain_replace),
  если решение с тех пор не менялось; второй шаг – обычная операция статуса с отметками.
* Дефект из карточки (этап 3, ADR-0120): операции `defect_blank`, `defect_create`, `defect_read`, `defect_link` и
  чтения сверки дефекта переходят в app/hub_defects.after_op – строка `hub_defects`, отметки части «тело дефекта»;
  с 0.9.23.dev4 – и `defect_update` («Push в Hub», ADR-0125).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from app import defect_drafts, hub_defects, hub_ops, hub_status, i18n
from app.db import Database, dumps, loads, now_iso

# сколько после выполнения ждать отметок: исполнитель повторяет доставку результата до 15 минут
EFFECTS_WAIT = timedelta(minutes=16)


class _AlreadyMarked(Exception):
    """Отметка той же редакции тем же текстом уже стоит: запись не нужна (проверка в транзакции mark_entered)."""

# пояснения пишутся в hub_ops.error по-русски, как прочие ошибки операций; перевод – при показе (hub_ops.error_text)
VERIFY_NOTE_MISMATCH = i18n.N_("сверка: в Hub другой статус, комментарий или срок – проверьте находку в Hub")
VERIFY_NOTE_FAILED = i18n.N_("сверка не удалась: чтение статуса из Hub не выполнено – сверьте ещё раз")
VERIFY_NOTE_DONE = i18n.N_("сверено чтением: статус в Hub совпал с отправленным")
CHAIN_NOTE_QUEUED = i18n.N_("прежний статус снят; новый комментарий отправляется следующей операцией")
CHAIN_NOTE_STALE = i18n.N_("прежний статус в Hub снят (стоит «Подтверждено»), а новый комментарий не отправлен: решение "
                           "изменилось, пока шёл первый шаг – отправьте решение в Hub ещё раз")
CHAIN_NOTE_BUSY = i18n.N_("прежний статус в Hub снят (стоит «Подтверждено»), а новый комментарий не отправлен: у находки уже "
                          "есть незакрытая операция статуса – дождитесь её итога и отправьте решение в Hub ещё раз")
CHAIN_NOTE_RESTORED = i18n.N_("База восстановлена из копии: второй шаг замены не поставлен, он мог уже уйти в Hub. Сверьте "
                              "статус с Hub.")
CHAIN_NOTE_LATER = i18n.N_("прежний статус в Hub снят (стоит «Подтверждено»), а второй шаг не ставился: позже принята другая "
                           "версия находки (новая запись или «Pull из Hub») – она и действует")


def after_result(db: Database, op: dict | None, worker_login: str = "",
                 prepare: Callable[[dict], dict] | None = None) -> None:
    """Последствия закрытой операции (и при повторной доставке); ничего не делает для прочих назначений и
    состояний. worker_login – кто в Hub у исполнителя, доставившего результат (записывается в дефект); prepare –
    подготовка «Push в Hub» по текущим решениям (ADR-0125, маршрут с запросом)."""
    if not op:
        return
    if op["purpose"] == "status" and op["state"] == "done":
        status_done(db, op)
    elif op["purpose"] == "read" and op["state"] in ("done", "failed"):
        if hub_defects.is_update_read(op):  # данные находки для сборки служебного блока – шаг «Push в Hub» (ADR-0139)
            hub_defects.after_op(db, op, worker_login, prepare=prepare)
        elif hub_defects.is_defect_read(op):
            hub_defects.after_op(db, op)
        else:
            verify_read(db, op)
    elif op["purpose"].startswith("defect_"):  # в том числе defect_update – «Push в Hub» (ADR-0125)
        hub_defects.after_op(db, op, worker_login, prepare=prepare)


def _same_origin(review: dict, target: dict) -> bool:
    if target.get("entered_origin") not in ("defect", "status"):
        return True
    return all(review.get(key) == target.get(key) for key in
               ("entered_origin", "entered_defect_id", "entered_op_id", "entered_defect_revision"))


def _marked(review: dict | None, target: dict) -> bool:
    return bool(review and _same_origin(review, target) and review["entered_hub"] and int(review["revision"] or 0) == target.get("revision")
                and str(review["entered_text_hash"] or "") == str(target.get("entered_hash") or ""))


def _later_mark(review: dict | None, target: dict, closed_at: str) -> bool:
    """Та же редакция отмечена другим текстом не раньше закрытия операции: это более позднее действие человека
    (отметка из карточки после снятия) – повторная доставка результата (`duplicate`) его не перетирает. Отметка,
    поставленная до закрытия операции, уступает: в Hub ушёл текст операции."""
    return bool(review and review["entered_hub"] and int(review["revision"] or 0) == target.get("revision")
                and (str(review["entered_text_hash"] or "") != str(target.get("entered_hash") or "")
                     or not _same_origin(review, target))
                and closed_at and str(review.get("entered_hub_at") or "") >= closed_at)


def _settled(review: dict | None, target: dict, closed_at: str) -> bool:
    """Отметка по цели больше не ожидается: стоит отметка операции или более поздняя."""
    return _marked(review, target) or _later_mark(review, target, closed_at)


_EXPECT_FIELDS = ("verify_op_id", "confirm_op_id")


def _not_marked_yet(project_id: int, target: dict, closed_at: str, defect_row=None, only_unmarked: bool = False,
                    expect_op: tuple | None = None):
    """Проверка в транзакции отметки: та же редакция уже отмечена тем же текстом или позже другим – _AlreadyMarked
    (дата отметки не перезаписывается и при одновременной повторной доставке); only_unmarked – любая стоящая отметка
    остаётся (отметки по подтверждённому составу после «Проверить в Hub», dev23); expect_op – (поле, номер операции),
    которую строка дефекта должна всё ещё ждать (устаревший обработчик ничего не ставит)."""
    def check(c) -> None:
        if expect_op is not None and defect_row is not None:
            field, op_id = expect_op
            if field not in _EXPECT_FIELDS:
                raise _AlreadyMarked()
            live = c.execute(f"SELECT {field} AS op FROM hub_defects WHERE id = ?", (defect_row["id"],)).fetchone()
            if live is None or live["op"] != op_id:
                raise _AlreadyMarked()
        if target.get("entered_origin") == "defect" and (
                defect_row is None or not defect_drafts.current_effect(c, defect_row, target)):
            raise _AlreadyMarked()
        if defect_row is not None and target.get("entered_origin") != "defect":
            # цель схемы 28: поколение не сверяется, но цель должна оставаться в текущем составе строки – прочитанная
            # до принятия отсутствия строка не вернёт отметку и не снимет пометку «выбыла» (ревью 31.10)
            live = c.execute("SELECT targets_json FROM hub_defects WHERE id = ?", (defect_row["id"],)).fetchone()
            hub_id, typ = str(target.get("hub_id") or ""), str(target.get("issue_type") or "")
            if live is None or not any(str(t.get("hub_id") or "") == hub_id and (not typ or str(t.get("issue_type") or "") == typ)
                                       for t in loads(live["targets_json"], [])):
                raise _AlreadyMarked()
        row = c.execute("SELECT * FROM reviews"
                        " WHERE project_id = ? AND hub_id = ?", (project_id, str(target.get("hub_id") or ""))).fetchone()
        if only_unmarked and row is not None and row["entered_hub"]:
            raise _AlreadyMarked()
        if _settled(dict(row) if row is not None else None, target, closed_at):
            raise _AlreadyMarked()
        if target.get("entered_origin") == "status":
            from app.hub_entity_versions import confirm_status
            if not confirm_status(c, project_id, target):
                raise _AlreadyMarked()
    return check


def chain_pending(op: dict | None) -> bool:
    """Первый шаг замены выполнен, а второй ещё не ставился и не отклонён (then.chained нет): последствия ответа не
    доставлены – сбой между записью результата и after_result, исполнитель перестал повторять доставку."""
    return bool(op and op.get("purpose") == "status" and op.get("state") == "done" and hub_status.is_reset(op)
                and hub_status.chain_of(op).get("chained") is None)


def recover_chains(db: Database) -> int:
    """При запуске: довести цепочки замены, у которых первый шаг выполнен, а второй не ставился (ревью dev29,
    круг 9). Проверки версии, редакции и then.chained – в chain_replace. Возвращает, скольким первым шагам
    поставлен второй."""
    done = 0
    for op in db.hub_unchained_resets():  # прямой запрос, без предела выборки (ревью, круг 10)
        if chain_pending(op) and chain_replace(db, op) is not None:
            done += 1
    return done


def status_done(db: Database, op: dict) -> None:
    """Выполненная операция статуса: первый шаг замены комментария снимает отметку прежнего статуса и ставит второй
    шаг, обычная – отметки."""
    if hub_status.is_reset(op):
        chain_replace(db, op)
    else:
        mark_targets(db, op)


def _withdraw_marks_in(c, op: dict, targets: list[dict]) -> None:
    """Первый шаг замены снял прежний статус в Hub: отметка «Внесено в Hub», подтверждённая записью статуса или
    принятым Pull в этом назначении, снимается (hub_pull.withdraw_status_mark – как при Pull, принявшем «To verify»);
    ручная отметка и отметка дефекта остаются. Вызывается один раз – в транзакции, которая записывает `then.chained`
    первого шага (ревью dev29, круг 3): повторная доставка результата первого шага отметку второго не снимает."""
    from app import hub_pull
    for target in targets:
        hub_id = str(target.get("hub_id") or "")
        local = c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?",
                          (int(op["project_id"]), hub_id)).fetchone() if hub_id else None
        if local is not None:
            hub_pull.withdraw_status_mark(c, op, hub_id, dict(local))


def chain_replace(db: Database, op: dict) -> dict | None:
    """Второй шаг замены комментария (dev29): после выполненного первого (промежуточный статус) – тот же статус с новым
    комментарием и сроком из `then`, теми же целями. Одной транзакцией: номер второго шага (или 0 – не поставлен)
    записывается в `then.chained` первого, поэтому повторная доставка результата первого шага второй не ставит,
    в каком бы состоянии тот ни был (ревью dev29, круг 2). Ключ второго шага различает цепочки (`replace:<номер
    первого>`): возврат к ранее отправленному тексту – новая операция, а не «уже выполнена». Если решение цели
    сохранили заново или у находки есть незакрытая операция статуса – второй шаг не ставится, пояснение остаётся в
    первом (оператор отправляет решение заново). Возвращает поставленную операцию."""
    then = hub_status.chain_of(op)
    targets = [t for t in loads(op.get("targets_json"), []) if isinstance(t, dict)]
    if not then or op.get("project_id") is None or not targets:
        return None
    project_id = int(op["project_id"])
    try:
        request = hub_status.status_request(targets, str(then["status"]), str(then["reason"]),
                                            str(then.get("expiredAt") or ""))
    except (hub_status.StatusRefused, hub_ops.HubRequestRejected):
        return None
    with db._tx() as c:
        row = c.execute("SELECT request_json, state FROM hub_ops WHERE id = ?", (int(op["id"]),)).fetchone()
        if row is None or row["state"] != "done":
            return None
        current = loads(row["request_json"], {}) or {}
        link = dict(current.get("then") or {})
        if link.get("chained") is not None:  # второй шаг уже ставился (или решено не ставить): повтор не создаёт
            return None

        def finish(note: str, chained: int) -> None:
            link["chained"] = chained
            current["then"] = link
            c.execute("UPDATE hub_ops SET request_json = ?, error = ?, updated_at = ? WHERE id = ?",
                      (dumps(current), note[:2000], now_iso(), int(op["id"])))

        # принятая версия каждой цели всё ещё подтверждена этим первым шагом (ревью dev29, круг 4): последствия,
        # отложенные до более поздней записи или принятого Pull, не снимают их отметок и не ставят второй POST
        from app.hub_entity_versions import confirmable
        for target in targets:
            _, confirmed, _, _ = confirmable(c, project_id, {**target, "entered_op_id": int(op["id"])})
            if not confirmed:
                finish(CHAIN_NOTE_LATER, 0)
                return None
        _withdraw_marks_in(c, op, targets)  # прежний статус снят – отметка о нём снимается, один раз
        if link.get("stop_after_restore"):  # база восстановлена из копии: второй шаг мог уже уйти в Hub, его ставит только оператор
            finish(CHAIN_NOTE_RESTORED, 0)
            return None

        for target in targets:  # решение каждой цели – той же редакции и «Проверено», как при подтверждении замены
            review = c.execute("SELECT revision, reviewed FROM reviews WHERE project_id = ? AND hub_id = ?",
                               (project_id, str(target.get("hub_id") or ""))).fetchone()
            if review is None or int(review["revision"] or 0) != target.get("revision") or not review["reviewed"]:
                finish(CHAIN_NOTE_STALE, 0)
                return None
        try:
            new = db._hub_insert(c, purpose="status", request=request, hub_url=op["hub_url"],
                                 app_id=op.get("app_id"), project_id=project_id, targets=targets,
                                 text=str(then["reason"]), key_extra=f"replace:{int(op['id'])}")
        except ValueError:  # у находки незакрытая операция статуса (другая вкладка) – второй шаг не ставится
            finish(CHAIN_NOTE_BUSY, 0)
            return None
        finish(CHAIN_NOTE_QUEUED, int(new["id"]))
        return new


def mark_targets(db: Database, op: dict) -> int:
    """Отметки «Внесено в Hub» целям выполненной операции; возвращает, скольким поставлены сейчас. Цель с другой
    редакцией не отмечается; уже отмеченная тем же текстом той же редакции – пропускается. Первый шаг замены
    комментария (промежуточный статус) отметок не ставит."""
    project_id = op.get("project_id")
    if project_id is None or hub_status.is_reset(op):
        return 0
    marked = 0
    closed_at = str(op.get("closed_at") or "")
    for target in loads(op.get("targets_json"), []):
        if op.get("purpose") == "status":
            target = {**target, "entered_origin": "status", "entered_op_id": op["id"],
                      "entered_defect_id": None, "entered_defect_revision": 0}
            # Подтверждённая запись Hub меняет порядок версий и после правки локального решения.
            # Отметка текущей редакции ниже по-прежнему требует совпадения revision.
            from app.hub_entity_versions import confirm_status
            with db._tx() as c:
                if not confirm_status(c, int(project_id), target):
                    continue
        hub_id, entered_hash = str(target.get("hub_id") or ""), str(target.get("entered_hash") or "")
        revision = target.get("revision")
        if not hub_id or not entered_hash or not isinstance(revision, int) or isinstance(revision, bool):
            continue
        try:
            row = db.mark_entered(int(project_id), hub_id, True, revision=revision, entered_hash=entered_hash,
                                  entered_parts=str(target.get("entered_parts") or ""),
                                  entered_origin=str(target.get("entered_origin") or ""),
                                  entered_defect_id=target.get("entered_defect_id"), entered_op_id=target.get("entered_op_id"),
                                  entered_defect_revision=int(target.get("entered_defect_revision") or 0),
                                  entered_decision_hash=str(target.get("decision_hash") or ""),
                                  check=_not_marked_yet(int(project_id), target, closed_at, op.get("defect_row"),
                                                        only_unmarked=bool(op.get("only_unmarked")),
                                                        expect_op=op.get("expect_op")))
        except _AlreadyMarked:
            continue
        if row is not None:
            marked += 1
    return marked


def effects_pending(db: Database, op: dict | None) -> bool:
    """Выполненная операция статуса, у которой отметка ещё может появиться: есть цель с той же редакцией без отметки,
    а со времени выполнения прошло меньше EFFECTS_WAIT (сбой после записи ответа доводит повторная доставка). Карточка
    до тех пор продолжает опрос и перезагружается, когда отметки поставлены."""
    if not op or op["purpose"] != "status" or op["state"] != "done" or op.get("project_id") is None:
        return False
    if legacy_status_needs_read(op) or hub_status.is_reset(op):  # первый шаг замены комментария отметок не ждёт
        return False
    try:
        closed = datetime.fromisoformat(str(op.get("closed_at") or ""))
    except ValueError:
        return False
    if closed.tzinfo is None:
        closed = closed.replace(tzinfo=UTC)
    if datetime.now(UTC) - closed > EFFECTS_WAIT:
        return False
    closed_at = str(op.get("closed_at") or "")
    from app.hub_entity_versions import confirmable
    for target in loads(op.get("targets_json"), []):
        target = {**target, "entered_origin": "status", "entered_op_id": op["id"],
                  "entered_defect_id": None, "entered_defect_revision": 0}
        review = db.get_review(int(op["project_id"]), str(target.get("hub_id") or ""))
        if review and int(review.get("revision") or 0) == target.get("revision") and not _settled(review, target, closed_at):
            # отметка, которую версия цели уже не допускает (принят более новый Pull), не ожидается (ревью dev16)
            if db.on_connection(lambda c, t=target: confirmable(c, int(op["project_id"]), t)[0]):
                return True
    return False


def legacy_status_needs_read(op: dict | None) -> bool:
    """Успешная операция прежней схемы без версии может подтверждаться только новым чтением."""
    if not op or op["purpose"] != "status" or op["state"] != "done":
        return False
    bases = loads(op.get("request_json"), {}).get("accepted_issue_bases", {})
    return any(f"{t['issue_type']}:{t['issue_id']}" not in bases for t in loads(op.get("targets_json"), []))


def next_round(db: Database, origin_id: int) -> int:
    """Номер следующего круга сверки операции origin_id."""
    return max((_round(row) for row in db.hub_verifications(origin_id)), default=0) + 1


def verify_requests(op: dict, round_no: int = 1) -> list[tuple[dict, list[dict]]]:
    """Чтения круга сверки операции статуса: (запрос, цели) на каждую находку."""
    out = []
    for target in loads(op.get("targets_json"), []):
        read_target = {"verify_of": op["id"], "round": int(round_no), "issue_id": target["issue_id"],
                       "issue_type": target["issue_type"], "hub_id": target.get("hub_id", "")}
        out.append((hub_status.read_request(target), [read_target]))
    return out


def _first_target(row: dict) -> dict:
    targets = loads(row.get("targets_json"), [])
    return targets[0] if targets and isinstance(targets[0], dict) else {}


def _issue_key(target: dict) -> tuple[str, str]:
    """Находка цели – (тип, номер в Hub)."""
    return str(target.get("issue_type") or ""), str(target.get("issue_id") or "")


def _round(row: dict) -> int:
    value = _first_target(row).get("round")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def verify_read(db: Database, read_op: dict) -> None:
    """Чтение сверки закрыто: итог по последнему кругу, когда закрыты все его чтения."""
    origin_id = _first_target(read_op).get("verify_of")
    if not isinstance(origin_id, int) or isinstance(origin_id, bool):
        return
    origin = db.hub_op(origin_id)
    if origin is None or origin["purpose"] != "status":
        return
    legacy = legacy_status_needs_read(origin)
    if origin["state"] == "done" and not legacy:
        status_done(db, origin)  # повторная доставка после сбоя: довести отметки (или поставить второй шаг замены)
        return
    if origin["state"] != "unknown" and not legacy:
        return
    reads = db.hub_verifications(origin_id)
    last = max((_round(row) for row in reads), default=0)
    if _round(read_op) != last:
        return  # чтение прежнего круга: итог считается только по последнему
    # чтения круга – по номеру и типу находки: у SAST и SCA номера Hub могут совпадать, и чтение одной находки не
    # должно закрыть сверку другой (план 09.11, этап 3)
    rows = {_issue_key(_first_target(row)): row for row in reads if _round(row) == last}
    wanted = {_issue_key(t) for t in loads(origin.get("targets_json"), [])}
    if set(rows) != wanted or any(row["state"] not in ("done", "failed") for row in rows.values()):
        return  # круг ещё не закрыт
    if any(row["state"] == "failed" for row in rows.values()):
        db.hub_note(origin_id, VERIFY_NOTE_FAILED)
        return
    body = (loads(origin.get("request_json"), {}) or {}).get("body") or {}
    expected: dict[str, Any] = {"status": body.get("status", ""), "reason": body.get("reason", ""),
                                "expired": body.get("expiredAt", "")}
    for row in rows.values():
        answer = hub_ops.parse_json((loads(row.get("result_json"), {}) or {}).get("body_text", ""))
        if not hub_status.status_matches(answer, expected["status"], expected["reason"], expected["expired"],
                                         target=_first_target(row)):
            db.hub_note(origin_id, VERIFY_NOTE_MISMATCH)
            return
    def still_last(c) -> bool:  # пока считали итог, другая вкладка могла поставить новый круг
        newer = c.execute("SELECT 1 FROM hub_ops WHERE purpose = 'read'"
                          " AND (targets_json::json -> 0 ->> 'verify_of') = ?"
                          " AND COALESCE((targets_json::json -> 0 ->> 'round')::bigint, 0) > ? LIMIT 1",
                          (str(origin_id), last)).fetchone()
        if newer is not None:
            return False
        from app.db import dumps
        from app.hub_entity_versions import current
        bases = {}
        for checked in rows.values():
            for key, expected_base in loads(checked["request_json"], {}).get("accepted_issue_bases", {}).items():
                if expected_base != current(c, origin["project_id"], origin["hub_url"], origin["app_id"], "issue", key):
                    return False
                bases[key] = expected_base
        keys = {f"{t['issue_type']}:{t['issue_id']}" for t in loads(origin["targets_json"], [])}
        if set(bases) != keys:
            return False
        fresh = loads(origin["request_json"], {})
        fresh["accepted_issue_bases"] = bases
        c.execute("UPDATE hub_ops SET request_json=? WHERE id=?", (dumps(fresh), origin_id))
        return True

    if legacy:
        with db._tx() as c:
            current_op = dict(c.execute("SELECT * FROM hub_ops WHERE id=?", (origin_id,)).fetchone())
            if not legacy_status_needs_read(current_op) or not still_last(c):
                return
            c.execute("UPDATE hub_ops SET error=? WHERE id=?", (VERIFY_NOTE_DONE, origin_id))
            resolved = dict(c.execute("SELECT * FROM hub_ops WHERE id=?", (origin_id,)).fetchone())
            from app.hub_entity_versions import confirm_targets
            confirm_targets(c, resolved)  # версии целей – до конца транзакции сверки, не при отметках (ревью dev16)
    else:
        resolved = db.hub_resolve(origin_id, "done", VERIFY_NOTE_DONE, check=still_last)
    if resolved is not None:
        status_done(db, resolved)
