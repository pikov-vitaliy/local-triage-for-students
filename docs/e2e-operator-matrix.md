---
title: "Сценарии оператора и проверки в браузере"
type: guide
status: active
date: 2026-11-05
tags: [testing, e2e, operator, hub, postgresql]
related: []
---

# Сценарии оператора и проверки в браузере

Таблица связывает 20 сценариев с проверками в `tests/e2e`. Модель, исполнитель и Hub в них поддельные. Запуск: `scripts/run-e2e.ps1`.

| № | Сценарий | Файл::тест | Что проверяется |
|---|---|---|---|
| 1 | Загрузка выгрузки и проект | `test_stage3::test_hub_report_with_hyperlink_formulas_imports` | выгрузка с формулами HYPERLINK принимается, книга с другой формулой отклоняется |
| 1 | Загрузка выгрузки и проект | `test_workflow::test_demo_project_from_triage_to_reimport` | демо-проект от разбора до повторной загрузки выгрузки |
| 2 | Прогон модели: пауза, продолжение | `test_operator_matrix::test_run_pause_resume_and_finish_the_same_run` | «Пауза», «Продолжить», рост счётчика, тот же прогон доходит до конца, каждая находка спрошена один раз |
| 2 | Прогон модели: стоп, повтор | `test_operator_readiness::test_operator_can_pause_resume_stop_and_finish_remaining_items` | «Стоп», затем новый прогон доходит до конца |
| 3 | Карточка SAST: решение | `test_operator_readiness::test_operator_mouse_decisions_survive_reopening` | три решения мышью сохраняются после перезагрузки |
| 3 | «Проверено» | `test_workflow::test_demo_project_from_triage_to_reimport` | флажок «Проверено» и отметка в карточке |
| 3 | Группа и соседи | `test_operator_readiness::test_group_sibling_decision_and_text_can_be_taken` | соседка видна, решение и текст переносятся |
| 3 | | `test_operator_sast_route::test_group_take_all_and_refusal_on_different_text` | «Взять решение и текст у всех»; при другом тексте дефект не готовится, приложение называет расхождение |
| 4 | Ложное срабатывание, статус в Hub | `test_hub_status_card::test_sast_false_positive_goes_to_hub` | отправка из карточки SAST, срок, отметка |
| 4 | | `test_hub_status_card::test_send_selected_from_list` | отправка выбранных из списка |
| 4 | Принятый риск, статус в Hub | `test_operator_matrix::test_sca_risk_accepted_goes_to_hub` | `Accepted risk`, `SCA_S`, комментарий, отметка |
| 5 | Замена комментария | `test_hub_status_card::test_replace_comment_of_status_already_in_hub` | «Confirmed», затем статус с новым комментарием |
| 6 | Дефект SAST: один | `test_hub_defect_card::test_defect_from_sast_card` | заготовка, предпросмотр, «Создать», номер, отметка |
| 7 | Дефект SAST: из выбранных | `test_defect_selected_flow::test_selected_flow_and_pull` | дефект по выбранным находкам и «Pull из Hub» |
| 8 | Привязка к дефекту | `test_hub_defect_card::test_new_group_member_is_linked_with_polling` | новая находка группы привязывается, опрос до итога |
| 8 | Два решения SAST | `test_stage3::test_statuses_two_outcomes_and_sast_defect` | ложное срабатывание: комментарий; подтверждённый дефект: заголовок `ID1` и текст |
| 8 | Карточка дефекта | `test_defect_card_page::test_defect_card_edit_and_update` | правка черновика и обновление со страницы дефекта |
| 9 | SCA: задание, исследование, импорт ответа | `test_component_research::test_component_research_cycle` | полный цикл исследования компонента |
| 10 | SCA: решение по версии, наборы | `test_operator_matrix::test_sca_finding_moves_between_sets` | решение по версии даёт общий набор; перенос в новый набор и обратно, состав у находки и соседки |
| 11 | SCA: ложное срабатывание | `test_hub_status_card::test_sca_false_positive_goes_to_hub` | `False Positive`, `SCA_S`, отметка |
| 11 | SCA: риск | `test_operator_matrix::test_sca_risk_accepted_goes_to_hub` | то же для `Accepted risk` |
| 12 | Дефект SCA | `test_operator_matrix::test_sca_defect_created_through_hub` | заготовка `type=SCA_S`, «Создать», №, `ID<n>` в заголовке, строка во вкладке «Дефекты» |
| 12 | Отметка дефекта SCA | `test_operator_matrix::test_sca_defect_badge_names_the_defect` | статус в Hub не отправлялся, отметка в карточке находки говорит о дефекте |
| 13 | «Push в Hub», SAST | `test_hub_defect_update_flow::test_prepare_preview_update_confirm_restart_and_verify` | предпросмотр, чтение, `PUT`, подтверждение, перезапуск, сверка |
| 13 | «Push в Hub», SCA | `test_operator_matrix::test_sca_defect_pull_and_push` | тело `PUT`: заменены только заголовок и описание, блок Hub на месте |
| 14 | «Pull из Hub», SAST | `test_hub_defect_import_flow::test_import_cancel_accept_sync_and_restart` | занесение, отмена, принятие, Pull, перезапуск |
| 14 | «Pull из Hub», SCA | `test_operator_matrix::test_sca_defect_pull_and_push` | во вкладке и в карточке дефекта: «совпадает», в том числе после записи |
| 15 | «Синхронизировать» | `test_hub_sync_flow::test_sync_apply_then_second_sync_matches` | применение, вторая синхронизация без расхождений |
| 15 | | `test_hub_sync_flow::test_hub_sync_confirmation_progress_stop_resume_diffs_and_matches` | подтверждение, ход, стоп, продолжение, расхождения |
| 16 | Журнал прогонов | `test_journal_workflow::test_journal_run_snapshot_filter_export_and_small_screen` | снимок прогона, отбор, выгрузка, узкий экран |
| 17 | Справочники | `test_stage3::test_feeds_upload_and_sca_defect_with_bdu` | загрузка БДУ и записи в карточке SCA |
| 17 | | `test_capec_workflow::test_capec_upload_catalog_and_return` | загрузка и каталог CAPEC |
| 17 | | `test_cwe_reference::test_cwe_list_search_filter_and_card` | список, поиск, отбор и карточка CWE |
| 17 | | `test_reference_updates_ui::test_reference_update_missing_id_and_return` | обновление справочника, отсутствующий номер |
| 18 | Настройки | `test_pages::test_settings_check_ollama_and_save` | проверка Ollama и сохранение |
| 18 | | `test_hub_settings::test_hub_section_probe_with_fake_worker` | раздел Hub, проверка через исполнителя |
| 18 | Провайдеры | `test_provider_form_chat::test_chat_profile_form_is_short_and_search_takes_standard_paths` | форма профиля и стандартные пути |
| 18 | | `test_providers_e2e::test_lan_profile_from_the_form_to_a_run` | профиль сервера в сети от формы до прогона |
| 19 | Перезапуск посреди прогона | `test_operator_matrix::test_restart_in_the_middle_of_a_run` | пауза с пояснением, «Продолжить», тот же прогон доходит до конца |
| 19 | Перезапуск посреди замены комментария | `test_operator_matrix::test_restart_after_first_step_of_comment_replace` | после запуска исполнитель получает только второй шаг |
| 20 | Неизвестный исход: статус | `test_hub_status_card::test_unknown_result_offers_verify_without_reload` | карточка предлагает сверку без перезагрузки |
| 20 | Неизвестный исход: создание дефекта | `test_defect_selected_flow::test_lost_create_response_visible_verify_without_second_post` | потерянный ответ, сверка без второго `POST` |

В варианте `crash_before_second_step` сценария 19 состояние готовится прямой правкой тестовой базы, пока приложение остановлено: сбой между записью результата первого шага и постановкой второго снаружи не поймать. Запуск и `recover_chains` работают как обычно. Отметка прежнего статуса к этому моменту уже снята первым проходом, поэтому её снятие внутри `recover_chains` этот вариант не проверяет.
