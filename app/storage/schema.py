"""Манифест схемы 33 (S): таблицы, колонки, ключи и порядок загрузки, по которому база переносилась из SQLite (инструменты
переноса удалены в 0.10.0.dev8).

Не меняется при новых миграциях; совпадение с базовой схемой проверяет tests/test_storage_store.py::test_manifest_matches_catalog."""

from __future__ import annotations

SCHEMA_VERSION = 36

# Колонки, добавленные миграциями после базовой схемы: базовый манифест TABLES не меняется (переносы из SQLite опирались
# на него), ожидаемая текущая структура – TABLES плюс эти колонки (app.db._expected_layout).
ADDED_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    'projects': (('mask_secrets', 'BIGINT'), ('identity_rev', 'BIGINT')),  # 0003 – схема 35; 0004 – схема 36
    'findings': (('pkg_ecosystem', 'TEXT'), ('pkg_name', 'TEXT'), ('pkg_source', 'TEXT'), ('pkg_note', 'TEXT'),
                 ('pkg_scope', 'TEXT'), ('pkg_rev', 'BIGINT')),  # 0004, схема 36
    'sca2_research': (('origin_ref', 'TEXT'),),  # 0004, схема 36
    'sca_set_members': (('pending_reason', 'TEXT'),),  # 0004, схема 36
}

# Таблицы, созданные миграциями после базовой схемы (формат – как у TABLES): базовый манифест не меняется.
ADDED_TABLES: dict[str, dict] = {
    'sca_identity_archive': {  # 0004, схема 36: история сущностей, снятых переходом идентичности пакета
        'columns': ('id', 'project_id', 'run_id', 'archived_at', 'source_table', 'key_json', 'row_json',
                    'moved_to_ref', 'reason'),
        'types': ('BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
}

TABLES: dict[str, dict] = {
    'ast_map': {
        'columns': ('ast_id', 'vuln_id', 'source', 'created_at'),
        'types': ('TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('ast_id', 'vuln_id'),
        'identity': None,
        'refs': (),
        'autoincrement': False,
    },
    'cases': {
        'columns': ('project_id', 'hub_id', 'case_hash', 'context_json', 'verdict_id', 'updated_at', 'code_cmp'),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'hub_id'),
        'identity': None,
        'refs': ('projects', 'verdicts'),
        'autoincrement': False,
    },
    'codebase_map': {
        'columns': ('project_id', 'codebase', 'folder', 'manual', 'updated_at'),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT'),
        'pk': ('project_id', 'codebase'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'defects': {
        'columns': ('project_id', 'defect_key', 'number', 'updated_at', 'assigned_at'),
        'types': ('BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'defect_key'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'findings': {
        'columns': (
        'id', 'project_id', 'hub_id', 'import_id', 'pos', 'kind', 'severity', 'cvss', 'urgent', 'codebase',
        'group_key', 'data_json', 'missing', 'missing_since', 'group_key2', 'g2_cat', 'g2_file', 'g2_line',
        'file_import_id', 'file_checked_import_id', 'file_presence', 'file_missing_since', 'file_data_json',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'DOUBLE PRECISION', 'BIGINT', 'TEXT',
        'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT', 'TEXT',
        'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'hub_attempts': {
        'columns': (
        'id', 'op_id', 'worker_id', 'lease_token', 'taken_at', 'taken_until', 'result_json', 'error',
        'received_at', 'late',
        ),
        'types': ('BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('hub_ops',),
        'autoincrement': True,
    },
    'hub_defect_history': {
        'columns': (
        'id', 'defect_id', 'row_id', 'revision', 'event', 'summary', 'command_text', 'details_json', 'op_id',
        'created_at',
        ),
        'types': ('BIGINT', 'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('hub_defects',),
        'autoincrement': True,
    },
    'hub_defect_reference_loads': {
        'columns': ('id', 'project_id', 'hub_url', 'app_id', 'state', 'load_json', 'created_at', 'closed_at'),
        'types': ('BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'hub_defect_sync_runs': {
        'columns': (
        'id', 'project_id', 'hub_url', 'app_id', 'state', 'run_json', 'created_at', 'closed_at', 'revision',
        'generation', 'snapshot_hash', 'applied_at', 'result_json',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT',
        'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'hub_defects': {
        'columns': (
        'id', 'project_id', 'kind', 'number', 'summary', 'anchor_hub_id', 'targets_json', 'left_out_json',
        'warnings_json', 'number_keys_json', 'command_text', 'source_fingerprint', 'body_html', 'blank_json',
        'priority', 'severity', 'hub_url', 'app_id', 'hub_defect_id', 'hub_link', 'blank_op_id',
        'create_op_id', 'read_op_id', 'link_op_id', 'verify_json', 'verify_op_id', 'confirm_op_id',
        'effects_done', 'state', 'error', 'created_by', 'created_at', 'updated_at', 'closed_at', 'origin',
        'import_json', 'sync_op_id', 'sync_json', 'update_op_id', 'update_json', 'text_generation',
        'draft_owner_id', 'draft_summary', 'draft_command_text', 'draft_fields_json',
        'confirmed_object_json', 'conflicts_json', 'draft_revision', 'sca_set_key',
        'draft_fields_basis_json',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT',
        'BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'hub_entity_versions': {
        'columns': (
        'project_id', 'hub_url', 'app_id', 'entity_kind', 'entity_key', 'accepted_epoch', 'accepted_hash',
        'accepted_source_json',
        ),
        'types': ('BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'hub_url', 'app_id', 'entity_kind', 'entity_key'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'hub_issue_states': {
        'columns': (
        'project_id', 'hub_url', 'app_id', 'issue_type', 'issue_id', 'finding_id', 'confirmed_json',
        'confirmed_run_id', 'confirmed_presence', 'observed_json', 'observed_run_id', 'base_local_signature',
        'alignment', 'pending_local_signature', 'pending_base_epoch', 'conflicts_json', 'revision',
        ),
        'types': (
        'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT',
        'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT',
        ),
        'pk': ('project_id', 'hub_url', 'app_id', 'issue_type', 'issue_id'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'hub_ops': {
        'columns': (
        'id', 'project_id', 'purpose', 'op_key', 'lock_keys', 'targets_json', 'request_json', 'hub_url',
        'app_id', 'text_hash', 'text_norm', 'state', 'result_json', 'hub_object_id', 'error', 'created_at',
        'updated_at', 'closed_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'hub_sync_applications': {
        'columns': (
        'run_id', 'entity_kind', 'entity_key', 'before_json', 'hub_json', 'presence', 'accepted_epoch',
        'accepted_hash',
        ),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT'),
        'pk': ('run_id', 'entity_kind', 'entity_key'),
        'identity': None,
        'refs': ('hub_defect_sync_runs',),
        'autoincrement': False,
    },
    'hub_sync_items': {
        'columns': (
        'run_id', 'entity_kind', 'entity_key', 'hub_json', 'source_ops_json', 'coverage_json', 'base_json',
        'base_epoch', 'local_json', 'local_signature', 'diff_json', 'choice_json', 'choice_revision',
        'observed_from', 'observed_to', 'stale_reason',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'BIGINT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('run_id', 'entity_kind', 'entity_key'),
        'identity': None,
        'refs': ('hub_defect_sync_runs',),
        'autoincrement': False,
    },
    'hub_sync_pending': {
        'columns': (
        'id', 'project_id', 'hub_url', 'app_id', 'entity_kind', 'entity_key', 'signature', 'payload_json',
        'created_run_id', 'created_at', 'state', 'resolved_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT',
        'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('hub_defect_sync_runs', 'projects'),
        'autoincrement': True,
    },
    'hub_sync_requests': {
        'columns': (
        'id', 'run_id', 'generation', 'request_key', 'op_id', 'entity_kind', 'entity_key', 'state',
        'request_json', 'base_epoch', 'base_hash', 'result_hash', 'processed_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT',
        'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('hub_defect_sync_runs', 'hub_ops'),
        'autoincrement': True,
    },
    'imports': {
        'columns': (
        'id', 'project_id', 'filename', 'format', 'total', 'stats_json', 'sheets_json', 'summary_json',
        'warnings_json', 'created_at', 'source_kind', 'sync_run_id',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'llm_executions': {
        'columns': (
        'id', 'provider_id', 'provider_version', 'kind', 'base_url', 'trust', 'purpose', 'model',
        'options_json', 'schema_mode', 'digest', 'note', 'created_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_providers',),
        'autoincrement': True,
    },
    'llm_providers': {
        'columns': (
        'id', 'name', 'kind', 'base_url', 'trust', 'auth', 'purposes_json', 'enabled', 'version',
        'default_model', 'models_json', 'capabilities_json', 'confirmed_addresses_json', 'generation_json',
        'created_at', 'updated_at',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': (),
        'autoincrement': True,
    },
    'meta': {
        'columns': ('key', 'value'),
        'types': ('TEXT', 'TEXT'),
        'pk': ('key',),
        'identity': None,
        'refs': (),
        'autoincrement': False,
    },
    'projects': {
        'columns': (
        'id', 'name', 'repos_dir', 'created_at', 'updated_at', 'model', 'archived', 'archived_at',
        'last_activity', 'provider_id', 'research_provider_id', 'external_allowed', 'external_reason',
        'external_confirmed_at', 'hub_app_id',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT',
        'BIGINT', 'TEXT', 'TEXT', 'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_providers',),
        'autoincrement': True,
    },
    'questions': {
        'columns': (
        'id', 'project_id', 'hub_id', 'question', 'answer', 'answer_json', 'model', 'case_hash',
        'verdict_id', 'state', 'error', 'stats_json', 'created_at', 'answered_at', 'execution_id',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions', 'projects'),
        'autoincrement': True,
    },
    'review_texts': {
        'columns': (
        'id', 'project_id', 'hub_id', 'decision', 'final_verdict', 'final_comment', 'final_fix',
        'decided_at', 'replaced_at',
        ),
        'types': ('BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': False,
    },
    'reviews': {
        'columns': (
        'project_id', 'hub_id', 'decision', 'final_verdict', 'final_comment', 'reviewed', 'reviewed_at',
        'copied_at', 'verdict_id', 'finding_sig', 'revision', 'updated_at', 'entered_hub', 'entered_hub_at',
        'code_hash', 'code_chars', 'entered_text_hash', 'answer_sig', 'kapo_state', 'decided_at',
        'final_fix', 'entered_parts', 'entered_origin', 'entered_defect_id', 'entered_op_id',
        'entered_defect_revision', 'entered_decision_hash', 'decision_origin', 'decision_source_json',
        'desired_hub_expired_at', 'defect_dropped',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT',
        'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('project_id', 'hub_id'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'run_items': {
        'columns': (
        'id', 'run_id', 'seq', 'hub_id', 'state', 'case_hash', 'verdict_id', 'error', 'seconds', 'eval_tps',
        'finished_at', 'stats_partial', 'sending_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'DOUBLE PRECISION',
        'DOUBLE PRECISION', 'TEXT', 'BIGINT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('runs',),
        'autoincrement': True,
    },
    'run_journal': {
        'columns': ('run_id', 'payload_json', 'active_seconds', 'active_since', 'incomplete'),
        'types': ('BIGINT', 'TEXT', 'DOUBLE PRECISION', 'TEXT', 'BIGINT'),
        'pk': ('run_id',),
        'identity': None,
        'refs': ('runs',),
        'autoincrement': False,
    },
    'run_review_events': {
        'columns': (
        'id', 'project_id', 'hub_id', 'verdict_id', 'revision', 'decision', 'final_verdict', 'reviewed',
        'observed_at',
        ),
        'types': ('BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'runs': {
        'columns': (
        'id', 'project_id', 'state', 'scope', 'model', 'prompt_version', 'fresh', 'total', 'done', 'failed',
        'cached', 'skipped', 'model_calls', 'model_seconds', 'output_tokens', 'eval_seconds', 'last_tps',
        'last_error', 'created_at', 'started_at', 'finished_at', 'updated_at', 'control', 'partial_stats',
        'origin', 'execution_id', 'parent_run_id',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT', 'BIGINT', 'BIGINT',
        'BIGINT', 'BIGINT', 'DOUBLE PRECISION', 'BIGINT', 'DOUBLE PRECISION', 'DOUBLE PRECISION', 'TEXT',
        'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT', 'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions', 'projects'),
        'autoincrement': True,
    },
    'sast_group_merges': {
        'columns': ('project_id', 'group_key2', 'old_keys_json', 'numbers_json', 'merged_at'),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'group_key2'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'saved_component_filters': {
        'columns': ('id', 'project_id', 'name', 'name_key', 'query', 'created_at', 'updated_at'),
        'types': ('BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'sca2_decisions': {
        'columns': (
        'id', 'project_id', 'input_ref', 'revision', 'action', 'rationale', 'target_version',
        'replacement_name', 'replacement_version', 'review_at', 'input_sig', 'research_sig', 'state',
        'decided_at', 'superseded_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'sca2_research': {
        'columns': (
        'id', 'project_id', 'task_id', 'input_ref', 'revision', 'answer_sig', 'input_sig', 'status',
        'coverage_checked', 'coverage_errors', 'findings_total', 'applicable', 'gaps_count',
        'evidence_count', 'payload_json', 'imported_at', 'content_sig', 'observation_json', 'observed_at',
        'validation_rules', 'answer_schema', 'execution_id',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT',
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions', 'projects', 'sca2_tasks'),
        'autoincrement': True,
    },
    'sca2_research_run_rows': {
        'columns': (
        'run_id', 'input_ref', 'position', 'state', 'revision', 'reason', 'tools_json', 'usage_json',
        'sending_at', 'updated_at',
        ),
        'types': ('BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT'),
        'pk': ('run_id', 'input_ref'),
        'identity': None,
        'refs': ('sca2_research_runs',),
        'autoincrement': False,
    },
    'sca2_research_runs': {
        'columns': (
        'id', 'project_id', 'task_id', 'consent_id', 'execution_id', 'state', 'reason', 'rows_total',
        'rows_saved', 'rows_unchanged', 'rows_failed', 'rows_unknown', 'usage_json', 'started_at',
        'updated_at', 'finished_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT',
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions', 'projects', 'sca2_tasks', 'sca_research_consents'),
        'autoincrement': True,
    },
    'sca2_task_rows': {
        'columns': (
        'task_id', 'input_ref', 'ecosystem', 'name', 'version', 'identity_kind', 'input_sig',
        'hub_fix_candidate', 'finding_count', 'codebase_count', 'position', 'vulnerability_ids',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'BIGINT',
        'TEXT',
        ),
        'pk': ('task_id', 'input_ref'),
        'identity': None,
        'refs': ('sca2_tasks',),
        'autoincrement': False,
    },
    'sca2_tasks': {
        'columns': (
        'id', 'project_id', 'import_id', 'task_id', 'contract', 'answer_contract', 'validator_version',
        'state', 'row_count', 'ecosystems_json', 'manifest_sha256', 'components_sha256', 'created_at',
        'updated_at', 'superseded_at', 'imported_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'sca_answers': {
        'columns': (
        'id', 'project_id', 'component', 'version', 'source', 'recommended_version', 'conclusion',
        'explanation', 'ids_json', 'links_json', 'created_at', 'updated_at', 'vulns_json', 'ecosystem',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('projects',),
        'autoincrement': True,
    },
    'sca_applicability': {
        'columns': (
        'project_id', 'input_ref', 'vuln_key', 'ids_json', 'decision', 'reason', 'research_revision',
        'revision', 'updated_at',
        ),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT'),
        'pk': ('project_id', 'input_ref', 'vuln_key'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'sca_defect_sets': {
        'columns': ('project_id', 'input_ref', 'set_no', 'revision', 'excluded_json', 'updated_at'),
        'types': ('BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'input_ref', 'set_no'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'sca_package_texts': {
        'columns': (
        'project_id', 'input_ref', 'set_no', 'revision', 'explanation', 'ast_json', 'target_version',
        'target_basis', 'version_checked_sig', 'text_checked_sig', 'text_sig', 'updated_at',
        'residual_checked_sig', 'recommendation_note',
        ),
        'types': (
        'BIGINT', 'TEXT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        'TEXT', 'TEXT',
        ),
        'pk': ('project_id', 'input_ref', 'set_no'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'sca_research_consents': {
        'columns': (
        'id', 'project_id', 'task_id', 'execution_id', 'components_sha256', 'cutoff_date', 'instructions',
        'instructions_sha256', 'rows_json', 'selection', 'include_unknown', 'model', 'search_mode',
        'tool_steps', 'consent_key', 'state', 'created_at', 'revoked_at',
        ),
        'types': (
        'BIGINT', 'BIGINT', 'BIGINT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT',
        'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions', 'projects', 'sca2_tasks'),
        'autoincrement': True,
    },
    'sca_set_members': {
        'columns': ('project_id', 'hub_id', 'input_ref', 'set_no', 'no_defect_reason', 'updated_at'),
        'types': ('BIGINT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT'),
        'pk': ('project_id', 'hub_id'),
        'identity': None,
        'refs': ('projects',),
        'autoincrement': False,
    },
    'schema_version': {
        'columns': ('version', 'applied_at', 'note'),
        'types': ('BIGINT', 'TEXT', 'TEXT'),
        'pk': ('version',),
        'identity': None,
        'refs': (),
        'autoincrement': False,
    },
    'settings': {
        'columns': ('key', 'value_json', 'updated_at'),
        'types': ('TEXT', 'TEXT', 'TEXT'),
        'pk': ('key',),
        'identity': None,
        'refs': (),
        'autoincrement': False,
    },
    'verdicts': {
        'columns': (
        'id', 'case_hash', 'model', 'prompt_version', 'verdict', 'confidence', 'data_json', 'raw_json',
        'stats_json', 'created_at', 'request_key', 'execution_id',
        ),
        'types': (
        'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'TEXT', 'BIGINT',
        ),
        'pk': ('id',),
        'identity': 'id',
        'refs': ('llm_executions',),
        'autoincrement': True,
    },
}

# Порядок загрузки: родители раньше детей (самоссылка runs.parent_run_id – отложенная проверка)
LOAD_ORDER: tuple[str, ...] = (
    'ast_map', 'llm_providers', 'projects', 'llm_executions', 'verdicts', 'cases', 'codebase_map', 'defects',
    'findings', 'hub_ops', 'hub_attempts', 'hub_defects', 'hub_defect_history', 'hub_defect_reference_loads',
    'hub_defect_sync_runs', 'hub_entity_versions', 'hub_issue_states', 'hub_sync_applications',
    'hub_sync_items', 'hub_sync_pending', 'hub_sync_requests', 'imports', 'meta', 'questions',
    'review_texts', 'reviews', 'runs', 'run_items', 'run_journal', 'run_review_events', 'sast_group_merges',
    'saved_component_filters', 'sca2_decisions', 'sca2_tasks', 'sca2_research', 'sca_research_consents',
    'sca2_research_runs', 'sca2_research_run_rows', 'sca2_task_rows', 'sca_answers', 'sca_applicability',
    'sca_defect_sets', 'sca_package_texts', 'sca_set_members', 'schema_version', 'settings',
)
