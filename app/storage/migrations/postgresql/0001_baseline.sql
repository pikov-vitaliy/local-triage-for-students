-- Базовая схема PostgreSQL: логическая схема 33 приложения «Локальный триаж» (ADR-0128, редакция 3).
-- Все целые – BIGINT, текст, JSON и даты – TEXT как есть; внешние ключи можно отложить (перенос данных),
-- при обычной работе они проверяются сразу, как в прежней базе.

-- Адрес Hub -> «https://host» без хвоста: как app.hub_ops.hub_base (схема – в нижнем регистре, как у urlsplit)
CREATE FUNCTION hub_base(url TEXT) RETURNS TEXT LANGUAGE SQL IMMUTABLE AS $body$
    SELECT COALESCE(lower(m[1]) || '://' || m[2], '')
    FROM (SELECT regexp_match(btrim(COALESCE(url, ''), E' \t\r\n\f\013'),
                              '^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)') AS m) AS parsed
$body$;

-- Поиск без учёта регистра по любому алфавиту: как normalize("NFC", ...).casefold() в Python. Своей свёртки регистра в PostgreSQL 17
-- нет: lower, затем замена букв, у которых она расходится с lower. Подготовлено scripts/gen_unicode_search.py
CREATE FUNCTION unicode_search(value TEXT) RETURNS TEXT LANGUAGE SQL STABLE AS $body$
    SELECT replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(translate(lower(replace(normalize(COALESCE(value, ''), NFC), E'\u0130', E'\u0069\u0307')),
        E'\u00B5\u017F\u0345\u03C2\u03D0\u03D1\u03D5\u03D6\u03F0\u03F1\u03F5\uAB70\uAB71\uAB72\uAB73\uAB74\uAB75\uAB76\uAB77\uAB78\uAB79\uAB7A\uAB7B\uAB7C\uAB7D\uAB7E\uAB7F\uAB80\uAB81\uAB82\uAB83\uAB84\uAB85\uAB86\uAB87\uAB88\uAB89\uAB8A\uAB8B\uAB8C\uAB8D\uAB8E\uAB8F\uAB90\uAB91\uAB92\uAB93\uAB94\uAB95\uAB96\uAB97\uAB98\uAB99\uAB9A\uAB9B\uAB9C\uAB9D\uAB9E\uAB9F\uABA0\uABA1\uABA2\uABA3\uABA4\uABA5\uABA6\uABA7\uABA8\uABA9\uABAA\uABAB\uABAC\uABAD\uABAE\uABAF\uABB0\uABB1\uABB2\uABB3\uABB4\uABB5\uABB6\uABB7\uABB8\uABB9\uABBA\uABBB\uABBC\uABBD\uABBE\uABBF\u13F8\u13F9\u13FA\u13FB\u13FC\u13FD\u1C80\u1C81\u1C82\u1C83\u1C84\u1C85\u1C86\u1C87\u1C88\u1E9B\u24B6\u24B7\u24B8\u24B9\u24BA\u24BB\u24BC\u24BD\u24BE\u24BF\u24C0\u24C1\u24C2\u24C3\u24C4\u24C5\u24C6\u24C7\u24C8\u24C9\u24CA\u24CB\u24CC\u24CD\u24CE\u24CF\u2C2F\uA7C0\uA7C7\uA7C9\uA7D0\uA7D6\uA7D8\uA7F5\U00010570\U00010571\U00010572\U00010573\U00010574\U00010575\U00010576\U00010577\U00010578\U00010579\U0001057A\U0001057C\U0001057D\U0001057E\U0001057F\U00010580\U00010581\U00010582\U00010583\U00010584\U00010585\U00010586\U00010587\U00010588\U00010589\U0001058A\U0001058C\U0001058D\U0001058E\U0001058F\U00010590\U00010591\U00010592\U00010594\U00010595',
        E'\u03BC\u0073\u03B9\u03C3\u03B2\u03B8\u03C6\u03C0\u03BA\u03C1\u03B5\u13A0\u13A1\u13A2\u13A3\u13A4\u13A5\u13A6\u13A7\u13A8\u13A9\u13AA\u13AB\u13AC\u13AD\u13AE\u13AF\u13B0\u13B1\u13B2\u13B3\u13B4\u13B5\u13B6\u13B7\u13B8\u13B9\u13BA\u13BB\u13BC\u13BD\u13BE\u13BF\u13C0\u13C1\u13C2\u13C3\u13C4\u13C5\u13C6\u13C7\u13C8\u13C9\u13CA\u13CB\u13CC\u13CD\u13CE\u13CF\u13D0\u13D1\u13D2\u13D3\u13D4\u13D5\u13D6\u13D7\u13D8\u13D9\u13DA\u13DB\u13DC\u13DD\u13DE\u13DF\u13E0\u13E1\u13E2\u13E3\u13E4\u13E5\u13E6\u13E7\u13E8\u13E9\u13EA\u13EB\u13EC\u13ED\u13EE\u13EF\u13F0\u13F1\u13F2\u13F3\u13F4\u13F5\u0432\u0434\u043E\u0441\u0442\u0442\u044A\u0463\uA64B\u1E61\u24D0\u24D1\u24D2\u24D3\u24D4\u24D5\u24D6\u24D7\u24D8\u24D9\u24DA\u24DB\u24DC\u24DD\u24DE\u24DF\u24E0\u24E1\u24E2\u24E3\u24E4\u24E5\u24E6\u24E7\u24E8\u24E9\u2C5F\uA7C1\uA7C8\uA7CA\uA7D1\uA7D7\uA7D9\uA7F6\U00010597\U00010598\U00010599\U0001059A\U0001059B\U0001059C\U0001059D\U0001059E\U0001059F\U000105A0\U000105A1\U000105A3\U000105A4\U000105A5\U000105A6\U000105A7\U000105A8\U000105A9\U000105AA\U000105AB\U000105AC\U000105AD\U000105AE\U000105AF\U000105B0\U000105B1\U000105B3\U000105B4\U000105B5\U000105B6\U000105B7\U000105B8\U000105B9\U000105BB\U000105BC'), E'\u00DF', E'\u0073\u0073'), E'\u0149', E'\u02BC\u006E'), E'\u01F0', E'\u006A\u030C'), E'\u0390', E'\u03B9\u0308\u0301'), E'\u03B0', E'\u03C5\u0308\u0301'), E'\u0587', E'\u0565\u0582'), E'\u1E96', E'\u0068\u0331'), E'\u1E97', E'\u0074\u0308'), E'\u1E98', E'\u0077\u030A'), E'\u1E99', E'\u0079\u030A'), E'\u1E9A', E'\u0061\u02BE'), E'\u1F50', E'\u03C5\u0313'), E'\u1F52', E'\u03C5\u0313\u0300'), E'\u1F54', E'\u03C5\u0313\u0301'), E'\u1F56', E'\u03C5\u0313\u0342'), E'\u1F80', E'\u1F00\u03B9'), E'\u1F81', E'\u1F01\u03B9'), E'\u1F82', E'\u1F02\u03B9'), E'\u1F83', E'\u1F03\u03B9'), E'\u1F84', E'\u1F04\u03B9'), E'\u1F85', E'\u1F05\u03B9'), E'\u1F86', E'\u1F06\u03B9'), E'\u1F87', E'\u1F07\u03B9'), E'\u1F90', E'\u1F20\u03B9'), E'\u1F91', E'\u1F21\u03B9'), E'\u1F92', E'\u1F22\u03B9'), E'\u1F93', E'\u1F23\u03B9'), E'\u1F94', E'\u1F24\u03B9'), E'\u1F95', E'\u1F25\u03B9'), E'\u1F96', E'\u1F26\u03B9'), E'\u1F97', E'\u1F27\u03B9'), E'\u1FA0', E'\u1F60\u03B9'), E'\u1FA1', E'\u1F61\u03B9'), E'\u1FA2', E'\u1F62\u03B9'), E'\u1FA3', E'\u1F63\u03B9'), E'\u1FA4', E'\u1F64\u03B9'), E'\u1FA5', E'\u1F65\u03B9'), E'\u1FA6', E'\u1F66\u03B9'), E'\u1FA7', E'\u1F67\u03B9'), E'\u1FB2', E'\u1F70\u03B9'), E'\u1FB3', E'\u03B1\u03B9'), E'\u1FB4', E'\u03AC\u03B9'), E'\u1FB6', E'\u03B1\u0342'), E'\u1FB7', E'\u03B1\u0342\u03B9'), E'\u1FC2', E'\u1F74\u03B9'), E'\u1FC3', E'\u03B7\u03B9'), E'\u1FC4', E'\u03AE\u03B9'), E'\u1FC6', E'\u03B7\u0342'), E'\u1FC7', E'\u03B7\u0342\u03B9'), E'\u1FD2', E'\u03B9\u0308\u0300'), E'\u1FD6', E'\u03B9\u0342'), E'\u1FD7', E'\u03B9\u0308\u0342'), E'\u1FE2', E'\u03C5\u0308\u0300'), E'\u1FE4', E'\u03C1\u0313'), E'\u1FE6', E'\u03C5\u0342'), E'\u1FE7', E'\u03C5\u0308\u0342'), E'\u1FF2', E'\u1F7C\u03B9'), E'\u1FF3', E'\u03C9\u03B9'), E'\u1FF4', E'\u03CE\u03B9'), E'\u1FF6', E'\u03C9\u0342'), E'\u1FF7', E'\u03C9\u0342\u03B9'), E'\uFB00', E'\u0066\u0066'), E'\uFB01', E'\u0066\u0069'), E'\uFB02', E'\u0066\u006C'), E'\uFB03', E'\u0066\u0066\u0069'), E'\uFB04', E'\u0066\u0066\u006C'), E'\uFB05', E'\u0073\u0074'), E'\uFB06', E'\u0073\u0074'), E'\uFB13', E'\u0574\u0576'), E'\uFB14', E'\u0574\u0565'), E'\uFB15', E'\u0574\u056B'), E'\uFB16', E'\u057E\u0576'), E'\uFB17', E'\u0574\u056D')
$body$;

-- Длина массива JSON, как у прежней json_array_length: не массив – 0, нет значения – NULL
CREATE FUNCTION json_len(value JSON) RETURNS BIGINT LANGUAGE SQL IMMUTABLE AS $body$
    SELECT CASE WHEN value IS NULL THEN NULL WHEN json_typeof(value) = 'array' THEN json_array_length(value) ELSE 0 END
$body$;

CREATE TABLE storage_migrations (
    number BIGINT NOT NULL PRIMARY KEY,
    schema_version BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE ast_map (
    ast_id TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (ast_id, vuln_id)
);

CREATE TABLE cases (
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    case_hash TEXT NOT NULL,
    context_json TEXT NOT NULL,
    verdict_id BIGINT,
    updated_at TEXT NOT NULL,
    code_cmp TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, hub_id)
);

CREATE TABLE codebase_map (
    project_id BIGINT NOT NULL,
    codebase TEXT NOT NULL,
    folder TEXT NOT NULL DEFAULT '',
    manual BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, codebase)
);

CREATE TABLE defects (
    project_id BIGINT NOT NULL,
    defect_key TEXT NOT NULL,
    number BIGINT NOT NULL,
    updated_at TEXT NOT NULL,
    assigned_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, defect_key)
);

CREATE TABLE findings (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    import_id BIGINT NOT NULL,
    pos BIGINT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    cvss DOUBLE PRECISION,
    urgent BIGINT NOT NULL DEFAULT 0,
    codebase TEXT NOT NULL DEFAULT '',
    group_key TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL,
    missing BIGINT NOT NULL DEFAULT 0,
    missing_since TEXT,
    group_key2 TEXT NOT NULL DEFAULT '',
    g2_cat TEXT NOT NULL DEFAULT '',
    g2_file TEXT NOT NULL DEFAULT '',
    g2_line BIGINT,
    file_import_id BIGINT,
    file_checked_import_id BIGINT,
    file_presence TEXT NOT NULL DEFAULT 'unknown',
    file_missing_since TEXT,
    file_data_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (id),
    UNIQUE (project_id, hub_id)
);

CREATE TABLE hub_attempts (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    op_id BIGINT NOT NULL,
    worker_id TEXT NOT NULL,
    lease_token TEXT NOT NULL,
    taken_at TEXT NOT NULL,
    taken_until TEXT NOT NULL,
    result_json TEXT,
    error TEXT NOT NULL DEFAULT '',
    received_at TEXT,
    late BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
);

CREATE TABLE hub_defect_history (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    defect_id BIGINT NOT NULL,
    row_id BIGINT,
    revision BIGINT NOT NULL,
    event TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    command_text TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    op_id BIGINT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE hub_defect_reference_loads (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    load_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    closed_at TEXT,
    PRIMARY KEY (id)
);

CREATE TABLE hub_defect_sync_runs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    run_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    closed_at TEXT,
    revision BIGINT NOT NULL DEFAULT 0,
    generation BIGINT NOT NULL DEFAULT 1,
    snapshot_hash TEXT NOT NULL DEFAULT '',
    applied_at TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (id)
);

CREATE TABLE hub_defects (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    number BIGINT,
    summary TEXT NOT NULL DEFAULT '',
    anchor_hub_id TEXT NOT NULL DEFAULT '',
    targets_json TEXT NOT NULL DEFAULT '[]',
    left_out_json TEXT NOT NULL DEFAULT '[]',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    number_keys_json TEXT NOT NULL DEFAULT '[]',
    command_text TEXT NOT NULL DEFAULT '',
    source_fingerprint TEXT NOT NULL DEFAULT '',
    body_html TEXT NOT NULL DEFAULT '',
    blank_json TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    hub_url TEXT NOT NULL DEFAULT '',
    app_id BIGINT,
    hub_defect_id TEXT NOT NULL DEFAULT '',
    hub_link TEXT NOT NULL DEFAULT '',
    blank_op_id BIGINT,
    create_op_id BIGINT,
    read_op_id BIGINT,
    link_op_id BIGINT,
    verify_json TEXT NOT NULL DEFAULT '',
    verify_op_id BIGINT,
    confirm_op_id BIGINT,
    effects_done BIGINT NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'blank',
    error TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    origin TEXT NOT NULL DEFAULT 'app',
    import_json TEXT NOT NULL DEFAULT '',
    sync_op_id BIGINT,
    sync_json TEXT NOT NULL DEFAULT '',
    update_op_id BIGINT,
    update_json TEXT NOT NULL DEFAULT '',
    text_generation BIGINT NOT NULL DEFAULT 0,
    draft_owner_id BIGINT,
    draft_summary TEXT NOT NULL DEFAULT '',
    draft_command_text TEXT NOT NULL DEFAULT '',
    draft_fields_json TEXT NOT NULL DEFAULT '{}',
    confirmed_object_json TEXT NOT NULL DEFAULT '',
    conflicts_json TEXT NOT NULL DEFAULT '[]',
    draft_revision BIGINT NOT NULL DEFAULT 0,
    sca_set_key TEXT NOT NULL DEFAULT '',
    draft_fields_basis_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (id)
);

CREATE TABLE hub_entity_versions (
    project_id BIGINT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    accepted_epoch BIGINT NOT NULL DEFAULT 0,
    accepted_hash TEXT NOT NULL DEFAULT '',
    accepted_source_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (project_id, hub_url, app_id, entity_kind, entity_key)
);

CREATE TABLE hub_issue_states (
    project_id BIGINT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    issue_type TEXT NOT NULL,
    issue_id TEXT NOT NULL,
    finding_id BIGINT,
    confirmed_json TEXT NOT NULL DEFAULT '{}',
    confirmed_run_id BIGINT,
    confirmed_presence TEXT NOT NULL DEFAULT 'unknown',
    observed_json TEXT NOT NULL DEFAULT '{}',
    observed_run_id BIGINT,
    base_local_signature TEXT,
    alignment TEXT NOT NULL DEFAULT 'no_local_decision',
    pending_local_signature TEXT,
    pending_base_epoch BIGINT,
    conflicts_json TEXT NOT NULL DEFAULT '[]',
    revision BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, hub_url, app_id, issue_type, issue_id)
);

CREATE TABLE hub_ops (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT,
    purpose TEXT NOT NULL,
    op_key TEXT NOT NULL,
    lock_keys TEXT NOT NULL DEFAULT '[]',
    targets_json TEXT NOT NULL DEFAULT '[]',
    request_json TEXT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT,
    text_hash TEXT NOT NULL DEFAULT '',
    text_norm TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'queued',
    result_json TEXT,
    hub_object_id TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (op_key)
);

CREATE TABLE hub_sync_applications (
    run_id BIGINT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    before_json TEXT NOT NULL,
    hub_json TEXT NOT NULL,
    presence TEXT NOT NULL,
    accepted_epoch BIGINT NOT NULL,
    accepted_hash TEXT NOT NULL,
    PRIMARY KEY (run_id, entity_kind, entity_key)
);

CREATE TABLE hub_sync_items (
    run_id BIGINT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    hub_json TEXT NOT NULL DEFAULT '{}',
    source_ops_json TEXT NOT NULL DEFAULT '{}',
    coverage_json TEXT NOT NULL DEFAULT '{}',
    base_json TEXT NOT NULL DEFAULT '{}',
    base_epoch BIGINT NOT NULL DEFAULT 0,
    local_json TEXT NOT NULL DEFAULT '{}',
    local_signature TEXT NOT NULL DEFAULT '',
    diff_json TEXT NOT NULL DEFAULT '{}',
    choice_json TEXT NOT NULL DEFAULT '{}',
    choice_revision BIGINT NOT NULL DEFAULT 0,
    observed_from TEXT,
    observed_to TEXT,
    stale_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, entity_kind, entity_key)
);

CREATE TABLE hub_sync_pending (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_url TEXT NOT NULL,
    app_id BIGINT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_run_id BIGINT NOT NULL,
    created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    resolved_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (project_id, hub_url, app_id, entity_kind, entity_key, signature)
);

CREATE TABLE hub_sync_requests (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    run_id BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    request_key TEXT NOT NULL,
    op_id BIGINT,
    entity_kind TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'planned',
    request_json TEXT NOT NULL,
    base_epoch BIGINT,
    base_hash TEXT,
    result_hash TEXT,
    processed_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (run_id, generation, request_key),
    UNIQUE (op_id)
);

CREATE TABLE imports (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    total BIGINT NOT NULL DEFAULT 0,
    stats_json TEXT NOT NULL DEFAULT '{}',
    sheets_json TEXT NOT NULL DEFAULT '[]',
    summary_json TEXT NOT NULL DEFAULT '{}',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    source_kind TEXT NOT NULL DEFAULT 'file',
    sync_run_id BIGINT,
    PRIMARY KEY (id)
);

CREATE TABLE llm_executions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    provider_id BIGINT,
    provider_version BIGINT,
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    options_json TEXT NOT NULL DEFAULT '{}',
    schema_mode TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE llm_providers (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'ollama',
    base_url TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT 'local',
    auth TEXT NOT NULL DEFAULT 'none',
    purposes_json TEXT NOT NULL DEFAULT '["code", "research"]',
    enabled BIGINT NOT NULL DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    default_model TEXT NOT NULL DEFAULT '',
    models_json TEXT NOT NULL DEFAULT '[]',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    confirmed_addresses_json TEXT NOT NULL DEFAULT '[]',
    generation_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE meta (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (key)
);

CREATE TABLE projects (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    name TEXT NOT NULL,
    repos_dir TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    archived BIGINT NOT NULL DEFAULT 0,
    archived_at TEXT,
    last_activity TEXT NOT NULL DEFAULT '',
    provider_id BIGINT,
    research_provider_id BIGINT,
    external_allowed BIGINT NOT NULL DEFAULT 0,
    external_reason TEXT NOT NULL DEFAULT '',
    external_confirmed_at TEXT,
    hub_app_id BIGINT,
    PRIMARY KEY (id)
);

CREATE TABLE questions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    answer_json TEXT NOT NULL DEFAULT '{}',
    model TEXT NOT NULL,
    case_hash TEXT NOT NULL DEFAULT '',
    verdict_id BIGINT,
    state TEXT NOT NULL DEFAULT 'pending',
    error TEXT NOT NULL DEFAULT '',
    stats_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    answered_at TEXT,
    execution_id BIGINT,
    PRIMARY KEY (id)
);

CREATE TABLE review_texts (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT '',
    final_verdict TEXT NOT NULL DEFAULT '',
    final_comment TEXT NOT NULL DEFAULT '',
    final_fix TEXT NOT NULL DEFAULT '',
    decided_at TEXT,
    replaced_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE reviews (
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT '',
    final_verdict TEXT NOT NULL DEFAULT '',
    final_comment TEXT NOT NULL DEFAULT '',
    reviewed BIGINT NOT NULL DEFAULT 0,
    reviewed_at TEXT,
    copied_at TEXT,
    verdict_id BIGINT,
    finding_sig TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    entered_hub BIGINT NOT NULL DEFAULT 0,
    entered_hub_at TEXT,
    code_hash TEXT NOT NULL DEFAULT '',
    code_chars BIGINT NOT NULL DEFAULT 0,
    entered_text_hash TEXT NOT NULL DEFAULT '',
    answer_sig TEXT NOT NULL DEFAULT '',
    kapo_state TEXT NOT NULL DEFAULT '',
    decided_at TEXT,
    final_fix TEXT NOT NULL DEFAULT '',
    entered_parts TEXT NOT NULL DEFAULT '',
    entered_origin TEXT NOT NULL DEFAULT '',
    entered_defect_id BIGINT,
    entered_op_id BIGINT,
    entered_defect_revision BIGINT NOT NULL DEFAULT 0,
    entered_decision_hash TEXT NOT NULL DEFAULT '',
    decision_origin TEXT NOT NULL DEFAULT '',
    decision_source_json TEXT NOT NULL DEFAULT '{}',
    desired_hub_expired_at TEXT,
    defect_dropped TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, hub_id)
);

CREATE TABLE run_items (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    run_id BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    case_hash TEXT NOT NULL DEFAULT '',
    verdict_id BIGINT,
    error TEXT NOT NULL DEFAULT '',
    seconds DOUBLE PRECISION,
    eval_tps DOUBLE PRECISION,
    finished_at TEXT,
    stats_partial BIGINT NOT NULL DEFAULT 0,
    sending_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (run_id, seq)
);

CREATE TABLE run_journal (
    run_id BIGINT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    active_since TEXT,
    incomplete BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id)
);

CREATE TABLE run_review_events (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    verdict_id BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    decision TEXT NOT NULL,
    final_verdict TEXT NOT NULL,
    reviewed BIGINT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (project_id, hub_id, revision)
);

CREATE TABLE runs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    scope TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    fresh BIGINT NOT NULL DEFAULT 0,
    total BIGINT NOT NULL DEFAULT 0,
    done BIGINT NOT NULL DEFAULT 0,
    failed BIGINT NOT NULL DEFAULT 0,
    cached BIGINT NOT NULL DEFAULT 0,
    skipped BIGINT NOT NULL DEFAULT 0,
    model_calls BIGINT NOT NULL DEFAULT 0,
    model_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    eval_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_tps DOUBLE PRECISION,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    control TEXT NOT NULL DEFAULT '',
    partial_stats BIGINT NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT '',
    execution_id BIGINT,
    parent_run_id BIGINT,
    PRIMARY KEY (id)
);

CREATE TABLE sast_group_merges (
    project_id BIGINT NOT NULL,
    group_key2 TEXT NOT NULL,
    old_keys_json TEXT NOT NULL DEFAULT '[]',
    numbers_json TEXT NOT NULL DEFAULT '[]',
    merged_at TEXT NOT NULL,
    PRIMARY KEY (project_id, group_key2)
);

CREATE TABLE saved_component_filters (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    query TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (project_id, name_key)
);

CREATE TABLE sca2_decisions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    revision BIGINT NOT NULL,
    action TEXT NOT NULL,
    rationale TEXT NOT NULL,
    target_version TEXT NOT NULL DEFAULT '',
    replacement_name TEXT NOT NULL DEFAULT '',
    replacement_version TEXT NOT NULL DEFAULT '',
    review_at TEXT NOT NULL DEFAULT '',
    input_sig TEXT NOT NULL DEFAULT '',
    research_sig TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'current',
    decided_at TEXT NOT NULL,
    superseded_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (project_id, input_ref, revision)
);

CREATE TABLE sca2_research (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    task_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    revision BIGINT NOT NULL,
    answer_sig TEXT NOT NULL,
    input_sig TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    coverage_checked BIGINT NOT NULL DEFAULT 0,
    coverage_errors BIGINT NOT NULL DEFAULT 0,
    findings_total BIGINT NOT NULL DEFAULT 0,
    applicable BIGINT NOT NULL DEFAULT 0,
    gaps_count BIGINT NOT NULL DEFAULT 0,
    evidence_count BIGINT NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}',
    imported_at TEXT NOT NULL,
    content_sig TEXT NOT NULL DEFAULT '',
    observation_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL DEFAULT '',
    validation_rules TEXT NOT NULL DEFAULT 'sca-contract/2.0.1',
    answer_schema TEXT NOT NULL DEFAULT '',
    execution_id BIGINT,
    PRIMARY KEY (id),
    UNIQUE (project_id, input_ref, revision)
);

CREATE TABLE sca2_research_run_rows (
    run_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    position BIGINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'queued',
    revision BIGINT,
    reason TEXT NOT NULL DEFAULT '',
    tools_json TEXT NOT NULL DEFAULT '[]',
    usage_json TEXT NOT NULL DEFAULT '{}',
    sending_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, input_ref)
);

CREATE TABLE sca2_research_runs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    task_id BIGINT NOT NULL,
    consent_id BIGINT NOT NULL,
    execution_id BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'running',
    reason TEXT NOT NULL DEFAULT '',
    rows_total BIGINT NOT NULL DEFAULT 0,
    rows_saved BIGINT NOT NULL DEFAULT 0,
    rows_unchanged BIGINT NOT NULL DEFAULT 0,
    rows_failed BIGINT NOT NULL DEFAULT 0,
    rows_unknown BIGINT NOT NULL DEFAULT 0,
    usage_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (consent_id)
);

CREATE TABLE sca2_task_rows (
    task_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    identity_kind TEXT NOT NULL DEFAULT 'short_name',
    input_sig TEXT NOT NULL DEFAULT '',
    hub_fix_candidate TEXT NOT NULL DEFAULT '',
    finding_count BIGINT NOT NULL DEFAULT 0,
    codebase_count BIGINT NOT NULL DEFAULT 0,
    position BIGINT NOT NULL DEFAULT 0,
    vulnerability_ids TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (task_id, input_ref)
);

CREATE TABLE sca2_tasks (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    import_id BIGINT NOT NULL,
    task_id TEXT NOT NULL,
    contract TEXT NOT NULL,
    answer_contract TEXT NOT NULL,
    validator_version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'current',
    row_count BIGINT NOT NULL DEFAULT 0,
    ecosystems_json TEXT NOT NULL DEFAULT '[]',
    manifest_sha256 TEXT NOT NULL,
    components_sha256 TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    superseded_at TEXT,
    imported_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (project_id, task_id)
);

CREATE TABLE sca_answers (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    component TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    recommended_version TEXT NOT NULL DEFAULT '',
    conclusion TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    ids_json TEXT NOT NULL DEFAULT '{}',
    links_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    vulns_json TEXT NOT NULL DEFAULT '[]',
    ecosystem TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE (project_id, ecosystem, component, version, source)
);

CREATE TABLE sca_applicability (
    project_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    vuln_key TEXT NOT NULL,
    ids_json TEXT NOT NULL DEFAULT '[]',
    decision TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    research_revision BIGINT NOT NULL DEFAULT 0,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, input_ref, vuln_key)
);

CREATE TABLE sca_defect_sets (
    project_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    set_no BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    excluded_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, input_ref, set_no)
);

CREATE TABLE sca_package_texts (
    project_id BIGINT NOT NULL,
    input_ref TEXT NOT NULL,
    set_no BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    explanation TEXT NOT NULL DEFAULT '',
    ast_json TEXT NOT NULL DEFAULT '{}',
    target_version TEXT NOT NULL DEFAULT '',
    target_basis TEXT NOT NULL DEFAULT '',
    version_checked_sig TEXT NOT NULL DEFAULT '',
    text_checked_sig TEXT NOT NULL DEFAULT '',
    text_sig TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    residual_checked_sig TEXT NOT NULL DEFAULT '',
    recommendation_note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, input_ref, set_no)
);

CREATE TABLE sca_research_consents (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    project_id BIGINT NOT NULL,
    task_id BIGINT NOT NULL,
    execution_id BIGINT NOT NULL,
    components_sha256 TEXT NOT NULL,
    cutoff_date TEXT NOT NULL,
    instructions TEXT NOT NULL,
    instructions_sha256 TEXT NOT NULL,
    rows_json TEXT NOT NULL DEFAULT '[]',
    selection TEXT NOT NULL DEFAULT 'all',
    include_unknown BIGINT NOT NULL DEFAULT 0,
    model TEXT NOT NULL,
    search_mode TEXT NOT NULL DEFAULT 'none',
    tool_steps BIGINT NOT NULL DEFAULT 0,
    consent_key TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (id),
    UNIQUE (id, project_id, task_id, execution_id)
);

CREATE TABLE sca_set_members (
    project_id BIGINT NOT NULL,
    hub_id TEXT NOT NULL,
    input_ref TEXT NOT NULL,
    set_no BIGINT,
    no_defect_reason TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, hub_id)
);

CREATE TABLE schema_version (
    version BIGINT NOT NULL,
    applied_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version)
);

CREATE TABLE settings (
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (key)
);

CREATE TABLE verdicts (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    case_hash TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence BIGINT NOT NULL DEFAULT 0,
    data_json TEXT NOT NULL,
    raw_json TEXT NOT NULL DEFAULT '{}',
    stats_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    request_key TEXT NOT NULL DEFAULT '',
    execution_id BIGINT,
    PRIMARY KEY (id)
);

ALTER TABLE cases ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE cases ADD FOREIGN KEY (verdict_id) REFERENCES verdicts (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE codebase_map ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE defects ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE findings ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_attempts ADD FOREIGN KEY (op_id) REFERENCES hub_ops (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_defect_history ADD FOREIGN KEY (defect_id) REFERENCES hub_defects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_defect_history ADD FOREIGN KEY (row_id) REFERENCES hub_defects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_defect_reference_loads ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_defect_sync_runs ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_defects ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_entity_versions ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_issue_states ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_ops ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_applications ADD FOREIGN KEY (run_id) REFERENCES hub_defect_sync_runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_items ADD FOREIGN KEY (run_id) REFERENCES hub_defect_sync_runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_pending ADD FOREIGN KEY (created_run_id) REFERENCES hub_defect_sync_runs (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_pending ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_requests ADD FOREIGN KEY (run_id) REFERENCES hub_defect_sync_runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE hub_sync_requests ADD FOREIGN KEY (op_id) REFERENCES hub_ops (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE imports ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE llm_executions ADD FOREIGN KEY (provider_id) REFERENCES llm_providers (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE projects ADD FOREIGN KEY (provider_id) REFERENCES llm_providers (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE projects ADD FOREIGN KEY (research_provider_id) REFERENCES llm_providers (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE questions ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE questions ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE review_texts ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE reviews ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE run_items ADD FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE run_journal ADD FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE run_review_events ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE runs ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE runs ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE runs ADD FOREIGN KEY (parent_run_id) REFERENCES runs (id) ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sast_group_merges ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE saved_component_filters ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_decisions ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research ADD FOREIGN KEY (task_id) REFERENCES sca2_tasks (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research_run_rows ADD FOREIGN KEY (run_id) REFERENCES sca2_research_runs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research_runs ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research_runs ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research_runs ADD FOREIGN KEY (task_id) REFERENCES sca2_tasks (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_research_runs ADD FOREIGN KEY (consent_id, project_id, task_id, execution_id) REFERENCES sca_research_consents (id, project_id, task_id, execution_id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_task_rows ADD FOREIGN KEY (task_id) REFERENCES sca2_tasks (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca2_tasks ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_answers ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_applicability ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_defect_sets ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_package_texts ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_research_consents ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_research_consents ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_research_consents ADD FOREIGN KEY (task_id) REFERENCES sca2_tasks (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sca_set_members ADD FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE verdicts ADD FOREIGN KEY (execution_id) REFERENCES llm_executions (id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE INDEX cases_by_cmp_hub ON cases(project_id, code_cmp, hub_id);
-- Ключи групп и категория строятся из ячеек выгрузки (до 32 767 знаков, например Location у DAST), а обычный индекс строку
-- длиннее примерно 2,7 КБ не принимает. Сравнение по ним – только на равенство: хеш-индекс и индекс по md5 предела не имеют.
CREATE INDEX findings_by_group2 ON findings USING hash (group_key2) WHERE group_key2 <> '';
CREATE INDEX findings_by_near2 ON findings(project_id, md5(g2_cat), md5(g2_file), g2_line);
CREATE INDEX findings_by_pos ON findings(project_id, pos);
CREATE INDEX hub_attempts_by_op ON hub_attempts(op_id, id);
CREATE INDEX hub_defects_by_project ON hub_defects(project_id, state, id);
CREATE INDEX hub_ops_by_project ON hub_ops(project_id, purpose, id);
CREATE INDEX hub_ops_by_state ON hub_ops(state, hub_url, id);
CREATE UNIQUE INDEX hub_sync_open_project ON hub_defect_sync_runs(project_id) WHERE closed_at IS NULL;
CREATE INDEX questions_by_finding ON questions(project_id, hub_id, id);
CREATE INDEX questions_by_state ON questions(state, id);
CREATE INDEX review_texts_by_finding ON review_texts(project_id, hub_id, id);
CREATE INDEX run_items_by_state ON run_items(run_id, state, seq);
CREATE INDEX run_reviews_by_answer ON run_review_events(project_id,hub_id,verdict_id,id);
CREATE INDEX runs_by_state ON runs(state, id);
CREATE INDEX sca2_decisions_by_ref ON sca2_decisions(project_id, input_ref, revision);
CREATE INDEX sca2_research_by_ref ON sca2_research(project_id, input_ref, revision);
CREATE INDEX sca2_research_run_rows_by_state ON sca2_research_run_rows(run_id, state, position);
CREATE INDEX sca2_research_runs_by_task ON sca2_research_runs(project_id, task_id, id);
CREATE UNIQUE INDEX sca2_research_runs_one_running ON sca2_research_runs(project_id) WHERE state = 'running';
CREATE INDEX sca2_rows_by_task ON sca2_task_rows(task_id, position);
CREATE INDEX sca_research_consents_by_key ON sca_research_consents(project_id, consent_key);
CREATE INDEX sca_research_consents_by_task ON sca_research_consents(project_id, task_id, id);
CREATE INDEX sca_set_members_by_ref ON sca_set_members(project_id, input_ref, set_no);
CREATE INDEX verdicts_by_case ON verdicts(case_hash, model, prompt_version, id);
CREATE INDEX verdicts_by_request ON verdicts(request_key, id);
