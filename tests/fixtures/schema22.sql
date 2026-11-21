-- Раскладка схемы 22, снятая кодом 0.9.12 с пустой базы: sqlite_master, meta, schema_version.
-- Синтетическая, без данных. Не править руками: снимается заново с кода выпуска, если понадобится другая схема.

CREATE TABLE schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE run_journal (
    run_id INTEGER PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL DEFAULT '{}',
    active_seconds REAL NOT NULL DEFAULT 0,
    active_since TEXT,
    incomplete INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE run_review_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id TEXT NOT NULL,
    verdict_id INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    decision TEXT NOT NULL,
    final_verdict TEXT NOT NULL,
    reviewed INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(project_id,hub_id,revision)
);
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE llm_providers (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT NOT NULL,
    kind                     TEXT NOT NULL DEFAULT 'ollama',
    base_url                 TEXT NOT NULL DEFAULT '',
    trust                    TEXT NOT NULL DEFAULT 'local',
    auth                     TEXT NOT NULL DEFAULT 'none',
    purposes_json            TEXT NOT NULL DEFAULT '["code", "research"]',
    enabled                  INTEGER NOT NULL DEFAULT 1,
    version                  INTEGER NOT NULL DEFAULT 1,
    default_model            TEXT NOT NULL DEFAULT '',
    models_json              TEXT NOT NULL DEFAULT '[]',
    capabilities_json        TEXT NOT NULL DEFAULT '{}',
    confirmed_addresses_json TEXT NOT NULL DEFAULT '[]',
    generation_json          TEXT NOT NULL DEFAULT '{}',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);
CREATE TABLE llm_executions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id      INTEGER REFERENCES llm_providers(id),
    provider_version INTEGER,
    kind             TEXT NOT NULL,
    base_url         TEXT NOT NULL DEFAULT '',
    trust            TEXT NOT NULL DEFAULT '',
    purpose          TEXT NOT NULL,
    model            TEXT NOT NULL DEFAULT '',
    options_json     TEXT NOT NULL DEFAULT '{}',
    schema_mode      TEXT NOT NULL DEFAULT '',
    digest           TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);
CREATE TABLE projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    repos_dir     TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    model         TEXT NOT NULL DEFAULT '',
    archived      INTEGER NOT NULL DEFAULT 0,
    archived_at   TEXT,
    last_activity TEXT NOT NULL DEFAULT '',
    provider_id   INTEGER REFERENCES llm_providers(id),
    research_provider_id INTEGER REFERENCES llm_providers(id)
);
CREATE TABLE imports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    format        TEXT NOT NULL,
    total         INTEGER NOT NULL DEFAULT 0,
    stats_json    TEXT NOT NULL DEFAULT '{}',
    sheets_json   TEXT NOT NULL DEFAULT '[]',
    summary_json  TEXT NOT NULL DEFAULT '{}',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL
);
CREATE TABLE findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id     TEXT NOT NULL,
    import_id  INTEGER NOT NULL,
    pos        INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT '',
    cvss       REAL,
    urgent     INTEGER NOT NULL DEFAULT 0,
    codebase   TEXT NOT NULL DEFAULT '',
    group_key  TEXT NOT NULL DEFAULT '',
    data_json  TEXT NOT NULL,
    missing    INTEGER NOT NULL DEFAULT 0,
    missing_since TEXT,
    group_key2 TEXT NOT NULL DEFAULT '',
    g2_cat     TEXT NOT NULL DEFAULT '',
    g2_file    TEXT NOT NULL DEFAULT '',
    g2_line    INTEGER,
    UNIQUE (project_id, hub_id)
);
CREATE TABLE sast_group_merges (
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_key2    TEXT NOT NULL,
    old_keys_json TEXT NOT NULL DEFAULT '[]',
    numbers_json  TEXT NOT NULL DEFAULT '[]',
    merged_at     TEXT NOT NULL,
    PRIMARY KEY (project_id, group_key2)
);
CREATE TABLE review_texts (
    id            INTEGER PRIMARY KEY,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id        TEXT NOT NULL,
    decision      TEXT NOT NULL DEFAULT '',
    final_verdict TEXT NOT NULL DEFAULT '',
    final_comment TEXT NOT NULL DEFAULT '',
    final_fix     TEXT NOT NULL DEFAULT '',
    decided_at    TEXT,
    replaced_at   TEXT NOT NULL
);
CREATE TABLE codebase_map (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    codebase   TEXT NOT NULL,
    folder     TEXT NOT NULL DEFAULT '',
    manual     INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, codebase)
);
CREATE TABLE verdicts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    case_hash      TEXT NOT NULL,
    model          TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    confidence     INTEGER NOT NULL DEFAULT 0,
    data_json      TEXT NOT NULL,
    raw_json       TEXT NOT NULL DEFAULT '{}',
    stats_json     TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    request_key    TEXT NOT NULL DEFAULT '',
    execution_id   INTEGER REFERENCES llm_executions(id)
);
CREATE TABLE cases (
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id       TEXT NOT NULL,
    case_hash    TEXT NOT NULL,
    context_json TEXT NOT NULL,
    verdict_id   INTEGER REFERENCES verdicts(id) ON DELETE SET NULL,
    updated_at   TEXT NOT NULL,
    code_cmp     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, hub_id)
);
CREATE TABLE reviews (
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id        TEXT NOT NULL,
    decision      TEXT NOT NULL DEFAULT '',
    final_verdict TEXT NOT NULL DEFAULT '',
    final_comment TEXT NOT NULL DEFAULT '',
    reviewed      INTEGER NOT NULL DEFAULT 0,
    reviewed_at   TEXT,
    copied_at     TEXT,
    verdict_id    INTEGER,
    finding_sig   TEXT NOT NULL DEFAULT '',
    revision      INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL,
    entered_hub   INTEGER NOT NULL DEFAULT 0,
    entered_hub_at TEXT,
    code_hash     TEXT NOT NULL DEFAULT '',
    code_chars    INTEGER NOT NULL DEFAULT 0,
    entered_text_hash TEXT NOT NULL DEFAULT '',
    answer_sig    TEXT NOT NULL DEFAULT '',
    kapo_state    TEXT NOT NULL DEFAULT '',
    decided_at    TEXT,
    final_fix     TEXT NOT NULL DEFAULT '',
    entered_parts TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, hub_id)
);
CREATE TABLE runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    state          TEXT NOT NULL,
    scope          TEXT NOT NULL,
    model          TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    fresh          INTEGER NOT NULL DEFAULT 0,
    total          INTEGER NOT NULL DEFAULT 0,
    done           INTEGER NOT NULL DEFAULT 0,
    failed         INTEGER NOT NULL DEFAULT 0,
    cached         INTEGER NOT NULL DEFAULT 0,
    skipped        INTEGER NOT NULL DEFAULT 0,
    model_calls    INTEGER NOT NULL DEFAULT 0,
    model_seconds  REAL NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    eval_seconds   REAL NOT NULL DEFAULT 0,
    last_tps       REAL,
    last_error     TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    started_at     TEXT,
    finished_at    TEXT,
    updated_at     TEXT NOT NULL,
    control        TEXT NOT NULL DEFAULT '',
    partial_stats  INTEGER NOT NULL DEFAULT 0,
    origin         TEXT NOT NULL DEFAULT '',
    execution_id   INTEGER REFERENCES llm_executions(id),
    parent_run_id  INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE TABLE run_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    hub_id      TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending',
    case_hash   TEXT NOT NULL DEFAULT '',
    verdict_id  INTEGER,
    error       TEXT NOT NULL DEFAULT '',
    seconds     REAL,
    eval_tps    REAL,
    finished_at TEXT,
    stats_partial INTEGER NOT NULL DEFAULT 0,
    UNIQUE (run_id, seq)
);
CREATE TABLE questions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id      TEXT NOT NULL,
    question    TEXT NOT NULL,
    answer      TEXT NOT NULL DEFAULT '',
    answer_json TEXT NOT NULL DEFAULT '{}',
    model       TEXT NOT NULL,
    case_hash   TEXT NOT NULL DEFAULT '',
    verdict_id  INTEGER,
    state       TEXT NOT NULL DEFAULT 'pending',
    error       TEXT NOT NULL DEFAULT '',
    stats_json  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    answered_at TEXT,
    execution_id INTEGER REFERENCES llm_executions(id)
);
CREATE TABLE sca_answers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    component           TEXT NOT NULL,
    version             TEXT NOT NULL,
    source              TEXT NOT NULL DEFAULT '',
    recommended_version TEXT NOT NULL DEFAULT '',
    conclusion          TEXT NOT NULL DEFAULT '',
    explanation         TEXT NOT NULL DEFAULT '',
    ids_json            TEXT NOT NULL DEFAULT '{}',
    links_json          TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    vulns_json          TEXT NOT NULL DEFAULT '[]',
    ecosystem           TEXT NOT NULL DEFAULT '',
    UNIQUE (project_id, ecosystem, component, version, source)
);
CREATE TABLE ast_map (
    ast_id     TEXT NOT NULL,
    vuln_id    TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (ast_id, vuln_id)
);
CREATE TABLE defects (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    defect_key TEXT NOT NULL,
    number     INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    assigned_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, defect_key)
);
CREATE TABLE sca2_tasks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    import_id         INTEGER NOT NULL,
    task_id           TEXT NOT NULL,
    contract          TEXT NOT NULL,
    answer_contract   TEXT NOT NULL,
    validator_version TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'current',
    row_count         INTEGER NOT NULL DEFAULT 0,
    ecosystems_json   TEXT NOT NULL DEFAULT '[]',
    manifest_sha256   TEXT NOT NULL,
    components_sha256 TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    superseded_at     TEXT,
    imported_at       TEXT,
    UNIQUE (project_id, task_id)
);
CREATE TABLE sca2_task_rows (
    task_id            INTEGER NOT NULL REFERENCES sca2_tasks(id) ON DELETE CASCADE,
    input_ref          TEXT NOT NULL,
    ecosystem          TEXT NOT NULL,
    name               TEXT NOT NULL,
    version            TEXT NOT NULL,
    identity_kind      TEXT NOT NULL DEFAULT 'short_name',
    input_sig          TEXT NOT NULL DEFAULT '',
    hub_fix_candidate  TEXT NOT NULL DEFAULT '',
    finding_count      INTEGER NOT NULL DEFAULT 0,
    codebase_count     INTEGER NOT NULL DEFAULT 0,
    position           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (task_id, input_ref)
);
CREATE TABLE sca2_research (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    task_id         INTEGER NOT NULL REFERENCES sca2_tasks(id) ON DELETE CASCADE,
    input_ref       TEXT NOT NULL,
    revision        INTEGER NOT NULL,
    answer_sig      TEXT NOT NULL,
    input_sig       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    coverage_checked INTEGER NOT NULL DEFAULT 0,
    coverage_errors INTEGER NOT NULL DEFAULT 0,
    findings_total  INTEGER NOT NULL DEFAULT 0,
    applicable      INTEGER NOT NULL DEFAULT 0,
    gaps_count      INTEGER NOT NULL DEFAULT 0,
    evidence_count  INTEGER NOT NULL DEFAULT 0,
    payload_json    TEXT NOT NULL DEFAULT '{}',
    imported_at     TEXT NOT NULL,
    content_sig     TEXT NOT NULL DEFAULT '',
    observation_json TEXT NOT NULL DEFAULT '{}',
    observed_at     TEXT NOT NULL DEFAULT '',
    validation_rules TEXT NOT NULL DEFAULT 'sca-contract/2.0.1',
    answer_schema   TEXT NOT NULL DEFAULT '',
    execution_id    INTEGER REFERENCES llm_executions(id),
    UNIQUE (project_id, input_ref, revision)
);
CREATE TABLE sca2_decisions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    input_ref           TEXT NOT NULL,
    revision            INTEGER NOT NULL,
    action              TEXT NOT NULL,
    rationale           TEXT NOT NULL,
    target_version      TEXT NOT NULL DEFAULT '',
    replacement_name    TEXT NOT NULL DEFAULT '',
    replacement_version TEXT NOT NULL DEFAULT '',
    review_at           TEXT NOT NULL DEFAULT '',
    input_sig           TEXT NOT NULL DEFAULT '',
    research_sig        TEXT NOT NULL DEFAULT '',
    state               TEXT NOT NULL DEFAULT 'current',
    decided_at          TEXT NOT NULL,
    superseded_at       TEXT,
    UNIQUE (project_id, input_ref, revision)
);
CREATE TABLE sca_defect_sets (
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    input_ref      TEXT NOT NULL,
    set_no         INTEGER NOT NULL,
    revision       INTEGER NOT NULL DEFAULT 0,
    excluded_json  TEXT NOT NULL DEFAULT '[]',
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (project_id, input_ref, set_no)
);
CREATE TABLE sca_set_members (
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id         TEXT NOT NULL,
    input_ref      TEXT NOT NULL,
    set_no         INTEGER,
    no_defect_reason TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (project_id, hub_id)
);
CREATE TABLE sca_package_texts (
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    input_ref      TEXT NOT NULL,
    set_no         INTEGER NOT NULL,
    revision       INTEGER NOT NULL DEFAULT 0,
    explanation    TEXT NOT NULL DEFAULT '',
    ast_json       TEXT NOT NULL DEFAULT '{}',
    target_version TEXT NOT NULL DEFAULT '',
    target_basis   TEXT NOT NULL DEFAULT '',
    version_checked_sig TEXT NOT NULL DEFAULT '',
    text_checked_sig TEXT NOT NULL DEFAULT '',
    text_sig       TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL,
    residual_checked_sig TEXT NOT NULL DEFAULT '',
    recommendation_note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, input_ref, set_no)
);
CREATE TABLE sca_applicability (
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    input_ref         TEXT NOT NULL,
    vuln_key          TEXT NOT NULL,
    ids_json          TEXT NOT NULL DEFAULT '[]',
    decision          TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    research_revision INTEGER NOT NULL DEFAULT 0,
    revision          INTEGER NOT NULL DEFAULT 1,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (project_id, input_ref, vuln_key)
);
CREATE INDEX run_reviews_by_answer ON run_review_events(project_id,hub_id,verdict_id,id);
CREATE INDEX findings_by_pos ON findings(project_id, pos);
CREATE INDEX findings_by_group ON findings(project_id, group_key);
CREATE INDEX findings_by_group2 ON findings(project_id, group_key2);
CREATE INDEX findings_by_near2 ON findings(project_id, g2_cat, g2_file, g2_line);
CREATE INDEX findings_by_hub2 ON findings(project_id, hub_id, g2_cat, kind, missing, group_key2);
CREATE INDEX review_texts_by_finding ON review_texts(project_id, hub_id, id);
CREATE INDEX verdicts_by_case ON verdicts(case_hash, model, prompt_version, id);
CREATE INDEX verdicts_by_request ON verdicts(request_key, id);
CREATE INDEX cases_by_cmp_hub ON cases(project_id, code_cmp, hub_id);
CREATE INDEX runs_by_state ON runs(state, id);
CREATE INDEX run_items_by_state ON run_items(run_id, state, seq);
CREATE INDEX questions_by_finding ON questions(project_id, hub_id, id);
CREATE INDEX questions_by_state ON questions(state, id);
CREATE INDEX sca2_research_by_ref ON sca2_research(project_id, input_ref, revision);
CREATE INDEX sca_set_members_by_ref ON sca_set_members(project_id, input_ref, set_no);
CREATE INDEX sca2_decisions_by_ref ON sca2_decisions(project_id, input_ref, revision);
CREATE INDEX sca2_rows_by_task ON sca2_task_rows(task_id, position);
INSERT INTO meta(key, value) VALUES ('schema_version', '22');
INSERT INTO schema_version(version, applied_at, note) VALUES (22, '2026-10-24T00:00:00+00:00', 'новая база');
