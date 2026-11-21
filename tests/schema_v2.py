"""Схема базы версии 2 (этап 2) – как её создавало приложение до шага обновления migrate_3. Не меняется: по ней
тесты строят базу прежней версии и проверяют, что шаги обновления доводят её до текущей схемы без потери данных."""

V2_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    repos_dir     TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    model         TEXT NOT NULL DEFAULT '',
    archived      INTEGER NOT NULL DEFAULT 0,
    archived_at   TEXT,
    last_activity TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS imports (
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

CREATE TABLE IF NOT EXISTS findings (
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
    UNIQUE (project_id, hub_id)
);
CREATE INDEX IF NOT EXISTS findings_by_pos ON findings(project_id, pos);

CREATE TABLE IF NOT EXISTS codebase_map (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    codebase   TEXT NOT NULL,
    folder     TEXT NOT NULL DEFAULT '',
    manual     INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, codebase)
);

CREATE TABLE IF NOT EXISTS verdicts (
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
    request_key    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS verdicts_by_case ON verdicts(case_hash, model, prompt_version, id);
CREATE INDEX IF NOT EXISTS verdicts_by_request ON verdicts(request_key, id);

CREATE TABLE IF NOT EXISTS cases (
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hub_id       TEXT NOT NULL,
    case_hash    TEXT NOT NULL,
    context_json TEXT NOT NULL,
    verdict_id   INTEGER REFERENCES verdicts(id) ON DELETE SET NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (project_id, hub_id)
);

CREATE TABLE IF NOT EXISTS reviews (
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
    PRIMARY KEY (project_id, hub_id)
);

CREATE TABLE IF NOT EXISTS runs (
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
    partial_stats  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_by_state ON runs(state, id);

CREATE TABLE IF NOT EXISTS run_items (
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
CREATE INDEX IF NOT EXISTS run_items_by_state ON run_items(run_id, state, seq);

CREATE TABLE IF NOT EXISTS questions (
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
    answered_at TEXT
);
CREATE INDEX IF NOT EXISTS questions_by_finding ON questions(project_id, hub_id, id);
CREATE INDEX IF NOT EXISTS questions_by_state ON questions(state, id);

CREATE TABLE IF NOT EXISTS sca_answers (
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
    UNIQUE (project_id, component, version, source)
);

CREATE TABLE IF NOT EXISTS ast_map (
    ast_id     TEXT NOT NULL,
    vuln_id    TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (ast_id, vuln_id)
);
"""
