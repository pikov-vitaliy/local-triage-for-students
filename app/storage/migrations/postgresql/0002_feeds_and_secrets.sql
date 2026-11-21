-- schema: 34
-- ADR-0133: справочники и ключи – в базе. Схема feeds – действующие справочники, feeds_imp – идущая загрузка той же
-- структуры, app_state – ключи приложения. Таблицы во время работы не создаются и не удаляются.
CREATE SCHEMA feeds;
CREATE SCHEMA feeds_imp;
CREATE SCHEMA app_state;

CREATE TABLE app_state.secrets (
    name       TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE feeds.feed_meta (
    kind        TEXT PRIMARY KEY,
    filename    TEXT NOT NULL,
    loaded_at   TEXT NOT NULL,
    records     INTEGER NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    source_date TEXT NOT NULL DEFAULT '',
    ref_records INTEGER NOT NULL DEFAULT 0,
    xml_bytes   BIGINT NOT NULL DEFAULT 0,
    seconds     DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE feeds.bdu (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE feeds.bdu_cve (cve TEXT NOT NULL, bdu_id TEXT NOT NULL, PRIMARY KEY (cve, bdu_id));
CREATE TABLE feeds.cwe_ru (id TEXT PRIMARY KEY, name_ru TEXT NOT NULL);
CREATE TABLE feeds.cwe (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE feeds.cwe_refs (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE feeds.cwe_links (id TEXT NOT NULL, rel TEXT NOT NULL, other_id TEXT NOT NULL, PRIMARY KEY (id, rel, other_id));
CREATE TABLE feeds.cwe_index (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
                              abstraction TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '');
CREATE TABLE feeds.cwe_capec (cwe TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (cwe, id));
CREATE TABLE feeds.capec (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE feeds.capec_index (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, search_text TEXT NOT NULL);
CREATE TABLE feeds.capec_refs (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE feeds.capec_links (id TEXT NOT NULL, rel TEXT NOT NULL, other_id TEXT NOT NULL, PRIMARY KEY (id, rel, other_id));
CREATE TABLE feeds.capec_cwe (id TEXT NOT NULL, cwe TEXT NOT NULL, PRIMARY KEY (id, cwe));
CREATE TABLE feeds.capec_meta (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);

CREATE TABLE feeds_imp.bdu (LIKE feeds.bdu INCLUDING ALL);
CREATE TABLE feeds_imp.bdu_cve (LIKE feeds.bdu_cve INCLUDING ALL);
CREATE TABLE feeds_imp.cwe_ru (LIKE feeds.cwe_ru INCLUDING ALL);
CREATE TABLE feeds_imp.cwe (LIKE feeds.cwe INCLUDING ALL);
CREATE TABLE feeds_imp.cwe_refs (LIKE feeds.cwe_refs INCLUDING ALL);
CREATE TABLE feeds_imp.cwe_links (LIKE feeds.cwe_links INCLUDING ALL);
CREATE TABLE feeds_imp.cwe_index (LIKE feeds.cwe_index INCLUDING ALL);
CREATE TABLE feeds_imp.cwe_capec (LIKE feeds.cwe_capec INCLUDING ALL);
CREATE TABLE feeds_imp.capec (LIKE feeds.capec INCLUDING ALL);
CREATE TABLE feeds_imp.capec_index (LIKE feeds.capec_index INCLUDING ALL);
CREATE TABLE feeds_imp.capec_refs (LIKE feeds.capec_refs INCLUDING ALL);
CREATE TABLE feeds_imp.capec_links (LIKE feeds.capec_links INCLUDING ALL);
CREATE TABLE feeds_imp.capec_cwe (LIKE feeds.capec_cwe INCLUDING ALL);
CREATE TABLE feeds_imp.capec_meta (LIKE feeds.capec_meta INCLUDING ALL);
