"""Baseline for PostgreSQL storage, provenance, and role boundaries."""

from alembic import op

revision = "0001_postgresql"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA_SQL = """
CREATE TABLE triagelens.timelines (
    id TEXT PRIMARY KEY,
    grouping_key TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    total_events INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    correlation_type TEXT DEFAULT 'confirmed',
    correlation_reason TEXT
);

CREATE TABLE triagelens.alerts (
    id TEXT PRIMARY KEY,
    timeline_id TEXT,
    timestamp TEXT,
    source_dataset TEXT NOT NULL,
    source_file TEXT NOT NULL,
    event_type TEXT NOT NULL,
    original_record JSONB NOT NULL,
    extracted_indicators TEXT NOT NULL,
    canonical_record JSONB NOT NULL,
    timestamp_utc TIMESTAMPTZ,
    created_at TEXT NOT NULL,
    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE SET NULL
);

CREATE TABLE triagelens.enrichments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    is_malicious INTEGER NOT NULL,
    raw_response TEXT NOT NULL,
    lookup_timestamp TEXT NOT NULL,
    lookup_status TEXT DEFAULT 'ok'
);

CREATE TABLE triagelens.enrichment_cache (
    cache_key TEXT PRIMARY KEY,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    lookup_status TEXT NOT NULL,
    is_malicious INTEGER NOT NULL,
    raw_response TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE triagelens.enrichment_quotas (
    provider TEXT NOT NULL,
    date_key TEXT NOT NULL,
    request_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, date_key)
);

CREATE TABLE triagelens.verdicts (
    id TEXT PRIMARY KEY,
    timeline_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL,
    summary TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    recommended_actions TEXT NOT NULL,
    raw_llm_response TEXT NOT NULL,
    created_at TEXT NOT NULL,
    model_name TEXT,
    uncertainty_level TEXT,
    missing_information TEXT,
    disposition TEXT,
    policy_version TEXT,
    evidence_basis TEXT,
    evidence_context TEXT,
    evidence_contract_version TEXT,
    predicted_techniques TEXT,
    evidence_hash TEXT,
    inference_policy_hash TEXT,
    cache_provenance_version INTEGER,
    cache_expires_at TEXT,
    cache_generated_at TEXT,
    cache_verdict_hash TEXT,
    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE CASCADE
);

CREATE TABLE triagelens.analyst_reviews (
    verdict_id TEXT PRIMARY KEY REFERENCES verdicts(id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    override_disposition TEXT,
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE triagelens_truth.evaluation_runs (
    run_id TEXT PRIMARY KEY,
    entrypoint TEXT NOT NULL CHECK(entrypoint IN ('cli','evaluation')),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
    inference_policy_hash TEXT,
    cohort_manifest TEXT NOT NULL,
    quality_cohort_hash TEXT NOT NULL,
    failure_category TEXT
);

CREATE TABLE triagelens_truth.triage_observations (
    observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal>0),
    timeline_id TEXT NOT NULL,
    origin TEXT CHECK(origin IN ('fresh','cache','skipped','unknown')),
    attempt_id TEXT UNIQUE,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('pending','completed','skipped','interrupted')),
    evidence_hash TEXT,
    inference_policy_hash TEXT,
    verdict_id TEXT,
    cache_validation TEXT NOT NULL DEFAULT 'unverified' CHECK(cache_validation IN ('unverified','verified','rejected')),
    failure_category TEXT,
    outcome_hash TEXT,
    UNIQUE(run_id,ordinal),
    FOREIGN KEY(run_id) REFERENCES evaluation_runs(run_id),
    FOREIGN KEY(timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,
    FOREIGN KEY(verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE
);

CREATE TABLE triagelens_truth.metric_cohorts (
    cohort_id TEXT PRIMARY KEY,
    manifest TEXT NOT NULL
);

CREATE TABLE triagelens_truth.metric_run_cohorts (
    run_id TEXT PRIMARY KEY REFERENCES evaluation_runs(run_id),
    cohort_id TEXT NOT NULL REFERENCES metric_cohorts(cohort_id)
);

CREATE TABLE triagelens.saved_hunting_queries (
    name TEXT PRIMARY KEY CHECK(length(name) BETWEEN 1 AND 100),
    query TEXT NOT NULL CHECK(length(query) BETWEEN 1 AND 2000),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE triagelens.detections (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL CHECK(length(trim(rule_id)) > 0),
    source TEXT NOT NULL CHECK(source IN ('sigma', 'hunt', 'yara')),
    detected_at TEXT NOT NULL ,
    technique_ids TEXT
);

CREATE TABLE triagelens.detection_events (
    detection_id TEXT NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
    PRIMARY KEY (detection_id, alert_id)
);

CREATE TABLE triagelens.yara_scans (
    id TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    scan_order BIGINT GENERATED ALWAYS AS IDENTITY
);

CREATE TABLE triagelens.yara_scan_detections (
    scan_id TEXT NOT NULL REFERENCES yara_scans(id) ON DELETE CASCADE,
    rule_key TEXT NOT NULL,
    detection_id TEXT NOT NULL REFERENCES detections(id),
    PRIMARY KEY(scan_id, rule_key)
);

CREATE TABLE triagelens.yara_jobs (
    id TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL
);

CREATE TABLE triagelens_truth.evaluations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timeline_id TEXT NOT NULL,
    verdict_id TEXT,
    ground_truth INTEGER,
    llm_prediction INTEGER,
    is_correct INTEGER,
    category TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    confidence_score DOUBLE PRECISION,
    severity_prediction TEXT,
    severity_ground_truth TEXT,
    severity_correct INTEGER,
    disposition TEXT,
    prediction_basis TEXT,
    policy_version TEXT,
    observation_id TEXT REFERENCES triage_observations(observation_id),
    evaluation_context_hash TEXT,
    quality_cohort_hash TEXT,
    provenance_version INTEGER,
    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,
    FOREIGN KEY (verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE
);

CREATE INDEX idx_enrichment_cache_expires ON enrichment_cache(expires_at);

CREATE UNIQUE INDEX idx_evaluation_observation ON evaluations(observation_id) WHERE observation_id IS NOT NULL;

CREATE INDEX idx_metric_cohort_runs ON metric_run_cohorts(cohort_id);

CREATE INDEX idx_detection_events_alert ON detection_events(alert_id);

CREATE INDEX idx_alerts_timeline ON alerts(timeline_id);

CREATE INDEX idx_enrichments_indicator ON enrichments(indicator);

CREATE INDEX idx_verdicts_timeline ON verdicts(timeline_id);

CREATE INDEX idx_evaluations_timeline ON evaluations(timeline_id);

CREATE TABLE triagelens_truth.alert_labels (
    alert_id TEXT PRIMARY KEY REFERENCES triagelens.alerts(id) ON DELETE CASCADE,
    ground_truth_label TEXT,
    ground_truth_metadata TEXT
);

CREATE INDEX idx_alerts_raw_gin ON triagelens.alerts USING GIN (original_record);

CREATE VIEW triagelens.hunting_alerts AS
SELECT a.id, a.timeline_id, a.timestamp, a.source_dataset, a.source_file,
       a.event_type, a.original_record, a.extracted_indicators, a.canonical_record,
       t.ground_truth_label, t.ground_truth_metadata
FROM triagelens.alerts a LEFT JOIN triagelens_truth.alert_labels t ON t.alert_id = a.id;
"""

ROLES = ("triagelens_triage", "triagelens_evaluator", "triagelens_analyst", "triagelens_hunt")


def upgrade():
    op.execute("CREATE SCHEMA triagelens_truth")
    for ddl in SCHEMA_SQL.strip().split(";"):
        if ddl.strip():
            op.execute(ddl)
    op.execute("""
        CREATE FUNCTION triagelens_truth.reject_cohort_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Immutable metric cohort' USING ERRCODE = '23514';
        END;
        $$;
    """)
    for table in ("metric_cohorts", "metric_run_cohorts"):
        op.execute(f"""
            CREATE TRIGGER immutable_cohort BEFORE UPDATE OR DELETE ON triagelens_truth.{table}
            FOR EACH ROW EXECUTE FUNCTION triagelens_truth.reject_cohort_mutation()
        """)
    for role in ROLES:
        op.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                    CREATE ROLE {role} NOLOGIN;
                ELSIF EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = '{role}'
                    AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
                ) THEN
                    RAISE EXCEPTION 'Unsafe existing TriageLens group role';
                END IF;
            END;
            $$;
        """)
        op.execute(f"GRANT USAGE ON SCHEMA triagelens TO {role}")
        op.execute(f"GRANT SELECT ON triagelens.alembic_version TO {role}")
    op.execute("REVOKE ALL ON SCHEMA triagelens_truth FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA triagelens_truth TO triagelens_evaluator, triagelens_analyst")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA triagelens_truth TO triagelens_analyst")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA triagelens TO triagelens_evaluator, triagelens_analyst")
    op.execute("""
        GRANT INSERT, UPDATE ON triagelens.alerts, triagelens.enrichments, triagelens.enrichment_cache,
        triagelens.enrichment_quotas, triagelens.timelines, triagelens.verdicts TO triagelens_evaluator
    """)
    op.execute("GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA triagelens_truth TO triagelens_evaluator")
    op.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA triagelens, triagelens_truth TO triagelens_evaluator")
    op.execute("GRANT INSERT ON triagelens.analyst_reviews TO triagelens_analyst")
    op.execute("GRANT INSERT, UPDATE, DELETE ON triagelens.saved_hunting_queries TO triagelens_analyst")
    op.execute("""
        GRANT INSERT, UPDATE ON triagelens.yara_jobs, triagelens.yara_scans, triagelens.yara_scan_detections,
        triagelens.detections, triagelens.detection_events, triagelens.enrichments, triagelens.enrichment_cache,
        triagelens.enrichment_quotas TO triagelens_analyst
    """)
    op.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA triagelens TO triagelens_analyst")
    op.execute("GRANT SELECT ON triagelens.verdicts TO triagelens_triage")
    op.execute("GRANT SELECT ON triagelens.hunting_alerts TO triagelens_hunt")


def downgrade():
    # Drop only objects owned by this revision. Cluster roles may be shared by other databases.
    op.execute("DROP VIEW triagelens.hunting_alerts")
    for table in ("evaluations", "metric_run_cohorts", "metric_cohorts", "triage_observations",
                  "evaluation_runs", "alert_labels"):
        op.execute(f"DROP TABLE triagelens_truth.{table}")
    op.execute("DROP FUNCTION triagelens_truth.reject_cohort_mutation()")
    op.execute("DROP SCHEMA triagelens_truth")
    for table in ("yara_jobs", "yara_scan_detections", "yara_scans", "detection_events", "detections",
                  "saved_hunting_queries", "analyst_reviews", "verdicts", "enrichment_quotas",
                  "enrichment_cache", "enrichments", "alerts", "timelines"):
        op.execute(f"DROP TABLE triagelens.{table}")
    for role in ROLES:
        op.execute(f"REVOKE SELECT ON triagelens.alembic_version FROM {role}")
        op.execute(f"REVOKE USAGE ON SCHEMA triagelens FROM {role}")
