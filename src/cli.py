"""End-to-end command-line orchestrator for the TriageLens pipeline.

Coordinates all six major stages:
1. Alert Intake (JSON and CSV)
2. Threat Intelligence Enrichment (VirusTotal, AbuseIPDB, URLhaus)
3. Incident Timeline Correlation
4. Cloud LLM-Assisted Triage (Groq API with PII Scrubbing)
5. Ground-Truth Accuracy & Validation Evaluation
6. Relational Persistence
"""

import argparse
import logging
import os
import sys
from typing import Dict, List, Optional
from uuid import UUID

from dotenv import load_dotenv

from src import config
from src.engine.database import DatabaseManager
from src.engine.enrichment import (
    AbuseIPDBProvider,
    EnrichmentEngine,
    URLhausProvider,
    VirusTotalProvider,
)
from src.engine.evaluation import AccuracyTracker
from src.engine.intake import AlertIntakeEngine
from src.engine.groq import GroqTriageEngine
from src.engine.provenance import evaluation_run
from src.engine.timeline import TimelineBuilder
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict
from src.utils.extraction import is_public_ipv4, is_public_ipv6, is_valid_domain

# Load environment variables (.env file)
load_dotenv()

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("triagelens.cli")


def detect_indicator_type(indicator: str) -> str:
    """Classifies an indicator string into its probable type.

    Returns:
        'ip', 'url', 'hash', 'domain', or 'unknown'
    """
    clean = indicator.strip()
    if clean.startswith(("http://", "https://")):
        return "url"
    if is_public_ipv4(clean) or is_public_ipv6(clean):
        return "ip"
    clean_hex = clean.lower()
    if len(clean_hex) in (32, 40, 64) and all(c in "0123456789abcdef" for c in clean_hex):
        return "hash"
    if is_valid_domain(clean):
        return "domain"
    return "unknown"


def run_pipeline(
    data_dir: str = "data/",
    db_path: Optional[str] = None,
    group_by: str = "auto",
    skip_llm: bool = False,
    max_lookups: Optional[int] = None,
) -> Dict[str, float]:
    """Executes the complete TriageLens alert investigation and triage pipeline.

    Args:
        data_dir: Path to directory containing alert log files.
        db_path: Path to SQLite database file.
        group_by: Field name used to correlate alerts into timelines.
        skip_llm: Whether to bypass the LLM triage and evaluation stages.
        max_lookups: Maximum number of external threat intelligence lookups per run.

    Returns:
        Dictionary of final accuracy evaluation metrics.
    """
    logger.info("=" * 65)
    logger.info("Initializing TriageLens Pipeline")
    logger.info("Input directory and database configured")
    logger.info("=" * 65)

    # 1. Initialize storage for the trusted intake and evaluation coordinator.
    db = config.open_database('evaluator', db_path, sqlite_factory=DatabaseManager)
    with evaluation_run(db, 'cli') as run:
        return _run_pipeline(db, run, data_dir, group_by, skip_llm, max_lookups)


def _run_pipeline(db, run, data_dir, group_by, skip_llm, max_lookups):

    # 2. Initialize Processing Engines
    intake_engine = AlertIntakeEngine()
    enrichment_engine = EnrichmentEngine(db=db, max_lookups_per_run=max_lookups)
    active_providers_str = ", ".join(enrichment_engine.providers.keys()) or "none"
    logger.info("[Enrichment] Active threat intelligence providers: %s", active_providers_str)

    timeline_builder = TimelineBuilder()
    accuracy_tracker = AccuracyTracker()

    # Initialize LLM Engine (if key exists and not explicitly skipped)
    groq_key = config.get_groq_api_key()
    triage_engine: Optional[GroqTriageEngine] = None

    if not skip_llm:
        if groq_key:
            try:
                triage_engine = GroqTriageEngine(api_key=groq_key)
                logger.info("[LLM Triage] Groq Triage Engine initialized with PII Scrubber.")
            except Exception as exc:
                logger.warning("[LLM Triage] Failed to initialize Groq Engine (%s).", type(exc).__name__)
        else:
            logger.warning("[LLM Triage] GROQ_API_KEY not found in environment; LLM stage will be skipped.")
    else:
        logger.info("[LLM Triage] Skipped via --skip-llm flag.")

    with db:
        # Ensure database tables exist
        logger.info('Evaluation run: %s', run.run_id)

        # =================================================================
        # Stage 1: Alert Intake
        # =================================================================
        logger.info("\n>>> STAGE 1: Alert Intake Engine")
        all_alerts: List[NormalizedAlert] = []
        unique_indicators = set()

        if not os.path.exists(data_dir):
            logger.error("Data directory does not exist.")
            raise FileNotFoundError('Pipeline input directory does not exist')

        for batch in intake_engine.ingest_directory(data_dir, batch_size=100):
            for alert in batch:
                db.insert_alert(alert)
                all_alerts.append(alert)
                for ind in alert.extracted_indicators:
                    unique_indicators.add(ind)

        logger.info("Successfully ingested and persisted %d alerts.", len(all_alerts))
        logger.info("Extracted %d unique indicators for threat intelligence enrichment.", len(unique_indicators))

        if not all_alerts:
            logger.warning("No alerts ingested. Pipeline exiting.")
            return accuracy_tracker.get_metrics()

        # =================================================================
        # Stage 2: Threat Intelligence Enrichment
        # =================================================================
        logger.info("\n>>> STAGE 2: Threat Intelligence Enrichment")
        all_enrichment_results: List[EnrichmentResult] = []

        for ind in unique_indicators:
            ind_type = detect_indicator_type(ind)
            if ind_type in ("unknown", "invalid"):
                logger.warning("Skipping indicator '%s' classified as '%s'", ind, ind_type)
                continue
            results = enrichment_engine.lookup_indicator(ind, indicator_type=ind_type)
            for res in results:
                all_enrichment_results.append(res)
                db.insert_enrichment(res)

        ok_count = sum(1 for r in all_enrichment_results if getattr(r, "lookup_status", "ok") == "ok")
        unavail_count = len(all_enrichment_results) - ok_count
        logger.info(
            "Enrichment completed. %d results persisted (%d verified, %d unavailable).",
            len(all_enrichment_results),
            ok_count,
            unavail_count,
        )

        # =================================================================
        # Stage 3: Incident Timeline Builder
        # =================================================================
        logger.info("\n>>> STAGE 3: Incident Timeline Correlation")
        timelines = timeline_builder.build_timelines(
            alerts=all_alerts,
            enrichment_data=all_enrichment_results,
            group_by=group_by,
        )

        for tl in timelines:
            db.insert_timeline(tl)

        logger.info("Successfully generated and persisted %d correlated threat timelines.", len(timelines))

        # =================================================================
        # Stage 4 & 5: LLM Triage & Ground Truth Accuracy Evaluation
        # =================================================================
        logger.info("\n>>> STAGE 4 & 5: AI Triage and Ground Truth Evaluation")
        verdicts_generated = 0

        for idx, tl in enumerate(timelines, start=1):
            observation_id = run.observe(tl, idx)
            logger.info(
                "Processing Timeline [%d/%d] (%d events)",
                idx,
                len(timelines),
                tl.total_events,
            )

            if triage_engine:
                acquisition = run.acquire(triage_engine, tl, observation_id)
                verdict = acquisition.verdict

                if verdict:
                    verdicts_generated += 1
                    logger.info(
                        "  -> AI Verdict: Severity=%s | Confidence=%.2f | Summary: %s",
                        verdict.severity,
                        verdict.confidence_score,
                        verdict.summary[:60] + "..." if len(verdict.summary) > 60 else verdict.summary,
                    )

                else:
                    logger.warning("  -> AI triage produced no verdict (rate limit, timeout, or schema rejection).")
                # Every attempted triage contributes an outcome, even without a verdict.
                eval_result = accuracy_tracker.evaluate(verdict, tl)
                run.complete(observation_id, eval_result, tl, accuracy_tracker,
                             verdict=verdict, failure_category=acquisition.failure_category)
                logger.info(
                    "  -> Ground Truth Evaluation: Category='%s' | Match=%s",
                    eval_result.category,
                    eval_result.is_correct,
                )
            else:
                db.skip_observation(observation_id)
                logger.info("  -> AI Triage bypassed (LLM engine inactive).")

    # =================================================================
    # Pipeline Summary & Performance Metrics
    # =================================================================
    metrics = accuracy_tracker.get_metrics()
    logger.info("\n" + "=" * 65)
    logger.info("PIPELINE EXECUTION SUMMARY")
    logger.info("=" * 65)
    logger.info("Total Alerts Ingested       : %d", len(all_alerts))
    logger.info("Unique Indicators Enriched  : %d", len(unique_indicators))
    logger.info("Timelines Correlated        : %d", len(timelines))
    logger.info("AI Verdicts Generated       : %d", verdicts_generated)
    logger.info("-" * 65)
    logger.info("ACCURACY & RELIABILITY METRICS (Stage 5)")
    logger.info("Accuracy                    : %.2f%%", metrics.get("accuracy", 0.0) * 100)
    logger.info("Precision                   : %.2f%%", metrics.get("precision", 0.0) * 100)
    logger.info("Recall (Sensitivity)        : %.2f%%", metrics.get("recall", 0.0) * 100)
    logger.info("F1-Score                    : %.2f%%", metrics.get("f1_score", 0.0) * 100)
    logger.info("Confusion Matrix Counts     : TP=%d, TN=%d, FP=%d, FN=%d", metrics.get("tp", 0), metrics.get("tn", 0), metrics.get("fp", 0), metrics.get("fn", 0))
    logger.info("Binary Evaluated Records    : %d (Unknown/abstained: %d)", metrics.get("total", 0), metrics.get("unknown", 0))
    logger.info("Undetermined Dispositions   : %d", metrics.get("abstained", 0))
    logger.info("Labelled Binary Coverage    : %d / %d available labelled (abstained: %d)",
                metrics.get("labelled_binary", 0), metrics.get("labelled_available", 0),
                metrics.get("labelled_abstained", 0))
    logger.info("Prediction Basis            : explicit=%d, legacy proxy=%d, unrecorded=%d",
                metrics.get("explicit_disposition_count", 0), metrics.get("legacy_severity_proxy_count", 0),
                metrics.get("prediction_basis_unknown_count", 0))
    logger.info("Unavailable AI Outcomes    : %d", metrics.get("unavailable", 0))
    logger.info("AI Availability Rate       : %.2f%%", metrics.get("availability_rate", 1.0) * 100)
    logger.info("=" * 65)

    return metrics


def main() -> None:
    """Entry point for command-line execution."""
    parser = argparse.ArgumentParser(
        prog="triagelens-cli",
        description="TriageLens: AI-Powered SOC Alert Triage and Reliability Pipeline",
    )
    parser.add_argument(
        "--data-dir",
        default="data/",
        help="Path to folder containing alert log files in JSON or CSV format (default: 'data/')",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="SQLite path override; relative paths use the project root (default: DATABASE_PATH, TRIAGELENS_DB_PATH, or data/triagelens.db). Configure the API with the same target.",
    )
    parser.add_argument(
        "--group-by",
        default="auto",
        help="Correlation strategy or field name: 'auto' (host+user correlation with time-windowing), 'host', 'user', or specific field name (default: 'auto')",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Bypass LLM triage analysis stage (useful for offline runs)",
    )
    parser.add_argument(
        "--max-lookups",
        type=int,
        default=None,
        help="Maximum external threat intelligence lookups per run (default: unlimited)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging verbosity level (default: 'INFO')",
    )

    args = parser.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))

    try:
        run_pipeline(
            data_dir=args.data_dir,
            db_path=args.db_path,
            group_by=args.group_by,
            skip_llm=args.skip_llm,
            max_lookups=args.max_lookups,
        )
    except KeyboardInterrupt:
        logger.warning("\nPipeline execution cancelled by user.")
        sys.exit(130)
    except Exception as exc:
        logger.critical("Fatal error during pipeline execution: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

