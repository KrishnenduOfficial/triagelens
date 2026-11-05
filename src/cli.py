"""End-to-end command-line orchestrator for the TriageLens pipeline.

Coordinates all six major stages:
1. Alert Intake (JSON and CSV)
2. Threat Intelligence Enrichment (VirusTotal, AbuseIPDB, URLhaus)
3. Incident Timeline Correlation
4. Cloud LLM-Assisted Triage (Gemini API with PII Scrubbing)
5. Ground-Truth Accuracy & Validation Evaluation
6. Relational Persistence to SQLite
"""

import argparse
import logging
import os
import sys
from typing import Dict, List, Optional
from uuid import UUID

from dotenv import load_dotenv

from src.engine.database import DatabaseManager
from src.engine.enrichment import (
    AbuseIPDBProvider,
    EnrichmentEngine,
    URLhausProvider,
    VirusTotalProvider,
)
from src.engine.evaluation import AccuracyTracker
from src.engine.intake import AlertIntakeEngine
from src.engine.llm import GeminiTriageEngine
from src.engine.timeline import TimelineBuilder
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict
from src.utils.extraction import is_public_ipv4, is_valid_domain

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
        'ip', 'url', 'hash', or 'domain'
    """
    clean = indicator.strip()
    if clean.startswith(("http://", "https://")):
        return "url"
    if is_public_ipv4(clean):
        return "ip"
    clean_hex = clean.lower()
    if len(clean_hex) in (32, 40, 64) and all(c in "0123456789abcdef" for c in clean_hex):
        return "hash"
    if is_valid_domain(clean):
        return "domain"
    return "domain"


def run_pipeline(
    data_dir: str = "data/",
    db_path: Optional[str] = None,
    group_by: str = "source_dataset",
    skip_llm: bool = False,
) -> Dict[str, float]:
    """Executes the complete TriageLens alert investigation and triage pipeline.

    Args:
        data_dir: Path to directory containing alert log files.
        db_path: Path to SQLite database file.
        group_by: Field name used to correlate alerts into timelines.
        skip_llm: Whether to bypass the LLM triage and evaluation stages.

    Returns:
        Dictionary of final accuracy evaluation metrics.
    """
    db_file = db_path or os.getenv("DATABASE_PATH", "triagelens.db")
    logger.info("=" * 65)
    logger.info("Initializing TriageLens Pipeline")
    logger.info("Target Data Directory : %s", data_dir)
    logger.info("Target SQLite Database: %s", db_file)
    logger.info("=" * 65)

    # 1. Initialize SQLite Database
    db = DatabaseManager(db_path=db_file, check_same_thread=False)

    # 2. Initialize Processing Engines
    intake_engine = AlertIntakeEngine()
    enrichment_engine = EnrichmentEngine()

    # Register threat intelligence providers (with graceful missing-key fallbacks)
    vt_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    if vt_key:
        enrichment_engine.register_provider(VirusTotalProvider(api_key=vt_key))
        logger.info("[Enrichment] VirusTotal provider registered.")
    else:
        logger.info("[Enrichment] VirusTotal API key not configured; skipping VT registration.")

    if abuse_key:
        enrichment_engine.register_provider(AbuseIPDBProvider(api_key=abuse_key))
        logger.info("[Enrichment] AbuseIPDB provider registered.")
    else:
        logger.info("[Enrichment] AbuseIPDB API key not configured; skipping AbuseIPDB registration.")

    # URLhaus operates without an API key
    enrichment_engine.register_provider(URLhausProvider())
    logger.info("[Enrichment] URLhaus provider registered.")

    timeline_builder = TimelineBuilder()
    accuracy_tracker = AccuracyTracker()

    # Initialize LLM Engine (if key exists and not explicitly skipped)
    gemini_key = os.getenv("GEMINI_API_KEY")
    triage_engine: Optional[GeminiTriageEngine] = None

    if not skip_llm:
        if gemini_key:
            try:
                triage_engine = GeminiTriageEngine(api_key=gemini_key)
                logger.info("[LLM Triage] Gemini Triage Engine initialized with PII Scrubber.")
            except Exception as exc:
                logger.warning("[LLM Triage] Failed to initialize Gemini Engine: %s", exc)
        else:
            logger.warning("[LLM Triage] GEMINI_API_KEY not found in environment; LLM stage will be skipped.")
    else:
        logger.info("[LLM Triage] Skipped via --skip-llm flag.")

    with db:
        # Ensure database tables exist
        db.init_db()

        # =================================================================
        # Stage 1: Alert Intake
        # =================================================================
        logger.info("\n>>> STAGE 1: Alert Intake Engine")
        all_alerts: List[NormalizedAlert] = []
        unique_indicators = set()

        if not os.path.exists(data_dir):
            logger.error("Data directory '%s' does not exist.", data_dir)
            return accuracy_tracker.get_metrics()

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
            res = enrichment_engine.lookup(ind, indicator_type=ind_type)
            if res:
                all_enrichment_results.append(res)
                db.insert_enrichment(res)

        logger.info(
            "Enrichment completed. %d indicators successfully enriched and persisted.",
            len(all_enrichment_results),
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
            logger.info(
                "Processing Timeline [%d/%d]: '%s' (%d events)",
                idx,
                len(timelines),
                tl.grouping_key,
                tl.total_events,
            )

            if triage_engine:
                verdict: Optional[TriageVerdict] = None
                try:
                    verdict = triage_engine.analyze_timeline(tl)
                except Exception as exc:
                    logger.warning(
                        "Resilient exception during AI triage for timeline '%s': %s",
                        tl.timeline_id,
                        exc,
                    )

                if verdict:
                    verdicts_generated += 1
                    db.insert_verdict(verdict)
                    logger.info(
                        "  -> AI Verdict: Severity=%s | Confidence=%.2f | Summary: %s",
                        verdict.severity,
                        verdict.confidence_score,
                        verdict.summary[:60] + "..." if len(verdict.summary) > 60 else verdict.summary,
                    )

                    # Evaluate verdict against deterministic ground truth
                    eval_result = accuracy_tracker.evaluate(verdict, tl)
                    db.insert_evaluation(eval_result)
                    logger.info(
                        "  -> Ground Truth Evaluation: Category='%s' | Match=%s",
                        eval_result.category,
                        eval_result.is_correct,
                    )
                else:
                    logger.warning("  -> AI triage produced no verdict (rate limit, timeout, or schema rejection).")
            else:
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
    logger.info("Total Evaluated Records     : %d (Unlabeled: %d)", metrics.get("total", 0), metrics.get("unknown", 0))
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
        help="Path to SQLite database file (default: 'triagelens.db' or DATABASE_PATH)",
    )
    parser.add_argument(
        "--group-by",
        default="source_dataset",
        help="Field name to group alerts by for timeline generation (default: 'source_dataset')",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Bypass LLM triage analysis stage (useful for offline runs)",
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
        )
    except KeyboardInterrupt:
        logger.warning("\nPipeline execution cancelled by user.")
        sys.exit(130)
    except Exception as exc:
        logger.critical("Fatal error during pipeline execution: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

