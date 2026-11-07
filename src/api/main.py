"""FastAPI application for TriageLens.

Provides REST endpoints for metrics, timelines, alerts, and triage verdicts
with CORS middleware, strict input validation, and thread-safe persistence.
"""

import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from src import config
from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.engine.hunting import KQLParseError, ThreatHuntingEngine

logger = logging.getLogger(__name__)


class HuntRequest(BaseModel):
    """Payload for threat hunting search queries with strict boundary constraints."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="KQL-style search query expression (1-2000 chars)",
    )
    limit: Optional[int] = Field(
        default=500,
        ge=1,
        le=1000,
        description="Maximum number of matching telemetry alerts to return (1-1000)",
    )


def get_db(request: Request) -> DatabaseManager:
    """Dependency provider for DatabaseManager."""
    return request.app.state.db


def get_tracker(request: Request) -> AccuracyTracker:
    """Dependency provider for AccuracyTracker."""
    return request.app.state.tracker


def create_app(
    db: Optional[DatabaseManager] = None,
    tracker: Optional[AccuracyTracker] = None,
) -> FastAPI:
    """Factory creating and configuring the FastAPI application.

    Args:
        db: Optional custom DatabaseManager instance (e.g. for testing).
        tracker: Optional custom AccuracyTracker instance.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="TriageLens API",
        description="AI-powered SOC alert triage and accuracy evaluation platform.",
        version="0.1.0",
    )

    # 1. Configure CORS middleware strictly for local frontend communication
    allowed_origins = config.get_allowed_origins()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. Attach DatabaseManager and AccuracyTracker to app state
    if db is None:
        db_path = config.get_database_path()
        db = DatabaseManager(db_path=db_path, check_same_thread=False)
        db.init_db()

    app.state.db = db
    app.state.tracker = tracker or AccuracyTracker()

    # 3. Global Exception Handler (sanitizes 500 errors, prevents stack/SQL/path leaks)
    @app.exception_handler(Exception)
    def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Global fallback handler catching unhandled exceptions.

        Returns a generic, sanitized JSON response without leaking stack traces,
        internal filesystem paths, SQL queries, or database connection strings.
        """
        logger.error(
            "Unhandled server error during %s %s: %s",
            request.method,
            request.url.path,
            str(exc),
            exc_info=False,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An internal server error occurred while processing the request.",
            },
        )

    # 4. Health check endpoint (checks database connectivity)
    @app.get(
        "/health",
        tags=["System"],
        summary="System health check and database connectivity status",
    )
    def health_check(db: DatabaseManager = Depends(get_db)) -> Dict[str, str]:
        """Health check endpoint verifying system responsiveness and database connectivity.

        Returns 200 OK with connectivity status, or 503 Service Unavailable if the
        database connection fails.
        """
        try:
            if db is None:
                raise RuntimeError("DatabaseManager dependency is None")
            db.connection.execute("SELECT 1;").fetchone()
            return {"status": "ok", "database": "connected", "service": "triagelens-api"}
        except Exception as exc:
            logger.error("Health check failed due to database connectivity issue: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database unhealthy",
            )

    # 4. Accuracy and Metrics Endpoint
    @app.get(
        "/api/metrics",
        tags=["Metrics"],
        summary="Retrieve AI triage accuracy and performance metrics",
    )
    def get_metrics(
        tracker: AccuracyTracker = Depends(get_tracker),
        db: DatabaseManager = Depends(get_db),
    ) -> Dict[str, Any]:
        """Returns the current confusion matrix and statistical evaluation metrics:

        TP, TN, FP, FN, Precision, Recall, Accuracy, and F1-Score.
        Dynamically computes from stored database evaluations when present.
        """
        if db is not None:
            db_tracker = AccuracyTracker.from_database(db)
            if db_tracker.total_evaluated > 0 or db_tracker.history:
                return db_tracker.get_metrics()
        return tracker.get_metrics()

    # 5. Timelines List Endpoint (with strict pagination validation)
    @app.get(
        "/api/timelines",
        tags=["Timelines"],
        summary="Retrieve paginated threat timelines",
    )
    def list_timelines(
        skip: int = Query(
            default=0,
            ge=0,
            description="Number of records to skip (offset)",
        ),
        limit: int = Query(
            default=50,
            ge=1,
            le=1000,
            description="Maximum number of records to return (1-1000)",
        ),
        db: DatabaseManager = Depends(get_db),
    ) -> List[Dict[str, Any]]:
        """Returns a paginated list of correlated threat timelines.

        Rejects negative offsets and excessive limits (> 1000) with HTTP 422.
        """
        return db.get_timelines(skip=skip, limit=limit)

    # 6. Timeline Detail Endpoint
    @app.get(
        "/api/timelines/{timeline_id}",
        tags=["Timelines"],
        summary="Retrieve detailed threat timeline with alerts and LLM verdict",
    )
    def get_timeline_detail(
        timeline_id: str,
        db: DatabaseManager = Depends(get_db),
    ) -> Dict[str, Any]:
        """Returns a specific timeline, its associated security alerts,

        and its AI-generated triage verdict.
        """
        timeline = db.get_timeline(timeline_id)
        if not timeline:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Timeline '{timeline_id}' not found.",
            )

        alerts = db.get_alerts_for_timeline(timeline_id)
        verdict = db.get_verdict_for_timeline(timeline_id)

        response_data = dict(timeline)
        response_data["alerts"] = alerts
        response_data["verdict"] = verdict
        response_data["timeline"] = timeline
        return response_data

    # 7. Alert Detail Endpoint
    @app.get(
        "/api/alerts/{alert_id}",
        tags=["Alerts"],
        summary="Retrieve normalized security alert by ID",
    )
    def get_alert_detail(
        alert_id: str,
        db: DatabaseManager = Depends(get_db),
    ) -> Dict[str, Any]:
        """Returns normalized alert telemetry by alert internal_id."""
        alert = db.get_alert(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found.",
            )
        return alert

    # 8. Indicator Enrichment Endpoint
    @app.get(
        "/api/enrichments/{indicator}",
        tags=["Enrichment"],
        summary="Retrieve threat intelligence lookups for an indicator",
    )
    def get_indicator_enrichment(
        indicator: str,
        db: DatabaseManager = Depends(get_db),
    ) -> List[Dict[str, Any]]:
        """Returns all cached/recorded threat intelligence lookups for an indicator."""
        return db.get_enrichments(indicator)

    # 9. Threat Hunting Endpoint
    @app.post(
        "/api/hunt",
        tags=["Threat Hunting"],
        summary="Execute KQL threat hunting query against security telemetry",
    )
    def hunt_telemetry(
        hunt_req: HuntRequest,
        db: DatabaseManager = Depends(get_db),
    ) -> List[Dict[str, Any]]:
        """Executes a KQL-style query translated into secure parameterized SQL.

        Returns matching NormalizedAlert items.
        """
        hunting_engine = ThreatHuntingEngine(db)
        try:
            matched = hunting_engine.execute_hunt(hunt_req.query, limit=hunt_req.limit)
            return [alert.model_dump(mode="json") for alert in matched]
        except KQLParseError as parse_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"KQL Parse Error: {str(parse_err)}",
            )

    return app


# Default application instance for ASGI servers (e.g. uvicorn src.api.main:app)
app = create_app()
