"""Adversarial and security tests for the KQL-style hunting filter engine.

Tests:
- SQL injection defense for filter expressions (payloads in values, fields, and operators).
- Malformed filter defense (unbalanced quotes, random keywords, invalid token chains).
- Deep JSON Query Translation (nested JSON paths like Network.DestinationIp).
- End-to-end execution against SQLite database and FastAPI /api/hunt endpoint.
"""

from uuid import uuid4
from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.hunting import KQLParseError, ThreatHuntingEngine
from src.models.alert import NormalizedAlert


@pytest.fixture
def hunting_setup():
    """Sets up an in-memory database populated with diverse security telemetry."""
    db = DatabaseManager(":memory:", check_same_thread=False)
    db.init_db()

    # Alert 1: Sysmon Process Creation with PowerShell
    alert1 = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="Sysmon_1.json",
        event_type="ProcessCreate",
        original_record={
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6 invoke-mimikatz",
            "User": "SYSTEM",
            "ProcessId": 4048,
        },
        extracted_indicators=["powershell.exe"],
        ground_truth_label="malicious",
    )

    # Alert 2: Network Connection to C2 IP
    alert2 = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="Sysmon_3.json",
        event_type="NetworkConnect",
        original_record={
            "Network": {
                "DestinationIp": "198.51.100.55",
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
            "User": "SYSTEM",
        },
        extracted_indicators=["198.51.100.55"],
        ground_truth_label="malicious",
    )

    # Alert 3: Benign User Logon
    alert3 = NormalizedAlert(
        source_dataset="SECURITY-LOGS",
        source_file="Security_4624.json",
        event_type="LogonSuccess",
        original_record={
            "User": "alice",
            "LogonType": 2,
            "Workstation": "WS-01",
            "Network": {
                "DestinationIp": "10.0.0.1",
                "DestinationPort": 80,
            },
        },
        extracted_indicators=["10.0.0.1"],
        ground_truth_label="benign",
    )

    db.insert_alert(alert1)
    db.insert_alert(alert2)
    db.insert_alert(alert3)

    engine = ThreatHuntingEngine(db)
    app = create_app(db=db)
    client = TestClient(app)

    return {
        "db": db,
        "engine": engine,
        "alerts": [alert1, alert2, alert3],
        "client": client,
    }


# =====================================================================
# 1. SQL Injection Defense Tests
# =====================================================================


def test_sql_injection_in_string_value(hunting_setup):
    """Verify that a DROP TABLE injection payload in a value is safely parameterized."""
    engine = hunting_setup["engine"]
    db = hunting_setup["db"]

    query = 'event_type == "\'; DROP TABLE alerts; --"'
    sql, params = engine.translate_kql_to_sql(query)

    assert "DROP TABLE" not in sql
    assert params == ["'; DROP TABLE alerts; --", 500]
    assert "event_type = ?" in sql

    # Execute the hunt and verify the database is not dropped
    results = engine.execute_hunt(query)
    assert results == []

    # Verify table remains intact
    cursor = db.connection.execute("SELECT COUNT(*) FROM alerts;")
    assert cursor.fetchone()[0] == 3


def test_sql_injection_in_contains_value(hunting_setup):
    """Verify contains operator safely wraps injection payload inside LIKE parameter."""
    engine = hunting_setup["engine"]

    query = 'CommandLine contains "\' UNION SELECT * FROM alerts; --"'
    sql, params = engine.translate_kql_to_sql(query)

    assert "UNION SELECT" not in sql
    expected_like = "%' UNION SELECT * FROM alerts; --%"
    assert params == [expected_like, 500]
    assert "LIKE ?" in sql


def test_sql_injection_in_field_identifier(hunting_setup):
    """Verify SQL injection attempted in the field name raises KQLParseError."""
    engine = hunting_setup["engine"]

    bad_queries = [
        "id' OR 1=1; -- == 'val'",
        "alerts.id; DROP TABLE alerts; -- == 'val'",
        "user\" == 'admin'",
        "field name with spaces == 'val'",
    ]

    for q in bad_queries:
        with pytest.raises(KQLParseError):
            engine.translate_kql_to_sql(q)


# =====================================================================
# 2. Malformed Hunting Filter Tests
# =====================================================================


def test_malformed_unbalanced_quotes(hunting_setup):
    """Verify unterminated string literals raise KQLParseError."""
    engine = hunting_setup["engine"]

    with pytest.raises(KQLParseError, match="Unterminated"):
        engine.translate_kql_to_sql('event_type == "unclosed string')

    with pytest.raises(KQLParseError, match="Unterminated"):
        engine.translate_kql_to_sql("user == 'single quote unclosed")


def test_malformed_random_strings(hunting_setup):
    """Verify random words without valid comparison operators raise KQLParseError."""
    engine = hunting_setup["engine"]

    with pytest.raises(KQLParseError):
        engine.translate_kql_to_sql("SELECT * FROM alerts")

    with pytest.raises(KQLParseError):
        engine.translate_kql_to_sql("random gibberish without syntax")


def test_malformed_unsupported_operators(hunting_setup):
    """Verify unsupported operators (e.g., MATCHES, REGEX) raise KQLParseError."""
    engine = hunting_setup["engine"]

    with pytest.raises(KQLParseError, match="Expected comparison operator"):
        engine.translate_kql_to_sql('event_type MATCHES "ProcessCreate"')


def test_malformed_trailing_and_consecutive_conjunctions(hunting_setup):
    """Verify trailing and consecutive AND/OR tokens raise KQLParseError."""
    engine = hunting_setup["engine"]

    with pytest.raises(KQLParseError, match="Trailing conjunction"):
        engine.translate_kql_to_sql('event_type == "ProcessCreate" AND')

    with pytest.raises(KQLParseError, match="Expected field identifier"):
        engine.translate_kql_to_sql('event_type == "ProcessCreate" AND OR User == "SYSTEM"')


def test_malformed_empty_query(hunting_setup):
    """Verify empty or whitespace-only queries raise KQLParseError."""
    engine = hunting_setup["engine"]

    with pytest.raises(KQLParseError, match="cannot be empty"):
        engine.translate_kql_to_sql("   ")

    with pytest.raises(KQLParseError, match="cannot be empty"):
        engine.translate_kql_to_sql("")


# =====================================================================
# 3. Deep JSON Telemetry Hunting Tests
# =====================================================================


def test_deep_json_hunting_nested_path(hunting_setup):
    """Verify nested JSON search using dot-notation: Network.DestinationIp."""
    engine = hunting_setup["engine"]

    query = 'Network.DestinationIp == "198.51.100.55"'
    sql, params = engine.translate_kql_to_sql(query)

    assert "json_extract(original_record, '$.Network.DestinationIp') = ?" in sql
    assert params == ["198.51.100.55", 500]

    results = engine.execute_hunt(query)
    assert len(results) == 1
    assert results[0].event_type == "NetworkConnect"
    assert results[0].original_record["Network"]["DestinationIp"] == "198.51.100.55"


def test_deep_json_hunting_numeric_comparison(hunting_setup):
    """Verify numeric comparisons on extracted JSON attributes."""
    engine = hunting_setup["engine"]

    # Numeric port lookup
    query = "Network.DestinationPort == 443"
    results = engine.execute_hunt(query)
    assert len(results) == 1
    assert results[0].event_type == "NetworkConnect"


def test_deep_json_hunting_contains_powershell(hunting_setup):
    """Verify contains operator searching within CommandLine attribute."""
    engine = hunting_setup["engine"]

    query = 'CommandLine contains "mimikatz"'
    results = engine.execute_hunt(query)
    assert len(results) == 1
    assert results[0].event_type == "ProcessCreate"
    assert "mimikatz" in results[0].original_record["CommandLine"]


def test_compound_kql_query_direct_and_nested_fields(hunting_setup):
    """Verify compound queries combining direct table columns and nested JSON."""
    engine = hunting_setup["engine"]

    query = 'event_type == "ProcessCreate" AND User == "SYSTEM"'
    results = engine.execute_hunt(query)
    assert len(results) == 1
    assert results[0].event_type == "ProcessCreate"

    query_or = 'User == "alice" OR Network.DestinationIp == "198.51.100.55"'
    results_or = engine.execute_hunt(query_or)
    assert len(results_or) == 2


def test_not_equals_operator(hunting_setup):
    """Verify != operator filters out target rows."""
    engine = hunting_setup["engine"]

    query = 'event_type != "ProcessCreate"'
    results = engine.execute_hunt(query)
    assert len(results) == 2
    assert all(r.event_type != "ProcessCreate" for r in results)


# =====================================================================
# 4. REST API Integration Tests (POST /api/hunt)
# =====================================================================


def test_api_hunt_endpoint_success(hunting_setup):
    """Verify POST /api/hunt returns matching alerts for a valid hunting filter."""
    client = hunting_setup["client"]

    response = client.post(
        "/api/hunt",
        json={"query": 'CommandLine contains "powershell"'},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["event_type"] == "ProcessCreate"


def test_api_hunt_endpoint_malformed_returns_400(hunting_setup):
    """Verify POST /api/hunt returns HTTP 400 with a descriptive filter error."""
    client = hunting_setup["client"]

    response = client.post(
        "/api/hunt",
        json={"query": 'event_type == "unclosed string'},
    )
    assert response.status_code == 400
    assert "KQL-style hunting filter error" in response.json()["detail"]


def test_api_hunt_endpoint_injection_payload_handled_safely(hunting_setup):
    """Verify POST /api/hunt handles injection payloads without server or DB error."""
    client = hunting_setup["client"]

    response = client.post(
        "/api/hunt",
        json={"query": 'event_type == "\'; DROP TABLE alerts; --"'},
    )
    assert response.status_code == 200
    assert response.json() == []


# =====================================================================
# 5. Hunting Filter Row Limit & Query Hardening Tests
# =====================================================================


def test_kql_sql_translation_enforces_default_limit(hunting_setup):
    """Verify translate_kql_to_sql appends parameterized LIMIT clause with default 500."""
    engine = hunting_setup["engine"]
    sql, params = engine.translate_kql_to_sql('event_type == "ProcessCreate"')
    assert "LIMIT ?" in sql
    assert 500 in params


def test_kql_custom_limit_enforced_and_capped(hunting_setup):
    """Verify custom limit argument is respected in translation and capped at 1000."""
    engine = hunting_setup["engine"]
    sql, params = engine.translate_kql_to_sql('event_type == "ProcessCreate"', limit=2)
    assert "LIMIT ?" in sql
    assert 2 in params

    # Exceeding MAX_LIMIT is capped
    sql_max, params_max = engine.translate_kql_to_sql('event_type == "ProcessCreate"', limit=50000)
    assert 1000 in params_max


def test_kql_execution_respects_limit(hunting_setup):
    """Verify execute_hunt truncates returned results at the limit."""
    engine = hunting_setup["engine"]
    # hunting_setup has 3 alerts, limit=1 must return exactly 1
    results = engine.execute_hunt('event_type != "NonExistent"', limit=1)
    assert len(results) == 1

