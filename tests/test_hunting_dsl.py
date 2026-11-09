"""Offline grammar, execution deadlines, persistence and independent differential tests."""

from datetime import datetime, timedelta, timezone
import json
import random
import sqlite3
import threading

from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.hunting import HuntTimeoutError, KQLParseError, ThreatHuntingEngine
from src.engine.hunting_dsl import Comparison, Logical, parse_query
from src.models.alert import GroundTruthMetadata, NormalizedAlert


@pytest.fixture
def db():
    manager = DatabaseManager()
    manager.init_db()
    yield manager
    manager.close()


def add(db, record, event_type="Event", **kwargs):
    alert = NormalizedAlert(source_dataset="synthetic", source_file="synthetic.json",
                            event_type=event_type, original_record=record, **kwargs)
    db.insert_alert(alert)
    return alert


def test_ast_precedence_and_parentheses(db):
    tree = parse_query('a == 1 OR b == 2 AND NOT (c == 3 OR d == 4)')
    assert isinstance(tree, Logical) and tree.operator == "OR"
    assert isinstance(tree.children[0], Comparison)
    assert tree.children[1].operator == "AND"
    assert tree.children[1].children[1].operator == "NOT"
    engine = ThreatHuntingEngine(db)
    a = add(db, {"a": 1, "b": 0, "c": 3, "d": 4})
    b = add(db, {"a": 0, "b": 2, "c": 0, "d": 0})
    add(db, {"a": 0, "b": 2, "c": 3, "d": 0})
    assert {r.internal_id for r in engine.execute_hunt(
        'a == 1 OR b == 2 AND NOT (c == 3 OR d == 4)')} == {a.internal_id, b.internal_id}
    assert engine.execute_hunt('(a == 1 OR b == 2) AND c == 0')[0].internal_id == b.internal_id


def test_nesting_boundaries_and_full_consumption(db):
    add(db, {"a": 1})
    engine = ThreatHuntingEngine(db)
    assert len(engine.execute_hunt('(' * 32 + 'a==1' + ')' * 32)) == 1
    assert len(engine.execute_hunt('NOT ' * 32 + 'a==1')) == 1
    # Both AND and OR add syntax tree nodes at each parenthesis level.
    query = 'a==1'
    for _ in range(30):
        query = f'(a==1 OR a==1 AND {query})'
    assert len(engine.execute_hunt(query)) == 1
    assert parse_query('123 == 1').field == '123'


@pytest.mark.parametrize("query", [
    "", "   ", 'a == "unterminated', 'a == 1; SELECT 1', 'a == 1 -- comment',
    'a == 1 /* comment */', 'a == 1 | take 1', 'a[0] == 1', 'a..b == 1',
    'a == 1 garbage', 'a == 1 AND', 'a == 1 OR OR b == 2', 'NOT', '()',
    '(a == 1', 'a == 1)', 'a = 1', 'a =~ "A"', 'a regex "x"', 'a == null',
    'a contains 1', 'a !contains true', 'a == 9223372036854775808',
    'a == -9223372036854775809', 'a == "' + 'x' * 2000 + '"',
    '(' * 34 + 'a == 1' + ')' * 34, 'NOT ' * 34 + 'a == 1',
    ' OR '.join('a == 1' for _ in range(130)),
])
def test_reject_invalid_or_excessive_queries(query):
    with pytest.raises(KQLParseError):
        parse_query(query)


@pytest.mark.parametrize("query,value", [
    (r'''a == "C:\Windows\Temp"''', r"C:\Windows\Temp"),
    (r'''a == "C:\\Windows\\Temp"''', r"C:\Windows\Temp"),
    (r'''a == 'it\'s "quoted"' ''', 'it\'s "quoted"'),
    (r'''a == "line\ntext"''', r"line\ntext"),
    ('a == unquoted.word', 'unquoted.word'),
    ('a == -1.25', -1.25), ('a == TRUE', True), ('a == false', False),
])
def test_literals(query, value):
    assert parse_query(query).value == value


@pytest.mark.parametrize("needle", ["%", "_", "\\", "100%_\\", "", "ABC", "é"])
def test_literal_contains_and_negation(db, needle):
    text = "Abc100%_\\é"
    add(db, {"text": text})
    add(db, {})
    engine = ThreatHuntingEngine(db)
    encoded = json.dumps(needle, ensure_ascii=False)
    matches = bool(engine.execute_hunt(f'text contains {encoded}'))
    assert matches == (_ascii_lower(needle) in _ascii_lower(text))
    assert bool(engine.execute_hunt(f'text !contains {encoded}')) is not matches
    assert len(engine.execute_hunt(f'NOT text contains {encoded}')) == int(not matches)


def test_types_null_missing_containers_and_case(db):
    numeric = add(db, {"value": 1, "text": "ÉA"})
    string = add(db, {"value": "1", "text": "éa"})
    boolean = add(db, {"value": True})
    for value in [None, {}, [], [1]]:
        add(db, {"value": value})
    add(db, {})
    engine = ThreatHuntingEngine(db)
    ids = lambda q: {a.internal_id for a in engine.execute_hunt(q)}
    assert ids('value == 1') == {numeric.internal_id, boolean.internal_id}
    assert ids('value == "1"') == {string.internal_id}
    assert ids('value != 1') == set()
    assert ids('NOT value == 1') == set()
    assert ids('value == 1 OR value == "1"') == {numeric.internal_id, string.internal_id, boolean.internal_id}
    assert ids('text contains "é"') == {string.internal_id}
    assert ids('text == "ÉA"') == {numeric.internal_id}
    assert ids('event_type == 1') == set()
    assert ids('original_record.value == 1') == set()


def test_json_paths_direct_aliases_and_metadata_preservation(db):
    metadata = GroundTruthMetadata(relative_path="dataset/file", status="mapped",
                                  label_sources={"review": "benign"})
    alert = add(db, {"Event": {"Data": {"4624": 12}}, "event_type": "raw"},
                ground_truth_metadata=metadata, ground_truth_label="benign")
    engine = ThreatHuntingEngine(db)
    assert len(engine.execute_hunt('Event.Data.4624 == 12 AND EVENT_TYPE == "Event"')) == 1
    assert engine.execute_hunt('Event.data.4624 == 12') == []
    match = engine.execute_hunt(f'internal_id == "{alert.internal_id}"')[0]
    assert match.ground_truth_metadata == metadata
    assert match.ground_truth_label == "benign"
    assert engine.execute_hunt('event_type == "raw"') == []


def test_dialect_interface_is_used_without_executing_another_backend(db):
    class RecordingDialect:
        def comparison(self, node, params):
            params.append(node.value)
            return f"test_field = ${len(params)}"

        def select(self, predicate):
            return f"SELECT test WHERE {predicate} LIMIT $2"

    sql, params = ThreatHuntingEngine(db, dialect=RecordingDialect()).translate_kql_to_sql('x == 2')
    assert sql == "SELECT test WHERE test_field = $1 LIMIT $2"
    assert params == [2, 500]


def test_injection_and_invalid_limits_never_become_sql(db, caplog):
    engine = ThreatHuntingEngine(db)
    payload = "'; DROP TABLE alerts; --"
    sql, params = engine.translate_kql_to_sql('User == ' + json.dumps(payload))
    assert payload not in sql and params == [payload, 500]
    with caplog.at_level("INFO"):
        assert engine.execute_hunt('User == ' + json.dumps(payload)) == []
    assert payload not in caplog.text
    assert db.connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    for limit in [True, "1", 1.5]:
        with pytest.raises(KQLParseError):
            engine.execute_hunt('a == 1', limit)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), 31])
def test_invalid_timeout(db, timeout):
    with pytest.raises(ValueError):
        ThreatHuntingEngine(db, timeout=timeout)


def test_execution_deadline_interrupts_and_restores_connection(db):
    for i in range(40):
        add(db, {"number": i})

    class Clock:
        calls = 0

        def __call__(self):
            self.calls += 1
            return 0 if self.calls < 4 else 3

    clock = Clock()
    busy_timeout = db.connection.execute("PRAGMA busy_timeout").fetchone()[0]
    engine = ThreatHuntingEngine(db, clock=clock)
    with pytest.raises(HuntTimeoutError):
        engine.execute_hunt('number >= 0')
    assert clock.calls >= 4  # A real SQLite progress callback crossed the deadline.
    assert db.connection.execute("PRAGMA busy_timeout").fetchone()[0] == busy_timeout
    assert db.connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 40
    # More than 100 VM instructions would hit a leaked, already-expired handler.
    assert db.connection.execute("""WITH RECURSIVE n(x) AS (
        VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<500)
        SELECT sum(x) FROM n""").fetchone()[0] == 125250
    assert len(ThreatHuntingEngine(db).execute_hunt('number >= 0')) == 40


def test_deadline_before_sql_and_lock_wait(db):
    values = iter([0, 3])
    with pytest.raises(HuntTimeoutError):
        ThreatHuntingEngine(db, clock=lambda: next(values)).execute_hunt('a == 1')
    ready, release = threading.Event(), threading.Event()

    def hold_lock():
        with db._lock:
            ready.set()
            release.wait(5)

    worker = threading.Thread(target=hold_lock)
    worker.start()
    try:
        assert ready.wait(2)
        with pytest.raises(HuntTimeoutError):
            ThreatHuntingEngine(db, timeout=0.01).execute_hunt('a == 1')
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()


def test_sql_error_also_cleans_up_progress_handler(db):
    add(db, {})
    db.connection.execute("UPDATE alerts SET original_record = 'invalid json'")
    with pytest.raises(sqlite3.OperationalError):
        ThreatHuntingEngine(db).execute_hunt('a == 1')
    assert db.connection.execute("PRAGMA busy_timeout").fetchone()[0] == 60000
    assert db.connection.execute("SELECT 1").fetchone()[0] == 1


def test_short_query_post_fetch_timeout_withholds_rows(db):
    add(db, {"a": 1})
    values = iter([0, 0, 3])
    with pytest.raises(HuntTimeoutError):
        ThreatHuntingEngine(db, clock=lambda: next(values)).execute_hunt('a == 1')
    assert len(ThreatHuntingEngine(db).execute_hunt('a == 1')) == 1


def test_row_cap_and_stable_order_for_tied_timestamps(db):
    for _ in range(1005):
        add(db, {})
    ids = sorted(row['id'] for row in db.connection.execute('SELECT id FROM alerts'))
    engine = ThreatHuntingEngine(db)
    assert [str(a.internal_id) for a in engine.execute_hunt('event_type == "Event"', 50000)] == ids[:1000]
    assert len(engine.execute_hunt('event_type == "Event"', 0)) == 500


def test_api_timeout_is_safe_and_parentheses_work(db, monkeypatch):
    add(db, {"a": 1})
    client = TestClient(create_app(db=db))
    assert len(client.post('/api/hunt', json={"query": '(a == 1)'}).json()) == 1

    def timeout(*args, **kwargs):
        raise HuntTimeoutError("private SQL or path must not escape")

    monkeypatch.setattr(ThreatHuntingEngine, "execute_hunt", timeout)
    response = client.post('/api/hunt', json={"query": 'a == 1'})
    assert response.status_code == 408
    assert response.json() == {"detail": "Hunting filter execution timed out. Narrow the filter and retry."}


def test_saved_queries_persist_upsert_validate_and_delete(tmp_path):
    path = str(tmp_path / 'hunting.sqlite')
    db = DatabaseManager(path)
    db.init_db()
    engine = ThreatHuntingEngine(db)
    alert = add(db, {"a": 1})
    name = "owner's query; --"
    saved = engine.save_query(name, 'a == 1')
    assert engine.execute_saved_query(name)[0].internal_id == alert.internal_id
    assert engine.list_saved_queries() == [saved]
    updated = engine.save_query(name, 'a == 2')
    assert updated['created_at'] == saved['created_at']
    assert engine.execute_saved_query(name) == []
    with pytest.raises(KQLParseError):
        engine.save_query(name, 'DROP TABLE alerts')
    for bad in ['', ' ', 'x' * 101]:
        with pytest.raises(KQLParseError):
            engine.save_query(bad, 'a == 1')
    db.close()
    db = DatabaseManager(path)
    db.init_db()  # Idempotent additive migration on an existing database.
    engine = ThreatHuntingEngine(db)
    assert engine.list_saved_queries() == [updated]
    assert engine.delete_saved_query(name) is True
    assert engine.delete_saved_query(name) is False
    with pytest.raises(KQLParseError, match='does not exist'):
        engine.execute_saved_query(name)
    assert db.connection.execute('SELECT count(*) FROM alerts').fetchone()[0] == 1
    for table in ['verdicts', 'evaluations']:
        assert db.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0
    db.close()


def _ascii_lower(text):
    return text.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def _evaluate(expression, row):
    """Independent test oracle over generator tuples, never production AST or SQL."""
    op, *parts = expression
    if op == 'not':
        result = _evaluate(parts[0], row)
        return None if result is None else not result
    if op in {'and', 'or'}:
        left, right = (_evaluate(child, row) for child in parts)
        if op == 'and':
            return False if left is False or right is False else None if left is None or right is None else True
        return True if left is True or right is True else None if left is None or right is None else False
    field, expected = parts
    actual = row.get(field) if field in {'event_type', 'source_file', 'timestamp'} else row['original_record']
    if field not in {'event_type', 'source_file', 'timestamp'}:
        for segment in field.split('.'):
            actual = actual.get(segment) if isinstance(actual, dict) else None
    if isinstance(expected, str):
        if not isinstance(actual, str):
            return None
    elif not isinstance(actual, (int, float)):
        return None
    if op == 'contains':
        return _ascii_lower(expected) in _ascii_lower(actual)
    if op == '!contains':
        return _ascii_lower(expected) not in _ascii_lower(actual)
    if op == '==':
        return actual == expected
    if op == '!=':
        return actual != expected
    if op == '>':
        return actual > expected
    if op == '<':
        return actual < expected
    if op == '>=':
        return actual >= expected
    if op == '<=':
        return actual <= expected
    raise AssertionError(op)


def _render(expression):
    op, *parts = expression
    if op == 'not':
        return f'NOT ({_render(parts[0])})'
    if op in {'and', 'or'}:
        return f'({_render(parts[0])} {op.upper()} {_render(parts[1])})'
    field, value = parts
    return f'{field} {op} {json.dumps(value, ensure_ascii=False)}'


@pytest.mark.parametrize('seed', [17, 49, 123, 909])
def test_random_queries_match_independent_python_evaluator(db, seed):
    rng = random.Random(seed)
    values = ['Alpha', 'alpha', 'Éclair', 'éclair', '100%_\\', '', '1', 'false',
              -2, 0, 1, 1.5, 10, True, False, None, [], {'x': 1}]
    rows = []
    for i in range(80):
        record = {name: rng.choice(values) for name in ['a', 'b'] if rng.random() > 0.2}
        if rng.random() > 0.2:
            record['nested'] = {'value': rng.choice(values)}
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i // 3)
        alert = add(db, record, rng.choice(['Alpha', 'Other']), timestamp=ts)
        rows.append({'id': str(alert.internal_id), 'timestamp': ts.isoformat(),
                     'event_type': alert.event_type, 'source_file': alert.source_file,
                     'original_record': record})
    rows.sort(key=lambda r: (r['timestamp'], r['id']))

    def generate(depth=0):
        if depth < 3 and rng.random() < 0.5:
            op = rng.choice(['and', 'or', 'not'])
            return (op, generate(depth + 1)) if op == 'not' else (op, generate(depth + 1), generate(depth + 1))
        field = rng.choice(['a', 'b', 'nested.value', 'missing', 'event_type', 'source_file', 'timestamp'])
        value = rng.choice(values[:15])
        operators = ['==', '!=', '>', '<', '>=', '<=']
        if isinstance(value, str):
            operators += ['contains', '!contains']
        return rng.choice(operators), field, value

    engine = ThreatHuntingEngine(db)
    for _ in range(200):
        expression = generate()
        query = _render(expression)
        limit = rng.choice([1, 3, 20, 500, 50000])
        expected = [row['id'] for row in rows if _evaluate(expression, row) is True][:min(limit, 1000)]
        actual = [str(row.internal_id) for row in engine.execute_hunt(query, limit)]
        assert actual == expected, (seed, query)
