# KQL-style hunting filter DSL

This is a small filter language over stored alerts, not full KQL. It returns
`NormalizedAlert` records through `ThreatHuntingEngine.execute_hunt` or
`POST /api/hunt` with `{"query": "...", "limit": 500}`. Searches run locally;
they make no provider calls. A match is an analyst search result, not an AI
prediction, dataset label, analyst disposition, or persisted rule detection.

## Grammar

```ebnf
query       = or_expr ;
or_expr     = and_expr, { "OR", and_expr } ;
and_expr    = unary, { "AND", unary } ;
unary       = "NOT", unary | "(", or_expr, ")" | comparison ;
comparison  = field, operator, value ;
operator    = "==" | "!=" | ">" | "<" | ">=" | "<=" | "contains" | "!contains" ;
field       = segment, { ".", segment } ;
segment     = ( ASCII_letter | digit | "_" ), { ASCII_letter | digit | "_" } ;
value       = string | number | boolean | bare_word ;
number      = [ "-" ], digit, { digit }, [ ".", digit, { digit } ] ;
boolean     = "true" | "false" ;
bare_word   = segment, { ".", segment } ;
string      = single_quoted | double_quoted ;
```

Whitespace separates words; parentheses and symbolic operators need no spaces.
The entire input must parse. Keywords and word operators are case insensitive.
`NOT` binds most tightly, followed by `AND`, then `OR`; parentheses override this.
`AND`, `OR`, `NOT`, `contains`, and `null` cannot be bare values; quote them.
Numeric-looking values parse as numbers, and true/false as booleans; quote them
to search strings. Numeric literals fit signed 64-bit integers or finite floats;
exponents and leading plus signs are not numeric syntax.

Single and double quotes both delimit strings. `\\` represents one backslash,
`\"` represents a double quote, and `\'` represents a single quote. Other
backslash sequences remain literal: `\n` is two characters, and `\u0041` is
six characters. Write Unicode characters directly. This permits Windows paths
such as `Image == "C:\Windows\System32\cmd.exe"`; doubling backslashes also works.
When sending JSON to the API, apply JSON escaping to the complete query as usual.

Examples:

```text
event_type == "ProcessCreate" AND User == "SYSTEM"
Network.DestinationPort >= 443 AND Network.Protocol == tcp
(User == "alice" OR User == "bob") AND NOT CommandLine contains "backup"
CommandLine contains "100%_complete"
```

## Field resolution and comparison semantics

These names resolve to relational columns, case insensitively:

| Name | Stored column |
| --- | --- |
| `id`, `internal_id` | `id` |
| `event_type` | `event_type` |
| `timestamp` | `timestamp` |
| `timeline_id` | `timeline_id` |
| `source_dataset` | `source_dataset` |
| `source_file` | `source_file` |
| `ground_truth_label` | `ground_truth_label` |

All other names resolve relative to `original_record`, with case-sensitive JSON
keys. `Network.DestinationIp` means that nested JSON path; do not prefix it with
`original_record`. Only object paths with the segment syntax above are supported.
Arrays, quoted keys, keys containing dots/hyphens/spaces, and wildcards are unsupported.
The listed source/ground-truth columns remain local search fields; searches do
not transmit them or their matches to the LLM or change independent labels.

Comparisons use explicit operand types. Strings compare only to strings, with
case-sensitive equality and lexical ordering. Numeric values compare only to
numbers, including JSON booleans (true = 1, false = 0). There is no string/number
coercion: JSON `443` differs from `"443"`. Direct columns listed above are text;
numeric comparisons against them produce UNKNOWN. Timestamps compare as stored
ISO text, without date parsing or timezone conversion.

Missing fields, JSON nulls, arrays, objects, and incompatible types produce
UNKNOWN for every comparison, including `!=` and `!contains`. `NOT UNKNOWN`
remains UNKNOWN. `AND` is false if either side is false, true if both are true,
otherwise UNKNOWN; `OR` is true if either is true, false if both are false,
otherwise UNKNOWN. Only TRUE rows are returned. There is no null literal or
existence operator in this version.

`contains` and `!contains` require string literals and string fields. They use
SQLite LIKE's default ASCII case-insensitive matching (Unicode case differences
remain distinct). `%`, `_`, and backslashes are escaped as literal characters.
The empty string is contained in every non-null string. SQLite LIKE stops at
embedded NUL characters; substring searches on such telemetry are outside this
version's supported text domain. Regex, joins, projections, aggregations, pipes,
comments, and arbitrary SQL are unsupported.

## Architecture, limits and errors

`hunting_dsl.py` tokenizes input, builds immutable `Comparison`/`Logical` nodes,
and compiles the tree through the `SQLDialect` interface. `SQLiteDialect` supplies
typed predicates, field expressions and SELECT syntax. Values and the row limit
are bound parameters; validated field paths and allowlisted operators supply SQL
structure. A future PostgreSQL dialect must implement the same semantics and
pass differential checks. No PostgreSQL execution is implemented here.

| Limit | Behavior |
| --- | --- |
| Query length | 1–2000 characters, including engine calls |
| Tokens / comparisons | At most 512 tokens / 128 comparisons |
| Nesting | At most 32 parentheses/NOT levels |
| Returned rows | Default 500; engine caps at 1000 |
| Row ordering | Stored timestamp ascending (null first), then id ascending |
| Execution budget | Default 2 seconds; engine accepts positive values up to 30 seconds |

For compatibility, engine limits of zero/negative use 500; non-integer limits
are rejected. The API instead rejects limits outside 1–1000 with HTTP 422.
Malformed/unsupported/oversized filters raise `KQLParseError` (HTTP 400; API
length validation may return 422 first). Error messages omit query values and
SQL. Query text is not logged by the engine.

The execution budget covers the shared connection lock wait and SQL execution/
fetch. SQLite checks a monotonic deadline every 100 VM instructions, with a
final check after fetch; its busy timeout is temporarily bounded by the remaining
budget. Timeout raises `HuntTimeoutError` (HTTP 408), withholding partial results.
The progress handler is removed and the previous busy timeout restored on success
or failure. This engine owns the progress handler during execution; callers must
not install a competing handler on the shared connection. Parsing and result
deserialization are outside the SQL budget. A single SQLite operation, connection
setup, and OS scheduling can exceed the deadline; this is cooperative cancellation,
not a hard wall-clock guarantee. Row limits do not bound scanning or sorting costs.

## Saved queries and verification

`DatabaseManager.init_db()` adds `saved_hunting_queries` to existing databases.
Definitions contain a unique case-sensitive name (1–100 characters, surrounding
whitespace trimmed), validated query, created-at and updated-at UTC timestamps.
`save_query(name, query)` upserts a definition; `list_saved_queries()` returns up
to 1000 definitions in name order; `delete_saved_query(name)` reports whether one
was removed; `execute_saved_query(name, limit=None)` reparses and executes the
stored definition. Unknown names raise `KQLParseError`. Saving never runs a query
or stores hits. Saved-query HTTP routes and dashboard controls are deferred.

From the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short tests/test_hunting_dsl.py tests/test_hunting_adversarial.py
```

The differential test uses four fixed seeds, 80 synthetic records per seed and
200 random queries per seed (800 query comparisons). An independent plain Python
evaluator works on generator tuples rather than the production AST or SQL. It
checks matched ids, ordering and limits across logical expressions, nested paths,
types, missing data and literal substring characters. These finite tests do not
establish compatibility with full KQL, arbitrary real telemetry, or PostgreSQL.
