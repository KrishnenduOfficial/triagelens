"""Private standalone worker; launched only inside yara_windows containment.

No project imports, sample paths, logging, native rule deserialization or provider
clients. stdout is bounded JSON, not compiler exception text or matched bytes.
"""

import base64
import hashlib
import json
import re
import sys


def emit(value):
    sys.stdout.write(json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n')
    sys.stdout.flush()


def execute(request):
    import yara_x

    sources, limits = request['sources'], request['limits']
    data = base64.b64decode(request['data'], validate=True)
    if len(data) > limits['file_bytes']:
        return {'status': 'worker_failure'}
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)
    compiler.max_warnings(30)
    required = {
        'id': r'^[A-Za-z0-9_.:-]{1,128}$',
        'author': r'^[^\x00-\x1f]{1,256}$',
        'source': r'^https://[^\s]{1,240}$',
        'revision': r'^[^\x00-\x1f]{1,256}$',
        'license': r'^[^\x00-\x1f]{1,256}$',
    }
    for name, pattern in required.items():
        compiler.allowed_metadata(name, yara_x.MetaType.STRING, required=True,
                                  error=True, regexp=pattern)
    compiler.allowed_metadata('mitre_attack', yara_x.MetaType.STRING, error=True,
                              regexp=r'^[^\x00-\x1f]{1,256}$')
    for index, source in enumerate(sources):
        text = source['text']
        if (re.search(r'\b(?:include|import)\b', text)
                or len(re.findall(r'\brule\b', text)) != 1
                or hashlib.sha256(text.encode()).hexdigest() != source['digest']):
            return {'status': 'compile_error', 'diagnostics': [{'category': 'invalid_source', 'source': index}]}
        compiler.new_namespace(source['namespace'])
        try:
            compiler.add_source(text, origin=str(index))
        except yara_x.CompileError:
            diagnostics = []
            for error in compiler.errors()[:30]:
                code = error.get('code', '')
                category = code if re.fullmatch(r'[A-Za-z0-9_]{1,64}', code) else 'compile_error'
                line = None
                for label in error.get('labels', []):
                    offset = label.get('span', {}).get('start')
                    if type(offset) is int and 0 <= offset <= len(text.encode()):
                        line = text.encode()[:offset].count(b'\n') + 1
                        break
                diagnostics.append({'category': category, 'source': index, 'line': line})
            return {'status': 'compile_error', 'diagnostics': diagnostics or [{'category': 'compile_error', 'source': index}]}
    rules = compiler.build()
    if rules.imports():
        return {'status': 'compile_error', 'diagnostics': [{'category': 'module_import'}]}
    # Inspect every compiled rule, including non-matching/private rules. A bad
    # rule pack cannot become an apparently successful no-match scan.
    compiled_rules = list(rules)
    if len(compiled_rules) != len(sources) or sum(len(r.patterns) for r in compiled_rules) > 10_000:
        return {'status': 'compile_error', 'diagnostics': [{'category': 'rule_limits'}]}
    for index, rule in enumerate(compiled_rules):
        metadata = dict(rule.metadata)
        if (len(metadata) != len(rule.metadata) or set(metadata) - set(required) - {'mitre_attack'}
                or not set(required).issubset(metadata)
                or any(not isinstance(v, str) or not v.strip() or len(v) > 256
                       or any(ord(c) < 32 for c in v) for v in metadata.values())):
            return {'status': 'compile_error', 'diagnostics': [{'category': 'invalid_metadata', 'source': index}]}
    emit({'phase': 'compiled'})
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(limits['scan_seconds'])
    # Request one sentinel occurrence to detect engine-level truncation.
    scanner.max_matches_per_pattern(limits['occurrences_per_pattern'] + 1)
    try:
        result = scanner.scan(data)
    except yara_x.TimeoutError:
        return {'status': 'timeout', 'diagnostics': [{'category': 'scan_timeout'}]}
    matches, count, truncated = [], 0, False
    by_namespace = {s['namespace']: s for s in sources}
    for rule in result.matching_rules:
        occurrences = []
        for pattern in rule.patterns:
            items = pattern.matches
            if len(items) > limits['occurrences_per_pattern']:
                truncated = True
            for item in items[:limits['occurrences_per_pattern']]:
                if count >= limits['occurrences_per_file']:
                    truncated = True
                    break
                occurrences.append({'pattern': pattern.identifier, 'offset': item.offset,
                                    'length': item.length})
                count += 1
        metadata = dict(rule.metadata)
        if len(metadata) != len(rule.metadata):
            return {'status': 'compile_error', 'diagnostics': [{'category': 'duplicate_metadata'}]}
        matches.append({'namespace': rule.namespace, 'rule': rule.identifier,
                        'source_digest': by_namespace[rule.namespace]['digest'],
                        'metadata': metadata, 'occurrences': occurrences})
    output = {'status': 'truncated' if truncated else ('match' if matches else 'no_match'),
              'matches': matches}
    # Drop whole matches rather than clipping JSON or pretending completeness.
    while len(json.dumps(output, ensure_ascii=True, separators=(',', ':')).encode()) > limits['response_bytes']:
        output['status'] = 'truncated'
        if not output['matches']:
            return {'status': 'truncated'}
        output['matches'].pop()
    return output


def main():
    try:
        raw = sys.stdin.buffer.read(24 * 1024 * 1024 + 1)
        if len(raw) > 24 * 1024 * 1024:
            raise ValueError()
        result = execute(json.loads(raw))
    except MemoryError:
        result = {'status': 'resource_exhausted', 'diagnostics': [{'category': 'memory_limit'}]}
    except BaseException:
        # Never serialize an exception: YARA diagnostics can contain sample/rule
        # bytes, source snippets and private paths.
        result = {'status': 'worker_failure', 'diagnostics': [{'category': 'worker_error'}]}
    emit({'result': result})


if __name__ == '__main__':
    main()
