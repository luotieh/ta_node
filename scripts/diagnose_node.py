#!/usr/bin/env python3
"""Read-only ta_node diagnostics; Python 3 standard library only.

Run on the node: python3 diagnose_node.py --base-dir /opt/ta_node
Use --pid for non-systemd installs; --db overrides the database path.
Output excludes API keys, tokens, raw packet contents and HTTP error bodies.
"""
import argparse
import collections
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.request


def fetch(base, endpoint):
    # Do not send localhost diagnostics through environment-configured proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base.rstrip('/') + endpoint, timeout=5) as response:
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024:
        raise ValueError('API response exceeds 4 MiB')
    return json.loads(body)


def utc(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat() if value else None


def queue_report(path, sample, max_retry, sources):
    # mode=ro prevents accidental database creation or event/status changes.
    conn = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        conn.execute('PRAGMA query_only=ON')
        probe = conn.execute("SELECT json_extract(payload, '$._ta_storage') FROM event_queue ORDER BY id DESC LIMIT 1").fetchone()
        if probe and probe[0] == 2:
            raise ValueError('This database uses lossless storage v2. Use ta_queue --inspect --source PATH or the node storage/summary APIs; raw SQL JSON extraction cannot resolve evidence references.')
        deadline = time.monotonic() + 15
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        result = {'path': str(path.resolve()), 'file_bytes': path.stat().st_size,
                  'sample_limit': sample, 'scope': 'newest queue rows, including context revisions'}
        rows = conn.execute('''
            SELECT id, event_time, status, retry_count,
                   json_extract(payload, '$.event_id'),
                   json_extract(payload, '$.src_ip'),
                   json_extract(payload, '$.dst_ip'),
                   json_extract(payload, '$.ioc_type'),
                   json_extract(payload, '$.ioc_value'), created_at,
                   json_extract(payload, '$.src_port'), json_extract(payload, '$.dst_port'),
                   json_extract(payload, '$.proto')
            FROM event_queue ORDER BY id DESC LIMIT ?''', (sample,)).fetchall()
        statuses = {0: 'pending', 2: 'pushed', 3: 'failed'}
        counts = collections.Counter()
        unique = collections.defaultdict(set)
        pairs = collections.Counter()
        indicators = collections.Counter()
        times = []
        exhausted = 0
        for rowid, event_time, status, retries, eid, src, dst, kind, value, created, sport, dport, proto in rows:
            label = statuses.get(status, str(status))
            counts[label] += 1
            unique[src].add(eid or str(rowid))
            pairs[(src, dst, label, sport, dport, proto)] += 1
            indicators[(kind, value)] += 1
            times.append(event_time / 1_000_000 if event_time else (created or 0))
            if max_retry is not None and max_retry > 0 and status in (0, 3) and retries >= max_retry:
                exhausted += 1
        result.update(sample_rows=len(rows), sample_status_rows=dict(counts),
                      sample_distinct_sources=len(unique), sample_retry_exhausted_rows=exhausted,
                      oldest_occurrence_utc=utc(min(times)) if times else None,
                      newest_occurrence_utc=utc(max(times)) if times else None,
                      top_sources=[{'src_ip': src, 'unique_events': len(ids)}
                                   for src, ids in sorted(unique.items(), key=lambda p: -len(p[1]))[:30]],
                      top_pairs=[{'src_ip': k[0], 'dst_ip': k[1], 'status': k[2],
                                  'src_port': k[3], 'dst_port': k[4], 'proto': k[5], 'rows': n}
                                 for k, n in pairs.most_common(30)],
                      top_iocs=[{'type': k[0], 'value': k[1], 'rows': n}
                                for k, n in indicators.most_common(20)],
                      requested_sources=[{'ip': src, 'unique_events_as_source': len(unique.get(src, ())),
                                          'rows_as_destination': sum(n for k, n in pairs.items() if k[1] == src)}
                                         for src in sources])
        if max_retry is not None:
            # Mirrors the worker's selection, but returns only metadata.
            front = conn.execute('''SELECT id,status,retry_count,
                json_extract(payload,'$.src_ip'), json_extract(payload,'$.dst_ip'),event_time
                FROM event_queue WHERE status IN (0,3) AND (? <= 0 OR retry_count < ?)
                ORDER BY id LIMIT 100''', (max_retry, max_retry)).fetchall()
            result['next_100_eligible_rows'] = [dict(zip(
                ('id', 'status', 'retry_count', 'src_ip', 'dst_ip', 'event_time_usec'), row)) for row in front]
        else:
            result['retry_note'] = 'Retry cap unknown; use --max-retry to inspect the worker queue head.'
        return result
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--api', default='http://127.0.0.1:19090')
    p.add_argument('--base-dir', help='Node process working directory, NOT the config directory')
    p.add_argument('--pid', type=int, help='Running ta_node PID; otherwise try systemd')
    p.add_argument('--db', help='Actual queue DB; relative paths use the node working directory')
    p.add_argument('--max-retry', type=int, help='Actual running retry cap, 0 means unlimited')
    p.add_argument('--sample', type=int, default=20000)
    p.add_argument('--source', action='append', default=[], help='Full IP to locate; may be repeated')
    args = p.parse_args()
    if not 1 <= args.sample <= 100000:
        p.error('--sample must be between 1 and 100000')
    report = {'generated_at_utc': utc(time.time()), 'errors': [],
              'notes': ['Queue source IP is the packet sender, not necessarily the malicious endpoint.',
                        'No row in a bounded sample does not prove no traffic was captured.',
                        'API config can contain saved settings awaiting restart; compare startup logs.']}
    pid = args.pid
    if not pid and os.name == 'posix':
        try:
            proc = subprocess.run(['systemctl', 'show', 'ta_node', '--property=MainPID', '--value'],
                                  capture_output=True, text=True, timeout=3)
            pid = int(proc.stdout.strip()) or None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    base = Path(args.base_dir).resolve() if args.base_dir else None
    if pid:
        try:
            cwd = Path('/proc/{}/cwd'.format(pid)).resolve(strict=True)
            report['process'] = {'pid': pid, 'cwd': str(cwd)}
            base = base or cwd
        except OSError as exc:
            report['errors'].append('Process directory: ' + str(exc))
    cfg = {}
    for name, endpoint in [('health', '/api/v1/health'), ('intel_stats', '/api/v1/intel/stats'),
                           ('config', '/api/v1/config')]:
        try:
            data = fetch(args.api, endpoint)
            if name == 'config':
                cfg = data['config']
                report['config_path'] = data.get('path')
                report['settings'] = {k: cfg.get(k, {}) for k in ('capture', 'patterns', 'intel', 'event', 'aggregation')}
                report['device_id'] = cfg.get('node', {}).get('device_id')
            else:
                report[name] = data
        except Exception as exc:
            report['errors'].append(name + ': ' + str(exc))
    db = args.db or cfg.get('event', {}).get('queue_db')
    cap = args.max_retry if args.max_retry is not None else cfg.get('event', {}).get('max_push_retry')
    if db:
        path = Path(db)
        if not path.is_absolute() and base is None:
            report['errors'].append('Relative DB path requires --base-dir or readable /proc/PID/cwd.')
        else:
            path = path if path.is_absolute() else base / path
            try:
                report['queue'] = queue_report(path, args.sample, cap, args.source)
            except (OSError, sqlite3.Error, ValueError) as exc:
                report['errors'].append('queue: ' + str(exc))
    else:
        report['errors'].append('Queue path unavailable; supply --db with the actual database path.')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
