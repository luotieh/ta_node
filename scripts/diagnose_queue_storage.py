#!/usr/bin/env python3
"""Read-only, bounded storage inspection of a ta_node event_queue database.

python3 diagnose_queue_storage.py /data/ta_node-archive/event_queue.db.archived
Does not delete records, vacuum, checkpoint or contact the management platform.
"""
import argparse
import collections
import json
from pathlib import Path
import sqlite3
import time


def inspect(path, sample=200):
    path = Path(path).resolve(strict=True)
    result = {'path': str(path), 'files_bytes': {}, 'sample_limit': sample,
              'notes': ['Statistics describe newest rows only, not the entire database.',
                        'Archived copies do not necessarily describe the current active queue.',
                        'Free SQLite pages can be reused; they are not automatically returned to the filesystem.']}
    for suffix in ('', '-wal', '-shm', '-journal'):
        file = Path(str(path) + suffix)
        if file.exists():
            result['files_bytes'][file.name] = file.stat().st_size
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        conn.execute('PRAGMA query_only=ON')
        probe = conn.execute("SELECT json_extract(payload, '$._ta_storage') FROM event_queue ORDER BY id DESC LIMIT 1").fetchone()
        if probe and probe[0] == 2:
            raise ValueError('This database uses lossless storage v2. Use ta_queue --inspect --source PATH or the node storage/summary APIs; raw SQL JSON extraction cannot resolve evidence references.')
        deadline = time.monotonic() + 15
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        for name in ('page_size', 'page_count', 'freelist_count', 'journal_mode', 'auto_vacuum'):
            result[name] = conn.execute('PRAGMA ' + name).fetchone()[0]
        result['allocated_page_bytes'] = result['page_size'] * result['page_count']
        result['free_page_bytes'] = result['page_size'] * result['freelist_count']
        rows = conn.execute('''SELECT id,status,retry_count,created_at,
            length(CAST(payload AS BLOB)),json_extract(payload,'$.event_id'),
            json_extract(payload,'$.context_revision'),json_extract(payload,'$.session_id'),
            json_extract(payload,'$.src_ip'),json_extract(payload,'$.dst_ip')
            FROM event_queue ORDER BY id DESC LIMIT ?''', (sample,)).fetchall()
        sizes = sorted(row[4] for row in rows)
        result['sample_rows'] = len(rows)
        if not rows:
            return result
        status_rows = collections.Counter()
        status_bytes = collections.Counter()
        sources = collections.Counter()
        event_rows = collections.Counter()
        for rowid, status, retries, created, size, eid, revision, session, src, dst in rows:
            label = {0: 'pending', 2: 'pushed', 3: 'failed'}.get(status, str(status))
            status_rows[label] += 1
            status_bytes[label] += size
            sources[src] += size
            event_rows[eid or str(rowid)] += 1
        result.update(sample_json_bytes=sum(sizes), sample_avg_json_bytes=sum(sizes) / len(sizes),
                      sample_max_json_bytes=max(sizes), sample_status_rows=dict(status_rows),
                      sample_status_json_bytes=dict(status_bytes),
                      sample_distinct_event_ids=len(event_rows),
                      sample_revision_rows=sum((r[6] or 0) > 1 for r in rows),
                      sample_max_context_revision=max(r[6] or 0 for r in rows),
                      sample_created_at_min=min(r[3] or 0 for r in rows),
                      sample_created_at_max=max(r[3] or 0 for r in rows),
                      sample_top_events=[{'event_id': k, 'rows': n} for k, n in event_rows.most_common(10)],
                      sample_top_sources=[{'src_ip': k, 'json_bytes': n} for k, n in sources.most_common(10)])
        return result
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('db')
    parser.add_argument('--sample', type=int, default=200)
    args = parser.parse_args()
    if not 1 <= args.sample <= 2000:
        parser.error('--sample must be between 1 and 2000')
    try:
        result = inspect(args.db, args.sample)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
