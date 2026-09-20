#!/usr/bin/env python3
"""Isolated binary smoke test. No production files or external HTTP requests.

python scripts/verify_storage_v2.py --node PATH --queue-tool PATH
"""
import argparse
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--queue-tool', required=True)
    args = parser.parse_args()
    node, tool = str(Path(args.node).resolve()), str(Path(args.queue_tool).resolve())
    with tempfile.TemporaryDirectory(prefix='ta-storage-smoke-') as tmp:
        root = Path(tmp)
        source, target = root / 'old.db', root / 'new.db'
        conn = sqlite3.connect(source)
        conn.execute('''CREATE TABLE event_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,event_time INTEGER NOT NULL,payload TEXT NOT NULL,
            status INTEGER DEFAULT 0,retry_count INTEGER DEFAULT 0,last_error TEXT,
            created_at INTEGER,updated_at INTEGER)''')
        raw = b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n' * 100
        ev = dict(event_id='smoke', event_time=1700000000000000, context_revision=2,
                  src_ip='192.0.2.10', dst_ip='203.0.113.8',
                  raw_packet=dict(packet_hex=raw.hex(), payload_text=raw.decode()))
        conn.execute('INSERT INTO event_queue VALUES (1,?,?,?,?,?,?,?,?)',
                     ('smoke@revision:2', ev['event_time'], json.dumps(ev), 3, 2,
                      'simulated failure', 1700000000, 1700000001))
        conn.commit()
        conn.close()
        subprocess.run([tool, '--offline', '--source', str(source), '--destination', str(target)], check=True)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        (root / 'intel.yaml').write_text('items: []\n', encoding='utf-8')
        # JSON is valid YAML and avoids any dependency on PyYAML.
        cfg = dict(node=dict(device_id='smoke'), patterns=dict(enable=False),
                   intel=dict(intel_file=str(root / 'intel.yaml'), enable_hot_reload=False,
                              enable_ioc_sync=False, prune_expired_interval_sec=0),
                   event=dict(queue_db=str(target), enable_push=False),
                   storage=dict(backend='v2', archive_dir='', maintenance_interval_sec=60),
                   server=dict(enable=True, listen='127.0.0.1:{}'.format(port), token='smoke-token'))
        config = root / 'node.yaml'
        config.write_text(json.dumps(cfg), encoding='utf-8')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = 'http://127.0.0.1:{}'.format(port)

        def request(path, payload=None, auth=False):
            headers = {'Content-Type': 'application/json'}
            if auth:
                headers['Authorization'] = 'Bearer smoke-token'
            req = urllib.request.Request(base + path, data=json.dumps(payload).encode() if payload else None, headers=headers)
            with opener.open(req, timeout=3) as response:
                return json.load(response)

        with (root / 'node.log').open('wb') as log:
            process = subprocess.Popen([node, '--config', str(config), '--config-only'], cwd=root,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        request('/api/v1/health')
                        break
                    except (OSError, urllib.error.URLError):
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('Node failed to start: ' + (root / 'node.log').read_text(errors='replace'))
                        time.sleep(.1)
                summaries = request('/api/v1/push/logs?summary=1')['items']
                assert summaries[0]['src_ip'] == ev['src_ip']
                assert not summaries[0]['raw_packet']['packet_hex']
                restored = request('/api/v1/push/event?event_id=smoke&revision=2', auth=True)
                assert restored['raw_packet']['packet_hex'] == raw.hex()
                part = request('/api/v1/push/event?event_id=smoke&revision=2&offset=7&length=32', auth=True)
                assert part['packet_hex'] == raw[7:39].hex()
                logs = request('/api/v1/push/logs')['items']
                assert logs[0]['retry_count'] == 2 and logs[0]['status'] == 'failed'
                assert logs[0]['raw_packet']['packet_hex'] == raw.hex()
                current = request('/api/v1/config')['config']
                assert current['storage']['backend'] == 'v2'
                current.pop('storage')  # older UI/client must not erase new settings
                assert request('/api/v1/config', {'config': current}, auth=True)['success']
                assert request('/api/v1/config')['config']['storage']['backend'] == 'v2'
                assert request('/api/v1/storage', auth=True)['page_bytes'] > 0
                print('PASS: migration, binary startup, summary, complete event, range, retry state, config compatibility, metrics')
            finally:
                process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    main()
