import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('diagnose_node', Path(__file__).with_name('diagnose_node.py'))
diagnose = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnose)


class DiagnosticsTest(unittest.TestCase):
    def test_revisions_sources_retry_head_and_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'queue.db'
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE event_queue (id INTEGER PRIMARY KEY, event_time INTEGER, '
                         'status INTEGER, retry_count INTEGER, payload TEXT, created_at INTEGER)')
            fixtures = [('a', '10.0.0.185', 2, 0), ('a', '10.0.0.185', 2, 0),
                        ('b', '10.0.0.144', 3, 20), ('c', '10.0.0.77', 0, 0),
                        ('d', '10.0.0.88', 3, 1)]
            for i, (eid, source, status, retry) in enumerate(fixtures, 1):
                payload = json.dumps({'event_id': eid, 'src_ip': source, 'dst_ip': '203.0.113.9',
                                      'ioc_type': 'ip', 'ioc_value': '203.0.113.9',
                                      'raw_packet': {'payload_text': 'DO-NOT-PRINT'}})
                conn.execute('INSERT INTO event_queue VALUES (?,?,?,?,?,?)',
                             (i, 1700000000000000 + i, status, retry, payload, 1700000000))
            conn.commit()
            conn.close()
            before = hashlib.sha256(path.read_bytes()).digest()
            result = diagnose.queue_report(path, 20, 20, ['10.0.0.77'])
            self.assertEqual(result['sample_distinct_sources'], 4)
            self.assertEqual(result['sample_retry_exhausted_rows'], 1)
            self.assertEqual([r['id'] for r in result['next_100_eligible_rows']], [4, 5])
            self.assertEqual(result['requested_sources'][0]['unique_events_as_source'], 1)
            self.assertEqual(next(r for r in result['top_sources'] if r['src_ip'] == '10.0.0.185')['unique_events'], 1)
            self.assertNotIn('DO-NOT-PRINT', json.dumps(result))
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())
            bounded = diagnose.queue_report(path, 1, 20, ['10.0.0.77'])
            self.assertEqual(bounded['sample_rows'], 1)
            self.assertEqual(bounded['requested_sources'][0]['unique_events_as_source'], 0)

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'missing.db'
            with self.assertRaises(sqlite3.OperationalError):
                diagnose.queue_report(path, 10, 20, [])
            self.assertFalse(path.exists())

    def test_config_output_omits_credentials(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = {'config': {'node': {'api_key': 'SECRET-KEY', 'device_id': 'test'},
                                   'server': {'token': 'SECRET-TOKEN'}, 'capture': {'interface': 'eth0'}},
                        'path': '/opt/ta_node/configs/ta_node.yaml'} if self.path.endswith('/config') else {'status': 'ok'}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            output = io.StringIO()
            with patch('sys.argv', ['diagnose_node.py', '--api', 'http://127.0.0.1:{}'.format(server.server_port)]):
                with contextlib.redirect_stdout(output):
                    diagnose.main()
            result = json.loads(output.getvalue())
            self.assertEqual(result['settings']['capture']['interface'], 'eth0')
            self.assertNotIn('SECRET-', output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
