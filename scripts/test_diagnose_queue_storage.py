import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('diagnose_queue_storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class StorageTest(unittest.TestCase):
    def test_bounded_revision_sizes_and_readonly(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'queue.db.archived'
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE event_queue (id INTEGER PRIMARY KEY,status INTEGER,retry_count INTEGER,created_at INTEGER,payload TEXT)')
            expected = 0
            for i in range(1, 4):
                body = json.dumps({'event_id': 'e1' if i > 1 else 'old', 'context_revision': i,
                                   'src_ip': '192.0.2.1', 'raw_packet': '秘密'}, ensure_ascii=False)
                conn.execute('INSERT INTO event_queue VALUES (?,?,?,?,?)', (i, 2, 0, 1700000000 + i, body))
                if i > 1:
                    expected += len(body.encode('utf-8'))
            conn.commit()
            conn.close()
            before = hashlib.sha256(path.read_bytes()).digest()
            report = storage.inspect(path, 2)
            self.assertEqual(report['sample_rows'], 2)
            self.assertEqual(report['sample_json_bytes'], expected)
            self.assertEqual(report['sample_distinct_event_ids'], 1)
            self.assertEqual(report['sample_revision_rows'], 2)
            self.assertEqual(report['sample_max_context_revision'], 3)
            self.assertEqual(report['sample_status_rows'], {'pushed': 2})
            self.assertGreater(report['page_count'], 0)
            self.assertNotIn('秘密', json.dumps(report, ensure_ascii=False))
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())

    def test_missing_database_not_created(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'missing.db'
            with self.assertRaises(FileNotFoundError):
                storage.inspect(path)
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
