import unittest
from src.detection_engine import parse_eve_log

class TestDetectionEngine(unittest.TestCase):
    def test_parse_valid_alert(self):
        sample_log = '{"event_type": "alert", "src_ip": "192.168.1.10", "dest_ip": "10.0.0.1", "alert": {"signature": "RECON Port Scan"}, "timestamp": "2026-10-18T10:00:00"}'
        parsed = parse_eve_log(sample_log)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['src_ip'], '192.168.1.10')
        self.assertEqual(parsed["mitre_ttp"], "T1595")

    def test_parse_invalid_json(self):
        invalid_log = 'INVALID_JSON_STREAM_DATA'
        parsed = parse_eve_log(invalid_log)
        self.assertIsNone(parsed)

if __name__ == '__main__':
    unittest.main()