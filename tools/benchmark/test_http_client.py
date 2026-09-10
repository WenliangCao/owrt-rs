#!/usr/bin/env python3
"""Protocol/counting gates for the LAN benchmark; uses only local fixtures."""
import http.server
import threading
import unittest

from http_client import benchmark


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen = getattr(self, "seen", 0)
        self.seen = seen + 1
        code = 503 if self.path == "/status-error" or (self.path == "/late-error" and seen) else 200
        body = b'{"result":[6]}' if self.path == "/rpc-error" else b"expected"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Gates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def test_remainder_requests_are_all_counted(self):
        result = benchmark(self.url, 17, 4, 1, None, b"expected")
        self.assertEqual(result["successful"], 17)
        self.assertEqual(len(result["latency_ns"]), 17)

    def test_http_error_invalidates_run(self):
        with self.assertRaises(RuntimeError):
            benchmark(self.url + "/status-error", 8, 2, 1, None, b"expected")

    def test_rpc_error_in_http_200_invalidates_run(self):
        with self.assertRaises(RuntimeError):
            benchmark(self.url + "/rpc-error", 8, 2, 1, None, {"result": [0, {}]}, True)

    def test_failure_after_warmup_invalidates_measurement(self):
        with self.assertRaises(RuntimeError):
            benchmark(self.url + "/late-error", 8, 2, 1, None, b"expected")

    def test_new_connections_keep_exact_count(self):
        result = benchmark(self.url, 11, 3, 1, None, b"expected", fresh=True)
        self.assertEqual(result["successful"], 11)
        self.assertEqual(result["connection_mode"], "new_connection")


if __name__ == "__main__":
    unittest.main()
