"""e2e/lib/loadgen.py (#495): canary keys only, one line per request with exactly its ten fields, failover once on a
connection error or a retryable 503 with the SAME nonce, never on a 4xx; the answering server named from its
certificate. Against real TLS servers with mutual TLS, on loopback."""
import datetime
import http.server
import io
import json
import os
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from e2e.lib import loadgen


def _cert(name, issuer_key=None, issuer_name=None, ca=False, san=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name or subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    # Python 3.13's strict verification wants both key identifiers
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False)
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                      encipher_only=False, decipher_only=False), critical=True)
    return key, builder.sign(issuer_key or key, hashes.SHA256())


def _write(directory, name, key, cert):
    k, c = os.path.join(directory, name + ".key"), os.path.join(directory, name + ".pem")
    with open(k, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(c, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return k, c


class Servers(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        ca_key, ca = _cert("test-ca", ca=True)
        self.ca = _write(self.dir, "ca", ca_key, ca)[1]
        self.client = _write(self.dir, "client", *_cert("loadgen", ca_key, ca.subject, san=["loadgen"]))
        self.seen, self.answers, self.servers = [], {}, []
        for name in ("node-a", "node-b"):
            key, cert = _write(self.dir, name, *_cert(name, ca_key, ca.subject, san=[name, "localhost"]))
            self.servers.append(self._serve(name, key, cert))

    def _serve(self, name, keyfile, certfile):
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.seen.append((name, self.path, self.headers["X-Request-ID"], self.headers["Idempotency-Key"], body,
                                  self.connection.getpeercert() is not None))
                status, code = test.answers.get(name, (200, None))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"signature": "AA=="} if status == 200 else {"code": code, "retryable": status == 503}).encode())

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=self.ca)
        context.load_cert_chain(certfile, keyfile)
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return {"name": name, "url": "https://localhost:%d" % server.server_address[1]}

    def config(self, servers=None, keys=None):
        return {"servers": servers or self.servers, "tls": {"cert": self.client[1], "key": self.client[0], "ca": self.ca},
                "keys": keys or [{"object_id": "canary-sign", "op": "sign", "purpose": "canary-sign", "environment": "production",
                                  "stateful": False}]}

    def line(self, config, first=0):
        context = loadgen.tls_context(config["tls"])
        return loadgen.one(config, context, config["keys"][0], "run-1", first)

    def test_an_answer_is_one_line_with_exactly_its_fields_naming_the_server(self):
        line = self.line(self.config())
        self.assertEqual(tuple(line), loadgen.FIELDS)
        self.assertEqual((line["node"], line["outcome"], line["attempt"], line["drill"], line["stateful"], line["key"], line["op"]),
                         ("node-a", "ok", 1, "run-1", False, "canary-sign", "sign"))
        name, path, request_id, idempotency, body, client_cert = self.seen[0]
        self.assertEqual((path, request_id), ("/v1/operations/sign", line["request_id"]))
        self.assertEqual(idempotency, body["context"]["nonce"])        # the API's rule
        self.assertTrue(client_cert, "the server saw no client certificate: not mutual TLS")
        self.assertLessEqual(line["start_ms"], line["end_ms"])

    def test_a_retryable_503_fails_over_once_with_the_same_nonce(self):
        self.answers["node-a"] = (503, "DEPENDENCY_UNAVAILABLE")
        line = self.line(self.config())
        self.assertEqual((line["node"], line["outcome"], line["attempt"]), ("node-b", "ok", 2))
        (a, _, rid_a, nonce_a, _, _), (b, _, rid_b, nonce_b, _, _) = self.seen
        self.assertEqual((a, b), ("node-a", "node-b"))
        self.assertEqual((rid_a, nonce_a), (rid_b, nonce_b))           # one request, retried: never a new nonce

    def test_a_4xx_is_never_retried(self):
        for code, status in (("CONFLICT", 409), ("DENIED", 403), ("RESOURCE_EXHAUSTED", 429)):
            with self.subTest(code=code):
                self.seen.clear()
                self.answers["node-a"] = (status, code)
                line = self.line(self.config())
                self.assertEqual((line["node"], line["outcome"], line["attempt"]), ("node-a", code, 1))
                self.assertEqual(len(self.seen), 1)

    def test_a_server_that_does_not_answer_fails_over(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        line = self.line(self.config(servers=[{"name": "down", "url": "https://localhost:%d" % port}, self.servers[1]]))
        self.assertEqual((line["node"], line["outcome"], line["attempt"]), ("node-b", "ok", 2))
        line = self.line(self.config(servers=[{"name": "down", "url": "https://localhost:%d" % port}]))
        self.assertEqual((line["node"], line["outcome"], line["attempt"]), ("", "CONNECTION", 1))

    def test_run_writes_one_line_per_request(self):
        out = io.StringIO()
        n = loadgen.run(self.config(), "run-2", 0.3, out, rate=50)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(lines), n)
        self.assertGreater(n, 2)
        self.assertTrue(all(tuple(sorted(line)) == tuple(sorted(loadgen.FIELDS)) for line in lines))


class Canaries(unittest.TestCase):
    def _files(self, objects, keys):
        directory = tempfile.mkdtemp()
        manifest, config = os.path.join(directory, "m.json"), os.path.join(directory, "c.json")
        with open(manifest, "w") as f:
            json.dump({"objects": objects}, f)
        with open(config, "w") as f:
            json.dump({"servers": [{"name": "a", "url": "https://a"}], "tls": {}, "keys": keys}, f)
        return config, manifest

    def test_only_canary_keys_of_the_manifest_are_taken(self):
        canary = {"object_id": "canary-sign", "op": "sign", "purpose": "canary-sign", "environment": "production", "stateful": False}
        objects = [{"id": "canary-sign", "purpose": "canary-sign"}, {"id": "release-signing", "purpose": "release-signing"}]
        loadgen.load_config(*self._files(objects, [canary]))
        for keys, why in (([dict(canary, object_id="release-signing", purpose="release-signing")], "is not a canary key"),
                          ([dict(canary, object_id="unknown")], "is not a canary key"),
                          ([dict(canary, purpose="canary-other")], "must be the manifest's"),
                          ([{k: v for k, v in canary.items() if k != "stateful"}], "stateful must be declared")):
            with self.subTest(why=why), self.assertRaisesRegex(loadgen.Refused, why):
                loadgen.load_config(*self._files(objects, keys))
        config, manifest = self._files(objects, [dict(canary, object_id="release-signing", purpose="release-signing")])
        self.assertEqual(loadgen.main(["run", "--config", config, "--manifest", manifest, "--drill", "x", "--seconds", "1",
                                       "--out", os.path.join(tempfile.mkdtemp(), "o")]), 2)


class Baseline(unittest.TestCase):
    def test_the_histogram_counts_latencies_and_outcomes_per_op(self):
        lines = [{"op": "sign", "start_ms": 0, "end_ms": 7, "outcome": "ok"}, {"op": "sign", "start_ms": 0, "end_ms": 7000, "outcome": "ok"},
                 {"op": "sign", "start_ms": 0, "end_ms": 20000, "outcome": "DEADLINE_EXCEEDED"}]
        b = loadgen.baseline(lines)["ops"]["sign"]
        self.assertEqual(b["requests"], 3)
        self.assertEqual((b["latency_ms"]["10"], b["latency_ms"]["10000"], b["latency_ms"]["inf"]), (1, 1, 1))
        self.assertEqual(b["outcomes"], {"ok": 2, "DEADLINE_EXCEEDED": 1})


if __name__ == "__main__":
    unittest.main()
