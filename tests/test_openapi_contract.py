import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "api" / "openapi.json"


class OpenAPIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))

    def operation(self, path, method):
        return self.spec["paths"][path][method]

    # ---- reachability -------------------------------------------------------------------------
    #
    # THE CHECKS BELOW USED HARDCODED SCHEMA NAMES, AND THE LIST WAS ALREADY WRONG.
    # SealEnvelopeRequest is the body of /v1/operations/seal-envelope and was in neither the
    # closed-schema list nor the forbidden-field list, so that endpoint could have been opened to
    # additionalProperties or given a `slot` field with every test here still green. The same gap
    # on the way out: the no-private-key-export check serialised `paths` and `tags` only, so a
    # `private_key` property added to OperationResult — the response body of every operation —
    # would not have been seen.
    #
    # Reachability is derived from the operations instead, so a new endpoint or a new $ref is
    # covered the moment it is added rather than when someone remembers to extend a list.

    def resolve(self, ref):
        """Resolve a local $ref, failing the test on a dangling one.

        A $ref that points at nothing is not a documentation nit: generators emit a broken client,
        validators reject the document, and the operation it belongs to has no described error
        shape at all. This found `#/components/responses/DependencyUnavailable` missing from the
        spec while seal-envelope referenced it."""
        self.assertTrue(ref.startswith("#/"), f"only local refs are expected here: {ref}")
        node = self.spec
        for part in ref[2:].split("/"):
            self.assertIn(part, node, f"dangling $ref {ref}: nothing at {part!r}")
            node = node[part]
        return node

    def reachable_schemas(self, roots):
        """Every schema reachable from `roots`, as {name-or-path: schema}, following $ref."""
        seen, out, queue = set(), {}, list(roots)
        while queue:
            name, node = queue.pop()
            if not isinstance(node, dict):
                continue
            ref = node.get("$ref")
            if ref:
                if ref in seen:
                    continue
                seen.add(ref)
                queue.append((ref.rsplit("/", 1)[-1], self.resolve(ref)))
                continue
            out[name] = node
            for key in ("properties", "patternProperties", "definitions"):
                for child, value in (node.get(key) or {}).items():
                    queue.append((f"{name}.{child}", value))
            for key in ("items", "additionalProperties", "not"):
                value = node.get(key)
                if isinstance(value, dict):
                    queue.append((f"{name}.{key}", value))
            for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
                for i, value in enumerate(node.get(key) or []):
                    queue.append((f"{name}.{key}[{i}]", value))
        return out

    def operations(self):
        for path, item in self.spec["paths"].items():
            for method, operation in item.items():
                if method in {"get", "post", "put", "patch", "delete"}:
                    yield path, method, operation

    def request_schemas(self):
        roots = []
        for path, method, operation in self.operations():
            for media in (operation.get("requestBody", {}).get("content", {}) or {}).values():
                if "schema" in media:
                    roots.append((f"{method.upper()} {path} request", media["schema"]))
        self.assertTrue(roots, "no request bodies were found; this check would pass vacuously")
        return self.reachable_schemas(roots)

    def response_schemas(self):
        roots = []
        for path, method, operation in self.operations():
            for code, response in (operation.get("responses", {}) or {}).items():
                if "$ref" in response:
                    response = self.resolve(response["$ref"])
                for media in (response.get("content", {}) or {}).values():
                    if "schema" in media:
                        roots.append((f"{method.upper()} {path} {code}", media["schema"]))
        self.assertTrue(roots, "no responses were found; this check would pass vacuously")
        return self.reachable_schemas(roots)

    def test_contract_is_openapi_31_and_versioned(self):
        self.assertRegex(self.spec["openapi"], r"^3\.1\.")
        self.assertEqual(self.spec["info"]["version"], "1.0.0")
        self.assertTrue(all(path.startswith("/v1/") for path in self.spec["paths"]))

    def test_only_health_endpoints_are_unauthenticated(self):
        self.assertEqual(self.spec["security"], [{"mutualTLS": []}])
        for path, path_item in self.spec["paths"].items():
            for method, operation in path_item.items():
                if method not in {"get", "post", "put", "patch", "delete"}:
                    continue
                if path in {"/v1/health/live", "/v1/health/ready"}:
                    self.assertEqual(operation.get("security"), [], path)
                else:
                    self.assertNotEqual(operation.get("security"), [], path)

    def test_spec_documents_exactly_the_surface_API_md_promises(self):
        """API.md and openapi.json must name the same endpoints.

        This test previously asserted a hardcoded set containing
        /v1/secrets/{secret_id}:release and /v1/objects/{object_id}/public-key --
        two endpoints nothing implements and API.md never named. Because the test
        encoded the fiction, it defended it: the spec could not be corrected
        without the test failing, and the three operations that DO exist
        (certificate-sign, key-agreement, release-secret) stayed undocumented.

        Comparing against API.md instead means neither document can drift alone.
        The Go test TestSpecRouterAndHandlerDescribeTheSameAPI binds this same
        spec to the code, so the chain runs API.md -> openapi.json -> router ->
        handler with no link asserted only against itself.
        """
        contract = (ROOT / "API.md").read_text(encoding="utf-8")
        documented = set(re.findall(r"`(?:POST|GET)\s+(/v1/[A-Za-z0-9/_-]+)`", contract))
        self.assertTrue(documented, "no endpoints were parsed out of API.md")

        specified = {
            path
            for path, item in self.spec["paths"].items()
            if any(method in item for method in ("get", "post", "put", "patch", "delete"))
        }
        self.assertEqual(
            documented,
            specified,
            "API.md and openapi.json disagree about the API surface; "
            f"only in API.md: {sorted(documented - specified)}; "
            f"only in the spec: {sorted(specified - documented)}",
        )

    def test_mutating_operations_require_request_and_idempotency_headers(self):
        for path, item in self.spec["paths"].items():
            if "post" not in item:
                continue
            parameters = item["post"].get("parameters", [])
            required_headers = {
                parameter.get("name")
                for parameter in parameters
                if parameter.get("in") == "header" and parameter.get("required") is True
            }
            self.assertIn("X-Request-ID", required_headers, path)
            self.assertIn("Idempotency-Key", required_headers, path)

    def test_requests_are_closed_and_payloads_are_bounded(self):
        schemas = self.spec["components"]["schemas"]
        # Every OBJECT schema a request can reach, not a remembered list of five.
        reached = self.request_schemas()
        self.assertGreaterEqual(len(reached), 5, f"only {len(reached)} request schemas reached")
        for name, schema in sorted(reached.items()):
            if schema.get("type") != "object" and "properties" not in schema:
                continue
            self.assertFalse(
                schema.get("additionalProperties", True),
                f"{name} accepts additional properties, so a client can smuggle fields the "
                f"daemon never validates past a contract that claims to be closed")
        self.assertLessEqual(schemas["SignRequest"]["properties"]["payload_base64"]["maxLength"], 1_400_000)
        self.assertLessEqual(schemas["UnwrapRequest"]["properties"]["wrapped_data_key_base64"]["maxLength"], 65_536)

    def test_clients_cannot_select_device_backend_slot_or_mechanism(self):
        forbidden = ("backend", "device_id", "slot", "mechanism", "pin", "private_key")
        for name, schema in sorted(self.request_schemas().items()):
            for field in (schema.get("properties") or {}):
                self.assertNotIn(
                    field, forbidden,
                    f"{name} lets a client choose {field!r}. Backend, device, slot and mechanism "
                    f"are the daemon's decision: a request that can name them can steer an "
                    f"operation onto another key or a weaker algorithm.")

    def test_safe_error_codes_are_stable_and_retry_is_explicit(self):
        error = self.spec["components"]["schemas"]["Error"]
        codes = set(error["properties"]["code"]["enum"])
        self.assertTrue(
            {
                "INVALID_ARGUMENT", "UNAUTHENTICATED", "DENIED", "NOT_FOUND", "CONFLICT",
                "BACKEND_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE", "DEADLINE_EXCEEDED", "INTERNAL",
                "RESOURCE_EXHAUSTED", "CANCELED",
            }.issubset(codes)
        )
        self.assertIn("retryable", error["required"])
        self.assertNotIn("details", error["properties"])

    def test_no_private_key_export_surface_exists(self):
        # Paths and tags are where such an endpoint would be NAMED; the response schemas are where
        # one would actually be HANDED OVER. Scanning only the former let a `private_key` property
        # on OperationResult — the body every operation returns — pass unseen.
        surface = json.dumps(
            {"paths": self.spec["paths"], "tags": self.spec.get("tags", []),
             "responses": self.response_schemas()},
            separators=(",", ":"), default=str,
        ).lower()
        for forbidden in ("private-key", "private_key", "exportkey", "privatekey"):
            self.assertNotIn(forbidden, surface)

    def test_every_local_ref_in_the_document_resolves(self):
        """A $ref that points at nothing breaks generated clients and leaves the operation with no
        described error shape. seal-envelope referenced components/responses/DependencyUnavailable
        while the spec defined no such response."""
        refs = []

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("$ref"), str):
                    refs.append(node["$ref"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(self.spec)
        self.assertGreater(len(refs), 10, "almost no $refs were found; the walk is broken")
        for ref in sorted(set(refs)):
            self.resolve(ref)


    # ---- the contract against the code ---------------------------------------------------------
    #
    # THE DOCUMENTS DRIFTED FROM THE DAEMON AND NOTHING NOTICED. api/openapi.json declared 422 on
    # every operation, a status the daemon never writes, and declared none of 404, 405, 429, 500 or
    # 504, which it does. API.md's table had no row for DEADLINE_EXCEEDED or CANCELED. And
    # SignRequest.content_type was a closed list without application/vnd.regalia.digest, the one
    # content type the shipped release-signing policy, the hardened-serve e2e and regalia-sign use.
    # Every test above compares the document with itself or with a list written in this file, so
    # none of them could see it. The tests below read the Go source.

    GO_STATUS = {
        "StatusBadRequest": 400, "StatusUnauthorized": 401, "StatusForbidden": 403,
        "StatusNotFound": 404, "StatusMethodNotAllowed": 405, "StatusConflict": 409,
        "StatusTooManyRequests": 429, "StatusInternalServerError": 500,
        "StatusServiceUnavailable": 503, "StatusGatewayTimeout": 504,
    }
    # The executor's codes reach the wire verbatim (coordinator.classifyExecution), with a status
    # chosen there by an if-chain a regex cannot read. So the pairs are stated here, and the test
    # holds this table to the executor's own constants: a code added there fails until it is
    # listed, and so documented.
    EXECUTOR = {
        "RESOURCE_EXHAUSTED": (429, True), "DEADLINE_EXCEEDED": (504, True),
        "CANCELED": (504, False), "INTERNAL": (500, False),
    }

    def emitted(self):
        """{(code, status, retryable)} for every error the daemon's source writes. `retryable` is
        None where the source assigns code and status only and the flag keeps an earlier value."""
        written = re.compile(r'"([A-Z][A-Z_]{3,})",\s*http\.(Status[A-Za-z]+)(?:,\s*(true|false))?')
        found = set()
        for directory in ("api", "operations"):
            for path in sorted((ROOT / "internal" / directory).glob("*.go")):
                if path.name.endswith("_test.go"):
                    continue
                for code, status, retryable in written.findall(path.read_text(encoding="utf-8")):
                    self.assertIn(status, self.GO_STATUS, f"{path.name} writes http.{status}; add it to GO_STATUS")
                    found.add((code, self.GO_STATUS[status], {"true": True, "false": False}.get(retryable)))
        executor = (ROOT / "internal" / "executor" / "executor.go").read_text(encoding="utf-8")
        constants = set(re.findall(r'Code\s*=\s*"([A-Z_]+)"', executor))
        self.assertEqual(constants, set(self.EXECUTOR), "the executor's codes and EXECUTOR above disagree")
        classify = (ROOT / "internal" / "operations" / "coordinator.go").read_text(encoding="utf-8")
        classify = classify[classify.index("func classifyExecution"):]
        classify = classify[:classify.index("\nfunc ", 1)]
        self.assertEqual(
            {self.GO_STATUS[name] for name in re.findall(r"http\.(Status[A-Za-z]+)", classify)},
            {status for status, _ in self.EXECUTOR.values()} | {503},
            "classifyExecution maps to other statuses than EXECUTOR records")
        found |= {(code, status, retryable) for code, (status, retryable) in self.EXECUTOR.items()}
        # Not vacuous: a pattern that stopped matching would otherwise pass every assertion below.
        self.assertGreaterEqual(len(found), 12)
        self.assertIn(("INVALID_ARGUMENT", 400, False), found)
        self.assertIn(("NOT_FOUND", 404, None), found)
        return found

    def test_every_code_and_status_the_daemon_writes_is_declared(self):
        codes = set(self.spec["components"]["schemas"]["Error"]["properties"]["code"]["enum"])
        emitted = self.emitted()
        self.assertLessEqual({code for code, _, _ in emitted}, codes)
        statuses = {str(status) for _, status, _ in emitted}
        operations = [path for path, _, _ in self.operations() if path.startswith("/v1/operations/")]
        self.assertGreaterEqual(len(operations), 7)
        for path in operations:
            declared = set(self.operation(path, "post")["responses"])
            self.assertLessEqual(statuses, declared, f"{path} does not declare {sorted(statuses - declared)}")
        # #74's admission gate answers a key operation with the EXISTING code and status, so that
        # no client contract moves. That only holds while this pair stays documented everywhere.
        self.assertIn(("DEPENDENCY_UNAVAILABLE", 503, True), emitted)

    def error_table(self):
        """API.md's error table as {code: (statuses, retryable)}."""
        text = (ROOT / "API.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| `([A-Z_]+)` \| ([0-9, ]+) \| (yes|no) \|", text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(rows), 9)
        return {code: ({int(s) for s in statuses.split(",")}, retryable == "yes") for code, statuses, retryable in rows}

    def test_API_md_error_table_matches_the_document_and_the_daemon(self):
        table = self.error_table()
        codes = set(self.spec["components"]["schemas"]["Error"]["properties"]["code"]["enum"])
        self.assertEqual(set(table), codes, "API.md's error table and the OpenAPI code list name different codes")
        for code, status, retryable in sorted(self.emitted(), key=str):
            statuses, documented = table[code]
            self.assertIn(status, statuses, f"the daemon answers {code} with {status}; API.md says {sorted(statuses)}")
            if retryable is not None:
                self.assertEqual(retryable, documented, f"the daemon marks {code} retryable={retryable}; API.md says otherwise")

    def test_sign_declares_the_content_types_the_shipped_policy_uses(self):
        declared = set(self.spec["components"]["schemas"]["SignRequest"]["properties"]["content_type"]["enum"])
        policies = json.loads((ROOT / "config" / "policy.example.json").read_text(encoding="utf-8"))["policies"]
        used = {kind for policy in policies if policy["operation"] == "sign" for kind in policy["content_types"]}
        self.assertTrue(used, "the example policy has no sign entry")
        self.assertLessEqual(used, declared, f"SignRequest.content_type omits {sorted(used - declared)}")

    def test_sign_declares_the_daemon_development_x509_boundary(self):
        source = (ROOT / "internal" / "operations" / "coordinator.go").read_text(encoding="utf-8")
        content_type = re.search(r'const x509TBSContentType = "([^"]+)"', source)
        self.assertIsNotNone(content_type, "the coordinator X.509 boundary constant moved")
        declaration = self.spec["components"]["schemas"]["SignRequest"]["properties"]["content_type"]
        self.assertIn(content_type.group(1), declaration["enum"])
        self.assertIn("development", declaration["description"])
        self.assertIn("32 KiB", declaration["description"])
        self.assertIn("unhashed", declaration["description"])


if __name__ == "__main__":
    unittest.main()
