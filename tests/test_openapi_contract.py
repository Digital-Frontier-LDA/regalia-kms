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


if __name__ == "__main__":
    unittest.main()
