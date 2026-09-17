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
        for name in ("SignRequest", "WrapRequest", "UnwrapRequest", "ReleaseSecretRequest", "OperationContext"):
            self.assertFalse(schemas[name].get("additionalProperties", True), name)
        self.assertLessEqual(schemas["SignRequest"]["properties"]["payload_base64"]["maxLength"], 1_400_000)
        self.assertLessEqual(schemas["UnwrapRequest"]["properties"]["wrapped_data_key_base64"]["maxLength"], 65_536)

    def test_clients_cannot_select_device_backend_slot_or_mechanism(self):
        request_names = ("SignRequest", "WrapRequest", "UnwrapRequest", "ReleaseSecretRequest", "OperationContext")
        serialized = json.dumps({name: self.spec["components"]["schemas"][name] for name in request_names})
        for forbidden in ("backend", "device_id", "slot", "mechanism", "pin", "private_key"):
            self.assertNotIn(f'"{forbidden}"', serialized)

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
        surface = json.dumps(
            {"paths": self.spec["paths"], "tags": self.spec.get("tags", [])},
            separators=(",", ":"),
        ).lower()
        self.assertNotIn("private-key", surface)
        self.assertNotIn("private_key", surface)
        self.assertNotIn("exportkey", surface)


if __name__ == "__main__":
    unittest.main()
