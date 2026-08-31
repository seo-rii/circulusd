from __future__ import annotations

import json
import unittest
from pathlib import Path

from api.proto import check_contract

try:
    import jsonschema
except ImportError:
    jsonschema = None


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "json-schema" / "v1alpha"
MAX_SAFE_INTEGER = 9_007_199_254_740_991

DEVELOPMENT_STATUS = {
    "apiVersion": "v1alpha",
    "profile": "development-reference",
    "mode": "diagnostic-only",
    "productionEligible": False,
    "admissionEnabled": False,
    "state": {
        "availability": "unavailable",
        "reason": "NOT_WIRED",
        "implementation": "none",
        "durability": "none",
    },
    "execution": {
        "availability": "unavailable",
        "reason": "NOT_WIRED",
        "provider": "none",
        "isolationConformance": "NOT_RUN",
    },
}

DOCTOR_REPORT = {
    "schemaVersion": 1,
    "apiVersion": "v1alpha",
    "probeRunId": "doctor-run-example",
    "profile": "lightweight",
    "configDigest": "sha256:" + ("1" * 64),
    "releaseDigest": "sha256:" + ("2" * 64),
    "hostId": "host-example",
    "runnerBinaryDigest": "sha256:" + ("3" * 64),
    "targetInstanceId": "single-node-example",
    "productionProfile": True,
    "requiredComponents": ["host.kernel", "state.kill-durability"],
    "startedAt": "2026-08-27T01:02:03Z",
    "finishedAt": "2026-08-27T01:02:04Z",
    "observedAt": "2026-08-27T01:02:04Z",
    "profileQualified": True,
    "productionEligible": True,
    "results": [
        {
            "component": "host.kernel",
            "status": "PASS",
            "evidence": {
                "evidenceClass": "host-observation",
                "kernel": "6.12.4-reference",
                "architecture": "x86_64",
                "artifactReferences": [],
            },
        },
        {
            "component": "state.kill-durability",
            "status": "PASS",
            "evidence": {
                "evidenceClass": "external",
                "binaryDigest": "sha256:" + ("4" * 64),
                "version": "0.3.0",
                "artifactReferences": [
                    {
                        "name": "state-app.wasm",
                        "digest": "sha256:" + ("5" * 64),
                    }
                ],
            },
        },
    ],
}


class JSONSchemaIntegerContractTest(unittest.TestCase):
    def test_every_json_integer_stays_exact_in_typescript(self) -> None:
        violations: list[str] = []

        def visit(value: object, path: str) -> None:
            if isinstance(value, dict):
                if value.get("type") == "integer":
                    maximum = value.get("maximum")
                    if not isinstance(maximum, int) or maximum > MAX_SAFE_INTEGER:
                        violations.append(f"{path}.maximum={maximum!r}")
                for key, child in value.items():
                    visit(child, f"{path}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{path}[{index}]")

        for schema_path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
            visit(json.loads(schema_path.read_text(encoding="utf-8")), schema_path.name)

        self.assertEqual(violations, [])


class JSONSchemaRegistryTest(unittest.TestCase):
    def test_registry_covers_every_versioned_schema(self) -> None:
        schema_files = tuple(
            path.name for path in sorted(SCHEMA_ROOT.glob("*.schema.json"))
        )

        self.assertCountEqual(check_contract.SCHEMA_FILES, schema_files)

    def test_registry_includes_doctor_report(self) -> None:
        self.assertIn("doctor-report.schema.json", check_contract.SCHEMA_FILES)


@unittest.skipIf(jsonschema is None, "jsonschema is not installed")
class DevelopmentStatusSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = SCHEMA_ROOT / "development-status.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cls.validator = jsonschema.Draft202012Validator(schema)

    def test_accepts_honest_diagnostic_status(self) -> None:
        self.validator.validate(DEVELOPMENT_STATUS)

    def test_rejects_production_or_unwired_capability_claims(self) -> None:
        invalid_statuses = []

        production_eligible = json.loads(json.dumps(DEVELOPMENT_STATUS))
        production_eligible["productionEligible"] = True
        invalid_statuses.append(production_eligible)

        admission_enabled = json.loads(json.dumps(DEVELOPMENT_STATUS))
        admission_enabled["admissionEnabled"] = True
        invalid_statuses.append(admission_enabled)

        memory_state = json.loads(json.dumps(DEVELOPMENT_STATUS))
        memory_state["state"]["implementation"] = "memory"
        invalid_statuses.append(memory_state)

        extra_api = json.loads(json.dumps(DEVELOPMENT_STATUS))
        extra_api["sessionAPI"] = {"availability": "available"}
        invalid_statuses.append(extra_api)

        for status in invalid_statuses:
            with self.subTest(status=status):
                self.assertFalse(self.validator.is_valid(status))


@unittest.skipIf(jsonschema is None, "jsonschema is not installed")
class DoctorReportSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = SCHEMA_ROOT / "doctor-report.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cls.schema = schema
        cls.validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
        )

    def test_requires_the_runtime_semantic_validator(self) -> None:
        semantic = self.schema.get("x-circulus-semantic-validator")
        self.assertIsInstance(semantic, dict)
        self.assertTrue(semantic.get("required"))
        self.assertEqual(semantic.get("reference"), "internal/doctor.ValidateCurrent")

    def test_accepts_identity_bound_external_and_host_evidence(self) -> None:
        self.validator.validate(DOCTOR_REPORT)

        optional_failure = json.loads(json.dumps(DOCTOR_REPORT))
        optional_failure["results"].append(
            {
                "component": "telemetry.optional",
                "status": "FAIL",
                "reason": "diagnostic endpoint is disabled",
                "evidence": {
                    "evidenceClass": "external",
                    "artifactReferences": [],
                },
            }
        )
        optional_failure["results"].append(
            {
                "component": "workerd.reference-probe",
                "status": "NOT_RUN",
                "reason": "reference runner is not production evidence",
                "evidence": {
                    "evidenceClass": "reference-only",
                    "artifactReferences": [],
                    "mock": True,
                },
            }
        )
        self.validator.validate(optional_failure)

        development_reference = json.loads(json.dumps(DOCTOR_REPORT))
        development_reference["profile"] = "development"
        development_reference["productionProfile"] = False
        development_reference["requiredComponents"] = ["state.reference"]
        development_reference["productionEligible"] = False
        development_reference["results"] = [
            {
                "component": "state.reference",
                "status": "PASS",
                "evidence": {
                    "evidenceClass": "reference-only",
                    "artifactReferences": [],
                    "mock": True,
                },
            }
        ]
        self.validator.validate(development_reference)

    def test_rejects_ambiguous_or_dishonest_evidence(self) -> None:
        invalid_reports: list[tuple[str, dict[str, object]]] = []

        for field in (
            "apiVersion",
            "probeRunId",
            "observedAt",
            "runnerBinaryDigest",
            "targetInstanceId",
            "productionProfile",
            "requiredComponents",
        ):
            candidate = json.loads(json.dumps(DOCTOR_REPORT))
            del candidate[field]
            invalid_reports.append((f"missing {field}", candidate))

        unknown_member = json.loads(json.dumps(DOCTOR_REPORT))
        unknown_member["cachedPass"] = True
        invalid_reports.append(("unknown member", unknown_member))

        unknown_class = json.loads(json.dumps(DOCTOR_REPORT))
        unknown_class["results"][0]["evidence"]["evidenceClass"] = "unit-test"
        invalid_reports.append(("unknown evidence class", unknown_class))

        missing_class = json.loads(json.dumps(DOCTOR_REPORT))
        del missing_class["results"][0]["evidence"]["evidenceClass"]
        invalid_reports.append(("missing evidence class", missing_class))

        unknown_status = json.loads(json.dumps(DOCTOR_REPORT))
        unknown_status["results"][0]["status"] = "SKIPPED"
        invalid_reports.append(("unknown status", unknown_status))

        invalid_digest = json.loads(json.dumps(DOCTOR_REPORT))
        invalid_digest["configDigest"] = "sha256:ABC"
        invalid_reports.append(("invalid digest", invalid_digest))

        missing_artifacts = json.loads(json.dumps(DOCTOR_REPORT))
        del missing_artifacts["results"][0]["evidence"]["artifactReferences"]
        invalid_reports.append(("missing artifact references", missing_artifacts))

        reference_production = json.loads(json.dumps(DOCTOR_REPORT))
        reference_production["results"][0]["evidence"]["evidenceClass"] = (
            "reference-only"
        )
        reference_production["results"][0]["evidence"]["mock"] = True
        invalid_reports.append(("reference production PASS", reference_production))

        mock_external = json.loads(json.dumps(DOCTOR_REPORT))
        mock_external["results"][0]["evidence"]["mock"] = True
        invalid_reports.append(("external mock", mock_external))

        host_class_for_service = json.loads(json.dumps(DOCTOR_REPORT))
        host_class_for_service["results"][1]["evidence"]["evidenceClass"] = (
            "host-observation"
        )
        invalid_reports.append(("host class for service", host_class_for_service))

        invalid_timestamp = json.loads(json.dumps(DOCTOR_REPORT))
        invalid_timestamp["observedAt"] = "not-a-timestamp"
        invalid_reports.append(("invalid timestamp", invalid_timestamp))

        duplicate_required = json.loads(json.dumps(DOCTOR_REPORT))
        duplicate_required["requiredComponents"] = [
            "host.kernel",
            "host.kernel",
        ]
        invalid_reports.append(("duplicate required component", duplicate_required))

        production_claim_for_development = json.loads(json.dumps(DOCTOR_REPORT))
        production_claim_for_development["productionProfile"] = False
        invalid_reports.append(
            ("development report claims production eligibility", production_claim_for_development)
        )

        contradictory_eligibility = json.loads(json.dumps(DOCTOR_REPORT))
        contradictory_eligibility["profileQualified"] = False
        contradictory_eligibility["failureReason"] = "gate failed"
        invalid_reports.append(("eligible but unqualified", contradictory_eligibility))

        unqualified_without_reason = json.loads(json.dumps(DOCTOR_REPORT))
        unqualified_without_reason["profileQualified"] = False
        unqualified_without_reason["productionEligible"] = False
        invalid_reports.append(("unqualified without reason", unqualified_without_reason))

        qualified_with_reason = json.loads(json.dumps(DOCTOR_REPORT))
        qualified_with_reason["failureReason"] = "forged failure"
        invalid_reports.append(("qualified with failure reason", qualified_with_reason))

        failed_without_reason = json.loads(json.dumps(DOCTOR_REPORT))
        failed_without_reason["results"][0]["status"] = "FAIL"
        invalid_reports.append(("failed result without reason", failed_without_reason))

        failed_with_blank_reason = json.loads(json.dumps(DOCTOR_REPORT))
        failed_with_blank_reason["results"][0]["status"] = "FAIL"
        failed_with_blank_reason["results"][0]["reason"] = "   "
        invalid_reports.append(("failed result with blank reason", failed_with_blank_reason))

        for name, report in invalid_reports:
            with self.subTest(name=name):
                self.assertFalse(self.validator.is_valid(report))


if __name__ == "__main__":
    unittest.main()
