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


if __name__ == "__main__":
    unittest.main()
