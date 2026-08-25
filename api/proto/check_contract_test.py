from __future__ import annotations

import json
import unittest
from pathlib import Path


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "json-schema" / "v1alpha"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


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


if __name__ == "__main__":
    unittest.main()
