"""Synthetic, in-memory contract checks; no runtime, host or network access."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from wormhole.contracts import ContractError, KINDS, MAX_ARTIFACT_BYTES, schema_for, validate_artifact


COMMON = {"schema_version": "1.0", "run_id": "12345678-1234-4234-9234-123456789abc",
          "source_revision": "a" * 40, "source_dirty": False, "mode": "fixture"}
STAGE = {"name": "fixture-integrity", "inputs": ["fixtures/source.bin"],
         "outputs": ["test-results.json"], "location": "local", "timeout_seconds": 2,
         "status": "pass", "duration_seconds": 0.01, "returncode": 0,
         "log_bytes": 0, "log_truncated": False, "error": None}
CHECK = {"check_id": "fixture-sha256", "target_id": None, "status": "pass",
         "required": True, "expected": "known synthetic hash", "observed": "known synthetic hash",
         "evidence": ["fixture/result.json"]}
TARGET = {"target_id": "target-1", "resource_id": "c" * 64, "host": "172.20.0.2",
          "ssh_port": 22, "ssh_user": "wormhole", "image_digest": "sha256:" + "d" * 64,
          "status": "unverified"}
SVD_TARGET = {"target_id": "target-1", "os_id": "ubuntu", "os_version": "fixture-only",
              "packages": [{"name": "synthetic-package", "version": "1.0"}],
              "payload_version": "synthetic-1", "image_digest": "sha256:" + "d" * 64,
              "candidate_sha256": "e" * 64, "collector_version": "synthetic-1"}


def fixtures():
    records = {
        "run-manifest": {"profile": "fixture", "outcome": "passed",
            "created_at": "2026-10-23T03:00:00Z", "updated_at": "2026-10-23T03:00:01.123456Z",
            "expected_checks": ["fixture-sha256"], "stages": [STAGE],
            "runtime_pipeline_complete": False, "production_iso_eligible": False},
        "inventory": {"status": "unverified", "targets": [TARGET]},
        "test-results": {"status": "pass", "checks": [CHECK]},
        "svd": {"status": "unverified", "targets": [SVD_TARGET]},
        "assessment": {"status": "unverified", "synthetic": True, "policy_id": "fixture.reference-only",
            "findings": [{"finding_id": "synthetic-1", "status": "Not Reviewed", "summary": "Synthetic fixture only."}]},
        "release-decision": {"status": "unsupported", "reference_eligible": False,
            "production_iso_eligible": False, "reasons": ["Runtime pipeline not implemented."]},
    }
    return {kind: deepcopy({**COMMON, **record}) for kind, record in records.items()}


class ArtifactContracts(unittest.TestCase):
    def test_six_nonempty_synthetic_records_round_trip_without_mutation(self):
        records = fixtures()
        original = deepcopy(records)
        self.assertEqual(set(records), set(KINDS))
        for kind, record in records.items():
            with self.subTest(kind=kind):
                self.assertIsNone(validate_artifact(kind, json.loads(json.dumps(record))))
                validate_artifact(kind, record)
        self.assertEqual(records, original)

    def test_published_schemas_are_generated_from_the_exact_definitions(self):
        root = Path(__file__).resolve().parents[1]
        for kind in KINDS:
            with self.subTest(kind=kind):
                published = json.loads((root / "schemas" / f"{kind}-v1.schema.json").read_text("utf-8"))
                self.assertEqual(published, schema_for(kind))
                self.assertFalse(published["additionalProperties"])
                self.assertEqual(published["$schema"], "https://json-schema.org/draft/2020-12/schema")
        schema_for("inventory")["properties"].clear()
        validate_artifact("inventory", fixtures()["inventory"])

    def test_kinds_versions_missing_fields_and_unknown_fields_are_rejected(self):
        for kind in ("manifest", "../inventory", None, []):
            with self.subTest(kind=kind), self.assertRaises(ContractError) as error:
                validate_artifact(kind, {})
            self.assertEqual(error.exception.code, "UNSUPPORTED_ARTIFACT")
        for kind, record in fixtures().items():
            for version in ("2.0", "1.1", 1, None, True):
                with self.subTest(kind=kind, version=version), self.assertRaises(ContractError):
                    validate_artifact(kind, {**record, "schema_version": version})
            for field in record:
                missing = deepcopy(record)
                del missing[field]
                with self.subTest(kind=kind, missing=field), self.assertRaises(ContractError):
                    validate_artifact(kind, missing)
            with self.assertRaises(ContractError) as error:
                validate_artifact(kind, {**record, "owner_password_NEVER_ECHO": "synthetic-secret-NEVER-ECHO"})
            self.assertNotIn("NEVER", str(error.exception))

    def test_strict_scalars_never_treat_boolean_as_numeric_or_constants(self):
        bad = []
        for value in (True, False, "2", None):
            record = fixtures()["run-manifest"]
            record["stages"][0]["timeout_seconds"] = value
            bad.append(("run-manifest", record))
        for value in (True, 0, "false", None):
            for kind in ("run-manifest", "release-decision"):
                record = fixtures()[kind]
                record["production_iso_eligible"] = value
                bad.append((kind, record))
        for field in ("runtime_pipeline_complete",):
            record = fixtures()["run-manifest"]
            record[field] = True
            bad.append(("run-manifest", record))
        record = fixtures()["release-decision"]
        record["reference_eligible"] = True
        bad.append(("release-decision", record))
        for kind, record in fixtures().items():
            bad.append((kind, {**record, "source_dirty": 0}))
        record = fixtures()["inventory"]
        record["targets"][0]["ssh_port"] = True
        bad.append(("inventory", record))
        record = fixtures()["test-results"]
        record["checks"][0]["required"] = 1
        bad.append(("test-results", record))
        for kind, record in bad:
            with self.subTest(kind=kind, record=record), self.assertRaises(ContractError):
                validate_artifact(kind, record)

    def test_identities_paths_and_dates_reject_traversal_and_wrong_formats(self):
        for field, values in {
            "run_id": ["../escape", "12345678-1234-4234-9234-123456789ABC", "x" * 36],
            "source_revision": ["a" * 39, "A" * 40, "../" + "a" * 37, "a" * 40 + "\n"],
            "created_at": ["2026-02-30T03:00:00Z", "2026-10-23", "2026-10-23T03:00:00+00:00"],
        }.items():
            for value in values:
                record = fixtures()["run-manifest"]
                record[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                    validate_artifact("run-manifest", record)
        for value in ("../private", "/etc/passwd", "C:/private", "C:\\private", "a/../b", "a//b",
                      "a/./b", "https://example.invalid/x", "file:///x", "a/%2e%2e/b", "a\n", "a\x00b", "a/", "\\\\server\\share"):
            record = fixtures()["run-manifest"]
            record["stages"][0]["outputs"] = [value]
            with self.subTest(path=value), self.assertRaises(ContractError):
                validate_artifact("run-manifest", record)
        for host in ("https://example.invalid", "user@host", "host/path", "a..b", "127.0.0.1\n", "-bad"):
            record = fixtures()["inventory"]
            record["targets"][0]["host"] = host
            with self.subTest(host=host), self.assertRaises(ContractError):
                validate_artifact("inventory", record)

    def test_malformed_nested_records_and_unsupported_enums_are_rejected(self):
        for kind, collection, changes in (
            ("inventory", "targets", {"target_id": "../target"}),
            ("inventory", "targets", {"ssh_port": 0}),
            ("inventory", "targets", {"image_digest": "latest"}),
            ("test-results", "checks", {"status": "green"}),
            ("test-results", "checks", {"observed": {"untrusted": "object"}}),
            ("svd", "targets", {"packages": [{"name": "missing-version"}]}),
            ("assessment", "findings", {"status": "Accepted"}),
            ("run-manifest", "stages", {"private_key": "synthetic-not-a-key"}),
        ):
            record = fixtures()[kind]
            record[collection][0].update(changes)
            with self.subTest(kind=kind, changes=changes), self.assertRaises(ContractError):
                validate_artifact(kind, record)

    def test_numeric_and_collection_bounds_are_enforced(self):
        for field, values in {"timeout_seconds": [0, -1, 3601, float("nan"), float("inf")],
                              "duration_seconds": [-1, 86401], "returncode": [1.5, 2**31],
                              "log_bytes": [-1, 65537]}.items():
            for value in values:
                record = fixtures()["run-manifest"]
                record["stages"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                    validate_artifact("run-manifest", record)
        record = fixtures()["inventory"]
        record["targets"] *= 101
        with self.assertRaises(ContractError):
            validate_artifact("inventory", record)
        with self.assertRaises(ContractError):
            validate_artifact("release-decision", {**fixtures()["release-decision"], "reasons": []})

    def test_duplicate_stage_target_check_and_finding_identities_are_rejected(self):
        for kind, field in (("run-manifest", "stages"), ("inventory", "targets"),
                            ("test-results", "checks"), ("svd", "targets"), ("assessment", "findings")):
            record = fixtures()[kind]
            record[field].append(deepcopy(record[field][0]))
            # Distinct observations must not make a duplicate identity acceptable.
            if kind == "test-results":
                record[field][1]["observed"] = "different observation"
            with self.subTest(kind=kind), self.assertRaises(ContractError):
                validate_artifact(kind, record)
        record = fixtures()["run-manifest"]
        record["expected_checks"] *= 2
        with self.assertRaises(ContractError):
            validate_artifact("run-manifest", record)

    def test_payload_depth_non_json_and_cyclic_input_fail_safely(self):
        record = fixtures()["test-results"]
        record["unknown"] = "x" * (MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(ContractError) as error:
            validate_artifact("test-results", record)
        self.assertEqual(error.exception.code, "ARTIFACT_LIMIT")
        for value in (None, [], "not an object"):
            with self.assertRaises(ContractError):
                validate_artifact("inventory", value)
        for value in (b"bytes", {"set"}, ("tuple",), "\ud800", 2**100):
            with self.subTest(type=type(value).__name__), self.assertRaises(ContractError):
                validate_artifact("inventory", {**fixtures()["inventory"], "unknown": value})
        cyclic = {}
        cyclic["self"] = cyclic
        with self.assertRaises(ContractError):
            validate_artifact("inventory", cyclic)
        nested = None
        for _ in range(18):
            nested = [nested]
        with self.assertRaises(ContractError):
            validate_artifact("inventory", {**fixtures()["inventory"], "unknown": nested})
        with self.assertRaises(ContractError):
            validate_artifact("inventory", {1: "non-string-key"})


if __name__ == "__main__":
    unittest.main()
