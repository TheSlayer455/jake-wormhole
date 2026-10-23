"""Bounded validation for Wormhole's six built-in artifact contracts.

The published JSON Schemas are generated from these definitions. This is a
validator for these fixed contracts, not a general-purpose JSON Schema engine.
The x-uniqueBy extension and encoded-size/depth limits are enforced here too.
Validation never reads a path, resolves a hostname or performs an external call.
"""

from copy import deepcopy
from datetime import datetime
import ipaddress
import json
import math
import re
from uuid import UUID


MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 20000
KINDS = (
    "run-manifest", "inventory", "test-results", "svd", "assessment",
    "release-decision",
)


class ContractError(ValueError):
    """Safe diagnostics contain contract locations, never submitted values."""

    def __init__(self, message, *, code="INVALID_ARTIFACT", path="$"):
        self.code = code
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


def _exact(pattern):
    # The final assertion also rejects a newline after an otherwise valid match.
    return "^(?:" + pattern + r")$(?![\s\S])"


def _text(maximum=4000, minimum=1, **extra):
    return {"type": "string", "minLength": minimum, "maxLength": maximum, **extra}


def _enum(*values):
    return {"type": "string", "enum": list(values)}


def _array(items, maximum, *, unique=False, unique_by=None):
    result = {"type": "array", "items": items, "maxItems": maximum}
    if unique:
        result["uniqueItems"] = True
    if unique_by:
        result["x-uniqueBy"] = unique_by
        result["$comment"] = "Wormhole also rejects duplicate identities named by x-uniqueBy."
    return result


def _object(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def _nullable(schema):
    return {**schema, "type": [schema["type"], "null"]}


_ID = _text(64, pattern=_exact(r"[a-z][a-z0-9_-]{0,63}"))
_SHA256 = _text(64, pattern=_exact(r"[0-9a-f]{64}"))
_IMAGE = _text(71, pattern=_exact(r"sha256:[0-9a-f]{64}"))
_PATH = _text(1024, pattern=_exact(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*"))
_PATHS = _array(_PATH, 32, unique=True)
_STATUS = _enum("pass", "fail", "error", "unsupported", "unverified")
_DATE = _text(32, pattern=_exact(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"), format="date-time")
_FALSE = {"type": "boolean", "const": False}
_COMMON = {
    "schema_version": {"type": "string", "const": "1.0"},
    "run_id": _text(36, format="uuid", pattern=_exact(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    "source_revision": _text(40, pattern=_exact(r"[0-9a-f]{40}")),
    "source_dirty": {"type": "boolean"},
    "mode": _enum("fixture", "container-reference"),
}
_STAGE = _object({
    "name": _ID,
    "inputs": _PATHS,
    "outputs": _PATHS,
    "location": _enum("local", "provisioner", "helper", "target"),
    "timeout_seconds": {"type": "number", "minimum": 0.01, "maximum": 3600},
    "status": _enum("pass", "fail", "error", "timeout", "unsupported"),
    "duration_seconds": {"type": "number", "minimum": 0, "maximum": 86400},
    "returncode": {"type": ["integer", "null"], "minimum": -(2**31), "maximum": 2**31 - 1},
    "log_bytes": {"type": "integer", "minimum": 0, "maximum": 65536},
    "log_truncated": {"type": "boolean"},
    "error": _nullable(_text(2000, 0)),
})
_TARGET = _object({
    "target_id": _ID,
    "resource_id": _text(128, pattern=_exact(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")),
    "host": _text(253, pattern=_exact(r"[A-Za-z0-9:][A-Za-z0-9.:-]{0,252}"), format="host"),
    "ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "ssh_user": _text(32, pattern=_exact(r"[a-z_][a-z0-9_-]{0,31}")),
    "image_digest": _IMAGE,
    "status": _enum("unverified", "created", "started", "tcp-ready", "ssh-ready", "ansible-ready", "failed"),
})
_CHECK = _object({
    "check_id": _ID,
    "target_id": _nullable(_ID),
    "status": _enum("pass", "fail", "error", "unreachable", "skipped", "unverified"),
    "required": {"type": "boolean"},
    "expected": _text(),
    "observed": _text(4000, 0),
    "evidence": _PATHS,
})
_SVD_TARGET = _object({
    "target_id": _ID,
    "os_id": _ID,
    "os_version": _text(128),
    "packages": _array(_object({"name": _text(240), "version": _text(240)}), 4096, unique=True),
    "payload_version": _text(128),
    "image_digest": _IMAGE,
    "candidate_sha256": _SHA256,
    "collector_version": _text(128),
})
_DEFINITIONS = {
    "run-manifest": _object({**_COMMON,
        "profile": _enum("fixture", "smoke", "five-targets", "twenty-targets"),
        "outcome": _enum("running", "passed", "failed", "cleaned"),
        "created_at": _DATE,
        "updated_at": _DATE,
        "expected_checks": _array(_ID, 1000, unique=True),
        "stages": _array(_STAGE, 32, unique_by=["name"]),
        "runtime_pipeline_complete": _FALSE,
        "production_iso_eligible": _FALSE,
    }),
    "inventory": _object({**_COMMON, "status": _STATUS,
        "targets": _array(_TARGET, 100, unique_by=["target_id"])}),
    "test-results": _object({**_COMMON, "status": _STATUS,
        "checks": _array(_CHECK, 1000, unique_by=["check_id", "target_id"])}),
    "svd": _object({**_COMMON, "status": _STATUS,
        "targets": _array(_SVD_TARGET, 100, unique_by=["target_id"])}),
    "assessment": _object({**_COMMON, "status": _STATUS,
        "synthetic": {"type": "boolean", "const": True},
        "policy_id": _text(128, pattern=_exact(r"[a-z][a-z0-9._-]{0,127}")),
        "findings": _array(_object({
            "finding_id": _ID,
            "status": _enum("Open", "Not a Finding", "Not Reviewed", "Not Applicable"),
            "summary": _text(),
        }), 1000, unique_by=["finding_id"])}),
    "release-decision": _object({**_COMMON, "status": _STATUS,
        "reference_eligible": _FALSE,
        "production_iso_eligible": _FALSE,
        "reasons": {**_array(_text(2000), 100, unique=True), "minItems": 1}}),
}


def schema_for(kind):
    """Return an independent, publishable schema for one built-in artifact."""
    if not isinstance(kind, str) or kind not in _DEFINITIONS:
        raise ContractError("Unsupported artifact kind.", code="UNSUPPORTED_ARTIFACT")
    return deepcopy({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:jake-wormhole:schema:{kind}:1.0",
        "title": f"Jake Wormhole {kind} v1",
        "$comment": "Generated from wormhole/contracts.py. Fixed-contract validation also enforces x-uniqueBy and the declared size/depth bounds; schema validity alone is not runtime acceptance or release eligibility. Version 1 cannot declare a complete runtime pipeline or an eligible release.",
        "x-maxEncodedBytes": MAX_ARTIFACT_BYTES,
        "x-maxDepth": MAX_DEPTH,
        **_DEFINITIONS[kind],
    })


def _bounded_json(value):
    remaining = MAX_NODES
    text_bytes = 0
    active = set()

    def visit(item, depth):
        nonlocal remaining, text_bytes
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            raise ContractError("Artifact structural bound exceeded.", code="ARTIFACT_LIMIT")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_ARTIFACT_BYTES:
                raise ContractError("Artifact exceeds its encoded-size limit.", code="ARTIFACT_LIMIT")
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                raise ContractError("Artifact contains invalid Unicode.") from None
            if text_bytes > MAX_ARTIFACT_BYTES:
                raise ContractError("Artifact exceeds its encoded-size limit.", code="ARTIFACT_LIMIT")
        elif kind in (list, dict):
            if len(item) > (64 if kind is dict else 4096) or id(item) in active:
                raise ContractError("Artifact collection is excessive or cyclic.", code="ARTIFACT_LIMIT")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ContractError("Object keys must be strings.")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            active.remove(id(item))
        elif kind is float:
            if not math.isfinite(item):
                raise ContractError("Numbers must be finite.")
        elif kind is int:
            if item.bit_length() > 63:
                raise ContractError("Integer bound exceeded.", code="ARTIFACT_LIMIT")
        elif item is not None and kind is not bool:
            raise ContractError("Artifact must contain only JSON values.")

    visit(value, 0)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ContractError("Artifact exceeds its encoded-size limit.", code="ARTIFACT_LIMIT")


def _matches_type(value, expected):
    return {
        "object": type(value) is dict, "array": type(value) is list,
        "string": type(value) is str, "integer": type(value) is int,
        "number": type(value) in (int, float), "boolean": type(value) is bool,
        "null": value is None,
    }[expected]


def _validate(schema, value, path):
    expected = schema["type"]
    types = expected if isinstance(expected, list) else [expected]
    if not any(_matches_type(value, item) for item in types):
        raise ContractError("Incorrect value type.", path=path)
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise ContractError("Required constant does not match.", path=path)
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError("Unsupported enumerated value.", path=path)
    if value is None:
        return
    if type(value) is dict:
        properties = schema["properties"]
        if set(value) - set(properties):
            raise ContractError("Unknown fields are not accepted.", path=path)
        for key in schema["required"]:
            if key not in value:
                raise ContractError("Required field is missing.", path=f"{path}.{key}")
        for key, child in value.items():
            _validate(properties[key], child, f"{path}.{key}")
    elif type(value) is list:
        if not schema.get("minItems", 0) <= len(value) <= schema["maxItems"]:
            raise ContractError("Collection length is outside its bound.", path=path)
        identities = set()
        for index, child in enumerate(value):
            _validate(schema["items"], child, f"{path}[{index}]")
            if schema.get("uniqueItems"):
                identity = json.dumps(child, sort_keys=True, ensure_ascii=False)
            elif schema.get("x-uniqueBy"):
                identity = tuple(child[key] for key in schema["x-uniqueBy"])
            else:
                continue
            if identity in identities:
                raise ContractError("Duplicate identity or item.", path=path)
            identities.add(identity)
    elif type(value) is str:
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", MAX_ARTIFACT_BYTES):
            raise ContractError("Text length is outside its bound.", path=path)
        if "pattern" in schema and not re.search(schema["pattern"], value, re.ASCII):
            raise ContractError("Invalid identity or portable relative path.", path=path)
        try:
            if schema.get("format") == "uuid" and str(UUID(value)) != value:
                raise ValueError
            if schema.get("format") == "date-time":
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            if schema.get("format") == "host":
                # Docker target addresses need no interface scope. ipaddress
                # otherwise accepts arbitrary scope text after a percent sign.
                if "%" in value:
                    raise ValueError
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    if len(value) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in value.split(".")):
                        raise ValueError
        except ValueError:
            raise ContractError("Invalid formatted identity.", path=path) from None
    elif type(value) in (int, float):
        if value < schema["minimum"] or value > schema["maximum"]:
            raise ContractError("Number is outside its bound.", path=path)


def validate_artifact(kind: str, value: dict) -> None:
    """Validate a built-in v1 record without mutating it or accessing resources.

    Passing this structural check does not prove expected-check completeness,
    current evidence, real execution, trusted identity or Minx acceptance. The
    run verifier/gate must check cross-artifact identities and the declared plan.
    """
    if not isinstance(kind, str) or kind not in _DEFINITIONS:
        raise ContractError("Unsupported artifact kind.", code="UNSUPPORTED_ARTIFACT")
    if type(value) is not dict:
        raise ContractError("Artifact must be an object.")
    _bounded_json(value)
    if "schema_version" in value and value["schema_version"] != "1.0":
        raise ContractError("Unsupported schema version.", code="UNSUPPORTED_SCHEMA")
    _validate(_DEFINITIONS[kind], value, "$")
