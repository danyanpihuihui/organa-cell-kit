from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MODE = "three-wallet-three-bitmap-same-controller-local-pilot"
TWO_ROLE_MODE = "two-role-requester-worker-same-controller-pilot"
CLAIMS_SCOPE = {"independent_controller": False, "external_adoption": False, "real_payment": False}
ROLE_NAMES = ("requester", "worker", "verifier")
TWO_ROLE_NAMES = ("requester", "worker")
ROLE_KEYS = {"agent_id", "cell_coordinate", "controller_address", "artifact_signing_algorithm", "artifact_signing_public_key", "wallet_identity_claim"}
TWO_ROLE_KEYS = {"agent_id", "cell_coordinate", "controller_address", "wallet_identity_claim", "provenance"}
PLACEHOLDER_MARKERS = ("REQUIRED", "PLACEHOLDER", "REPLACE_ME", "example.invalid", "<")
KNOWN_TWO_ROLE_MAPPING = {
    "requester": {"agent_id": "dq", "cell_coordinate": "7187.bitmap", "controller_address": "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq", "provenance": "existing public 7187 claim"},
    "worker": {"agent_id": "n6", "cell_coordinate": "720202.bitmap", "controller_address": "bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6", "provenance": "existing public 720202 claim"},
}


class IdentityPilotError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IdentityPilotError("strict JSON artifact required") from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_loads(raw: str, label: str) -> Any:
    try:
        return json.loads(raw, parse_constant=_reject_json_constant, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise IdentityPilotError(f"invalid {label}: {exc}") from exc


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: dict, *, immutable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if immutable and path.exists():
        if path.read_text(encoding="utf-8-sig") != data:
            raise IdentityPilotError(f"immutable identity artifact changed: {path}")
        return
    path.write_text(data, encoding="utf-8")
    if immutable:
        path.chmod(0o444)


def _placeholder(value: str) -> bool:
    return any(marker.lower() in value.lower() for marker in PLACEHOLDER_MARKERS)


def _validate_common(config: dict, roles: tuple[str, ...], role_keys: set[str]) -> None:
    if config.get("claims_scope") != CLAIMS_SCOPE:
        raise IdentityPilotError("claims_scope must keep all three claims false")
    seen_coords, seen_addresses, seen_agents = set(), set(), set()
    for role in roles:
        item = config[role]
        if not isinstance(item, dict) or set(item) != role_keys:
            raise IdentityPilotError(f"closed {role} role schema required")
        for field in ("agent_id", "cell_coordinate", "controller_address"):
            value = item[field]
            if not isinstance(value, str) or not value.strip():
                raise IdentityPilotError(f"{role}.{field} required")
            if _placeholder(value):
                raise IdentityPilotError(f"placeholder remains for {role}.{field}")
        if "provenance" in item and _placeholder(item["provenance"]):
            raise IdentityPilotError(f"placeholder remains for {role}.provenance")
        if role == "verifier" or "artifact_signing_algorithm" in item:
            if _placeholder(item["artifact_signing_public_key"]) or not isinstance(item["artifact_signing_public_key"], str):
                raise IdentityPilotError(f"placeholder remains for {role}.artifact_signing_public_key")
            if item["artifact_signing_algorithm"] != "Ed25519":
                raise IdentityPilotError("artifact signing algorithm must be Ed25519")
        if item["wallet_identity_claim"] != "human-wallet-bip322-simple-message":
            raise IdentityPilotError("wallet identity claim must be BIP-322 Simple")
        coord = item["cell_coordinate"]
        if not coord.endswith(".bitmap") or not coord[:-7].isdigit() or coord.startswith("0"):
            raise IdentityPilotError(f"invalid {role} Bitmap coordinate")
        if coord in seen_coords or item["controller_address"] in seen_addresses or item["agent_id"] in seen_agents:
            raise IdentityPilotError("role coordinates, addresses, and agent IDs must be distinct")
        seen_coords.add(coord); seen_addresses.add(item["controller_address"]); seen_agents.add(item["agent_id"])


def _validate(config: dict) -> None:
    mode = config.get("mode")
    if mode == MODE:
        if set(config) != {"mode", "pilot_id", "claims_scope", *ROLE_NAMES}:
            raise IdentityPilotError("closed pilot config schema")
        _validate_common(config, ROLE_NAMES, ROLE_KEYS)
        return
    if mode == TWO_ROLE_MODE:
        if set(config) != {"mode", "pilot_id", "claims_scope", *TWO_ROLE_NAMES, "verifier_status"}:
            raise IdentityPilotError("closed two-role pilot config schema")
        if config["verifier_status"] != "pending-registration":
            raise IdentityPilotError("verifier status must remain pending-registration")
        for role in TWO_ROLE_NAMES:
            item = config[role]
            if any(_placeholder(str(item.get(field, ""))) for field in TWO_ROLE_KEYS):
                raise IdentityPilotError(f"placeholder remains for {role}")
        for role in TWO_ROLE_NAMES:
            expected = KNOWN_TWO_ROLE_MAPPING[role]
            if any(config[role].get(field) != value for field, value in expected.items()):
                raise IdentityPilotError(f"{role} does not match known public mapping")
        _validate_common(config, TWO_ROLE_NAMES, TWO_ROLE_KEYS)
        return
    raise IdentityPilotError("invalid pilot mode")


def identity_message(pilot_id: str, role: str, item: dict, document_hash: str, *, mode: str = MODE) -> str:
    prefix = "Organa two-role Requester/Worker same-controller pilot identity binding v0.1" if mode == TWO_ROLE_MODE else "Organa three-wallet three-Bitmap same-controller local pilot identity binding v0.1"
    extra = f"Provenance: {item['provenance']}\n" if "provenance" in item else f"Artifact signing algorithm: {item['artifact_signing_algorithm']}\nArtifact signing public key: {item['artifact_signing_public_key']}\n"
    return (f"{prefix}\nPilot ID: {pilot_id}\nRole: {role}\nAgent ID: {item['agent_id']}\n"
            f"Bitmap coordinate: {item['cell_coordinate']}\nBitcoin controller address: {item['controller_address']}\n{extra}"
            f"Canonical identity document SHA-256: {document_hash}\n"
            "Safety: This is a message signature only; no transfer, no transaction, PSBT, spending authorization, fee, or miner payment.")


def _verify_bip322(address: str, message: str, signature: str) -> tuple[bool, str]:
    if not isinstance(signature, str) or not signature.strip() or _placeholder(signature) or signature in {"NOT_A_BIP322_SIGNATURE", "test-bip322-signature"}:
        return False, "empty or placeholder BIP-322 signature"
    node = shutil.which("node")
    script = Path(__file__).resolve().parents[2] / "scripts" / "verify_bip322.js"
    if not node or not script.is_file():
        return False, "BIP-322 verifier unavailable"
    try:
        proc = subprocess.run([node, str(script)], input=json.dumps({"signing_address": address, "message": message, "signature": signature}), text=True, capture_output=True, timeout=20)
        result = _strict_json_loads(proc.stdout or "{}", "BIP-322 verifier response")
        return proc.returncode == 0 and result.get("ok") is True, result.get("error", "invalid BIP-322 signature")
    except Exception as exc:
        return False, str(exc)


def _prepare_two_role(root: Path, config: dict) -> dict:
    roles = {}
    for role in TWO_ROLE_NAMES:
        item = config[role]
        doc = {"schema_version": "organa-pilot-two-role-identity-document-v0.1", "mode": TWO_ROLE_MODE, "pilot_id": config["pilot_id"], "role": role, **item, "safety": "no transfer, transaction, PSBT, spending authorization, fee, or miner payment"}
        doc_hash = _sha(_canonical(doc))
        role_dir = root / "identity" / role
        _write_json(role_dir / "identity-document.json", doc, immutable=True)
        message = identity_message(config["pilot_id"], role, item, doc_hash, mode=TWO_ROLE_MODE)
        request = {"schema_version": "organa-pilot-two-role-bip322-signature-request-v0.1", "pilot_id": config["pilot_id"], "mode": TWO_ROLE_MODE, "role": role, "agent_id": item["agent_id"], "cell_coordinate": item["cell_coordinate"], "controller_address": item["controller_address"], "provenance": item["provenance"], "message_encoding": "UTF-8", "message": message, "message_sha256": _sha(message.encode()), "status": "awaiting-human-signature", "safety_notice": "Human wallet signing only; no computer-use wallet confirmation and no transaction."}
        _write_json(role_dir / "signature-request.json", request, immutable=True)
        roles[role] = {"identity_document_sha256": doc_hash, "message": message, "signature_request": request}
    worksheet = {"schema_version": "organa-pilot-verifier-pending-worksheet-v0.1", "pilot_id": config["pilot_id"], "status": "pending-registration", "note": "Verifier intentionally deferred; do not consume or claim a verifier address until human registration is complete."}
    _write_json(root / "identity" / "verifier-pending-worksheet.json", worksheet, immutable=True)
    result = {"schema_version": "organa-pilot-two-role-identity-preparation-v0.1", "mode": TWO_ROLE_MODE, "pilot_id": config["pilot_id"], "claims_scope": CLAIMS_SCOPE, "status": "awaiting-human-signature-and-verifier-registration", "production_ready": False, "settled": False, "roles": roles, "verifier": {"status": "pending-registration", "worksheet": str(root / "identity" / "verifier-pending-worksheet.json")}}
    _write_json(root / "identity" / "identity-preparation.json", result, immutable=True)
    return result


def prepare_identity(root: Path, config: dict) -> dict:
    _validate(config)
    root = _safe_root(root)
    if config["mode"] == TWO_ROLE_MODE:
        return _prepare_two_role(root, config)
    roles = {}
    for role in ROLE_NAMES:
        item = config[role]
        role_dir = root / "identity" / role
        doc = {"schema_version": "organa-pilot-identity-document-v0.1", "mode": MODE, "pilot_id": config["pilot_id"], "role": role, **item, "safety": "no transfer, transaction, PSBT, spending authorization, fee, or miner payment"}
        doc_hash = _sha(_canonical(doc))
        _write_json(role_dir / "identity-document.json", doc, immutable=True)
        message = identity_message(config["pilot_id"], role, item, doc_hash)
        request = {"schema_version": "organa-pilot-bip322-signature-request-v0.1", "pilot_id": config["pilot_id"], "mode": MODE, "role": role, "controller_address": item["controller_address"], "message_encoding": "UTF-8", "message": message, "message_sha256": _sha(message.encode()), "status": "awaiting-human-signature", "safety_notice": "Human wallet signing only; no computer-use wallet confirmation and no transaction."}
        _write_json(role_dir / "signature-request.json", request, immutable=True)
        roles[role] = {"identity_document_sha256": doc_hash, "message": message, "signature_request": request}
    result = {"schema_version": "organa-pilot-identity-preparation-v0.1", "mode": MODE, "pilot_id": config["pilot_id"], "claims_scope": CLAIMS_SCOPE, "status": "awaiting-human-signature", "roles": roles}
    _write_json(root / "identity" / "identity-preparation.json", result, immutable=True)
    return result


def record_identity_signature(root: Path, role: str, signature: str, *, expected_role: str | None = None) -> dict:
    if role not in ROLE_NAMES:
        raise IdentityPilotError("unknown role")
    if expected_role is not None and expected_role != role:
        raise IdentityPilotError("role mismatch")
    root = _safe_root(root, create=False)
    request = _strict_json_file(root / "identity" / role / "signature-request.json", "signature request")
    ok, error = _verify_bip322(request["controller_address"], request["message"], signature)
    if not ok:
        raise IdentityPilotError("BIP-322 signature invalid: " + error)
    claim = {"schema_version": "organa-pilot-bip322-identity-claim-v0.1", "pilot_id": request["pilot_id"], "mode": request["mode"], "role": role, "controller_address": request["controller_address"], "message": request["message"], "message_sha256": request["message_sha256"], "signature": signature, "status": "signed"}
    _write_json(root / "identity" / role / "identity-claim.json", claim, immutable=True)
    return {"ok": True, "role": role, "status": "signed", "claim_path": str(root / "identity" / role / "identity-claim.json")}


ARTIFACT_AUTHORITY = {
    "json_artifact_signing": True,
    "bitcoin_payment": False,
    "bitcoin_spending": False,
    "transaction": False,
    "psbt": False,
    "fee": False,
    "miner_payment": False,
}
ARTIFACT_KEY_KEYS = {
    "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
    "algorithm", "public_key_encoding", "public_key", "status",
}
IDENTITY_CLAIM_KEYS = {
    "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
    "controller_address", "message", "message_sha256", "signature", "status",
}
COMPACT_IDENTITY_CLAIM_KEYS = IDENTITY_CLAIM_KEYS - {"agent_id", "cell_coordinate"} | {"mode"}
VERIFIER_IDENTITY_CLAIM_KEYS = IDENTITY_CLAIM_KEYS | {"claims_scope"}
AUTH_REQUEST_KEYS = {
    "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
    "controller_address", "artifact_signing_algorithm", "artifact_signing_public_key",
    "identity_claim_sha256", "message_encoding", "message", "message_sha256",
    "authority", "status", "safety_notice",
}
AUTH_CLAIM_KEYS = AUTH_REQUEST_KEYS - {"message_encoding", "safety_notice"} | {"signature"}
SIGNED_ARTIFACT_KEYS = {
    "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
    "algorithm", "public_key", "authorization_sha256", "payload",
    "payload_sha256", "signature",
}
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _require_closed(value: Any, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise IdentityPilotError(f"closed {label} schema required")
    return value


def _require_safe_token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_TOKEN.fullmatch(value) or value in {".", ".."}:
        raise IdentityPilotError(f"unsafe {label}")
    return value


def _safe_root(root: Path, *, create: bool = True) -> Path:
    supplied = Path(root).absolute()
    for candidate in (supplied, *supplied.parents):
        if candidate.exists() and candidate.is_symlink():
            raise IdentityPilotError("identity root cannot use symlink ancestors")
    if supplied.is_symlink():
        raise IdentityPilotError("identity root cannot use symlinks")
    if create:
        supplied.mkdir(parents=True, exist_ok=True)
    root = supplied.resolve()
    if not root.is_dir():
        raise IdentityPilotError("identity root must be a safe directory")
    return root


def _safe_regular(path: Path, label: str) -> Path:
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise IdentityPilotError(f"{label} must be a safe regular file without symlinks")
    if not path.is_file():
        raise IdentityPilotError(f"{label} must be a safe regular file without symlinks")
    return path


def _strict_json_file(path: Path, label: str) -> Any:
    path = _safe_regular(path, label)
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise IdentityPilotError(f"invalid {label}") from exc
    return _strict_json_loads(raw, label)


def _read_closed_json(path: Path, keys: set[str], label: str) -> dict:
    value = _strict_json_file(path, label)
    return _require_closed(value, keys, label)


def _immutable_json(path: Path, value: dict) -> None:
    path = Path(path).absolute()
    if path.is_symlink() or path.parent.is_symlink():
        raise IdentityPilotError("immutable identity artifact path cannot use symlinks")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise IdentityPilotError("immutable identity artifact path cannot use symlinks")
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_text(encoding="utf-8-sig") != data:
            raise IdentityPilotError(f"immutable identity artifact changed: {path}")
        path.chmod(0o444)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o444)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    path.chmod(0o444)


def _raw_public_key(private_key: Ed25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(public).decode("ascii")


def _decode_canonical_base64(value: Any, *, decoded_length: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise IdentityPilotError(f"invalid {label}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise IdentityPilotError(f"invalid {label}") from exc
    if len(decoded) != decoded_length or base64.b64encode(decoded).decode("ascii") != value:
        raise IdentityPilotError(f"invalid {label}")
    return decoded


def _assert_no_symlink_components(root: Path, relative: Path, label: str) -> None:
    current = Path(root).absolute()
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise IdentityPilotError(f"{label} path cannot use symlinks")


def _key_path(root: Path, role: str) -> Path:
    return root / ".private" / "artifact-keys" / f"{role}.ed25519"


def _public_key_path(root: Path, role: str) -> Path:
    return root / "identity" / role / "artifact-key.json"


def generate_artifact_key(root: Path, *, pilot_id: str, role: str, agent_id: str, cell_coordinate: str, controller_address: str) -> dict:
    del controller_address  # Wallet identity belongs in authorization artifacts, not the operational public-key artifact.
    root = _safe_root(root)
    role = _require_safe_token(role, "role")
    if role not in ROLE_NAMES:
        raise IdentityPilotError("unknown role")
    _require_safe_token(pilot_id, "pilot_id")
    _require_safe_token(agent_id, "agent_id")
    if not isinstance(cell_coordinate, str) or not cell_coordinate.endswith(".bitmap") or not cell_coordinate[:-7].isdigit():
        raise IdentityPilotError("invalid Bitmap coordinate")
    _assert_no_symlink_components(root, Path(".private") / "artifact-keys", "private artifact key")
    _assert_no_symlink_components(root, Path("identity") / role, "public artifact key")
    private_path = _key_path(root, role)
    public_path = _public_key_path(root, role)
    if private_path.exists() or private_path.is_symlink() or public_path.exists() or public_path.is_symlink():
        private_path = _safe_regular(private_path, "private artifact key")
        if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
            raise IdentityPilotError("private artifact key permissions must be 0600")
        key = Ed25519PrivateKey.from_private_bytes(private_path.read_bytes())
        expected = {
            "schema_version": "organa-artifact-operational-key-v0.1",
            "pilot_id": pilot_id, "role": role, "agent_id": agent_id,
            "cell_coordinate": cell_coordinate, "algorithm": "Ed25519",
            "public_key_encoding": "base64-raw-32", "public_key": _raw_public_key(key),
            "status": "awaiting-wallet-authorization",
        }
        existing = _read_closed_json(public_path, ARTIFACT_KEY_KEYS, "artifact key")
        if existing != expected:
            raise IdentityPilotError(f"immutable identity artifact changed: {public_path}")
        public_path.chmod(0o444)
        return existing
    private_parent = private_path.parent
    private_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_parent.chmod(0o700)
    private_parent.parent.chmod(0o700)
    if private_parent.is_symlink():
        raise IdentityPilotError("private artifact key path cannot use symlinks")
    key = Ed25519PrivateKey.generate()
    raw_private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(private_path, flags, 0o600)
    try:
        os.write(fd, raw_private)
        os.fsync(fd)
    finally:
        os.close(fd)
    private_path.chmod(0o600)
    artifact = {
        "schema_version": "organa-artifact-operational-key-v0.1",
        "pilot_id": pilot_id, "role": role, "agent_id": agent_id,
        "cell_coordinate": cell_coordinate, "algorithm": "Ed25519",
        "public_key_encoding": "base64-raw-32", "public_key": _raw_public_key(key),
        "status": "awaiting-wallet-authorization",
    }
    _immutable_json(public_path, artifact)
    return artifact


def _normalize_identity_claim(value: Any, artifact_key: dict) -> dict:
    if not isinstance(value, dict):
        raise IdentityPilotError("closed existing wallet identity claim schema required")
    keys = set(value)
    if keys == IDENTITY_CLAIM_KEYS:
        return dict(value)
    if keys == COMPACT_IDENTITY_CLAIM_KEYS:
        if value.get("mode") != TWO_ROLE_MODE:
            raise IdentityPilotError("unsupported existing wallet identity claim mode")
        normalized = {key: item for key, item in value.items() if key != "mode"}
        normalized["agent_id"] = artifact_key["agent_id"]
        normalized["cell_coordinate"] = artifact_key["cell_coordinate"]
        return normalized
    if keys == VERIFIER_IDENTITY_CLAIM_KEYS:
        if value.get("claims_scope") != CLAIMS_SCOPE:
            raise IdentityPilotError("existing wallet identity claim scope is invalid")
        return {key: item for key, item in value.items() if key != "claims_scope"}
    raise IdentityPilotError("closed existing wallet identity claim schema required")


def _identity_claim_hash(claim: dict) -> str:
    return _sha(_canonical(claim))


def _artifact_authorization_message(fields: dict) -> str:
    return (
        "Organa Ed25519 JSON Artifact operational-key authorization v0.1\n"
        f"Pilot ID: {fields['pilot_id']}\nRole: {fields['role']}\nAgent ID: {fields['agent_id']}\n"
        f"Bitmap coordinate: {fields['cell_coordinate']}\nBitcoin controller address: {fields['controller_address']}\n"
        f"Existing wallet identity claim SHA-256: {fields['identity_claim_sha256']}\n"
        f"Artifact signing algorithm: {fields['artifact_signing_algorithm']}\nArtifact signing public key: {fields['artifact_signing_public_key']}\n"
        "Authority: authorize only this role-bound key to sign JSON artifacts for this pilot.\n"
        "No payment authority: no Bitcoin payment, spending, transfer, transaction, PSBT, fee, or miner payment."
    )


def _validate_authorization_request(request: dict, *, expected_role: str | None = None) -> None:
    if request["schema_version"] != "organa-artifact-key-authorization-request-v0.1":
        raise IdentityPilotError("unsupported artifact authorization request schema")
    if expected_role is not None and request["role"] != expected_role:
        raise IdentityPilotError("artifact authorization request role mismatch")
    if request["artifact_signing_algorithm"] != "Ed25519" or request["authority"] != ARTIFACT_AUTHORITY:
        raise IdentityPilotError("artifact authorization request authority is invalid")
    if request["status"] != "awaiting-human-signature" or request["message_encoding"] != "UTF-8":
        raise IdentityPilotError("artifact authorization request status is invalid")
    expected_message = _artifact_authorization_message(request)
    if request["message"] != expected_message or request["message_sha256"] != _sha(expected_message.encode("utf-8")):
        raise IdentityPilotError("artifact authorization request binding is invalid")


def create_artifact_authorization_request(root: Path, *, identity_claim: dict, artifact_key: dict) -> dict:
    root = _safe_root(root)
    key = _require_closed(artifact_key, ARTIFACT_KEY_KEYS, "artifact key")
    original_claim = identity_claim
    claim = _normalize_identity_claim(identity_claim, key)
    if claim["status"] != "signed" or claim["message_sha256"] != _sha(claim["message"].encode("utf-8")):
        raise IdentityPilotError("existing wallet identity claim is invalid")
    ok, error = _verify_bip322(claim["controller_address"], claim["message"], claim["signature"])
    if not ok:
        raise IdentityPilotError("existing wallet identity claim is invalid: " + error)
    binding_fields = ("pilot_id", "role", "agent_id", "cell_coordinate")
    if any(claim[field] != key[field] for field in binding_fields):
        raise IdentityPilotError("existing wallet identity role/key binding mismatch")
    if key["algorithm"] != "Ed25519" or key["status"] != "awaiting-wallet-authorization":
        raise IdentityPilotError("artifact key is not eligible for authorization")
    _decode_canonical_base64(key["public_key"], decoded_length=32, label="artifact signing public key")
    claim_hash = _identity_claim_hash(original_claim)
    _immutable_json(root / "identity" / claim["role"] / "identity-claim.json", original_claim)
    request_fields = {
        "pilot_id": claim["pilot_id"], "role": claim["role"], "agent_id": claim["agent_id"],
        "cell_coordinate": claim["cell_coordinate"], "controller_address": claim["controller_address"],
        "artifact_signing_algorithm": "Ed25519", "artifact_signing_public_key": key["public_key"],
        "identity_claim_sha256": claim_hash,
    }
    message = _artifact_authorization_message(request_fields)
    request = {
        "schema_version": "organa-artifact-key-authorization-request-v0.1",
        **request_fields, "message_encoding": "UTF-8",
        "message": message, "message_sha256": _sha(message.encode("utf-8")),
        "authority": ARTIFACT_AUTHORITY, "status": "awaiting-human-signature",
        "safety_notice": "Human wallet message signing only; no payment, transaction, PSBT, fee, miner payment, or computer-use wallet confirmation.",
    }
    _immutable_json(root / "identity" / claim["role"] / "artifact-authorization-request.json", request)
    return request


def record_artifact_authorization(root: Path, role: str, signature: str) -> dict:
    root = _safe_root(root)
    role = _require_safe_token(role, "role")
    request = _read_closed_json(root / "identity" / role / "artifact-authorization-request.json", AUTH_REQUEST_KEYS, "artifact authorization request")
    _validate_authorization_request(request, expected_role=role)
    ok, error = _verify_bip322(request["controller_address"], request["message"], signature)
    if not ok:
        raise IdentityPilotError("BIP-322 artifact authorization invalid: " + error)
    claim = {key: value for key, value in request.items() if key not in {"message_encoding", "safety_notice"}}
    claim["schema_version"] = "organa-artifact-key-authorization-v0.1"
    claim["signature"] = signature
    claim["status"] = "authorized"
    _immutable_json(root / "identity" / role / "artifact-authorization.json", claim)
    return claim


def verify_artifact_authorization(path: Path) -> bool:
    try:
        path = Path(path).absolute()
        claim = _read_closed_json(path, AUTH_CLAIM_KEYS, "artifact authorization")
        request = _read_closed_json(path.with_name("artifact-authorization-request.json"), AUTH_REQUEST_KEYS, "artifact authorization request")
        original_identity_claim = _strict_json_file(path.with_name("identity-claim.json"), "identity claim")
        normalized_identity_claim = _normalize_identity_claim(original_identity_claim, {
            "schema_version": "organa-artifact-operational-key-v0.1",
            "pilot_id": claim["pilot_id"], "role": claim["role"], "agent_id": claim["agent_id"],
            "cell_coordinate": claim["cell_coordinate"], "algorithm": "Ed25519",
            "public_key_encoding": "base64-raw-32", "public_key": claim["artifact_signing_public_key"],
            "status": "awaiting-wallet-authorization",
        })
        if claim["identity_claim_sha256"] != _identity_claim_hash(original_identity_claim):
            return False
        if any(normalized_identity_claim[field] != claim[field] for field in ("pilot_id", "role", "agent_id", "cell_coordinate", "controller_address")):
            return False
        if normalized_identity_claim["status"] != "signed" or normalized_identity_claim["message_sha256"] != _sha(normalized_identity_claim["message"].encode("utf-8")):
            return False
        identity_ok, _ = _verify_bip322(normalized_identity_claim["controller_address"], normalized_identity_claim["message"], normalized_identity_claim["signature"])
        if not identity_ok:
            return False
        _validate_authorization_request(request, expected_role=claim["role"])
        expected = {key: value for key, value in request.items() if key not in {"message_encoding", "safety_notice"}}
        expected["schema_version"] = "organa-artifact-key-authorization-v0.1"
        expected["signature"] = claim["signature"]
        expected["status"] = "authorized"
        if claim != expected or claim["authority"] != ARTIFACT_AUTHORITY:
            return False
        ok, _ = _verify_bip322(claim["controller_address"], claim["message"], claim["signature"])
        return ok
    except (IdentityPilotError, KeyError, TypeError):
        return False


def _authorization_hash(authorization: dict) -> str:
    return _sha(_canonical(authorization))


def sign_json_artifact(root: Path, *, role: str, payload: dict) -> dict:
    root = _safe_root(root)
    role = _require_safe_token(role, "role")
    auth_path = root / "identity" / role / "artifact-authorization.json"
    if not verify_artifact_authorization(auth_path):
        raise IdentityPilotError("valid human artifact authorization required")
    authorization = _read_closed_json(auth_path, AUTH_CLAIM_KEYS, "artifact authorization")
    key_artifact = _read_closed_json(_public_key_path(root, role), ARTIFACT_KEY_KEYS, "artifact key")
    if any(authorization[field] != key_artifact[field] for field in ("pilot_id", "role", "agent_id", "cell_coordinate")) or authorization["artifact_signing_public_key"] != key_artifact["public_key"]:
        raise IdentityPilotError("authorized role/key mismatch")
    private_path = _safe_regular(_key_path(root, role), "private artifact key")
    if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
        raise IdentityPilotError("private artifact key permissions must be 0600")
    private = Ed25519PrivateKey.from_private_bytes(private_path.read_bytes())
    if _raw_public_key(private) != key_artifact["public_key"]:
        raise IdentityPilotError("private/public artifact key mismatch")
    if not isinstance(payload, dict):
        raise IdentityPilotError("JSON artifact payload must be an object")
    signature = private.sign(_canonical(payload))
    return {
        "schema_version": "organa-signed-json-artifact-v0.1",
        "pilot_id": authorization["pilot_id"], "role": role,
        "agent_id": authorization["agent_id"], "cell_coordinate": authorization["cell_coordinate"],
        "algorithm": "Ed25519", "public_key": key_artifact["public_key"],
        "authorization_sha256": _authorization_hash(authorization), "payload": payload,
        "payload_sha256": _sha(_canonical(payload)), "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_json_artifact(envelope: dict, authorization: dict, *, authorization_path: Path | None = None) -> bool:
    try:
        if authorization_path is None or not verify_artifact_authorization(authorization_path):
            return False
        stored_authorization = _read_closed_json(Path(authorization_path), AUTH_CLAIM_KEYS, "artifact authorization")
        if authorization != stored_authorization:
            return False
        if not isinstance(envelope, dict) or set(envelope) != SIGNED_ARTIFACT_KEYS:
            return False
        if not isinstance(authorization, dict) or set(authorization) != AUTH_CLAIM_KEYS:
            return False
        if authorization["status"] != "authorized" or authorization["authority"] != ARTIFACT_AUTHORITY:
            return False
        if envelope["schema_version"] != "organa-signed-json-artifact-v0.1" or envelope["algorithm"] != "Ed25519":
            return False
        if any(envelope[field] != authorization[field] for field in ("pilot_id", "role", "agent_id", "cell_coordinate")):
            return False
        if envelope["public_key"] != authorization["artifact_signing_public_key"] or envelope["authorization_sha256"] != _authorization_hash(authorization):
            return False
        if not isinstance(envelope["payload"], dict) or envelope["payload_sha256"] != _sha(_canonical(envelope["payload"])):
            return False
        public = Ed25519PublicKey.from_public_bytes(
            _decode_canonical_base64(envelope["public_key"], decoded_length=32, label="artifact signing public key")
        )
        signature = _decode_canonical_base64(envelope["signature"], decoded_length=64, label="artifact signature")
        public.verify(signature, _canonical(envelope["payload"]))
        return True
    except Exception:
        return False
