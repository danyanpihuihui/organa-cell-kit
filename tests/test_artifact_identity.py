import base64
import json
import os
from pathlib import Path

import pytest

import organa_cell_kit.pilot_identity as identity
from organa_cell_kit.pilot_identity import (
    IdentityPilotError,
    create_artifact_authorization_request,
    generate_artifact_key,
    record_artifact_authorization,
    sign_json_artifact,
    verify_artifact_authorization,
    verify_signed_json_artifact,
)


PILOT_ID = "dq-n6-two-role-production-001"
ROLES = {
    "requester": {
        "agent_id": "dq",
        "cell_coordinate": "7187.bitmap",
        "controller_address": "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq",
    },
    "worker": {
        "agent_id": "n6",
        "cell_coordinate": "720202.bitmap",
        "controller_address": "bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6",
    },
    "verifier": {
        "agent_id": "organa-verifier-922937",
        "cell_coordinate": "922937.bitmap",
        "controller_address": "bc1q6953dpmf3g3sfr8qz3tu7ht4zpu6qz7a2qx757",
    },
}


def _claim(role):
    item = ROLES[role]
    return {
        "schema_version": "test-existing-bip322-identity-claim-v0.1",
        "pilot_id": PILOT_ID,
        "role": role,
        "agent_id": item["agent_id"],
        "cell_coordinate": item["cell_coordinate"],
        "controller_address": item["controller_address"],
        "message": f"existing wallet identity claim for {role}",
        "message_sha256": identity._sha(f"existing wallet identity claim for {role}".encode()),
        "signature": f"valid-existing-{role}",
        "status": "signed",
    }


def _authorized_role(tmp_path, monkeypatch, role="requester"):
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))
    key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role=role, **ROLES[role])
    request = create_artifact_authorization_request(tmp_path, identity_claim=_claim(role), artifact_key=key)
    claim = record_artifact_authorization(tmp_path, role, f"valid-authorization-{role}")
    return key, request, claim


def test_generates_distinct_three_role_keys_with_private_0600_and_public_safe_artifacts(tmp_path):
    public_keys = set()
    for role, item in ROLES.items():
        artifact = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role=role, **item)
        public_keys.add(artifact["public_key"])
        assert set(artifact) == {
            "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
            "algorithm", "public_key_encoding", "public_key", "status",
        }
        assert "private" not in json.dumps(artifact).lower()
        public_path = tmp_path / "identity" / role / "artifact-key.json"
        private_path = tmp_path / ".private" / "artifact-keys" / f"{role}.ed25519"
        assert public_path.stat().st_mode & 0o777 == 0o444
        assert private_path.stat().st_mode & 0o777 == 0o600
        assert str(private_path) not in public_path.read_text()
    assert len(public_keys) == 3


def test_key_generation_rejects_unsafe_roles_symlink_roots_and_mutation(tmp_path):
    with pytest.raises(IdentityPilotError, match="role"):
        generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="../worker", **ROLES["worker"])

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(IdentityPilotError, match="symlink"):
        generate_artifact_key(alias, pilot_id=PILOT_ID, role="worker", **ROLES["worker"])

    escaped_private = tmp_path / "escaped-private"
    escaped_private.mkdir()
    private_root = tmp_path / ".private"
    private_root.symlink_to(escaped_private, target_is_directory=True)
    with pytest.raises(IdentityPilotError, match="symlink"):
        generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="requester", **ROLES["requester"])
    assert not list(escaped_private.rglob("*.ed25519"))
    private_root.unlink()

    escaped_public = tmp_path / "escaped-public"
    escaped_public.mkdir()
    identity_root = tmp_path / "identity"
    identity_root.symlink_to(escaped_public, target_is_directory=True)
    with pytest.raises(IdentityPilotError, match="symlink"):
        generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="verifier", **ROLES["verifier"])
    assert not list(escaped_public.rglob("artifact-key.json"))
    identity_root.unlink()

    key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="worker", **ROLES["worker"])
    changed = dict(key, agent_id="attacker")
    (tmp_path / "identity" / "worker" / "artifact-key.json").chmod(0o644)
    (tmp_path / "identity" / "worker" / "artifact-key.json").write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(IdentityPilotError, match="immutable"):
        generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="worker", **ROLES["worker"])


def test_authorization_request_binds_existing_wallet_identity_key_role_agent_bitmap_and_no_payment(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))
    key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="verifier", **ROLES["verifier"])
    request = create_artifact_authorization_request(tmp_path, identity_claim=_claim("verifier"), artifact_key=key)

    assert set(request) == {
        "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
        "controller_address", "artifact_signing_algorithm", "artifact_signing_public_key",
        "identity_claim_sha256", "message_encoding", "message", "message_sha256",
        "authority", "status", "safety_notice",
    }
    for value in (PILOT_ID, "verifier", ROLES["verifier"]["agent_id"], "922937.bitmap", key["public_key"]):
        assert value in request["message"]
    assert request["authority"] == {
        "json_artifact_signing": True,
        "bitcoin_payment": False,
        "bitcoin_spending": False,
        "transaction": False,
        "psbt": False,
        "fee": False,
        "miner_payment": False,
    }
    assert "no payment" in request["message"].lower()


def test_authorization_accepts_existing_two_role_and_verifier_claim_schema_shapes(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))
    requester_key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="requester", **ROLES["requester"])
    compact_claim = {key: value for key, value in _claim("requester").items() if key not in {"agent_id", "cell_coordinate"}}
    compact_claim["mode"] = "two-role-requester-worker-same-controller-pilot"
    request = create_artifact_authorization_request(tmp_path, identity_claim=compact_claim, artifact_key=requester_key)
    assert request["agent_id"] == "dq"
    assert request["cell_coordinate"] == "7187.bitmap"

    verifier_key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="verifier", **ROLES["verifier"])
    verifier_claim = dict(_claim("verifier"), claims_scope={"independent_controller": False, "external_adoption": False, "real_payment": False})
    request = create_artifact_authorization_request(tmp_path, identity_claim=verifier_claim, artifact_key=verifier_key)
    assert request["agent_id"] == "organa-verifier-922937"


def test_authorization_rejects_invalid_existing_claim_closed_schema_and_role_key_mismatch(tmp_path, monkeypatch):
    key = generate_artifact_key(tmp_path, pilot_id=PILOT_ID, role="requester", **ROLES["requester"])
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (False, "bad signature"))
    with pytest.raises(IdentityPilotError, match="existing wallet identity"):
        create_artifact_authorization_request(tmp_path, identity_claim=_claim("requester"), artifact_key=key)

    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))
    extra = dict(_claim("requester"), unexpected=True)
    with pytest.raises(IdentityPilotError, match="closed"):
        create_artifact_authorization_request(tmp_path, identity_claim=extra, artifact_key=key)

    with pytest.raises(IdentityPilotError, match="role"):
        create_artifact_authorization_request(tmp_path, identity_claim=_claim("worker"), artifact_key=key)


def test_records_and_verifies_human_authorization_immutably_and_rejects_tampering(tmp_path, monkeypatch):
    _, request, claim = _authorized_role(tmp_path, monkeypatch, "requester")
    assert verify_artifact_authorization(tmp_path / "identity" / "requester" / "artifact-authorization.json") is True
    assert set(claim) == {
        "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
        "controller_address", "artifact_signing_algorithm", "artifact_signing_public_key",
        "identity_claim_sha256", "message", "message_sha256", "signature", "status",
        "authority",
    }
    assert (tmp_path / "identity" / "requester" / "artifact-authorization.json").stat().st_mode & 0o777 == 0o444

    request["message"] += "tampered"
    request_path = tmp_path / "identity" / "requester" / "artifact-authorization-request.json"
    request_path.chmod(0o644)
    request_path.write_text(json.dumps(request), encoding="utf-8")
    assert verify_artifact_authorization(tmp_path / "identity" / "requester" / "artifact-authorization.json") is False


def test_signed_json_artifact_requires_authorized_matching_role_key_and_rejects_payload_or_envelope_tampering(tmp_path, monkeypatch):
    key, _, authorization = _authorized_role(tmp_path, monkeypatch, "worker")
    payload = {"schema_version": "organa-test-artifact-v0.1", "task": "verify-package", "ok": True}
    envelope = sign_json_artifact(tmp_path, role="worker", payload=payload)

    assert set(envelope) == {
        "schema_version", "pilot_id", "role", "agent_id", "cell_coordinate",
        "algorithm", "public_key", "authorization_sha256", "payload",
        "payload_sha256", "signature",
    }
    assert envelope["public_key"] == key["public_key"]
    authorization_path = tmp_path / "identity" / "worker" / "artifact-authorization.json"
    assert verify_signed_json_artifact(envelope, authorization, authorization_path=authorization_path) is True
    assert verify_signed_json_artifact(dict(envelope, payload={**payload, "ok": False}), authorization, authorization_path=authorization_path) is False
    assert verify_signed_json_artifact(dict(envelope, role="verifier"), authorization, authorization_path=authorization_path) is False
    assert verify_signed_json_artifact(dict(envelope, unexpected=True), authorization, authorization_path=authorization_path) is False
    assert verify_signed_json_artifact(envelope, authorization) is False


def test_authorization_request_rejects_unsigned_metadata_rebinding(tmp_path, monkeypatch):
    _, request, _ = _authorized_role(tmp_path, monkeypatch, "requester")
    request_path = tmp_path / "identity" / "requester" / "artifact-authorization-request.json"
    request["agent_id"] = "attacker"
    request_path.chmod(0o644)
    request_path.write_text(json.dumps(request), encoding="utf-8")
    with pytest.raises(IdentityPilotError, match="binding"):
        record_artifact_authorization(tmp_path, "requester", "valid-authorization-requester")


def test_strict_json_rejects_non_finite_numbers(tmp_path, monkeypatch):
    _authorized_role(tmp_path, monkeypatch, "worker")
    with pytest.raises(IdentityPilotError, match="strict JSON"):
        sign_json_artifact(tmp_path, role="worker", payload={"value": float("nan")})


def test_signed_json_verifier_rejects_unverified_authorization_dict(tmp_path, monkeypatch):
    _, _, authorization = _authorized_role(tmp_path, monkeypatch, "worker")
    envelope = sign_json_artifact(tmp_path, role="worker", payload={"artifact_type": "worker-result"})
    forged = dict(authorization, signature="not-a-bip322-signature")
    assert verify_signed_json_artifact(envelope, forged) is False


def test_private_key_and_authorization_paths_reject_symlinks(tmp_path, monkeypatch):
    _authorized_role(tmp_path, monkeypatch, "requester")
    private_path = tmp_path / ".private" / "artifact-keys" / "requester.ed25519"
    target = tmp_path / "stolen-key"
    target.write_bytes(private_path.read_bytes())
    target.chmod(0o600)
    private_path.unlink()
    private_path.symlink_to(target)
    with pytest.raises(IdentityPilotError, match="symlink"):
        sign_json_artifact(tmp_path, role="requester", payload={"x": 1})

    auth_path = tmp_path / "identity" / "requester" / "artifact-authorization.json"
    auth_copy = tmp_path / "auth-copy.json"
    auth_copy.write_bytes(auth_path.read_bytes())
    auth_path.unlink()
    auth_path.symlink_to(auth_copy)
    assert verify_artifact_authorization(auth_path) is False


def test_authorization_verifier_rejects_symlinked_ancestor_directory(tmp_path, monkeypatch):
    _authorized_role(tmp_path, monkeypatch, "requester")
    real_role_dir = tmp_path / "identity" / "requester"
    moved_role_dir = tmp_path / "requester-real"
    real_role_dir.rename(moved_role_dir)
    real_role_dir.symlink_to(moved_role_dir, target_is_directory=True)

    assert verify_artifact_authorization(real_role_dir / "artifact-authorization.json") is False


@pytest.mark.parametrize("invalid_fragment", ['"role":"attacker",', '"message_sha256":Infinity,'])
def test_authorization_json_reader_rejects_duplicate_keys_and_non_finite_numbers(tmp_path, monkeypatch, invalid_fragment):
    _authorized_role(tmp_path, monkeypatch, "requester")
    request_path = tmp_path / "identity" / "requester" / "artifact-authorization-request.json"
    raw = request_path.read_text(encoding="utf-8")
    request_path.chmod(0o644)
    request_path.write_text(raw.replace("{", "{" + invalid_fragment, 1), encoding="utf-8")

    assert verify_artifact_authorization(tmp_path / "identity" / "requester" / "artifact-authorization.json") is False


def test_signed_json_verifier_rejects_noncanonical_base64_and_wrong_decoded_lengths(tmp_path, monkeypatch):
    key, _, authorization = _authorized_role(tmp_path, monkeypatch, "worker")
    envelope = sign_json_artifact(tmp_path, role="worker", payload={"artifact_type": "worker-result"})
    authorization_path = tmp_path / "identity" / "worker" / "artifact-authorization.json"

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last_data_index = len(envelope["signature"].rstrip("=")) - 1
    original_index = alphabet.index(envelope["signature"][last_data_index])
    noncanonical_char = alphabet[(original_index & ~15) | ((original_index + 1) & 15)]
    noncanonical_signature = envelope["signature"][:last_data_index] + noncanonical_char + envelope["signature"][last_data_index + 1:]
    assert base64.b64decode(noncanonical_signature, validate=True) == base64.b64decode(envelope["signature"], validate=True)
    assert noncanonical_signature != envelope["signature"]
    assert verify_signed_json_artifact(
        dict(envelope, signature=noncanonical_signature), authorization, authorization_path=authorization_path
    ) is False

    short_signature = base64.b64encode(base64.b64decode(envelope["signature"])[:-1]).decode("ascii")
    assert verify_signed_json_artifact(
        dict(envelope, signature=short_signature), authorization, authorization_path=authorization_path
    ) is False

    public_key_index = len(key["public_key"].rstrip("=")) - 1
    original_key_index = alphabet.index(key["public_key"][public_key_index])
    noncanonical_key_char = alphabet[(original_key_index & ~3) | ((original_key_index + 1) & 3)]
    noncanonical_public_key = key["public_key"][:public_key_index] + noncanonical_key_char + key["public_key"][public_key_index + 1:]
    assert base64.b64decode(noncanonical_public_key, validate=True) == base64.b64decode(key["public_key"], validate=True)
    with pytest.raises(IdentityPilotError, match="public key"):
        create_artifact_authorization_request(
            tmp_path,
            identity_claim=_claim("worker"),
            artifact_key=dict(key, public_key=noncanonical_public_key),
        )

    short_public_key = base64.b64encode(base64.b64decode(key["public_key"])[:-1]).decode("ascii")
    with pytest.raises(IdentityPilotError, match="public key"):
        create_artifact_authorization_request(
            tmp_path,
            identity_claim=_claim("worker"),
            artifact_key=dict(key, public_key=short_public_key),
        )
