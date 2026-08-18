import json
from pathlib import Path

import pytest

import organa_cell_kit.pilot_identity as identity

from organa_cell_kit.pilot_identity import (
    IdentityPilotError,
    prepare_identity,
    record_identity_signature,
)


def role(agent, coord, address, pub):
    return {
        "agent_id": agent,
        "cell_coordinate": coord,
        "controller_address": address,
        "artifact_signing_algorithm": "Ed25519",
        "artifact_signing_public_key": pub,
        "wallet_identity_claim": "human-wallet-bip322-simple-message",
    }


def config(tmp_path):
    return {
        "mode": "three-wallet-three-bitmap-same-controller-local-pilot",
        "pilot_id": "pilot-test-001",
        "claims_scope": {"independent_controller": False, "external_adoption": False, "real_payment": False},
        "requester": role("requester", "810001.bitmap", "bc1qrequesterexample000000000000000", "ed25519-requester"),
        "worker": role("worker", "810002.bitmap", "bc1qworkerexample00000000000000000", "ed25519-worker"),
        "verifier": role("verifier", "810003.bitmap", "bc1qverifierexample000000000000000", "ed25519-verifier"),
    }


def test_prepare_generates_exact_role_messages_requests_and_immutable_docs(tmp_path):
    result = prepare_identity(tmp_path, config(tmp_path))
    assert result["status"] == "awaiting-human-signature"
    assert set(result["roles"]) == {"requester", "worker", "verifier"}
    for role_name, item in result["roles"].items():
        assert item["signature_request"]["status"] == "awaiting-human-signature"
        assert item["signature_request"]["message_sha256"].startswith("sha256:")
        assert "no transaction" in item["message"].lower()
        assert (tmp_path / "identity" / role_name / "identity-document.json").is_file()


def test_prepare_rejects_duplicate_coordinates_addresses_and_placeholders(tmp_path):
    c = config(tmp_path)
    c["worker"]["cell_coordinate"] = c["requester"]["cell_coordinate"]
    with pytest.raises(IdentityPilotError, match="distinct"):
        prepare_identity(tmp_path, c)
    c = config(tmp_path)
    c["verifier"]["controller_address"] = "REQUIRED_REPLACE_ME"
    with pytest.raises(IdentityPilotError, match="placeholder"):
        prepare_identity(tmp_path, c)


def test_record_rejects_invalid_and_role_swap_signatures(tmp_path):
    c = config(tmp_path)
    prepare_identity(tmp_path, c)
    with pytest.raises(IdentityPilotError, match="BIP-322"):
        record_identity_signature(tmp_path, "requester", "NOT_A_BIP322_SIGNATURE")
    with pytest.raises(IdentityPilotError, match="role"):
        record_identity_signature(tmp_path, "worker", "valid-but-wrong-role", expected_role="requester")


@pytest.mark.parametrize("invalid_fragment", ['"role":"attacker",', '"message_sha256":NaN,'])
def test_record_identity_signature_rejects_duplicate_keys_and_non_finite_json(tmp_path, monkeypatch, invalid_fragment):
    prepare_identity(tmp_path, config(tmp_path))
    request_path = tmp_path / "identity" / "requester" / "signature-request.json"
    raw = request_path.read_text(encoding="utf-8")
    request_path.chmod(0o644)
    request_path.write_text(raw.replace("{", "{" + invalid_fragment, 1), encoding="utf-8")
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))

    with pytest.raises(IdentityPilotError, match="invalid signature request|duplicate|constant"):
        record_identity_signature(tmp_path, "requester", "valid-signature")


def test_identity_entrypoints_reject_symlinked_root_ancestors(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(IdentityPilotError, match="symlink"):
        prepare_identity(alias / "pilot", config(tmp_path))


def test_two_role_preparation_accepts_known_public_mapping_and_defers_verifier(tmp_path):
    result = prepare_identity(tmp_path, two_role_config())
    assert result["mode"] == "two-role-requester-worker-same-controller-pilot"
    assert result["status"] == "awaiting-human-signature-and-verifier-registration"
    assert result["verifier"]["status"] == "pending-registration"
    assert set(result["roles"]) == {"requester", "worker"}
    assert result["roles"]["requester"]["signature_request"]["controller_address"] == "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq"
    assert result["roles"]["worker"]["signature_request"]["controller_address"] == "bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6"
    assert "720202" in result["roles"]["worker"]["message"]
    assert "verifier" not in result["roles"]
    worksheet = tmp_path / "identity" / "verifier-pending-worksheet.json"
    assert json.loads(worksheet.read_text())["status"] == "pending-registration"
    assert "bc1q6953dpmf3g3sfr8qz3tu7ht4zpu6qz7a2qx757" not in worksheet.read_text()
    assert result["production_ready"] is False
    assert result["settled"] is False


def two_role_config():
    return {
        "mode": "two-role-requester-worker-same-controller-pilot",
        "pilot_id": "dq-n6-two-role-001",
        "claims_scope": {"independent_controller": False, "external_adoption": False, "real_payment": False},
        "requester": {
            "agent_id": "dq", "cell_coordinate": "7187.bitmap",
            "controller_address": "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq",
            "wallet_identity_claim": "human-wallet-bip322-simple-message",
            "provenance": "existing public 7187 claim",
        },
        "worker": {
            "agent_id": "n6", "cell_coordinate": "720202.bitmap",
            "controller_address": "bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6",
            "wallet_identity_claim": "human-wallet-bip322-simple-message",
            "provenance": "existing public 720202 claim",
        },
        "verifier_status": "pending-registration",
    }


def test_two_role_preparation_rejects_swaps_and_duplicate_or_placeholder_roles(tmp_path):
    c = two_role_config()
    c["worker"]["controller_address"] = c["requester"]["controller_address"]
    with pytest.raises(IdentityPilotError, match="known public mapping"):
        prepare_identity(tmp_path, c)
    c = two_role_config()
    c["requester"]["cell_coordinate"] = "720202.bitmap"
    with pytest.raises(IdentityPilotError, match="known public mapping"):
        prepare_identity(tmp_path, c)
    c = two_role_config()
    c["worker"]["provenance"] = "REQUIRED_REPLACE_ME"
    with pytest.raises(IdentityPilotError, match="placeholder"):
        prepare_identity(tmp_path, c)


def test_two_role_messages_bind_role_coordinate_address_and_do_not_consume_verifier(tmp_path):
    result = prepare_identity(tmp_path, two_role_config())
    for role_name, item in two_role_config().items():
        if role_name not in {"requester", "worker"}:
            continue
        message = result["roles"][role_name]["message"]
        assert f"Role: {role_name}" in message
        assert item["agent_id"] in message
        assert item["cell_coordinate"] in message
        assert item["controller_address"] in message
        assert item["provenance"] in message
    assert "bc1q6953dpmf3g3sfr8qz3tu7ht4zpu6qz7a2qx757" not in json.dumps(result)
    assert not list(tmp_path.rglob("*private*"))
    assert not list(tmp_path.rglob("*seed*"))



def test_scope_flags_are_false_and_no_secrets_are_written(tmp_path):
    c = config(tmp_path)
    result = prepare_identity(tmp_path, c)
    assert result["claims_scope"] == c["claims_scope"]
    assert not list(tmp_path.rglob("*seed*"))
    assert not list(tmp_path.rglob("*private*"))
