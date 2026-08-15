import json
from pathlib import Path

import pytest

from organa_cell_kit.workflow import CellKitError, build, doctor, init, publish_candidate, record_signature, activate, status, verify


COORDINATE = "123456.bitmap"
ADDRESS = "bc1qexamplecontrolleraddress0000000000000000000"
BASE_URL = "https://example.test/organa-cell-123456"


def test_init_creates_valid_config_and_initialized_state(tmp_path: Path):
    result = init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")

    assert result["stage"] == "initialized"
    config = json.loads((tmp_path / "cell-kit.json").read_text())
    assert config["coordinate"] == COORDINATE
    assert config["controller_address"] == ADDRESS
    assert config["controller_independence"] == "independent-controller-claimed-not-yet-verified"
    assert status(tmp_path)["stage"] == "initialized"


def test_build_and_verify_create_pending_candidate(tmp_path: Path):
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")

    built = build(tmp_path)
    checked = verify(tmp_path)

    assert built["stage"] == "built"
    assert checked["ok"] is True
    assert checked["stage"] == "verified"
    assert (tmp_path / "dist" / "versions" / "0.1.0" / "organa-cell.json").exists()
    manifest = json.loads((tmp_path / "dist" / "versions" / "0.1.0" / "organa-cell.json").read_text())
    assert manifest["lifecycle_status"] == "pending"
    assert manifest["controller"]["signature_status"] == "pending-user-signature"


def test_state_machine_requires_verify_before_publish_and_signature_before_activate(tmp_path: Path):
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")
    with pytest.raises(CellKitError, match="verified"):
        publish_candidate(tmp_path)
    build(tmp_path)
    verify(tmp_path)
    published = publish_candidate(tmp_path)
    assert published["stage"] == "candidate-published"
    with pytest.raises(CellKitError, match="signature"):
        activate(tmp_path)


def test_record_signature_and_activate_preserve_signed_manifest_bytes(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("organa_cell_kit.workflow._bip322_verify", lambda address, message, signature: (signature == "valid-signature", "invalid"))
    monkeypatch.setattr("organa_cell_kit.workflow._verify_public_candidate", lambda config: {"ok": True, "status": "integrity-valid", "integrity_valid": True})
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")
    build(tmp_path)
    verify(tmp_path)
    publish_candidate(tmp_path)
    manifest = tmp_path / "dist" / "versions" / "0.1.0" / "organa-cell.json"
    before = manifest.read_bytes()

    claim = record_signature(tmp_path, signature="valid-signature")
    activated = activate(tmp_path)

    assert claim["stage"] == "signed"
    assert activated["stage"] == "active"
    assert manifest.read_bytes() == before
    resolver = json.loads((tmp_path / "dist" / ".well-known" / "organa.json").read_text())
    assert resolver["activation_status"] == "active"
    assert resolver["controller_claim"]["status"] == "signed"
    assert resolver["current_manifest"]["lifecycle_status"] == "live"


def test_doctor_explains_human_actions_and_never_share_boundary(tmp_path: Path):
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")

    result = doctor(tmp_path)

    assert result["ok"] is True
    assert "Personally approve final BIP-322 wallet signature" in result["human_required"]
    assert "seed phrase" in result["never_share"]
    assert result["next_action"] == "Run build, then verify."


def test_record_signature_requires_public_production_verifier_success(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("organa_cell_kit.workflow._bip322_verify", lambda address, message, signature: (True, ""))
    monkeypatch.setattr(
        "organa_cell_kit.workflow._verify_public_candidate",
        lambda config: {"ok": False, "status": "integrity-invalid", "errors": ["schema mismatch"]},
    )
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")
    build(tmp_path); verify(tmp_path); publish_candidate(tmp_path)

    with pytest.raises(CellKitError, match="production verifier"):
        record_signature(tmp_path, signature="valid-signature")


def test_activate_rechecks_public_production_verifier_success(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("organa_cell_kit.workflow._bip322_verify", lambda address, message, signature: (True, ""))
    monkeypatch.setattr("organa_cell_kit.workflow._verify_public_candidate", lambda config: {"ok": True, "status": "resolved-integrity-valid", "integrity_valid": True})
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")
    build(tmp_path); verify(tmp_path); publish_candidate(tmp_path)
    record_signature(tmp_path, signature="valid-signature")
    monkeypatch.setattr(
        "organa_cell_kit.workflow._verify_public_candidate",
        lambda config: {"ok": False, "status": "integrity-invalid", "errors": ["resource closure failed"]},
    )

    with pytest.raises(CellKitError, match="production verifier"):
        activate(tmp_path)


def test_fail_closed_on_invalid_config_and_false_signature(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("organa_cell_kit.workflow._bip322_verify", lambda address, message, signature: (False, "invalid"))
    with pytest.raises(CellKitError):
        init(tmp_path, coordinate="bad", controller_address=ADDRESS, base_url=BASE_URL, cell_name="Bad")
    init(tmp_path, coordinate=COORDINATE, controller_address=ADDRESS, base_url=BASE_URL, cell_name="Independent Research Cell")
    build(tmp_path); verify(tmp_path); publish_candidate(tmp_path)
    with pytest.raises(CellKitError, match="valid"):
        record_signature(tmp_path, signature="bad")
