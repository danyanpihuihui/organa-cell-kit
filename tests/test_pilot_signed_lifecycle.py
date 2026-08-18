import hashlib
import json
import shutil
from pathlib import Path

import pytest

import organa_cell_kit.pilot_identity as identity
from organa_cell_kit.pilot import (
    PilotError,
    init_pilot,
    requester_publish,
    verifier_settle,
    verify_pilot_handoff,
    worker_run,
)
from organa_cell_kit.pilot_identity import (
    create_artifact_authorization_request,
    generate_artifact_key,
    record_artifact_authorization,
    sign_json_artifact,
    verify_signed_json_artifact,
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def make_package(root: Path) -> Path:
    root.mkdir(parents=True)
    resource = root / "proof-index.json"
    resource.write_text('{"entries": []}\n', encoding="utf-8")
    manifest = {
        "schema_version": "organa-cell-resolution-v0.1",
        "coordinate": "720202.bitmap",
        "cell_type": "organa-cell",
        "version": "0.3.0",
        "created_at_utc": "2026-08-16T00:00:00+00:00",
        "lifecycle_status": "live",
        "controller": {"address": "bc1qfixture", "claim_type": "bitmap-controller-wallet-claim", "signature_status": "signed", "signature_request_url": "https://example.invalid/signature-request.json"},
        "public_base_url": "https://example.invalid/720202",
        "agents": [{"id": "fixture-agent"}],
        "services": [{"id": "fixture-service"}],
        "resources": [{"path": "proof-index.json", "sha256": "sha256:" + hashlib.sha256(resource.read_bytes()).hexdigest()}],
    }
    (root / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    return root


def authorize_role(root: Path, config: dict, role: str) -> None:
    item = config[role]
    controller_address = f"bc1q{role}testcontroller"
    key = generate_artifact_key(
        root,
        pilot_id=config["pilot_id"],
        role=role,
        agent_id=item["agent_id"],
        cell_coordinate=item["cell_coordinate"],
        controller_address=controller_address,
    )
    item["signing_public_key"] = key["public_key"]
    message = f"existing wallet identity claim for {role}"
    claim = {
        "schema_version": "test-existing-bip322-identity-claim-v0.1",
        "pilot_id": config["pilot_id"],
        "role": role,
        "agent_id": item["agent_id"],
        "cell_coordinate": item["cell_coordinate"],
        "controller_address": controller_address,
        "message": message,
        "message_sha256": identity._sha(message.encode()),
        "signature": f"valid-existing-{role}",
        "status": "signed",
    }
    create_artifact_authorization_request(root, identity_claim=claim, artifact_key=key)
    record_artifact_authorization(root, role, f"valid-authorization-{role}")


def prepare(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(identity, "_verify_bip322", lambda address, message, signature: (True, ""))
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))
    config_path = pilot / "pilot-config.json"
    config = load(config_path)
    config["requester"].update(cell_coordinate="810001.bitmap", endpoint="https://dq.example.invalid/organa")
    config["worker"].update(cell_coordinate="810002.bitmap", endpoint="https://n6.example.invalid/organa")
    config["verifier"].update(cell_coordinate="810003.bitmap", endpoint="local://verifier")
    config["execution_mode"] = "local-rehearsal"
    authorize_role(pilot, config, "requester")
    authorize_role(pilot / "workspaces" / "n6-worker", config, "worker")
    authorize_role(pilot / "workspaces" / "local-verifier", config, "verifier")
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    requester = requester_publish(pilot)
    worker = worker_run(public_board_dir=Path(requester["public_board_dir"]), worker_workspace=pilot / "workspaces" / "n6-worker")
    return pilot, requester, worker


def resign_handoff(verifier_root: Path, handoff_path: Path, mutate) -> None:
    payload = load(handoff_path)["payload"]
    mutate(payload)
    handoff_path.write_text(
        json.dumps(sign_json_artifact(verifier_root, role="verifier", payload=payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_lifecycle_exchanges_authorized_ed25519_envelopes_and_receipt_binds_all_signers(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    public = Path(requester["public_board_dir"])
    submission = Path(worker["submission_dir"])

    requester_envelope = load(public / "requester-publication.json")
    requester_authorization = load(public / "requester-identity" / "artifact-authorization.json")
    assert requester_envelope["role"] == "requester"
    assert verify_signed_json_artifact(requester_envelope, requester_authorization, authorization_path=public / "requester-identity" / "artifact-authorization.json") is True

    worker_envelope = load(submission / "worker-submission.json")
    worker_authorization = load(submission / "worker-identity" / "artifact-authorization.json")
    assert worker_envelope["role"] == "worker"
    assert verify_signed_json_artifact(worker_envelope, worker_authorization, authorization_path=submission / "worker-identity" / "artifact-authorization.json") is True

    settled = verifier_settle(
        public_board_dir=public,
        worker_submission_dir=submission,
        verifier_workspace=pilot / "workspaces" / "local-verifier",
    )
    receipt_path = Path(settled["pilot_receipt_path"])
    verifier_envelope = load(receipt_path)
    verifier_authorization = load(receipt_path.parent / "verifier-identity" / "artifact-authorization.json")
    assert verifier_envelope["role"] == "verifier"
    assert verify_signed_json_artifact(verifier_envelope, verifier_authorization, authorization_path=receipt_path.parent / "verifier-identity" / "artifact-authorization.json") is True
    assert verifier_envelope["payload"]["requester_signed_artifact_sha256"] == identity._sha(identity._canonical(requester_envelope))
    assert verifier_envelope["payload"]["worker_signed_artifact_sha256"] == identity._sha(identity._canonical(worker_envelope))


def test_requester_requires_human_authorized_ed25519_key(tmp_path: Path):
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))
    config_path = pilot / "pilot-config.json"
    config = load(config_path)
    config["requester"].update(cell_coordinate="810001.bitmap", endpoint="https://dq.invalid", signing_public_key="not-authorized")
    config["worker"].update(cell_coordinate="810002.bitmap", endpoint="https://n6.invalid", signing_public_key="not-authorized-worker")
    config["verifier"].update(cell_coordinate="810003.bitmap", endpoint="local://verifier", signing_public_key="not-authorized-verifier")
    config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="authorization|Ed25519|sign"):
        requester_publish(pilot)


def test_worker_rejects_rehashed_but_unsigned_requester_payload(tmp_path: Path, monkeypatch):
    pilot, requester, _ = prepare(tmp_path, monkeypatch)
    public = Path(requester["public_board_dir"])
    envelope = load(public / "requester-publication.json")
    envelope["payload"]["fixture_package_sha256"] = "sha256:" + "0" * 64
    envelope["payload_sha256"] = identity._sha(identity._canonical(envelope["payload"]))
    (public / "requester-publication.json").write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="signature|signed|requester"):
        worker_run(public_board_dir=public, worker_workspace=pilot / "workspaces" / "n6-worker")


def test_public_authorization_bundle_contains_exact_original_identity_claim_and_reverifies_it(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    public = Path(requester["public_board_dir"])
    submission = Path(worker["submission_dir"])

    for exported, source, role in (
        (public / "requester-identity", pilot / "identity" / "requester", "requester"),
        (submission / "worker-identity", pilot / "workspaces" / "n6-worker" / "identity" / "worker", "worker"),
    ):
        assert (exported / "identity-claim.json").read_bytes() == (source / "identity-claim.json").read_bytes()
        authorization = load(exported / "artifact-authorization.json")
        claim = load(exported / "identity-claim.json")
        assert authorization["identity_claim_sha256"] == identity._sha(identity._canonical(claim))
        assert identity.verify_artifact_authorization(exported / "artifact-authorization.json") is True


def test_complete_handoff_verifier_checks_all_three_authorizations_receipt_and_distinctness(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )

    result = verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)

    assert result == {
        "ok": True,
        "execution_mode": "local-rehearsal",
        "authoritative_receipt_checked": True,
        "roles_verified": ["requester", "worker", "verifier"],
    }
    handoff = load(Path(settled["pilot_receipt_path"]))["payload"]
    assert handoff["execution_mode"] == "local-rehearsal"
    assert handoff["status"] == "local-rehearsal-complete"
    assert handoff["production_receipt_relative_path"] == Path(settled["receipt_path"]).relative_to(verifier_root).as_posix()
    assert "production_receipt_path" not in handoff
    assert (Path(settled["pilot_receipt_path"]).parent / "requester-signed-artifact.json").is_file()
    assert (Path(settled["pilot_receipt_path"]).parent / "worker-signed-artifact.json").is_file()


def test_complete_handoff_verifies_after_copying_the_whole_workspace(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    copied_root = tmp_path / "relocated-verifier-workspace"
    shutil.copytree(verifier_root, copied_root)
    copied_handoff = copied_root / Path(settled["pilot_receipt_path"]).relative_to(verifier_root)

    result = verify_pilot_handoff(copied_handoff, project_root=copied_root)

    assert result["ok"] is True
    assert result["authoritative_receipt_checked"] is True


@pytest.mark.parametrize(
    "replacement",
    [
        "/tmp/receipt.json",
        "../receipt.json",
        "runs/../receipt.json",
        "runs/other-run/receipt.json",
    ],
)
def test_complete_handoff_rejects_signed_unsafe_or_wrong_run_receipt_reference(tmp_path: Path, monkeypatch, replacement: str):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    handoff_path = Path(settled["pilot_receipt_path"])
    resign_handoff(verifier_root, handoff_path, lambda payload: payload.__setitem__("production_receipt_relative_path", replacement))

    with pytest.raises(PilotError, match="receipt.*(relative|path|run|binding|normalized|unsafe)"):
        verify_pilot_handoff(handoff_path, project_root=verifier_root)


@pytest.mark.parametrize("symlink_part", ["receipt", "run"])
def test_complete_handoff_rejects_receipt_symlink_leaf_or_ancestor(tmp_path: Path, monkeypatch, symlink_part: str):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    receipt = Path(settled["receipt_path"])
    if symlink_part == "receipt":
        target = tmp_path / "receipt-target.json"
        shutil.copy2(receipt, target)
        receipt.unlink()
        receipt.symlink_to(target)
    else:
        run = receipt.parent
        target = tmp_path / "run-target"
        shutil.copytree(run, target)
        shutil.rmtree(run)
        run.symlink_to(target, target_is_directory=True)

    with pytest.raises(PilotError, match="receipt.*(symlink|unsafe|path|authoritative)|safe authoritative.*symlink"):
        verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)


def test_complete_handoff_rejects_substituted_receipt_even_at_signed_relative_location(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    receipt = Path(settled["receipt_path"])
    receipt.write_text('{"substituted": true}\n', encoding="utf-8")

    with pytest.raises(PilotError, match="receipt.*(hash|bytes)"):
        verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)


def test_complete_handoff_verifier_rejects_direct_handoff_symlink(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    handoff = Path(settled["pilot_receipt_path"])
    original = handoff.with_name("real-pilot-handoff-receipt.json")
    handoff.rename(original)
    handoff.symlink_to(original)

    with pytest.raises(PilotError, match="safe authoritative|symlink"):
        verify_pilot_handoff(handoff, project_root=verifier_root)


def test_complete_handoff_verifier_rejects_symlinked_handoff_ancestor(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    handoff = Path(settled["pilot_receipt_path"])
    runs_alias = verifier_root / "runs-alias"
    runs_alias.symlink_to(verifier_root / "runs", target_is_directory=True)
    aliased_handoff = runs_alias / handoff.parent.name / handoff.name

    with pytest.raises(PilotError, match="safe authoritative|symlink"):
        verify_pilot_handoff(aliased_handoff, project_root=verifier_root)


def test_complete_handoff_verifier_rejects_symlinked_artifact_inside_run(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    handoff = Path(settled["pilot_receipt_path"])
    artifact = handoff.parent / "requester-signed-artifact.json"
    original = handoff.parent / "requester-signed-artifact-real.json"
    artifact.rename(original)
    artifact.symlink_to(original)

    with pytest.raises(PilotError, match="symlink"):
        verify_pilot_handoff(handoff, project_root=verifier_root)


@pytest.mark.parametrize("duplicate_field", ["agent_id", "cell_coordinate", "artifact_signing_public_key", "controller_address"])
def test_complete_handoff_verifier_rejects_any_duplicate_role_identity_dimension(tmp_path: Path, monkeypatch, duplicate_field: str):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    run = Path(settled["pilot_receipt_path"]).parent
    requester_auth_path = run / "requester-identity" / "artifact-authorization.json"
    requester_auth = load(requester_auth_path)
    verifier_auth = load(run / "verifier-identity" / "artifact-authorization.json")
    requester_auth[duplicate_field] = verifier_auth[duplicate_field]
    requester_auth_path.chmod(0o644)
    requester_auth_path.write_text(json.dumps(requester_auth) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="authorization|distinct|identity"):
        verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)


def test_complete_handoff_verifier_rejects_changed_receipt_bytes_and_non_authoritative_state(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    verifier_root = pilot / "workspaces" / "local-verifier"
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=verifier_root,
    )
    receipt = Path(settled["receipt_path"])
    original = receipt.read_bytes()
    receipt.write_bytes(original + b" ")
    with pytest.raises(PilotError, match="receipt.*hash|receipt.*bytes"):
        verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)
    receipt.write_bytes(original)

    current = load(verifier_root / "current.json")
    current["task_hash"] = "sha256:" + "0" * 64
    (verifier_root / "current.json").write_text(json.dumps(current) + "\n", encoding="utf-8")
    with pytest.raises(PilotError, match="authoritative|current"):
        verify_pilot_handoff(Path(settled["pilot_receipt_path"]), project_root=verifier_root)


def test_execution_mode_is_closed_and_never_inferred_from_public_key_text(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path, monkeypatch)
    config_path = pilot / "pilot-config.json"
    config = load(config_path)
    config["execution_mode"] = "cross-controller-pilot"
    config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    requester = requester_publish(pilot)
    assert load(Path(requester["public_board_dir"]) / "requester-publication.json")["payload"]["execution_mode"] == "cross-controller-pilot"

    config["requester"]["signing_public_key"] = config["worker"]["signing_public_key"]
    config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    with pytest.raises(PilotError, match="public keys must be distinct"):
        requester_publish(pilot)

    config["requester"]["signing_public_key"] = load(pilot / "identity" / "requester" / "artifact-key.json")["public_key"]
    config["execution_mode"] = "unknown-mode"
    config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")
    with pytest.raises(PilotError, match="execution mode"):
        requester_publish(pilot)
