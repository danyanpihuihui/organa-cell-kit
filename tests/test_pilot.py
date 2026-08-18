import hashlib
import json
import shutil
from pathlib import Path

import pytest

import organa_cell_kit.pilot_identity as pilot_identity
import organa_cell_kit.pilot as pilot_module
from organa_cell_kit.pilot import (
    PilotError,
    directory_sha256,
    init_pilot,
    requester_publish,
    verifier_settle,
    worker_run,
)
from organa_cell_kit.production_loop import verify_receipt
from organa_cell_kit.pilot_identity import create_artifact_authorization_request, generate_artifact_key, record_artifact_authorization


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


@pytest.mark.parametrize(
    "raw",
    [
        '{"schema_version":"organa-cross-controller-pilot-config-v0.1","schema_version":"organa-cross-controller-pilot-config-v0.1"}',
        '{"schema_version":NaN}',
        '{"schema_version":Infinity}',
        '{"schema_version":-Infinity}',
    ],
)
def test_pilot_artifact_parser_rejects_noncanonical_json(tmp_path: Path, raw: str):
    path = tmp_path / "artifact.json"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(PilotError, match="invalid pilot JSON artifact"):
        pilot_module._read_json(path)


def test_pilot_json_writer_rejects_non_finite_numbers(tmp_path: Path):
    with pytest.raises(ValueError):
        pilot_module._write_json(tmp_path / "artifact.json", {"not_finite": float("inf")})


def test_pilot_json_reader_rejects_symlinked_file_and_ancestor(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    target = real / "artifact.json"
    target.write_text("{}\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    direct = tmp_path / "artifact.json"
    direct.symlink_to(target)

    with pytest.raises(PilotError, match="symlink"):
        pilot_module._read_json(alias / "artifact.json")
    with pytest.raises(PilotError, match="symlink"):
        pilot_module._read_json(direct)


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
        "controller": {"address": "bc1qpublicfixture", "claim_type": "bitmap-controller-wallet-claim", "signature_status": "signed", "signature_request_url": "https://example.invalid/signature-request.json"},
        "public_base_url": "https://example.invalid/720202",
        "agents": [{"id": "fixture-agent"}],
        "services": [{"id": "fixture-service"}],
        "resources": [{"path": "proof-index.json", "sha256": "sha256:" + hashlib.sha256(resource.read_bytes()).hexdigest()}],
    }
    (root / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    return root


def test_package_paths_reject_symlinked_ancestors(tmp_path: Path):
    real = tmp_path / "real"
    package = make_package(real / "pkg")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(PilotError, match="symlink|safe directory"):
        directory_sha256(alias / "pkg")
    with pytest.raises(PilotError, match="symlink|safe directory"):
        init_pilot(tmp_path / "pilot", fixture_source=alias / "pkg")

    assert directory_sha256(package).startswith("sha256:")


@pytest.fixture(autouse=True)
def accept_test_wallet_signatures(monkeypatch):
    monkeypatch.setattr(pilot_identity, "_verify_bip322", lambda address, message, signature: (True, ""))


def authorize_role(root: Path, config: dict, role: str) -> None:
    item = config[role]
    address = f"bc1q{role}testcontroller"
    key = generate_artifact_key(root, pilot_id=config["pilot_id"], role=role, agent_id=item["agent_id"], cell_coordinate=item["cell_coordinate"], controller_address=address)
    item["signing_public_key"] = key["public_key"]
    message = f"existing wallet identity claim for {role}"
    claim = {"schema_version": "test-existing-bip322-identity-claim-v0.1", "pilot_id": config["pilot_id"], "role": role, "agent_id": item["agent_id"], "cell_coordinate": item["cell_coordinate"], "controller_address": address, "message": message, "message_sha256": pilot_identity._sha(message.encode()), "signature": f"valid-{role}", "status": "signed"}
    create_artifact_authorization_request(root, identity_claim=claim, artifact_key=key)
    record_artifact_authorization(root, role, f"valid-authorization-{role}")


def ready_config(pilot: Path) -> Path:
    path = pilot / "pilot-config.json"
    config = load(path)
    config["requester"].update(cell_coordinate="810001.bitmap", endpoint="https://dq.example.invalid/organa")
    config["worker"].update(cell_coordinate="810002.bitmap", endpoint="https://n6.example.invalid/organa")
    config["verifier"].update(cell_coordinate="810003.bitmap", endpoint="local://organa-user-controller")
    authorize_role(pilot, config, "requester")
    authorize_role(pilot / "workspaces" / "n6-worker", config, "worker")
    authorize_role(pilot / "workspaces" / "local-verifier", config, "verifier")
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def prepare(tmp_path: Path):
    fixture = make_package(tmp_path / "fixture")
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=fixture)
    ready_config(pilot)
    requester = requester_publish(pilot)
    worker = worker_run(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_workspace=pilot / "workspaces" / "n6-worker",
    )
    return pilot, requester, worker


def test_pilot_init_writes_portable_templates_and_rejects_required_placeholders(tmp_path: Path):
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))

    assert (pilot / "README.zh-CN.md").read_bytes().startswith(b"\xef\xbb\xbf")
    config = load(pilot / "pilot-config.json")
    assert config["requester"]["agent_id"] == "dq"
    assert config["worker"]["agent_id"] == "n6"
    assert config["verifier"]["agent_id"] == "organa-verifier-922937"
    assert config["verifier"]["controller_scope"] == "local-user-organa-controlled-not-independent-third-party"
    assert config["settlement"]["unit"] == "ORGANA_TEST_CREDIT"
    assert config["settlement"]["real_payment"] is False
    assert config["execution_mode"] == "cross-controller-pilot"
    assert (pilot / "messages" / "send-to-dq.md").exists()
    assert (pilot / "messages" / "send-to-n6.md").exists()
    assert load(pilot / "public-board-package.template.json")["status"] == "awaiting-requester-publication"
    assert load(pilot / "receipt.template.json")["status"] == "awaiting-external-role-artifacts"

    with pytest.raises(PilotError, match="placeholder"):
        requester_publish(pilot)


def test_requester_publish_recreates_missing_exchange_parent(tmp_path: Path):
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))
    ready_config(pilot)
    exchange_parent = pilot / "exchange" / "requester-to-worker"
    shutil.rmtree(exchange_parent)
    result = requester_publish(pilot)
    assert Path(result["public_board_dir"]).is_dir()


def test_requester_publish_and_worker_run_exchange_identity_bound_artifacts(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    public = Path(requester["public_board_dir"])
    submission = Path(worker["submission_dir"])

    assert public.parent == pilot / "exchange" / "requester-to-worker"
    assert load(public / "board.json")["tasks"][0]["frozen_task"]["requester_id"] == "dq"
    assert load(public / "requester-publication.json")["role"] == "requester"
    assert load(submission / "acceptance.json")["worker_id"] == "n6"
    assert load(submission / "worker-submission.json")["agent_id"] == "n6"
    assert (submission / "worker-package" / "organa-cell.json").exists()


def test_worker_rejects_role_provenance_mismatch(tmp_path: Path):
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))
    ready_config(pilot)
    requester = requester_publish(pilot)
    public = Path(requester["public_board_dir"])
    config = load(public / "pilot-config.snapshot.json")
    config["worker"]["agent_id"] = "forged-worker"
    (public / "pilot-config.snapshot.json").write_text(json.dumps(config) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="publication|provenance|identity"):
        worker_run(public_board_dir=public, worker_workspace=pilot / "workspaces" / "n6-worker")


def test_worker_rejects_public_board_with_symlinked_ancestor(tmp_path: Path):
    pilot = tmp_path / "pilot"
    init_pilot(pilot, fixture_source=make_package(tmp_path / "fixture"))
    ready_config(pilot)
    requester = requester_publish(pilot)
    public = Path(requester["public_board_dir"])
    alias = tmp_path / "public-alias"
    alias.symlink_to(public.parent, target_is_directory=True)

    with pytest.raises(PilotError, match="symlink"):
        worker_run(public_board_dir=alias / public.name, worker_workspace=pilot / "workspaces" / "n6-worker")


def test_verifier_rejects_tampered_worker_package(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    submission = Path(worker["submission_dir"])
    (submission / "worker-package" / "proof-index.json").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(PilotError, match="submission|package|hash"):
        verifier_settle(
            public_board_dir=Path(requester["public_board_dir"]),
            worker_submission_dir=submission,
            verifier_workspace=pilot / "workspaces" / "local-verifier",
        )
    assert not list((pilot / "workspaces" / "local-verifier").glob("runs/*/receipt.json"))


def test_verifier_rejects_submission_with_symlinked_ancestor(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    submission = Path(worker["submission_dir"])
    alias = tmp_path / "submission-alias"
    alias.symlink_to(submission.parent, target_is_directory=True)

    with pytest.raises(PilotError, match="symlink"):
        verifier_settle(
            public_board_dir=Path(requester["public_board_dir"]),
            worker_submission_dir=alias / submission.name,
            verifier_workspace=pilot / "workspaces" / "local-verifier",
        )


def test_verifier_rejects_failed_manifest_verification_without_settlement(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    submission = Path(worker["submission_dir"])
    package = submission / "worker-package"
    manifest = load(package / "organa-cell.json")
    manifest["resources"][0]["sha256"] = "sha256:" + "0" * 64
    (package / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    # Rebind the worker envelope to prove the trusted verifier still fails semantic verification.
    from organa_cell_kit.pilot import directory_sha256
    from organa_cell_kit.pilot_identity import sign_json_artifact
    envelope = load(submission / "worker-submission.json")
    payload = envelope["payload"]
    payload["package_sha256"] = directory_sha256(package)
    resigned = sign_json_artifact(pilot / "workspaces" / "n6-worker", role="worker", payload=payload)
    (submission / "worker-submission.json").write_text(json.dumps(resigned, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(Exception, match="verifier|resource integrity|package hash"):
        verifier_settle(
            public_board_dir=Path(requester["public_board_dir"]),
            worker_submission_dir=submission,
            verifier_workspace=pilot / "workspaces" / "local-verifier",
        )
    assert not (pilot / "workspaces" / "local-verifier" / "current.json").exists()


def test_successful_cross_workspace_local_rehearsal_settles_test_credit_only(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    settled = verifier_settle(
        public_board_dir=Path(requester["public_board_dir"]),
        worker_submission_dir=Path(worker["submission_dir"]),
        verifier_workspace=pilot / "workspaces" / "local-verifier",
    )

    receipt = Path(settled["receipt_path"])
    assert verify_receipt(receipt)["ok"] is True
    value = load(receipt)
    assert value["roles"]["requester"]["agent_id"] == "dq"
    assert value["roles"]["worker"]["agent_id"] == "n6"
    assert value["roles"]["verifier"]["agent_id"] == "organa-verifier-922937"
    assert value["settlement_mode"] == "local-test-credit"
    assert value["settlement"]["unit"] == "ORGANA_TEST_CREDIT"
    assert value["settlement"]["real_payment"] is False
    handoff = load(Path(settled["pilot_receipt_path"]))["payload"]
    assert handoff["external_execution_claimed"] is False
    assert handoff["verifier_independence_claimed"] is False
    assert handoff["production_receipt_sha256"].startswith("sha256:")


def test_verifier_handoff_signing_failure_leaves_no_authoritative_settlement(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path)
    workspace = pilot / "workspaces" / "local-verifier"
    real_sign = pilot_module.sign_json_artifact

    def fail_verifier_signing(root, *, role, payload):
        if role == "verifier":
            raise pilot_module.IdentityPilotError("injected verifier signing failure")
        return real_sign(root, role=role, payload=payload)

    monkeypatch.setattr(pilot_module, "sign_json_artifact", fail_verifier_signing)
    with pytest.raises(PilotError, match="verifier artifact authorization"):
        verifier_settle(
            public_board_dir=Path(requester["public_board_dir"]),
            worker_submission_dir=Path(worker["submission_dir"]),
            verifier_workspace=workspace,
        )

    assert not (workspace / "current.json").exists()
    assert not list((workspace / "runs").glob("*/receipt.json"))


def test_verifier_identity_copy_failure_leaves_no_authoritative_settlement(tmp_path: Path, monkeypatch):
    pilot, requester, worker = prepare(tmp_path)
    workspace = pilot / "workspaces" / "local-verifier"
    real_copy = pilot_module._copy_public_identity

    def fail_verifier_copy(source_root, role, destination):
        if role == "verifier":
            raise PilotError("injected verifier identity copy failure")
        return real_copy(source_root, role, destination)

    monkeypatch.setattr(pilot_module, "_copy_public_identity", fail_verifier_copy)
    with pytest.raises(PilotError, match="injected verifier identity copy failure"):
        verifier_settle(
            public_board_dir=Path(requester["public_board_dir"]),
            worker_submission_dir=Path(worker["submission_dir"]),
            verifier_workspace=workspace,
        )

    assert not (workspace / "current.json").exists()
    assert not list((workspace / "runs").glob("*/receipt.json"))


def test_verifier_rejects_rehashed_mutable_publication_identity(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    public = Path(requester["public_board_dir"])
    config = load(public / "pilot-config.snapshot.json")
    config["worker"]["cell_coordinate"] = "849999.bitmap"
    (public / "pilot-config.snapshot.json").write_text(json.dumps(config) + "\n", encoding="utf-8")
    publication = load(public / "requester-publication.json")
    publication["payload"]["config_hash"] = "sha256:" + hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    publication["payload_sha256"] = pilot_identity._sha(pilot_identity._canonical(publication["payload"]))
    (public / "requester-publication.json").write_text(json.dumps(publication) + "\n", encoding="utf-8")
    submission = Path(worker["submission_dir"])
    envelope = load(submission / "worker-submission.json")
    envelope["cell_coordinate"] = "849999.bitmap"
    (submission / "worker-submission.json").write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="directory|publication|provenance|identity"):
        verifier_settle(public_board_dir=public, worker_submission_dir=submission, verifier_workspace=pilot / "workspaces" / "local-verifier")


def test_verifier_rejects_worker_substituted_target_package_after_rehash(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    submission = Path(worker["submission_dir"])
    replacement = tmp_path / "replacement"
    make_package(replacement)
    manifest = load(replacement / "organa-cell.json")
    manifest["controller"]["address"] = "bc1qattacker"
    (replacement / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    shutil.rmtree(submission / "worker-package")
    shutil.copytree(replacement, submission / "worker-package")
    from organa_cell_kit.pilot import directory_sha256
    envelope = load(submission / "worker-submission.json")
    envelope["payload"]["package_sha256"] = directory_sha256(submission / "worker-package")
    envelope["payload_sha256"] = pilot_identity._sha(pilot_identity._canonical(envelope["payload"]))
    (submission / "worker-submission.json").write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="fixture|target|package|signed"):
        verifier_settle(public_board_dir=Path(requester["public_board_dir"]), worker_submission_dir=submission, verifier_workspace=pilot / "workspaces" / "local-verifier")


def test_verifier_rejects_cross_artifact_worker_provenance_rehash(tmp_path: Path):
    pilot, requester, worker = prepare(tmp_path)
    submission = Path(worker["submission_dir"])
    acceptance = load(submission / "acceptance.json")
    result = load(submission / "worker-result.json")
    acceptance["worker_coordinate"] = "849999.bitmap"
    (submission / "acceptance.json").write_text(json.dumps(acceptance) + "\n", encoding="utf-8")
    result["acceptance_hash"] = "sha256:" + hashlib.sha256(json.dumps(acceptance, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result["worker_coordinate"] = "849999.bitmap"
    (submission / "worker-result.json").write_text(json.dumps(result) + "\n", encoding="utf-8")
    envelope = load(submission / "worker-submission.json")
    envelope["payload"]["acceptance_hash"] = "sha256:" + hashlib.sha256(json.dumps(acceptance, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    envelope["payload"]["worker_result_hash"] = "sha256:" + hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    envelope["payload_sha256"] = pilot_identity._sha(pilot_identity._canonical(envelope["payload"]))
    (submission / "worker-submission.json").write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    with pytest.raises(PilotError, match="provenance|role|worker"):
        verifier_settle(public_board_dir=Path(requester["public_board_dir"]), worker_submission_dir=submission, verifier_workspace=pilot / "workspaces" / "local-verifier")
